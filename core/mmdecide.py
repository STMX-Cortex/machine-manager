# SPDX-License-Identifier: Apache-2.0
"""machine-manager pure decision functions (PORTING.md, "Pure functions").

Readings and context in, decisions out. No file, process, clock or network access: the time comes in as `now`.
Each function has language-neutral vectors in vectors/<function>/ that a port must pass unchanged.
Settings `s` is the flat settings dict ("section.key" -> value).
"""
import re

LEVELS = {"INFO": 1, "ATTENTION": 2, "ACTION": 3}
FAR_PAST = -1e18


# ------------------------------------------------------------------------------------------- the Mac state

def classify(window, s, disk_gb=None, kernel_event=False):
    """The machine state from recent memory samples (oldest first). Each sample: t (s), free_pct, swap_used_mb,
    swap_total_mb, comp_mb, pressure, seg_pct, load1, load5, sys_pct (missing keys are None).
    Returns [state, reasons, complete]; complete is False when an essential reading is missing (then no raise)."""
    if not window:
        return ["UNKNOWN", ["no readings"], False]
    cur = window[-1]
    n = s["slots.sustain_samples"]

    def get(sample, k):
        v = sample.get(k)
        return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None

    def growth(k, seconds):
        """Rise of k over the last `seconds` (newest value minus the lowest value inside the window)."""
        t1 = cur["t"]
        vals = [get(x, k) for x in window if t1 - x["t"] <= seconds + 1 and get(x, k) is not None]
        if len(vals) < 2 or get(cur, k) is None:
            return None
        return get(cur, k) - min(vals[:-1])

    def sustained(k, limit):
        """Every sample of the last (n-1) minutes is above the limit (n samples at least; the window reaches back)."""
        span = (n - 1) * 60
        if window[0]["t"] > cur["t"] - span + 1:
            return False
        pts = [get(x, k) for x in window if cur["t"] - x["t"] <= span + 1]
        return len(pts) >= n and all(v is not None and v > limit for v in pts)

    red, amber = [], []
    free, pressure = get(cur, "free_pct"), get(cur, "pressure")
    if pressure is not None and pressure >= 4:
        red.append("kernel pressure %d (critical)" % pressure)
    if free is not None and free < s["slots.red_free_pct"]:
        red.append("free %.0f%% < %g%%" % (free, s["slots.red_free_pct"]))
    g = growth("swap_used_mb", 60)
    if g is not None and g > s["slots.red_swap_growth_mb_60s"]:
        red.append("swap +%.0f MB in 60 s" % g)
    g = growth("comp_mb", 60)
    if g is not None and g > s["slots.red_comp_growth_mb_60s"]:
        red.append("compressor +%.0f MB in 60 s" % g)
    seg = get(cur, "seg_pct")
    if seg is not None and seg > s["slots.red_segments_pct"]:
        red.append("compressor segments %.0f%% of limit" % seg)
    used, total = get(cur, "swap_used_mb"), get(cur, "swap_total_mb")
    g60 = growth("swap_used_mb", 60)
    if used is not None and total and used / total * 100 > s["slots.red_swap_used_of_total_pct"] and g60 and g60 > 0:
        red.append("swap %.0f of %.0f MB and growing" % (used, total))
    if sustained("sys_pct", s["slots.red_sys_pct"]):
        red.append("system CPU > %g%% in %d samples" % (s["slots.red_sys_pct"], n))
    if sustained("load1", s["slots.red_load1_per_core"] * s["slots.cores"]):
        red.append("load1 > %g in %d samples" % (s["slots.red_load1_per_core"] * s["slots.cores"], n))
    if kernel_event:
        red.append("kernel memorystatus event (no paging space or suspending)")
    if disk_gb is not None and disk_gb < s["slots.red_disk_gb"]:
        red.append("disk %.0f GB < %g GB" % (disk_gb, s["slots.red_disk_gb"]))

    if pressure is not None and pressure >= 2 and not red:
        amber.append("kernel pressure %d (warn)" % pressure)
    if free is not None and free < s["slots.amber_free_pct"]:
        amber.append("free %.0f%% < %g%%" % (free, s["slots.amber_free_pct"]))
    g = growth("swap_used_mb", 1800)
    if g is not None and g > s["slots.amber_swap_growth_mb_30m"]:
        amber.append("swap +%.0f MB over its 30-min base" % g)
    comp = get(cur, "comp_mb")
    if comp is not None and comp > s["slots.amber_comp_mb"]:
        amber.append("compressor %.0f MB" % comp)
    l5 = get(cur, "load5")
    if l5 is not None and l5 > s["slots.amber_load5"]:
        amber.append("load5 %.1f > %g" % (l5, s["slots.amber_load5"]))
    if sustained("sys_pct", s["slots.amber_sys_pct"]):
        amber.append("system CPU > %g%% in %d samples" % (s["slots.amber_sys_pct"], n))

    complete = all(get(cur, k) is not None for k in ("free_pct", "swap_used_mb", "comp_mb", "load5"))
    if red:
        return ["RED", red, complete]
    if amber:
        return ["AMBER", amber, complete]
    green_fail = []
    if free is None or free < s["slots.green_free_pct"]:
        green_fail.append("free below %g%%" % s["slots.green_free_pct"])
    g = growth("swap_used_mb", 1800)
    if g is not None and g >= s["slots.amber_swap_growth_mb_30m"]:
        green_fail.append("swap grew")
    if l5 is None or l5 >= s["slots.green_load5"]:
        green_fail.append("load5 not under %g" % s["slots.green_load5"])
    sp = get(cur, "sys_pct")
    if sp is not None and sp >= s["slots.green_sys_pct"]:
        green_fail.append("system CPU not under %g%%" % s["slots.green_sys_pct"])
    if disk_gb is not None and disk_gb < s["disk.recover_gb"]:
        green_fail.append("disk under %g GB" % s["disk.recover_gb"])
    if green_fail or not complete:
        return ["STEADY", green_fail or ["readings incomplete"], complete]
    return ["GREEN", ["all readings in the green band"], complete]


# ------------------------------------------------------------------------------------------- the slot controller

def slot_decide(state, inp, s):
    """One step of the slot controller. One step up at a time after a long GREEN with demand; down at once.
    state: the controller's own dict (returned updated, never changed in place).
    inp: now, mac_state, reasons, slots, busy, waiting, wx_waiting, override ({slots, until, reason} or null),
    events (list of 'timing-failure', 'guard-kill', 'trim').
    Returns {"slots": new or None, "why": text or None, "state": the new state}."""
    st = dict(state or {})
    now, mac_state, reasons, slots = inp["now"], inp["mac_state"], inp.get("reasons", []), inp["slots"]
    events = inp.get("events") or []
    override = inp.get("override")
    floor, ceiling = s["slots.floor"], s["slots.ceiling"]
    st.setdefault("last_change", now)
    st.setdefault("green_since", None)
    if "trim" in events:
        st["last_trim"] = now
    if mac_state == "RED":
        st["last_red"] = now
    st["green_since"] = (st["green_since"] or now) if mac_state == "GREEN" else None
    pin = None
    if override and override.get("until", 0) > now:
        pin = max(1, min(16, int(override["slots"])))
    target = why = None
    amber_events = [e for e in events if e in ("timing-failure", "guard-kill")]
    if mac_state == "RED":
        if slots > floor:
            target, why = floor, "RED: " + "; ".join(reasons)
    elif mac_state == "AMBER" or amber_events:
        if slots > floor and now - st.get("last_down", FAR_PAST) >= s["slots.amber_step_interval_s"]:
            target = max(floor, slots - 1)
            why = "AMBER: " + "; ".join(list(reasons if mac_state == "AMBER" else []) + amber_events)
    elif pin is not None:
        if slots != pin:
            target, why = pin, "pin: " + str(override.get("reason", ""))
    elif mac_state == "GREEN":
        held = now - st["green_since"] >= s["slots.raise_green_minutes"] * 60
        calm = now - st["last_change"] >= s["slots.raise_green_minutes"] * 60
        no_red = now - st.get("last_red", FAR_PAST) >= s["slots.hold_after_red_minutes"] * 60
        no_trim = now - st.get("last_trim", FAR_PAST) >= s["slots.hold_after_trim_minutes"] * 60
        demand = inp["waiting"] >= s["slots.raise_requires_waiting"] and inp["busy"] >= slots
        if held and calm and no_red and no_trim and demand and not inp.get("wx_waiting") and slots < ceiling:
            target, why = slots + 1, "GREEN %.0f min, %d waiting, all %d slots busy" % (
                (now - st["green_since"]) / 60, inp["waiting"], slots)
    if target is not None and pin is not None and target > pin:
        target = pin
    if target is None or target == slots:
        return {"slots": None, "why": None, "state": st}
    if target < slots:
        st["last_down"] = now
    st["last_change"] = now
    return {"slots": target, "why": why, "state": st}


# ------------------------------------------------------------------------------------------- alert dedupe and repeat

def repeat_s(level, s):
    if level == "ACTION":
        return s["repeat.action_minutes"] * 60
    if level == "ATTENTION":
        return s["repeat.attention_hours"] * 3600
    return None


def alert_raise(entry, acked, cond, now, s):
    """One active condition against its stored entry (None when new).
    cond: key, name, level, text, value, band, worse ('up'|'down'), command, investigate.
    Returns {"push": bool, "why": text or None, "entry": new entry, "acked": bool (after this step)}."""
    cur = dict(entry) if entry else None
    level = cond["level"]
    push, why = False, None
    if cur is None:
        push, why = True, "new"
        cur = {"key": cond["key"], "name": cond["name"], "level": level, "first": now, "count": 0}
    else:
        if LEVELS[level] > LEVELS[cur.get("pushed_level", cur["level"])] and LEVELS[level] > LEVELS[cur["level"]]:
            push, why = True, "level rose"
        elif cond.get("band") and cond.get("value") is not None and cur.get("pushed_value") is not None:
            delta = cond["value"] - cur["pushed_value"] if cond.get("worse", "up") == "up" else cur["pushed_value"] - cond["value"]
            if delta >= cond["band"]:
                push, why = True, "worse by a band"
        rep = repeat_s(level, s)
        if not push and rep is not None and now - cur.get("pushed_at", 0) >= rep:
            push, why = True, "repeat"
    if push and why == "repeat" and acked:
        push = False
    if push and why in ("worse by a band", "level rose"):
        acked = False
    if push and LEVELS[level] == 1 and why != "new":
        push = False
    cur.pop("absent_since", None)
    cur.update(level=level, last=now, text=cond["text"], value=cond.get("value"), command=cond.get("command"),
               investigate=cond.get("investigate"), name=cond["name"])
    cur["count"] = cur.get("count", 0) + 1
    if push:
        cur["pushed_at"], cur["pushed_value"], cur["pushed_level"] = now, cond.get("value"), level
    return {"push": push, "why": why if push else None, "entry": cur, "acked": bool(acked)}


def alert_absent(entry, now, s):
    """A stored entry whose condition was not raised this round. It clears only after repeat.clear_after_minutes absent.
    Returns {"clear": bool, "push_cleared": bool, "entry": the entry (when kept)}."""
    cur = dict(entry)
    cur.setdefault("absent_since", now)
    if now - cur["absent_since"] < s.get("repeat.clear_after_minutes", 5) * 60:
        return {"clear": False, "push_cleared": False, "entry": cur}
    return {"clear": True, "push_cleared": LEVELS[cur["level"]] >= 2, "entry": cur}


# ------------------------------------------------------------------------------------------- the delete guard

def delete_guard(f):
    """The decision for one SAFE-AUTO candidate from its gathered facts.
    f: enabled, forbidden, parent_ok, symlink, keep_file, untouched ([ok, why]), held (reason or null),
    live_tools (list), needs_no_live_tools, age_minutes, recheck (bool: this is the re-check right before the delete).
    Returns {"verb": "DELETE"|"WOULD-DELETE"|"KEEP", "guard": text}."""
    if f.get("forbidden"):
        return {"verb": "KEEP", "guard": "forbidden path (protected)"}
    if not f.get("parent_ok"):
        return {"verb": "KEEP", "guard": "not directly inside an allowed root"}
    if f.get("symlink"):
        return {"verb": "KEEP", "guard": "symbolic link"}
    if f.get("keep_file"):
        return {"verb": "KEEP", "guard": ".keep"}
    ok, why = f.get("untouched") or [False, "age unknown"]
    if not ok:
        return {"verb": "KEEP", "guard": why}
    if f.get("held"):
        return {"verb": "KEEP", "guard": f["held"]}
    if f.get("needs_no_live_tools") and f.get("live_tools"):
        return {"verb": "KEEP", "guard": "live_tools=%s" % ",".join(f["live_tools"][:3])}
    g = "pass: age>%gmin lsof=empty%s" % (f.get("age_minutes", 0), " live_tools=none" if f.get("needs_no_live_tools") else "")
    return {"verb": "DELETE" if f.get("enabled") else "WOULD-DELETE", "guard": g}


# ------------------------------------------------------------------------------------------- placement

EXIT = {"MACHINE": 0, "GO": 0, "POOL": 10, "WAIT": 20}


def expected_wait(q, medians, default, now):
    """Minutes until a new shared call starts on a machine: work ahead divided by slots."""
    if not q or not q.get("slots"):
        return None
    ahead = 0.0
    for b in q.get("busy", []):
        typ = medians.get(b.get("kind") or "other", default)
        el = (now - b["since"]) / 60.0 if b.get("since") else 0.0
        ahead += max(typ - el, 1.0)
    for t in q.get("tickets", []):
        ahead += medians.get(t.get("kind") or "other", default)
    if q["slots"] - len(q.get("busy", [])) > 0 and not q.get("tickets"):
        return 0.0
    return ahead / q["slots"]


def place(req, ctx, s):
    """Placement over a list of candidates (today: this machine and one CI pool).
    req: kind, shards, wide, agents.
    ctx: now, wide_kind, kinds ({machine_only: {kind: why}, pool: {kind: max_shards}}), machine ({id, state, reasons, free_pct, queue,
    medians}), pools ([{id, minutes_left, minutes_source, plan_minutes, job_minutes, guard: null|{rc, line}|"skip",
    guard_why, stop_active}]).
    Returns {"place": MACHINE|GO|POOL|WAIT, "candidate": id or null, "reasons": [...], "need_guard": pool id or null}.
    When a pool needs its budget guard read and ctx has none yet, the answer says need_guard: the caller reads the guard
    and calls place() again with it (two pure steps; the guard read is the adapter's)."""
    m = ctx["machine"]
    st, reasons = m["state"], m.get("reasons", [])
    out = ["state %s: %s" % (st, "; ".join(reasons)[:200])]
    kinds = ctx["kinds"]
    if req.get("agents"):
        n = req["agents"]
        if st == "RED":
            return _ans("WAIT", None, out + ["RED: no agent launch now (%d asked)" % n])
        if st == "AMBER" and n > 1:
            return _ans("WAIT", None, out + ["AMBER: launch one agent at a time"])
        return _ans("GO", m["id"], out + ["%d agent(s) may start" % n])
    q = m.get("queue") or {}
    if req.get("wide") or req["kind"] == ctx.get("wide_kind"):
        free = m.get("free_pct")
        why = []
        if st in ("RED", "AMBER"):
            why.append("state %s" % st)
        if free is None or free < s["queue.wide_free_pct"]:
            why.append("free %s%% < %g%%" % (free, s["queue.wide_free_pct"]))
        if any("swap +" in r or "swap grew" in r for r in reasons):
            why.append("swap is growing")
        if [b for b in q.get("busy", []) if b.get("mode") in ("W", "X")] + \
                [t for t in q.get("tickets", []) if t.get("mode") in ("W", "X")]:
            why.append("another wide or exclusive call holds or waits")
        if why:
            return _ans("WAIT", None, out + ["--wide waits: " + "; ".join(why)])
        return _ans("MACHINE", m["id"], out + ["--wide may start: free %s%%, swap flat, no other wide" % free])
    wait = expected_wait(q, m.get("medians") or {}, s["queue.default_run_minutes"], ctx["now"])
    wtxt = "expected wait on %s: %s min" % (m["id"], "?" if wait is None else "%.0f" % wait)
    kind = req["kind"]
    if kind not in kinds["pool"]:
        why = kinds["machine_only"].get(kind, "kind '%s' runs only on a machine" % kind)
        if st == "RED":
            return _ans("WAIT", None, out + ["RED; " + why])
        return _ans("MACHINE", m["id"], out + [wtxt, why])
    if st != "RED" and wait is not None and wait <= s["queue.placement_max_mac_wait_minutes"]:
        return _ans("MACHINE", m["id"], out + [wtxt + " <= %g" % s["queue.placement_max_mac_wait_minutes"]])
    no_all = []
    for p in ctx.get("pools", []):
        shards = req.get("shards", 1)
        worst = p["plan_minutes"] + shards * p["job_minutes"]
        no = []
        if shards > kinds["pool"][kind]:
            no.append("%d shards > %d" % (shards, kinds["pool"][kind]))
        if p.get("minutes_left") is None:
            no.append("minutes left unknown (%s)" % p.get("minutes_source"))
        elif p["minutes_left"] - worst <= s["github.reserve_minutes"]:
            no.append("minutes left %.0f - worst case %d <= reserve %g" % (p["minutes_left"], worst, s["github.reserve_minutes"]))
        if p.get("stop_active"):
            no.append("GUARD_STOP is active")
        if p.get("guard_why"):
            no.append(p["guard_why"])
        if not no:
            g = p.get("guard")
            if g is None:
                return {"place": None, "candidate": None, "reasons": out, "need_guard": p["id"]}
            if g["rc"] != 0:
                no.append("guard %s: %s" % ({1: "refused", 2: "cannot read"}.get(g["rc"], "rc=%s" % g["rc"]), g["line"][:160]))
        if not no:
            return _ans("POOL", p["id"], out + [wtxt, "%s: %.0f minutes left (%s), worst case %d, reserve %g" % (
                p["id"], p["minutes_left"], p.get("minutes_source"), worst, s["github.reserve_minutes"]),
                "guard: " + p["guard"]["line"][:160]])
        no_all.append("%s: %s" % (p["id"], "; ".join(no)))
    if st == "RED":
        return _ans("WAIT", None, out + ["RED; no pool: " + " | ".join(no_all)])
    return _ans("MACHINE", m["id"], out + [wtxt, "no pool: " + " | ".join(no_all)])


def _ans(place_, cand, reasons):
    return {"place": place_, "candidate": cand, "reasons": reasons, "need_guard": None}


# ------------------------------------------------------------------------------------------- small helpers

def disk_rate(hist, now):
    """GB per hour of falling free space, from the newest reading at least 30 min old (positive = falling)."""
    if not hist:
        return None
    newest = hist[-1]
    older = [x for x in hist if newest[0] - x[0] >= 1800]
    if not older:
        return None
    o = older[-1]
    return (o[1] - newest[1]) / ((newest[0] - o[0]) / 3600)


def reason_kind(reason):
    """A reason with its numbers replaced by N, so counts group by rule."""
    return re.sub(r"[+-]?\d+(\.\d+)?", "N", reason)


def count_state(counts, inp):
    """Ticks per state, per RED and AMBER rule, RED episodes, and the state the interval system CPU value would give.
    inp: now, state, reasons, alt_state. Returns the new counts."""
    c = {k: (dict(v) if isinstance(v, dict) else v) for k, v in (counts or {}).items()}
    now, state = inp["now"], inp["state"]
    c.setdefault("since", now)
    c.setdefault("ticks", {})
    c["ticks"][state] = c["ticks"].get(state, 0) + 1
    if state in ("RED", "AMBER"):
        key = "red_rules" if state == "RED" else "amber_rules"
        c.setdefault(key, {})
        for r in inp.get("reasons", []):
            k = reason_kind(r)
            c[key][k] = c[key].get(k, 0) + 1
    if state == "RED" and c.get("last_state") != "RED":
        c["red_episodes"] = c.get("red_episodes", 0) + 1
    c["last_state"] = state
    c.setdefault("alt_ticks", {})
    c["alt_ticks"][inp["alt_state"]] = c["alt_ticks"].get(inp["alt_state"], 0) + 1
    c["updated"] = now
    return c


# ------------------------------------------------------------------------------------------- the memory drill

def drill_stop(inp, s):
    """Whether the memory drill must stop before (or after) its next step. It never aims at RED.
    inp: elapsed_s, time_limit_s, state (the supervisor's), free_pct, swap_used_mb, swap_start_mb, step_mb, total_mb
    (the machine's memory), interrupted, held_mb (what the drill holds now), free_start_pct (free at the start),
    recent ([held_mb, free_pct] pairs, oldest first: the start reading, then one per step). Returns a stop reason or None.
    The floor is the RED free line + 10 points; a step whose predicted free value would reach it is not taken.
    The cap: the drill never holds more than the room above the floor at the start plus one step, whatever the
    readings say. And when 3 steps add memory but free falls by less than 1 point, or by less than a quarter of what
    the added memory takes of the machine, the memory is not being used
    (compressed or not resident), so the drill stops instead of holding more and more."""
    if inp.get("interrupted"):
        return "interrupted"
    if inp.get("state") in ("AMBER", "RED"):
        return "supervisor %s" % inp["state"]
    if inp.get("elapsed_s", 0) >= inp["time_limit_s"]:
        return "time limit %gs" % inp["time_limit_s"]
    floor = s["slots.red_free_pct"] + 10
    free = inp.get("free_pct")
    if free is None:
        return "free unreadable"
    if free <= floor:
        return "floor: free %.0f%% <= %g%%" % (free, floor)
    if inp.get("total_mb") and free - inp["step_mb"] * 100.0 / inp["total_mb"] <= floor:
        return "floor next: free %.0f%% - one step would reach %g%%" % (free, floor)
    f0, held = inp.get("free_start_pct"), inp.get("held_mb", 0)
    if f0 is None or not inp.get("total_mb"):
        return "cap unknown: free at the start or the machine's memory unreadable"
    room = max(0.0, (f0 - floor) * inp["total_mb"] / 100.0)
    if held > room:
        return "cap: held %d MB > %.0f MB of room above the floor at the start" % (held, room)
    rec = inp.get("recent") or []
    if len(rec) >= 4:
        (h0, fa), (h1, fb) = rec[-4], rec[-1]
        need = max(1.0, 0.25 * (h1 - h0) * 100.0 / inp["total_mb"])
        if h1 > h0 and fa is not None and fb is not None and fa - fb < need:
            return "memory not used (compressed?): held +%d MB over 3 steps, free fell %.1f points (< %.1f)" % (
                h1 - h0, fa - fb, need)
    sw0, sw = inp.get("swap_start_mb"), inp.get("swap_used_mb")
    if sw0 is not None and sw is not None and sw - sw0 > s["slots.amber_swap_growth_mb_30m"]:
        return "swap +%.0f MB > %g MB" % (sw - sw0, s["slots.amber_swap_growth_mb_30m"])
    return None


# ------------------------------------------------------------------------------------------- self-recovery

SAMPLE_KEYS = ("free_pct", "swap_total_mb", "swap_used_mb", "comp_mb", "pressure", "load1", "load5")


def sample_problems(sample):
    """Readings that are missing or impossible in one memory sample: a list of short texts (empty = fine).
    Impossible: free_pct outside 0..100, a negative size or load, swap used above its total, a pressure level that
    is not 1, 2 or 4, a compressor segment share above 100 %."""
    out = []

    def num(k):
        v = sample.get(k)
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v:
            out.append("%s %r is not a number" % (k, v))
            return False
        return v

    vals = {}
    for k in SAMPLE_KEYS:
        v = num(k)
        if v is None:
            out.append("%s missing" % k)
        elif v is not False:
            vals[k] = v
    for k in ("swap_total_mb", "swap_used_mb", "comp_mb", "load1", "load5"):
        if k in vals and vals[k] < 0:
            out.append("%s %g is negative" % (k, vals[k]))
    if "free_pct" in vals and not 0 <= vals["free_pct"] <= 100:
        out.append("free_pct %g outside 0..100" % vals["free_pct"])
    if "swap_used_mb" in vals and "swap_total_mb" in vals and vals["swap_used_mb"] > vals["swap_total_mb"] * 1.01 + 1:
        out.append("swap used %g MB above its total %g MB" % (vals["swap_used_mb"], vals["swap_total_mb"]))
    if "pressure" in vals and vals["pressure"] not in (1, 2, 4):
        out.append("pressure level %g is not 1, 2 or 4" % vals["pressure"])
    seg = num("seg_pct")
    if seg not in (None, False) and not 0 <= seg <= 100.5:
        out.append("seg_pct %g outside 0..100" % seg)
    return out


def self_check(state, inp, s):
    """The supervisor's check of itself, once per tick. state: {"slow": n, "bad": n} (consecutive counts, kept by the
    caller). inp: now, rss_mb (None = not read this tick), tick_s, tick_errors (failed ticks in a row),
    reading_problems (list), data_writable, data_free_mb, slot_changes (times), safe (in safe mode now).
    Returns {"state", "action": "ok"|"restart"|"safe"|"alert", "reasons"}. A fault of the tool itself (memory, slow or
    failing ticks) asks for a restart; a fault a restart cannot fix (wrong readings, the data folder, a slot count
    that keeps changing) asks for safe mode. In safe mode the answer is never restart or safe, only alert."""
    state = state or {}
    slow = state.get("slow", 0) + 1 if inp.get("tick_s", 0) > s["self.max_tick_s"] else 0
    bad = state.get("bad", 0) + 1 if inp.get("reading_problems") else 0
    restart, safe = [], []
    rss = inp.get("rss_mb")
    if rss is not None and rss > s["self.max_rss_mb"]:
        restart.append("own memory %.0f MB above %g MB" % (rss, s["self.max_rss_mb"]))
    if slow >= s["self.slow_ticks"]:
        restart.append("%d ticks in a row took over %g s" % (slow, s["self.max_tick_s"]))
    if inp.get("tick_errors", 0) >= s["self.bad_reading_ticks"]:
        restart.append("%d ticks in a row failed" % inp["tick_errors"])
    if bad >= s["self.bad_reading_ticks"]:
        safe.append("readings wrong %d ticks in a row: %s" % (bad, inp["reading_problems"][0]))
    if inp.get("data_writable") is False:
        safe.append("the data folder is not writable")
    free = inp.get("data_free_mb")
    if free is not None and free < s["self.min_free_mb"]:
        safe.append("the data folder's disk has %.0f MB free, below %g MB" % (free, s["self.min_free_mb"]))
    now = inp.get("now", 0)
    changes = [t for t in inp.get("slot_changes", []) if now - t < 3600]
    if len(changes) > s["self.max_slot_changes_per_hour"]:
        safe.append("the slot count changed %d times in the last hour (limit %d)"
                    % (len(changes), s["self.max_slot_changes_per_hour"]))
    reasons = safe + restart
    if inp.get("safe"):
        action = "alert" if reasons else "ok"
    else:
        action = "safe" if safe else ("restart" if restart else "ok")
    return {"state": {"slow": slow, "bad": bad}, "action": action, "reasons": reasons}


def crash_loop(starts, now, s):
    """Unclean starts (the run before did not end by itself) inside self.crash_loop_minutes. Returns
    {"starts": the ones kept, "safe": True at self.crash_loop_starts or more}."""
    kept = sorted(t for t in starts if 0 <= now - t < s["self.crash_loop_minutes"] * 60)
    return {"starts": kept, "safe": len(kept) >= s["self.crash_loop_starts"]}


def resume_targets(paused, current):
    """The pids to continue: each paused pid whose process start time now is the one recorded at the pause
    (a pid that is gone or was reused gets nothing). paused, current: {pid (string): start time text or None}."""
    return sorted(int(p) for p, st in paused.items() if st and current.get(p) == st)


def reboot_check(prev, cur):
    """A Mac reboot seen at the supervisor's start. prev: the record the last run kept (boot_time, last_tick,
    last_state, last_slots, panics) or None; cur: boot_time, now, panics (file names), missing_jobs (names).
    Returns None (no reboot, or no record to compare), else {level, text, uptime_s, down_s, new_panics}."""
    if not prev or prev.get("boot_time") is None or cur.get("boot_time") is None:
        return None
    if abs(cur["boot_time"] - prev["boot_time"]) < 2:
        return None
    up = cur["now"] - cur["boot_time"]
    down = cur["now"] - prev["last_tick"] if prev.get("last_tick") else None
    old = set(prev.get("panics") or [])
    new = sorted(p for p in (cur.get("panics") or []) if p not in old)
    miss = list(cur.get("missing_jobs") or [])
    parts = ["Mac rebooted: up %.0f min" % (up / 60)]
    parts.append("tool down %s" % ("unknown" if down is None else "%.0f min" % (down / 60)))
    parts.append("before: %s slots %s" % (prev.get("last_state") or "?", prev.get("last_slots") if prev.get("last_slots") is not None else "?"))
    if cur.get("panics") is None:
        parts.append("panic reports unreadable")
    else:
        parts.append("%d new panic report%s" % (len(new), "" if len(new) == 1 else "s"))
    if miss:
        parts.append("not running: " + ", ".join(miss))
    level = "ACTION" if new or miss else "ATTENTION"
    return {"level": level, "text": "; ".join(parts), "uptime_s": up, "down_s": down, "new_panics": new}
