# SPDX-License-Identifier: Apache-2.0
"""machine-manager alert rules: a pure function from a snapshot of readings to active conditions.

Each condition: dict(key, name, level, text, value, band, worse, command, investigate). The AlertStore does dedupe,
bands, repeat, clear and ack (mmdecide.alert_raise / alert_absent). Pool (CI) conditions come from the CI adapter.
`names` gives the words a project wants in its texts: owner, recipient, trim_command, jobs_file.
"""
import hashlib
import shlex


def _c(key, name, level, text, value=None, band=None, worse="up", command=None, investigate=None):
    return {"key": key, "name": name, "level": level, "text": text, "value": value, "band": band, "worse": worse,
            "command": command, "investigate": investigate}


def _h(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]


def _gb(b):
    return "?" if b is None else "%.1f GB" % (b / 1e9)


def queue_calls(busy):
    """Call identity and held slots, using the earliest lock start for each PID."""
    by_pid = {}
    for b in busy:
        if b.get("pid"):
            by_pid.setdefault(b["pid"], []).append(b)
    calls = {}
    for pid, held in by_pid.items():
        starts = [b["since"] for b in held if b.get("since") is not None]
        if starts:
            # A wide call's lock files can have slightly different mtimes.
            call = "%s:%s" % (pid, float(min(starts)))
            calls[call] = (pid, {b["slot"] for b in held})
    return calls


def evaluate(snap, s, now, active=frozenset(), names=None):
    """Active conditions for one evaluation. `active` holds the keys active before (for hysteresis)."""
    out = []
    g = snap.get
    nm = dict({"owner": "the owner", "recipient": "the recipient", "trim_command": None, "jobs_file": "the job file"},
              **(names or {}))
    TRIM_CMD = nm["trim_command"]

    # --- memory state (the controller acts on the same state)
    st = g("state")
    if st:
        state, reasons = st
        top = g("top_outside") or []
        tops = ", ".join("%s %.0f MB" % (n, mb) for n, mb in top[:3])
        if state == "RED":
            out.append(_c("MEM", "MEM_RED", "ACTION",
                          "machine RED: %s; slots to the floor; hold launches and heavy calls; top outside queue: %s"
                          % ("; ".join(reasons), tops or "n/a"),
                          investigate={"question": "What caused the memory or CPU burst?",
                                       "hypotheses": ["a queue call grew", "agents started together", "an outside app"]}))
        elif state == "AMBER":
            out.append(_c("MEM", "MEM_AMBER", "ATTENTION",
                          "machine AMBER: %s; slots step down; top outside queue: %s" % ("; ".join(reasons), tops or "n/a")))

    for ev in g("kernel_events") or []:
        who = ev.get("process") or "the system"
        if ev.get("kind") == "suspending":
            text = ("macOS suspended %s [%s] at %s (%s); it stays stopped until %s resumes or quits it"
                    % (who, ev.get("pid"), (ev.get("time") or "")[11:19], ev.get("why"), nm["owner"]))
        else:
            text = "kernel: no paging space at %s (swap exhausted); hold every launch" % (ev.get("time") or "")[11:19]
        out.append(_c("KERNEL:%s:%s" % (ev.get("kind"), who), "KERNEL_SUSPEND", "ACTION", text,
                      investigate={"question": "Why did the kernel report swap exhaustion?",
                                   "hypotheses": ["swap total full", "compressor segments", "process storm"]}))

    for line in g("kills_new") or []:
        out.append(_c("KILL:" + _h(line), "GUARD_KILL", "ACTION",
                      "memory guard killed a queue process: " + line[:160]))

    # --- disk and cache
    disk = g("disk_gb")
    if disk is not None:
        low, rec = s["disk.low_gb"], s["disk.recover_gb"]
        if disk < low or ("DISK_LOW" in active and disk < rec):
            out.append(_c("DISK_LOW", "DISK_LOW", "ACTION", "disk %.1f GB free (alert < %g GB, clears > %g GB)"
                          % (disk, low, rec), value=disk, band=10, worse="down"))
        rate = g("disk_rate_gb_h")
        if rate and rate > 0 and disk >= low and (disk - low) / rate < s["disk.trend_hours"]:
            out.append(_c("DISK_TREND", "DISK_TREND", "ATTENTION", "disk %.1f GB, falling %.1f GB/h: %g GB in %.1f h"
                          % (disk, rate, low, (disk - low) / rate), value=disk, band=10, worse="down"))
    cache = g("cache_gb")
    if cache is not None:
        if cache > s["disk.cache_action_gb"] or (disk is not None and disk < s["disk.cache_action_disk_gb"]
                                                 and cache > s["disk.cache_attention_gb"]):
            out.append(_c("CACHE_BIG", "CACHE_BIG", "ACTION", "build cache %.0f GB (disk %s GB)" % (
                cache, "?" if disk is None else "%.0f" % disk), value=cache, band=10, command=TRIM_CMD))
        elif cache > s["disk.cache_attention_gb"]:
            out.append(_c("CACHE_BIG", "CACHE_BIG", "ATTENTION", "build cache %.0f GB" % cache, value=cache, band=10,
                          command=TRIM_CMD))

    # --- usage
    u = g("usage")
    if u:
        cw = u.get("codex_week")
        if cw is not None and cw >= s["usage.codex_action_pct"]:
            out.append(_c("CODEX", "CODEX98", "ACTION", "Codex weekly %g%%: tell %s a reset is needed now" % (cw, nm["owner"])))
        elif cw is not None and cw >= s["usage.codex_attention_pct"]:
            out.append(_c("CODEX", "CODEX95", "ATTENTION", "Codex weekly %g%%: tell %s a reset is needed soon" % (cw, nm["owner"])))
        c5, cwk = u.get("claude_5h"), u.get("claude_week")
        if (cwk is not None and cwk >= s["usage.claude_action_pct"]) or (c5 is not None and c5 >= s["usage.claude_action_pct"]):
            out.append(_c("CLAUDE98", "CLAUDE98", "ACTION", "Claude weekly %s%%, 5-hour %s%%: tell %s" % (cwk, c5, nm["owner"])))
        proj = u.get("proj")
        if isinstance(proj, (int, float)) and proj > s["usage.claude_projection_pct"]:
            out.append(_c("CLAUDE_PROJ", "CLAUDE_PROJ", "ATTENTION", "Claude weekly projection %.1f%%" % proj,
                          value=proj, band=2))
        if c5 is not None and c5 >= s["usage.claude_5h_attention_pct"]:
            out.append(_c("FIVE_H", "FIVE_H", "ATTENTION", "Claude 5-hour %g%%: no agent bursts before its reset" % c5))

    # --- the queue
    q = g("queue")
    if q and q.get("slots"):
        slots, busy, tickets = q["slots"], q.get("busy", []), q.get("tickets", [])
        for t in tickets:
            age = t.get("age_s")
            if age is not None and age > s["queue.wait_minutes"] * 60:
                out.append(_c("QWAIT:" + t["name"], "QWAIT", "ATTENTION", "queue call waits %.0f min: %s"
                              % (age / 60, (t.get("label") or "")[:120]), value=age / 60, band=10))
        if tickets and tickets[0]["mode"] in ("W", "X") and (tickets[0].get("age_s") or 0) > s["queue.head_block_minutes"] * 60 \
                and len(busy) < slots:
            holders = ", ".join((b.get("label") or "?")[:40] for b in busy) or "none"
            out.append(_c("HEAD_BLOCK:" + tickets[0]["name"], "HEAD_BLOCK", "ATTENTION",
                          "%s call at the head waits %.0f min, %d of %d slots idle, %d behind; holders: %s"
                          % ("wide" if tickets[0]["mode"] == "W" else "exclusive", tickets[0]["age_s"] / 60,
                             slots - len(busy), slots, len(tickets) - 1, holders)))
        for b in busy:
            if b.get("mode") == "S" and b.get("since") and now - b["since"] > s["queue.long_call_minutes"] * 60:
                out.append(_c("LONG:%s:%s" % (b["slot"], b.get("pid")), "LONG_CALL", "ATTENTION",
                              "shared call runs %.0f min (split it): %s" % ((now - b["since"]) / 60, (b.get("label") or "")[:120])))
    hour = g("history_hour") or []
    long_waits = [c for c in hour if c.get("wait", 0) > 1200]
    if len(long_waits) >= s["queue.waits_over_20_per_hour"]:
        out.append(_c("QWAIT:hour", "QWAIT", "ATTENTION", "%d calls waited over 20 min in the last hour" % len(long_waits),
                      value=len(long_waits), band=3))
    for c in g("refused_recent") or []:
        why = "refused by placement" if c["mode"] == "P" else ("refused as too large for an agent" if c["mode"] == "A"
                                                               else "admitted without memory rules (mem=na)")
        out.append(_c("REFUSED:%s:%d" % (c["pid"], int(c["end"])), "REFUSED", "ATTENTION",
                      "queue call %s: %s" % (why, (c.get("cmd") or "")[:120])))
    slot_cpu = g("slot_cpu") or {}
    if "queue" in snap:
        calls = {call: held for call, (_, held) in queue_calls((g("queue") or {}).get("busy", [])).items()}
    else:
        # Older pure inputs omit the queue; live snapshots always supply it.
        calls = {slot: {slot} for slot in slot_cpu}
    for call, held in calls.items():
        readings = [slot_cpu[slot] for slot in held if slot in slot_cpu]
        if not readings:
            continue
        cores = max(readings)
        if cores > s["queue.slot_cpu_cores"] * len(held):
            out.append(_c("SLOT_CPU:" + call, "SLOT_CPU", "ATTENTION", "call %s process tree uses about %.1f cores over %d slots" % (call, cores, len(held)),
                          investigate={"question": "Which process in this call runs wider than its cap?",
                                       "hypotheses": ["go test -p unbounded", "cargo jobs", "pytest -n"]}))
    idle = g("idle_minutes")
    if idle is not None and idle >= s["queue.idle_room_minutes"]:
        out.append(_c("IDLE_ROOM", "IDLE_ROOM", "INFO", "slots idle %.0f min, nothing waiting, machine GREEN" % idle))

    # --- other sources
    fsev = g("fsev_mb")
    if fsev is not None and fsev > s["other.fseventsd_mb"]:
        out.append(_c("FSEV", "FSEV", "ATTENTION", "fseventsd uses %.0f MB" % fsev))
    c5m = g("cache5m")
    if c5m:
        m5, h1 = c5m.get("m5", 0), c5m.get("h1", 0)
        if m5 is not None and h1 is not None and m5 > s["other.cache_5m_min_tokens_m"] * 1e6:
            share = m5 * 100.0 / max(1, m5 + h1)
        else:
            share = None
        if share is not None and share > s["other.cache_5m_share_pct"]:
            out.append(_c("CACHE_5M", "CACHE_5M", "ATTENTION", "subagents wrote %.1fM tokens of 5-minute cache in 1 h (%.0f%%)"
                          % (m5 / 1e6, share)))
    if g("on_ac") is False:
        out.append(_c("POWER", "POWER", "ACTION", "machine on battery: timed jobs fail if it sleeps"))
    gap = g("resumed_gap_s")
    if gap:
        out.append(_c("RESUMED", "RESUMED", "INFO", "machine resumed after %.0f min asleep: timed calls across the gap may fail"
                      % (gap / 60)))
    r1 = g("recipient_wait")
    if r1 and r1[1] > s["other.recipient_tool_wait_minutes"] * 60:
        out.append(_c("RECIPIENT_WAIT", "RECIPIENT_WAIT", "ATTENTION", "%s's %s call has no result for %.0f min" % (nm["recipient"], r1[0], r1[1] / 60),
                      investigate={"question": "Is the recipient's session stalled?", "hypotheses": ["hook stall", "long command"]}))
    for name, why in (g("stale_sources") or {}).items():
        level = "ACTION" if name == "memory-guard" else "ATTENTION"
        out.append(_c("SOURCE_STALE:" + name, "GUARD_DOWN" if name == "memory-guard" else "SOURCE_STALE", level,
                      "source %s is stale: %s" % (name, why)))
    # --- the guarded trim and the owner's cleanup list
    tr = g("trim") or {}
    if tr.get("event"):
        name, level, text = tr["event"]
        out.append(_c("TRIM:" + name, name, level, text))
    if tr.get("needed_min") and g("trim_needed_ok"):
        out.append(_c("TRIM_NEEDED", "TRIM_NEEDED", "ACTION",
                      "disk < %g GB and no drained queue moment for %.0f min: run the cache trim yourself"
                      % (s["disk.low_gb"], tr["needed_min"]), command=TRIM_CMD))
    cl = g("cleanup")
    if cl and cl.get("count"):
        level = "ATTENTION" if disk is not None and disk < s["disk.cache_action_disk_gb"] else "INFO"
        top = "; ".join("%s %s (%s)" % (i["rule"], i["path"], _gb(i.get("bytes"))) for i in cl.get("top", [])[:3])
        out.append(_c("CLEANUP_LIST", "CLEANUP_LIST", level,
                      "%d delete candidates for %s, %s; largest: %s" % (cl["count"], nm["recipient"], _gb(cl.get("bytes")), top),
                      command="mm cleanup",
                      value=(cl.get("bytes") or 0) / 1e9, band=10))
    for p in g("link_skipped") or []:
        out.append(_c("LINK_SKIPPED:" + _h(p), "LINK_SKIPPED", "ATTENTION",
                      "a configured delete or prune path goes through a link (or out of its folder); skipped: %s" % p,
                      command="ls -ld " + shlex.quote(p)))
    for rid, err in g("deletes_failed") or []:
        out.append(_c("DELETES_FAILED:" + str(rid), "DELETES_FAILED", "ATTENTION",
                      "deletes: %s failed: %s (the other rules and the cleanup list still run)" % (rid, err)))
    # --- the queue's slot and ticket files: a path there that is not a regular file counts as not held
    for p in g("slot_not_a_file") or []:
        out.append(_c("SLOT_NOT_A_FILE:" + _h(p), "SLOT_NOT_A_FILE", "ATTENTION",
                      "a queue slot or ticket path is not a regular file (a link or a FIFO); counted as not held, "
                      "never paused through: %s" % p, command="ls -ld " + shlex.quote(p)))
    # --- the pause: a process that is not the queue launcher had the newest call's slot file open
    pr = g("pause_refused")
    if pr:
        pids = ",".join(str(x) for x in pr.get("pids") or [])
        out.append(_c("PAUSE_REFUSED", "PAUSE_REFUSED", "ATTENTION", pr["text"],
                      command="ps -o pid=,command= -p " + pids if pids else "mm status"))

    # --- the tool itself
    for prob in g("readings_mismatch") or []:
        out.append(_c("READINGS_MISMATCH", "READINGS_MISMATCH", "ACTION",
                      "fast readings disagree with the macOS commands (%s); using the commands" % prob[:120],
                      command="mm check"))
        break
    off = g("off")
    if off:
        out.append(_c("OFF", "OFF", "ATTENTION", "automatic actions are off since %s (%s); readings and alerts go on"
                      % (off.get("since", "?"), (off.get("reason") or "")[:60]), command="mm on"))

    for pid, rc in g("jobs_dead") or []:
        out.append(_c("JOB_DEAD:%d" % pid, "JOB_DEAD", "ATTENTION",
                      "pid %d in %s is dead and its rc file is missing: %s" % (pid, nm["jobs_file"], rc)))
    return out
