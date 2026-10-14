# SPDX-License-Identifier: Apache-2.0
"""machine-manager supervisor: readings, the machine state, the slot controller, the alerts, the deletes, the trim.

One tick every 10 s (`mm run`). Each tick writes status.json (the machine's status record and heartbeat) atomically.
Safety actions are local and never wait on the network; slow reads (sizes, the pool, the delete scan) run in threads.
Modes: observe (settings mode.observe) and the off switch (`mm off`) turn every action into a logged WOULD line;
--dry-run reads live data and writes only into its data folder.
"""
import collections
import json
import os
import queue as queue_mod
import signal
import subprocess
import sys
import threading
import time

import mmadapters
import mmalerts
import mmcore
import mmdecide
import mmdelete
import mmevidence
import mmread
import mmrecover

KERNEL_PREDICATE = ('sender == "kernel" AND eventMessage CONTAINS "memorystatus" AND '
                    '(eventMessage CONTAINS "suspending" OR eventMessage CONTAINS "no paging space")')
TICK_ERRORS_ALERT = 3
FALLBACK_REPEAT = {"repeat.action_minutes": 30, "repeat.attention_hours": 3, "repeat.clear_after_minutes": 5}
CHECK_EVERY_S = 86400
EXIT_RESTART = 75  # a self-check restart: launchd starts the supervisor again (KeepAlive)
STOP_DEADLINE_S = 8  # without settings: s from a SIGTERM to the forced end (under the plist's ExitTimeOut)
HELD_REBOOT_S = 3600
HELD_SELF_S = 1800


class KernelStream:
    """A child `log stream` that reports the two memorystatus events; restarted when it ends (at most once a minute)."""

    def __init__(self, argv=None):
        self.argv = argv or ["/usr/bin/log", "stream", "--style", "ndjson", "--predicate", KERNEL_PREDICATE]
        self.proc, self.events, self.started = None, queue_mod.Queue(), 0.0

    def ensure(self):
        if self.proc is not None and self.proc.poll() is None:
            return True
        if time.time() - self.started < 60:
            return False
        self.started = time.time()
        try:
            self.proc = subprocess.Popen(self.argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except OSError:
            self.proc = None
            return False
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()
        return True

    def _read(self, proc):
        for line in proc.stdout:
            ev = mmread.parse_kernel_line(line)
            if ev:
                self.events.put(ev)

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def drain(self):
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue_mod.Empty:
                return out

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()


class Worker:
    """One slow job at a time in a thread; its result is picked up by the loop."""

    def __init__(self, fn):
        self.fn, self.thread, self.result, self.error, self.started = fn, None, None, None, None

    def busy(self):
        return self.thread is not None and self.thread.is_alive()

    def kick(self, *args):
        if self.busy():
            return False
        self.started = time.time()

        def run():
            try:
                self.result, self.error = self.fn(*args), None
            except Exception as e:  # a failed slow job is reported, never fatal
                self.error = repr(e)[:300]
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        return True

    def take(self):
        r, self.result = self.result, None
        return r


def sizes_job(paths, delivery):
    sizes = {}
    for name, p in paths.items():
        rc, out = mmread.run(["/usr/bin/nice", "-n", "19", "/usr/bin/du", "-sk", mmcore.expand(p)], timeout=1800)
        try:
            sizes[name] = int(out.split()[0]) * 1024 / 1e9 if rc == 0 else None
        except (IndexError, ValueError):
            sizes[name] = None
    return {"sizes": sizes, "cache5m": delivery.cache_5m(time.time()) if delivery else None, "at": time.time()}


def deletes_job(s, now, enabled, ctx, with_list, live_spec, mid):
    run = mmdelete.Run(s, ctx, enabled=enabled, now=now, live_spec=live_spec, mid=mid)
    run.all()
    res = {"time": now, "enabled": enabled, "would_bytes": run.would, "freed_bytes": run.freed,
           "keep": sum(1 for l in run.lines if " KEEP " in l), "lines": len(run.lines)}
    if with_list:
        items = mmdelete.cleanup_list(ctx, now)
        mmcore.write_atomic(mmcore.path("state", "cleanup-list.json"),
                            json.dumps(mmcore.stamp({"time": now, "items": items}, mid=mid), indent=1))
        res["cleanup"] = {"time": now, "count": len(items), "bytes": sum(i["bytes"] or 0 for i in items),
                          "top": sorted(items, key=lambda i: -(i["bytes"] or 0))[:5]}
    mmcore.write_atomic(mmcore.path("state", "deletes-last.json"), json.dumps(res, sort_keys=True))
    return res


def _tail(f):
    try:
        with open(f) as fh:
            lines = [l.strip() for l in fh.read().splitlines() if l.strip()]
        return mmcore.mask(lines[-1][:200]) if lines else ""
    except OSError:
        return ""


class Trim:
    """The guarded cache trim. It starts only with the cache condition, a drained queue (0 busy, 0 tickets, no live tool
    by name) for trim.drained_minutes, and actions on. It takes an exclusive queue call itself (the queue adapter's
    exclusive_argv with bin/cachetrim.py), then warms the cache with an ordinary shared call (profile trim.warm_argv)."""

    def __init__(self, state, queue, cfg, live_spec, mid=None):
        self.mid = mid or mmcore.machine_id()
        self.st = state.setdefault("trim", {})
        self.q, self.cfg, self.live = queue, cfg, live_spec
        self.cache = mmcore.expand(cfg.get("cache", ""))

    def _rc(self, phase):
        try:
            with open(mmcore.path("state", "trim-%s.rc" % phase)) as f:
                return int(f.read().split()[0])
        except (OSError, ValueError, IndexError):
            return None

    def _start(self, phase, argv, now, env_extra):
        rcf = mmcore.path("state", "trim-%s.rc" % phase)
        try:
            os.remove(rcf)
        except OSError:
            pass
        out = open(mmcore.path("state", "trim-%s.out" % phase), "w")
        sh = '"$@"; echo $? > "$MM_RC_FILE"'
        p = subprocess.Popen(["/bin/sh", "-c", sh, "trim"] + argv, stdout=out, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, start_new_session=True,
                             env=dict(os.environ, MM_RC_FILE=rcf, **env_extra))
        out.close()
        self.st["running"] = {"phase": phase, "pid": p.pid, "started": now}
        self._proc = p

    def trim_argv(self, s, deletes_log):
        cmd = [sys.executable, "-I", os.path.join(mmcore.BIN, "cachetrim.py"), "--cache", self.cache,
               "--age", str(s["trim.age_minutes"]), "--wait", str(s["trim.wait_s"]), "--log", deletes_log,
               "--live", json.dumps(self.live), "--machine", self.mid]
        if self.cfg.get("marker_file"):
            cmd += ["--marker-file", self.cfg["marker_file"], "--marker-text", self.cfg.get("marker_text", "")]
        return self.q.exclusive_argv(cmd)

    def step(self, now, s, cond, drained, enabled, events, deletes_log):
        """Returns a dict for the alerts: {'event': (name, level, text)} and/or {'needed_min': m}."""
        out = {}
        if not self.cache or self.q is None:
            return out
        run = self.st.get("running")
        if run:
            proc = getattr(self, "_proc", None)
            if proc is not None:
                proc.poll()
            rc = self._rc(run["phase"])
            if rc is None and mmread.pid_alive(run["pid"]):
                return out
            self.st.pop("running")
            if run["phase"] == "trim":
                if rc == 0:
                    events.append("trim")
                    self.st["last_trim"] = now
                    self.st["event"] = ["TRIM_DONE", "INFO", "cache trim done: %s" % _tail(mmcore.path("state", "trim-trim.out")), now]
                    warm = self.cfg.get("warm_argv")
                    if warm:
                        self._start("warm", self.q.shared_argv([x.replace("{cache}", self.cache) for x in warm]), now, {})
                else:
                    self.st["event"] = ["TRIM_REFUSED", "ATTENTION", "cache trim refused or failed (rc=%s): %s"
                                        % (rc, _tail(mmcore.path("state", "trim-trim.out"))), now]
            else:
                self.st["warm_rc"] = rc
            return out
        ev = self.st.get("event")
        if ev and now - ev[3] < 3600:
            out["event"] = ev[:3]
        if not cond:
            self.st.pop("drained_since", None)
            self.st.pop("cond_since", None)
            return out
        self.st.setdefault("cond_since", now)
        if drained:
            self.st.setdefault("drained_since", now)
            self.st["last_drained"] = now
        else:
            self.st.pop("drained_since", None)
        last_drained = self.st.get("last_drained", self.st["cond_since"])
        if now - last_drained >= s["trim.needed_after_minutes"] * 60:
            out["needed_min"] = (now - last_drained) / 60
        ds = self.st.get("drained_since")
        if ds is None or now - ds < s["trim.drained_minutes"] * 60:
            return out
        if not enabled:
            if now - self.st.get("would_logged", 0) >= 3600:
                self.st["would_logged"] = now
                mmcore.append_line(deletes_log, "%s WOULD-TRIM rule=trim path=%s guard=pass: cache condition, drained %.0f s "
                                   "(actions off) machine=%s v=%d" % (mmcore.now_local(now), mmcore.log_path(self.cache),
                                                                       now - ds, self.mid, mmcore.SCHEMA_VERSION))
            return out
        self._start("trim", self.trim_argv(s, deletes_log), now, self.q.exclusive_env())
        return out


class Pauser:
    """At a critical RED, SIGSTOP the newest queue call's process tree; SIGCONT it after GREEN.
    Only pids it stopped itself: each pid and its start time go into state/paused.json BEFORE its SIGSTOP, so a crash
    or a hang never leaves a process stopped (mmrecover.resume_paused runs at every start, in safe mode, at stop and
    rollback, and from the watchdog when the supervisor is stale)."""

    def __init__(self, state=None):
        pass

    @property
    def st(self):
        return mmrecover.read_paused()

    @staticmethod
    def start_time(pid):
        return mmrecover.start_time(pid)

    def pause(self, busy, procs):
        holders = [b for b in busy if b.get("pid") and b.get("since")]
        if not holders or self.st:
            return None
        newest = max(holders, key=lambda b: b["since"])
        plan = {}
        for pid in mmread.descendants(procs, newest["pid"]):
            st = self.start_time(pid)
            if st:
                plan[str(pid)] = st
        mmrecover.add_paused(plan)
        failed = []
        for pid in plan:
            try:
                os.kill(int(pid), signal.SIGSTOP)
            except OSError:
                failed.append(pid)
        if failed:
            mmrecover.drop_paused(failed)
        return newest, sorted(int(p) for p in plan if p not in failed)

    def resume(self, why="green"):
        return mmrecover.resume_paused(why)


def critical(reasons):
    return any(r.startswith(("kernel pressure 4", "swap +", "compressor +")) for r in reasons)


class Supervisor:
    def __init__(self, profile, dry_run=False, kernel=True, allow_live_slots=False, clock=time.time, sampler=None,
                 sizes=True, slow_jobs=True, delete_extra=None, check_readings=True, boot=None):
        self.p = profile
        self.mid = mmcore.machine_id(profile)
        self.dry, self.allow_live = dry_run, allow_live_slots
        self.clock = clock
        self.sampler = sampler or mmread.memory_sample
        self.fallback = False
        self.check_on = check_readings and sampler is None
        self.sizes = sizes
        self.queue = mmadapters.queue(profile)
        self.pool = mmadapters.pool(profile)
        self.delivery = mmadapters.delivery(profile)
        self.settings = mmcore.Settings(real_slots=self.queue.slots_path() if self.queue else None)
        self.kernel = KernelStream() if kernel else None
        self.live_spec = profile.get("live_tools") or {}
        self.state = mmcore.read_json(mmcore.path("state", "controller.json"), {}) or {}
        offs = self.state.setdefault("offsets", {})

        def start(file, saved):  # first start: the end of a file that exists, 0 for a file not made yet
            if saved is not None:
                return saved
            try:
                return os.path.getsize(file)
            except OSError:
                return 0
        hf = self.queue.history_log() if self.queue else "/nonexistent"
        kf = mmcore.expand((profile.get("memory_guard") or {}).get("kills_log") or "/nonexistent")
        ef = mmcore.path("state", "events.jsonl")
        self.hist = mmread.Tail(hf, start(hf, offs.get("history")))
        self.kills = mmread.Tail(kf, start(kf, offs.get("kills")))
        self.events = mmread.Tail(ef, start(ef, offs.get("events")))
        self.window = collections.deque()
        self.ticks = None
        self.mono0, self.wall0 = time.monotonic(), clock()
        self.started = self.wall0
        self.last = {}
        self.cache = {"history_hour": [], "kernel_events": [], "kills_held": [], "refused": [], "resumed": None}
        self.tick_n = 0
        self.slow_jobs = slow_jobs
        self.delete_ctx = mmdelete.Ctx(profile.get("deletes") or {}, extra=delete_extra)
        self.bg = Worker(sizes_job)
        self.gh = Worker(self.pool.job) if self.pool else None
        self.deletes = Worker(deletes_job)
        self.trim = Trim(self.state, self.queue, profile.get("trim") or {}, self.live_spec, self.mid)
        self.cache["github"] = mmcore.read_json(mmcore.path("state", "github.json"), None)
        self.cache["deletes"] = mmcore.read_json(mmcore.path("state", "deletes-last.json"), None)
        self.counts = mmcore.read_json(mmcore.path("state", "counts.json"), {}) or {}
        self.free_pct = None
        os.makedirs(mmcore.path("state"), exist_ok=True)
        self.state.setdefault("held", {})
        self.self_state = {}
        self.reading_problems = []
        self.ping = Worker(mmrecover.ping)
        # every start: no process stays stopped by an earlier run (a crash or a kill during a pause)
        legacy = self.state.pop("paused", None)
        if mmrecover.read_paused() or legacy:
            got = mmrecover.resume_paused("start", legacy=legacy)
            self.log_decision("%s RESUME pids %s (start)" % (mmcore.now_local(self.wall0), got))
        self._boot_check(boot)

    def hold(self, key, name, level, text, until, command=None):
        """An event alert raised on every tick until `until` (kept in controller.json, so it outlives a restart)."""
        self.state.setdefault("held", {})[key] = {"name": name, "level": level, "text": text, "until": until,
                                                  "command": command}

    def save_state(self):
        mmcore.write_atomic(mmcore.path("state", "controller.json"), json.dumps(self.state, sort_keys=True))

    def _boot_check(self, boot):
        """At start: a Mac reboot since the last run (kern.boottime changed) gives MAC_REBOOTED (mmdecide.reboot_check)."""
        now = self.wall0
        try:
            cur = boot() if boot else {"boot_time": mmrecover.boot_time(), "panics": mmrecover.panic_names(),
                                       "missing_jobs": mmrecover.missing_jobs(
                                           (self.p.get("recovery") or {}).get("expected_jobs") or [])}
        except Exception as e:  # the check must never stop the start
            mmcore.append_line(mmcore.path("state", "errors.log"), mmcore.mask("%s boot check %r" % (mmcore.now_local(now), e)))
            return
        cur["now"] = now
        prev = mmrecover.boot_record()
        last = mmcore.read_json(mmcore.path("status.json"), None) or {}
        if isinstance(prev, dict):
            prev = dict(prev, last_tick=last.get("time"), last_state=last.get("state"), last_slots=last.get("slots"))
        r = mmdecide.reboot_check(prev, cur)
        if r:
            f = mmcore.path("state", "reboot-%s.json" % time.strftime("%Y%m%d-%H%M%S", time.localtime(now)))
            mmcore.write_atomic(f, json.dumps(mmcore.stamp(dict(r, previous=prev, current=cur), mid=self.mid),
                                              sort_keys=True, indent=1))
            self.hold("MAC_REBOOTED", "MAC_REBOOTED", r["level"], r["text"], now + HELD_REBOOT_S, command="mm explain MAC_REBOOTED")
            mmrecover.log("MAC_REBOOTED %s (%s)" % (r["text"], os.path.basename(f)), now)
        panics = cur.get("panics")
        if panics is None and isinstance(prev, dict):
            panics = prev.get("panics")  # unreadable now: keep the names seen before
        mmrecover.save_boot({"boot_time": cur.get("boot_time"), "panics": panics or [], "seen": now})

    def check_self(self, tick_s, tick_errors):
        """mmdecide.self_check on this tick's facts. Returns its result; the caller acts on "restart"."""
        s = self.settings.load()
        if not s:
            return {"action": "ok", "reasons": []}
        now = self.clock()
        rss = None
        for p in self.cache.get("procs") or []:
            if p["pid"] == os.getpid():
                rss = p["rss_mb"]
        writable, free = mmrecover.data_facts()
        safe = mmcore.safe_state()
        r = mmdecide.self_check(self.self_state, {
            "now": now, "rss_mb": rss, "tick_s": tick_s, "tick_errors": tick_errors,
            "reading_problems": self.reading_problems, "data_writable": writable, "data_free_mb": free,
            "slot_changes": self.state.get("slot_changes", []), "safe": bool(safe)}, s)
        self.self_state = r["state"]
        why = "; ".join(r["reasons"])
        if r["action"] == "restart":
            mmrecover.log("SELF RESTART: %s" % why, now)
            self.hold("SELF_RESTART", "SELF_RESTART", "ACTION", "machine-manager restarted itself: %s" % why,
                      now + HELD_SELF_S, command="mm status")
            mmrecover.resume_paused("self restart", now)
            self.save_state()
        elif r["action"] == "safe":
            mmrecover.enter_safe("self-check: " + why, now, self.mid)
            mmrecover.resume_paused("safe mode", now)
        elif r["action"] == "alert":
            self.hold("SELF_CHECK", "SELF_CHECK", "ATTENTION", "self-check in safe mode: %s" % why, now + HELD_SELF_S,
                      command="mm on")
            self.save_state()
        return r

    def due(self, name, every, now):
        if now - self.last.get(name, -1e18) >= every:
            self.last[name] = now
            return True
        return False

    def log_decision(self, line):
        mmcore.append_line(mmcore.path("state", "decisions.log"), mmcore.mask(line))

    def tick(self):
        now = self.clock()
        mono = time.monotonic()
        self.tick_n += 1
        s = self.settings.load()
        if s is None:
            st = mmcore.AlertStore(FALLBACK_REPEAT, clock=self.clock, mid=self.mid)
            st.begin()
            st.raise_("SETTINGS_BAD", "SETTINGS_BAD", "ACTION", "settings invalid and no last good values: the tool reads "
                      "and controls nothing: %s" % self.settings.problem, command="mm check")
            self._status(now, "UNKNOWN", ["no valid settings"], None, None, "no valid settings")
            return
        store = mmcore.AlertStore(s, clock=self.clock, mid=self.mid)
        store.begin()
        snap = {}
        off = mmcore.off_state()
        safe = mmcore.safe_state()
        observe = s["mode.observe"]
        writes_on = not observe and not off and not self.dry
        actions_on = writes_on and not safe
        snap["off"] = off
        # sleep detection: the wall clock moved more than the monotonic clock
        wall_d, mono_d = now - self.wall0, mono - self.mono0
        self.wall0, self.mono0 = now, mono
        if wall_d - mono_d > s["other.resume_gap_s"]:
            self.cache["resumed"] = (now, wall_d - mono_d)
        if self.cache["resumed"] and now - self.cache["resumed"][0] < 1800:
            snap["resumed_gap_s"] = self.cache["resumed"][1]

        # the macOS change check: at start and daily
        if self.check_on and self.due("readings_check", CHECK_EVERY_S, now):
            try:
                bad, _, _ = mmread.check_readings(now)
            except Exception as e:  # the check must never stop the loop
                bad = ["check failed: %r" % e]
            self.state["readings_check"] = {"time": now, "problems": bad}
            self.fallback = bool(bad)
            if bad:
                self.log_decision("%s READINGS_MISMATCH %s: the fallback sampler is on" % (mmcore.now_local(now), "; ".join(bad)))
        snap["readings_mismatch"] = (self.state.get("readings_check") or {}).get("problems") or []

        # fast memory sample, every tick
        sampler = mmread.command_sample if self.fallback else self.sampler
        sample, self.ticks = sampler(now, self.ticks)
        sample["sys_pct_interval"] = sample.pop("sys_pct", None)
        self.reading_problems = mmdecide.sample_problems(sample)
        if "sys_pct_fixture" in sample:
            sample["sys_pct"] = sample.pop("sys_pct_fixture")
        lp, ll_age = self.queue.last_sample(now) if self.queue else (None, None)
        # the sys rule uses the queue sampler's top-based value (the measure its thresholds use) when fresh
        if "sys_pct" not in sample:
            sample["sys_pct"] = lp["sys_pct"] if lp and ll_age is not None and ll_age < 150 else (
                None if self.queue else sample["sys_pct_interval"])
        self.window.append(sample)
        while self.window and now - self.window[0]["t"] > 1900:
            self.window.popleft()
        win = list(self.window)

        # kernel events (held 30 min for the alert, 2 min for RED)
        if self.kernel is not None:
            self.kernel.ensure()
            for ev in self.kernel.drain():
                ev["seen"] = now
                self.cache["kernel_events"].append(ev)
                mmcore.append_line(mmcore.path("state", "kernel.jsonl"), json.dumps(mmcore.mask_obj(ev)))
        self.cache["kernel_events"] = [e for e in self.cache["kernel_events"] if now - e["seen"] < 1800]
        snap["kernel_events"] = self.cache["kernel_events"]
        recent_kernel = any(now - e["seen"] < 120 for e in self.cache["kernel_events"])

        # disk every 5 min (trend over 6 h)
        if self.due("disk", 300, now) or "disk" not in self.cache:
            d = mmread.disk_free_gb()
            self.cache["disk"] = d
            hist = self.state.setdefault("disk_hist", [])
            if d is not None:
                hist.append([now, d])
            self.state["disk_hist"] = [x for x in hist if now - x[0] < 6 * 3600]
        snap["disk_gb"] = self.cache["disk"]
        snap["disk_rate_gb_h"] = mmdecide.disk_rate(self.state.get("disk_hist", []), now)

        mac_state, reasons, complete = mmdecide.classify(win, s, disk_gb=snap["disk_gb"], kernel_event=recent_kernel)
        snap["state"] = (mac_state, reasons)
        alt_win = [dict(x, sys_pct=x.get("sys_pct_interval")) for x in win]
        alt_state = mmdecide.classify(alt_win, s, disk_gb=snap["disk_gb"], kernel_event=recent_kernel)[0]
        self.counts = mmdecide.count_state(self.counts, {"now": now, "state": mac_state, "reasons": reasons,
                                                         "alt_state": alt_state})
        self.free_pct = sample.get("free_pct")

        # every 30 s: ps and the queue
        if self.due("ps", 30, now) or "procs" not in self.cache:
            self.cache["procs"] = mmread.read_ps()
            try:
                self.cache["queue"] = self.queue.read(now) if self.queue else None
            except OSError:
                self.cache["queue"] = None
            self._proc_facts(now)
        q = self.cache.get("queue")
        snap["queue"] = q
        snap.update({k: self.cache.get(k) for k in ("top_outside", "slot_cpu", "fsev_mb")})

        # every 60 s: history, kills, events, power, sources, the recipient
        events = []
        if self.due("minute", 60, now):
            self._minute(now, s, events)
        snap["history_hour"] = [c for c in self.cache["history_hour"] if now - c["end"] < 3600]
        snap["refused_recent"] = [c for c in self.cache["refused"] if now - c["end"] < 3600]
        snap["kills_new"] = [k for t, k in self.cache["kills_held"] if now - t < 1800]
        for k in ("on_ac", "stale_sources", "recipient_wait", "jobs_dead"):
            snap[k] = self.cache.get(k)
        if self.delivery and (self.due("usage", 300, now) or "usage" not in self.cache):
            self.cache["usage"] = self.delivery.usage(now)
        snap["usage"] = self.cache.get("usage")
        if self.sizes and self.p.get("sizes") and self.due("sizes", s["disk.sizes_interval_minutes"] * 60, now):
            self.bg.kick(self.p["sizes"], self.delivery)
        got = self.bg.take()
        if got:
            self.cache["sizes"] = got
        sz = self.cache.get("sizes") or {}
        if sz:
            snap["cache_gb"] = (sz.get("sizes") or {}).get("cache")
            snap["cache5m"] = sz.get("cache5m")

        # the pool reads, in a worker thread
        if self.slow_jobs and self.gh:
            got = self.gh.take()
            if got is not None:
                self.cache["github"] = got
                for k in self.pool.good_keys(got):  # a good read clears its SOURCE_STALE now, not 5 min later
                    store.clear(k)
            if self.due("gh", s["github.read_interval_s"], now) or self._watch_pending(now, s):
                self.gh.kick(s, now)
        gh = self.cache.get("github")
        first_read_pending = gh is None and now - self.started < s["github.stale_minutes"] * 60
        if self.pool and not first_read_pending:  # a fresh start is not a stale source
            names = self.p["names"]
            for c in self.pool.conditions(gh, s, now, mmalerts._c, names.get("owner", "the owner")):
                snap.setdefault("pool_conditions", []).append(c)
        # the deletion scan (WOULD-DELETE unless deletes are on) and the cleanup list
        deletes_on = s["deletes.enabled"] and actions_on
        if self.slow_jobs:
            got = self.deletes.take()
            if got is not None:
                self.cache["deletes"] = got
            last = self.state.get("cleanup_at", 0)
            if self.due("deletes", s["deletes.interval_minutes"] * 60, now):
                with_list = now - last >= s["deletes.cleanup_list_hours"] * 3600 or (
                    snap["disk_gb"] is not None and snap["disk_gb"] < s["disk.cache_action_disk_gb"] and now - last >= 3600)
                if self.deletes.kick(s, now, deletes_on, self.delete_ctx, with_list, self.live_spec, self.mid) and with_list:
                    self.state["cleanup_at"] = now
        dl = self.cache.get("deletes") or {}
        if dl.get("cleanup"):
            snap["cleanup"] = dl["cleanup"]
        # the guarded cache trim
        procs = self.cache.get("procs")
        drained = bool(q and not q.get("busy") and not q.get("tickets") and procs is not None
                       and not mmread.live_named(procs, self.live_spec))
        gc, dk = snap.get("cache_gb"), snap.get("disk_gb")
        cond = gc is not None and (gc > s["disk.cache_attention_gb"] or (dk is not None and dk < s["disk.cache_action_disk_gb"]))
        snap["trim"] = self.trim.step(now, s, cond, drained, deletes_on, events, mmcore.path("deletes.log"))
        snap["trim_needed_ok"] = dk is not None and dk < s["disk.low_gb"]

        # idle room
        idle_now = q and q.get("slots") and len(q["busy"]) < q["slots"] and not q["tickets"] and mac_state == "GREEN"
        if idle_now:
            self.state.setdefault("idle_since", now)
        else:
            self.state.pop("idle_since", None)
        if self.state.get("idle_since"):
            snap["idle_minutes"] = (now - self.state["idle_since"]) / 60

        # the slot controller
        if self.queue:
            self._control(now, s, mac_state, reasons, q, events, writes_on, safe)

        # alerts
        if self.settings.problem:
            store.raise_("SETTINGS_BAD", "SETTINGS_BAD", "ACTION", "settings invalid; the last good values stay: "
                         + self.settings.problem, command="mm check")
        active_before = set((mmcore.read_json(store.state_file, {}) or {}).get("active", {}))
        conds = mmalerts.evaluate(snap, s, now, active_before, self.p.get("names")) + snap.get("pool_conditions", [])
        conds += self._recovery_conditions(now, s, safe)
        for c in conds:
            store.raise_(c["key"], c["name"], c["level"], c["text"], value=c["value"], band=c["band"], worse=c["worse"],
                         command=c["command"], investigate=c["investigate"])
        store.finish(scope_prefixes=None)
        for rec in store.pushed:
            if rec["level"] == "ACTION" and self.delivery:
                self.delivery.banner(mmcore.alert_line(rec), s["banner.enabled"] and not self.dry)
            if rec.get("investigate") and rec.get("why") != "cleared":
                try:
                    mmevidence.bundle(rec, s, now, self.queue, extra={"sizes": sz.get("sizes"), "profile": self.p},
                                      usage_file=self.delivery.usage_file() if self.delivery else None)
                except Exception as e:  # a bundle is help, never a reason to stop the loop
                    mmcore.append_line(mmcore.path("state", "errors.log"), mmcore.mask("%s evidence %r" % (mmcore.now_local(now), e)))

        # the pause (the launch gate is in the hook)
        self._gate_and_pause(now, s, mac_state, reasons, actions_on, safe)

        # files
        active = (mmcore.read_json(store.state_file, {}) or {}).get("active") or {}
        self._status(now, mac_state, reasons, q, sample, "ok", active, s, observe, off, safe)
        if self.pool:
            self._pool_status(now, s, gh, active)
        if self.due("metrics", 60, now):
            self._metrics(now, sample, mac_state, q)
            mmcore.write_atomic(mmcore.path("state", "counts.json"), json.dumps(self.counts, sort_keys=True))
        self.state["offsets"] = {"history": self.hist.offset, "kills": self.kills.offset, "events": self.events.offset}
        self.save_state()

    def _recovery_conditions(self, now, s, safe):
        """Safe mode, held events (a reboot, a self restart), the watchdog's stamp and the dead-man ping."""
        out = []
        if safe:
            out.append(mmalerts._c("SAFE_MODE", "SAFE_MODE", "ACTION", "safe mode since %s: %s; automatic actions off"
                                   % (mmcore.now_local(safe.get("since"))[11:16], safe.get("reason", "?")), command="mm on"))
        held = self.state.setdefault("held", {})
        for k in [k for k, h in held.items() if h["until"] <= now]:
            held.pop(k)
        for k, h in sorted(held.items()):
            out.append(mmalerts._c(k, h["name"], h["level"], h["text"], command=h.get("command")))
        # the watchdog: installed runs only (the install record names this data folder)
        rec = mmcore.install_record()
        if not self.dry and rec and os.path.realpath(rec.get("data") or "/") == os.path.realpath(mmcore.data_dir()) \
                and not os.path.exists(mmcore.path("state", "stopped.json")):
            age = mmrecover.watchdog_age(now)
            if (age if age is not None else now - self.started) > s["self.watchdog_stale_s"]:
                text = "watchdog %s" % ("never ran" if age is None else "last ran %.0f s ago" % age)
                import mminstall
                wd = mminstall.labels(self.p)[1]
                if now - self.state.get("watchdog_kick", 0) >= 600:
                    self.state["watchdog_kick"] = now
                    self.state["watchdog_unloaded"] = None
                    if not mminstall.is_loaded(wd):  # kickstart needs a loaded service: load it again
                        rc = mminstall.bootstrap(wd)
                        self.state["watchdog_unloaded"] = rc
                        mmrecover.log("WATCHDOG_UNLOADED %s; bootstrap rc=%s" % (text, rc), now)
                    else:
                        rc, _ = mminstall.launchctl(["kickstart", "-k", "gui/%d/%s" % (os.getuid(), wd)])
                        mmrecover.log("WATCHDOG_STALE %s; kickstart rc=%s" % (text, rc), now)
                if self.state.get("watchdog_unloaded") is not None:
                    out.append(mmalerts._c("SELF_UNLOADED:watchdog", "SELF_UNLOADED", "ACTION",
                                           "the watchdog was not loaded; loaded it again (rc=%s)" % self.state["watchdog_unloaded"],
                                           command="mm status"))
                out.append(mmalerts._c("WATCHDOG_STALE", "WATCHDOG_STALE", "ATTENTION",
                                       text + "; restarted it; nothing restarts a stuck supervisor meanwhile",
                                       command="mm status"))
        # the outside dead-man ping (off unless heartbeat.url is set)
        if s["heartbeat.url"] and not self.dry:
            got = self.ping.take()
            if got:
                mmrecover.log_ping(got, now)
            if self.due("ping", s["heartbeat.every_min"] * 60, now):
                self.ping.kick(s["heartbeat.url"], s["heartbeat.timeout_s"])
        return out

    def _watch_pending(self, now, s):
        import ad_ci_github
        w = mmcore.read_json(ad_ci_github.watch_file(), {}) or {}
        if any(not v.get("done_at") for v in w.values()):
            return self.due("gh_watch", s["github.watch_interval_s"], now)
        return False

    def _proc_facts(self, now):
        procs, q = self.cache.get("procs"), self.cache.get("queue")
        if not procs:
            return
        in_slots, slot_cpu = set(), {}
        for b in (q or {}).get("busy", []):
            pids = mmread.descendants(procs, b.get("pid")) if b.get("pid") else []
            in_slots.update(pids)
            cpu = sum(p["cpu"] for p in procs if p["pid"] in set(pids)) / 100.0
            prev = self.state.get("slot_cpu_prev", {}).get(b["slot"])
            slot_cpu[b["slot"]] = min(cpu, prev) if prev is not None else 0.0  # sustained over 2 reads
            self.state.setdefault("slot_cpu_prev", {})[b["slot"]] = cpu
        outside = sorted((p for p in procs if p["pid"] not in in_slots), key=lambda p: -p["rss_mb"])[:3]
        self.cache["top_outside"] = [(os.path.basename(p["comm"]), p["rss_mb"]) for p in outside]
        self.cache["slot_cpu"] = slot_cpu
        fse = [p["rss_mb"] for p in procs if p["comm"].endswith("fseventsd")]
        self.cache["fsev_mb"] = max(fse) if fse else None

    def _minute(self, now, s, events):
        if self.queue:
            for line in self.hist.new_lines() or []:
                c = self.queue.parse_history(line)
                if not c:
                    continue
                self.cache["history_hour"].append(c)
                if c["mode"] in ("A", "P") or c["mem"] == "na":
                    self.cache["refused"].append(c)
        self.cache["history_hour"] = [c for c in self.cache["history_hour"] if now - c["end"] < 3600]
        self.cache["refused"] = [c for c in self.cache["refused"] if now - c["end"] < 3600]
        for line in self.kills.new_lines() or []:
            if line.strip():
                self.cache["kills_held"].append((now, line.strip()))
                events.append("guard-kill")
        self.cache["kills_held"] = [x for x in self.cache["kills_held"] if now - x[0] < 1800]
        for line in self.events.new_lines() or []:
            try:
                ev = json.loads(line)
                if ev.get("event") == "timing-failure":
                    events.append("timing-failure")
            except ValueError:
                pass
        rc, out = mmread.run(["/usr/bin/pmset", "-g", "batt"], timeout=10)
        self.cache["on_ac"] = mmread.parse_pmset(out) if rc == 0 else None
        stale = {}
        if self.queue:
            try:
                age = now - os.path.getmtime(self.queue.sample_log())
                if age > s["other.load_log_max_age_s"]:
                    stale["queue-sampler"] = "last line %.0f s old" % age
            except OSError:
                stale["queue-sampler"] = "missing"
        if self.delivery and self.delivery.usage_file():
            u = self.delivery.usage(now)
            if u is None:
                stale["usage"] = "state unreadable"
            elif u["age_s"] > s["usage.watch_state_max_age_s"]:
                stale["usage"] = "state %.0f min old" % (u["age_s"] / 60)
        mg = self.p.get("memory_guard") or {}
        if mg.get("state_file"):
            sw = mmcore.read_json(mmcore.expand(mg["state_file"]), None)
            sw_age = now - float(sw.get(mg.get("heartbeat_key", "heartbeat_epoch"), 0)) if isinstance(sw, dict) else None
            pid = int((sw or {}).get(mg.get("pid_key", "pid"), 0) or 0) if isinstance(sw, dict) else 0
            if sw_age is None or sw_age > mg.get("max_age_s", 60) or not mmread.pid_alive(pid):
                stale["memory-guard"] = "heartbeat %s" % ("missing" if sw_age is None else "%.0f s old or its pid is dead" % sw_age)
        if self.kernel is not None and not self.kernel.alive():
            stale["kernel-stream"] = "log stream is not running"
        if self.cache.get("procs") is None:
            stale["ps"] = "ps failed"
        self.cache["stale_sources"] = stale
        if self.delivery:
            self.cache["recipient_wait"] = self.delivery.open_tool_call(now)
            self.cache["jobs_dead"] = [(pid, rc) for pid, rc in self.delivery.jobs()
                                       if not mmread.pid_alive(pid) and not os.path.exists(rc)]

    def _control(self, now, s, mac_state, reasons, q, events, actions_on, safe=None):
        """actions_on: slot writes allowed by mode, the off switch and the dry run. In safe mode the count is once
        lowered to at most safe_mode.slots, and after that the controller may only lower it."""
        mode = s["mode.slot_writes"] if actions_on else "off"
        target_file = None
        if mode == "test":
            target_file = s["mode.slots_file"] or None
        elif mode == "live":
            target_file = self.queue.slots_path() if self.allow_live else None
        cur = None
        if target_file:
            try:
                with open(target_file) as f:
                    cur = int(f.read().split()[0])
            except (OSError, ValueError, IndexError):
                cur = None
        if cur is None:
            cur = self.state.get("virtual_slots") or (q or {}).get("slots") or s["slots.floor"]
        tickets = (q or {}).get("tickets", [])
        override = mmcore.read_json(mmcore.path("override.json"), None)
        r = mmdecide.slot_decide(self.state.get("controller") or {}, {
            "now": now, "mac_state": mac_state, "reasons": list(reasons), "slots": cur,
            "busy": len((q or {}).get("busy", [])), "waiting": len(tickets),
            "wx_waiting": any(t["mode"] in ("W", "X") for t in tickets), "override": override, "events": events}, s)
        self.state["controller"] = r["state"]
        if safe and safe.get("slot_write") is None:
            to = min(cur, s["safe_mode.slots"])
            r = {"slots": to, "why": "safe mode: at most %d slots" % s["safe_mode.slots"]} if to < cur else {"slots": None}
            mmrecover.mark_safe_slot_write("%s %d -> %d" % ("SET" if target_file else "WOULD", cur, to))
        elif safe and r["slots"] is not None and r["slots"] > cur:
            r = {"slots": None}  # safe mode: no raise
        if r["slots"] is None:
            self.state["virtual_slots"] = cur
            return
        if r["slots"] != cur:
            ch = [t for t in self.state.get("slot_changes", []) if now - t < 3600]
            self.state["slot_changes"] = ch + [now]
        line = "%s %s slots %d -> %d: %s" % (mmcore.now_local(now), "SET" if target_file else "WOULD", cur, r["slots"], r["why"])
        if mode == "live" and not self.allow_live:
            line += " (live writes refused: this run lacks --allow-live-slots)"
        if target_file:
            try:
                mmcore.write_slots(target_file, r["slots"])
            except OSError as e:
                line += " (write failed: %s)" % e
        self.state["virtual_slots"] = r["slots"]
        self.log_decision(line)

    def _gate_and_pause(self, now, s, mac_state, reasons, actions_on, safe=None):
        gate = self.state.setdefault("gate", {})
        if mac_state == "RED":
            gate.setdefault("red_since", now)
        else:
            gate.pop("red_since", None)
        if not s["pause_newest_call.enabled"]:
            return
        p = Pauser(self.state)
        q = self.cache.get("queue")
        if mac_state == "RED" and critical(reasons) and not p.st and q:
            busy = [b for b in q["busy"] if b.get("pid") and b.get("since")]
            if not actions_on:
                if busy and now - self.state.get("would_pause_at", 0) > 600:
                    self.state["would_pause_at"] = now
                    newest = max(busy, key=lambda b: b["since"])
                    self.log_decision("%s WOULD-PAUSE %s (actions off)" % (mmcore.now_local(now), newest.get("label")))
            else:
                got = p.pause(q["busy"], self.cache.get("procs") or [])
                if got:
                    self.log_decision("%s PAUSE %s pids %s" % (mmcore.now_local(now), got[0].get("label"), got[1]))
        if mac_state == "GREEN":
            gs = self.state.setdefault("green_for_pause", now)
            if p.st and now - gs >= s["pause_newest_call.resume_after_green_s"]:
                self.log_decision("%s RESUME pids %s" % (mmcore.now_local(now), p.resume()))
        else:
            self.state.pop("green_for_pause", None)
        if p.st and (mmcore.off_state() or self.dry or safe):
            why = "safe mode" if safe else "off switch"
            self.log_decision("%s RESUME pids %s (%s)" % (mmcore.now_local(now), p.resume(why), why))

    def _status(self, now, mac_state, reasons, q, sample, note, active=None, s=None, observe=None, off=None, safe=None):
        """status.json: the machine's status record and the heartbeat, every tick (schemas/status.schema.json)."""
        gate = self.state.get("gate", {})
        sample = sample or {}
        counts = {"ACTION": 0, "ATTENTION": 0, "INFO": 0}
        for a in (active or {}).values():
            counts[a.get("level", "INFO")] = counts.get(a.get("level", "INFO"), 0) + 1
        rec = mmcore.stamp({
            "kind": "machine", "time": now, "state": mac_state, "reasons": reasons, "red_since": gate.get("red_since"),
            "mode": "dry" if self.dry else ("off" if off else ("safe" if safe else ("observe" if observe else "act"))),
            "slots": (q or {}).get("slots"), "slots_would": self.state.get("virtual_slots"),
            "busy": len((q or {}).get("busy", [])), "waiting": len((q or {}).get("tickets", [])),
            "readings": {k: (round(sample[k], 2) if isinstance(sample.get(k), float) else sample.get(k))
                         for k in ("free_pct", "swap_used_mb", "swap_total_mb", "comp_mb", "pressure", "load5", "sys_pct")},
            "disk_gb": None if self.cache.get("disk") is None else round(self.cache["disk"], 1),
            "sampler": "commands" if self.fallback else "fast",
            "alerts": counts,
            "heartbeat": {"pid": os.getpid(), "tick": self.tick_n, "note": note}}, mid=self.mid)
        mmcore.write_atomic(mmcore.path("status.json"), json.dumps(rec, sort_keys=True))

    def _pool_status(self, now, s, gh, active):
        keys = [k for k, a in active.items() if a.get("name", "").startswith(("GH_", "GUARD")) or k.endswith(":gh")]
        rec = self.pool.status(gh, s, now, keys)
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in self.pool.id)
        mmcore.write_atomic(mmcore.path("pools", safe + ".json"), json.dumps(rec, sort_keys=True))

    def _metrics(self, now, sample, mac_state, q):
        f = mmcore.path("metrics.csv")
        cols = ["time", "machine_id", "state", "free_pct", "swap_used_mb", "swap_total_mb", "comp_mb", "pressure", "seg_pct",
                "load1", "load5", "sys_pct", "sys_pct_interval", "slots", "busy", "waiting", "disk_gb"]
        row = {"time": mmcore.now_local(now), "machine_id": self.mid, "state": mac_state,
               "slots": self.state.get("virtual_slots"), "busy": len((q or {}).get("busy", [])),
               "waiting": len((q or {}).get("tickets", [])), "disk_gb": self.cache.get("disk"),
               **{k: sample.get(k) for k in cols if k in sample}}
        new = not os.path.exists(f)
        try:
            if not new and os.path.getsize(f) > 8 << 20:
                os.replace(f, f + ".1")  # rotation of its own log
                new = True
        except OSError:
            pass
        with open(f, "a") as out:
            if new:
                out.write(",".join(cols) + "\n")
            out.write(",".join("" if row.get(c) is None else (("%.2f" % row[c]) if isinstance(row[c], float) else str(row[c]))
                               for c in cols) + "\n")


def _stop_deadline(stop):
    """The tick did not end after a SIGTERM: end now (the run is already marked clean)."""
    try:
        mmrecover.log("STOP deadline: the tick did not end in %g s after SIGTERM; killed %d commands; exit"
                      % (stop["deadline_s"], mmread.kill_children()))
        sup = stop.get("sup")
        if sup is not None and sup.kernel is not None:
            sup.kernel.stop()
        mmrecover.resume_paused("exit")
    finally:
        os._exit(0)


def run_loop(profile, dry_run=False, ticks=0, duration=0, tick_seconds=10, kernel=True, allow_live_slots=False):
    """The supervisor's life. At start: the unclean-start count (mmrecover.note_start); at 3 in 15 min, safe mode.
    Each tick: the tick, then the self-check. Ends with 0 when stopped (SIGTERM) or done, and with EXIT_RESTART when the
    self-check asks for a restart (launchd starts it again; that start counts as unclean).
    A SIGTERM is a planned stop, so it is clean whatever comes next: the handler marks the run clean at once, the wait
    between ticks ends at once, and a tick that does not end in self.stop_deadline_s is cut: its commands are killed,
    paused processes continued, and the process ends (2026-10-14: launchd's 5 s ExitTimeOut killed a stop mid-tick)."""
    stop = {"now": False, "sup": None, "deadline_s": STOP_DEADLINE_S}

    def on_term(*_):
        if stop["now"]:
            return
        stop["now"] = True
        try:
            mmrecover.note_clean_exit()
        except Exception:
            pass
        t = threading.Timer(stop["deadline_s"], _stop_deadline, args=(stop,))
        t.daemon = True
        stop["timer"] = t
        t.start()
    signal.signal(signal.SIGTERM, on_term)  # first: a SIGTERM during the start still ends clean
    st0 = mmcore.Settings().load() or mmcore.resolve(mmcore.defaults())
    stop["deadline_s"] = st0.get("self.stop_deadline_s", STOP_DEADLINE_S)
    mid = mmcore.machine_id(profile)
    loop, unclean, _ = mmrecover.note_start(time.time(), st0)
    mmrecover.starting_status(time.time(), mid)  # a heartbeat at once: the watchdog sees a live start
    if loop["safe"]:
        mmrecover.enter_safe("%d unclean starts in %g min (crash loop)" % (len(loop["starts"]), st0["self.crash_loop_minutes"]),
                             time.time(), mid)
    if unclean:
        mmrecover.log("START after an unclean end (%d unclean starts inside %g min)"
                      % (len(loop["starts"]), st0["self.crash_loop_minutes"]))
    t0, n, errors = time.monotonic(), 0, 0
    code, ended, sup = 0, False, None
    try:
        sup = Supervisor(profile, dry_run=dry_run, kernel=kernel, allow_live_slots=allow_live_slots)
        stop["sup"] = sup
        while not stop["now"]:
            start = time.monotonic()
            try:
                sup.tick()
                errors = 0
            except Exception as e:  # one bad tick must not end the loop; status.json says why
                errors += 1
                try:
                    sup._status(time.time(), "UNKNOWN", ["tick error"], None, None, "tick error: %s" % str(e)[:200])
                    mmcore.append_line(mmcore.path("state", "errors.log"), mmcore.mask("%s %r" % (mmcore.now_local(), e)))
                    if errors == TICK_ERRORS_ALERT:
                        st = mmcore.AlertStore(FALLBACK_REPEAT, mid=sup.mid)
                        st.begin()
                        st.raise_("SUPERVISOR_ERROR", "SUPERVISOR_ERROR", "ACTION",
                                  "ticks fail %d times in a row: %r" % (errors, e), command="mm explain SUPERVISOR_ERROR")
                except Exception:
                    pass
            try:
                r = sup.check_self(time.monotonic() - start, errors)
            except Exception as e:  # the self-check must never end the loop by itself failing
                r = {"action": "ok"}
                mmcore.append_line(mmcore.path("state", "errors.log"), mmcore.mask("%s self-check %r" % (mmcore.now_local(), e)))
            if r["action"] == "restart":
                code = EXIT_RESTART
                break
            n += 1
            if ticks and n >= ticks or duration and time.monotonic() - t0 >= duration:
                break
            end = start + tick_seconds
            while not stop["now"] and time.monotonic() < end:  # a SIGTERM ends the wait at once
                time.sleep(min(0.2, max(0.0, end - time.monotonic())))
        ended = True
    finally:
        stop["now"] = True  # a SIGTERM from here on needs no deadline: the end is near
        mmread.kill_children()
        if sup is not None and sup.kernel is not None:
            sup.kernel.stop()
        if code == 0:
            mmrecover.resume_paused("exit")
        if ended and code == 0:
            mmrecover.note_clean_exit()
        if stop.get("timer") is not None:  # the end came in time: no forced exit after the return
            stop["timer"].cancel()
    return code
