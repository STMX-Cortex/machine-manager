# SPDX-License-Identifier: Apache-2.0
"""`mm drill memory`: a controlled memory load that tests the AMBER response and the alert path. It never aims at RED.

Preconditions (else one refusal line): schedule.tick_s is at most 20 s (status.json then stays within STATUS_FRESH_S
between two ticks); the queue has 0 busy and 0 waiting; the memory guard is alive; the supervisor's status is fresh; no
other drill runs (a lock). It fills memory in steps inside ONE child process (random bytes in every page, so the compressor cannot shrink them),
reads after each step, and stops at the first of: the supervisor reports AMBER (or RED), the floor (RED free line + 10
points, also predicted one step ahead), the cap (never more than the room above the floor at the start plus one step),
memory not used (3 steps add memory but free falls under 1 point or under a quarter of the added share), swap growth over the AMBER line, the time limit,
Ctrl-C or SIGTERM. Any stop or
error kills the child at once, so all its memory goes back. One result file records each step and the outcome.
Pass: the supervisor reached AMBER, a slot decision line (WOULD or SET) followed, and the alert reached the hook path.
"""
import fcntl
import json
import os
import signal
import subprocess
import sys
import time

import mmcore
import mmdecide
import mmread

MB = 1 << 20
# A drill safety limit, kept stricter than other.status_fresh_s: the drill starts, and trusts the supervisor's state
# (its AMBER stop), only while status.json is at most 30 s (3 ticks at the default schedule.tick_s) old. A tick of
# more than STATUS_FRESH_S / 1.5 (20 s) can leave status.json older than that between two ticks: the drill refuses.
STATUS_FRESH_S = 30


def fill(mb):
    """mb MB that no compressor can shrink: fresh random bytes in every page. (2026-10-14: one written byte per page
    left the pages almost all zero; the macOS compressor stored them about 7.5 to 1 and the drill held 18 GB of
    a 16 GB Mac with free memory still at 76%.)"""
    b = bytearray(mb * MB)
    for i in range(mb):
        b[i * MB:(i + 1) * MB] = os.urandom(MB)
    return b


def child_main():
    """The child's loop: one line in (MB to add), one line out (MB held)."""
    blocks = []
    for line in sys.stdin:
        blocks.append(fill(int(line)))
        print(sum(len(x) for x in blocks) // MB, flush=True)


CHILD = "import sys; sys.path.insert(0, %r); import mmdrill; mmdrill.child_main()" % os.path.dirname(os.path.abspath(__file__))


class Child:
    """The memory holder: one process; grow(mb) blocks until the pages are written."""

    def __init__(self):
        self.p = subprocess.Popen([sys.executable, "-I", "-c", CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True, start_new_session=True)

    def grow(self, mb):
        self.p.stdin.write("%d\n" % mb)
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("the drill child ended")
        return int(line)

    def release(self):
        if self.p.poll() is None:
            self.p.kill()
        self.p.wait(timeout=10)


def total_mb():
    if mmread.plat.SERVICE == "systemd":
        return mmread.machine_facts().get("ram_mb") or 0
    return (mmread.sysctl_int("hw.memsize") or 0) / 2**20


def live_reader(now):
    """Readings and the supervisor's state, as the drill sees them."""
    sample, _ = mmread.memory_sample(now)
    st = mmcore.read_json(mmcore.path("status.json"), {}) or {}
    fresh = now - float(st.get("time", 0)) < STATUS_FRESH_S
    return {"free_pct": sample.get("free_pct"), "swap_used_mb": sample.get("swap_used_mb"), "comp_mb": sample.get("comp_mb"),
            "state": st.get("state") if fresh else None, "status_fresh": fresh}


def preconditions(profile, queue, now, s=None):
    """None when the drill may start; else the refusal line."""
    most = STATUS_FRESH_S / 1.5
    if s is not None and s["schedule.tick_s"] > most:
        return ("E_DRILL schedule.tick_s %g is over %g s: the drill trusts status.json only up to %g s old; fix: set "
                "schedule.tick_s to %g or less for the drill" % (s["schedule.tick_s"], most, STATUS_FRESH_S, most))
    if queue is not None:
        try:
            q = queue.read(now)
        except OSError as e:
            return "E_DRILL queue unreadable: %s; fix: check profile queue.dir" % e
        if q.get("busy") or q.get("tickets"):
            return "E_DRILL queue busy=%d waiting=%d; fix: run the drill when the queue is empty" % (
                len(q.get("busy", [])), len(q.get("tickets", [])))
    mg = profile.get("memory_guard") or {}
    if mg.get("state_file"):
        sw = mmcore.read_json(mmcore.expand(mg["state_file"]), None)
        age = now - float(sw.get(mg.get("heartbeat_key", "heartbeat_epoch"), 0)) if isinstance(sw, dict) else None
        if age is None or age > mg.get("max_age_s", 60):
            return "E_DRILL memory guard not alive; fix: start the memory guard first"
    st = mmcore.read_json(mmcore.path("status.json"), None)
    if not isinstance(st, dict) or now - float(st.get("time", 0)) > STATUS_FRESH_S:
        return "E_DRILL supervisor status not fresh; fix: mm start, then retry"
    return None


def run(profile, s, queue=None, step_mb=512, settle_s=25, time_limit_s=900, reader=live_reader, child_factory=Child,
        clock=time.time, sleep=time.sleep, total=None, after_s=60, probe=None):
    """Returns the result record (also written to drills/drill-<time>.json). Refusal: {'refused': line}."""
    now = clock()
    os.makedirs(mmcore.path("drills"), exist_ok=True)
    with open(mmcore.path("drills", ".lock"), "a") as lockf:
        try:
            fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"refused": "E_DRILL another drill runs; fix: wait for it"}
        return _run_locked(profile, s, queue, step_mb, settle_s, time_limit_s, reader, child_factory, clock, sleep, total,
                           after_s, probe, now)


def _run_locked(profile, s, queue, step_mb, settle_s, time_limit_s, reader, child_factory, clock, sleep, total, after_s,
                probe, now):
    why = preconditions(profile, queue, now, s)
    if why:
        return {"refused": why}
    total = total or total_mb()
    start = clock()
    r0 = reader(start)
    rec = mmcore.stamp({"kind": "drill", "drill": "memory", "start": mmcore.now_local(start), "step_mb": step_mb,
                        "time_limit_s": time_limit_s, "floor_free_pct": s["slots.red_free_pct"] + 10, "steps": [],
                        "before": r0}, profile)
    interrupted = {"v": False}
    old = signal.signal(signal.SIGTERM, lambda *_: interrupted.update(v=True))
    child = None
    reason = None
    try:
        child = child_factory()
        held = 0
        recent = [[0, r0.get("free_pct")]]
        while True:
            r = reader(clock())
            reason = mmdecide.drill_stop({"elapsed_s": clock() - start, "time_limit_s": time_limit_s, "state": r.get("state"),
                                          "free_pct": r.get("free_pct"), "swap_used_mb": r.get("swap_used_mb"),
                                          "swap_start_mb": r0.get("swap_used_mb"), "step_mb": step_mb, "total_mb": total,
                                          "interrupted": interrupted["v"], "held_mb": held,
                                          "free_start_pct": r0.get("free_pct"), "recent": recent[-4:]}, s)
            if reason:
                break
            held = child.grow(step_mb)
            sleep(settle_s)
            r = reader(clock())
            recent.append([held, r.get("free_pct")])
            rec["steps"].append({"t": round(clock() - start, 1), "held_mb": held, "free_pct": r.get("free_pct"),
                                 "swap_used_mb": r.get("swap_used_mb"), "comp_mb": r.get("comp_mb"), "state": r.get("state")})
    except KeyboardInterrupt:
        reason = "interrupted"
    except Exception as e:  # any error: release at once, record it
        reason = "error: %r" % e
    finally:
        if child is not None:
            child.release()
        signal.signal(signal.SIGTERM, old)
    stop_t = clock()
    rec["stop_reason"] = reason
    rec["stop_s"] = round(stop_t - start, 1)
    sleep(after_s)  # the supervisor writes its decision and alert lines; then the checks read them
    rec["checks"] = evaluate(start, stop_t, reason, probe)
    rec["passed"] = all(rec["checks"].values())
    f = mmcore.path("drills", "drill-%s.json" % time.strftime("%Y%m%d-%H%M%S", time.localtime(start)))
    mmcore.write_atomic(f, json.dumps(rec, indent=1))
    rec["file"] = f
    return rec


def evaluate(start, stop_t, reason, probe=None):
    """The pass checks: AMBER reached (the stop reason), a slot decision line after the start, the MEM alert pushed and
    visible through the hook path (a probe session's first read of the active alerts)."""
    amber = isinstance(reason, str) and reason.startswith("supervisor ")
    lines = []
    try:
        with open(mmcore.path("state", "decisions.log"), newline="") as f:  # records end only at line feeds (C-22)
            lines = [line for line in mmcore.mmtext.split_lines(f.read())[-200:]
                     if " slots " in line and ("WOULD" in line or "SET" in line)]
    except OSError:
        pass
    t0 = mmcore.now_local(start)
    decision = any(l[:19] >= t0 and "AMBER" in l or l[:19] >= t0 and "RED" in l for l in lines)
    pushed = [r for r in mmcore.read_pushed(0) if r.get("name") in ("MEM_AMBER", "MEM_RED") and r.get("time", "") >= t0]
    seen = False
    if probe is None:
        import ad_deliver_claude

        def probe():
            return ad_deliver_claude.take_unseen("drill-probe-%d" % int(start), 2, time.time())
    try:
        seen = any(r.get("name") in ("MEM_AMBER", "MEM_RED") for r in probe())
    except Exception:
        seen = False
    return {"amber_reached": amber, "slot_decision": decision, "alert_pushed": bool(pushed), "alert_in_hook": seen}
