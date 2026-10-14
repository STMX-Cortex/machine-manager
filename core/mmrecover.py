# SPDX-License-Identifier: Apache-2.0
"""machine-manager self-recovery: the paused-process record, unclean starts and the crash-loop guard, safe mode,
the Mac reboot check, the watchdog's stamp and the outside dead-man ping.

The decisions are the pure functions in mmdecide (sample_problems, self_check, crash_loop, resume_targets,
reboot_check); this module gathers their facts and keeps their files in the data folder:
  state/paused.json    {pid: start time} of every process the pause stopped; written BEFORE the SIGSTOP
  state/run.json       {pid, started, clean}: clean is set only when a run ends by itself (SIGTERM, ticks done)
  state/starts.json    the times of unclean starts (for the crash-loop guard)
  safe.json            safe mode: {safe, since, reason, slot_write}
  state/boot.json      the boot time, the last tick, state and slots, the panic report names
  state/watchdog.stamp the watchdog's last run (its time as text)
  state/recovery.log   one line per recovery step
The tool never reboots the Mac and never signals a process it did not pause itself.
"""
import json
import os
import re
import signal
import struct
import time
import urllib.parse
import urllib.request

import mmcore
import mmdecide
import mmread

PANIC_DIR = "/Library/Logs/DiagnosticReports"


def log(line, now=None):
    mmcore.append_line(mmcore.path("state", "recovery.log"), mmcore.mask("%s %s" % (mmcore.now_local(now), line)))


# ------------------------------------------------------------------------------------------- paused processes

def paused_file():
    return mmcore.path("state", "paused.json")


def _lock():
    return mmcore.Locked(mmcore.path("state", "paused.lock"))


def start_time(pid):
    """The process start time as ps prints it (lstart), or None when the pid is gone."""
    rc, out = mmread.run(["/bin/ps", "-o", "lstart=", "-p", str(int(pid))], timeout=5)
    return (out.strip() or None) if rc == 0 else None


def read_paused():
    d = mmcore.read_json(paused_file(), {})
    return {str(k): v for k, v in d.items()} if isinstance(d, dict) else {}


def add_paused(entries):
    """Record {pid: start time} before the pids are stopped, so a crash after the SIGSTOP never loses them."""
    with _lock():
        d = read_paused()
        d.update({str(k): v for k, v in entries.items()})
        mmcore.write_atomic(paused_file(), json.dumps(d, sort_keys=True))


def drop_paused(pids):
    with _lock():
        d = read_paused()
        for p in pids:
            d.pop(str(p), None)
        mmcore.write_atomic(paused_file(), json.dumps(d, sort_keys=True))


def resume_paused(why, now=None, legacy=None):
    """SIGCONT every recorded pid whose start time still matches (mmdecide.resume_targets), then forget the record.
    `legacy`: an older record kept in controller.json ({pid: start}). Returns the pids continued."""
    try:
        with _lock():
            d = read_paused()
            d.update({str(k): v for k, v in (legacy or {}).items()})
            if not d:
                return []
            cur = {p: start_time(p) for p in d}
            done = []
            for pid in mmdecide.resume_targets(d, cur):
                try:
                    os.kill(pid, signal.SIGCONT)
                    done.append(pid)
                except OSError:
                    pass
            mmcore.write_atomic(paused_file(), "{}")
    except (OSError, TimeoutError) as e:
        log("RESUME failed (%s): %r" % (why, e), now)
        return []
    skipped = sorted(int(p) for p in d if int(p) not in done)
    log("RESUME pids %s skipped %s (%s)" % (done, skipped, why), now)
    return done


# ------------------------------------------------------------------------------------------- starts and safe mode

def note_start(now, s):
    """Record this start. An unclean start (the run before did not end by itself) counts for the crash-loop guard.
    Returns (crash_loop result, unclean, the previous run record)."""
    prev = mmcore.read_json(mmcore.path("state", "run.json"), None)
    unclean = isinstance(prev, dict) and not prev.get("clean")
    starts = mmcore.read_json(mmcore.path("state", "starts.json"), [])
    starts = [t for t in starts if isinstance(t, (int, float))] if isinstance(starts, list) else []
    if unclean:
        starts.append(now)
    r = mmdecide.crash_loop(starts, now, s)
    mmcore.write_atomic(mmcore.path("state", "starts.json"), json.dumps(r["starts"]))
    mmcore.write_atomic(mmcore.path("state", "run.json"), json.dumps({"pid": os.getpid(), "started": now, "clean": False}))
    return r, unclean, prev


def note_clean_exit():
    f = mmcore.path("state", "run.json")
    rec = mmcore.read_json(f, None)
    if isinstance(rec, dict) and rec.get("pid") == os.getpid():
        rec["clean"] = True
        mmcore.write_atomic(f, json.dumps(rec))


def enter_safe(reason, now, mid=None):
    """Turn safe mode on (once; a second reason does not replace the first). Returns the record."""
    cur = mmcore.safe_state()
    if cur:
        return cur
    rec = mmcore.stamp({"safe": True, "since": now, "reason": reason[:300], "slot_write": None}, mid=mid)
    mmcore.write_atomic(mmcore.path("safe.json"), json.dumps(rec, sort_keys=True))
    log("SAFE MODE on: %s" % reason, now)
    return rec


def mark_safe_slot_write(text):
    f = mmcore.path("safe.json")
    rec = mmcore.read_json(f, None)
    if isinstance(rec, dict) and rec.get("safe"):
        rec["slot_write"] = text
        mmcore.write_atomic(f, json.dumps(rec, sort_keys=True))


def clear_safe(why):
    """End safe mode and forget the unclean starts (so the next start does not enter it again at once).
    Returns the record that was on, or None."""
    cur = mmcore.safe_state()
    for f in (mmcore.path("safe.json"), mmcore.path("state", "starts.json")):
        try:
            os.remove(f)
        except OSError:
            pass
    if cur:
        log("SAFE MODE off: %s" % why)
    return cur


# ------------------------------------------------------------------------------------------- the Mac reboot

def boot_time():
    """kern.boottime (struct timeval) in epoch seconds, or None."""
    raw = mmread.sysctl_raw("kern.boottime")
    if raw is None or len(raw) < 16:
        return None
    sec, usec = struct.unpack("<qq", raw[:16])
    return sec + usec / 1e6


def panic_names(folder=PANIC_DIR):
    """Names of the kernel panic reports (names only; never the content), or None when the folder is unreadable."""
    try:
        return sorted(n for n in os.listdir(folder) if not n.startswith(".") and "panic" in n.lower())
    except OSError:
        return None


def missing_jobs(expected):
    """The expected detached jobs (profile recovery.expected_jobs: [{name, match}]) whose regex matches no process's
    command line. One ps call."""
    if not expected:
        return []
    rc, out = mmread.run(["/bin/ps", "-axo", "args="], timeout=10)
    if rc != 0:
        return ["(ps failed)"]
    lines = out.splitlines()
    miss = []
    for job in expected:
        try:
            rx = re.compile(job["match"])
        except (re.error, KeyError, TypeError):
            miss.append("%s (bad match)" % job.get("name", "?"))
            continue
        if not any(rx.search(l) for l in lines):
            miss.append(job.get("name") or job["match"])
    return miss


def boot_record():
    return mmcore.read_json(mmcore.path("state", "boot.json"), None)


def save_boot(rec):
    mmcore.write_atomic(mmcore.path("state", "boot.json"), json.dumps(rec, sort_keys=True))


# ------------------------------------------------------------------------------------------- the watchdog stamp

def stamp_watchdog(now):
    mmcore.write_atomic(mmcore.path("state", "watchdog.stamp"), "%.3f\n" % now)


def watchdog_age(now):
    try:
        with open(mmcore.path("state", "watchdog.stamp")) as f:
            return now - float(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


# ------------------------------------------------------------------------------------------- the dead-man ping

def ping(url, timeout):
    """One GET of the owner's dead-man URL. Returns a short result for the log; the log names only the host."""
    host = urllib.parse.urlsplit(url).hostname or "?"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout) as r:
            return "host=%s status=%s" % (host, r.status)
    except Exception as e:  # any failure is a log line, never a stop
        return "host=%s failed=%s" % (host, type(e).__name__)


def log_ping(result, now):
    mmcore.append_line(mmcore.path("state", "heartbeat.log"), "%s ping %s" % (mmcore.now_local(now), result))


def data_facts():
    """(writable, free MB) of the data folder."""
    d = mmcore.data_dir()
    try:
        st = os.statvfs(d)
        free = st.f_bavail * st.f_frsize / 2**20
    except OSError:
        free = None
    probe = os.path.join(d, "state", ".write-probe")
    try:
        with open(probe, "w") as f:
            f.write("x")
        os.remove(probe)
        ok = True
    except OSError:
        ok = False
    return ok, free


def sleep_until(cond, limit_s, step=0.25):
    end = time.monotonic() + limit_s
    while time.monotonic() < end:
        v = cond()
        if v:
            return v
        time.sleep(step)
    return cond()
