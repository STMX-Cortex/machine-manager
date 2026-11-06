# SPDX-License-Identifier: Apache-2.0
"""machine-manager self-recovery: the paused-process record, unclean starts and the crash-loop guard, safe mode,
the machine reboot check, the watchdog's stamp and the outside dead-man ping.

The decisions are the pure functions in mmdecide (sample_problems, self_check, crash_loop, resume_targets,
reboot_check); this module gathers their facts and keeps their files in the data folder:
  state/paused.json    {pid: start time} of every process the pause stopped; written BEFORE the SIGSTOP
  state/run.json       {pid, started, clean}: clean is set only when a run ends by itself (SIGTERM, ticks done)
  state/starts.json    the times of unclean starts (for the crash-loop guard)
  safe.json            safe mode: {safe, since, reason, slot_write}
  state/self-check-clear.json  the last `mm on` / `mm restart --clear-safe`: {cleared_at, why, was_safe}; the
                       self-check counts only the slot changes after cleared_at
  state/boot.json      the boot time, the last tick, state and slots, the panic report names
  state/watchdog.stamp the watchdog's last run (its time as text)
  state/recovery.log   one line per recovery step
The tool never reboots the machine and never signals a process it did not pause itself.
"""
import json
import math
import os
import re
import signal
import time
import urllib.parse
import urllib.request

import mmcore
import mmdecide
import mmread
import mmtext

PANIC_DIR = mmread.plat.PANIC_DIR  # None: the platform has no panic report folder


def log(line, now=None):
    mmcore.append_line(mmcore.path("state", "recovery.log"), mmcore.mask("%s %s" % (mmcore.now_local(now), line)))


# ------------------------------------------------------------------------------------------- paused processes

def paused_file():
    return mmcore.path("state", "paused.json")


def _lock():
    return mmcore.Locked(mmcore.path("state", "paused.lock"))


def start_time(pid):
    """Birth identity: Linux boot id plus /proc start ticks, or macOS ps lstart; None when unreadable or gone."""
    if getattr(mmread.plat, "SERVICE", None) == "systemd":
        return mmread.plat.proc_start(pid)
    argv = mmread.plat.ps_lstart_argv(pid)
    if not argv:
        return None
    rc, out = mmread.run(argv, timeout=5)
    return (out.strip() or None) if rc == 0 else None


class PausedBroken(dict):
    """read_paused's error state: state/paused.json exists but cannot be used. It holds no pid (none can be known
    from it) yet is TRUE, so every "is anything paused?" check answers "maybe": no new pause starts, the watchdog and
    `mm recover-paused` do not report "nothing paused". `problem` says why. The file is never written over."""

    def __init__(self, problem):
        super().__init__()
        self.problem = problem

    def __bool__(self):
        return True


PID_KEY = re.compile(r"[1-9][0-9]{0,9}\Z")
PID_MAX = 2 ** 31 - 1  # a larger pid cannot exist (os.kill raises OverflowError): the record is PausedBroken


def paused_problem(d):
    """The problem text of a read_paused() result, or None for a usable record."""
    return getattr(d, "problem", None)


def paused_broken_alert(problem):
    """(text, command) of the PAUSED_FILE_BROKEN alert (the supervisor's key and the watchdog's WD:paused-file)."""
    return ("%s; no new pause, and no pid is continued from it: processes it listed may still be stopped; inspect the "
            "file, continue them by hand (kill -CONT PID), then remove it" % problem, "mm explain PAUSED_FILE_BROKEN")


def read_paused():
    """{pid text: start time} of every process the pause stopped. Missing: {}. Anything else that is not an object of
    pid -> start-time text (a read error, a dangling link, invalid JSON, not an object, a key that is not a pid in
    1..2**31-1, a value that is not a non-empty text) is PausedBroken (fail closed: "maybe paused", never "nothing
    paused")."""
    f = paused_file()
    try:
        with open(f) as fh:
            d = json.load(fh)
    except FileNotFoundError:
        return PausedBroken("state/paused.json: a dangling link") if os.path.lexists(f) else {}
    except (OSError, ValueError, RecursionError) as e:
        return PausedBroken("state/paused.json: cannot be read (%s)" % e.__class__.__name__)
    if not isinstance(d, dict):
        return PausedBroken("state/paused.json: not a JSON object")
    for k, v in d.items():
        if not PID_KEY.match(k) or int(k) > PID_MAX or not isinstance(v, str) or not v:
            return PausedBroken("state/paused.json: an entry is not pid -> start time")
    return {str(k): v for k, v in d.items()}


def signal_process(pid, expected, sig):
    if sig not in (signal.SIGSTOP, signal.SIGCONT):
        raise ValueError("only pause and resume signals are permitted")
    if mmread.plat.SERVICE == "systemd":
        return mmread.plat.signal_process(pid, expected, sig)
    if start_time(pid) != expected:
        raise ProcessLookupError("process identity changed")
    if sig == signal.SIGSTOP:
        return os.kill(pid, signal.SIGSTOP)
    return os.kill(pid, signal.SIGCONT)


def add_paused(entries):
    """Record {pid: start time} before the pids are stopped, so a crash after the SIGSTOP never loses them.
    Returns None when recorded; the problem text when state/paused.json cannot be used (PausedBroken): then nothing
    is written (the broken file is kept as it is) and the caller must not stop any pid."""
    with _lock():
        d = read_paused()
        problem = paused_problem(d)
        if problem:
            log("PAUSE refused: %s; the file is kept, no pid stopped" % problem)
            return problem
        d.update({str(k): v for k, v in entries.items()})
        mmcore.write_atomic(paused_file(), json.dumps(d, sort_keys=True))
        return None


def drop_paused(pids):
    with _lock():
        d = read_paused()
        if paused_problem(d):  # never write over a broken record
            log("PAUSE record not updated: %s; the file is kept" % paused_problem(d))
            return
        for p in pids:
            d.pop(str(p), None)
        mmcore.write_atomic(paused_file(), json.dumps(d, sort_keys=True))


def resume_paused(why, now=None, legacy=None):
    """SIGCONT each recorded pid whose start time still matches; retain uncertain or failed entries for retry.
    `legacy`: an older record kept in controller.json ({pid: start}). Returns the pids actually continued, even when
    writing the updated record fails after a signal. A state/paused.json that cannot be used (PausedBroken) names no
    pid: nothing is signalled from it and it is never written over (only `legacy` pids are continued)."""
    done = []
    try:
        with _lock():
            d = read_paused()
            problem = paused_problem(d)
            if problem:
                log("RESUME from state/paused.json refused: %s; no pid signalled from it, the file is kept (%s)"
                    % (problem, why), now)
                d = {}
            d.update({str(k): v for k, v in (legacy or {}).items()})
            if not d:
                return []
            keep = {}
            for p in sorted(d, key=int):
                expected = d[p]
                pid = int(p)
                try:
                    current = start_time(pid)
                    if current is None:
                        # ps cannot distinguish a vanished pid from a timeout or a failed fork. Only ESRCH proves
                        # it is gone; signal 0 checks existence without continuing an unverified process.
                        os.kill(pid, 0)
                        keep[p] = expected
                        log("RESUME start time unreadable for pid %s; record kept (%s)" % (pid, why), now)
                        continue
                    if current != expected:
                        continue
                    signal_process(pid, expected, signal.SIGCONT)
                    done.append(pid)
                except ProcessLookupError:
                    pass
                except (OSError, TimeoutError) as e:
                    keep[p] = expected
                    log("RESUME pid %s failed; record kept (%s): %r" % (pid, why, e), now)
            if problem:
                if keep:
                    log("RESUME legacy pids %s not continued and not recorded: %s (%s)" % (sorted(keep), problem, why), now)
            else:
                mmcore.write_atomic(paused_file(), json.dumps(keep, sort_keys=True))
    except (OSError, TimeoutError) as e:
        log("RESUME failed (%s): %r" % (why, e), now)
        return done
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


def starting_status(now, mid=None):
    """status.json at the very start, before the first tick (heartbeat tick 0, note "starting"), so the watchdog and
    the hook see a live start and `mm restart` waits for tick 1."""
    rec = mmcore.stamp({"kind": "machine", "time": now, "state": "UNKNOWN", "reasons": ["starting"],
                        "heartbeat": {"pid": os.getpid(), "tick": 0, "note": "starting"}}, mid=mid)
    mmcore.write_atomic(mmcore.path("status.json"), json.dumps(rec, sort_keys=True))


def note_loaded(now):
    """Mark service loading by install/start (the watchdog's start grace counts from this time)."""
    mmcore.write_atomic(mmcore.path("state", "loaded.json"), json.dumps({"time": now}))


def start_ref(now):
    """The latest of the supervisor's start (state/run.json) and the agents' load (state/loaded.json), or None."""
    ts = []
    for f, k in (("run.json", "started"), ("loaded.json", "time")):
        rec = mmcore.read_json(mmcore.path("state", f), None)
        if isinstance(rec, dict) and isinstance(rec.get(k), (int, float)) and rec[k] <= now + 5:
            ts.append(rec[k])
    return max(ts) if ts else None


def note_clean_exit():
    f = mmcore.path("state", "run.json")
    rec = mmcore.read_json(f, None)
    if isinstance(rec, dict) and rec.get("pid") == os.getpid():
        rec["clean"] = True
        mmcore.write_atomic(f, json.dumps(rec))


def enter_safe(reason, now, mid=None):
    """Turn safe mode on (once; a second reason does not replace the first). Returns the record. A safe.json that
    cannot be used already counts as safe mode on: it is kept as it is (never written over), and the trip is logged."""
    cur = mmcore.safe_state()
    if cur:
        if mmcore.record_problem(cur):
            log("SAFE MODE trip (%s): %s is kept as it is; safe mode stays on" % (reason, mmcore.record_problem(cur)), now)
        return cur
    rec = mmcore.stamp({"safe": True, "since": now, "reason": reason[:300], "slot_write": None}, mid=mid)
    mmcore.write_atomic(mmcore.path("safe.json"), json.dumps(rec, sort_keys=True))
    log("SAFE MODE on: %s" % reason, now)
    return rec


def mark_safe_slot_write(text):
    f = mmcore.path("safe.json")
    rec = mmcore.read_json(f, None)
    if isinstance(rec, dict) and rec.get("safe") is True:  # a broken safe.json is never written over
        rec["slot_write"] = text
        mmcore.write_atomic(f, json.dumps(rec, sort_keys=True))


CLEAR_FILE = ("state", "self-check-clear.json")


def clear_safe(why, now=None):
    """End safe mode and forget the unclean starts (so the next start does not enter it again at once). It also writes
    the clear record (CLEAR_FILE: cleared_at, why, was_safe), also when safe mode was not on: the self-check then
    counts only the slot changes after it, so the changes that tripped safe mode do not trip it again at once.
    The clear record is written FIRST: when that fails, nothing is cleared (safe mode and the unclean starts stay) and
    MMError E_CLEAR is raised. safe.json is removed without reading it (never recursively); when the guard is still
    set after that (a folder there, a new file), E_CLEAR is raised too and the unclean starts stay. Returns the record
    that was on, or None."""
    cur = mmcore.safe_state()
    now = time.time() if now is None else now
    try:
        mmcore.write_atomic(mmcore.path(*CLEAR_FILE), json.dumps(
            mmcore.stamp({"cleared_at": now, "why": str(why)[:200], "was_safe": bool(cur)}), sort_keys=True))
    except OSError as e:
        try:  # best effort: the log may fail for the same reason; E_CLEAR is raised either way
            log("SELF-CHECK clear record not written (%s); safe mode and the unclean starts are kept"
                % e.__class__.__name__, now)
        except OSError:
            pass
        raise mmcore.MMError("E_CLEAR", "the clear record state/self-check-clear.json was not written (%s); safe mode "
                             "and the unclean starts are kept" % e.__class__.__name__,
                             "make the data folder's state/ writable, then run it again")
    failed = None
    try:
        os.remove(mmcore.path("safe.json"))  # never a recursive delete: a folder there stays, and the check says so
    except FileNotFoundError:
        pass
    except OSError as e:
        failed = e.__class__.__name__
    if mmcore.safe_state() is not None:  # the guard is checked again: E_CLEAR while it is still set
        log("SAFE MODE not cleared: safe.json was not removed (%s); the unclean starts are kept"
            % (failed or "it is back"), now)
        raise mmcore.MMError("E_CLEAR", "safe.json was not removed (%s); safe mode and the unclean starts stay"
                             % (failed or "it is back"), "remove it by hand (mm on never deletes a folder), then run it again")
    try:
        os.remove(mmcore.path("state", "starts.json"))
    except OSError:
        pass
    if cur:
        log("SAFE MODE off: %s" % why)
    return cur


def read_clear():
    """The clear record (clear_safe): (cleared_at, problem). No file: (None, None). A record that cannot be read or
    is not valid is not "no record" (the control-reader rule): (None, the problem's text); the caller then counts every
    slot change of the hour and shows the problem."""
    f = mmcore.path(*CLEAR_FILE)
    try:
        with open(f) as fh:
            rec = json.load(fh)
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError, RecursionError) as e:  # RecursionError: deeply nested arrays; the file is kept
        return None, "%s: %s" % (os.path.basename(f), e.__class__.__name__)
    t = rec.get("cleared_at") if isinstance(rec, dict) else None
    try:
        ok = isinstance(t, (int, float)) and not isinstance(t, bool) and math.isfinite(float(t))
    except OverflowError:  # an int too large for a float (10**400)
        ok = False
    if not ok:
        return None, "%s: no valid cleared_at" % os.path.basename(f)
    return t, None


# ------------------------------------------------------------------------------------------- the machine reboot

def boot_time():
    """The boot time in epoch seconds (macOS kern.boottime, Linux /proc/stat btime: the backend), or None."""
    return mmread.boot_time()


def panic_names(folder=None):
    """Names of the kernel panic reports in folder (default PANIC_DIR; names only, never the content), or None when
    the folder is unreadable or the platform has none."""
    folder = folder or PANIC_DIR
    if not folder:
        return None
    try:
        return sorted(n for n in os.listdir(folder) if not n.startswith(".") and "panic" in n.lower())
    except OSError:
        return None


def missing_jobs(expected):
    """The expected detached jobs (profile recovery.expected_jobs: [{name, match}]) whose regex matches no process's
    command line. One ps call."""
    if not expected:
        return []
    argv = mmread.plat.PS_ARGS_ARGV
    rc, out = mmread.run(argv, timeout=10) if argv else (None, "")
    if rc != 0:
        return ["(ps failed)"]
    # command lines agents chose: records end at line feeds; each cut before the patterns (C-22)
    lines = [mmtext.cut(line) for line in mmtext.split_lines(out)]
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
