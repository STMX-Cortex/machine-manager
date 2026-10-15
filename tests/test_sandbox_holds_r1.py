# SPDX-License-Identifier: Apache-2.0
"""Sandbox holds, review round 1: three rulings on rules 47 and 48 (README.md, "Agent-written files").

C-10 (the pause, rule 47), with C-12 (Q3): pause candidates are processes that have the slot file open with write
access (lsof access `u` or `w`; the queue launcher opens its slot `a+`). A process that has the slot file open
read-only (a waiter's liveness scan: a read-only open and a shared-lock try) is never paused and raises no
PAUSE_REFUSED, even when it runs the queue launcher; a write-access opener that is not the launcher raises
PAUSE_REFUSED. Accepted limit: a waiter that tries a slot has it open read-write for a moment.

C-12 (Q1, Q2): every open of a queue slot or ticket file by the tool (the queue read, the evidence bundle) uses
O_NONBLOCK and O_NOFOLLOW, requires a regular file (fstat) and reads at most 4096 bytes. A path that is not a regular
file (a link, a FIFO) counts as not held and raises the ATTENTION alert SLOT_NOT_A_FILE naming the path; the pause
never runs lsof on it and pauses nothing through it.

C-11 (deletes, rule 48): `has_marker` opens the marker without following a link and without blocking, requires a
regular file, reads at most 4096 bytes and decodes with errors replaced, so an agent-made marker (invalid UTF-8, a FIFO,
a link, a folder, a huge file) neither crashes nor hangs the deletes. An error in one delete rule no longer stops the
later rules or the cleanup list, and any error of the deletes worker raises the ATTENTION alert DELETES_FAILED naming
the rule and the error; for a cleanup-list failure it names `cleanup_list` in place of a rule id (C-12, Q4).

Every fixture lives in the test's own temporary folder. The only processes signalled are ones the test started: a guard
around os.kill refuses (and records) any SIGSTOP or SIGCONT to another pid. A step that could hang (a FIFO) runs in a
thread with a time limit; at the limit the test opens the FIFO itself so the step can end, and the test fails."""
import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

import mmtest
from mmtest import mmread
import ad_queue_fifo
import mmdelete
import mmrecover
import mmsuper
import test_sandbox_holds as tsh

# Time limits of this test file (seconds). A tick, a deletes pass or a marker check that takes longer is a hang.
STEP_LIMIT_S = 60
MARKER_LIMIT_S = 20

# The queue launcher stand-in (written over the queue folder's configured launcher, in the test's own folder):
#   launcher.py -- CMD...               a queue call: holds .slot.1 (opened a+, exclusive flock), runs CMD
#   launcher.py --scan SLOT READY       a waiter's liveness scan: SLOT opened read-only, a shared-lock try, kept open
#   launcher.py --fifo PATH READY       PATH opened read-write without blocking (a FIFO), kept open
STAND_IN = r'''# SPDX-License-Identifier: Apache-2.0
import fcntl, os, subprocess, sys, time
HERE = os.path.dirname(os.path.realpath(__file__))
a = sys.argv[1:]
if a[:1] == ["--scan"]:
    f = open(a[1], "r")
    try:
        fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError:
        pass
    open(a[2], "w").close()
    time.sleep(300)
    sys.exit(0)
if a[:1] == ["--fifo"]:
    fd = os.open(a[1], os.O_RDWR | os.O_NONBLOCK)
    open(a[2], "w").close()
    time.sleep(300)
    sys.exit(0)
if a[:1] != ["--"]:
    sys.exit(2)
f = open(os.path.join(HERE, ".slot.1"), "a+")
fcntl.flock(f, fcntl.LOCK_EX)
f.seek(0); f.truncate(); f.write("S %d %s\n" % (os.getpid(), " ".join(a[1:]))); f.flush()
sys.exit(subprocess.call(a[1:]))
'''

# Not the launcher: the slot file opened read-only (with a shared-lock try), kept open.
READER = r'''
import fcntl, sys, time
f = open(sys.argv[1], "r")
try:
    fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)
except OSError:
    pass
open(sys.argv[2], "w").close()
time.sleep(300)
'''

# Not the launcher: the slot file opened read-write (r+), label left alone, kept open.
IMPOSTOR = r'''
import sys, time
f = open(sys.argv[1], "r+")
open(sys.argv[2], "w").close()
time.sleep(300)
'''

# Not the launcher: the slot file opened twice, read-only first (the lower descriptor), then read-write.
# Not the launcher: the slot file opened write-only (no truncation), kept open.
IMPOSTOR_WRITE_ONLY = r'''
import os, sys, time
fd = os.open(sys.argv[1], os.O_WRONLY)
open(sys.argv[2], "w").close()
time.sleep(300)
'''

IMPOSTOR_TWO_FDS = r'''
import sys, time
r = open(sys.argv[1], "r")
w = open(sys.argv[1], "r+")
open(sys.argv[2], "w").close()
time.sleep(300)
'''


def held(path):
    """Another process holds an exclusive flock on the file at path (the test's own check; it follows a link)."""
    try:
        with open(path) as f:
            try:
                fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(f, fcntl.LOCK_UN)
            return False
    except OSError:
        return False


def names_pid(text, pid):
    return re.search(r"(?<!\d)%d(?!\d)" % pid, text or "") is not None


def run_within(fn, limit, unblock=None):
    """fn() in a thread; its value, or its exception raised here. Past `limit` seconds: unblock() (so the thread can
    end), then an AssertionError naming the hang."""
    box = {}

    def body():
        try:
            box["value"] = fn()
        except BaseException as e:  # re-raised in the test's thread
            box["error"] = e
    t = threading.Thread(target=body, daemon=True)
    t.start()
    t.join(limit)
    if t.is_alive():
        if unblock:
            unblock()
        t.join(30)
        raise AssertionError("hung: the step did not end within %d s" % limit)
    if "error" in box:
        raise box["error"]
    return box.get("value")


def fifo_unblocker(path):
    """Opens the FIFO read-write and closes it: a reader blocked in open() or read() on it can go on."""
    def unblock():
        try:
            fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        except OSError:
            return
        time.sleep(0.5)
        os.close(fd)
    return unblock


# ------------------------------------------------------------------------------------------------ C-10: the pause

class PauseBase(tsh.Base):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir(slots=5)
        with open(os.path.join(self.q, "launcher.py"), "w") as f:
            f.write(STAND_IN)
        self.launcher_path = os.path.join(self.q, "launcher.py")
        self.slot = os.path.join(self.q, ".slot.1")
        self.started = []
        self.refused = []
        self.unblock = None
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "pause_newest_call.enabled": True})

    def tearDown(self):
        for pid in self.mine():
            try:
                os.kill(pid, signal.SIGCONT)
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        for p in self.started:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                pass
        super().tearDown()

    # -- processes this test starts

    def start(self, argv):
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.started.append(p)
        return p

    def mine(self):
        """The pids this test started and all their descendants, now."""
        procs = mmread.read_ps() or []
        out = set()
        for p in self.started:
            out.update(mmread.descendants(procs, p.pid))
        return out

    def wait_until(self, cond, what):
        for _ in range(100):
            if cond():
                return
            time.sleep(0.1)
        self.fail("timed out waiting for " + what)

    def label(self):
        with open(self.slot) as f:
            return f.readline().strip()

    def call(self):
        """A queue call: the configured launcher (the stand-in) holds .slot.1 read-write and runs a sleep."""
        p = self.start([sys.executable, "-I", self.launcher_path, "--", "/bin/sleep", "300"])
        self.wait_until(lambda: held(self.slot) and self.label().startswith("S %d " % p.pid),
                        "the launcher to hold its slot")
        self.wait_until(lambda: len(mmread.descendants(mmread.read_ps() or [], p.pid)) >= 2, "the launcher's child")
        return p

    def ready_file(self, name):
        return os.path.join(self.t, "ready-" + name)

    def started_ready(self, argv, name):
        ready = self.ready_file(name)
        p = self.start(argv + [ready])
        self.wait_until(lambda: os.path.exists(ready), name + " to open the slot file")
        return p

    def launcher_scan(self):
        """The configured launcher in its waiter's form: the slot file open read-only."""
        return self.started_ready([sys.executable, "-I", self.launcher_path, "--scan", self.slot], "scan")

    def reader(self):
        return self.started_ready([sys.executable, "-I", "-c", READER, self.slot], "reader")

    def impostor(self, script=IMPOSTOR, name="impostor"):
        return self.started_ready([sys.executable, "-I", "-c", script, self.slot], name)

    # -- the supervisor at a critical RED

    def tick_red(self, n=3):
        """Supervisor ticks at a critical RED in act mode, in a thread with a time limit, with os.kill guarded: a
        SIGSTOP or SIGCONT to a pid this test did not start is refused and recorded."""
        real_kill = os.kill
        allowed = self.mine()

        def kill(pid, sig):
            if sig in (signal.SIGSTOP, signal.SIGCONT) and pid not in allowed:
                self.refused.append((pid, sig))
                raise PermissionError("guard: not a process of this test")
            return real_kill(pid, sig)

        def killpg(pgid, sig):
            self.refused.append(("group", pgid, sig))
            raise PermissionError("guard: no group signals in this test")
        clock = {"t": time.time()}

        def ticks():
            sup = mmsuper.Supervisor(self.profile(), kernel=False, clock=lambda: clock["t"], sampler=tsh.CRITICAL,
                                     sizes=False, slow_jobs=False, check_readings=False)
            for _ in range(n):
                sup.tick()
                clock["t"] += 10
            return sup
        with mock.patch.object(os, "kill", kill), mock.patch.object(os, "killpg", killpg):
            sup = run_within(ticks, STEP_LIMIT_S, self.unblock)
        self.assertEqual(self.refused, [], "a signal to a process this test did not start")
        return sup

    # -- checks

    def stopped(self, pid):
        return tsh.proc_stat(pid).startswith("T")

    def tree_of(self, p):
        return sorted(mmread.descendants(mmread.read_ps() or [], p.pid))

    def refusals(self):
        return [a for a in tsh.alert_records(self.data) if a.get("name") == "PAUSE_REFUSED"]

    def assert_slot_not_a_file(self, path):
        """C-12 (Q1, Q2): an ATTENTION alert SLOT_NOT_A_FILE names the path (as given, or with its folder resolved)."""
        got = [a for a in tsh.alert_records(self.data) if a.get("name") == "SLOT_NOT_A_FILE"]
        self.assertTrue(got, "a SLOT_NOT_A_FILE alert")
        self.assertTrue(all(a.get("level") == "ATTENTION" for a in got), got)
        text = "\n".join(a.get("text") or "" for a in got)
        forms = (path, os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path)))
        self.assertTrue(any(f in text for f in forms), "the alert names %s: %s" % (path, text))

    def assert_paused_exactly(self, call):
        tree = self.tree_of(call)
        self.assertTrue(all(self.stopped(pid) for pid in tree), "the queue call and its command are paused")
        self.assertEqual(sorted(int(x) for x in mmrecover.read_paused()), tree,
                         "only the queue call's process tree is recorded as paused")

    def assert_not_paused(self, *procs):
        for p in procs:
            self.assertFalse(self.stopped(p.pid), "pid %d was paused" % p.pid)

    def assert_nothing_paused(self, *procs):
        self.assert_not_paused(*procs)
        self.assertEqual(mmrecover.read_paused(), {}, "nothing is recorded as paused")

    def assert_no_refusal(self):
        self.assertEqual(self.refusals(), [], "no PAUSE_REFUSED: no process other than the launcher had it open "
                                              "read-write")

    def assert_refusal_names(self, named, not_named=()):
        got = self.refusals()
        self.assertTrue(got, "a PAUSE_REFUSED alert")
        self.assertTrue(all(a.get("level") == "ATTENTION" for a in got), got)
        text = "\n".join(a.get("text") or "" for a in got)
        self.assertIn(".slot.1", text, "the alert names the slot file")
        for p in named:
            self.assertTrue(names_pid(text, p.pid), "the alert names pid %d: %s" % (p.pid, text))
        for p in not_named:
            self.assertFalse(names_pid(text, p.pid), "a read-only opener (pid %d) is named: %s" % (p.pid, text))


class ReadOnlyOpeners(PauseBase):
    """C-10: read-only openers are never candidates and need no alert."""

    def test_the_launchers_own_read_only_scan_is_never_paused(self):
        """A waiting queue call (the configured launcher) scans the slot file read-only: only the holder is paused."""
        call = self.call()
        scan = self.launcher_scan()
        self.tick_red()
        self.assert_not_paused(scan)
        self.assert_paused_exactly(call)
        self.assert_no_refusal()

    def test_a_read_only_opener_that_is_not_the_launcher_raises_no_refusal(self):
        call = self.call()
        r = self.reader()
        self.tick_red()
        self.assert_not_paused(r)
        self.assert_paused_exactly(call)
        self.assert_no_refusal()

    def test_a_read_write_impostor_is_named_and_a_reader_beside_it_is_not(self):
        call = self.call()
        r = self.reader()
        imp = self.impostor()
        self.tick_red()
        self.assert_not_paused(r, imp)
        self.assert_paused_exactly(call)
        self.assert_refusal_names([imp], not_named=[r])

    def test_a_write_only_impostor_is_named(self):
        """C-12 (Q3): write access `w` makes a candidate too; this one is not the launcher, so it is named and never
        paused."""
        call = self.call()
        imp = self.impostor(IMPOSTOR_WRITE_ONLY, "impostor-w")
        self.tick_red()
        self.assert_not_paused(imp)
        self.assert_paused_exactly(call)
        self.assert_refusal_names([imp])

    def test_an_impostor_with_a_read_only_and_a_read_write_descriptor_is_still_named(self):
        """Any read-write descriptor makes a candidate, also when a read-only one of the same process comes first."""
        call = self.call()
        imp = self.impostor(IMPOSTOR_TWO_FDS, "impostor2")
        self.tick_red()
        self.assert_not_paused(imp)
        self.assert_paused_exactly(call)
        self.assert_refusal_names([imp])

    def test_a_launcher_scan_beside_a_holder_that_is_not_the_launcher_is_never_paused(self):
        """The holder is not the launcher: nothing is paused, not even the launcher's read-only scan; the alert names
        the holder and not the scan."""
        h = self.start([sys.executable, "-I", "-c", tsh.HOLDER, self.slot, "S SELF go test ./x"])
        self.wait_until(lambda: held(self.slot) and self.label() == "S %d go test ./x" % h.pid,
                        "the holder to hold the slot")
        scan = self.launcher_scan()
        self.tick_red()
        self.assert_nothing_paused(h, scan)
        self.assert_refusal_names([h], not_named=[scan])


class SlotPathNotARegularFile(PauseBase):
    """C-10 and C-12: a link or a FIFO at the slot path pauses nothing, lsof never runs on it, and SLOT_NOT_A_FILE
    names it."""

    def lsof_on_slot(self, spy):
        return [c for c in spy.calls if c[0] and os.path.basename(str(c[0][0])) == "lsof"
                and any(str(w) in (self.slot, os.path.realpath(self.slot)) for w in c[0])]

    def swap_after_the_read(self, swap):
        """The queue read sees the regular slot file held; right after it, `swap` replaces the slot path (the pause
        then works on what the read reported)."""
        real = ad_queue_fifo.Queue.read
        done = []

        def read(queue, now=None):
            out = real(queue, now)
            if not done and any(b.get("slot") == ".slot.1" for b in (out or {}).get("busy", [])):
                done.append(True)
                swap()
            return out
        return mock.patch.object(ad_queue_fifo.Queue, "read", read)

    def move_slot_away(self):
        held = os.path.join(self.t, "held-slot")
        os.rename(self.slot, held)
        return held

    def test_a_link_planted_at_the_slot_path_before_the_call_pauses_nothing(self):
        """The call holds the agent's file through the link: nothing is paused."""
        target = os.path.join(self.t, "agent-slot")
        open(target, "w").close()
        self.link(target, self.slot)
        call = self.call()
        with tsh.GitSpy() as spy:
            self.tick_red()
        self.assert_nothing_paused(call)
        self.assertEqual(self.lsof_on_slot(spy), [], "lsof never runs on a slot path that is a link")
        self.assert_slot_not_a_file(self.slot)

    def test_a_slot_swapped_for_a_link_after_the_read_pauses_nothing_and_alerts(self):
        call = self.call()

        def swap():
            self.link(self.move_slot_away(), self.slot)
        with self.swap_after_the_read(swap), tsh.GitSpy() as spy:
            self.tick_red()
        self.assertTrue(os.path.islink(self.slot), "the swap ran")
        self.assert_nothing_paused(call)
        self.assertEqual(self.lsof_on_slot(spy), [], "lsof never runs on a slot path that is a link")
        self.assert_slot_not_a_file(self.slot)

    def test_a_slot_swapped_for_a_fifo_after_the_read_pauses_nothing_and_alerts(self):
        call = self.call()

        def swap():
            self.move_slot_away()
            os.mkfifo(self.slot)
        self.unblock = fifo_unblocker(self.slot)
        with self.swap_after_the_read(swap), tsh.GitSpy() as spy:
            self.tick_red()
        self.assertTrue(os.path.exists(self.slot) and not os.path.isfile(self.slot), "the swap ran")
        self.assert_nothing_paused(call)
        self.assertEqual(self.lsof_on_slot(spy), [], "lsof never runs on a slot path that is a FIFO")
        self.assert_slot_not_a_file(self.slot)

    def test_a_fifo_at_the_slot_path_held_read_write_by_the_launcher_pauses_nothing(self):
        """The FIFO's opener runs the configured launcher with the FIFO open read-write: still nothing is paused."""
        call = self.call()
        fifo = os.path.join(self.t, "agent-fifo")
        os.mkfifo(fifo)
        opener = self.started_ready([sys.executable, "-I", self.launcher_path, "--fifo", fifo], "fifo")

        def swap():
            self.move_slot_away()
            os.rename(fifo, self.slot)
        self.unblock = fifo_unblocker(self.slot)
        with self.swap_after_the_read(swap):
            self.tick_red()
        self.assert_nothing_paused(call, opener)
        self.assert_slot_not_a_file(self.slot)


class QueueReadWithAFifo(PauseBase):
    """C-12 (Q1): the queue read and the evidence bundle open every `.slot.N` and ticket file. Before the fix a FIFO
    there blocked a plain open() while no writer had it open, and with a writer the flock failed (EOPNOTSUPP) and the
    whole queue reading was lost. Agents may write the slot and ticket files (README.md, "Agent-written files").
    Expected: the ticks end, the real call is still paused, and SLOT_NOT_A_FILE names the FIFO."""

    def test_a_fifo_at_an_idle_slot_path_hangs_no_tick(self):
        call = self.call()
        fifo = os.path.join(self.q, ".slot.2")
        os.mkfifo(fifo)
        self.unblock = fifo_unblocker(fifo)
        self.tick_red()
        self.assert_paused_exactly(call)
        self.assert_slot_not_a_file(fifo)

    def test_a_fifo_at_an_idle_slot_path_with_a_writer_does_not_stop_the_pause(self):
        call = self.call()
        fifo = os.path.join(self.q, ".slot.2")
        os.mkfifo(fifo)
        fd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)  # the agent's writer, held open
        try:
            self.tick_red()
        finally:
            os.close(fd)
        self.assert_paused_exactly(call)
        self.assert_slot_not_a_file(fifo)

    def test_a_ticket_that_is_a_link_counts_as_not_held_and_alerts(self):
        """A ticket link to a file another process holds locked: not a regular file, so SLOT_NOT_A_FILE names it."""
        call = self.call()
        target = os.path.join(self.t, "agent-ticket")
        h = self.start([sys.executable, "-I", "-c", tsh.HOLDER, target, "S SELF go test ./x"])
        self.wait_until(lambda: held(target), "the holder to lock its file")
        ticket = self.link(target, os.path.join(self.q, "queue", "%d-%d" % (time.time_ns(), h.pid)))
        self.tick_red()
        self.assert_not_paused(h)
        self.assert_paused_exactly(call)
        self.assert_slot_not_a_file(ticket)

    def test_a_fifo_ticket_hangs_no_tick(self):
        call = self.call()
        fifo = os.path.join(self.q, "queue", "%d-%d" % (time.time_ns(), os.getpid()))
        os.mkfifo(fifo)
        self.unblock = fifo_unblocker(fifo)
        self.tick_red()
        self.assert_paused_exactly(call)
        self.assert_slot_not_a_file(fifo)


# ------------------------------------------------------------------------------------------------ C-11: markers

def cache_rule(rid, cache):
    return {"id": rid, "type": "cache_entries", "cache": cache, "marker_file": "README", "marker_text": "Go build",
            "age_minutes": 60, "no_live_tools": False}


class MarkerBase(tsh.Base):
    def cache(self, name, readme=None):
        """A cache with one old entry folder of two old files; its README replaced by `readme(path)` when given."""
        c = tsh.cache_at(os.path.join(self.t, name))
        if readme is not None:
            os.unlink(os.path.join(c, "README"))
            readme(os.path.join(c, "README"))
        return c, [os.path.join(c, "0a", "old-a"), os.path.join(c, "0a", "old-b")]

    def write_bytes(self, data):
        def f(path):
            with open(path, "wb") as fh:
                fh.write(data)
        return f

    def check(self, c, limit=MARKER_LIMIT_S, unblock=None):
        return run_within(lambda: mmdelete.has_marker(c, "README", "Go build"), limit, unblock)

    def assert_gone(self, files):
        for f in files:
            self.assertFalse(os.path.exists(f), "not deleted: %s" % f)

    def assert_kept(self, files):
        for f in files:
            self.assertTrue(os.path.exists(f), "deleted: %s" % f)


class HasMarker(MarkerBase):
    """C-11: has_marker on agent-made markers: no crash, no hang."""

    def test_invalid_utf8_without_the_marker_text_is_no_marker(self):
        c, _ = self.cache("c", self.write_bytes(b"\xff\xfe\x80 not a cache\n"))
        self.assertFalse(self.check(c))

    def test_invalid_utf8_around_the_marker_text_still_finds_it(self):
        """Errors are replaced, so the valid marker text is found."""
        c, _ = self.cache("c", self.write_bytes(b"\xff\xfe This directory holds cached Go build artifacts.\n\x80"))
        self.assertTrue(self.check(c))

    def test_a_fifo_readme_without_a_writer_is_no_marker_and_no_hang(self):
        c, _ = self.cache("c", os.mkfifo)
        readme = os.path.join(c, "README")
        self.assertFalse(self.check(c, unblock=fifo_unblocker(readme)))

    def test_a_fifo_readme_with_a_silent_writer_is_no_marker_and_no_hang(self):
        c, _ = self.cache("c", os.mkfifo)
        readme = os.path.join(c, "README")
        fd = os.open(readme, os.O_RDWR | os.O_NONBLOCK)  # a writer that never writes
        try:
            self.assertFalse(self.check(c, unblock=lambda: os.close(fd)))
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def test_a_link_readme_to_a_real_marker_file_is_no_marker(self):
        """The marker is opened without following a link."""
        real = os.path.join(self.t, "real-readme")
        with open(real, "w") as f:
            f.write("This directory holds cached Go build artifacts.\n")
        c, _ = self.cache("c", lambda p: self.link(real, p))
        self.assertFalse(self.check(c))

    def test_a_link_readme_to_a_fifo_is_no_marker_and_no_hang(self):
        fifo = os.path.join(self.t, "fifo")
        os.mkfifo(fifo)
        c, _ = self.cache("c", lambda p: self.link(fifo, p))
        self.assertFalse(self.check(c, unblock=fifo_unblocker(fifo)))

    def test_a_folder_named_readme_is_no_marker(self):
        c, _ = self.cache("c", os.mkdir)
        self.assertFalse(self.check(c))

    def test_an_unreadable_readme_is_no_marker(self):
        c, _ = self.cache("c", self.write_bytes(b"This directory holds cached Go build artifacts.\n"))
        os.chmod(os.path.join(c, "README"), 0)
        try:
            self.assertFalse(self.check(c))
        finally:
            os.chmod(os.path.join(c, "README"), 0o600)

    def test_a_huge_readme_with_the_marker_at_the_start_is_found(self):
        def huge(p):
            with open(p, "wb") as f:
                f.write(b"This directory holds cached Go build artifacts.\n")
                f.truncate(64 << 20)  # sparse
        c, _ = self.cache("c", huge)
        self.assertTrue(self.check(c))

    def test_marker_text_after_the_first_4096_bytes_is_not_read(self):
        """At most 4096 bytes are read: 2100 two-byte characters (4200 bytes) come before the marker text."""
        c, _ = self.cache("c", self.write_bytes(("é" * 2100 + " Go build\n").encode("utf-8")))
        self.assertFalse(self.check(c))

    def test_a_character_cut_at_the_4096_byte_limit_is_no_error(self):
        """The marker text comes first; byte 4096 falls inside a two-byte character."""
        head = b"Go build cache\n"
        pad = b"a" * (4095 - len(head))
        c, _ = self.cache("c", self.write_bytes(head + pad + "é".encode("utf-8") * 10))
        self.assertTrue(self.check(c))


class DeleteRulesGoOn(MarkerBase):
    """C-11: one failing rule never stops the later rules; an agent-made marker stops nothing."""

    def run_all(self, rules):
        r = mmdelete.Run(mmtest.base_settings(**{"deletes.lsof_timeout_s": 60}), self.ctx(rules), enabled=True,
                         procs=lambda: [], live_spec=tsh.LIVE, mid="m1")
        try:
            run_within(r.all, STEP_LIMIT_S, getattr(self, "unblock", None))
        except AssertionError:
            raise
        except Exception:
            pass  # the run may report a rule's error after the other rules ran; the deletes below decide
        return r

    def test_a_link_readme_stops_the_cache_rule_from_deleting(self):
        real = os.path.join(self.t, "real-readme")
        with open(real, "w") as f:
            f.write("This directory holds cached Go build artifacts.\n")
        c, files = self.cache("c", lambda p: self.link(real, p))
        self.run_all([cache_rule("S5", c)])
        self.assert_kept(files)

    def test_an_invalid_utf8_readme_in_one_rule_does_not_stop_the_next(self):
        bad, _ = self.cache("bad", self.write_bytes(b"\xff\xfe\x80 agent text\n"))
        good, files = self.cache("good")
        r = mmdelete.Run(mmtest.base_settings(**{"deletes.lsof_timeout_s": 60}),
                         self.ctx([cache_rule("S5a", bad), cache_rule("S5b", good)]), enabled=True,
                         procs=lambda: [], live_spec=tsh.LIVE, mid="m1")
        r.all()  # the reviewer's reproduction: UnicodeDecodeError here
        self.assert_gone(files)

    def test_a_fifo_readme_in_one_rule_does_not_hang_the_pass(self):
        bad, _ = self.cache("bad", os.mkfifo)
        good, files = self.cache("good")
        self.unblock = fifo_unblocker(os.path.join(bad, "README"))
        self.run_all([cache_rule("S5a", bad), cache_rule("S5b", good)])
        self.assert_gone(files)

    def test_an_error_in_one_rule_does_not_stop_the_later_rules(self):
        faulty, kept = self.cache("faulty")
        good, files = self.cache("good")
        real = mmdelete.Run.cache_entries

        def cache_entries(run, r):
            if r["id"] == "FAULTY":
                raise RuntimeError("planted fault 7f3a")
            return real(run, r)
        with mock.patch.object(mmdelete.Run, "cache_entries", cache_entries):
            r = self.run_all([cache_rule("FAULTY", faulty), cache_rule("S5b", good)])
        self.assert_gone(files)
        self.assert_kept(kept)
        self.assertTrue(any(mmtest.mmcore.parse_delete_line(l)["verb"] == "DELETE" and "rule=S5b" in l for l in r.lines),
                        r.lines)


class DeletesFailedAlert(MarkerBase):
    """C-11: any error of the supervisor's deletes worker raises the ATTENTION alert DELETES_FAILED naming the rule and
    the error; the later rules and the cleanup list still run."""

    def supervise(self, rules, ticks=3):
        prof = os.path.join(self.root, "profile.toml")
        with open(mmtest.PROFILE) as f:
            text = f.read()
        for r in rules:
            text += "\n[[deletes.rules]]\n" + "\n".join("%s = %s" % (k, json.dumps(v)) for k, v in r.items()) + "\n"
        with open(prof, "w") as f:
            f.write(text)
        os.environ["MM_PROFILE"] = prof  # TempData puts the old value back
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "deletes.enabled": True})

        def go():
            sup = mmsuper.Supervisor(self.profile(), kernel=False, sampler=tsh.sampler_of(), sizes=False,
                                     slow_jobs=True, check_readings=False)
            for _ in range(ticks):
                sup.tick()
                if sup.deletes.thread is not None:
                    sup.deletes.thread.join(STEP_LIMIT_S)
            return sup
        return run_within(go, STEP_LIMIT_S * (ticks + 1), getattr(self, "unblock", None))

    def failed_alerts(self):
        return [a for a in tsh.alert_records(self.data) if a.get("name") == "DELETES_FAILED"]

    def cleanup_list_written(self):
        return os.path.exists(os.path.join(self.data, "state", "cleanup-list.json"))

    def test_a_failing_rule_raises_deletes_failed_and_the_rest_still_runs(self):
        faulty, kept = self.cache("faulty")
        good, files = self.cache("good")
        real = mmdelete.Run.cache_entries

        def cache_entries(run, r):
            if r["id"] == "FAULTY":
                raise RuntimeError("planted fault 7f3a")
            return real(run, r)
        with mock.patch.object(mmdelete.Run, "cache_entries", cache_entries):
            self.supervise([cache_rule("FAULTY", faulty), cache_rule("S5b", good)])
        self.assert_gone(files)
        self.assert_kept(kept)
        self.assertTrue(self.cleanup_list_written(), "the cleanup list still runs after a failing rule")
        got = self.failed_alerts()
        self.assertTrue(got, "a DELETES_FAILED alert")
        self.assertTrue(all(a.get("level") == "ATTENTION" for a in got), got)
        text = "\n".join(a.get("text") or "" for a in got)
        self.assertIn("FAULTY", text, "the alert names the rule")
        self.assertIn("planted fault 7f3a", text, "the alert names the error")

    def test_a_failing_cleanup_list_raises_deletes_failed(self):
        good, files = self.cache("good")

        def cleanup_list(ctx, now, sizes=True):
            raise RuntimeError("planted cleanup fault 9c1e")
        with mock.patch.object(mmdelete, "cleanup_list", cleanup_list):
            self.supervise([cache_rule("S5b", good)])
        self.assert_gone(files)
        got = self.failed_alerts()
        self.assertTrue(got, "a DELETES_FAILED alert")
        self.assertTrue(all(a.get("level") == "ATTENTION" for a in got), got)
        text = "\n".join(a.get("text") or "" for a in got)
        self.assertIn("cleanup_list", text, "the alert names cleanup_list in place of a rule id")
        self.assertIn("planted cleanup fault 9c1e", text, "the alert names the error")

    def test_an_agent_made_readme_is_no_failure_and_stops_nothing(self):
        """The reviewer's reproduction under the supervisor: an invalid UTF-8 README in the first rule's cache."""
        bad, _ = self.cache("bad", self.write_bytes(b"\xff\xfe\x80 agent text\n"))
        good, files = self.cache("good")
        self.supervise([cache_rule("S5a", bad), cache_rule("S5b", good)])
        self.assert_gone(files)
        self.assertTrue(self.cleanup_list_written(), "the cleanup list still runs")
        self.assertEqual(self.failed_alerts(), [], "an agent-made README is no error of the deletes")


if __name__ == "__main__":
    unittest.main()
