# SPDX-License-Identifier: Apache-2.0
"""Sandbox holds, review round 2 (C-14): no agent-made queue or cache file can cost the whole reading, pause a wrong
process, or make alerts without bound (README.md, "Agent-written files").

R2C-1's alert: a regular slot or ticket file that cannot be opened (mode 000) counts as not held and raises one
ATTENTION alert QUEUE_FILE_UNREADABLE: one key however many files, naming the count and up to 5 paths. The other slots
are still read, so the real call is still paused at a critical RED; the alert clears when the files go.
N4: CLEANUP_LIST and the cleanup list's LINK_SKIPPED alerts keep their state until the cleanup list next runs, not
until the next deletes pass (as R2C-2 does for DELETES_FAILED:cleanup_list).
A1: a held slot (its flock taken) with no write opener raises PAUSE_REFUSED naming the slot; nothing is paused.
N2: the pause takes a fresh process snapshot just before it signals, never one older than that tick.
N3: QWAIT alert keys never come from a ticket's name: one key, naming the count and the oldest ticket.
The socket and mode-000 reading cases of R2C-1, R2C-2 and R2C-3 are in tests/test_sandbox_holds_review2.py.

Every fixture lives in the test's own temporary folder. The only processes signalled are ones the test started: a guard
around os.kill refuses (and records) any SIGSTOP or SIGCONT to another pid."""
import json
import os
import re
import signal
import sys
import time
import unittest
from unittest import mock

import mmtest
from mmtest import mmread
import mmrecover
import mmsuper
import test_sandbox_holds as tsh
import test_sandbox_holds_r1 as r1

# The stand-in launcher of round 1 with one more form:
#   launcher.py --lock-ro SLOT READY    SLOT opened read-only and locked exclusively (flock), kept open
STAND_IN = r1.STAND_IN.replace('if a[:1] != ["--"]:', '''if a[:1] == ["--lock-ro"]:
    f = open(a[1], "r")
    fcntl.flock(f, fcntl.LOCK_EX)
    open(a[2], "w").close()
    time.sleep(300)
    sys.exit(0)
if a[:1] != ["--"]:''', 1)
assert "--lock-ro" in STAND_IN, "the stand-in gained its read-only lock form"

# Not the launcher: the slot file opened read-only and locked exclusively, kept open.
RO_LOCKER = r'''
import fcntl, sys, time
f = open(sys.argv[1], "r")
fcntl.flock(f, fcntl.LOCK_EX)
open(sys.argv[2], "w").close()
time.sleep(300)
'''

# A queue call's command that starts its own child only once the file GO exists.
CHILD_LATER = r'''
import os, subprocess, sys, time
while not os.path.exists(sys.argv[1]):
    time.sleep(0.05)
subprocess.Popen(["/bin/sleep", "300"]).wait()
'''

# A queue call's command with a child that it ends (and reaps) once the file GO exists.
CHILD_ENDS = r'''
import os, subprocess, sys, time
c = subprocess.Popen(["/bin/sleep", "300"])
while not os.path.exists(sys.argv[1]):
    time.sleep(0.05)
c.kill(); c.wait()
time.sleep(300)
'''

# Waiting tickets: argv[1] READY, then pairs PATH LABEL; each path opened a+, locked exclusively, labelled, kept open.
TICKETS = r'''
import fcntl, os, sys, time
held = []
args = sys.argv[2:]
for i in range(0, len(args), 2):
    f = open(args[i], "a+")
    fcntl.flock(f, fcntl.LOCK_EX)
    f.seek(0); f.truncate(); f.write("S %d %s\n" % (os.getpid(), args[i + 1])); f.flush()
    held.append(f)
open(sys.argv[1], "w").close()
time.sleep(300)
'''

TICKET_LABELS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]


def active_alerts(data):
    """key -> the active entry (alerts-state.json)."""
    try:
        with open(os.path.join(data, "alerts-state.json")) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in (st.get("active") or {}).items() if isinstance(v, dict)}


def named(data, name):
    return {k: v for k, v in active_alerts(data).items() if v.get("name") == name}


def path_forms(path):
    return (path, os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path)))


def names_count(text, n, strip=()):
    """The text names the number n, once the given strings (paths, names) are taken out of it."""
    for s in sorted(strip, key=len, reverse=True):
        text = text.replace(s, " ")
    return re.search(r"(?<!\d)%d(?!\d)" % n, text) is not None


class Stepped(r1.PauseBase):
    """One supervisor, ticked by hand: a GREEN or critical-RED sampler per step, a scripted clock, and os.kill guarded
    (every SIGSTOP and SIGCONT is recorded; one to a pid this test did not start is refused)."""

    def setUp(self):
        super().setUp()
        with open(self.launcher_path, "w") as f:
            f.write(STAND_IN)
        self.red = False
        self.clock = {"t": time.time()}
        self.signals = []

    def settings(self, **over):
        base = {"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                "pause_newest_call.enabled": True, "repeat.clear_after_minutes": 0}
        base.update(over)
        self.write_settings(**base)

    def supervisor(self, slow_jobs=False):
        def sampler(now, ticks):
            return (tsh.CRITICAL if self.red else tsh.sampler_of())(now, ticks)
        return mmsuper.Supervisor(self.profile(), kernel=False, clock=lambda: self.clock["t"], sampler=sampler,
                                  sizes=False, slow_jobs=slow_jobs, check_readings=False)

    def step(self, sup, n=1, every=10):
        real_kill = os.kill
        allowed = self.mine()

        def kill(pid, sig):
            if sig in (signal.SIGSTOP, signal.SIGCONT):
                self.signals.append((pid, sig))
                if pid not in allowed:
                    self.refused.append((pid, sig))
                    raise PermissionError("guard: not a process of this test")
            return real_kill(pid, sig)

        def killpg(pgid, sig):
            self.refused.append(("group", pgid, sig))
            raise PermissionError("guard: no group signals in this test")

        def ticks():
            for _ in range(n):
                sup.tick()
                if sup.deletes.thread is not None:
                    sup.deletes.thread.join(r1.STEP_LIMIT_S)
                self.clock["t"] += every
        with mock.patch.object(os, "kill", kill), mock.patch.object(os, "killpg", killpg):
            r1.run_within(ticks, r1.STEP_LIMIT_S * (n + 1), self.unblock)
        self.assertEqual(self.refused, [], "a signal to a process this test did not start")

    def call_of(self, cmd):
        """A queue call (the stand-in launcher) that holds .slot.1 and runs cmd."""
        p = self.start([sys.executable, "-I", self.launcher_path, "--"] + list(cmd))
        self.wait_until(lambda: r1.held(self.slot) and self.label().startswith("S %d " % p.pid),
                        "the launcher to hold its slot")
        self.wait_until(lambda: len(self.tree_of(p)) >= 2, "the launcher's command")
        return p


# ------------------------------------------------------------------------------------------------ R2C-1: the alert

def make_unreadable(path):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0)
    os.close(fd)
    return path


class QueueFileUnreadable(Stepped):
    """C-14 (R2C-1): mode-000 slot and ticket files: not held, one QUEUE_FILE_UNREADABLE key, the reading goes on."""

    def setUp(self):
        super().setUp()
        if os.geteuid() == 0:
            self.skipTest("root reads a mode 000 file")
        self.settings()

    def unreadable(self, slots, tickets):
        out = [make_unreadable(os.path.join(self.q, ".slot.%d" % k)) for k in slots]
        out += [make_unreadable(os.path.join(self.q, "queue", "%d-%d" % (time.time_ns(), 70000 + i)))
                for i in range(tickets)]
        return out

    def the_alert(self):
        got = named(self.data, "QUEUE_FILE_UNREADABLE")
        self.assertEqual(len(got), 1, "exactly one QUEUE_FILE_UNREADABLE key: %s" % sorted(got))
        a = list(got.values())[0]
        self.assertEqual(a.get("level"), "ATTENTION", a)
        return a.get("text") or ""

    def named_paths(self, text, paths):
        return [p for p in paths if any(f in text for f in path_forms(p))]

    @mmtest.needs_proc
    def test_eleven_unreadable_files_give_one_alert_and_the_call_is_still_paused(self):
        call = self.call()
        files = self.unreadable([5, 6, 8, 9], 7)
        self.red = True
        self.step(self.supervisor(), n=3)
        self.assert_paused_exactly(call)
        text = self.the_alert()
        self.assertEqual(len(self.named_paths(text, files)), 5, "the alert names 5 of the 11 paths: %s" % text)
        strip = [f for p in files for f in path_forms(p)] + [self.root, os.path.realpath(self.root)]
        self.assertTrue(names_count(text, 11, strip), "the alert names the count 11: %s" % text)

    @mmtest.needs_proc
    def test_one_unreadable_ticket_is_named_with_its_count(self):
        call = self.call()
        files = self.unreadable([], 1)
        self.red = True
        self.step(self.supervisor(), n=3)
        self.assert_paused_exactly(call)
        text = self.the_alert()
        self.assertEqual(self.named_paths(text, files), files, text)

    def test_the_alert_clears_when_the_files_go(self):
        files = self.unreadable([5], 2)
        sup = self.supervisor()
        self.step(sup, n=2)
        self.the_alert()
        for p in files:
            os.unlink(p)
        self.step(sup, n=4, every=20)  # past the 30 s queue read, then a tick that sees the clean reading
        self.assertEqual(named(self.data, "QUEUE_FILE_UNREADABLE"), {}, "the alert clears when the files go")


# ------------------------------------------------------------------------------------------------ A1: a read-only lock

class ReadOnlyLockHolder(Stepped):
    """C-14 (A1): a held slot with no write opener: PAUSE_REFUSED names the slot, and nothing is paused."""

    def setUp(self):
        super().setUp()
        self.settings()
        with open(self.slot, "w") as f:
            f.write("S 1 go test ./x\n")

    def locked_by(self, argv, name):
        p = self.started_ready(argv, name)
        self.wait_until(lambda: r1.held(self.slot), "the slot to be locked")
        return p

    def check(self, p):
        self.red = True
        self.step(self.supervisor(), n=3)
        self.assert_nothing_paused(p)
        got = self.refusals()
        self.assertTrue(got, "a PAUSE_REFUSED alert")
        self.assertTrue(all(a.get("level") == "ATTENTION" for a in got), got)
        self.assertIn(".slot.1", "\n".join(a.get("text") or "" for a in got), "the alert names the slot")

    def test_a_read_only_lock_of_another_program_refuses_the_pause(self):
        self.check(self.locked_by([sys.executable, "-I", "-c", RO_LOCKER, self.slot], "ro-locker"))

    def test_a_read_only_lock_of_the_launcher_itself_refuses_the_pause(self):
        self.check(self.locked_by([sys.executable, "-I", self.launcher_path, "--lock-ro", self.slot], "ro-launcher"))


# ------------------------------------------------------------------------------------------------ N2: a fresh snapshot

class FreshSnapshot(Stepped):
    """C-14 (N2): the pause signals the call's tree as it is in that tick."""

    def setUp(self):
        super().setUp()
        self.settings()
        self.go = os.path.join(self.t, "go")

    @mmtest.needs_proc
    def test_a_child_started_after_an_older_snapshot_is_still_paused(self):
        call = self.call_of([sys.executable, "-I", "-c", CHILD_LATER, self.go])
        sup = self.supervisor()
        self.step(sup)  # GREEN: this tick reads the process list (and the next read is 30 s later)
        open(self.go, "w").close()
        self.wait_until(lambda: len(self.tree_of(call)) >= 3, "the command's new child")
        tree = self.tree_of(call)
        self.red = True
        self.step(sup, n=2)  # within the 30 s: no new process list from the tick's own schedule
        self.assertTrue(self.stopped(call.pid), "the queue call is paused")
        for pid in tree:
            self.assertTrue(self.stopped(pid), "pid %d of the call's tree is paused (a child newer than the last "
                                               "process list)" % pid)
        self.assertEqual(sorted(int(x) for x in mmrecover.read_paused()), tree)

    @mmtest.needs_proc
    def test_a_pid_that_ended_before_the_tick_is_never_signalled(self):
        call = self.call_of([sys.executable, "-I", "-c", CHILD_ENDS, self.go])
        self.wait_until(lambda: len(self.tree_of(call)) >= 3, "the command's child")
        before = self.tree_of(call)
        sup = self.supervisor()
        self.step(sup)  # GREEN: the process list holds the child
        open(self.go, "w").close()
        self.wait_until(lambda: len(self.tree_of(call)) == 2, "the child to end")
        gone = sorted(set(before) - set(self.tree_of(call)))
        self.assertEqual(len(gone), 1, (before, self.tree_of(call)))
        self.red = True
        self.step(sup, n=2)
        self.assertTrue(self.stopped(call.pid), "the queue call is paused")
        self.assertNotIn(gone[0], [pid for pid, sig in self.signals], "a pid that ended before the tick is signalled")
        self.assertNotIn(str(gone[0]), mmrecover.read_paused(), "a pid that ended is recorded as paused")


# ------------------------------------------------------------------------------------------------ N3: one QWAIT key

class OneQwaitKey(Stepped):
    """C-14 (N3): six waiting tickets with distinct names give one QWAIT key, naming the count and the oldest."""

    def setUp(self):
        super().setUp()
        self.settings()

    def test_many_waiting_tickets_give_one_qwait_key(self):
        now = time.time()
        paths, args = [], []
        for i, label in enumerate(TICKET_LABELS):
            born = int((now - (120 + 10 * i) * 60) * 1e9)  # the last one is the oldest
            p = os.path.join(self.q, "queue", "%d-%d" % (born, 71000 + i))
            paths.append(p)
            args += [p, "wait-" + label]
        ready = self.ready_file("tickets")
        self.start([sys.executable, "-I", "-c", TICKETS, ready] + args)
        self.wait_until(lambda: os.path.exists(ready), "the tickets to be held")
        self.step(self.supervisor(), n=2)
        got = {k: v for k, v in named(self.data, "QWAIT").items() if k != "QWAIT:hour"}
        self.assertEqual(len(got), 1, "one QWAIT key for all waiting tickets: %s" % sorted(got))
        key, a = list(got.items())[0]
        for p in paths:
            self.assertNotIn(os.path.basename(p), key, "a QWAIT key from a ticket's name")
        text = a.get("text") or ""
        oldest = paths[-1]
        self.assertTrue(os.path.basename(oldest) in text or "wait-" + TICKET_LABELS[-1] in text,
                        "the alert names the oldest ticket: %s" % text)
        strip = [os.path.basename(p) for p in paths] + [f for p in paths for f in path_forms(p)]
        self.assertTrue(names_count(text, len(paths), strip), "the alert names the count %d: %s" % (len(paths), text))


# ------------------------------------------------------------------------------------------------ N4: list alerts

class CleanupListAlertsLifetime(Stepped):
    """C-14 (N4): CLEANUP_LIST and the list's LINK_SKIPPED keep their state until the cleanup list next runs."""

    def setUp(self):
        super().setUp()
        self.real = os.path.join(self.t, "old-scratch")
        tsh.make(self.real)
        self.linked = self.link(tsh.make(os.path.join(self.t, "elsewhere")), os.path.join(self.t, "linked-scratch"))
        prof = os.path.join(self.root, "profile.toml")
        with open(mmtest.PROFILE) as f:
            text = f.read()
        text += "\n[[deletes.cleanup]]\nid = \"P1\"\ntype = \"paths\"\npaths = %s\nwhy = \"listed path\"\n" % json.dumps(
            [self.real, self.linked])
        with open(prof, "w") as f:
            f.write(text)
        os.environ["MM_PROFILE"] = prof  # TempData puts the old value back
        # disk.cache_action_disk_gb at its lowest: the list keeps its own interval (no hourly list on a low disk)
        self.settings(**{"deletes.enabled": True, "disk.cache_action_disk_gb": 1})

    def link_alerts(self):
        return [a for a in named(self.data, "LINK_SKIPPED").values()
                if any(f in (a.get("text") or "") for f in path_forms(self.linked))]

    def test_the_lists_alerts_stay_until_the_list_runs_again(self):
        sup = self.supervisor(slow_jobs=True)
        s = sup.settings.load()
        self.step(sup, n=2)  # the first run (rules and list) and the tick that takes its result
        self.assertTrue(named(self.data, "CLEANUP_LIST"), "the list raises CLEANUP_LIST")
        self.assertTrue(self.link_alerts(), "the list raises LINK_SKIPPED for the linked path")
        start = self.clock["t"]
        self.clock["t"] += s["deletes.interval_minutes"] * 60 + 60
        self.step(sup, n=3)  # a rules-only run (the list waits its hours) and the ticks after it
        self.assertTrue(named(self.data, "CLEANUP_LIST"), "CLEANUP_LIST stays until the list runs again")
        self.assertTrue(self.link_alerts(), "the list's LINK_SKIPPED stays until the list runs again")
        os.unlink(self.linked)
        self.links.remove(self.linked)
        self.clock["t"] = start + s["deletes.cleanup_list_hours"] * 3600 + 60
        self.step(sup, n=3)  # the list's next run: the link is gone
        self.assertEqual(self.link_alerts(), [], "the list's next run updates its LINK_SKIPPED")
        self.assertTrue(named(self.data, "CLEANUP_LIST"), "the real path is still a candidate")


if __name__ == "__main__":
    unittest.main()
