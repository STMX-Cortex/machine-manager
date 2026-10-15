# SPDX-License-Identifier: Apache-2.0
"""Review round 10, part C (rule 47, the pause): a queue call started by a launcher path relative to its working folder.

Rule 47: the pid to pause comes from the process that holds the slot file open; it is paused only if its command line
is the queue launcher of the configured queue folder. Settlement C-5: each opener whose command line runs the configured
queue folder's launcher is paused with its children; no other process is ever paused.

A call started as `python3 <relative path>/<launcher> ...` from a folder where that path names the configured launcher runs
the configured launcher. The first three tests start the fixture launcher that way (the form a project's own recipes and
alert texts may give, with `--exclusive` and an extra environment variable in one of them) and expect it paused with no
PAUSE_REFUSED. The last test is the guard for any fix: the same relative text, resolved from another folder, names
another file, and that holder is never paused.

Run from the repository root (not registered in tests/run_tests.py):
    python3 -I -c "import sys; sys.path.insert(0, 'tests'); import unittest; \
        unittest.main(module='test_sandbox_holds_review', argv=['x'])"

Every fixture lives in the test's own temporary folder. The only processes signalled are ones the test started: a guard
around os.kill refuses (and records) any SIGSTOP or SIGCONT to another pid."""
import os
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock

import mmtest  # noqa: F401  (sets sys.path for the code)
from mmtest import TempData, mmread
import mmrecover
import mmsuper
import test_sandbox_holds as tsh


class RelativeLauncherPause(TempData):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir(slots=5)
        self.t = os.path.realpath(os.path.join(self.root, "t"))
        os.makedirs(self.t)
        self.started = []
        self.refused = []
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

    # -- helpers (as tests/test_sandbox_holds.py, Rule47Pause)

    def start(self, argv, cwd=None, env=None):
        p = subprocess.Popen(argv, cwd=cwd, env=dict(os.environ, **(env or {})), stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        self.started.append(p)
        return p

    def mine(self):
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

    def label(self, slot):
        with open(slot) as f:
            return f.readline().strip()

    def held_by(self, slot, pid):
        return mmread.flock_held(slot)[0] and " %d " % pid in " %s " % self.label(slot)

    def tick_red(self, n=3):
        real_kill, real_killpg = os.kill, os.killpg
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
        with mock.patch.object(os, "kill", kill), mock.patch.object(os, "killpg", killpg):
            sup = mmsuper.Supervisor(self.profile(), kernel=False, clock=lambda: clock["t"], sampler=tsh.CRITICAL,
                                     sizes=False, slow_jobs=False, check_readings=False)
            for _ in range(n):
                sup.tick()
                clock["t"] += 10
        self.assertEqual(self.refused, [], "a signal to a process this test did not start")
        return sup

    def stopped(self, pid):
        return tsh.proc_stat(pid).startswith("T")

    def refusals(self):
        return [a for a in tsh.alert_records(self.data) if a.get("name") == "PAUSE_REFUSED"]

    def relative_call(self, cwd, rel, extra=(), env=None, slot=".slot.1"):
        """The fixture launcher started as `python -I <rel> [extra] -- sleep 300` from `cwd`; waits until it holds
        `slot` and runs its sleep."""
        self.assertEqual(os.path.realpath(os.path.join(cwd, rel)), os.path.realpath(os.path.join(self.q, "launcher.py")),
                         "the relative path names the configured launcher from that folder")
        p = self.start([sys.executable, "-I", rel] + list(extra) + ["--", "/bin/sleep", "300"], cwd=cwd, env=env)
        s = os.path.join(self.q, slot)
        self.wait_until(lambda: self.held_by(s, p.pid), "the launcher to hold " + slot)
        self.wait_until(lambda: len(self.mine()) >= 2, "the launcher's child")
        return p

    def assert_call_paused(self, call):
        kids = [pid for pid in self.mine() if pid != call.pid]
        self.assertTrue(self.stopped(call.pid), "the queue launcher that holds the slot is paused")
        self.assertTrue(kids and all(self.stopped(k) for k in kids), "its command is paused")
        self.assertEqual(sorted(int(x) for x in mmrecover.read_paused()), sorted([call.pid] + kids))
        self.assertEqual(self.refusals(), [], "no PAUSE_REFUSED: the opener runs the configured launcher")

    # -- the configured launcher, started by a relative path

    def test_a_call_started_by_a_path_relative_to_the_parent_folder_is_paused(self):
        """`python3 <dir>/<launcher> -- CMD` from the folder above the queue folder (a recipe's form)."""
        call = self.relative_call(os.path.dirname(self.q), os.path.join(os.path.basename(self.q), "launcher.py"))
        self.tick_red()
        self.assert_call_paused(call)

    def test_a_call_started_inside_the_queue_folder_is_paused(self):
        """`python3 <launcher> -- CMD` from the queue folder itself."""
        call = self.relative_call(self.q, "launcher.py")
        self.tick_red()
        self.assert_call_paused(call)

    def test_an_exclusive_call_by_a_relative_path_with_an_extra_environment_is_paused(self):
        """The trim command's form: `X=1 python3 <rel>/<launcher> --exclusive -- CMD` (it holds every slot)."""
        call = self.relative_call(os.path.dirname(self.q), os.path.join(os.path.basename(self.q), "launcher.py"),
                                  extra=["--exclusive"], env={"QUEUE_EXCLUSIVE_OK": "1", "QUEUE_CALLER_TAG": "1"},
                                  slot=".slot.3")
        self.tick_red()
        self.assert_call_paused(call)

    # -- the guard: the same relative text from another folder names another file

    def test_the_same_relative_text_from_another_folder_is_never_paused(self):
        other = os.path.join(self.t, os.path.basename(os.path.dirname(self.q)))
        fake_q = os.path.join(other, os.path.basename(self.q))
        os.makedirs(fake_q)
        with open(os.path.join(fake_q, "launcher.py"), "w") as f:
            f.write(tsh.HOLDER)
        rel = os.path.join(os.path.basename(self.q), "launcher.py")
        slot = os.path.join(self.q, ".slot.1")
        h = self.start([sys.executable, "-I", rel, slot, "S SELF go test ./x"], cwd=other)
        self.wait_until(lambda: self.held_by(slot, h.pid), "the holder to hold the slot")
        self.tick_red()
        self.assertFalse(self.stopped(h.pid), "a relative path that names another file is not the launcher")
        self.assertEqual(mmrecover.read_paused(), {}, "nothing is recorded as paused")
        got = self.refusals()
        self.assertTrue(got and str(h.pid) in "\n".join(a.get("text") or "" for a in got), got)


if __name__ == "__main__":
    unittest.main()
