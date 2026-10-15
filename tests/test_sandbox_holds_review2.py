# SPDX-License-Identifier: Apache-2.0
"""Review round 10, part C, review round 2: the fix of C-10, C-11, C-12 and R10C-1 (README.md, "Agent-written files").

R2C-1 (C-12: slot and ticket files). Agents may create the queue's slot and ticket files (regular files only, create and
data). A regular file created with mode 000 cannot be opened for reading by the tool, and a Unix socket at such a path
cannot be opened at all (EOPNOTSUPP). Either one makes the whole queue read fail: the supervisor then has no queue
reading, so at a critical RED the real queue call is never paused, and no alert says why. C-12 asks that a path that is
not a regular file count as not held and raise SLOT_NOT_A_FILE (README item 3: "A link, a FIFO or any other kind
there"); one agent-made file must not cost the reading of every other slot. Expected: the real call is still paused;
a socket raises SLOT_NOT_A_FILE naming its path.

R2C-2 (C-11: DELETES_FAILED). A cleanup-list failure raises DELETES_FAILED naming `cleanup_list`. The list runs only
every deletes.cleanup_list_hours (24 h by default), the delete rules every deletes.interval_minutes (180 min). The next
rules-only run must not clear the alert while the list still fails and has not run again.

R2C-3 (C-11: DELETES_FAILED text). When the whole deletes job fails (outside any rule), the alert must not say that the
other rules and the cleanup list still run: none of them ran.

Run from the repository root (not registered in tests/run_tests.py):
    python3 -I -c "import sys; sys.path.insert(0, 'tests'); import unittest; \
        unittest.main(module='test_sandbox_holds_review2', argv=['x'])"

Every fixture lives in the test's own temporary folder. The only processes signalled are ones the test started (the
guard of test_sandbox_holds_r1.PauseBase.tick_red)."""
import json
import os
import socket
import time
import unittest
from unittest import mock

import mmtest  # noqa: F401  (sets sys.path for the code)
import mmdelete
import mmsuper
import test_sandbox_holds as tsh
import test_sandbox_holds_r1 as r1


def make_unreadable(path):
    """A regular file created with mode 000, as an agent's create call may make it (the agent profile allows the
    create of a regular file there; the mode is part of the create)."""
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0)
    os.close(fd)
    return path


# ------------------------------------------------------------------------------------------------ R2C-1: queue files

class UnreadableQueueFile(r1.PauseBase):
    """R2C-1: an agent-made slot or ticket file that the tool cannot open does not cost the queue reading."""

    def setUp(self):
        super().setUp()
        if os.geteuid() == 0:
            self.skipTest("root reads a mode 000 file")

    def assert_unreadable(self, path):
        with self.assertRaises(PermissionError, msg="the fixture is unreadable for this user"):
            open(path).close()

    def test_an_unreadable_ticket_does_not_stop_the_pause(self):
        call = self.call()
        ticket = make_unreadable(os.path.join(self.q, "queue", "%d-%d" % (time.time_ns(), os.getpid())))
        self.assert_unreadable(ticket)
        self.tick_red()
        self.assert_paused_exactly(call)

    def test_an_unreadable_slot_file_does_not_stop_the_pause(self):
        call = self.call()
        slot = make_unreadable(os.path.join(self.q, ".slot.9"))
        self.assert_unreadable(slot)
        self.tick_red()
        self.assert_paused_exactly(call)


class SocketAtAQueuePath(r1.PauseBase):
    """R2C-1: a Unix socket at a slot or ticket path is not a regular file: not held, SLOT_NOT_A_FILE (C-12)."""

    def bind(self, folder, name):
        """A Unix socket bound at folder/name (bound by a relative name: the full path may pass the 104-byte limit)."""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(s.close)
        old = os.getcwd()
        os.chdir(folder)
        try:
            s.bind(name)
        finally:
            os.chdir(old)
        return os.path.join(folder, name)

    def test_a_socket_at_an_idle_slot_path_counts_as_not_held_and_alerts(self):
        call = self.call()
        path = self.bind(self.q, ".slot.7")
        self.tick_red()
        self.assert_paused_exactly(call)
        self.assert_slot_not_a_file(path)

    def test_a_socket_ticket_counts_as_not_held_and_alerts(self):
        call = self.call()
        path = self.bind(os.path.join(self.q, "queue"), "%d-%d" % (time.time_ns(), os.getpid()))
        self.tick_red()
        self.assert_paused_exactly(call)
        self.assert_slot_not_a_file(path)


# ------------------------------------------------------------------------------------------------ R2C-2, R2C-3: deletes

class DeletesFailedLifetime(r1.MarkerBase):
    """R2C-2 and R2C-3: the DELETES_FAILED alert while its cause holds, and its text when the whole job failed."""

    def supervisor(self, rules, clock):
        prof = os.path.join(self.root, "profile.toml")
        with open(mmtest.PROFILE) as f:
            text = f.read()
        for r in rules:
            text += "\n[[deletes.rules]]\n" + "\n".join("%s = %s" % (k, json.dumps(v)) for k, v in r.items()) + "\n"
        with open(prof, "w") as f:
            f.write(text)
        os.environ["MM_PROFILE"] = prof  # TempData puts the old value back
        # disk.cache_action_disk_gb at its lowest: the list keeps its own interval (no hourly list on a low disk)
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "deletes.enabled": True, "disk.cache_action_disk_gb": 1})
        return mmsuper.Supervisor(self.profile(), kernel=False, clock=lambda: clock["t"], sampler=tsh.sampler_of(),
                                  sizes=False, slow_jobs=True, check_readings=False)

    def tick(self, sup):
        sup.tick()
        if sup.deletes.thread is not None:
            sup.deletes.thread.join(r1.STEP_LIMIT_S)

    def active(self, name):
        """The active alerts of that name (alerts-state.json)."""
        try:
            with open(os.path.join(self.data, "alerts-state.json")) as f:
                st = json.load(f)
        except (OSError, ValueError):
            return []
        return [a for a in (st.get("active") or {}).values() if isinstance(a, dict) and a.get("name") == name]

    def test_a_cleanup_list_failure_stays_raised_while_the_list_has_not_run_again(self):
        good, _ = self.cache("good")
        clock = {"t": time.time()}

        def cleanup_list(ctx, now, sizes=True):
            raise RuntimeError("planted cleanup fault 9c1e")

        def steps():
            sup = self.supervisor([r1.cache_rule("S5b", good)], clock)
            with mock.patch.object(mmdelete, "cleanup_list", cleanup_list):
                for _ in range(2):  # the first run (rules and list) and the tick that takes its result
                    self.tick(sup)
                    clock["t"] += 10
                raised = [a for a in self.active("DELETES_FAILED") if "cleanup_list" in (a.get("text") or "")]
                # the next rules-only run (the list waits its hours), then past repeat.clear_after_minutes
                clock["t"] += sup.settings.load()["deletes.interval_minutes"] * 60 + 60
                for _ in range(3):
                    self.tick(sup)
                    clock["t"] += 6 * 60
                return raised, [a for a in self.active("DELETES_FAILED") if "cleanup_list" in (a.get("text") or "")]
        raised, later = r1.run_within(steps, r1.STEP_LIMIT_S * 4)
        self.assertTrue(raised, "the cleanup-list failure raises DELETES_FAILED")
        self.assertTrue(later, "DELETES_FAILED for cleanup_list stays while the list still fails and has not run "
                               "again (a rules-only run cleared it)")

    def test_a_whole_job_failure_does_not_say_the_rules_and_the_list_still_ran(self):
        good, files = self.cache("good")
        clock = {"t": time.time()}

        def failing_run(*a, **kw):
            raise RuntimeError("planted job fault 4b2d")

        def steps():
            sup = self.supervisor([r1.cache_rule("S5b", good)], clock)
            with mock.patch.object(mmdelete, "Run", failing_run):
                for _ in range(3):
                    self.tick(sup)
                    clock["t"] += 10
        r1.run_within(steps, r1.STEP_LIMIT_S * 4)
        self.assert_kept(files)  # no rule ran
        got = self.active("DELETES_FAILED")
        self.assertTrue(got, "the job's failure raises DELETES_FAILED")
        text = "\n".join(a.get("text") or "" for a in got)
        self.assertIn("planted job fault 4b2d", text, "the alert names the error")
        self.assertNotIn("still run", text, "no rule and no cleanup list ran: the alert must not say they still run")


if __name__ == "__main__":
    unittest.main()
