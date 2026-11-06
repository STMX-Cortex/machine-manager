# SPDX-License-Identifier: Apache-2.0
"""Live risks 1-3, review round 1 (six faults): a parent folder swapped for a link right before an own_files delete;
a broken safe.json or off.json writes no slot at all; a pid above 2**31-1 (or 0) in paused.json is a broken record;
user fields named "broken" or a non-text "reason" in a valid off.json / safe.json; `mm on` with a folder in place of a
control file; `mm status` without status.json shows a broken file.

Helpers come from test_live_risks (imported as a module, so its tests do not run twice). Every file lives in the test's
temporary folder; no signal is sent to anything (SignalSpy)."""
import json
import os
import shutil
import time
import unittest

import mmtest
from mmtest import mmcore
import mmrecover
import mmwatch
import test_live_risks as lr


# ===================================================================================== 1: a parent swapped for a link

def fresh_alerts(data):
    """A subtest starts with no alert (an alert clears only after repeat.clear_after_minutes absent)."""
    try:
        os.remove(os.path.join(data, "alerts-state.json"))
    except FileNotFoundError:
        pass


class _Proxy:
    """A stand-in for a module inside mmdelete: every name is the real one, except the calls in `hooked`, which first
    run `before(path)`."""

    def __init__(self, real, hooked, before):
        self._real, self._hooked, self._before = real, hooked, before

    def __getattr__(self, name):
        attr = getattr(self._real, name)
        if name not in self._hooked:
            return attr

        def call(path, *a, **kw):
            self._before(path)
            return attr(path, *a, **kw)
        return call


class R1ParentSwap(lr.F2Base):
    """files=["state/rotated"], old and valid. Right before the delete (the first remove, unlink, rmdir or rmtree of
    it, or an open of `state` or below), `state` becomes a link to an outside folder that holds a file of the same
    name. The outside file must survive, and the rule gives a KEEP refusal."""

    def setUp(self):
        super().setUp()
        import mmdelete
        self.mmdelete = mmdelete
        self.state = os.path.join(os.path.realpath(self.data), "state")
        self.inside = self.old_file(os.path.join(self.state, "rotated"), "inside")
        self.victim = self.old_file(os.path.join(self.outside, "rotated"), "outside: never deleted")
        self.swapped = False
        real_os, real_shutil = mmdelete.os, mmdelete.shutil
        mmdelete.os = _Proxy(real_os, ("remove", "unlink", "rmdir", "open"), self.maybe_swap)
        mmdelete.shutil = _Proxy(real_shutil, ("rmtree",), self.maybe_swap)
        self.addCleanup(setattr, mmdelete, "os", real_os)
        self.addCleanup(setattr, mmdelete, "shutil", real_shutil)

    def maybe_swap(self, path):
        if self.swapped or not isinstance(path, str):
            return
        name = path.rstrip(os.sep)
        if not (name.endswith("rotated") or name == self.state or name.startswith(self.state + os.sep)
                or os.path.basename(name) == "state"):
            return
        self.swapped = True
        os.rename(self.state, self.state + ".real")
        os.symlink(self.outside, self.state)

    def test_swap_before_the_delete_keeps_the_outside_file(self):
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["state/rotated"]}])
        self.assertTrue(self.swapped, "the swap ran (the delete path was reached): %s" % r.lines)
        self.assertTrue(os.path.exists(self.victim), "the outside file is deleted through the swapped link: %s"
                        % r.lines)
        self.assertEqual(open(self.victim).read(), "outside: never deleted")
        recs = self.recs(r)
        self.assertTrue(any(x["verb"] == "KEEP" for x in recs), r.lines)
        self.assertFalse([x for x in recs if x["verb"] == "DELETE"], r.lines)

    def test_control_without_a_swap_deletes(self):
        """The fixture: with the hooks on but no link swapped in, the inside file is deleted (so the test above
        reaches the delete path)."""
        self.swapped = True  # never swap
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["state/rotated"]}])
        self.assertFalse(os.path.lexists(self.inside), r.lines)
        self.assertTrue(os.path.exists(self.victim))
        self.assertEqual([x["verb"] for x in self.recs(r)], ["DELETE"])


# ===================================================================================== 2: no slot write at all

class R2NoSlotWrite(lr.SupBase):
    """A broken safe.json or off.json in act mode on a RED machine: the slots file stays as it is (8). A valid safe.json
    keeps today's safe-mode step down (8 -> 5)."""

    def red_act(self, slots, n):
        test_slots = os.path.join(self.root, "test-slots")
        mmcore.write_slots(test_slots, slots)
        self.act(**{"mode.slot_writes": "test", "mode.slots_file": test_slots})
        clock = {"t": time.time()}
        self.ticks(self.sup(lr.RED, clock=lambda: clock["t"]), n, clock)
        return open(test_slots).read()

    def test_control_valid_safe_json_steps_down_to_5(self):
        mmrecover.enter_safe("test", time.time())
        self.assertEqual(self.red_act(8, 1), "5\n")
        self.assertEqual(mmcore.safe_state()["slot_write"], "SET 8 -> 5")

    def test_control_no_guard_steps_down(self):
        self.assertNotEqual(self.red_act(8, 3), "8\n", "the fixture writes on RED without a guard")

    def test_broken_safe_json_writes_no_slot(self):
        for text in ("[]", "{}", '{"safe": 1}', '{"safe": tru'):
            with self.subTest(safe=text):
                target = os.path.join(self.data, "safe.json")
                lr.write_raw(target, text)
                self.assertEqual(self.red_act(8, 3), "8\n", "no slot write with safe.json %s" % text)
                self.assertNotIn("SET slots", self.decisions())
                self.assertEqual(lr.raw(target), text.encode())

    def test_broken_off_json_writes_no_slot(self):
        for text in ("[]", "{}", '{"off": 1}', '{"off": tru'):
            with self.subTest(off=text):
                lr.write_raw(os.path.join(self.data, "off.json"), text)
                self.assertEqual(self.red_act(8, 3), "8\n", "no slot write with off.json %s" % text)
                self.assertNotIn("SET slots", self.decisions())


# ===================================================================================== 3: pids out of range

class R3PidRange(lr.F3PausedBase):
    """A pid key above 2**31-1 (or 0) is not a pid: PausedBroken; nothing crashes, nothing is signalled."""
    BAD = ("9999999999", "2147483648", "4294967296", "0")

    def test_out_of_range_keys_are_paused_broken(self):
        for key in self.BAD:
            with self.subTest(key=key):
                lr.write_raw(self.paused(), json.dumps({key: "birth"}))
                d = mmrecover.read_paused()
                self.assertIsInstance(d, mmrecover.PausedBroken)
                self.assertTrue(mmrecover.paused_problem(d).startswith("state/paused.json: "))

    def test_the_largest_pid_is_still_good(self):
        lr.write_raw(self.paused(), json.dumps({"2147483647": "birth", "1": "boot"}))
        d = mmrecover.read_paused()
        self.assertNotIsInstance(d, mmrecover.PausedBroken)
        self.assertEqual(d, {"2147483647": "birth", "1": "boot"})

    def test_supervisor_start_and_tick_do_not_crash(self):
        spy = lr.SignalSpy(self)
        self.act()
        for key in self.BAD:
            with self.subTest(key=key):
                fresh_alerts(self.data)
                lr.write_raw(self.paused(), json.dumps({key: "birth"}))
                before = lr.raw(self.paused())
                sup = self.sup()  # the start check: no crash
                sup.tick()
                st = mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {})
                self.assertIn("PAUSED_FILE_BROKEN", st["active"], self.active())
                self.assertEqual(lr.raw(self.paused()), before)
        self.assertEqual(spy.calls, [])

    def test_watchdog_recovery_does_not_crash(self):
        spy = lr.SignalSpy(self)
        lr.write_raw(os.path.join(self.data, "state", "stopped.json"), json.dumps({"time": time.time()}))
        for key in self.BAD:
            with self.subTest(key=key):
                fresh_alerts(self.data)
                lr.write_raw(self.paused(), json.dumps({key: "birth"}))
                probs = mmwatch.check(time.time(), self.s(), self.profile(), restart=False)
                self.assertTrue([p for p in probs if p.startswith("state/paused.json: ")], probs)
                st = mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {})
                self.assertIn("WD:paused-file", st["active"])
        self.assertEqual(spy.calls, [])

    def test_resume_paused_does_not_crash(self):
        spy = lr.SignalSpy(self)
        for key in self.BAD:
            with self.subTest(key=key):
                lr.write_raw(self.paused(), json.dumps({key: "birth"}))
                self.assertEqual(mmrecover.resume_paused("test"), [])
        self.assertEqual(spy.calls, [])

    def test_recover_paused_command_does_not_crash(self):
        lr.write_raw(self.paused(), json.dumps({"9999999999": "birth"}))
        r = self.mm("recover-paused")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertTrue(r.stdout.startswith('resumed="" broken="state/paused.json: '), r.stdout)
        self.assertNotIn("Traceback", r.stderr)


# ===================================================================================== 4: user fields

class R4UserFields(lr.SupBase):
    """A valid off.json / safe.json that holds a field named "broken", or a "reason" that is not a text: a valid guard,
    no crash, no CONTROL_FILE_BROKEN; a user field never becomes the broken text."""

    def alerts(self):
        st = mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {}) or {}
        return st.get("active") or {}

    def no_broken(self):
        self.assertEqual([k for k in self.alerts() if k.startswith("CONTROL_FILE_BROKEN")], [], self.alerts())
        self.assertEqual(mmcore.control_broken(), [])
        r = self.mm("status")
        self.assertFalse([l for l in r.stdout.splitlines() if l.startswith("broken=")], r.stdout)
        self.assertNotIn("broken", json.loads(self.mm("status", "--json").stdout))

    def test_off_json_with_a_broken_field(self):
        self.act()
        for value in (True, "off.json: fake problem", 5, None, ["x"]):
            with self.subTest(broken=value):
                fresh_alerts(self.data)
                lr.write_raw(os.path.join(self.data, "off.json"),
                             json.dumps({"off": True, "broken": value, "since": "x", "reason": "by hand"}))
                self.assertTrue(mmcore.off_state())
                self.assertEqual(mmcore.control_problem("off.json", "off")[1], None)
                self.sup().tick()  # no crash
                self.assertEqual(self.status()["mode"], "off")
                self.assertIn("OFF", self.alerts())
                self.assertIn("by hand", self.alerts()["OFF"]["text"])
                self.assertNotIn("fake problem", json.dumps(self.alerts()))
                self.no_broken()

    def test_off_json_with_a_reason_that_is_not_text(self):
        self.act()
        for value in (5, True, ["x"], {"a": 1}, None):
            with self.subTest(reason=value):
                fresh_alerts(self.data)
                lr.write_raw(os.path.join(self.data, "off.json"), json.dumps({"off": True, "reason": value, "since": 1}))
                self.sup().tick()  # no crash in the alert evaluation
                self.assertIn("OFF", self.alerts())
                self.assertEqual(self.status()["mode"], "off")
                self.no_broken()

    def test_safe_json_with_a_broken_field_is_a_valid_safe_mode(self):
        self.act()
        lr.write_raw(os.path.join(self.data, "safe.json"),
                     json.dumps({"safe": True, "broken": "safe.json: fake problem", "since": time.time(),
                                 "reason": "real reason", "slot_write": None}))
        rec = mmcore.safe_state()
        self.assertTrue(rec)
        self.assertEqual(mmcore.control_problem("safe.json", "safe")[1], None)
        self.sup().tick()
        a = self.alerts().get("SAFE_MODE")
        self.assertIsNotNone(a, self.alerts())
        self.assertIn("real reason", a["text"])
        self.assertNotIn("fake problem", a["text"])
        self.no_broken()

    def test_safe_json_with_a_reason_that_is_not_text(self):
        self.act()
        for value in (5, ["x"], None):
            with self.subTest(reason=value):
                fresh_alerts(self.data)
                lr.write_raw(os.path.join(self.data, "safe.json"),
                             json.dumps({"safe": True, "reason": value, "since": time.time(), "slot_write": "x"}))
                self.sup().tick()
                self.assertIn("SAFE_MODE", self.alerts())
                self.no_broken()

    def test_safe_json_with_a_broken_field_still_steps_down(self):
        """A valid safe.json (slot_write null) keeps the step down, whatever user field it holds."""
        lr.write_raw(os.path.join(self.data, "safe.json"),
                     json.dumps({"safe": True, "broken": True, "since": time.time(), "reason": "r", "slot_write": None}))
        test_slots = os.path.join(self.root, "test-slots")
        mmcore.write_slots(test_slots, 8)
        self.act(**{"mode.slot_writes": "test", "mode.slots_file": test_slots})
        self.sup(lr.CALM).tick()
        self.assertEqual(open(test_slots).read(), "5\n")


# ===================================================================================== 5: `mm on` with a folder

class R5MmOnFolder(lr.SupBase):
    """A folder in place of safe.json or off.json: `mm on` cannot end it; it says so (E_CLEAR, exit 2), the guard stays
    set and the folder is not deleted (never a recursive delete)."""
    # removing a folder with os.remove: EPERM on macOS, EISDIR on Linux
    WHY = r"(PermissionError|IsADirectoryError)"
    SAFE = (r"E_CLEAR safe\.json was not removed \(%s\); safe mode and the unclean starts stay; fix: remove it by hand "
            r"\(mm on never deletes a folder\), then run it again" % WHY)
    OFF = (r"E_CLEAR off\.json was not removed \(%s\); actions stay off; fix: remove it by hand \(mm on never deletes "
           r"a folder\), then run mm on again" % WHY)

    def check_folder(self, name, fn, line):
        folder = os.path.join(self.data, name)
        os.makedirs(folder)
        lr.write_raw(os.path.join(folder, "keep.txt"), "the owner's file")
        r = self.mm("on")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertRegex(r.stdout.strip(), "^" + line + "$")
        self.assertEqual(len(r.stdout.splitlines()), 1, r.stdout)
        self.assertNotIn("Traceback", r.stderr)
        self.assertTrue(os.path.isdir(folder))
        self.assertEqual(open(os.path.join(folder, "keep.txt")).read(), "the owner's file")
        self.assertTrue(fn(), "the guard stays set")

    def test_safe_json_folder(self):
        lr.write_raw(os.path.join(self.data, "state", "starts.json"), "[1, 2, 3]")
        self.check_folder("safe.json", mmcore.safe_state, self.SAFE)
        self.assertEqual(lr.raw(os.path.join(self.data, "state", "starts.json")), b"[1, 2, 3]",
                         "the unclean starts stay")
        self.assertIn("SAFE MODE not cleared: safe.json was not removed (",
                      open(os.path.join(self.data, "state", "recovery.log")).read())

    def test_off_json_folder(self):
        self.check_folder("off.json", mmcore.off_state, self.OFF)

    def test_off_json_folder_after_a_cleared_safe_mode_says_so(self):
        mmrecover.enter_safe("test", time.time())
        line = self.OFF.replace("; actions stay off;", "; actions stay off; safe mode was cleared;")
        self.check_folder("off.json", mmcore.off_state, line)
        self.assertIsNone(mmcore.safe_state())

    def test_empty_folder_too(self):
        os.makedirs(os.path.join(self.data, "safe.json"))
        r = self.mm("on")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertRegex(r.stdout.strip(), "^" + self.SAFE + "$")
        self.assertTrue(os.path.isdir(os.path.join(self.data, "safe.json")))
        self.assertTrue(mmcore.safe_state())

    def test_clear_safe_raises_e_clear(self):
        os.makedirs(os.path.join(self.data, "safe.json"))
        with self.assertRaises(mmcore.MMError) as cm:
            mmrecover.clear_safe("test")
        self.assertRegex(str(cm.exception), "^" + self.SAFE + "$")
        self.assertTrue(os.path.isdir(os.path.join(self.data, "safe.json")))


class R5RestartClearSafeFolder(lr._RecoveryBase):
    @mmtest.darwin_only
    def test_restart_clear_safe_with_a_folder_stops_nothing(self):
        os.makedirs(os.path.join(self.data, "safe.json"))
        rc, out, err = self.run_mm("restart", "--clear-safe", FAKE_HEARTBEAT_PID="4343")
        self.assertEqual(rc, 2, out + [err])
        self.assertEqual(len(out), 1, out)
        self.assertRegex(out[0], "^" + R5MmOnFolder.SAFE + "$")
        self.assertEqual(self.launchctl(), [], "E_CLEAR comes first: the service is not stopped")
        self.assertTrue(os.path.isdir(os.path.join(self.data, "safe.json")))


# ===================================================================================== 6: no status.json

class R6StatusWithoutStatusJson(lr.SupBase):
    def test_nothing_broken_is_main_output(self):
        """The same bytes as main 45b4bd5 (bin/mm cmd_status: E_NO_STATUS, exit 3)."""
        self.assertFalse(os.path.exists(os.path.join(self.data, "status.json")))
        r = self.mm("status")
        self.assertEqual((r.returncode, r.stdout),
                         (3, "E_NO_STATUS no status.json in %s; fix: mm start (or mm install)\n" % self.data))
        r = self.mm("status", "--json")
        self.assertEqual((r.returncode, r.stdout), (3, '{"error": "E_NO_STATUS", "state": "UNKNOWN"}\n'))

    def test_broken_files_show(self):
        for name, text, problem in (("safe.json", "[]", "safe.json: not a JSON object"),
                                    ("off.json", "{}", "off.json: no off flag"),
                                    ("state/paused.json", "[]", "state/paused.json: not a JSON object")):
            with self.subTest(file=name):
                target = os.path.join(self.data, name)
                lr.write_raw(target, text)
                r = self.mm("status")
                self.assertEqual(r.returncode, 3, r.stdout)
                self.assertIn(problem, r.stdout)
                self.assertTrue(r.stdout.startswith("E_NO_STATUS "), r.stdout)
                self.assertLessEqual(len(r.stdout.splitlines()), 5)
                obj = json.loads(self.mm("status", "--json").stdout)
                self.assertEqual((obj["state"], obj["error"], obj["broken"]), ("UNKNOWN", "E_NO_STATUS", [problem]))
                os.remove(target)


# ===================================================================================== review round 2 (own_files)

class R7DataFolderSwap(lr.F2Base):
    """The data folder ITSELF swapped for a link (to an outside folder holding the same file names) at the first open
    of the data folder inside mmdelete. The outside file must survive, with a KEEP line; the rule refuses."""

    def setUp(self):
        super().setUp()
        import mmdelete
        self.data_real = os.path.realpath(self.data)
        self.inside = self.old_file(os.path.join(self.data_real, "old.log"), "inside")
        self.other = os.path.realpath(os.path.join(self.root, "outside2"))
        os.makedirs(self.other)
        self.victim = self.old_file(os.path.join(self.other, "old.log"), "outside: never deleted")
        self.swapped = False
        self.no_swap = False
        real_os = mmdelete.os
        mmdelete.os = _Proxy(real_os, ("open",), self.maybe_swap)
        self.addCleanup(setattr, mmdelete, "os", real_os)

    def maybe_swap(self, path):
        if self.swapped or self.no_swap or not isinstance(path, str):
            return
        if path.rstrip(os.sep) not in (self.data_real, self.data.rstrip(os.sep)):
            return
        self.swapped = True
        os.rename(self.data_real, self.data_real + ".real")
        os.symlink(self.other, self.data_real)

    def test_swap_at_the_first_open_keeps_the_outside_file(self):
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["old.log"]}])
        self.assertTrue(self.swapped, "the data folder was opened (the swap ran): %s" % r.lines)
        self.assertTrue(os.path.exists(self.victim), "the outside file is deleted through the swapped data folder: %s"
                        % r.lines)
        self.assertEqual(open(self.victim).read(), "outside: never deleted")
        recs = self.recs(r)
        self.assertTrue([x for x in recs if x["verb"] == "KEEP"], r.lines)
        self.assertFalse([x for x in recs if x["verb"] == "DELETE"], r.lines)

    def test_control_no_swap_deletes(self):
        self.no_swap = True
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["old.log"]}])
        self.assertFalse(os.path.lexists(self.inside), r.lines)
        self.assertTrue(os.path.exists(self.victim))
        self.assertEqual([x["verb"] for x in self.recs(r)], ["DELETE"])


class R8DotDotParts(lr.F2Base):
    """ANY name with a ".." part is refused, even one that normalizes back inside the data folder."""

    def test_link_then_dotdot(self):
        good = self.old_file(os.path.join(self.data, "old.log"))
        self.old_file(os.path.join(self.outside, "old.log"))
        os.symlink(self.outside, os.path.join(self.data, "linked"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["linked/../old.log"]}])
        self.assertTrue(os.path.exists(good), r.lines)
        self.assertTrue(os.path.exists(os.path.join(self.outside, "old.log")))
        recs = self.recs(r)
        self.assertEqual(len(recs), 1, r.lines)
        self.assertEqual(recs[0]["verb"], "KEEP")
        self.assertTrue(recs[0]["guard"].startswith("refused: files name"), r.lines)

    def test_dotdot_back_into_the_same_folder(self):
        os.makedirs(os.path.join(self.data, "a"))
        for name in ("state/../state/x", "state/./../state/x", "a/../state/x"):
            with self.subTest(name=name):
                x = self.old_file(os.path.join(self.data, "state", "x"))
                r = self.run_rules([{"id": "S1", "type": "own_files", "files": [name]}])
                self.assertTrue(os.path.exists(x), r.lines)
                recs = self.recs(r)
                self.assertEqual([x_["verb"] for x_ in recs], ["KEEP"], r.lines)
                self.assertTrue(recs[0]["guard"].startswith("refused: files name"), r.lines)

    def test_dotdot_slot_dir_back_inside(self):
        ev = lr.make(os.path.join(self.data, "evidence", "01"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": "state/../evidence", "files": []}])
        self.assertTrue(os.path.exists(ev), r.lines)
        recs = self.recs(r)
        self.assertEqual([x["verb"] for x in recs], ["KEEP"], r.lines)
        self.assertTrue(recs[0]["guard"].startswith("refused: slot_dir"), r.lines)

    def test_dots_inside_a_name_stay_allowed(self):
        """Only a ".." PART is refused: "a..b", "..x" and "x.." are ordinary names."""
        names = ["a..b", "..x", "x..", "state/decisions.log.1"]
        for n in names:
            self.old_file(os.path.join(self.data, n))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": names}])
        for n in names:
            self.assertFalse(os.path.lexists(os.path.join(self.data, n)), (n, r.lines))
        self.assertEqual([x["verb"] for x in self.recs(r)], ["DELETE"] * 4)

    def test_mm_check_refuses_a_dotdot_part(self):
        prof = os.path.join(self.root, "profile.toml")
        with open(mmtest.PROFILE) as f:
            text = f.read()
        with open(prof, "w") as f:
            f.write(text + '\n[[deletes.rules]]\nid = "S1"\ntype = "own_files"\nslot_dir = "state/../evidence"\n'
                    'files = ["linked/../old.log", "state/../state/x", "a..b"]\n')
        self.queue_dir()
        r = self.mm("check", "--profile", prof)
        lines = [l for l in r.stdout.splitlines() if l.startswith("E_PROFILE deletes rule")]
        self.assertEqual([l.split(" is ", 1)[0] if " is " in l else l.split(" has ", 1)[0] for l in lines],
                         ['E_PROFILE deletes rule S1: slot_dir "state/../evidence"',
                          'E_PROFILE deletes rule S1: files "linked/../old.log"',
                          'E_PROFILE deletes rule S1: files "state/../state/x"'], lines)
        self.assertEqual(r.returncode, 1)


class R9BadCharacters(lr.F2Base):
    """A name that cannot be checked (a NUL character, a name too long) refuses only that name: no rule failure."""

    def test_nul_name_refuses_only_itself(self):
        good = self.old_file(os.path.join(self.data, "old.log"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["bad\x00name", "old.log"]}])
        self.assertFalse(os.path.lexists(good), "old.log is still deleted: %s" % r.lines)
        recs = self.recs(r)
        self.assertEqual(sorted(x["verb"] for x in recs), ["DELETE", "KEEP"], r.lines)
        keep = [x for x in recs if x["verb"] == "KEEP"][0]
        self.assertTrue(keep["guard"].startswith("refused: files name"), r.lines)
        self.assertFalse([l for l in r.lines if "rule failed" in l], r.lines)

    def test_nul_in_a_folder_part(self):
        good = self.old_file(os.path.join(self.data, "old.log"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["state\x00/x", "old.log"]}])
        self.assertFalse(os.path.lexists(good), r.lines)
        self.assertFalse([l for l in r.lines if "rule failed" in l], r.lines)

    def test_nul_slot_dir_refuses_only_the_slots(self):
        good = self.old_file(os.path.join(self.data, "old.log"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": "evi\x00dence", "files": ["old.log"]}])
        self.assertFalse(os.path.lexists(good), r.lines)
        self.assertFalse([l for l in r.lines if "rule failed" in l], r.lines)
        self.assertTrue([x for x in self.recs(r) if x["guard"].startswith("refused: slot_dir")], r.lines)

    def test_a_name_too_long_refuses_only_itself(self):
        good = self.old_file(os.path.join(self.data, "old.log"))
        for name in ("x" * 5000, "a" * 300 + "/x", "state/" + "b" * 300):
            with self.subTest(name=name[:20]):
                r = self.run_rules([{"id": "S1", "type": "own_files", "files": [name, "old.log"]}])
                self.assertFalse([l for l in r.lines if "rule failed" in l], r.lines)
                self.assertFalse([x for x in self.recs(r) if x["verb"] == "DELETE" and x["path"].endswith(name)])
                self.old_file(good)

    def test_mm_check_nul_name(self):
        """A TOML text may hold \\u0000: mm check names the rule (no crash)."""
        prof = os.path.join(self.root, "profile.toml")
        with open(mmtest.PROFILE) as f:
            text = f.read()
        with open(prof, "w") as f:
            f.write(text + '\n[[deletes.rules]]\nid = "S1"\ntype = "own_files"\nfiles = ["bad\\u0000name", "old.log"]\n')
        self.queue_dir()
        r = self.mm("check", "--profile", prof)
        self.assertNotIn("Traceback", r.stderr)
        lines = [l for l in r.stdout.splitlines() if l.startswith("E_PROFILE deletes rule S1: files ")]
        self.assertEqual(len(lines), 1, r.stdout)
        self.assertEqual(r.returncode, 1)

if __name__ == "__main__":
    unittest.main()
