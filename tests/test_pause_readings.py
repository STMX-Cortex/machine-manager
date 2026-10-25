# SPDX-License-Identifier: Apache-2.0
"""Pause-release regression proofs: incomplete growth windows, cap changes, record-write failures,
uncertain process identity and restart/load controls. Process tests retain the reviewer's reproductions;
the unit group exercises the guards and recovery failures without outside commands."""
import json
import os
import signal
import unittest
from unittest.mock import patch

import mmtest
from mmtest import TempData, base_settings, mmcore
import mmdecide
import mmrecover
import mmsuper
import test_pause_max as tpm

STEP = 300  # Original swap-race reproduction: 1800 MB per minute, above the default 512 MB growth threshold.

class PauseReadingUnits(TempData):
    """Actual records and decision entry points, with all process facilities intercepted."""

    def sample(self, t):
        return dict(t=t, free_pct=80, swap_used_mb=100, swap_total_mb=2048, comp_mb=300, pressure=1,
                    seg_pct=1, load1=1, load5=1)

    def test_k1_n2_each_memory_gap_holds_until_it_leaves_the_growth_window(self):
        fields = ("free_pct", "swap_used_mb", "swap_total_mb", "comp_mb", "pressure", "seg_pct")
        for field in fields:
            for bad in (None, True, float("nan"), "missing"):
                for index in range(7):
                    with self.subTest(field=field, bad=bad, index=index):
                        window = [self.sample(t) for t in range(0, 70, 10)]
                        window[index][field] = bad
                        self.assertFalse(mmsuper.pause_readings_present(True, window))
                        window.append(self.sample(window[index]["t"] + 62))
                        self.assertTrue(mmsuper.pause_readings_present(True, window))

    def test_k1_n2_growth_window_uses_classifys_one_second_tolerance(self):
        window = [self.sample(0), self.sample(61)]
        window[0]["swap_used_mb"] = None
        self.assertFalse(mmsuper.pause_readings_present(True, window))
        window[-1]["t"] = 62
        self.assertTrue(mmsuper.pause_readings_present(True, window))
        self.assertFalse(mmsuper.pause_readings_present(True, []))

    def controller(self):
        sup = object.__new__(mmsuper.Supervisor)
        sup.state = {"paused_at": 0, "paused_call": "fixture call"}
        sup.cache, sup.dry = {}, False
        sup.log_decision = lambda line: None
        self.texts = []
        sup.hold = lambda key, name, level, text, until, **kw: self.texts.append(text)

        class Pauser:
            st = {"123": "start"}

            def __init__(self):
                self.resumes = []

            def resume(self, why="calm"):
                self.resumes.append(why)
                pids = [int(pid) for pid in self.st]
                self.st = {}
                return pids

        self.pauser, self.sup = Pauser(), sup
        self.settings = base_settings(**{"pause_newest_call.enabled": True, "pause_newest_call.max_minutes": 0.5,
                                        "pause_newest_call.resume_after_green_s": 60})
        self.enterContext(patch.object(mmsuper, "Pauser", return_value=self.pauser))

    def tick(self, now, state="AMBER", readings=True):
        self.sup._gate_and_pause(now, self.settings, state, [], True, readings_ok=readings)

    def test_k1_n2_both_release_paths_reject_a_gap_then_recover(self):
        for cap in (0, 0.5):
            with self.subTest(cap=cap):
                self.controller()
                self.settings["pause_newest_call.max_minutes"] = cap
                window = [self.sample(t) for t in range(0, 70, 10)]
                self.tick(60, "STEADY", mmsuper.pause_readings_present(True, window))
                self.assertTrue(self.pauser.st)
                window.append(self.sample(70))
                window[-1]["comp_mb"] = None
                for now in range(70, 141, 10):
                    if now > 70:
                        window.append(self.sample(now))
                    self.tick(now, "STEADY", mmsuper.pause_readings_present(True, window))
                    self.assertTrue(self.pauser.st)
                    if now < 140:
                        self.assertNotIn("green_for_pause", self.sup.state)
                if cap:
                    self.tick(150, "STEADY")
                else:
                    self.tick(190, "STEADY")
                    self.assertTrue(self.pauser.st)
                    self.tick(200, "STEADY")
                self.assertFalse(self.pauser.st)
                self.assertEqual(len(self.pauser.resumes), 1)

    def test_k2_every_inactive_cap_tick_drops_the_count(self):
        for cap in (0, 2):
            with self.subTest(cap=cap):
                self.controller()
                self.tick(30)
                self.assertEqual(self.sup.state["cap_clear_ticks"], 1)
                self.settings["pause_newest_call.max_minutes"] = cap
                self.tick(40)
                self.assertNotIn("cap_clear_ticks", self.sup.state)
                self.settings["pause_newest_call.max_minutes"] = 0.5
                self.tick(50)
                self.assertTrue(self.pauser.st)
                self.tick(60)
                self.assertFalse(self.pauser.st)

    def test_k4_incomplete_load_never_advances_either_release_path(self):
        self.controller()
        self.tick(30)
        window = [self.sample(40)]
        window[0]["load1"] = None
        complete = mmdecide.classify(window, self.settings)[2]
        self.assertFalse(complete)
        self.tick(40, "STEADY", mmsuper.pause_readings_present(complete, window))
        self.assertEqual(self.sup.state["cap_clear_ticks"], 0)
        self.assertNotIn("green_for_pause", self.sup.state)
        self.assertTrue(self.pauser.st)

    def test_k1_n2_supervisor_ticks_use_the_whole_window(self):
        self.queue_dir()
        self.write_settings(**{"mode.observe": False, "pause_newest_call.enabled": True,
                               "pause_newest_call.max_minutes": 0.5,
                               "pause_newest_call.resume_after_green_s": 60})
        clock = {"t": 1_800_000_000}
        reading = {}

        def sampler(now, ticks):
            return dict(self.sample(now), free_pct=52, **reading), ticks

        with patch.object(tpm.mmread, "read_ps", return_value=[]), patch.object(
                tpm.mmread, "disk_free_gb", return_value=tpm.DISK_GB), patch.object(
                mmrecover, "start_time", return_value="start"), patch.object(mmrecover.os, "kill") as kill:
            sup = mmsuper.Supervisor(self.profile(), kernel=False, sampler=sampler, sizes=False,
                                     slow_jobs=False, check_readings=False, clock=lambda: clock["t"])
            mmrecover.add_paused({"123": "start"})
            sup.state.update(paused_at=clock["t"] - 120, paused_call="fixture call")
            start = clock["t"]
            for offset in range(0, 100, 10):
                clock["t"] = start + offset
                reading.clear()
                if offset == 10:
                    reading["swap_used_mb"] = None
                sup.tick()
                with open(mmcore.path("status.json")) as f:
                    self.assertEqual(json.load(f)["state"], "STEADY")
                if offset < 90:
                    self.assertEqual(mmrecover.read_paused(), {"123": "start"})
                    kill.assert_not_called()
            self.assertEqual(mmrecover.read_paused(), {})
            kill.assert_called_once_with(123, signal.SIGCONT)

    def test_n1_read_failures_keep_the_record_send_nothing_and_retry(self):
        for failure in (None, OSError("cannot fork"), TimeoutError("ps timed out")):
            with self.subTest(failure=failure):
                mmrecover.add_paused({"123": "start"})
                options = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                with patch.object(mmrecover, "start_time", **options), patch.object(mmrecover.os, "kill") as kill:
                    self.assertEqual(mmrecover.resume_paused("read failure"), [])
                    self.assertEqual(mmrecover.read_paused(), {"123": "start"})
                    self.assertNotIn(unittest.mock.call(123, signal.SIGCONT), kill.call_args_list)
                with patch.object(mmrecover, "start_time", return_value="start"), patch.object(mmrecover.os, "kill") as kill:
                    self.assertEqual(mmrecover.resume_paused("retry"), [123])
                    kill.assert_called_once_with(123, signal.SIGCONT)
                self.assertEqual(mmrecover.read_paused(), {})
        with open(mmcore.path("state", "recovery.log")) as f:
            self.assertIn("record kept", f.read())

    def test_n1_only_gone_or_different_start_drops_an_uncontinued_pid(self):
        for current, error in ((None, ProcessLookupError()), ("different start", None)):
            with self.subTest(current=current):
                mmrecover.add_paused({"123": "start"})
                with patch.object(mmrecover, "start_time", return_value=current), patch.object(
                        mmrecover.os, "kill", side_effect=error) as kill:
                    self.assertEqual(mmrecover.resume_paused("gone"), [])
                    self.assertNotIn(unittest.mock.call(123, signal.SIGCONT), kill.call_args_list)
                self.assertEqual(mmrecover.read_paused(), {})

    def test_n1_permission_or_continue_failure_keeps_only_uncertain_pids(self):
        mmrecover.add_paused({"123": "start", "456": "start"})

        def kill(pid, sig):
            if pid == 123:
                raise PermissionError("refused")

        with patch.object(mmrecover, "start_time", return_value="start"), patch.object(mmrecover.os, "kill", side_effect=kill):
            self.assertEqual(mmrecover.resume_paused("signal failure"), [456])
        self.assertEqual(mmrecover.read_paused(), {"123": "start"})
        with patch.object(mmrecover, "start_time", return_value=None), patch.object(mmrecover.os, "kill", side_effect=kill):
            self.assertEqual(mmrecover.resume_paused("existence uncertain"), [])
        self.assertEqual(mmrecover.read_paused(), {"123": "start"})

    def test_k3_signal_success_record_failure_reports_what_happened(self):
        self.controller()
        mmrecover.add_paused({"123": "start"})
        real_write = mmcore.write_atomic

        def fail_record(path, text, *a, **kw):
            if path == mmrecover.paused_file():
                raise OSError("disk full")
            return real_write(path, text, *a, **kw)

        class Recorded:
            st = property(lambda self: mmrecover.read_paused())

            def resume(self, why):
                return mmrecover.resume_paused(why)

        with patch.object(mmrecover, "start_time", return_value="start"), patch.object(mmrecover.os, "kill") as kill, patch.object(
                mmcore, "write_atomic", side_effect=fail_record):
            self.sup._resume_at_cap(40, 0.5, "AMBER", Recorded())
            kill.assert_called_once_with(123, signal.SIGCONT)
        self.assertEqual(mmrecover.read_paused(), {"123": "start"})
        self.assertIn("continued", self.texts[-1])
        self.assertIn("record was not written", self.texts[-1])
        self.assertNotIn("stays paused", self.texts[-1])
        with patch.object(mmrecover, "start_time", return_value="start"), patch.object(mmrecover.os, "kill"):
            self.assertEqual(mmrecover.resume_paused("write recovered"), [123])
        self.assertEqual(mmrecover.read_paused(), {})


class Harness(tpm.PauseMax):
    def status(self):
        return json.load(open(os.path.join(self.data, "status.json")))

    def race_tick(self, read=True):
        """One tick of a swap race: swap used rises STEP MB; with read=False the sample has no swap reading."""
        self.swap += STEP
        r = dict(tpm.READINGS["RED_SWAP"])
        if not read:
            r["swap_used_mb"] = None
        return self.tick_raw(r)

    def race_pause(self):
        self.tick_as("GREEN")  # fixture: an earlier sample, so the rise shows
        for _ in range(4):
            t = self.clock["t"]
            st = self.race_tick()
            if self.stopped():
                self.assertEqual(st["state"], "RED")
                self.assertTrue(mmsuper.critical(st["reasons"]), st["reasons"])
                return t
        self.fail("fixture: the swap race pauses the call")

class K1GrowthWindowAfterAGap(Harness):
    """F1 ruling: the cap must not end a pause on a tick that only looks calm because a reading is missing. classify
    measures swap growth over the last 60 s. After a swap gap of 60 s or more (6 ticks), the first ticks that read swap
    again have no value 60 s back: the first has no growth at all, the second only 10 s of it. They look calm, while
    the same race with every reading is a critical RED."""

    @mmtest.needs_proc
    def test_swap_race_after_a_long_swap_gap_keeps_the_pause(self):
        paused_at = self.race_pause()
        while self.clock["t"] - paused_at <= tpm.CAP_S:
            st = self.race_tick()
            self.assertTrue(self.stopped())
            self.assertTrue(mmsuper.critical(st["reasons"]), "fixture: the full-window race is critical: %s" % st)
        for _ in range(6):  # the sampler loses the swap reading for 60 s; the race goes on underneath
            st = self.race_tick(read=False)
            self.assertEqual(st["reasons"], ["readings incomplete"], "fixture: gap tick")
            self.assertTrue(self.stopped(), "fixture: a gap tick never ends the pause")
        seen = []
        for k in range(3):  # the swap reading is back; the race goes on at the same rate
            st = self.race_tick()
            seen.append((st["state"], st["reasons"]))
            self.assertTrue(self.stopped(), "tick %d after the gap ended the pause during the swap race (%s); resume "
                            "lines: %s" % (k + 1, seen, self.resume_lines()))
        self.assertTrue(mmsuper.critical(seen[-1][1]), "fixture: once 60 s of readings are back the race is a "
                        "critical RED again: %s" % seen)

    @mmtest.needs_proc
    def test_control_a_gap_under_60_s_keeps_the_pause(self):
        """Control: the same race with a 50-s gap (5 ticks): a swap value 60 s back is still in the window, so the
        first tick back is a critical RED and the pause holds."""
        paused_at = self.race_pause()
        while self.clock["t"] - paused_at <= tpm.CAP_S:
            self.race_tick()
        for _ in range(5):
            self.race_tick(read=False)
        for _ in range(3):
            st = self.race_tick()
            self.assertTrue(mmsuper.critical(st["reasons"]), st)
            self.assertTrue(self.stopped())
        self.assertEqual(self.resume_lines(), [])

class K2CountAcrossACapChange(Harness):
    """F1 ruling: 'The ticks count from the cap time; a non-clear tick resets the count.' The count is kept only
    while now is past the cap time; a cap the owner raises (or turns off and on) mid-count puts now before the cap
    again, and the critical RED ticks of that time never reset it."""

    @mmtest.needs_proc
    def test_a_count_from_before_a_cap_raise_does_not_carry(self):
        paused_at = self.pause_at()
        self.past_cap(paused_at)
        self.tick_as("AMBER")  # clear tick 1 past the 30-s cap
        self.assertTrue(self.stopped())
        self.settings(**{"pause_newest_call.max_minutes": 2})  # the owner raises the cap to 120 s
        while self.clock["t"] - paused_at < 120:
            self.tick_as("RED")  # critical RED: never a clear tick
            self.assertTrue(self.stopped())
        self.tick_as("AMBER")  # the first clear tick from the new cap time
        self.assertTrue(self.stopped(), "one clear tick from the new cap time ended the pause (the count came from "
                        "before the raise, across critical RED ticks): %s" % self.resume_lines())
        self.tick_as("AMBER")
        self.assertFalse(self.stopped(), "control: the second clear tick in a row ends it")

    @mmtest.needs_proc
    def test_a_count_from_before_the_cap_was_turned_off_does_not_carry(self):
        paused_at = self.pause_at()
        self.past_cap(paused_at)
        self.tick_as("AMBER")  # clear tick 1
        self.settings(**{"pause_newest_call.max_minutes": 0})  # cap off: only a calm span ends the pause
        for _ in range(5):
            self.tick_as("RED")
            self.assertTrue(self.stopped())
        self.settings(**{"pause_newest_call.max_minutes": tpm.CAP_MIN})  # on again; now is past the cap time
        self.tick_as("AMBER")
        self.assertTrue(self.stopped(), "one clear tick after the cap came back ended the pause: %s"
                        % self.resume_lines())

class K3ResumeFailedText(Harness):
    """F3 ruling: PAUSE_MAX tells the truth about what the cap's resume did. mmrecover.resume_paused sends SIGCONT,
    then writes the empty record; when that write fails (a full disk) it returns [] and keeps the record, though the
    call runs. The new text then says 'the resume failed; it stays paused'."""

    @mmtest.needs_proc
    def test_no_stays_paused_claim_when_the_call_runs(self):
        paused_at = self.pause_at()
        real = mmcore.write_atomic
        pf = os.path.realpath(mmrecover.paused_file())

        def write_atomic(path, data, *a, **k):
            if os.path.realpath(path) == pf and data == "{}":
                raise OSError(28, "No space left on device")
            return real(path, data, *a, **k)
        mmcore.write_atomic = write_atomic
        try:
            while self.clock["t"] - paused_at <= tpm.RESUME_S + tpm.TICK_S:  # one more tick: held alerts push then
                self.tick_as("AMBER")
        finally:
            mmcore.write_atomic = real
        self.assertFalse(self.stopped(), "fixture: SIGCONT went out before the record write failed")
        texts = [r["text"] for r in self.pause_max_alerts()]
        self.assertTrue(texts, "fixture: a PAUSE_MAX was pushed")
        for t in texts:
            self.assertNotIn("stays paused", t, "PAUSE_MAX says the call stays paused, but it runs")

class K4MutantKills(Harness):
    """Killing tests for the two planted mutants that the lasting tests miss (mutants.py M6 and M9)."""

    @mmtest.needs_proc
    def test_a_count_kept_before_a_restart_never_reaches_a_new_pause(self):
        """M9 (no count reset at a new pause): a restart continues the call; when the first ticks after it pause the
        call again, the count kept in controller.json from the old pause must not carry into the new one."""
        paused_at = self.pause_at()
        self.past_cap(paused_at)
        self.tick_as("AMBER")  # count 1 for the old pause
        self.assertEqual(self.controller().get("cap_clear_ticks"), 1, "fixture: a count is kept")
        self.supervisor = self.sup(self.supervisor.sampler, clock=lambda: self.clock["t"])  # a new run
        self.assertFalse(self.stopped(), "fixture: the start continues the call")
        second = self.pause_at()  # the first tick of the new run is a critical RED: a new pause
        self.ticks_until_cap("AMBER", second)  # RESUME_S after the new pause, never CAP_S

    @mmtest.needs_proc
    def test_load_missing_tick_is_not_clear(self):
        """M6 (classify's `complete` dropped): ruling F1 'no readings incomplete'; a tick without load1 is
        incomplete, so it starts the count again."""
        paused_at = self.pause_at()
        self.past_cap(paused_at)
        self.tick_as("AMBER")
        self.tick_raw(dict(tpm.READINGS["AMBER"], load1=None))
        self.assertTrue(self.stopped(), "a tick with readings incomplete (load1) counted as clear")

class N1StartTimeReadFails(Harness):
    """Outside scope (base 8043d1d mmrecover.resume_paused): a failed start-time read (ps fails: a timeout, no fork)
    counts as 'gone'; the record is dropped and the stopped call is never continued. Round 2's text then says the call
    'ended while stopped'."""

    @mmtest.needs_proc
    def test_a_failed_start_time_read_never_strands_the_call(self):
        paused_at = self.pause_at()
        real = mmrecover.start_time
        mmrecover.start_time = lambda pid: None
        try:
            while self.clock["t"] - paused_at <= tpm.RESUME_S + tpm.TICK_S:
                self.tick_as("AMBER")
        finally:
            mmrecover.start_time = real
        texts = [r["text"] for r in self.pause_max_alerts()]
        alive = all(tpm.proc_stat(pid) for pid in self.call_pids)
        self.assertTrue(alive, "fixture: the call is alive")
        for _ in range(3):
            self.tick_as("AMBER")
        self.assertFalse(self.stopped(), "the call stays stopped with no record (stranded); PAUSE_MAX said: %s" % texts)

class N2CalmSpanOnGapTicks(Harness):
    """Outside scope (base 8043d1d: a paused call continues after a calm span of GREEN or STEADY): a STEADY tick whose
    only reason is 'readings incomplete' counts as calm, so a swap gap as long as resume_after_green_s during a swap
    race ends the pause with no cap at all (max_minutes 0)."""

    @mmtest.needs_proc
    def test_gap_ticks_are_not_a_calm_span(self):
        self.settings(**{"pause_newest_call.resume_after_green_s": 60})  # max_minutes: the default 0
        self.race_pause()
        for _ in range(8):  # 80 s without the swap reading; the race goes on underneath
            st = self.race_tick(read=False)
            self.assertEqual(st["reasons"], ["readings incomplete"])
        self.assertTrue(self.stopped(), "gap ticks made a calm span: %s" % self.resume_lines())


def load_tests(loader, tests, pattern):
    """Run the retained proofs once, without inheriting the harness's original test suite into every subclass."""
    suite = unittest.TestSuite()
    for cls in (PauseReadingUnits, K1GrowthWindowAfterAGap, K2CountAcrossACapChange, K3ResumeFailedText,
                K4MutantKills, N1StartTimeReadFails, N2CalmSpanOnGapTicks):
        for name in sorted(cls.__dict__):
            if name.startswith("test_"):
                suite.addTest(cls(name))
    return suite
