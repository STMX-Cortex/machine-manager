# SPDX-License-Identifier: Apache-2.0
"""`pause_newest_call.max_minutes` (default 0 = no limit, range 0-1440): a paused call continues once it has been
paused that long, even with no calm span, on the `slots.sustain_samples`-th clear tick in a row counted from the cap
time (default 2). A clear tick has every memory reading present and no reason that holds the pause: a critical RED
reason (mmsuper.critical), a kernel memorystatus event, swap near its total and growing, or compressor segments over
their limit (round-1 review F1 and F5). Any other tick starts the count again. The supervisor logs
`RESUME pids [...] (max N min paused, state S)` and raises ATTENTION `PAUSE_MAX` naming the call, once for each capped
pause (F2); when the call ended while stopped, PAUSE_MAX says it was gone (F3). The time counts from the tick that
paused the call; a later pause counts again from its own tick. The round-1 review's reproductions C1 to C6 are kept
here (C2 to C6) and in test_guard_settings.py (C1).

Each test runs a real call of the fixture queue launcher in a temporary data folder, pauses it with a scripted
critical RED reading in act mode, then drives the supervisor tick by tick with a scripted clock (whole seconds, so the
boundary is exact) and scripted readings. It asserts what an owner sees: the process state of the call's tree, the
machine state in status.json (each scripted reading reaches its stated state), the decision log and the alerts."""
import json
import os
import re
import signal
import subprocess
import sys
import time

from mmtest import mmcore, mmread
import mmdecide
import mmsuper
from test_supervisor import Base, sampler_of

TICK_S = 10
CAP_MIN = 0.5          # 30 s: three ticks
CAP_S = int(CAP_MIN * 60)
CAP_TICKS = 2          # slots.sustain_samples at its default: clear ticks in a row from the cap time
RESUME_S = CAP_S + (CAP_TICKS - 1) * TICK_S  # the tick that ends a pause when every tick from the cap time is clear
KERNEL_RED = "kernel memorystatus event (no paging space or suspending)"
CALM_SPAN_S = 3600     # resume_after_green_s at its maximum: no calm span ends a pause inside these tests
DISK_GB = 200
LABEL = "/bin/sleep 300"  # the call's label: fixtures/launcher.py writes its command into the slot file

READINGS = {
    "GREEN": {},
    "STEADY": {"free_pct": 52},
    "AMBER": {"free_pct": 45},
    "RED": {"free_pct": 70, "pressure": 4},            # critical: kernel pressure 4
    "RED_SWAP": {"swap_total_mb": 1e6},                # swap used set per tick: +600 MB in each 10 s (critical)
    "RED_FREE": {"free_pct": 30},                      # RED, not critical: free under red_free_pct
    "RED_COMP": {"comp_mb": 7000},                     # critical with slots.red_comp_mb 6000; AMBER by default
    "AMBER_COMP": {"comp_mb": 7000},
    "RED_SEG": {"seg_pct": 95},                        # RED, not critical: compressor segments over their limit
}
STATE_OF = {"GREEN": "GREEN", "STEADY": "STEADY", "AMBER": "AMBER", "RED": "RED", "RED_SWAP": "RED",
            "RED_FREE": "RED", "RED_COMP": "RED", "AMBER_COMP": "AMBER", "RED_SEG": "RED"}
CAP_LINE = re.compile(r"^\S.* RESUME pids \[([0-9, ]*)\] \(max ([0-9.]+) min paused, state ([A-Z]+)\)$")


def proc_stat(pid):
    return subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True,
                          timeout=5).stdout.strip()


class PauseMax(Base):
    extra = {}

    def setUp(self):
        super().setUp()
        real_disk = mmread.disk_free_gb
        mmread.disk_free_gb = lambda *a, **k: DISK_GB
        self.addCleanup(setattr, mmread, "disk_free_gb", real_disk)
        self.reading = READINGS["GREEN"]
        self.swap = 100
        self.call_pids = self.start_call()
        self.settings(**{"pause_newest_call.max_minutes": CAP_MIN})
        self.clock = {"t": float(int(time.time()))}
        base = sampler_of()

        def sampler(now, ticks):
            d, ticks = base(now, ticks)
            d.update(self.reading)
            d["swap_used_mb"] = self.swap
            return d, ticks
        self.supervisor = self.sup(sampler, clock=lambda: self.clock["t"])

    def settings(self, **over):
        self.write_settings(**dict({"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                                    "pause_newest_call.enabled": True,
                                    "pause_newest_call.resume_after_green_s": CALM_SPAN_S}, **over))

    # -- fixtures ------------------------------------------------------------------------------------------------
    def start_call(self):
        p = subprocess.Popen([sys.executable, "-I", os.path.join(self.q, "launcher.py"), "--", "/bin/sleep", "300"])
        self.addCleanup(self.kill_tree, p)
        kids = []
        for _ in range(100):
            kids = [x["pid"] for x in mmread.read_ps() or [] if x["ppid"] == p.pid]
            if kids and mmread.flock_held(os.path.join(self.q, ".slot.1"))[0]:
                break
            time.sleep(0.1)
        self.assertTrue(kids, "fixture: the launcher runs its command")
        self.assertTrue(mmread.flock_held(os.path.join(self.q, ".slot.1"))[0], "fixture: the call holds slot 1")
        return sorted([p.pid] + kids)

    def tick_raw(self, reading):
        """One tick with this exact reading (a reading set to None is missing) and no state check; returns status.json.
        A `swap_used_mb` key replaces the scripted swap reading for this tick only."""
        self.reading = dict(reading)
        saved = self.swap
        if "swap_used_mb" in reading:
            self.swap = reading["swap_used_mb"]
        self.supervisor.tick()
        self.swap = saved
        self.clock["t"] += TICK_S
        return json.load(open(os.path.join(self.data, "status.json")))

    def tick_as(self, label):
        """One tick with this reading; asserts the state it reaches; returns the tick's time."""
        self.reading = dict(READINGS[label])
        if label == "RED_SWAP":
            self.swap += 600  # over red_swap_growth_mb_60s (512) in one minute: a critical reason
        t = self.clock["t"]
        self.supervisor.tick()
        st = json.load(open(os.path.join(self.data, "status.json")))
        self.assertEqual(st["state"], STATE_OF[label], "fixture: reading %s gives %s (%s)" % (label, STATE_OF[label],
                                                                                             st["reasons"]))
        self.clock["t"] += TICK_S
        return t

    def stopped(self):
        stats = [proc_stat(pid) for pid in self.call_pids]
        if all(s.startswith("T") for s in stats):
            return True
        if not any(s.startswith("T") for s in stats):
            return False
        self.fail("the call's tree is partly stopped: %r" % list(zip(self.call_pids, stats)))

    def resume_lines(self):
        return [line for line in self.decisions().splitlines() if " RESUME" in line]

    def cap_lines(self):
        return [line for line in self.resume_lines() if CAP_LINE.match(line)]

    def pause_at(self, label="RED"):
        """Critical RED ticks until the call is stopped; returns the time of the tick that paused it."""
        for _ in range(3):
            t = self.tick_as(label)
            if self.stopped():
                return t
        self.fail("fixture: the call is paused at a critical RED (%s)" % label)

    def pause_max_alerts(self):
        return [r for r in self.pushed() if r.get("name") == "PAUSE_MAX" and r.get("why") != "cleared"]

    def controller(self):
        return json.load(open(os.path.join(self.data, "state", "controller.json")))

    def assert_cap_resume(self, line, state):
        m = CAP_LINE.match(line)
        self.assertTrue(m, "the line reads `<time> RESUME pids [...] (max N min paused, state S)`: %r" % line)
        self.assertEqual(sorted(int(x) for x in m.group(1).replace(",", " ").split()), self.call_pids)
        self.assertEqual((float(m.group(2)), m.group(3)), (CAP_MIN, state))

    def ticks_until_cap(self, label, paused_at):
        """Clear ticks of `label`: stopped on every tick before the CAP_TICKS-th clear tick from the cap time, running
        on that tick (RESUME_S after the pause)."""
        before = len(self.cap_lines())
        while True:
            t = self.tick_as(label)
            if t - paused_at < RESUME_S:
                self.assertTrue(self.stopped(), "still stopped %d s after the pause (cap %d s, %d clear ticks)"
                                % (t - paused_at, CAP_S, CAP_TICKS))
                self.assertEqual(len(self.cap_lines()), before)
            else:
                self.assertEqual(t - paused_at, RESUME_S, "the cap ends the pause on the %d-th clear tick from the "
                                 "cap time" % CAP_TICKS)
                self.assertFalse(self.stopped(), "the call runs again %d s after the pause (%s)" % (RESUME_S, label))
                return

    def past_cap(self, paused_at):
        """Critical RED ticks (the pause holds) until the cap time is behind; the next tick is past it."""
        while self.clock["t"] - paused_at <= CAP_S:
            self.tick_as("RED")
            self.assertTrue(self.stopped())

    # -- the cap ends a pause in a non-critical state ---------------------------------------------------------------
    def test_amber_resumes_at_the_cap_once_with_line_and_alert(self):
        paused_at = self.pause_at()
        self.ticks_until_cap("AMBER", paused_at)
        for _ in range(3):
            self.tick_as("AMBER")
        self.assertFalse(self.stopped())
        lines = self.resume_lines()
        self.assertEqual(len(lines), 1, lines)
        self.assert_cap_resume(lines[0], "AMBER")
        alerts = self.pause_max_alerts()
        self.assertEqual(len(alerts), 1, alerts)
        self.assertEqual(alerts[0]["level"], "ATTENTION")
        self.assertIn(LABEL, alerts[0]["text"], "PAUSE_MAX names the call")
        for pid in self.call_pids:
            self.assertIn(str(pid), alerts[0]["text"])
        self.assertNotIn("paused_at", self.controller(), "nothing paused: no pause time kept")

    def test_red_without_a_critical_reason_resumes_at_the_cap(self):
        paused_at = self.pause_at()
        self.ticks_until_cap("RED_FREE", paused_at)
        for _ in range(3):  # a non-critical RED never pauses again
            self.tick_as("RED_FREE")
            self.assertFalse(self.stopped())
        lines = self.resume_lines()
        self.assertEqual(len(lines), 1, lines)
        self.assert_cap_resume(lines[0], "RED")

    def test_critical_red_ticks_count_toward_the_cap(self):
        """Critical RED past the cap holds the pause; after it, CAP_TICKS clear ticks in a row end the pause."""
        paused_at = self.pause_at()
        while self.clock["t"] - paused_at <= 3 * CAP_S:
            self.tick_as("RED")
            self.assertTrue(self.stopped())
        for _ in range(CAP_TICKS - 1):
            t = self.tick_as("AMBER")
            self.assertGreater(t - paused_at, CAP_S)
            self.assertTrue(self.stopped(), "one clear tick after the cap is not yet enough")
        self.tick_as("AMBER")
        self.assertFalse(self.stopped(), "the %d-th clear tick after the cap continues the call" % CAP_TICKS)
        self.assert_cap_resume(self.resume_lines()[0], "AMBER")
        self.assertEqual(len(self.resume_lines()), 1)

    # -- review F1 (C6): only clear ticks in a row from the cap time end a pause ----------------------------------------
    def test_one_missing_swap_reading_in_a_swap_race_keeps_the_pause(self):
        """Review C6: a swap race past the cap with ONE sample whose swap reading is missing (a sampler gap). The race
        has not ended; that tick only looks calm (STEADY, readings incomplete) and never ends the pause."""
        self.tick_as("GREEN")  # fixture: an earlier sample, so the rise shows
        paused_at = self.pause_at("RED_SWAP")
        while self.clock["t"] - paused_at <= CAP_S:
            self.tick_as("RED_SWAP")
            self.assertTrue(self.stopped(), "fixture: a critical RED holds the pause")
        st = self.tick_raw(dict(READINGS["RED_SWAP"], swap_used_mb=None))
        self.assertEqual((st["state"], st["reasons"]), ("STEADY", ["readings incomplete"]), "fixture: the gap tick")
        self.assertTrue(self.stopped(), "the cap ended the pause on the one gap tick; the swap race goes on: %s"
                        % self.resume_lines())
        for _ in range(3):
            self.tick_as("RED_SWAP")
            self.assertTrue(self.stopped())
        self.assertEqual(self.resume_lines(), [])
        self.assertEqual(self.pause_max_alerts(), [])

    def test_a_tick_with_a_missing_memory_reading_starts_the_count_again(self):
        """Round-3 ruling 1: a gap holds the pause through the 60 s growth window, then CAP_TICKS clear ticks end it.
        Each memory reading counts, also the ones classify's `complete` does not name (pressure, segments)."""
        for missing in ("swap_used_mb", "free_pct", "comp_mb", "swap_total_mb", "pressure", "seg_pct"):
            with self.subTest(missing=missing):
                paused_at = self.pause_at()
                self.past_cap(paused_at)
                self.tick_as("AMBER")  # clear tick 1
                self.assertTrue(self.stopped())
                gap_at = self.clock["t"]
                self.tick_raw(dict(READINGS["AMBER"], **{missing: None}))  # not clear: the count starts again
                self.assertTrue(self.stopped(), "a tick without %s never counts toward the cap" % missing)
                while self.clock["t"] - gap_at <= 60:
                    self.tick_as("AMBER")
                    self.assertTrue(self.stopped(), "the growth window still contains the %s gap" % missing)
                for clear_tick in range(1, CAP_TICKS + 1):
                    t = self.tick_as("AMBER")
                    self.assertEqual(t - gap_at, 60 + clear_tick * TICK_S)
                    self.assertEqual(self.stopped(), clear_tick < CAP_TICKS,
                                     "complete-window clear tick %d after the %s gap" % (clear_tick, missing))
                self.assert_cap_resume(self.cap_lines()[-1], "AMBER")
                for _ in range(2):
                    self.tick_as("AMBER")

    def test_ticks_before_the_cap_time_do_not_count(self):
        """Clear ticks all along: the pause still ends exactly RESUME_S after it (CAP_TICKS clear ticks from the cap
        time), never at the cap time on a count carried from before it."""
        paused_at = self.pause_at()
        for _ in range(CAP_S // TICK_S - 1):
            self.tick_as("AMBER")
        self.ticks_until_cap("AMBER", paused_at)

    def test_the_count_follows_slots_sustain_samples(self):
        self.settings(**{"pause_newest_call.max_minutes": CAP_MIN, "slots.sustain_samples": 1})
        paused_at = self.pause_at()
        while True:
            t = self.tick_as("AMBER")
            if t - paused_at < CAP_S:
                self.assertTrue(self.stopped())
            else:
                self.assertEqual(t - paused_at, CAP_S, "one clear tick is enough with slots.sustain_samples 1")
                self.assertFalse(self.stopped())
                break
        self.settings(**{"pause_newest_call.max_minutes": CAP_MIN, "slots.sustain_samples": 4})
        paused_at = self.pause_at()
        while True:
            t = self.tick_as("AMBER")
            if t - paused_at < CAP_S + 3 * TICK_S:
                self.assertTrue(self.stopped())
            else:
                self.assertEqual(t - paused_at, CAP_S + 3 * TICK_S)
                self.assertFalse(self.stopped(), "four clear ticks from the cap time with slots.sustain_samples 4")
                break

    # -- review F5 (C4): the other RED memory reasons hold the pause too --------------------------------------------
    def gate_ticks(self, reasons, n, readings_ok=True):
        """`n` gate steps past the cap with this RED state; returns whether the call is still stopped."""
        s = mmcore.Settings().load()
        for _ in range(n):
            self.supervisor._gate_and_pause(self.clock["t"], s, "RED", reasons, True, None, readings_ok)
            self.clock["t"] += TICK_S
        return self.stopped()

    def hold_back(self, reasons):
        paused_at = self.pause_at()
        self.clock["t"] = max(self.clock["t"], paused_at + CAP_S + 1)
        self.assertTrue(self.gate_ticks(reasons, 3 * CAP_TICKS), "the cap ended the pause during RED %s" % reasons)
        self.assertEqual(self.resume_lines(), [])

    def test_kernel_memorystatus_event_keeps_the_pause(self):
        self.hold_back([KERNEL_RED])

    def test_swap_near_total_and_growing_keeps_the_pause(self):
        self.hold_back(["swap 1900 of 2048 MB and growing"])

    def test_compressor_segments_over_limit_keeps_the_pause(self):
        self.hold_back(["compressor segments 95% of limit"])

    def test_control_another_red_reason_ends_the_pause_at_the_cap(self):
        """Control for the three above: the same steps with a RED reason that does not hold the pause end it."""
        paused_at = self.pause_at()
        self.clock["t"] = max(self.clock["t"], paused_at + CAP_S + 1)
        self.assertTrue(self.gate_ticks(["free 30% < 35%"], CAP_TICKS - 1))
        self.assertFalse(self.gate_ticks(["free 30% < 35%"], 1))
        self.assert_cap_resume(self.resume_lines()[0], "RED")

    def test_control_no_readings_flag_never_ends_the_pause(self):
        paused_at = self.pause_at()
        self.clock["t"] = max(self.clock["t"], paused_at + CAP_S + 1)
        self.assertTrue(self.gate_ticks(["free 30% < 35%"], 3 * CAP_TICKS, readings_ok=False))

    def test_compressor_segments_red_from_real_readings_keeps_the_pause(self):
        paused_at = self.pause_at()
        while self.clock["t"] - paused_at <= 4 * CAP_S:
            self.tick_as("RED_SEG")
            self.assertTrue(self.stopped(), "RED compressor segments past the cap hold the pause")
        self.assertIn("compressor segments 95% of limit",
                      json.load(open(os.path.join(self.data, "status.json")))["reasons"])
        self.ticks_after_hold("RED_SEG")

    def ticks_after_hold(self, label):
        for _ in range(CAP_TICKS - 1):
            self.tick_as("AMBER")
            self.assertTrue(self.stopped(), "after %s the clear count starts at its first clear tick" % label)
        self.tick_as("AMBER")
        self.assertFalse(self.stopped())

    def test_hold_back_reasons_match_how_classify_builds_them(self):
        s = mmcore.Settings().load()
        w = [{"t": 1_800_000_000.0 - 60 + 60 * k, "free_pct": 70, "swap_used_mb": 1900 + 10 * k, "swap_total_mb": 2000,
              "comp_mb": 300, "pressure": 1, "seg_pct": 95, "load1": 1, "load5": 1, "sys_pct": 10} for k in range(2)]
        state, reasons, _ = mmdecide.classify(w, s, disk_gb=DISK_GB, kernel_event=True)
        self.assertEqual(state, "RED")
        self.assertEqual(sorted(reasons), sorted([KERNEL_RED, "compressor segments 95% of limit",
                                                  "swap 1910 of 2000 MB and growing"]), "fixture: the three reasons")
        self.assertFalse(mmsuper.critical(reasons), "none of them pauses")
        for r in reasons:
            self.assertTrue(mmsuper.cap_holds("RED", [r]), r)
        for r in ("free 30% < 35%", "disk 10 GB < 20 GB", "load1 > 20 in 2 samples", "system CPU > 40% in 2 samples"):
            self.assertFalse(mmsuper.cap_holds("RED", [r]), r)
        self.assertFalse(mmsuper.cap_holds("AMBER", [KERNEL_RED]), "only a RED tick holds")

    # -- review F2 (C2) and F3 (C3): one PAUSE_MAX for each capped pause, and the truth when the call is gone -----------
    def test_each_capped_resume_pushes_its_own_pause_max(self):
        first = self.pause_at()
        self.ticks_until_cap("AMBER", first)
        for _ in range(2):
            self.tick_as("AMBER")
        second = self.pause_at()  # the call races again: paused again inside the first PAUSE_MAX's 30-min hold
        self.ticks_until_cap("AMBER", second)
        for _ in range(3):
            self.tick_as("AMBER")
        self.assertEqual(len(self.cap_lines()), 2, self.resume_lines())
        pushed = self.pause_max_alerts()
        self.assertEqual(len(pushed), 2, "two capped resumes, but PAUSE_MAX was pushed %d time(s): %s"
                         % (len(pushed), [r.get("text") for r in pushed]))
        self.assertEqual(len({r.get("key") for r in pushed}), 2, "each capped pause has its own alert key")
        for r in pushed:
            self.assertTrue(r.get("key", "").startswith("PAUSE_MAX:"), r)
            self.assertIn(LABEL, r["text"])

    def test_no_continued_claim_when_no_pid_was_continued(self):
        paused_at = self.pause_at()
        for pid in reversed(self.call_pids):  # processes this test started
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        for _ in range(50):
            for pid in self.call_pids:  # reap our own child (the launcher), so no zombie keeps its start time
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
            if not any(proc_stat(pid) for pid in self.call_pids):
                break
            time.sleep(0.1)
        self.assertFalse(any(proc_stat(pid) for pid in self.call_pids), "fixture: the paused call is gone")
        while self.clock["t"] - paused_at <= RESUME_S:
            self.tick_as("AMBER")
        for _ in range(2):
            self.tick_as("AMBER")
        lines = self.cap_lines()
        self.assertEqual(len(lines), 1, self.resume_lines())
        self.assertIn("RESUME pids [] (max", lines[0])
        alerts = self.pause_max_alerts()
        self.assertEqual(len(alerts), 1, alerts)
        text = alerts[0]["text"]
        self.assertFalse(re.search(r"continued", text), "PAUSE_MAX says the call continued, but no pid was: %s" % text)
        self.assertIn("was gone", text)
        self.assertIn(LABEL, text)
        self.assertNotIn("paused_at", self.controller())

    def test_a_failed_resume_at_the_cap_says_so_and_tries_again(self):
        """F3's sibling: the resume itself fails (the record stays): PAUSE_MAX never claims the call continued or was
        gone; the next clear tick tries again and continues it."""
        import mmrecover
        paused_at = self.pause_at()
        real = mmrecover.resume_paused
        mmrecover.resume_paused = lambda why, now=None, legacy=None: []  # the lock or the write failed
        try:
            while self.clock["t"] - paused_at <= RESUME_S + TICK_S:  # one more tick: held alerts push on the next
                self.tick_as("AMBER")
        finally:
            mmrecover.resume_paused = real
        self.assertTrue(self.stopped(), "fixture: the failed resume left the call stopped")
        texts = [r["text"] for r in self.pause_max_alerts()]
        self.assertEqual(len(texts), 1, texts)
        self.assertIn("resume failed", texts[0])
        self.assertNotIn("continued", texts[0])
        self.assertNotIn("was gone", texts[0])
        self.tick_as("AMBER")
        self.assertFalse(self.stopped(), "the next clear tick continues the call")

    # -- review C5: a restart drops the pause time -------------------------------------------------------------------
    def test_restart_drops_the_pause_time(self):
        paused_at = self.pause_at()
        self.tick_as("AMBER")
        self.assertIn("paused_at", self.controller())
        self.supervisor = self.sup(self.supervisor.sampler, clock=lambda: self.clock["t"])  # a new run: start resume
        self.assertFalse(self.stopped(), "the start continues the paused call")
        self.tick_as("AMBER")
        self.assertNotIn("paused_at", self.controller())
        self.assertNotIn("cap_clear_ticks", self.controller())
        second = self.pause_at()
        self.assertGreater(second, paused_at)
        self.ticks_until_cap("AMBER", second)

    # -- never during a critical RED --------------------------------------------------------------------------------
    def never_resumes(self, labels, seconds, paused_at):
        k = 0
        while self.clock["t"] - paused_at <= seconds:
            self.tick_as(labels[k % len(labels)])
            k += 1
            self.assertTrue(self.stopped(), "a critical RED (%s) never ends a pause" % "/".join(labels))
        self.assertEqual(self.resume_lines(), [])
        self.assertEqual(self.pause_max_alerts(), [])

    def test_critical_red_by_pressure_never_resumes(self):
        self.never_resumes(["RED"], 10 * CAP_S, self.pause_at())

    def test_critical_red_by_swap_growth_never_resumes(self):
        self.tick_as("GREEN")  # fixture: one earlier sample, so the swap rise shows
        self.never_resumes(["RED_SWAP"], 10 * CAP_S, self.pause_at("RED_SWAP"))

    def test_critical_red_by_compressor_ceiling_pauses_and_never_resumes(self):
        self.settings(**{"pause_newest_call.max_minutes": CAP_MIN, "slots.red_comp_mb": 6000})
        paused_at = self.pause_at("RED_COMP")
        self.assertIn("compressor at 7000 MB (near its ceiling)",
                      json.load(open(os.path.join(self.data, "status.json")))["reasons"])
        self.never_resumes(["RED_COMP", "RED"], 10 * CAP_S, paused_at)

    # -- defaults and kept behaviour --------------------------------------------------------------------------------
    def test_default_zero_never_ends_a_pause(self):
        self.settings()  # max_minutes not named: the default
        self.assertEqual(mmcore.Settings().load()["pause_newest_call.max_minutes"], 0)
        paused_at = self.pause_at()
        while self.clock["t"] - paused_at <= 20 * CAP_S:
            self.tick_as("AMBER")
            self.assertTrue(self.stopped(), "with no limit only a calm span ends a pause")
        self.assertEqual(self.resume_lines(), [])
        self.assertEqual(self.pause_max_alerts(), [])

    def test_compressor_ceiling_default_is_off(self):
        """With the default slots.red_comp_mb the same compressor reading is AMBER and pauses nothing."""
        for _ in range(4):
            self.tick_as("AMBER_COMP")
            self.assertFalse(self.stopped())
        self.assertNotIn(" PAUSE ", self.decisions())

    def test_calm_span_still_resumes_first_without_a_pause_max(self):
        self.settings(**{"pause_newest_call.max_minutes": 10, "pause_newest_call.resume_after_green_s": 60})
        paused_at = self.pause_at()
        while self.stopped():
            t = self.tick_as("STEADY")
            self.assertLess(t - paused_at, 10 * 60)
        lines = self.resume_lines()
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(re.match(r"^\S.* RESUME pids \[[0-9, ]*\]$", lines[0]), lines[0])
        self.assertEqual(self.pause_max_alerts(), [])
        self.assertNotIn("paused_at", self.controller())

    def test_a_second_pause_counts_from_its_own_tick(self):
        first = self.pause_at()
        self.ticks_until_cap("AMBER", first)
        for _ in range(2):  # a calm-free gap, so the second pause is well after the first cap
            self.tick_as("AMBER")
        second = self.pause_at()
        self.assertGreater(second - first, CAP_S)
        self.ticks_until_cap("AMBER", second)
        lines = self.cap_lines()
        self.assertEqual(len(lines), 2, self.resume_lines())
        for line in lines:
            self.assert_cap_resume(line, "AMBER")

    def test_pausing_turned_off_drops_the_pause_time(self):
        paused_at = self.pause_at()
        self.tick_as("AMBER")
        self.settings(**{"pause_newest_call.enabled": False, "pause_newest_call.max_minutes": CAP_MIN})
        self.tick_as("AMBER")
        self.assertFalse(self.stopped())
        self.assertNotIn("paused_at", self.controller())
        self.settings(**{"pause_newest_call.max_minutes": CAP_MIN})
        second = self.pause_at()
        self.assertGreater(second, paused_at)
        self.ticks_until_cap("AMBER", second)

    def test_range(self):
        base = mmcore.defaults()
        for bad in (-1, 1441, "5", True):
            self.assertTrue(mmcore.validate(dict(base, **{"pause_newest_call.max_minutes": bad})), bad)
        for good in (0, 0.5, 20, 1440):
            self.assertEqual(mmcore.validate(dict(base, **{"pause_newest_call.max_minutes": good})), [], good)


del Base  # imported for its helpers only; its tests run in their own module
