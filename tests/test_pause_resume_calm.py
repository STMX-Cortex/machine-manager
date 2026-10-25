# SPDX-License-Identifier: Apache-2.0
"""A paused queue call resumes on a calm machine, GREEN or STEADY (pause-steady design note, PR-1 and PR-2).

Each test runs a real call of the fixture queue launcher, pauses it with a scripted RED reading in act mode, then
drives the supervisor tick by tick with a scripted clock and scripted readings. It asserts only what an owner sees:
the process state of the call's tree (stopped or running), the machine state in status.json (to prove each scripted
reading reaches its stated state) and the RESUME lines of the decision log.

Span rule (PR-1): calm means GREEN or STEADY on every tick; the span starts at the first calm tick; the call continues
once the span has lasted at least `pause_newest_call.resume_after_green_s` seconds. An AMBER or RED tick ends the span.
The tests never pin the exact boundary tick: they require "still stopped" up to one tick before the span length and
"running" at the latest one tick after it."""
import json
import os
import re
import subprocess
import sys
import time

import mmtest
from mmtest import mmread
import mmsuper
from test_supervisor import Base, sampler_of

SPAN_S = 60   # pause_newest_call.resume_after_green_s in these tests (the setting's range is 10 to 3600)
TICK_S = 10   # scripted clock step per tick
DISK_GB = 200  # scripted free disk, well above the disk lines (low_gb 40, recover_gb 45)

# Scripted readings and the machine state each must reach (cores 10; thresholds from the settings' defaults).
READINGS = {
    "GREEN": {},
    "STEADY": {"free_pct": 52},          # free memory under the GREEN line, above AMBER
    "STEADY_LOAD": {"load1": 9},         # a busy but calm machine: load1 over the GREEN band, nothing else
    "AMBER": {"free_pct": 45},
    "RED": {"free_pct": 70, "pressure": 4},
}
STATE_OF = {"GREEN": "GREEN", "STEADY": "STEADY", "STEADY_LOAD": "STEADY", "AMBER": "AMBER", "RED": "RED"}
RESUME_LINE = re.compile(r"^\S.* RESUME pids \[([0-9, ]*)\]$")
DISABLED_RESUME_LINE = re.compile(r"^\S.* RESUME pids \[([0-9, ]*)\] \(pausing disabled\)$")


def proc_stat(pid):
    return subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True,
                          timeout=5).stdout.strip()


class PauseResumeCalm(Base):
    def setUp(self):
        super().setUp()
        # Script the free disk reading too: the real disk of the test machine must not decide GREEN or STEADY.
        real_disk = mmread.disk_free_gb
        mmread.disk_free_gb = lambda *a, **k: DISK_GB
        self.addCleanup(setattr, mmread, "disk_free_gb", real_disk)
        self.reading = READINGS["GREEN"]
        self.call_pids = self.start_call()
        self.set_pausing(True)
        self.clock = {"t": time.time()}
        base = sampler_of()

        def sampler(now, ticks):
            d, ticks = base(now, ticks)
            d.update(self.reading)
            return d, ticks
        self.supervisor = self.sup(sampler, clock=lambda: self.clock["t"])
        self.pause_at_red()

    def set_pausing(self, enabled):
        """settings.toml with act mode and the pause switch as given (the other values stay the same)."""
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "pause_newest_call.enabled": enabled,
                               "pause_newest_call.resume_after_green_s": SPAN_S})

    # -- fixtures ------------------------------------------------------------------------------------------------
    def start_call(self):
        """A real call of the fixture launcher that holds slot 1 and runs a child; returns the tree's pids."""
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

    def tick_as(self, label):
        """One supervisor tick with this scripted reading; asserts the machine state it reaches; returns the tick time."""
        self.reading = READINGS[label]
        t = self.clock["t"]
        self.supervisor.tick()
        state = json.load(open(os.path.join(self.data, "status.json")))["state"]
        self.assertEqual(state, STATE_OF[label], "fixture: reading %s gives state %s" % (label, STATE_OF[label]))
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

    def pause_at_red(self):
        for _ in range(3):
            self.tick_as("RED")
            if self.stopped():
                break
        self.assertTrue(self.stopped(), "fixture: the call is paused at a critical RED")
        self.assertEqual(self.resume_lines(), [], "fixture: nothing resumed yet")

    # -- shared checks -------------------------------------------------------------------------------------------
    def calm_span_resumes(self, labels):
        """Tick the calm labels in turn (cycled) as one span; the call stays stopped while the span is shorter than
        SPAN_S - TICK_S and runs by SPAN_S + TICK_S, with exactly one RESUME line naming the call's pids."""
        start = None
        k = 0
        while True:
            t = self.tick_as(labels[k % len(labels)])
            k += 1
            start = t if start is None else start
            elapsed = t - start
            if elapsed <= SPAN_S - TICK_S:
                self.assertTrue(self.stopped(), "still stopped %d s into a %d s calm span" % (elapsed, SPAN_S))
                self.assertEqual(self.resume_lines(), [])
            if elapsed >= SPAN_S + TICK_S:
                break
        self.assertFalse(self.stopped(), "the call runs again after a calm span of %d s (%s)" % (SPAN_S, labels))
        for _ in range(3):  # more calm ticks: no second resume
            self.tick_as(labels[0])
        lines = self.resume_lines()
        self.assertEqual(len(lines), 1, lines)
        m = RESUME_LINE.match(lines[0])
        self.assertTrue(m, "the RESUME line keeps its format: %r" % lines[0])
        self.assertEqual(sorted(int(x) for x in m.group(1).replace(",", " ").split()), self.call_pids)
        self.assertFalse(self.stopped())

    def calm_for_less_than_span(self, label):
        """Calm ticks whose span stays under SPAN_S - TICK_S: the call stays stopped."""
        start = self.tick_as(label)
        while self.clock["t"] - start <= SPAN_S - TICK_S:
            self.tick_as(label)
            self.assertTrue(self.stopped())
        self.assertEqual(self.resume_lines(), [])

    def assert_never_resumes(self, labels, seconds):
        for k in range(seconds // TICK_S):
            self.tick_as(labels[k % len(labels)])
            self.assertTrue(self.stopped(), "a %s machine never continues a paused call" % "/".join(labels))
        self.assertEqual(self.resume_lines(), [])

    # -- PR-1: resume on calm (new behaviour; fails on the base) ------------------------------------------------
    @mmtest.needs_proc
    def test_pr1_steady_for_the_full_span_resumes_once(self):
        self.calm_span_resumes(["STEADY"])

    @mmtest.needs_proc
    def test_pr1_steady_by_load_for_the_full_span_resumes_once(self):
        self.calm_span_resumes(["STEADY_LOAD"])

    @mmtest.needs_proc
    def test_pr1_green_and_steady_mixed_form_one_span(self):
        self.calm_span_resumes(["STEADY", "GREEN", "GREEN", "STEADY_LOAD"])

    @mmtest.needs_proc
    def test_pr1_green_then_steady_form_one_span(self):
        self.calm_span_resumes(["GREEN"] * 3 + ["STEADY"] * 20)

    @mmtest.needs_proc
    def test_pr1_span_broken_by_one_amber_tick_starts_again(self):
        self.span_broken_by("AMBER")

    @mmtest.needs_proc
    def test_pr1_span_broken_by_one_red_tick_starts_again(self):
        self.span_broken_by("RED")

    def span_broken_by(self, breaker):
        """Calm for SPAN_S - TICK_S, one breaking tick, then calm again: the wait counts from the next calm tick, so
        neither the first span nor the summed calm time continues the call early."""
        self.calm_for_less_than_span("STEADY")
        self.tick_as(breaker)
        self.assertTrue(self.stopped(), "a %s tick never continues the call" % breaker)
        self.calm_span_resumes(["STEADY"])

    # -- PR-1 guard: a short calm span (passes on the base too) -----------------------------------------------
    @mmtest.needs_proc
    def test_pr1_steady_for_less_than_the_span_stays_paused(self):
        self.calm_for_less_than_span("STEADY")
        self.assertTrue(self.stopped())

    # -- PR-2: kept behaviour (passes on the base) --------------------------------------------------------------
    @mmtest.needs_proc
    def test_pr2_red_and_amber_for_a_long_time_never_resume(self):
        self.assert_never_resumes(["AMBER", "RED"], 20 * SPAN_S)

    @mmtest.needs_proc
    def test_pr2_amber_for_a_long_time_never_resumes(self):
        self.assert_never_resumes(["AMBER"], 20 * SPAN_S)

    @mmtest.needs_proc
    def test_pr2_red_for_a_long_time_never_resumes(self):
        self.assert_never_resumes(["RED"], 20 * SPAN_S)

    @mmtest.needs_proc
    def test_pr2_green_only_span_resumes_once(self):
        self.calm_span_resumes(["GREEN"])

    @mmtest.needs_proc
    def test_pr2_green_span_broken_by_amber_starts_again(self):
        self.calm_for_less_than_span("GREEN")
        self.tick_as("AMBER")
        self.assertTrue(self.stopped())
        self.calm_span_resumes(["GREEN"])


    # -- PR-3: turning pausing off releases (review finding F1; fails on the base) ---------------------------------
    def disabled_release(self, state):
        """Pausing turned off while the call is paused: it runs again on the next tick, whatever the state, with
        exactly one `RESUME pids [...] (pausing disabled)` line; further ticks while off pause nothing."""
        self.set_pausing(False)
        self.tick_as(state)
        self.assertFalse(self.stopped(), "pausing turned off continues the paused call on the next tick (%s)" % state)
        for _ in range(3):
            self.tick_as("RED")
            self.assertFalse(self.stopped(), "pausing is off: a RED tick pauses nothing")
        lines = self.resume_lines()
        self.assertEqual(len(lines), 1, lines)
        m = DISABLED_RESUME_LINE.match(lines[0])
        self.assertTrue(m, "the release line reads `<time> RESUME pids [...] (pausing disabled)`: %r" % lines[0])
        self.assertEqual(sorted(int(x) for x in m.group(1).replace(",", " ").split()), self.call_pids)

    @mmtest.needs_proc
    def test_pr3_pausing_turned_off_at_red_releases_on_the_next_tick(self):
        self.disabled_release("RED")

    @mmtest.needs_proc
    def test_pr3_pausing_turned_off_at_amber_releases_on_the_next_tick(self):
        self.disabled_release("AMBER")

    @mmtest.needs_proc
    def test_pr3_pausing_turned_off_on_a_calm_tick_releases_at_once(self):
        self.disabled_release("STEADY")

    def no_span_across_a_disabled_period(self, breaker):
        """A calm span begun, then pausing off across `breaker` ticks (the call is released), then pausing on again
        and a new pause at RED: the call is not continued before a new full calm span, then it is, once."""
        calm = ["GREEN", "STEADY"]
        for k in range(3):  # a calm span begun: 20 s, under SPAN_S - TICK_S
            self.tick_as(calm[k % 2])
        self.assertTrue(self.stopped())
        self.set_pausing(False)
        for _ in range(3):
            self.tick_as(breaker)
        self.assertFalse(self.stopped(), "pausing off released the call")
        self.set_pausing(True)
        self.pause_at_red_again()
        start = None
        while True:
            t = self.tick_as(calm[0 if start is None else 1])
            start = t if start is None else start
            if t - start <= SPAN_S - TICK_S:
                self.assertTrue(self.stopped(), "no calm span carries across a disabled period (%s)" % breaker)
            if t - start >= SPAN_S + TICK_S:
                break
        self.assertFalse(self.stopped(), "a new full calm span after the new pause continues the call")
        lines = self.resume_lines()
        self.assertEqual(len(lines), 2, lines)
        self.assertTrue(DISABLED_RESUME_LINE.match(lines[0]), lines[0])
        m = RESUME_LINE.match(lines[1])
        self.assertTrue(m, lines[1])
        self.assertEqual(sorted(int(x) for x in m.group(1).replace(",", " ").split()), self.call_pids)

    def pause_at_red_again(self):
        for _ in range(3):
            self.tick_as("RED")
            if self.stopped():
                break
        self.assertTrue(self.stopped(), "fixture: pausing on again, the call is paused at a critical RED")

    @mmtest.needs_proc
    def test_pr3_no_calm_span_across_a_disabled_amber_period(self):
        self.no_span_across_a_disabled_period("AMBER")

    @mmtest.needs_proc
    def test_pr3_no_calm_span_across_a_disabled_red_period(self):
        self.no_span_across_a_disabled_period("RED")


del Base  # imported for its helpers only; its tests run in their own module
