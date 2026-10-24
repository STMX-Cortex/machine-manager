# SPDX-License-Identifier: Apache-2.0
"""`pause_newest_call.max_minutes` (default 0 = no limit, range 0-1440): a paused call continues once it has been
paused that long, even with no calm span, but never on a tick that is RED with a critical reason. The supervisor logs
`RESUME pids [...] (max N min paused, state S)` and raises ATTENTION `PAUSE_MAX` naming the call. The time counts
from the tick that paused the call; a later pause counts again from its own tick.

Each test runs a real call of the fixture queue launcher in a temporary data folder, pauses it with a scripted
critical RED reading in act mode, then drives the supervisor tick by tick with a scripted clock (whole seconds, so the
boundary is exact) and scripted readings. It asserts what an owner sees: the process state of the call's tree, the
machine state in status.json (each scripted reading reaches its stated state), the decision log and the alerts."""
import json
import os
import re
import subprocess
import sys
import time

from mmtest import mmcore, mmread
from test_supervisor import Base, sampler_of

TICK_S = 10
CAP_MIN = 0.5          # 30 s: three ticks
CAP_S = int(CAP_MIN * 60)
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
}
STATE_OF = {"GREEN": "GREEN", "STEADY": "STEADY", "AMBER": "AMBER", "RED": "RED", "RED_SWAP": "RED",
            "RED_FREE": "RED", "RED_COMP": "RED", "AMBER_COMP": "AMBER"}
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
        """Ticks of `label` up to the cap: stopped on every tick under it, running on the tick that reaches it."""
        before = len(self.cap_lines())
        while True:
            t = self.tick_as(label)
            if t - paused_at < CAP_S:
                self.assertTrue(self.stopped(), "still stopped %d s after the pause (cap %d s)" % (t - paused_at, CAP_S))
                self.assertEqual(len(self.cap_lines()), before)
            else:
                self.assertEqual(t - paused_at, CAP_S, "the cap ends the pause on the first tick that reaches it")
                self.assertFalse(self.stopped(), "the call runs again %d s after the pause (%s)" % (CAP_S, label))
                return

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
        """Critical RED past the cap holds the pause; the first non-critical tick after it ends the pause at once."""
        paused_at = self.pause_at()
        while self.clock["t"] - paused_at <= 3 * CAP_S:
            self.tick_as("RED")
            self.assertTrue(self.stopped())
        t = self.tick_as("AMBER")
        self.assertGreater(t - paused_at, CAP_S)
        self.assertFalse(self.stopped(), "the first non-critical tick after the cap continues the call")
        self.assert_cap_resume(self.resume_lines()[0], "AMBER")
        self.assertEqual(len(self.resume_lines()), 1)

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
