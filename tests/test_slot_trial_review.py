# SPDX-License-Identifier: Apache-2.0
"""Independent round-one review: synthetic inputs only; no live data or processes.

The failing tests are review evidence, intentionally left unmarked and unfixed.
Numeric values below are fixture inputs, not new operational limits or defaults.
"""
import copy
import unittest

import mmtest
from mmtest import mmcore
import mmalerts
import mmdecide
import mmsuper
import run_vectors
from slot_trial_helpers import NOW, busy, sample, settings


def cpu_supervisor(cores=5.8, slots=(".gate.lock", ".slot.2")):
    sup = object.__new__(mmsuper.Supervisor)
    sup.state = {}
    sup.cache = {
        "queue": {"slots": 5, "busy": busy(slots=slots), "tickets": []},
        "procs": [
            {"pid": 4100, "ppid": 1, "cpu": 20, "rss_mb": 10, "comm": "wrapper"},
            {"pid": 4101, "ppid": 4100, "cpu": cores * 100 - 20,
             "rss_mb": 20, "comm": "worker"},
            {"pid": 9000, "ppid": 1, "cpu": 100, "rss_mb": 30, "comm": "outside"},
        ],
    }
    return sup


def cpu_read(sup, now, **over):
    sup._proc_facts(now)
    return [c for c in mmalerts.evaluate(sup.cache, settings(**over), now)
            if c["name"] == "SLOT_CPU"]


class ReviewCallCPU(unittest.TestCase):
    def test_reused_pid_requires_its_own_two_cpu_readings(self):
        sup = cpu_supervisor(4.5, (".slot.1",))
        self.assertEqual(cpu_read(sup, NOW), [])
        self.assertEqual(len(cpu_read(sup, NOW + 30)), 1)
        # Between polls a different invocation gets the same PID and slot.
        # The queue records a different acquisition time, even with the same command.
        sup.cache["queue"]["busy"] = busy(slots=(".slot.1",), mode="S")
        sup.cache["queue"]["busy"][0]["since"] = NOW + 40
        self.assertEqual(cpu_read(sup, NOW + 60), [],
                         "a new invocation inherited CPU history solely through its reused PID")

    def test_reused_pid_after_observed_idle_gets_a_new_call_alert_key(self):
        sup = cpu_supervisor(4.5, (".slot.1",))
        cpu_read(sup, NOW)
        old = cpu_read(sup, NOW + 30)[0]
        sup.cache["queue"]["busy"] = []
        self.assertEqual(cpu_read(sup, NOW + 60), [])
        sup.cache["queue"]["busy"] = busy(slots=(".slot.1",), mode="S")
        sup.cache["queue"]["busy"][0]["since"] = NOW + 70
        self.assertEqual(cpu_read(sup, NOW + 90), [])
        new = cpu_read(sup, NOW + 120)[0]
        self.assertNotEqual(old["key"], new["key"],
                            "different calls share alert dedupe/ack identity when the PID is reused")

    def test_finished_wide_call_and_failed_ps_read_do_not_create_two_alerts(self):
        sup = cpu_supervisor()
        self.assertEqual(cpu_read(sup, NOW), [])
        self.assertEqual(cpu_read(sup, NOW + 30), [])
        self.assertEqual(set(sup.cache["slot_cpu"].values()), {5.8})
        # tick() refreshes queue even when read_ps() returns None.
        sup.cache["queue"]["busy"] = []
        sup.cache["procs"] = None
        self.assertEqual(cpu_read(sup, NOW + 60), [],
                         "stale CPU from a finished wide call became two one-slot alerts")

    def test_finished_wide_call_with_successful_ps_read_clears_cpu(self):
        sup = cpu_supervisor()
        cpu_read(sup, NOW)
        cpu_read(sup, NOW + 30)
        sup.cache["queue"]["busy"] = []
        sup.cache["procs"] = [sup.cache["procs"][-1]]
        self.assertEqual(cpu_read(sup, NOW + 60), [])
        self.assertEqual(sup.cache["slot_cpu"], {})
        self.assertEqual(sup.state["call_cpu_prev"], {})

    def test_zero_held_slots_has_no_call_cpu_alert(self):
        sup = cpu_supervisor(100, ())
        self.assertEqual(cpu_read(sup, NOW), [])
        self.assertEqual(cpu_read(sup, NOW + 30), [])
        self.assertEqual(sup.state["call_cpu_prev"], {})
        self.assertEqual(len(sup.cache["top_outside"]), 3)

    def test_many_slots_and_cpu_cap_range_ends(self):
        for width in (1, 2, 16):
            for cap in (0.5, 64):
                for excess, expected in ((0, 0), (0.01, 1)):
                    with self.subTest(width=width, cap=cap, excess=excess):
                        slots = tuple(".slot.%d" % n for n in range(1, width + 1))
                        sup = cpu_supervisor(cap * width + excess, slots)
                        over = {"queue.slot_cpu_cores": cap}
                        self.assertEqual(cpu_read(sup, NOW, **over), [])
                        self.assertEqual(len(cpu_read(sup, NOW + 30, **over)), expected)
                        self.assertEqual(sup.cache["top_outside"], [("outside", 30)])


class ReviewTimers(unittest.TestCase):
    def test_backward_clock_step_does_not_keep_demand_in_the_future(self):
        ctl = mmcore.SlotController(settings(), {"last_change": NOW - 7200})
        ctl.decide(NOW, "STEADY", [], 5, 5, 2, False)
        # The wall clock steps back an hour before GREEN starts. After this
        # point GREEN and demand hold together for the configured 15 minutes.
        ctl.decide(NOW - 3600, "GREEN", [], 5, 5, 2, False)
        self.assertEqual(ctl.st["green_since"], NOW - 3600)
        self.assertEqual(ctl.decide(NOW - 2700, "GREEN", [], 5, 5, 2, False)[0], 6,
                         "a future demand timestamp adds an extra hour to the GREEN hold")

    def test_band_flapping_restarts_green_hold(self):
        ctl = mmcore.SlotController(settings(), {})
        for elapsed, load, expected in ((0, 7.9, None), (890, 8, None),
                                        (900, 7.9, None), (1799, 7.9, None), (1800, 7.9, 6)):
            state, reasons, _ = mmdecide.classify([sample(NOW + elapsed, load1=load)], settings())
            self.assertEqual(ctl.decide(NOW + elapsed, state, reasons, 5, 5, 2, False)[0], expected)

    def test_demand_stopping_and_restarting_needs_full_hold(self):
        for lacking in ({"busy": 4, "waiting": 2}, {"busy": 5, "waiting": 0}):
            with self.subTest(lacking=lacking):
                ctl = mmcore.SlotController(settings(), {})
                ctl.decide(NOW, "GREEN", [], 5, 5, 2, False)
                ctl.decide(NOW + 890, "GREEN", [], 5, lacking["busy"], lacking["waiting"], False)
                self.assertIsNone(ctl.st["demand_since"])
                self.assertIsNone(ctl.decide(NOW + 900, "GREEN", [], 5, 5, 2, False)[0])
                self.assertIsNone(ctl.decide(NOW + 1799, "GREEN", [], 5, 5, 2, False)[0])
                self.assertEqual(ctl.decide(NOW + 1800, "GREEN", [], 5, 5, 2, False)[0], 6)

    def test_upgrade_without_demand_time_and_hold_range_ends(self):
        for minutes in (1, 240):
            with self.subTest(minutes=minutes):
                ctl = mmcore.SlotController(settings(**{"slots.raise_green_minutes": minutes}),
                                            {"green_since": NOW - 86400, "last_change": NOW - 86400})
                self.assertIsNone(ctl.decide(NOW, "GREEN", [], 5, 5, 2, False)[0])
                self.assertEqual(ctl.st["demand_since"], NOW)
                self.assertIsNone(ctl.decide(NOW + minutes * 60 - 1, "GREEN", [], 5, 5, 2, False)[0])
                self.assertEqual(ctl.decide(NOW + minutes * 60, "GREEN", [], 5, 5, 2, False)[0], 6)

    def test_load1_band_range_ends_and_missing_reading(self):
        for band in (0.1, 4):
            s = settings(**{"slots.green_load1_per_core": band})
            self.assertEqual(mmcore.validate(s), [])
            for load, expected in ((band * 10 - 0.001, "GREEN"), (band * 10, "STEADY"),
                                   (band * 10 + 0.001, "STEADY"), (None, "STEADY")):
                with self.subTest(band=band, load=load):
                    # One sample: the unchanged sustained RED rule is not met.
                    got = mmdecide.classify([sample(load1=load)], s)
                    self.assertEqual(got[0], expected)
                    self.assertEqual(got[2], load is not None)


class ReviewVectors(unittest.TestCase):
    def test_all_vector_outputs_match_contract(self):
        for fn, name, vector, s in run_vectors.load_all():
            with self.subTest(function=fn, case=name):
                self.assertEqual(run_vectors.norm(run_vectors.FUNCTIONS[fn](vector["input"], s)),
                                 vector["expected"])

    def test_updated_green_vectors_still_isolate_the_named_guard(self):
        cases = {name.removesuffix(".json"): (v, s) for fn, name, v, s in run_vectors.load_all()
                 if fn == "slot_decide"}
        for name in ("green-at-ceiling", "green-held-after-red", "green-held-after-trim",
                     "green-no-demand", "green-too-short", "green-wide-waiting"):
            with self.subTest(case=name):
                vector, original_settings = cases[name]
                i, s = copy.deepcopy(vector["input"]), dict(original_settings)
                self.assertIsNone(mmdecide.slot_decide(i["state"], i["inp"], s)["slots"])
                if name == "green-at-ceiling":
                    s["slots.ceiling"] += 1
                elif name == "green-held-after-red":
                    i["state"]["last_red"] = i["inp"]["now"] - s["slots.hold_after_red_minutes"] * 60
                elif name == "green-held-after-trim":
                    i["inp"]["events"] = []
                elif name == "green-no-demand":
                    i["inp"]["waiting"] = s["slots.raise_requires_waiting"]
                elif name == "green-too-short":
                    i["state"]["green_since"] = i["inp"]["now"] - s["slots.raise_green_minutes"] * 60
                else:
                    i["inp"]["wx_waiting"] = False
                self.assertEqual(mmdecide.slot_decide(i["state"], i["inp"], s)["slots"],
                                 i["inp"]["slots"] + 1)


if __name__ == "__main__":
    unittest.main()
