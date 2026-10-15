# SPDX-License-Identifier: Apache-2.0
"""Independent confirmation of a5b8fe2, using synthetic readings only.

The final test intentionally fails to prove a Low identity variant, accepted
under the owner's 2026-10-15 decision. Numbers are fixtures, not new limits.
"""
import unittest

import mmtest
import mmalerts
import mmdecide
import mmsuper
from slot_trial_helpers import NOW, busy, settings


def supervisor(cores=8.5):
    sup = object.__new__(mmsuper.Supervisor)
    sup.state = {}
    sup.cache = {
        "queue": {"slots": 5, "busy": busy(), "tickets": []},
        "procs": [{"pid": 4100, "ppid": 1, "cpu": cores * 100,
                   "rss_mb": 20, "comm": "fixture-worker"}],
    }
    return sup


def cpu_alerts(sup, elapsed):
    sup._proc_facts(NOW + elapsed)
    return [c for c in mmalerts.evaluate(sup.cache, settings(), NOW + elapsed)
            if c["name"] == "SLOT_CPU"]


class ConfirmRoundOneFix(unittest.TestCase):
    def test_future_demand_resets_to_now_and_holds_exactly_normal_interval(self):
        state = {"green_since": NOW - 7200, "last_change": NOW - 7200,
                 "demand_since": NOW + 3600}
        inp = {"now": NOW, "mac_state": "GREEN", "slots": 5,
               "busy": 5, "waiting": 2}
        result = mmdecide.slot_decide(state, inp, settings())
        self.assertEqual(result["state"]["demand_since"], NOW)
        self.assertIsNone(result["slots"])
        hold = settings()["slots.raise_green_minutes"] * 60
        for elapsed, expected in ((hold - 1, None), (hold, 6)):
            inp["now"] = NOW + elapsed
            result = mmdecide.slot_decide(result["state"], inp, settings())
            self.assertEqual(result["slots"], expected)

    def test_reused_pid_with_fractionally_different_start_gets_fresh_history(self):
        sup = supervisor()
        self.assertEqual(cpu_alerts(sup, 0), [])
        old = cpu_alerts(sup, 30)[0]
        for entry in sup.cache["queue"]["busy"]:
            entry["since"] += 0.001
        self.assertEqual(cpu_alerts(sup, 60), [])
        new = cpu_alerts(sup, 90)
        self.assertEqual(len(new), 1)
        self.assertNotEqual(old["key"], new[0]["key"])

    def test_failed_process_read_discards_history_even_if_call_remains_busy(self):
        for failed in (None, []):
            with self.subTest(failed=failed):
                sup = supervisor()
                procs = sup.cache["procs"]
                cpu_alerts(sup, 0)
                self.assertEqual(len(cpu_alerts(sup, 30)), 1)
                sup.cache["procs"] = failed
                self.assertEqual(cpu_alerts(sup, 60), [])
                self.assertEqual(sup.cache["slot_cpu"], {})
                self.assertEqual(sup.state["call_cpu_prev"], {})
                sup.cache["procs"] = procs
                self.assertEqual(cpu_alerts(sup, 90), [])
                self.assertEqual(len(cpu_alerts(sup, 120)), 1)

    def test_current_busy_list_controls_stale_slot_readings(self):
        sup = supervisor()
        cpu_alerts(sup, 0)
        self.assertEqual(len(cpu_alerts(sup, 30)), 1)
        sup.cache["queue"]["busy"] = []
        alerts = mmalerts.evaluate(sup.cache, settings(), NOW + 60)
        self.assertEqual([c for c in alerts if c["name"] == "SLOT_CPU"], [])

    def test_different_lock_mtimes_and_order_still_produce_one_call(self):
        sup = supervisor()
        sup.cache["queue"]["busy"][1]["since"] += 0.001
        cpu_alerts(sup, 0)
        first = cpu_alerts(sup, 30)
        self.assertEqual(len(first), 1)
        sup.cache["queue"]["busy"].reverse()
        self.assertEqual(cpu_alerts(sup, 60), first)

    def test_declared_missing_start_and_legacy_input_behaviors(self):
        sup = supervisor()
        for entry in sup.cache["queue"]["busy"]:
            entry["since"] = None
        self.assertEqual(cpu_alerts(sup, 0), [])
        self.assertEqual(cpu_alerts(sup, 30), [])
        self.assertEqual(sup.state["call_cpu_prev"], {})
        alerts = mmalerts.evaluate({"slot_cpu": {".slot.1": 4.5}}, settings(), NOW)
        self.assertEqual(len([c for c in alerts if c["name"] == "SLOT_CPU"]), 1)


class AcceptedLowIdentityVariant(unittest.TestCase):
    @unittest.expectedFailure
    def test_restoring_earliest_start_does_not_reidentify_same_wide_call(self):
        sup = supervisor()
        earliest = sup.cache["queue"]["busy"][0]
        original_start = earliest["since"]
        earliest["since"] = None  # read_queue permits an unavailable stat result.
        sup.cache["queue"]["busy"][1]["since"] += 0.001
        cpu_alerts(sup, 0)
        first = cpu_alerts(sup, 30)[0]
        # Same PID, locks and invocation; only the missing metadata recovers.
        earliest["since"] = original_start
        cpu_alerts(sup, 60)
        later = cpu_alerts(sup, 90)
        self.assertEqual(len(later), 1)
        self.assertEqual(later[0]["key"], first["key"],
                         "one invocation acquired a second SLOT_CPU alert identity")
