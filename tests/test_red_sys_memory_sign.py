# SPDX-License-Identifier: Apache-2.0
"""R-1: sustained system CPU needs a current memory sign before it can cause RED."""
import json
import os
import unittest

from mmtest import TempData, base_settings, mmcore
import ad_deliver_claude
import mmalerts
import mmdecide

NOW = 1_800_000_000.0
NEEDS_SIGN = "slots.red_sys_needs_memory_sign"
COMP_GROWTH = "slots.red_sys_comp_growth_mb_60s"
RED_REASON = "system CPU > 40% in 2 samples"
NO_SIGN_REASON = RED_REASON + ", no memory sign"
AMBER_REASON = "system CPU > 30% in 2 samples"


def window(**columns):
    """Two complete, minute-spaced samples; values are pairs, oldest first."""
    rows = []
    for i in range(2):
        row = {"t": NOW - 60 + 60 * i, "free_pct": 80.0, "pressure": 1, "swap_used_mb": 500.0,
               "swap_total_mb": 2048.0, "comp_mb": 300.0, "seg_pct": 5.0, "load1": 2.0,
               "load5": 2.0, "sys_pct": 50.0}
        row.update({key: values[i] for key, values in columns.items()})
        rows.append(row)
    return rows


def decide(rows=None, **over):
    return mmdecide.classify(window() if rows is None else rows, base_settings(**over), disk_gb=100.0)


class RedSysMemorySign(unittest.TestCase):
    def test_default_cpu_alone_is_amber_with_both_cpu_reasons(self):
        self.assertEqual(decide(), ["AMBER", [NO_SIGN_REASON, AMBER_REASON], True])

    def test_explicit_true_requires_memory_sign(self):
        self.assertEqual(decide(**{NEEDS_SIGN: True})[0:2], ["AMBER", [NO_SIGN_REASON, AMBER_REASON]])

    def test_each_memory_sign_alone_authorizes_cpu_red(self):
        # Swap +1 and compressor +257 are below the independent RED growth limits.
        for sign in ({"pressure": (1, 2)}, {"swap_used_mb": (500, 501)}, {"comp_mb": (300, 557)}):
            with self.subTest(sign=sign):
                self.assertEqual(decide(window(**sign)), ["RED", [RED_REASON], True])

    def test_pressure_warning_needs_only_current_sample(self):
        for pressure in (2, 3):
            with self.subTest(pressure=pressure):
                self.assertEqual(decide(window(pressure=(1, pressure))), ["RED", [RED_REASON], True])

    def test_past_pressure_warning_is_not_a_current_memory_sign(self):
        self.assertEqual(decide(window(pressure=(2, 1))), ["AMBER", [NO_SIGN_REASON, AMBER_REASON], True])

    def test_swap_growth_is_strictly_positive(self):
        for delta, state in ((-1, "AMBER"), (0, "AMBER"), (0.01, "RED")):
            with self.subTest(delta=delta):
                self.assertEqual(decide(window(swap_used_mb=(500, 500 + delta)))[0], state)

    def test_compressor_growth_default_and_configured_boundaries(self):
        for limit in (256, 64):
            for offset, state in ((-0.01, "AMBER"), (0, "AMBER"), (0.01, "RED")):
                with self.subTest(limit=limit, offset=offset):
                    result = decide(window(comp_mb=(300, 300 + limit + offset)), **{COMP_GROWTH: limit})
                    reasons = [RED_REASON] if state == "RED" else [NO_SIGN_REASON, AMBER_REASON]
                    self.assertEqual(result, [state, reasons, True])

    def test_memory_growth_uses_last_sixty_seconds_not_old_baseline(self):
        for field, old, recent in (("swap_used_mb", 0, 500), ("comp_mb", 0, 600)):
            rows = window(**{field: (recent, recent)})
            rows.insert(0, dict(rows[0], t=NOW - 120, **{field: old}))
            with self.subTest(field=field):
                self.assertEqual(decide(rows), ["AMBER", [NO_SIGN_REASON, AMBER_REASON], True])

    def test_swap_growth_uses_recent_minimum_not_only_previous_sample(self):
        rows = window(swap_used_mb=(500, 501))
        rows.insert(1, dict(rows[0], t=NOW - 30, swap_used_mb=502))
        self.assertEqual(decide(rows), ["RED", [RED_REASON], True])

    def test_false_preserves_old_red_result_byte_for_byte(self):
        self.assertEqual(decide(**{NEEDS_SIGN: False}), ["RED", [RED_REASON], True])

    def test_one_high_sample_or_short_history_is_not_sustained(self):
        for rows in (window(sys_pct=(10, 50)), window()[1:],
                     [dict(window()[0], t=NOW - 10), window()[1]]):
            for over in ({}, {NEEDS_SIGN: False}):
                with self.subTest(rows=rows, over=over):
                    self.assertEqual(decide(rows, **over), ["STEADY", ["system CPU not under 25%"], True])

    def test_cpu_limit_is_strict_even_with_memory_sign(self):
        self.assertEqual(decide(window(sys_pct=(40, 40))), ["AMBER", [AMBER_REASON], True])
        result = decide(window(sys_pct=(40, 40), pressure=(2, 2)))
        self.assertEqual(result, ["AMBER", ["kernel pressure 2 (warn)", AMBER_REASON], True])

    def test_reason_numbers_and_sustain_count_follow_settings(self):
        rows = window(sys_pct=(48, 49))
        rows.insert(0, dict(rows[0], t=NOW - 120))
        result = decide(rows, **{"slots.red_sys_pct": 47.5, "slots.sustain_samples": 3})
        self.assertEqual(result, ["AMBER", ["system CPU > 47.5% in 3 samples, no memory sign",
                                            "system CPU > 30% in 3 samples"], True])

    def test_existing_amber_cpu_rule_survives_below_red_limit(self):
        self.assertEqual(decide(window(sys_pct=(35, 35))), ["AMBER", [AMBER_REASON], True])

    def test_independent_red_free_rule_still_wins(self):
        self.assertEqual(decide(window(free_pct=(30, 30))), ["RED", ["free 30% < 35%"], True])

    def test_missing_memory_sign_readings_do_not_authorize_red(self):
        for field in ("pressure", "swap_used_mb", "comp_mb"):
            rows = window()
            rows[-1].pop(field)
            with self.subTest(field=field):
                self.assertEqual(decide(rows), ["AMBER", [NO_SIGN_REASON, AMBER_REASON], field == "pressure"])


class RedSysSettings(TempData):
    def test_default_requires_sign(self):
        self.assertIs(mmcore.defaults().get(NEEDS_SIGN), True)

    def test_default_compressor_growth_is_256_mb(self):
        self.assertEqual(mmcore.defaults().get(COMP_GROWTH), 256)

    def test_both_settings_are_registered_and_have_schema_ranges(self):
        props = mmcore.settings_json_schema()["properties"]
        self.assertIn(NEEDS_SIGN, props)
        self.assertIn(COMP_GROWTH, props)
        self.assertEqual(props[NEEDS_SIGN], {"type": "boolean"})
        self.assertEqual((props[COMP_GROWTH]["minimum"], props[COMP_GROWTH]["maximum"]), (1, 100000))

    def test_boolean_accepts_only_booleans(self):
        for value in (True, False):
            with self.subTest(valid=value):
                self.assertEqual(mmcore.validate(base_settings(**{NEEDS_SIGN: value})), [])
        for value in (0, 1, "true", "false", None):
            with self.subTest(invalid=value):
                self.assertTrue(any(p.startswith(NEEDS_SIGN + ":")
                                    for p in mmcore.validate(base_settings(**{NEEDS_SIGN: value}))))

    def test_compressor_growth_accepts_range_and_rejects_bad_values(self):
        for value in (1, 256, 100000):
            with self.subTest(valid=value):
                self.assertEqual(mmcore.validate(base_settings(**{COMP_GROWTH: value})), [])
        for value in (0, 100001, True, "256", None, float("nan"), float("inf")):
            with self.subTest(invalid=value):
                self.assertTrue(any(p.startswith(COMP_GROWTH + ":")
                                    for p in mmcore.validate(base_settings(**{COMP_GROWTH: value}))))

    def test_owner_settings_file_overrides_both_values_and_behavior(self):
        for needs, limit in ((False, 64), (True, 700)):
            with self.subTest(needs_sign=needs, limit=limit):
                self.write_settings(**{NEEDS_SIGN: needs, COMP_GROWTH: limit})
                settings = mmcore.Settings()
                loaded = settings.load()
                self.assertIsNone(settings.problem)
                self.assertIsNotNone(loaded)
                self.assertEqual((loaded[NEEDS_SIGN], loaded[COMP_GROWTH]), (needs, limit))
                self.assertEqual(mmdecide.classify(window(), loaded)[0], "AMBER" if needs else "RED")

    def test_bad_owner_override_keeps_last_good_settings(self):
        for key, value in ((NEEDS_SIGN, "false"), (COMP_GROWTH, 0), (COMP_GROWTH, 100001)):
            with self.subTest(key=key, value=value):
                settings = mmcore.Settings()
                good = settings.load()
                self.assertIsNotNone(good)
                self.write_settings(**{key: value})
                self.assertEqual(settings.load(), good)
                self.assertTrue(settings.problem)
                self.write_settings()


class RedSysDelivery(TempData):
    def test_cpu_alone_produces_amber_alert_without_mem_red(self):
        state, reasons, _ = decide()
        conditions = mmalerts.evaluate({"state": [state, reasons]}, base_settings(), NOW)
        self.assertNotIn("MEM_RED", [c["name"] for c in conditions])
        self.assertEqual([(c["name"], c["level"]) for c in conditions], [("MEM_AMBER", "ATTENTION")])

    def test_cpu_alone_leaves_launch_gate_open_with_red_control(self):
        settings = base_settings(**{"launch_gate.enabled": True})
        for rows, held in ((window(), False), (window(free_pct=(30, 30)), True)):
            state, reasons, _ = decide(rows)
            mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps(
                {"time": NOW, "state": state, "reasons": reasons, "red_since": NOW - 60}))
            with self.subTest(held=held):
                result = ad_deliver_claude.gate_decision({"tool_name": "Agent"}, settings, NOW,
                                                       {"launch_tools": ["Agent"]})
                if held:
                    self.assertIsNotNone(result)
                    self.assertTrue(result.startswith("E_GATE_RED "))
                else:
                    self.assertIsNone(result)
