# SPDX-License-Identifier: Apache-2.0
"""Usage-row design, coarse rule items 1-6. All state is synthetic and lives in TempData.

The future-time case is deliberately a day ahead: the design leaves the small clock allowance unspecified.
No test chooses that allowance. Booleans are not percentage/timestamp numbers (as in the billing parser).
"""
import json
import os
import unittest
from unittest.mock import patch

from mmtest import TempData
import ad_deliver_claude
import mmalerts
import mmread
import mmsuper

NOW = 1_800_000_000.0
LEVELS = {"claude_5h": "claude_5h", "claude_weekly": "claude_week", "codex_weekly": "codex_week"}
WATCHED = tuple(LEVELS) + ("codex_5h",)
USAGE_ALERTS = {"CODEX95", "CODEX98", "CLAUDE98", "FIVE_H", "CLAUDE_PROJ"}
MISSING = object()


def state():
    return {"checked_at": NOW, "max_age_seconds": 1800, "claude_weekly_projection": 50,
            "levels": {k: {"status": "ok", "used_percent": 10, "read_at": NOW - 60,
                            "reset_at": NOW + 3600, "age_seconds": 60, "window_minutes": 300}
                       for k in WATCHED}}


def invalid_rows():
    """The outer check stays fresh, including when a cached row has expired or reset."""
    cases = [
        ("unknown", {"status": "unknown"}, "unknown"),
        ("unrecognised-status", {"status": "error"}, "error"),
        ("old-ok", {"read_at": NOW - 1801, "age_seconds": 0}, r"age|old|expir|\d"),
        ("old-cached", {"status": "cached", "read_at": NOW - 1801}, r"age|old|expir|\d"),
        ("reset-ok", {"reset_at": NOW - 1}, "window reset"),
        ("reset-cached", {"status": "cached", "reset_at": NOW - 1}, "window reset"),
        ("reset-at-now", {"reset_at": NOW}, "window reset"),
        ("future-read", {"read_at": NOW + 86400}, r"future|ahead|age|\d"),
    ]
    for key in ("status", "used_percent", "read_at"):
        for label, value in (("missing", MISSING), ("null", None), ("boolean", True),
                             ("list", []), ("object", {}), ("string", "98")):
            cases.append((key + "-" + label, {key: value}, None))
    return cases


def change_row(d, level, over):
    row = d["levels"][level]
    for key, value in over.items():
        if value is MISSING:
            row.pop(key, None)
        else:
            row[key] = value


class UsageRows(TempData):
    def write_state(self, d):
        path = os.path.join(self.data, "usage.json")
        with open(path, "w") as f:
            json.dump(d, f)
        return path

    def read(self, d):
        return ad_deliver_claude.read_usage(self.write_state(d), NOW)

    def usage_alerts(self, u):
        return sorted((c["name"], c["level"]) for c in mmalerts.evaluate({"usage": u}, self.s(), NOW)
                      if c["name"] in USAGE_ALERTS)

    def tick_state(self, d=MISSING):
        if d is not MISSING:
            self.write_state(d)
        profile = self.profile()
        profile["memory_guard"] = {}

        def sample(now, ticks):
            return {"t": now, "free_pct": 80, "swap_used_mb": 100, "swap_total_mb": 2048,
                    "comp_mb": 300, "pressure": 1, "seg_pct": 1, "load1": 1, "load5": 1,
                    "sys_pct": 10}, ticks

        with patch.object(mmread, "read_ps", return_value=[]), \
                patch.object(mmread, "disk_free_gb", return_value=100), \
                patch.object(mmread, "run", return_value=(0, "Now drawing from 'AC Power'")):
            sup = mmsuper.Supervisor(profile, kernel=False, clock=lambda: NOW, sampler=sample,
                                     sizes=False, slow_jobs=False, check_readings=False,
                                     boot=lambda: {"boot_time": NOW - 86400, "panics": [], "missing_jobs": []})
            sup.tick()
        self.assertEqual(sup.tick_n, 1)
        return sup

    def usage_stale(self, sup):
        return {k: v for k, v in sup.cache["stale_sources"].items() if k == "usage" or k.startswith("usage:")}

    def assert_stale_alerts(self, sup, expected):
        stale = self.usage_stale(sup)
        self.assertEqual(set(stale), set(expected))
        for key, reason in expected.items():
            self.assertIsInstance(stale[key], str)
            self.assertTrue(stale[key].strip(), key)
            if reason:
                self.assertRegex(stale[key].lower(), reason)
        conds = mmalerts.evaluate({"stale_sources": stale}, self.s(), NOW)
        self.assertEqual({(c["key"], c["name"], c["level"]) for c in conds},
                         {("SOURCE_STALE:" + key, "SOURCE_STALE", "ATTENTION") for key in expected})

    def test_item1_invalid_rows_are_unknown_under_a_fresh_outer_check(self):
        for level, output in LEVELS.items():
            for label, over, _ in invalid_rows():
                with self.subTest(level=level, case=label):
                    d = state()
                    d["levels"][level]["used_percent"] = 98
                    change_row(d, level, over)
                    u = self.read(d)
                    self.assertIsInstance(u, dict, "a bad row must not discard its valid siblings")
                    self.assertIsNone(u[output])
                    for sibling, key in LEVELS.items():
                        if sibling != level:
                            self.assertEqual(u[key], 10)

    def test_item1_missing_or_malformed_individual_row_preserves_siblings(self):
        for level, output in LEVELS.items():
            for row in (MISSING, None, [], "bad", 98, True):
                with self.subTest(level=level, row=repr(row)):
                    d = state()
                    if row is MISSING:
                        del d["levels"][level]
                    else:
                        d["levels"][level] = row
                    u = self.read(d)
                    self.assertIsInstance(u, dict)
                    self.assertIsNone(u[output])
                    self.assertEqual([u[key] for k, key in LEVELS.items() if k != level], [10, 10])

    def test_item1_state_max_age_controls_each_row_including_the_boundary(self):
        for status in ("ok", "cached"):
            for age, expected in ((119, 98), (120, 98), (121, None)):
                with self.subTest(status=status, age=age):
                    d = state()
                    d["max_age_seconds"] = 120
                    d["levels"]["codex_weekly"].update(status=status, used_percent=98, read_at=NOW - age)
                    self.assertEqual(self.read(d)["codex_week"], expected)

    def test_item2_unknown_levels_raise_no_level_alert_and_are_not_zero(self):
        for level, output in LEVELS.items():
            for label, over, _ in invalid_rows():
                with self.subTest(level=level, case=label):
                    d = state()
                    d["levels"][level]["used_percent"] = 98
                    change_row(d, level, over)
                    u = self.read(d)
                    with self.subTest(assertion="alerts"):
                        self.assertEqual(self.usage_alerts(u), [])
                    with self.subTest(assertion="unknown-is-not-zero"):
                        self.assertIsInstance(u, dict)
                        self.assertIsNone(u[output])

    def test_item2_codex_unknown_does_not_raise_either_threshold(self):
        for percent in (95, 98):
            with self.subTest(percent=percent):
                d = state()
                d["levels"]["codex_weekly"].update(status="unknown", used_percent=percent)
                self.assertEqual(self.usage_alerts(self.read(d)), [])

    def test_item3_each_unknown_watched_level_has_a_reason_and_stale_alert(self):
        for level in WATCHED:
            for label, over, reason in invalid_rows():
                with self.subTest(level=level, case=label):
                    d = state()
                    change_row(d, level, over)
                    sup = self.tick_state(d)
                    self.assert_stale_alerts(sup, {"usage:" + level: reason})

    def test_item3_missing_levels_are_named_individually(self):
        d = state()
        d["levels"] = {}
        sup = self.tick_state(d)
        self.assert_stale_alerts(sup, {"usage:" + k: None for k in WATCHED})

    def test_item3_one_missing_or_malformed_row_names_only_its_own_source(self):
        for level in WATCHED:
            for label, row in (("missing", MISSING), ("null", None), ("array", []),
                               ("string", "bad"), ("number", 98), ("boolean", True)):
                with self.subTest(level=level, case=label):
                    d = state()
                    if row is MISSING:
                        del d["levels"][level]
                    else:
                        d["levels"][level] = row
                    sup = self.tick_state(d)
                    self.assert_stale_alerts(sup, {"usage:" + level: None})

    def test_item3_row_age_uses_the_states_limit_not_the_supervisor_outer_limit(self):
        for age in (120, 121):
            with self.subTest(age=age):
                d = state()
                d["max_age_seconds"] = 120
                d["levels"]["codex_weekly"]["read_at"] = NOW - age
                expected = {} if age == 120 else {"usage:codex_weekly": r"age|old|expir|\d"}
                self.assert_stale_alerts(self.tick_state(d), expected)

    def test_item3_mixed_levels_keep_current_alert_and_expose_only_unknown_sources(self):
        d = state()
        d["levels"]["codex_weekly"]["used_percent"] = 98
        d["levels"]["claude_weekly"].update(status="unknown", used_percent=98)
        d["levels"]["claude_5h"].update(read_at=NOW - 1801, used_percent=98)
        d["levels"]["codex_5h"]["status"] = "not_offered"
        sup = self.tick_state(d)
        with self.subTest(assertion="sources"):
            self.assert_stale_alerts(sup, {"usage:claude_weekly": "unknown", "usage:claude_5h": None})
        with self.subTest(assertion="level-alerts"):
            self.assertEqual(self.usage_alerts(sup.cache["usage"]), [("CODEX98", "ACTION")])
        with self.subTest(assertion="published-alerts"):
            active = mmcore_active(self.data)
            self.assertIn("SOURCE_STALE:usage:claude_weekly", active)
            self.assertIn("SOURCE_STALE:usage:claude_5h", active)
            self.assertIn("CODEX", active)
            self.assertNotIn("CLAUDE98", active)
            self.assertNotIn("FIVE_H", active)

    def test_item3_not_offered_codex_5h_is_skipped_without_a_stale_source(self):
        d = state()
        d["levels"]["codex_5h"] = {"status": "not_offered", "used_percent": 98}
        sup = self.tick_state(d)
        self.assert_stale_alerts(sup, {})
        self.assertEqual(self.usage_alerts(sup.cache["usage"]), [])

    def test_item4_projection_is_unknown_when_its_weekly_row_is_not_current(self):
        for label, over, _ in invalid_rows():
            with self.subTest(case=label):
                d = state()
                d["claude_weekly_projection"] = 120
                change_row(d, "claude_weekly", over)
                u = self.read(d)
                with self.subTest(assertion="projection-value"):
                    self.assertIsInstance(u, dict)
                    self.assertIsNone(u["proj"])
                with self.subTest(assertion="projection-alert"):
                    self.assertEqual(self.usage_alerts(u), [])

    def test_item4_projection_is_not_rescued_by_a_current_five_hour_row(self):
        d = state()
        d["claude_weekly_projection"] = 120
        d["levels"]["claude_weekly"]["read_at"] = NOW - 1801
        sup = self.tick_state(d)
        with self.subTest(assertion="source"):
            self.assert_stale_alerts(sup, {"usage:claude_weekly": None})
        with self.subTest(assertion="alerts"):
            self.assertEqual(self.usage_alerts(sup.cache["usage"]), [])

    def test_item4_current_weekly_projection_survives_unknown_siblings(self):
        d = state()
        d["claude_weekly_projection"] = 120
        d["levels"]["claude_5h"].update(status="unknown", used_percent=98)
        d["levels"]["codex_weekly"].update(status="unknown", used_percent=98)
        sup = self.tick_state(d)
        with self.subTest(assertion="projection"):
            self.assertEqual(sup.cache["usage"]["proj"], 120)
        with self.subTest(assertion="sources"):
            self.assert_stale_alerts(sup, {"usage:claude_5h": "unknown", "usage:codex_weekly": "unknown"})
        with self.subTest(assertion="alerts"):
            self.assertEqual(self.usage_alerts(sup.cache["usage"]), [("CLAUDE_PROJ", "ATTENTION")])

    def test_item5_current_ok_and_cached_rows_preserve_percentages_and_no_stale_sources(self):
        for status in ("ok", "cached"):
            with self.subTest(status=status):
                d = state()
                for row in d["levels"].values():
                    row["status"] = status
                u = self.read(d)
                self.assertEqual([u[k] for k in LEVELS.values()], [10, 10, 10])
                self.assertEqual(u["proj"], 50)
                self.assertEqual(self.usage_alerts(u), [])
                self.assert_stale_alerts(self.tick_state(d), {})

    def test_item5_current_zero_and_float_percentages_are_preserved(self):
        for percent in (0, 0.0, 97.5):
            with self.subTest(percent=percent):
                d = state()
                d["levels"]["codex_weekly"]["used_percent"] = percent
                self.assertEqual(self.read(d)["codex_week"], percent)

    def test_item5_current_high_rows_publish_existing_alerts_without_stale_sources(self):
        d = state()
        for row in d["levels"].values():
            row.update(status="cached", used_percent=98)
        d["claude_weekly_projection"] = 120
        sup = self.tick_state(d)
        self.assert_stale_alerts(sup, {})
        active = mmcore_active(self.data)
        self.assertEqual(sorted((c["name"], c["level"]) for c in active.values() if c["name"] in USAGE_ALERTS),
                         [("CLAUDE98", "ACTION"), ("CLAUDE_PROJ", "ATTENTION"),
                          ("CODEX98", "ACTION"), ("FIVE_H", "ATTENTION")])

    def test_item5_optional_reset_and_derived_age_do_not_invalidate_current_rows(self):
        for reset in (MISSING, None, "not-a-number", [], {}):
            with self.subTest(reset=repr(reset)):
                d = state()
                change_row(d, "codex_weekly", {"reset_at": reset, "used_percent": 98,
                                              "age_seconds": 999999, "window_minutes": None})
                self.assertEqual(self.usage_alerts(self.read(d)), [("CODEX98", "ACTION")])
                self.assert_stale_alerts(self.tick_state(d), {})

    def test_item5_existing_default_alert_thresholds_do_not_change(self):
        cases = [
            ("codex_weekly", 94.9, []), ("codex_weekly", 95, [("CODEX95", "ATTENTION")]),
            ("codex_weekly", 97.9, [("CODEX95", "ATTENTION")]),
            ("codex_weekly", 98, [("CODEX98", "ACTION")]),
            ("claude_weekly", 97.9, []), ("claude_weekly", 98, [("CLAUDE98", "ACTION")]),
            ("claude_5h", 84.9, []), ("claude_5h", 85, [("FIVE_H", "ATTENTION")]),
            ("claude_5h", 97.9, [("FIVE_H", "ATTENTION")]),
            ("claude_5h", 98, [("CLAUDE98", "ACTION"), ("FIVE_H", "ATTENTION")]),
        ]
        for status in ("ok", "cached"):
            for level, percent, expected in cases:
                with self.subTest(status=status, level=level, percent=percent):
                    d = state()
                    d["levels"][level].update(status=status, used_percent=percent)
                    self.assertEqual(self.usage_alerts(self.read(d)), expected)

    def test_item5_current_weekly_projection_uses_existing_strict_threshold(self):
        for status in ("ok", "cached"):
            for projection, expected in ((95, []), (95.1, [("CLAUDE_PROJ", "ATTENTION")])):
                with self.subTest(status=status, projection=projection):
                    d = state()
                    d["levels"]["claude_weekly"]["status"] = status
                    d["claude_weekly_projection"] = projection
                    self.assertEqual(self.read(d)["proj"], projection)
                    self.assertEqual(self.usage_alerts(self.read(d)), expected)

    def test_item5_existing_settings_still_control_current_alert_thresholds(self):
        self.write_settings(**{"usage.codex_attention_pct": 90, "usage.codex_action_pct": 92,
                               "usage.claude_action_pct": 93, "usage.claude_5h_attention_pct": 80,
                               "usage.claude_projection_pct": 110})
        d = state()
        d["levels"]["codex_weekly"]["used_percent"] = 92
        d["levels"]["claude_weekly"]["used_percent"] = 93
        d["levels"]["claude_5h"]["used_percent"] = 80
        d["claude_weekly_projection"] = 111
        self.assertEqual(self.usage_alerts(self.read(d)), [("CLAUDE98", "ACTION"), ("CLAUDE_PROJ", "ATTENTION"),
                                                        ("CODEX98", "ACTION"), ("FIVE_H", "ATTENTION")])

    def test_item6_unreadable_or_malformed_state_marks_the_whole_source_stale(self):
        path = os.path.join(self.data, "usage.json")
        for label, text in (("missing", None), ("directory", None), ("empty", ""), ("truncated", '{"levels":'),
                            ("array", "[]"), ("null", "null"), ("string", '"bad"'), ("number", "98"),
                            ("bad-check-time", '{"checked_at": "bad", "levels": {}}'),
                            ("bad-levels", '{"checked_at": 1800000000, "levels": []}')):
            with self.subTest(case=label):
                if os.path.isdir(path):
                    os.rmdir(path)
                elif os.path.exists(path):
                    os.unlink(path)
                if label == "directory":
                    os.mkdir(path)
                elif text is not None:
                    with open(path, "w") as f:
                        f.write(text)
                self.assertIsNone(ad_deliver_claude.read_usage(path, NOW))
                sup = self.tick_state()
                self.assert_stale_alerts(sup, {"usage": "unreadable"})
                self.assertEqual(self.usage_alerts(sup.cache["usage"]), [])

    def test_item6_existing_outer_state_age_still_marks_whole_source_stale(self):
        d = state()
        d["checked_at"] = NOW - self.s()["usage.watch_state_max_age_s"] - 1
        self.assert_stale_alerts(self.tick_state(d), {"usage": "old"})


def mmcore_active(data):
    with open(os.path.join(data, "alerts-state.json")) as f:
        return json.load(f)["active"]


if __name__ == "__main__":
    unittest.main()
