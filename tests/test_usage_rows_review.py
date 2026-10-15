# SPDX-License-Identifier: Apache-2.0
"""Independent review reproductions using synthetic state and isolated homes only."""
import json
import os
import unittest
from unittest.mock import patch

from mmtest import TempData, base_settings
import ad_deliver_claude
import mmalerts
import mmcore
import mmread
import mmschema
import mmsuper
import vector_functions

NOW = 1_800_000_000.0
LEVELS = ("claude_5h", "claude_weekly", "codex_weekly", "codex_5h")
ALERT_KEYS = ("CODEX", "CLAUDE98", "FIVE_H", "CLAUDE_PROJ")


def state():
    return {"checked_at": NOW, "max_age_seconds": 1800, "claude_weekly_projection": 120,
            "levels": {level: {"status": "cached", "used_percent": 98, "read_at": NOW - 60,
                               "reset_at": NOW + 3600} for level in LEVELS}}


class UsageRowsReview(TempData):
    def setUp(self):
        super().setUp()
        self.now = NOW
        self.usage_file = os.path.join(self.data, "usage.json")
        self.conditions = []
        for target, values in (("read_ps", {"return_value": []}),
                               ("disk_free_gb", {"return_value": 100}),
                               ("run", {"return_value": (0, "Now drawing from 'AC Power'")})):
            self.enterContext(patch.object(mmread, target, **values))

        evaluate = mmalerts.evaluate

        def record(*args, **kwargs):
            got = evaluate(*args, **kwargs)
            self.conditions = got
            return got

        self.enterContext(patch.object(mmalerts, "evaluate", side_effect=record))

    def write_state(self, d):
        with open(self.usage_file, "w") as f:
            json.dump(d, f)

    def read(self, d, s=None):
        self.write_state(d)
        return ad_deliver_claude.read_usage(self.usage_file, self.now, s)

    def supervisor(self):
        profile = self.profile()
        profile.pop("queue", None)
        profile.pop("ci", None)
        profile["memory_guard"] = {}

        def sample(now, ticks):
            return {"t": now, "free_pct": 80, "swap_used_mb": 100, "swap_total_mb": 2048,
                    "comp_mb": 300, "pressure": 1, "seg_pct": 1, "load1": 1, "load5": 1,
                    "sys_pct": 10}, ticks

        return mmsuper.Supervisor(profile, kernel=False, clock=lambda: self.now, sampler=sample,
                                  sizes=False, slow_jobs=False, check_readings=False,
                                  boot=lambda: {"boot_time": NOW - 86400, "panics": [], "missing_jobs": []})

    def usage_conditions(self):
        return sorted((c["name"], c["level"]) for c in self.conditions if c["key"] in ALERT_KEYS)

    def test_cached_snapshot_cannot_raise_at_the_reset_second(self):
        d = state()
        for row in d["levels"].values():
            row["reset_at"] = NOW + 5
        self.write_state(d)
        sup = self.supervisor()
        sup.tick()
        self.assertEqual(len(self.usage_conditions()), 4)
        self.now += 5
        # A direct read correctly rejects the same rows at the exact reset second.
        self.assertIsNone(ad_deliver_claude.read_usage(self.usage_file, self.now)["codex_week"])
        sup.tick()
        self.assertEqual(self.usage_conditions(), [], "expired cached rows still reach the alert store")

    def test_cached_snapshot_cannot_raise_after_read_age_expires(self):
        d = state()
        d["max_age_seconds"] = 120
        for row in d["levels"].values():
            row["read_at"] = NOW - 115
        self.write_state(d)
        sup = self.supervisor()
        sup.tick()
        self.now += 10
        self.assertIsNone(ad_deliver_claude.read_usage(self.usage_file, self.now)["proj"])
        sup.tick()
        self.assertEqual(self.usage_conditions(), [], "the minute cache outlives the rows' max age")

    def test_current_row_is_recovered_at_the_clock_allowance_boundary(self):
        d = state()
        for row in d["levels"].values():
            row["read_at"] = NOW + 10
        self.write_state(d)
        sup = self.supervisor()
        sup.tick()
        self.assertEqual(self.usage_conditions(), [])
        self.now += 5
        self.assertEqual(ad_deliver_claude.read_usage(self.usage_file, self.now)["codex_week"], 98)
        sup.tick()
        self.assertIn(("CODEX98", "ACTION"), self.usage_conditions())

    def test_threshold_reload_cannot_push_a_new_action_from_an_expired_cached_row(self):
        d = state()
        d["levels"]["codex_weekly"]["reset_at"] = NOW + 5
        self.write_settings(**{"usage.codex_attention_pct": 99, "usage.codex_action_pct": 99})
        self.write_state(d)
        sup = self.supervisor()
        sup.tick()
        self.assertFalse(any(p["name"] == "CODEX98" for p in self.pushed()))
        self.now += 5
        # Restoring the default threshold must not resurrect an already reset reading.
        self.write_settings()
        sup.tick()
        pushed = [(p["name"], p["level"]) for p in self.pushed() if p["name"] == "CODEX98"]
        self.assertEqual(pushed, [], "a new ACTION was pushed after the usage window reset")

    def test_one_oversized_row_number_cannot_discard_current_siblings(self):
        for field in ("used_percent", "read_at", "reset_at"):
            with self.subTest(field=field):
                d = state()
                # This is a valid JSON integer, beyond the float conversion range.
                d["levels"]["codex_5h"][field] = 10 ** 400
                got = self.read(d)
                self.assertIsInstance(got, dict, "one row discarded current weekly readings and projection")
                self.assertEqual(got["codex_week"], 98)
                self.assertEqual(got["proj"], 120)

    def test_read_usage_vectors_apply_their_supplied_settings(self):
        d = state()
        d["levels"]["codex_weekly"]["read_at"] = NOW + 1
        s = base_settings(**{"usage.read_clock_allowance_s": 0})
        self.assertIsNone(self.read(d, s)["codex_week"])
        got = vector_functions.FUNCTIONS["read_usage"]({"state": d, "now": NOW}, s)
        self.assertIsNone(got["codex_week"], "the vector adapter silently uses the default allowance")

    def test_default_clock_allowance_and_inclusive_boundaries(self):
        self.assertEqual(mmcore.defaults()["usage.read_clock_allowance_s"], 5)
        for status in ("ok", "cached"):
            for allowance in (0, 5, 60):
                for offset, expected in ((allowance, 98), (allowance + 0.25, None)):
                    with self.subTest(status=status, allowance=allowance, offset=offset):
                        d = state()
                        d["levels"]["codex_weekly"].update(status=status, read_at=NOW + offset)
                        s = base_settings(**{"usage.read_clock_allowance_s": allowance})
                        self.assertEqual(self.read(d, s)["codex_week"], expected)

    def test_clock_setting_validation_and_generated_schema_agree(self):
        schema = mmschema.load("settings")
        self.assertEqual(schema, mmcore.settings_json_schema())
        for allowance, valid in ((0, True), (5, True), (60, True), (-0.25, False), (60.25, False),
                                 (True, False), ("5", False)):
            with self.subTest(allowance=allowance):
                s = base_settings(**{"usage.read_clock_allowance_s": allowance})
                self.assertEqual(mmcore.validate(s) == [], valid)
                self.assertEqual(mmschema.validate(s, schema) == [], valid)

    def test_stale_source_keys_are_fixed_and_display_is_bounded(self):
        d = state()
        for row in d["levels"].values():
            row["status"] = "unknown\n" * 100
        d["levels"]["extra_level"] = {"status": "unknown"}
        sup = self.supervisor()
        self.write_state(d)
        sup.tick()
        self.assertEqual(set(sup.cache["stale_sources"]), {"usage:" + level for level in LEVELS})
        for c in self.conditions:
            if c["name"] == "SOURCE_STALE":
                line = mmcore.alert_line(c)
                self.assertLessEqual(len(line), mmcore.LINE_MAX)
                self.assertNotIn("\n", line)


if __name__ == "__main__":
    unittest.main()
