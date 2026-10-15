# SPDX-License-Identifier: Apache-2.0
"""Round-two review: isolate invalid row numbers before they lose valid siblings."""
import json
import os
import sys
import unittest

from mmtest import TempData
import ad_deliver_claude
import mmalerts


NOW = 1_800_000_000.0
LEVELS = ("claude_5h", "claude_weekly", "codex_weekly", "codex_5h")
USAGE_ALERTS = {"CODEX98", "CLAUDE98", "FIVE_H", "CLAUDE_PROJ"}


def state():
    return {"checked_at": NOW, "max_age_seconds": 1800,
            "claude_weekly_projection": 120,
            "levels": {level: {"status": "cached", "used_percent": 98,
                               "read_at": NOW - 60, "reset_at": NOW + 3600}
                       for level in LEVELS}}


class UsageRowsReviewR2(TempData):
    def read_text(self, text):
        path = os.path.join(self.data, "usage.json")
        with open(path, "w") as f:
            f.write(text)
        return ad_deliver_claude.read_usage(path, NOW, self.s())

    def oversized_integer_text(self, field):
        # Derive the boundary from this interpreter; introduce no parser limit.
        limit = getattr(sys, "get_int_max_str_digits", lambda: 0)()
        if not limit:
            self.skipTest("this interpreter has no enabled integer-string limit")
        digits = "1" * (limit + 1)
        d = state()
        d["levels"]["codex_5h"][field] = "INTEGER_TOKEN"
        text = json.dumps(d).replace('"INTEGER_TOKEN"', digits)
        # Confirm valid JSON syntax without first converting the large integer.
        parsed = json.loads(text, parse_int=str)
        self.assertEqual(parsed["levels"]["codex_5h"][field], digits)
        return text

    def usage_alert_names(self, usage):
        return {c["name"] for c in mmalerts.evaluate({"usage": usage}, self.s(), NOW)
                if c["name"] in USAGE_ALERTS}

    def test_integer_above_decoder_digit_limit_preserves_sibling_rows(self):
        for field in ("used_percent", "read_at", "reset_at"):
            with self.subTest(field=field):
                got = self.read_text(self.oversized_integer_text(field))
                self.assertIsInstance(got, dict, "valid JSON with one invalid row lost all siblings")
                self.assertIsNone(got["codex_5h"])
                self.assertIn("codex_5h", got["stale_levels"])
                for key in ("claude_5h", "claude_week", "codex_week"):
                    self.assertEqual(got[key], 98)
                self.assertEqual(got["proj"], 120)

    def test_integer_above_decoder_digit_limit_preserves_sibling_alerts(self):
        self.assertEqual(self.usage_alert_names(self.read_text(json.dumps(state()))), USAGE_ALERTS)
        for field in ("used_percent", "read_at", "reset_at"):
            with self.subTest(field=field):
                got = self.read_text(self.oversized_integer_text(field))
                self.assertEqual(self.usage_alert_names(got), USAGE_ALERTS,
                                 "an invalid Codex 5-hour number hid valid weekly/Claude alerts")

    def test_nonfinite_and_float_overflow_rows_preserve_siblings(self):
        for field in ("used_percent", "read_at", "reset_at"):
            for value in (float("nan"), float("inf"), -float("inf"), 10 ** 400, -(10 ** 400)):
                with self.subTest(field=field, kind=type(value).__name__):
                    d = state()
                    d["levels"]["codex_5h"][field] = value
                    got = self.read_text(json.dumps(d))
                    self.assertIsInstance(got, dict)
                    self.assertIsNone(got["codex_5h"])
                    self.assertIn("codex_5h", got["stale_levels"])
                    self.assertEqual(self.usage_alert_names(got), USAGE_ALERTS)


if __name__ == "__main__":
    unittest.main()
