# SPDX-License-Identifier: Apache-2.0
"""Round-four review: malformed timestamps and ordinary cache-percentage compatibility."""
import json
import os
import time
import unittest
from unittest.mock import patch

from mmtest import TempData
import ad_deliver_claude
import mmalerts
import mmread
import mmsuper


NOW = 1_800_000_000.0


class UsageRowsReviewR4(TempData):
    def record(self, mid, m5, h1):
        return {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(NOW - 60)),
                "message": {"id": mid, "usage": {"cache_creation": {
                    "ephemeral_5m_input_tokens": m5, "ephemeral_1h_input_tokens": h1}}}}

    def project(self, lines):
        project = os.path.join(self.root, "projects")
        sub = os.path.join(project, "session", "subagents")
        os.makedirs(sub)
        path = os.path.join(sub, "agent.jsonl")
        with open(path, "w") as f:
            for line in lines:
                f.write(json.dumps(line) + "\n")
        os.utime(path, (NOW, NOW))
        return project

    def test_object_timestamp_is_skipped_and_sizes_job_keeps_good_lines(self):
        bad = self.record("bad", 90_000_000, 90_000_000)
        bad["timestamp"] = {}
        project = self.project([self.record("before", 2_000_000, 250_000), bad,
                                self.record("after", 3_000_000, 750_000)])
        delivery = ad_deliver_claude.Delivery({"transcripts_dir": project})
        disk_path = os.path.join(self.root, "disk-cache")
        with patch.object(mmread, "run", return_value=(0, "8000000\t%s\n" % disk_path)), \
                patch.object(mmsuper.time, "time", return_value=NOW):
            try:
                result = mmsuper.sizes_job({"cache": disk_path}, delivery)
            except Exception as exc:
                self.fail("one object-valued timestamp failed the whole sizes job: %r" % exc)
        self.assertEqual(result["sizes"], {"cache": 8_000_000 * 1024 / 1e9})
        self.assertEqual(result["cache5m"], {"m5": 5_000_000, "h1": 1_000_000, "skipped": 1})

    def test_ordinary_counts_at_configured_share_threshold_do_not_gain_an_alert(self):
        settings = self.s()
        settings["other.cache_5m_share_pct"] = 60
        # Both totals are ordinary, exact floats from cache_5m. The old rule's strict
        # comparison excludes exactly 60%; scaling currently makes it 60.00000000000001.
        cache = {"m5": 3_000_000.0, "h1": 2_000_000.0}
        old_share = cache["m5"] * 100.0 / max(1, cache["m5"] + cache["h1"])
        self.assertEqual(old_share, settings["other.cache_5m_share_pct"])
        got = mmalerts.evaluate({"cache5m": cache}, settings, NOW)
        self.assertNotIn("CACHE_5M", {condition["name"] for condition in got}, got)

    def test_ordinary_counts_keep_the_previously_displayed_cache_percentage(self):
        cache = {"m5": 3_000_000.0, "h1": 5_000_000.0}
        old_share = cache["m5"] * 100.0 / max(1, cache["m5"] + cache["h1"])
        self.assertEqual("%.0f%%" % old_share, "38%")
        got = [condition for condition in mmalerts.evaluate({"cache5m": cache}, self.s(), NOW)
               if condition["name"] == "CACHE_5M"]
        self.assertEqual(len(got), 1)
        self.assertIn("(38%)", got[0]["text"])


if __name__ == "__main__":
    unittest.main()
