# SPDX-License-Identifier: Apache-2.0
"""Round-three review: transcript usage numbers that each convert must not, together, hide sibling alerts.

Design, "Round 2 ... coarse rule": no single value in a usage source can make another row unknown; a number
Python cannot hold or will not convert becomes unknown for its own row only. The transcript cache counts
(cache_5m) keep every finite number, so two in-range integers can add up past the float range; the alert
evaluation then does float arithmetic on the sum and raises, and every usage alert of the tick is lost."""
import os
import time
import unittest

from mmtest import TempData
import ad_deliver_claude
import mmalerts


NOW = 1_800_000_000.0
# The largest power of ten that still converts to a float: each value alone is valid and finite.
IN_RANGE = "1" + "0" * 308


class UsageRowsReviewR3(TempData):
    def project(self, case, lines):
        sub = os.path.join(self.root, "projects-%d" % case, "sess", "subagents")
        os.makedirs(sub)
        path = os.path.join(sub, "agent.jsonl")
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(NOW - 60)) + ".000Z"
        with open(path, "w") as f:
            for i, (m5, h1) in enumerate(lines):
                f.write('{"timestamp": "%s", "message": {"id": "msg-%d", "usage": {"cache_creation": '
                        '{"ephemeral_5m_input_tokens": %s, "ephemeral_1h_input_tokens": %s}}}}\n' % (ts, i, m5, h1))
        os.utime(path, (NOW - 60, NOW - 60))
        return os.path.dirname(os.path.dirname(sub))

    def test_in_range_transcript_counts_do_not_hide_usage_alerts(self):
        usage = {"codex_week": 99, "codex_5h": None, "claude_5h": None, "claude_week": None, "proj": None,
                 "stale_levels": {}}
        cases = {"control, ordinary counts": [("2000000", "10")],
                 "one line, both counts": [(IN_RANGE, IN_RANGE)],
                 "two lines, 5-minute counts": [(IN_RANGE, "0"), (IN_RANGE, "0")]}
        for case, (name, lines) in enumerate(cases.items()):
            with self.subTest(case=name):
                cache = ad_deliver_claude.cache_5m(self.project(case, lines), NOW)
                self.assertIsInstance(cache, dict)
                try:
                    got = {c["name"] for c in mmalerts.evaluate({"cache5m": cache, "usage": usage}, self.s(), NOW)}
                except (OverflowError, ValueError, TypeError) as e:
                    self.fail("transcript counts made the alert evaluation raise %r; CODEX98 was lost" % e)
                self.assertIn("CODEX98", got)


if __name__ == "__main__":
    unittest.main()
