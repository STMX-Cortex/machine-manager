# SPDX-License-Identifier: Apache-2.0
"""Round 3: real transcript parsing must preserve cache alerts and the sizes-job result.

The external du command and sizes-job clock are replaced; one portability test selects
the standard library's recursive JSON backend. Transcript files, the Delivery adapter,
token accounting and alert evaluation exercise the real code.
Malformed fixtures contain ephemeral_5m so they reach decoding and shape validation.
"""
import json
import json.scanner
import os
import sys
import time
import unittest
from unittest.mock import patch

from mmtest import TempData
import ad_deliver_claude
import mmalerts
import mmread
import mmsuper


NOW = 1_800_000_000.0


class UsageRowsTranscript(TempData):
    def record(self, mid, m5, h1, age=60):
        return {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(NOW - age)),
                "message": {"id": mid, "usage": {"cache_creation": {
                    "ephemeral_5m_input_tokens": m5, "ephemeral_1h_input_tokens": h1}}}}

    def transcript(self, name, lines):
        project = os.path.join(self.root, name)
        sub = os.path.join(project, "session", "subagents")
        os.makedirs(sub)
        path = os.path.join(sub, "agent.jsonl")
        with open(path, "w") as f:
            for line in lines:
                f.write(line + "\n")
        # File freshness and message freshness are separate; both must admit the fixtures.
        os.utime(path, (NOW, NOW))
        return project

    def counts(self, cache):
        self.assertIsInstance(cache, dict)
        return {key: cache[key] for key in ("m5", "h1")}

    def cache_conditions(self, cache):
        return [(c["name"], c["level"]) for c in mmalerts.evaluate({"cache5m": cache}, self.s(), NOW)
                if c["name"] == "CACHE_5M"]

    def sizes_result(self, project):
        # Different disk sizes expose loss, swapping or partial preservation of the result.
        kib = {os.path.join(self.root, "disk-cache"): 8_000_000,
               os.path.join(self.root, "disk-build"): 3_000_000}
        paths = dict(zip(("cache", "build"), kib))

        def du(argv, **kwargs):
            self.assertEqual(argv[-2], "-sk")
            self.assertIn(argv[-1], kib)
            return 0, "%d\t%s\n" % (kib[argv[-1]], argv[-1])

        delivery = ad_deliver_claude.Delivery({"transcripts_dir": project})
        with patch.object(mmread, "run", side_effect=du) as run, \
                patch.object(mmsuper.time, "time", return_value=NOW):
            result = mmsuper.sizes_job(paths, delivery)
        self.assertEqual(run.call_count, len(paths))
        self.assertEqual(result["sizes"], {name: kib[path] * 1024 / 1e9 for name, path in paths.items()})
        self.assertEqual(result["at"], NOW)
        return result

    def malformed_lines(self):
        record = self.record("after", 90_000_000, 90_000_000)
        stamp = record["timestamp"]
        list_id = self.record(["bad"], 90_000_000, 90_000_000)
        object_id = self.record({"bad": "id"}, 90_000_000, 90_000_000)
        # Derive depth from this interpreter, rather than choosing a parser nesting limit.
        depth = 2 * sys.getrecursionlimit()
        return {
            "list-line": json.dumps([record]),
            "string-line": json.dumps("ephemeral_5m"),
            "string-message": json.dumps({"timestamp": stamp, "message": "ephemeral_5m"}),
            "list-message": json.dumps({"timestamp": stamp, "message": [record["message"]]}),
            "list-id": json.dumps(list_id),
            "object-id": json.dumps(object_id),
            "string-usage": json.dumps({"timestamp": stamp, "message": {"id": "after", "usage": "ephemeral_5m"}}),
            "list-usage": json.dumps({"timestamp": stamp, "message": {"id": "after", "usage": [record]}}),
            "string-cache-creation": json.dumps({"timestamp": stamp, "message": {
                "id": "after", "usage": {"cache_creation": "ephemeral_5m"}}}),
            "list-cache-creation": json.dumps({"timestamp": stamp, "message": {
                "id": "after", "usage": {"cache_creation": [record]}}}),
            "deep-nesting": '{"ephemeral_5m":' + "[" * depth + "0" + "]" * depth + "}",
        }

    def good_lines(self):
        return [json.dumps(self.record("before", 2_000_000, 250_000)),
                json.dumps(self.record("after", 3_000_000, 750_000))]

    def test_recent_matching_transcript_produces_cache_5m_condition(self):
        project = self.transcript("recent", [json.dumps(self.record("recent", 3_000_000, 1_000_000))])
        cache = ad_deliver_claude.cache_5m(project, NOW)
        self.assertEqual(self.counts(cache), {"m5": 3_000_000, "h1": 1_000_000})
        self.assertEqual(cache["skipped"], 0)
        self.assertEqual(self.cache_conditions(cache), [("CACHE_5M", "ATTENTION")])

    def test_recent_transcript_below_volume_or_share_threshold_does_not_alert(self):
        for name, m5, h1 in (("low-volume", 500_000, 0), ("low-share", 3_000_000, 40_000_000)):
            with self.subTest(case=name):
                project = self.transcript(name, [json.dumps(self.record(name, m5, h1))])
                cache = ad_deliver_claude.cache_5m(project, NOW)
                self.assertEqual(self.counts(cache), {"m5": m5, "h1": h1})
                self.assertEqual(cache["skipped"], 0)
                self.assertEqual(self.cache_conditions(cache), [])

    def test_sizes_job_keeps_disk_sizes_with_a_recent_matching_transcript(self):
        project = self.transcript("sizes-recent", [json.dumps(self.record("recent", 3_000_000, 1_000_000))])
        result = self.sizes_result(project)
        self.assertEqual(self.counts(result["cache5m"]), {"m5": 3_000_000, "h1": 1_000_000})
        self.assertEqual(result["cache5m"]["skipped"], 0)
        self.assertEqual(self.cache_conditions(result["cache5m"]), [("CACHE_5M", "ATTENTION")])

    def test_unexpected_shapes_are_skipped_and_other_lines_still_count(self):
        before, after = self.good_lines()
        for name, bad in self.malformed_lines().items():
            with self.subTest(shape=name):
                project = self.transcript(name, [before, bad, after])
                cache = ad_deliver_claude.cache_5m(project, NOW)
                self.assertEqual(self.counts(cache), {"m5": 5_000_000, "h1": 1_000_000})
                self.assertEqual(cache["skipped"], 1)
                self.assertEqual(self.cache_conditions(cache), [("CACHE_5M", "ATTENTION")])

    def test_sizes_job_keeps_disk_sizes_and_good_lines_for_each_unexpected_shape(self):
        before, after = self.good_lines()
        for name, bad in self.malformed_lines().items():
            with self.subTest(shape=name):
                project = self.transcript(name, [before, bad, after])
                result = self.sizes_result(project)
                self.assertEqual(self.counts(result["cache5m"]), {"m5": 5_000_000, "h1": 1_000_000})
                self.assertEqual(result["cache5m"]["skipped"], 1)
                self.assertEqual(self.cache_conditions(result["cache5m"]), [("CACHE_5M", "ATTENTION")])

    def test_many_unexpected_lines_preserve_following_messages_and_sizes(self):
        before, after = self.good_lines()
        bad = list(self.malformed_lines().values())
        project = self.transcript("mixed", bad + [before] + bad + [after] + bad)
        result = self.sizes_result(project)
        self.assertEqual(self.counts(result["cache5m"]), {"m5": 5_000_000, "h1": 1_000_000})
        self.assertEqual(result["cache5m"]["skipped"], 3 * len(bad))
        self.assertEqual(self.cache_conditions(result["cache5m"]), [("CACHE_5M", "ATTENTION")])

    def test_recursive_decoder_failure_skips_deep_line_and_preserves_sizes(self):
        before, after = self.good_lines()
        bad = self.malformed_lines()["deep-nesting"]
        project = self.transcript("recursive-decoder", [before, bad, after])
        # Python 3.14's C decoder can accept this depth. Exercise the stdlib recursive
        # backend too, so recovery from RecursionError is checked on every interpreter.
        with patch.object(json.scanner, "make_scanner", json.scanner.py_make_scanner):
            with self.assertRaises(RecursionError):
                json.JSONDecoder().decode(bad)
            result = self.sizes_result(project)
        self.assertEqual(self.counts(result["cache5m"]), {"m5": 5_000_000, "h1": 1_000_000})
        self.assertEqual(result["cache5m"]["skipped"], 1)
        self.assertEqual(self.cache_conditions(result["cache5m"]), [("CACHE_5M", "ATTENTION")])

    def test_old_and_duplicate_transcript_messages_do_not_inflate_recent_counts(self):
        recent = json.dumps(self.record("recent", 3_000_000, 1_000_000))
        # One second beyond the existing one-hour transcript window, in a freshly modified file.
        old = json.dumps(self.record("old", 90_000_000, 90_000_000, age=3601))
        project = self.transcript("window", [old, recent, recent])
        cache = ad_deliver_claude.cache_5m(project, NOW)
        self.assertEqual(self.counts(cache), {"m5": 3_000_000, "h1": 1_000_000})
        self.assertEqual(cache["skipped"], 2)
        self.assertEqual(self.cache_conditions(cache), [("CACHE_5M", "ATTENTION")])


if __name__ == "__main__":
    unittest.main()
