# SPDX-License-Identifier: Apache-2.0
"""Owner-approved cleanup size warning and profile worktree keep patterns; fixtures only."""
import json
import os
import shlex
import subprocess
import time
import unittest
from unittest.mock import patch

import mmtest
from mmtest import TempData, base_settings, mmcore
from test_deletes import make
import mmalerts
import mmdelete
import mminstall
import mmschema


class CleanupAttention(unittest.TestCase):
    def condition(self, size, limit=10, disk=100, path="/work/done", names=None):
        snap = {"disk_gb": disk, "cleanup": {
            "count": 1, "bytes": size, "top": [{"rule": "R1", "path": path, "bytes": size}]}}
        settings = base_settings(**{"deletes.cleanup_attention_gb": limit})
        return next(c for c in mmalerts.evaluate(snap, settings, 1_800_000_000, names=names)
                    if c["name"] == "CLEANUP_LIST")

    def old_text(self, size, path="/work/done"):
        size_text = "?" if size is None else "%.1f GB" % (size / 1e9)
        return "1 delete candidates for the recipient, %s; largest: R1 %s (%s)" % (size_text, path, size_text)

    def test_size_boundary_uses_decimal_gb_and_preserves_alert_fields(self):
        for size, level, suffix in ((10_000_000_000 - 1, "INFO", ""),
                                    (10_000_000_000, "ATTENTION", "; list over 10 GB"),
                                    (10_000_000_000 + 1, "ATTENTION", "; list over 10 GB")):
            with self.subTest(size=size):
                c = self.condition(size)
                self.assertEqual(c, {"key": "CLEANUP_LIST", "name": "CLEANUP_LIST", "level": level,
                                     "text": self.old_text(size) + suffix, "value": size / 1e9, "band": 10,
                                     "worse": "up", "command": "mm cleanup", "investigate": None})

    def test_zero_disables_size_warning_for_a_huge_list(self):
        c = self.condition(100_000e9, limit=0)
        self.assertEqual((c["level"], c["text"]), ("INFO", self.old_text(100_000e9)))

    def test_unknown_size_counts_as_zero(self):
        c = self.condition(None, limit=0.1)
        self.assertEqual((c["level"], c["value"], c["text"]), ("INFO", 0, self.old_text(None)))

    def test_low_disk_alone_preserves_old_text(self):
        disk = base_settings()["disk.cache_action_disk_gb"] - 1
        for size, limit in ((1e9, 10), (100_000e9, 0), (None, 10)):
            with self.subTest(size=size, limit=limit):
                c = self.condition(size, limit=limit, disk=disk)
                self.assertEqual((c["level"], c["text"]), ("ATTENTION", self.old_text(size)))

    def test_both_reasons_preserve_old_text(self):
        c = self.condition(11e9, disk=base_settings()["disk.cache_action_disk_gb"] - 1)
        self.assertEqual((c["level"], c["text"]), ("ATTENTION", self.old_text(11e9)))

    def test_disk_boundary_is_not_low_disk(self):
        disk = base_settings()["disk.cache_action_disk_gb"]
        c = self.condition(1e9, disk=disk)
        self.assertEqual((c["level"], c["text"]), ("INFO", self.old_text(1e9)))
        self.assertTrue(self.condition(10e9, disk=disk)["text"].endswith("; list over 10 GB"))

    def test_size_warning_with_unknown_disk_and_fractional_setting(self):
        c = self.condition(2.5e9, limit=2.5, disk=None)
        self.assertEqual((c["level"], c["text"]),
                         ("ATTENTION", self.old_text(2.5e9) + "; list over 2.5 GB"))

    def test_profile_command_is_preserved(self):
        command = "/opt/example/bin/cleanup --list"
        self.assertEqual(self.condition(10e9, names={"disk_command": command})["command"], command)

    def test_saved_settings_without_the_new_key_use_the_default(self):
        settings = mmtest.restored_without("deletes.cleanup_attention_gb")
        self.assertEqual(settings["deletes.cleanup_attention_gb"], 10)
        snap = {"disk_gb": 100, "cleanup": {"count": 1, "bytes": 10e9}}
        c = next(c for c in mmalerts.evaluate(snap, settings, 1_800_000_000) if c["name"] == "CLEANUP_LIST")
        self.assertEqual(c["level"], "ATTENTION")
        self.assertTrue(c["text"].endswith("; list over 10 GB"))

    def test_long_paths_and_commands_keep_the_alert_line_within_200_characters(self):
        for size, disk in ((1e9, 100), (10e9, 100), (10e9, 1)):
            with self.subTest(size=size, disk=disk):
                c = self.condition(size, disk=disk, path="/work/" + "long-folder/" * 50,
                                   names={"disk_command": "/opt/example/" + "long-folder/" * 50 + "cleanup"})
                line = mmcore.alert_line(c)
                self.assertLessEqual(len(line), 200)
                self.assertNotIn("\n", line)
                self.assertIn(" | do: mm explain CLEANUP_LIST", line)

    def test_no_candidates_means_no_cleanup_alert(self):
        settings = base_settings(**{"deletes.cleanup_attention_gb": 1})
        for cleanup in (None, {"count": 0, "bytes": 100e9}):
            with self.subTest(cleanup=cleanup):
                self.assertFalse(any(c["name"] == "CLEANUP_LIST" for c in mmalerts.evaluate(
                    {"disk_gb": 1, "cleanup": cleanup}, settings, 1_800_000_000)))


class CleanupSetting(TempData):
    def test_default_and_schema_agree(self):
        key = "deletes.cleanup_attention_gb"
        self.assertEqual(mmcore.defaults()[key], 10)
        schema = mmschema.load("settings")
        self.assertEqual(schema, mmcore.settings_json_schema())
        self.assertEqual(schema["properties"][key], {"type": "number", "minimum": 0, "maximum": 10000})

    def test_boundary_settings_are_accepted(self):
        for limit in (0, 10000):
            with self.subTest(limit=limit):
                self.write_settings(**{"deletes.cleanup_attention_gb": limit})
                settings = mmcore.Settings()
                self.assertEqual(settings.load()["deletes.cleanup_attention_gb"], limit)
                self.assertFalse(settings.problem)

    def test_out_of_range_settings_are_refused(self):
        for limit in (-1, 10001):
            with self.subTest(limit=limit):
                self.write_settings(**{"deletes.cleanup_attention_gb": limit})
                settings = mmcore.Settings()
                settings.load()
                self.assertIn("deletes.cleanup_attention_gb", settings.problem)


class WorktreeKeep(TempData):
    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.root, "repo")
        self.trees = os.path.join(self.root, "trees")
        self.git("init", "-q", "-b", "main", self.repo, cwd=self.root)
        with open(os.path.join(self.repo, ".gitignore"), "w") as f:
            f.write("cache/\n")
        self.git("add", ".gitignore")
        self.git("commit", "-q", "-m", "fixture")
        self.done = os.path.join(self.trees, "journal-done")
        self.other = os.path.join(self.trees, "other-done")
        for path in (self.done, self.other):
            self.git("worktree", "add", "-q", "-b", os.path.basename(path), path)
            make(os.path.join(path, "cache"))
            self.assertEqual(self.git("status", "--porcelain", cwd=path), "")
            self.git("merge-base", "--is-ancestor", "HEAD", "main", cwd=path)
        self.rule = {"id": "R1", "type": "git_worktrees", "repo": self.repo, "roots": [self.trees],
                     "merged_into": "main", "inner_caches": ["cache"], "inner_id": "R2"}

    def git(self, *args, cwd=None):
        result = subprocess.run(["/usr/bin/git", "-C", cwd or self.repo] + list(args),
                                capture_output=True, text=True, timeout=60,
                                env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                                         GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com"))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def items(self, **over):
        rule = dict(self.rule, **over)
        ctx = mmdelete.Ctx({"cleanup": [rule]}, extra={"user_tmp": self.root}, data=self.data)
        return mmdelete.cleanup_list(ctx, time.time(), sizes=False)

    def test_matching_tree_is_kept_and_inner_cache_is_not_listed(self):
        items = self.items(keep=["journal-*"])
        kept = [i for i in items if i["path"] == self.done]
        self.assertEqual(kept, [{"rule": "R1", "path": self.done, "verb": "KEEP",
                                 "why": "kept by the profile (keep: journal-*)", "bytes": None, "command": None}])
        self.assertFalse(any(i["path"].startswith(self.done + os.sep) for i in items))
        self.assertTrue(os.path.isfile(os.path.join(self.done, "cache", "a.o")))

    def test_nonmatching_tree_and_cache_are_still_candidates(self):
        items = self.items(keep=["journal-*"])
        other = next(i for i in items if i["path"] == self.other)
        self.assertEqual(other["why"], "merged into main and clean")
        self.assertEqual(shlex.split(other["command"]), ["git", "-C", self.repo, "worktree", "remove", self.other])
        self.assertTrue(any(i["path"] == os.path.join(self.other, "cache") and i["command"] for i in items))

    def test_several_patterns_match_case_sensitively_on_basename(self):
        for patterns in (["absent-*", "journal-?one"], ["*/journal-*", "JOURNAL-*", "journal-[d]one"]):
            with self.subTest(patterns=patterns):
                kept = next(i for i in self.items(keep=patterns) if i["path"] == self.done)
                self.assertEqual(kept["verb"], "KEEP")
                self.assertEqual(kept["why"], "kept by the profile (keep: %s)" % patterns[-1])
        baseline = self.items()
        self.assertEqual(self.items(keep=["JOURNAL-*", "*/journal-*"]), baseline)

    def test_empty_keep_is_identical_to_absent_keep(self):
        self.assertEqual(self.items(keep=[]), self.items())

    def test_first_matching_pattern_names_the_reason(self):
        kept = next(i for i in self.items(keep=["journal-*", "*-done"]) if i["path"] == self.done)
        self.assertEqual(kept["why"], "kept by the profile (keep: journal-*)")


class KeepProfileValidation(TempData):
    def test_keep_patterns_accept_lists_and_refuse_bad_fields_as_profile_errors(self):
        for value, valid in (([], True), (["journal-*", "other-?"], True), ("journal-*", False),
                             ([""], False), ([42], False), (42, False)):
            with self.subTest(value=value):
                raw = {"name": "fixture", "deletes": {"cleanup": [
                    {"id": "R1", "type": "git_worktrees", "repo": "/repo", "roots": ["/trees"],
                     "merged_into": "main", "keep": value}]}}
                problems = mmschema.validate(raw, mmschema.load("profile"))
                if valid:
                    self.assertEqual(problems, [])
                else:
                    self.assertTrue(problems, value)
                    self.assertTrue(all("$.deletes.cleanup[0]" in p for p in problems), problems)
                path = os.path.join(self.root, "profile.toml")
                with open(path, "w") as f:
                    f.write('name = "fixture"\n[[deletes.cleanup]]\nid = "R1"\ntype = "git_worktrees"\n'
                            'repo = "/repo"\nroots = ["/trees"]\nmerged_into = "main"\nkeep = %s\n'
                            % json.dumps(value))
                if valid:
                    self.assertEqual(mmcore.load_profile(path)["deletes"]["cleanup"][0]["keep"], value)
                with patch.object(mminstall.mmread, "check_readings", return_value=([], {}, {})):
                    errors = [line for line in mminstall.check(path) if line.startswith("E_PROFILE ")]
                if valid:
                    self.assertEqual(errors, [])
                else:
                    self.assertTrue(errors, value)
                    self.assertTrue(all("$.deletes.cleanup[0]" in line for line in errors), errors)

    def test_other_rule_types_keep_their_existing_extra_fields(self):
        for rule_type in ("git_branches", "stale_children", "paths"):
            with self.subTest(rule_type=rule_type):
                raw = {"name": "fixture", "deletes": {"cleanup": [
                    {"id": "R1", "type": rule_type, "keep": "unrelated extra field"}]}}
                self.assertEqual(mmschema.validate(raw, mmschema.load("profile")), [])


if __name__ == "__main__":
    unittest.main()
