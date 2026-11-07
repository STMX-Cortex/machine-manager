# SPDX-License-Identifier: Apache-2.0
"""Slot ceiling, review round 1 (written from the coordinator's review items, not from the code).

1. A malformed pin record is NO pin: the ceiling rule applies (13 -> 10 with ceiling 10), the tick does not crash
   (slot_decide and the supervisor's slot path), and a problem "slot pin invalid: <reason>" is shown. A valid pin
   above the ceiling is still kept.
2. tests/gen_vectors.py --function F --case GOOD --case UNKNOWN stops with E_CASE and changes no file.
Synthetic inputs, temporary folders and a copy of the code tree only; the real vectors/ is never written."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import mmtest
from mmtest import mmcore, mmread
import mmdecide
from slot_trial_helpers import NOW
import test_slot_ceiling as sc
from test_slot_ceiling import why, inp, settings, calm_state
from test_recovery import Base as RecoveryBase

PIN_PROBLEM = "slot pin invalid: "  # the prefix; done2 pins the reason texts

# Malformed records as slot_decide receives them (the supervisor passes the parsed override.json as it is).
BAD_PINS = (
    ("no slots", {"until": NOW + 600, "reason": "r"}),
    ("until a string", {"slots": 13, "until": "soon", "reason": "r"}),
    ("until true", {"slots": 13, "until": True, "reason": "r"}),
    ("until infinity", {"slots": 13, "until": float("inf"), "reason": "r"}),
    ("until nan", {"slots": 13, "until": float("nan"), "reason": "r"}),
    ("slots a string", {"slots": "13", "until": NOW + 600, "reason": "r"}),
    ("slots true", {"slots": True, "until": NOW + 600, "reason": "r"}),
    ("slots null", {"slots": None, "until": NOW + 600, "reason": "r"}),
    ("no until", {"slots": 13, "reason": "r"}),
    ("a list", []),
    ("a string", "x"),
    ("a number", 13),
)

# The same as override.json text (Infinity and NaN: Python's JSON reader accepts them).
BAD_FILES = (
    ("no slots", '{"until": %r, "reason": "r"}' % (NOW + 600)),
    ("until a string", '{"slots": 13, "until": "soon", "reason": "r"}'),
    ("until true", '{"slots": 13, "until": true, "reason": "r"}'),
    ("until infinity", '{"slots": 13, "until": Infinity, "reason": "r"}'),
    ("slots a string", '{"slots": "13", "until": %r, "reason": "r"}' % (NOW + 600)),
    ("slots true", '{"slots": true, "until": %r, "reason": "r"}' % (NOW + 600)),
    ("a list", "[]"),
    ("a string", '"x"'),
)


class MalformedPin(unittest.TestCase):
    def decide(self, override, mac_state="GREEN"):
        return mmdecide.slot_decide(calm_state(), inp(mac_state=mac_state, override=override), settings())

    def test_a_malformed_pin_is_no_pin_and_the_ceiling_applies(self):
        for name, override in BAD_PINS:
            for mac_state in ("GREEN", "STEADY", "AMBER"):
                with self.subTest(name, mac_state=mac_state):
                    r = self.decide(override, mac_state)
                    self.assertEqual((r["slots"], r["why"]), (10, why(13)))

    def test_a_malformed_pin_is_shown_as_a_problem(self):
        for name, override in BAD_PINS:
            with self.subTest(name):
                r = self.decide(override)
                self.assertTrue(r["problem"] and PIN_PROBLEM in r["problem"], r["problem"])

    def test_red_with_a_malformed_pin_goes_to_the_floor(self):
        for name, override in BAD_PINS:
            with self.subTest(name):
                self.assertEqual(self.decide(override, "RED")["slots"], 3)

    def test_a_malformed_pin_below_the_ceiling_sets_nothing(self):
        """slots true would be int(True) == 1 and "13" a pin of 13: a malformed pin never sets a count."""
        for name, override in BAD_PINS:
            with self.subTest(name):
                r = mmdecide.slot_decide(calm_state(), inp(slots=5, mac_state="STEADY", override=override), settings())
                self.assertIsNone(r["slots"], r["why"])

    def test_no_pin_and_an_ended_pin_are_no_problem(self):
        for override in (None, {"slots": 13, "until": NOW - 1, "reason": "old"}):
            with self.subTest(override=override):
                r = self.decide(override)
                self.assertEqual((r["slots"], r["problem"]), (10, None))

    def test_a_valid_pin_is_still_kept(self):
        for override in ({"slots": 13, "until": NOW + 600, "reason": "trial"},
                         {"slots": 13, "until": NOW + 600.5, "reason": "trial"},
                         {"slots": 13, "until": int(NOW) + 600}):
            with self.subTest(override=override):
                r = self.decide(override)
                self.assertEqual((r["slots"], r["problem"]), (None, None))


class SupervisorMalformedPin(RecoveryBase):
    """test_slot_ceiling.Supervisor's fixture (slots 13, ceiling 10, act mode on a test file), its helpers reused."""
    build, decisions, ticks = sc.Supervisor.build, sc.Supervisor.decisions, sc.Supervisor.ticks
    count = staticmethod(sc.Supervisor.count)

    def setUp(self):
        super().setUp()
        real = mmread.disk_free_gb
        mmread.disk_free_gb = lambda *a, **k: 200.0
        self.addCleanup(setattr, mmread, "disk_free_gb", real)

    def shown(self):
        """Every place a problem can be shown: alerts, the decisions log, the recovery log."""
        texts = [json.dumps(r) for r in self.pushed()]
        for name in ("decisions.log", "recovery.log"):
            try:
                texts.append(open(os.path.join(self.data, "state", name)).read())
            except OSError:
                pass
        return "\n".join(texts)

    def test_a_malformed_override_json_steps_down_without_a_crash(self):
        for name, text in BAD_FILES:
            with self.subTest(name):
                with open(mmcore.path("override.json"), "w") as f:
                    f.write(text)
                clock = {"t": NOW}
                sup, f = self.build(clock)
                sup.tick()
                self.assertEqual(self.count(f), 10, self.decisions())
                self.assertIn(PIN_PROBLEM, self.shown())

    def test_a_null_override_json_steps_down_without_a_crash(self):
        with open(mmcore.path("override.json"), "w") as f:
            f.write("null")
        clock = {"t": NOW}
        sup, f = self.build(clock)
        sup.tick()
        self.assertEqual(self.count(f), 10, self.decisions())

    def test_a_valid_override_json_pin_is_still_kept(self):
        mmcore.write_atomic(mmcore.path("override.json"), json.dumps({"slots": 13, "until": NOW + 600, "reason": "t"}))
        clock = {"t": NOW}
        sup, f = self.build(clock)
        self.ticks(sup, clock, 2)
        self.assertEqual(self.count(f), 13, self.decisions())
        self.assertNotIn(PIN_PROBLEM, self.shown())


# ------------------------------------------------------------------------------------------- 2. gen_vectors --case

def tree_sums(root):
    out = {}
    for d, _, files in os.walk(root):
        for n in files:
            p = os.path.join(d, n)
            with open(p, "rb") as f:
                out[os.path.relpath(p, root)] = hashlib.sha256(f.read()).hexdigest()
    return out


class GenVectorsCase(unittest.TestCase):
    """gen_vectors.py writes into the vectors/ next to its own tests/: it runs from a copy of the code tree."""
    GOOD = "green-above-ceiling"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=os.environ.get("MM_TEST_TMP"))
        self.addCleanup(tmp.cleanup)
        self.copy = os.path.join(tmp.name, "code")
        ignore = shutil.ignore_patterns("results", "__pycache__", ".git")
        for d in ("core", "adapters", "bin", "tests", "vectors", "schemas", "profiles"):
            src = os.path.join(mmtest.CODE, d)
            if os.path.isdir(src):
                shutil.copytree(src, os.path.join(self.copy, d), ignore=ignore)
        for n in ("settings.default.toml",):
            shutil.copy(os.path.join(mmtest.CODE, n), self.copy)
        self.vec = os.path.join(self.copy, "vectors")
        self.home = os.path.join(tmp.name, "home")
        os.makedirs(self.home)

    def gen(self, *args):
        env = dict(os.environ, HOME=self.home, MM_DATA=os.path.join(self.home, "data"))
        return subprocess.run([sys.executable, "-I", os.path.join(self.copy, "tests", "gen_vectors.py")] + list(args),
                              capture_output=True, text=True, timeout=120, env=env, cwd=self.copy)

    def good_path(self):
        return os.path.join(self.vec, "slot_decide", self.GOOD + ".json")

    def test_an_unknown_case_is_e_case_and_changes_no_file(self):
        # the good case's file is changed in the copy first: a write of it before the check would show
        with open(self.good_path(), "a") as f:
            f.write(" ")
        before = tree_sums(self.vec)
        r = self.gen("--function", "slot_decide", "--case", self.GOOD, "--case", "no-such-case")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("E_CASE", r.stderr + r.stdout)
        self.assertIn("no-such-case", r.stderr + r.stdout)
        self.assertEqual(tree_sums(self.vec), before, "no file in the copy changes")

    def test_only_unknown_cases_is_e_case_too(self):
        before = tree_sums(self.vec)
        r = self.gen("--function", "slot_decide", "--case", "no-such-case")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("E_CASE", r.stderr + r.stdout)
        self.assertEqual(tree_sums(self.vec), before)

    def test_a_good_case_writes_only_that_file_with_the_committed_content(self):
        committed = open(os.path.join(mmtest.CODE, "vectors", "slot_decide", self.GOOD + ".json"), "rb").read()
        os.remove(self.good_path())
        before = tree_sums(self.vec)
        r = self.gen("--function", "slot_decide", "--case", self.GOOD)
        self.assertEqual(r.returncode, 0, r.stderr)
        after = tree_sums(self.vec)
        self.assertEqual(set(after) - set(before), {os.path.join("slot_decide", self.GOOD + ".json")})
        self.assertEqual({k: v for k, v in after.items() if k in before}, before, "no other file changes")
        self.assertEqual(open(self.good_path(), "rb").read(), committed)

    def test_case_needs_function(self):
        before = tree_sums(self.vec)
        r = self.gen("--case", self.GOOD)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(tree_sums(self.vec), before)


del RecoveryBase

if __name__ == "__main__":
    unittest.main()
