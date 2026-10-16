# SPDX-License-Identifier: Apache-2.0
"""Sandbox holds, C-22a: a cut never opens a gate.

C-22 cuts each line of agent text to the profile's text_line_max characters (default 4096, from 256 to 1048576)
before a pattern sees it. C-22a: where a pattern decides a refusal or a guard, a line longer than text_line_max counts
as a match, so the gate fails closed for it (README, "Agent-written files", item 7):
- the hook's launch gate (`delivery.launch_bash_regex`): while the machine is RED, a Bash command with a line too long
  to see whole is refused like a launch. With no launch_bash_regex in the profile there is no Bash gate, and a long
  command passes;
- `live_tools.path_regexes` (`mmread.live_named`, the guard that makes a delete or a trim wait): a process name too
  long to see whole counts as a live run. With no path_regexes, the names and suffixes alone decide.
Patterns that only show, sort or mask text use the cut line and do not fail closed (the control here: the queue's
kind patterns).
A line is a record split at line feeds only (C-22b): a LINE SEPARATOR inside a long line does not make it short.

Run from the repository root:
    python3 -I tests/run_tests.py sandbox_holds_c22a

Every fixture lives in the test's own temporary folder."""
import json
import os
import subprocess
import time
import unittest

import mmtest
from mmtest import MM, mmcore, mmread
import ad_deliver_claude
import ad_queue_fifo
import mmdelete
import mmtext

DEFAULT_MAX = 4096  # C-22's default text_line_max (the test profile does not set it)
SESSION = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
LAUNCH_TAIL = "; claude -p hi"  # a launch by the test profile's launch_bash_regex


def plain(n):
    """A Bash command of exactly n characters that launches nothing."""
    return "echo " + "x" * (n - 5)


def launch_at_end(n):
    """A Bash command of exactly n characters whose launch is its last text."""
    return "echo " + "x" * (n - 5 - len(LAUNCH_TAIL)) + LAUNCH_TAIL


def proc(comm, pid=4242):
    return {"pid": pid, "ppid": 1, "rss_mb": 1.0, "cpu": 0.0, "comm": comm}


def name_of(n, tail="/tool"):
    """A process name of exactly n characters that ends with tail."""
    return "/opt/" + "a" * (n - 5 - len(tail)) + tail


class LimitKept(mmtest.TempData):
    """Each test may load a profile with its own text_line_max; the limit in force is put back afterwards, so other
    tests in this process see what they saw before."""

    def setUp(self):
        super().setUp()
        self._limit = mmtext.TEXT_LINE_MAX
        self.addCleanup(setattr, mmtext, "TEXT_LINE_MAX", self._limit)

    def write_profile(self, text_line_max=None, launch_pattern=True):
        """A copy of the test profile, with text_line_max set and launch_bash_regex kept or removed; MM_PROFILE points
        to it (TempData puts MM_PROFILE back)."""
        with open(mmtest.PROFILE) as f:
            lines = f.read().split("\n")
        out = []
        for line in lines:
            if not launch_pattern and line.startswith("launch_bash_regex"):
                continue
            out.append(line)
            if line.startswith("machine_id") and text_line_max is not None:
                out.append("text_line_max = %s" % text_line_max)  # a top-level key: before the first table
        p = os.path.join(self.root, "profile-c22a.toml")
        with open(p, "w") as f:
            f.write("\n".join(out))
        os.environ["MM_PROFILE"] = p
        return p


class HookGate(LimitKept):
    """The hook itself (`mm hook --event PreToolUse`), for the recipient's session, while the machine is fresh RED."""

    def setUp(self):
        super().setUp()
        with open(os.path.join(self.data, "recipient.md"), "w") as f:
            f.write("# agent state\n\nSession: %s\n" % SESSION)
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps(
            {"time": now, "state": "RED", "reasons": ["test"], "red_since": now - 10}))
        self.write_settings(**{"launch_gate.enabled": True, "mode.observe": False})  # observe mode only logs

    def pre(self, cmd, tool="Bash"):
        """The hook's decision on one call: "deny" or None (allowed)."""
        data = {"session_id": SESSION, "tool_name": tool, "tool_input": {"command": cmd},
                "hook_event_name": "PreToolUse"}
        r = subprocess.run(MM + ["hook", "--event", "PreToolUse"], input=json.dumps(data).encode(),
                           capture_output=True, timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        if not r.stdout.strip():
            return None
        out = json.loads(r.stdout)["hookSpecificOutput"]
        self.assertTrue(out["permissionDecisionReason"].startswith("E_GATE_RED"), out)
        return out["permissionDecision"]


# ------------------------------------------------------------------------------------- the launch gate

class LaunchGateFailsClosedOnACut(HookGate):
    """C-22a: the launch gate (with a launch_bash_regex) refuses a Bash command with a line over text_line_max."""

    def test_the_fixture_reaches_the_gate(self):
        self.assertEqual(self.pre("claude -p hi"), "deny", "a short launch is refused while RED")
        self.assertIsNone(self.pre("ls -la"), "a short plain command passes")

    def test_a_launch_past_the_cut_is_refused(self):
        cmd = "echo " + "x" * DEFAULT_MAX + LAUNCH_TAIL
        self.assertGreater(cmd.index("claude"), DEFAULT_MAX, "the launch text lies past the cut")
        self.assertEqual(self.pre(cmd), "deny", "a launch hidden past the cut opens no gate")

    def test_any_line_over_the_limit_counts_as_a_launch(self):
        self.assertEqual(self.pre(plain(DEFAULT_MAX + 1)), "deny",
                         "one character over text_line_max: the pattern cannot see the line whole")
        self.assertEqual(self.pre(plain(3 * DEFAULT_MAX)), "deny")

    def test_a_long_line_among_short_lines_is_refused(self):
        long_line = plain(DEFAULT_MAX + 50)
        for cmd, where in [("ls\n" + long_line, "the last line"), (long_line + "\nls", "the first line"),
                           ("ls\n" + long_line + "\npwd", "a middle line")]:
            with self.subTest(where=where):
                self.assertEqual(self.pre(cmd), "deny", "the long line is %s of three short ones" % where)

    def test_a_line_separator_does_not_make_a_long_line_short(self):
        # C-22b: records end only at line feeds; U+2028 stays inside its line, so the line is still too long
        half = DEFAULT_MAX // 2 + 10
        cmd = "echo " + "x" * half + " " + "x" * half + LAUNCH_TAIL
        self.assertEqual(self.pre(cmd), "deny")
        cmd = "echo " + "x" * half + " " + "x" * half
        self.assertEqual(self.pre(cmd), "deny", "no launch text at all: the long line still counts as one")

    def test_a_line_of_exactly_the_limit_is_checked_normally(self):
        self.assertEqual(len(plain(DEFAULT_MAX)), DEFAULT_MAX)
        self.assertEqual(len(launch_at_end(DEFAULT_MAX)), DEFAULT_MAX)
        self.assertIsNone(self.pre(plain(DEFAULT_MAX)), "a plain command of exactly text_line_max characters passes")
        self.assertEqual(self.pre(launch_at_end(DEFAULT_MAX)), "deny",
                         "a launch at the end of a line of exactly text_line_max characters is seen and refused")
        self.assertIsNone(self.pre("ls\n" + plain(DEFAULT_MAX) + "\npwd"), "lines at the limit stay plain commands")

    def test_other_tools_are_not_bash_commands(self):
        self.assertIsNone(self.pre(plain(DEFAULT_MAX + 100), tool="Read"),
                          "only a Bash command is matched against launch_bash_regex")


class LaunchGateWithoutAPattern(HookGate):
    """The coder's account (ecf52d7): with no launch_bash_regex there is no Bash gate, so a long command still passes;
    the launch tools stay gated."""

    def setUp(self):
        super().setUp()
        self.write_profile(launch_pattern=False)
        self.assertNotIn("launch_bash_regex", mmcore.load_profile()["delivery"], "the fixture has no pattern")

    def test_a_long_command_passes(self):
        self.assertEqual(self.pre("x", tool="Agent"), "deny", "the gate is on: a launch tool is refused while RED")
        self.assertIsNone(self.pre(plain(DEFAULT_MAX + 1)))
        self.assertIsNone(self.pre("echo " + "x" * DEFAULT_MAX + LAUNCH_TAIL))
        self.assertIsNone(self.pre("claude -p hi"), "no pattern: no Bash command is a launch")


class GateDecisionDirect(LimitKept):
    """The same rule at `gate_decision`, the function the hook calls (no process start: many sizes are cheap)."""

    def setUp(self):
        super().setUp()
        self.now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps(
            {"time": self.now, "state": "RED", "reasons": ["test"], "red_since": self.now - 10}))
        self.s = dict(mmcore.Settings().load(), **{"launch_gate.enabled": True})
        self.cfg = mmcore.load_profile()["delivery"]

    def refused(self, cmd, cfg=None):
        return ad_deliver_claude.gate_decision({"tool_name": "Bash", "tool_input": {"command": cmd}}, self.s,
                                               self.now, self.cfg if cfg is None else cfg) is not None

    def test_every_size_around_the_limit(self):
        for n in (DEFAULT_MAX - 1, DEFAULT_MAX):
            with self.subTest(n=n):
                self.assertFalse(self.refused(plain(n)), "a plain line of %d characters passes" % n)
                self.assertTrue(self.refused(launch_at_end(n)), "a launch at the end of %d characters is seen" % n)
        for n in (DEFAULT_MAX + 1, DEFAULT_MAX + 2, DEFAULT_MAX + len(mmtext.CUT_MARK), 2 * DEFAULT_MAX):
            with self.subTest(n=n):
                self.assertTrue(self.refused(plain(n)), "a line of %d characters is too long to see whole" % n)
                self.assertTrue(self.refused(launch_at_end(n)))

    def test_no_pattern_no_bash_gate(self):
        cfg = {k: v for k, v in self.cfg.items() if k != "launch_bash_regex"}
        self.assertFalse(self.refused(plain(DEFAULT_MAX + 1), cfg))
        self.assertFalse(self.refused(plain(DEFAULT_MAX + 1), dict(cfg, launch_bash_regex="")),
                         "an empty pattern is no pattern")


# ------------------------------------------------------------------------------------- live_tools.path_regexes

class LiveToolGuardFailsClosedOnACut(LimitKept):
    """C-22a: `live_named` (the guard that makes deletes and trims wait) counts a process name over text_line_max as
    live where the profile has path_regexes; the test profile's live_tools: names go, testshard, test2json; suffix
    .test; path_regexes ["/go-build[0-9]+/"]."""

    def setUp(self):
        super().setUp()
        self.spec = mmcore.load_profile()["live_tools"]
        self.assertEqual(self.spec["path_regexes"], ["/go-build[0-9]+/"], "the fixture's pattern")

    def live(self, comm, spec=None):
        return bool(mmread.live_named([proc(comm)], self.spec if spec is None else spec))

    def test_the_fixture_reaches_each_rule(self):
        self.assertTrue(self.live("/tmp/go-build123/b001/exe/tool"), "a path_regexes match alone is live")
        self.assertTrue(self.live("/opt/pkg.test"), "a suffix alone is live")
        self.assertTrue(self.live("/usr/local/bin/go"), "a name alone is live")
        self.assertFalse(self.live("/usr/bin/tool"), "a plain short name is not live")
        two = dict(self.spec, path_regexes=["/go-build[0-9]+/", "^never-matches$"])
        self.assertTrue(self.live("/tmp/go-build1/x", two), "one matching pattern of several is enough")

    def test_a_match_past_the_cut_counts_as_live(self):
        comm = "/opt/" + "a" * DEFAULT_MAX + "/go-build7/b001/exe/tool"
        self.assertGreater(comm.index("go-build"), DEFAULT_MAX)
        self.assertTrue(self.live(comm))

    def test_any_name_over_the_limit_counts_as_live(self):
        self.assertTrue(self.live(name_of(DEFAULT_MAX + 1)), "one character over text_line_max")
        self.assertTrue(self.live(name_of(3 * DEFAULT_MAX)))
        half = DEFAULT_MAX // 2 + 10
        self.assertTrue(self.live("/opt/" + "a" * half + " " + "a" * half + "/tool"),
                        "a LINE SEPARATOR inside a name does not make it short (C-22b)")

    def test_a_name_of_exactly_the_limit_is_checked_normally(self):
        self.assertEqual(len(name_of(DEFAULT_MAX)), DEFAULT_MAX)
        self.assertFalse(self.live(name_of(DEFAULT_MAX)), "a plain name of exactly text_line_max is not live")
        self.assertTrue(self.live(name_of(DEFAULT_MAX, "/go-build9/b/tool")), "a match at its end is seen")
        self.assertFalse(self.live(name_of(DEFAULT_MAX - 1)))

    def test_no_path_regexes_names_and_suffixes_decide(self):
        spec = dict(self.spec, path_regexes=[])
        self.assertFalse(self.live(name_of(DEFAULT_MAX + 1), spec), "no pattern: no cut rule")
        self.assertTrue(self.live(name_of(DEFAULT_MAX + 1, "/go"), spec), "the name still decides")
        self.assertTrue(self.live(name_of(DEFAULT_MAX + 1, "/x.test"), spec), "the suffix still decides")

    def test_only_the_long_process_is_live(self):
        procs = [proc("/usr/bin/tool", 1), proc(name_of(DEFAULT_MAX + 1), 2), proc("/usr/bin/other", 3)]
        self.assertEqual([p["pid"] for p in mmread.live_named(procs, self.spec)], [2])


class DeleteGuardWaitsForALongName(LimitKept):
    """The guard's caller: a delete rule with no_live_tools keeps its folder while a process too long to see whole
    runs (the profile's live_tools, through `mmdelete.Run`'s process seam)."""

    def delete_pass(self, comm):
        cache = os.path.join(self.root, "t", "cache")
        os.makedirs(os.path.join(cache, "0a"), exist_ok=True)
        with open(os.path.join(cache, "README"), "w") as f:
            f.write("This directory holds cached Go build artifacts.\n")
        old = time.time() - 30 * 86400
        with open(os.path.join(cache, "0a", "old-a"), "w") as f:
            f.write("x" * 4096)
        for p in (os.path.join(cache, "0a", "old-a"), os.path.join(cache, "0a"), cache):
            os.utime(p, (old, old))
        rule = {"id": "S5", "type": "cache_entries", "cache": cache, "marker_file": "README", "marker_text": "Go build",
                "age_minutes": 2880, "no_live_tools": True}
        ctx = mmdelete.Ctx({"rules": [rule], "cleanup": [], "forbidden_parts": [".ssh"], "protected_roots": []},
                           extra={"t": os.path.join(self.root, "t")}, data=self.data)
        r = mmdelete.Run(mmtest.base_settings(**{"deletes.lsof_timeout_s": 60}), ctx, enabled=False,
                         procs=lambda: [proc(comm)], live_spec=mmcore.load_profile()["live_tools"], mid="m1")
        r.all()
        return r

    def test_a_long_name_keeps_the_folder(self):
        r = self.delete_pass(name_of(DEFAULT_MAX + 1))
        self.assertEqual(len(r.lines), 1, r.lines)
        self.assertEqual(r.lines[0].split(" ")[2], "KEEP", r.lines[0][:300])
        self.assertIn("live_tools", r.lines[0])

    def test_control_a_plain_name_lets_the_rule_go_on(self):
        r = self.delete_pass("/usr/bin/tool")
        self.assertTrue(r.lines, "the rule ran")
        self.assertNotIn("guard=live_tools", "\n".join(r.lines))


# ------------------------------------------------------------------------------------- patterns that only sort

class SortPatternsUseTheCutLine(LimitKept):
    """Control: a pattern that only sorts (the queue's kind patterns over a history or queue command) uses the cut
    line and does not count a long line as a match."""

    def test_kind_patterns_see_only_the_cut_start(self):
        q = ad_queue_fifo.Queue({"dir": self.root, "kind_patterns": [["pytest", "py-suite"]]})
        self.assertEqual(q.kind_of("pytest -q"), "py-suite", "the fixture reaches the pattern")
        self.assertEqual(q.kind_of("pytest " + "x" * (2 * DEFAULT_MAX)), "py-suite", "a match in the cut start counts")
        self.assertEqual(q.kind_of("x" * (2 * DEFAULT_MAX) + " pytest"), "other", "a match past the cut is not seen")
        self.assertEqual(q.kind_of("x" * (2 * DEFAULT_MAX)), "other", "a long line is no match by itself")


# ------------------------------------------------------------------------------------- text_line_max from a profile

class ProfileSetsTheLimit(HookGate):
    """A profile's text_line_max (256 to 1048576) is the limit these gates use; a value outside is refused."""

    def test_a_small_limit_from_the_profile(self):
        self.write_profile(text_line_max=300)
        spec = mmcore.load_profile()["live_tools"]
        self.assertTrue(mmread.live_named([proc(name_of(301))], spec), "301 characters: over the profile's 300")
        self.assertFalse(mmread.live_named([proc(name_of(300))], spec), "300 characters: at the profile's limit")
        self.assertEqual(self.pre(plain(301)), "deny", "the hook uses the profile's limit")
        self.assertIsNone(self.pre(plain(300)))
        self.assertEqual(self.pre(launch_at_end(300)), "deny")

    def test_a_large_limit_from_the_profile(self):
        self.write_profile(text_line_max=1 << 20)
        spec = mmcore.load_profile()["live_tools"]
        self.assertFalse(mmread.live_named([proc(name_of(3 * DEFAULT_MAX))], spec), "under the profile's limit")
        self.assertTrue(mmread.live_named([proc(name_of(3 * DEFAULT_MAX, "/go-build1/x"))], spec),
                        "a match far past the default limit is seen whole")
        self.assertIsNone(self.pre(plain(3 * DEFAULT_MAX)), "the hook uses the profile's limit")
        self.assertEqual(self.pre("echo " + "x" * (3 * DEFAULT_MAX) + LAUNCH_TAIL), "deny")

    def test_the_range_ends_are_accepted(self):
        for n in (256, 1 << 20):
            with self.subTest(text_line_max=n):
                self.write_profile(text_line_max=n)
                spec = mmcore.load_profile()["live_tools"]
                self.assertTrue(mmread.live_named([proc(name_of(n + 1))], spec))
                self.assertFalse(mmread.live_named([proc(name_of(n))], spec))

    def test_a_value_outside_the_range_is_refused(self):
        for value in ("255", "1048577", "0", "-4096", "true", '"4096"', "4096.0", "[4096]"):
            with self.subTest(text_line_max=value):
                self.write_profile(text_line_max=value)
                with self.assertRaises(mmcore.MMError) as e:
                    mmcore.load_profile()
                self.assertEqual(e.exception.code, "E_PROFILE")
                self.assertIn("text_line_max", str(e.exception))


if __name__ == "__main__":
    unittest.main()
