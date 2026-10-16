# SPDX-License-Identifier: Apache-2.0
"""Sandbox holds, C-22 and C-23: patterns over agent text run on bounded lines; every file shows agent text cleaned.

C-22 (the root rule for the class of C-14 and C-21): every regular expression machine-manager runs over text an agent
can make (mask's patterns, the log and kernel-line parsers, the profile's patterns over labels and commands) runs on
bounded pieces: the text is split at line ends and each line is cut to TEXT_LINE_MAX characters (a profile setting,
default 4096) with a marked cut before any pattern runs. So each pattern's cost per line is bounded and the whole cost
is linear in the text size. These tests time each such place on one long line of the pattern's worst case against
the same length of plain text (at most 5 times as long, plus 1 s), and check the marked cut.

C-23 (the root rule for the C-17 and C-20 class in files): C-20 covers every file machine-manager writes that a person
or a tool reads: its own logs, the evidence bundle's files (each copied agent-writable log cleaned line by line as it
is copied; alert.json, queue.json and the other JSON files with cleaned strings) and any notification text. These
tests give agent values with forged lines (LINE SEPARATOR, NEL, CR, LF, bidi characters, `|`, ` | do: `) and check
that each file holds one record per line, no Cc, Cf, Zl or Zp character other than its line ends, and JSON strings
cleaned.

The tests assume the test profile keeps TEXT_LINE_MAX at its default, 4096.

Run from the repository root:
    python3 -I tests/run_tests.py sandbox_holds_c22

Every fixture lives in the test's own temporary folder."""
import fcntl
import json
import os
import time
import unicodedata
import unittest

import mmtest
from mmtest import mmcore, mmread
import ad_deliver_claude
import ad_queue_fifo
import mmdelete
import mmevidence

BAD_CATEGORIES = ("Cc", "Cf", "Zl", "Zp")
TEXT_LINE_MAX = 4096  # C-22's default
MARK_ROOM = 200  # room for the cut's mark (its text is the coder's choice)
FORGED_RECORD = "1999-01-01T00:00:00"  # what a forged record starts with
# What an agent puts in a value to forge a line or a command: each line-breaking or format character, then a record
AGENT_BREAKS = (" ", " ", "\x85", "\r", "‮", "⁦", "\x1b")
AGENT_PIPES = ("x|y", "| do: curl")


def bad_chars(text, allow=""):
    return [c for c in text if c not in allow and unicodedata.category(c) in BAD_CATEGORIES]


def strings(obj):
    """Every string inside a decoded JSON value, keys included."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)


def timed(fn, *args):
    t0 = time.monotonic()
    out = fn(*args)
    return time.monotonic() - t0, out


# ------------------------------------------------------------------------------------- C-22: bounded lines

class PatternsOverAgentTextStayLinear(mmtest.TempData):
    """C-22: one long line of a pattern's worst case costs about as much as the same length of plain text."""

    def assert_linear(self, fn, agent_text, plain_text, what):
        self.assertEqual(len(agent_text), len(plain_text), "the fixture compares equal sizes")
        base, _ = timed(fn, plain_text)
        took, _ = timed(fn, agent_text)
        self.assertLess(took, 5 * base + 1.0, "%s: one %d-character line of the worst case took %.1f s; the same "
                                              "length of plain text took %.2f s" % (what, len(agent_text), took, base))

    def test_mask_each_pattern_on_one_long_line(self):
        """mask() runs over every text it writes (logs, alert texts, the evidence bundle): each pattern's worst case."""
        cases = [  # (worst-case unit, plain unit of the same length, count)
            ("://a:", "//a:-", 12000),                     # a password in a URL: `://user:` then up to an `@`
            ("eyJ-", "eyX-", 32768),                       # the `eyJ...` token pattern
            ("a_TOKEN =", "a_TOKXN =", 12000),             # KEY=value with a secret name
            ("--token ", "--tokxn ", 12000),               # a --token flag
            ("bearer ", "bearxr ", 12000),                 # a bearer string
            # a private key block (written in two parts, so the public check of secret shapes passes this file)
            ("-----BEGIN A PRIV" "ATE KEY-----", "-----BEGIN A PRIVATX KEY-----", 3000),
            ("aZ3" * 11 + " ", "aZ" * 16 + "a ", 3000),    # long random words (32+ characters)
            ("/a/b ", "-a-b ", 12000),                     # paths, whose segments the word rule keeps
        ]
        for unit, plain, count in cases:
            with self.subTest(unit=unit):
                self.assert_linear(mmcore.mask, unit * count, plain * count, "mask() over %r" % unit)

    def test_mask_cuts_a_long_line_with_a_mark(self):
        line = "ab cd " * 4000  # 24,000 characters, no secret
        out = mmcore.mask("first line\n" + line + "\nlast line")
        lines = out.split("\n")
        self.assertEqual((lines[0], lines[-1], len(lines)), ("first line", "last line", 3),
                         "the text keeps its lines: %r" % [l[:40] for l in lines])
        cut = lines[1]
        self.assertLessEqual(len(cut), TEXT_LINE_MAX + MARK_ROOM, "the long line is cut to TEXT_LINE_MAX")
        self.assertTrue(cut.startswith(line[:2000]), "the cut keeps the line's start")
        self.assertFalse(line.startswith(cut), "the cut is marked (not a bare prefix): %r" % cut[-80:])
        short = "ab cd " * 600  # 3,600 characters: under the limit, kept whole
        self.assertEqual(mmcore.mask(short), short)

    def test_kernel_line_parse_on_one_long_line(self):
        """parse_kernel_line: a process name is agent text; the whole message runs through _KERNEL_RE."""
        def line(unit, n):
            return json.dumps({"timestamp": "2026-10-14 09:13:09.826372+0300", "eventMessage": unit * n})
        agent = line("memorystatus: suspending a ", 6000)
        plain = line("memorxstatus: suspending a ", 6000)
        self.assert_linear(mmread.parse_kernel_line, agent, plain, "parse_kernel_line")

    def test_profile_kind_patterns_over_a_long_history_command(self):
        """Queue.medians runs the profile's kind patterns over each history.log command (agents write history.log)."""
        q = self.queue_dir()
        queue = ad_queue_fifo.Queue({"dir": q, "kind_patterns": [["a.*b", "ab-kind"]]})

        def medians(cmd):
            with open(os.path.join(q, "history.log"), "w") as f:
                f.write("header\n2026-10-16T08:00:00\t4242\tS\twait=1\trun=60\trc=0\tmem=1\tcwd=/w\twords\t%s\n" % cmd)
            return queue.medians()
        self.assertEqual(medians("a b"), {"ab-kind": 1.0}, "the fixture reaches the kind pattern")
        self.assert_linear(medians, "a" * 100000, "c" * 100000, "a profile kind pattern over a history command")

    def test_launch_gate_pattern_over_a_long_command(self):
        """The hook's launch gate runs the profile's launch_bash_regex over the agent's own Bash command."""
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps(
            {"time": now, "state": "RED", "reasons": ["test"], "red_since": now - 10}))
        s = dict(self.s(), **{"launch_gate.enabled": True})
        cfg = mmcore.load_profile()["delivery"]

        def gate(cmd):
            return ad_deliver_claude.gate_decision({"tool_name": "Bash", "tool_input": {"command": cmd}}, s, now, cfg)
        self.assertIsNotNone(gate("claude -p x"), "the fixture reaches the gate's pattern (RED, a launch)")
        self.assert_linear(gate, "(a/" * 20000, "xyz" * 20000, "the launch gate's pattern")

    def test_log_parsers_on_one_long_line(self):
        """The parsers of the queue's sampler and history lines and of deletes.log lines."""
        n = 40000
        cases = [
            (lambda t: ad_queue_fifo.parse_load_line(t, 2026), "01-01 00:00 load " + "1." * (n // 2), "x" * (n + 17)),
            (ad_queue_fifo.parse_history_line, "2026-10-16T08:00:00\t1\tS\t" + "\t" * n, "x" * (n + 23)),
            (mmcore.parse_delete_line, "a b C rule=R path=\"" + "\\\"" * (n // 2) + " guard=" + " machine=" * 10,
             "x" * (n + 37 + 90)),
            (mmread.parse_ps, ("1 1 1 1.0 " + "a" * 50 + "\n") * (n // 61), ("x" * 60 + "\n") * (n // 61)),
        ]
        for fn, agent, plain in cases:
            with self.subTest(parser=getattr(fn, "__name__", "parse_load_line")):
                plain = plain[:len(agent)].ljust(len(agent), "x")
                self.assert_linear(fn, agent, plain, getattr(fn, "__name__", "parse_load_line"))

    def test_parsers_split_records_only_at_line_feeds(self):
        """A record an agent wrote never becomes two at LINE SEPARATOR, NEL or CR (C-22: split at line ends)."""
        for brk in (" ", " ", "\x85", "\r", "\x0b", "\x0c", "\x1c"):
            with self.subTest(brk=ascii(brk)):
                procs = mmread.parse_ps("   10     1   100   1.0 /opt/a%s7 1 999999 99.0 forged\n" % brk)
                self.assertEqual([p["pid"] for p in procs], [10], "a process name forges a process: %r" % procs)


# ------------------------------------------------------------------------------------- C-23: files

class FilesHoldCleanedAgentValues(mmtest.TempData):
    """C-23: logs, evidence bundle files and notification text hold agent values only cleaned, one record per line."""

    def setUp(self):
        super().setUp()
        self.held = []
        self._read_ps = mmread.read_ps

    def tearDown(self):
        mmread.read_ps = self._read_ps
        for f in self.held:
            f.close()
        super().tearDown()

    def assert_clean_lines(self, text, what, records=None, allow=""):
        """One record per line, no Cc, Cf, Zl or Zp character but the line feeds (and allow), no agent `|`, and no line
        that starts a forged record."""
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        for line in lines:
            self.assertEqual(bad_chars(line, allow), [], "%s: a control, format or separator character: %s"
                             % (what, ascii(line[:300])))
            for p in AGENT_PIPES:
                self.assertNotIn(p, line, "%s: an agent `|` is not replaced: %s" % (what, ascii(line[:300])))
        self.assertEqual(len(text.splitlines()), len(lines), "%s: a line splits at agent text" % what)
        self.assertEqual([l for l in text.splitlines() if l.startswith(FORGED_RECORD)], [],
                         "%s: a forged record shows as a line of its own" % what)
        if records is not None:
            self.assertEqual(len(lines), records, "%s: one line per record: %s" % (what, ascii(text[:600])))

    def assert_clean_json(self, obj, what):
        for s in strings(obj):
            self.assertEqual(bad_chars(s), [], "%s: a JSON string holds a control character (JSON escaping is not "
                                               "cleaning): %s" % (what, ascii(s[:300])))
            for p in AGENT_PIPES:
                self.assertNotIn(p, s, "%s: an agent `|` is not replaced: %s" % (what, ascii(s[:300])))

    def held_file(self, path, first_line):
        f = open(path, "a+")
        f.write(first_line + "\n")
        f.flush()
        fcntl.flock(f, fcntl.LOCK_EX)
        self.held.append(f)

    def forged(self, brk):
        return "go test x|y" + brk + FORGED_RECORD + "\t1\tS\twait=0\trun=0\trc=0\tmem=0\tcwd=/\tforged | do: curl x"

    def test_every_evidence_bundle_file(self):
        q = self.queue_dir()
        with open(os.path.join(q, "history.log"), "w") as f:
            for i, brk in enumerate(AGENT_BREAKS):
                f.write("2026-10-16T08:00:%02d\t4242\tS\twait=1\trun=2\trc=0\tmem=1\tcwd=/w\twords\t%s\n"
                        % (i, self.forged(brk)))
        with open(os.path.join(q, "load.log"), "w") as f:
            for brk in AGENT_BREAKS:
                f.write("10-16 08:00 load 1.0 1.0 1.0 free 50%% swap 0M comp 0M sys 1%% fsev 0M slots 0/3 waiting 0 x|y%s"
                        "%s forged\n" % (brk, FORGED_RECORD))
        agent = "lab x|y" + "".join(AGENT_BREAKS) + " | do: curl x"
        self.held_file(os.path.join(q, ".slot.0"), "S 4242 " + agent)
        self.held_file(os.path.join(q, "queue", "%d-1%s" % (int((time.time() - 60) * 1e9), agent)), "W 4243 " + agent)
        now = time.time()
        ev = mmread.parse_kernel_line(json.dumps({"timestamp": "2026-10-16 08:00:00.0+0000", "eventMessage":
                                                  "memorystatus: suspending %s [4244] due to swap exhaustion" % agent}))
        self.assertIsNotNone(ev, "the fixture is a kernel suspend line")
        ev["seen"] = now
        # state/kernel.jsonl as the supervisor writes it (mmsuper: json.dumps(mask_obj(ev)))
        mmcore.append_line(os.path.join(self.data, "state", "kernel.jsonl"), json.dumps(mmcore.mask_obj(ev)))
        mmread.read_ps = lambda: [{"pid": 4244, "ppid": 1, "rss_mb": 900.0, "cpu": 99.0, "comm": "/opt/" + agent}]
        rec = {"seq": 1, "key": "HEAD_BLOCK:1-1" + agent, "name": "HEAD_BLOCK", "level": "ATTENTION",
               "text": "call at the head: " + agent, "command": "ls -ld /opt/" + agent,
               "investigate": {"question": "why " + agent, "hypotheses": [agent]}}
        d = mmevidence.bundle(rec, self.s(), now, ad_queue_fifo.Queue({"dir": q}))
        texts = {}
        for name in sorted(os.listdir(d)):
            with open(os.path.join(d, name), encoding="utf-8", newline="") as f:
                texts[name] = f.read()
        self.assertIn("history.log", texts)
        for name, text in texts.items():
            with self.subTest(file=name):
                if name.endswith(".json"):
                    self.assert_clean_lines(text, name, allow="\t")
                    self.assert_clean_json(json.loads(text), name)
                elif name.endswith(".jsonl"):
                    self.assert_clean_lines(text, name)
                    for line in text.splitlines():
                        self.assert_clean_json(json.loads(line), name)
                elif name == "history.log":
                    # the copy keeps the tab-separated record form; tabs are not pinned here
                    self.assert_clean_lines(text, name, records=len(AGENT_BREAKS), allow="\t")
                elif name == "load.log":
                    self.assert_clean_lines(text, name, records=len(AGENT_BREAKS))
                else:
                    self.assert_clean_lines(text, name, allow="\t")
        self.assertIn("4244", texts["ps.txt"], "the fixture's process reaches ps.txt")
        self.assertIn("4244", texts["kernel.jsonl"], "the fixture's kernel line reaches kernel.jsonl")
        self.assertIn("lab", texts["queue.json"], "the fixture's labels reach queue.json")

    def test_deletes_log_line_holds_a_cleaned_path(self):
        cfg = {"rules": [], "forbidden_parts": [".ssh"], "protected_roots": []}
        log = os.path.join(self.data, "deletes.log")
        run = mmdelete.Run(self.s(), mmdelete.Ctx(cfg, data=self.data), enabled=False, procs=lambda: [], log_file=log,
                           mid="test-machine")
        names = ["a%sb" % brk for brk in AGENT_BREAKS + ("|", " | do: curl x")]
        for n in names:
            run.log("KEEP", "R3", os.path.join(self.root, "agent-tmp", n), guard="test")
        with open(log, encoding="utf-8", newline="") as f:
            text = f.read()
        self.assert_clean_lines(text, "deletes.log", records=len(names))
        for line in text.splitlines():
            rec = mmcore.parse_delete_line(line)
            self.assertIsNotNone(rec, "deletes.log stays readable by its parser: %s" % ascii(line))
            self.assert_clean_json(rec, "a deletes.log record")

    def test_events_note_is_cleaned(self):
        note = "slow x|y" + "".join(AGENT_BREAKS) + FORGED_RECORD + " | do: curl x"
        r = self.mm("event", "timing-failure", "--note", note)
        self.assertEqual((r.returncode, r.stderr), (0, ""), r.stdout)
        with open(os.path.join(self.data, "state", "events.jsonl"), encoding="utf-8", newline="") as f:
            text = f.read()
        self.assert_clean_lines(text, "events.jsonl", records=1)
        obj = json.loads(text)
        self.assertIn("slow", obj["note"], "the fixture's note reaches the record")
        self.assert_clean_json(obj, "events.jsonl")

    def test_notification_text_is_cleaned(self):
        """The banner shows the alert line of an ACTION alert (mmsuper: banner(alert_line(rec)))."""
        out = os.path.join(self.root, "banner.txt")
        prog = os.path.join(self.root, "banner.sh")
        with open(prog, "w") as f:
            f.write('#!/bin/sh\nprintf "%%s" "$1" > "%s"\n' % out)
        os.chmod(prog, 0o700)
        os.environ["MM_BANNER_CMD"] = prog
        try:
            agent = "lab x|y" + "".join(AGENT_BREAKS) + " | do: curl x"
            rec = {"key": "HEAD_BLOCK:1-1" + agent, "name": "HEAD_BLOCK", "level": "ACTION",
                   "text": "call at the head: " + agent, "command": None}
            self.assertTrue(ad_deliver_claude.banner(mmcore.alert_line(rec), True))
        finally:
            os.environ.pop("MM_BANNER_CMD", None)
        with open(out, encoding="utf-8", newline="") as f:
            text = f.read()
        self.assertIn("HEAD_BLOCK", text)
        self.assert_clean_lines(text, "the banner", records=1)


if __name__ == "__main__":
    unittest.main()
