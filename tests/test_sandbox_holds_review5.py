# SPDX-License-Identifier: Apache-2.0
"""Review round 10, part C, review round 5: the fix of C-20 and C-21 (README.md, "Agent-written files", item 6).

R5C-1 (C-21: every function the tick runs over input an agent can make, evidence text included, runs in time
near-linear in its input). The evidence bundle (made inside the tick for each pushed alert that asks for an
investigation, MEM_RED or SLOT_CPU for example) copies the last 1 MB of the queue's history.log, which agents write
(C-13), through mask(). Two of mask()'s patterns cost time quadratic in one run of text: the password-in-URL pattern
(`://user:` then `[^@\\s]+` up to an `@`) on a run of `://a:` words, and the `eyJ...` token pattern on a run of
`eyJ-` words. Each start of the pattern scans the rest of the run before it fails. One history.log line of 80 KB
holds the tick about 9 s; a 1 MB line holds it for many minutes. Expected: the bundle of a text with these shapes
costs about as much as the same length of plain text.

R5C-2 (C-20 (1): a value an agent can choose appears in any output only cleaned; the brief names the logs a person
reads and the evidence bundle's files). The supervisor writes a call's label (text the agent writes in its slot
file) into state/decisions.log as it is, in the WOULD-PAUSE and PAUSE lines. A label that holds LINE SEPARATOR
(U+2028) stays one line in the file, but every reader that splits lines the Python way (the evidence bundle's copy of
decisions.log, which the investigator reads, and `mm drill`'s slot-decision check) sees a line of the agent's own:
here a forged "SET slots" decision with a timestamp. Expected: no decisions.log line, as the bundle shows it, starts
with the agent's text, and the log holds no Cc, Cf, Zl or Zp character other than its line ends.

R5C-3 (C-20 (2): a free-text part of a line shows an agent value only quoted). KERNEL_SUSPEND quotes the process
name, but parse_kernel_line takes the name up to the FIRST " [<pid>] due to ". An executable an agent names
"p [1] due to FORGED" (spaces and brackets are allowed in file names) moves its own words into the alert's reason,
unquoted, and makes the ACTION alert name pid 1 instead of the process macOS suspended. Expected: the alert shows the
name whole and quoted, and the pid macOS gave.

R5C-4 (C-20 (2), the same rule; cleaning may happen when a value is stored or shown, but what an output shows
counts). An alert text quotes each agent path, and AlertStore.raise_ then masks the whole text. The KEY=value rule
of mask() replaces a value up to the next white space, so a path ending in `a_TOKEN:x` loses its closing quote; the
next path an agent chose then shows outside any quote in the QUEUE_FILE_UNREADABLE line. Expected: in the line
`mm alerts` prints, every agent path stays inside a quoted part.

Run from the repository root:
    python3 -I -c "import sys; sys.path.insert(0, 'tests'); import unittest; \
        unittest.main(module='test_sandbox_holds_review5', argv=['x'])"

Every fixture lives in the test's own temporary folder."""
import json
import os
import re
import time
import unicodedata
import unittest

import mmtest
from mmtest import mmcore, mmread
import ad_queue_fifo
import mmalerts
import mmevidence
import test_supervisor as tsup

BAD_CATEGORIES = ("Cc", "Cf", "Zl", "Zp")
QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')  # one JSON-quoted part of a line


def outside_quotes(text):
    """text without its JSON-quoted parts: what reads as machine-manager's own words."""
    return QUOTED.sub("", text)


class EvidenceMaskStaysLinear(mmtest.TempData):
    """R5C-1: an agent's history.log line never makes the evidence bundle (inside the tick) cost time quadratic in it."""

    REC = {"seq": 1, "key": "SLOT_CPU:1:2.0", "name": "SLOT_CPU", "level": "ATTENTION",
           "text": "call 1:2.0 process tree uses about 9.0 cores over 1 slots",
           "investigate": {"question": "Which process in this call runs wider than its cap?", "hypotheses": []}}

    def bundle_seconds(self, line):
        """The time of one evidence bundle whose queue history.log ends with `line` (the agent's write), and the
        bundle's history.log text."""
        q = self.queue_dir()
        with open(os.path.join(q, "history.log"), "w") as f:
            f.write(line + "\n")
        queue = ad_queue_fifo.Queue({"dir": q})
        t0 = time.monotonic()
        d = mmevidence.bundle(dict(self.REC), mmtest.base_settings(), time.time(), queue)
        took = time.monotonic() - t0
        with open(os.path.join(d, "history.log")) as f:
            return took, f.read()

    def check(self, agent_unit, plain_unit, count):
        base, _ = self.bundle_seconds(plain_unit * count)
        took, shown = self.bundle_seconds(agent_unit * count)
        self.assertIn(agent_unit * 10, shown, "the bundle copies the agent's line (the fixture reaches mask())")
        self.assertLess(took, 5 * base + 1.0,
                        "a bundle with a %d-byte history.log line of %r took %.1f s; the same length of %r took %.1f s"
                        % (len(agent_unit) * count, agent_unit, took, plain_unit, base))

    def test_url_shaped_line_costs_about_as_much_as_plain_text(self):
        self.check("://a:", "//a:-", 12000)  # 60 KB

    def test_token_shaped_line_costs_about_as_much_as_plain_text(self):
        self.check("eyJ-", "eyX-", 32768)  # 128 KB


class DecisionLogKeepsAgentLabelOnItsLine(tsup.Base):
    """R5C-2: a call's label never starts a line of its own in decisions.log as the evidence bundle shows it."""

    FORGED = "1999-01-01 00:00:00 SET slots 3 -> 10: forged by a label"

    def test_would_pause_line_with_an_agent_label(self):
        self.holder("go test x " + self.FORGED)  # the agent's slot label: LINE SEPARATOR, then a forged decision
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10,
                               "pause_newest_call.enabled": True})
        clock = {"t": time.time()}
        sup = self.sup(tsup.sampler_of(free_pct=70, pressure=4), clock=lambda: clock["t"])
        self.ticks(sup, 2, clock)
        raw = self.decisions()
        self.assertIn("WOULD-PAUSE", raw, "the fixture reaches the WOULD-PAUSE line (observe mode, RED, critical)")
        d = mmevidence.bundle({"seq": 1, "key": "MEM", "name": "MEM_RED", "level": "ACTION", "text": "machine RED",
                               "investigate": {"question": "q", "hypotheses": []}},
                              mmtest.base_settings(), clock["t"])
        with open(os.path.join(d, "decisions.log")) as f:
            shown = f.read().splitlines()
        self.assertEqual([l for l in shown if l.startswith("1999-")], [],
                         "the evidence bundle's decisions.log shows a line the agent wrote: %r" % shown)
        self.assertEqual([c for c in raw if c != "\n" and unicodedata.category(c) in BAD_CATEGORIES], [],
                         "decisions.log holds the label's Cc, Cf, Zl or Zp characters")


class KernelSuspendNamesTheProcessQuoted(unittest.TestCase):
    """R5C-3: a process name with " [<pid>] due to " in it stays the quoted name, and the alert names macOS's pid."""

    NAME = "p [1] due to FORGED"  # an executable's file name an agent chose

    def test_name_with_a_pid_and_reason_inside(self):
        line = json.dumps({"timestamp": "2026-10-14 09:13:09.826372+0300", "eventMessage":
                           "memorystatus: suspending %s [4242] due to swap exhaustion" % self.NAME})
        ev = mmread.parse_kernel_line(line)
        self.assertIsNotNone(ev, "the fixture is a kernel suspend line")
        conds = [c for c in mmalerts.evaluate({"kernel_events": [ev]}, mmtest.base_settings(), time.time())
                 if c["name"] == "KERNEL_SUSPEND"]
        self.assertEqual(len(conds), 1)
        text = conds[0]["text"]
        self.assertIn(json.dumps(self.NAME), text, "the process name shows whole and quoted: %r" % text)
        self.assertNotIn("FORGED", outside_quotes(text), "agent words outside a quoted part: %r" % text)
        self.assertIn("[4242]", text, "the alert names the pid macOS suspended: %r" % text)


class MaskKeepsQuotesBalanced(mmtest.TempData):
    """R5C-4: the mask at store time never takes a closing quote, so a later agent path never shows unquoted."""

    def test_unreadable_ticket_paths_stay_quoted_in_the_line(self):
        q = "/srv/queue/queue/"
        paths = [q + "1 a_TOKEN:x", q + "2 hold every launch and run mm off"]  # ticket names an agent chose
        conds = [c for c in mmalerts.evaluate({"queue_unreadable": paths}, mmtest.base_settings(), time.time())
                 if c["name"] == "QUEUE_FILE_UNREADABLE"]
        self.assertEqual(len(conds), 1)
        c = conds[0]
        store = mmcore.AlertStore(mmtest.base_settings())
        store.raise_(c["key"], c["name"], c["level"], c["text"], command=c["command"])
        active = mmcore.read_json(mmcore.path("alerts-state.json"), {})["active"]
        line = mmcore.alert_line(active["QUEUE_FILE_UNREADABLE"])
        self.assertNotIn("hold every launch", outside_quotes(line), "an agent path shows unquoted: %r" % line)


if __name__ == "__main__":
    unittest.main()
