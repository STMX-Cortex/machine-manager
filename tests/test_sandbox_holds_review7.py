# SPDX-License-Identifier: Apache-2.0
"""Review round 10, part C, review round 7 (the check of C-24: a URL password that holds `/` is masked, as before
round 6, and the rule stays linear). The evidence bundle's copy of the queue's history.log (agents write it, C-13)
goes through mask().

R7C-1 (mask()'s doc: "passwords in URLs" are replaced; R6C-1's expectation: "the password never shows"). The rule
needs a user name of at least one character before the `:`. A URL with a password and no user name is the usual form
for a Redis server that has only a password (`redis://:<password>@host:6379/0`, as the Redis, redis-py and Celery
documents give it). Its password shows whole. Expected: no 8-character piece of the password shows.

R7C-2 (the same rule). The rule ends the user name and the password at the first `@`. The URL parsers that agents'
tools use (the WHATWG URL parser of browsers and Node, Python's urllib and urllib3) end them at the last `@` before
the host, so a raw `@` in a password or an e-mail address as the user name works in those tools. The part of the
password after the first `@`, or all of it after an e-mail user name, shows. Expected: no 8-character piece of the
password shows.

R7C-3 (R6C-1's expectation: "a URL with no password stays as it is"). Since a password may hold `/` (C-24), a URL
with a port and a later `@` in the same word reads as `://<host>:<port/path...>@`: the port, the path and the query
up to the `@` are replaced by `***`. Plain commands lose their text: a Vite or npm-scope path (`/@vite`, `/@types`),
a pip VCS pin (`.git@v1.2.3`), an e-mail address in a query. Expected: each of these commands stays as it is.

R7C-4 (C-24: the rule stays linear): see UrlRuleStaysLinearOnCutLines. It passes at the fix and fails with the rule
of 9fccdc1 put back (the review's planted fault); no earlier test fails then.

Run from the repository root:
    python3 -I -c "import sys; sys.path.insert(0, 'tests'); import unittest; \
        unittest.main(module='test_sandbox_holds_review7', argv=['x'])"

Every fixture lives in the test's own temporary folder."""
import os
import time
import unittest

import mmtest
from mmtest import mmcore
import ad_queue_fifo
import mmevidence

ROW = "2026-10-16T08:00:00\t4242\tS\twait=1\trun=60\trc=0\tmem=1\tcwd=/w\twords\t"  # a history row up to its command


def pieces(secret, n):
    """Every n-character piece of secret."""
    return {secret[i:i + n] for i in range(len(secret) - n + 1)}


class Base(mmtest.TempData):
    REC = {"seq": 1, "key": "SLOT_CPU:1:2.0", "name": "SLOT_CPU", "level": "ATTENTION",
           "text": "call 1:2.0 process tree uses about 9.0 cores over 1 slots",
           "investigate": {"question": "Which process in this call runs wider than its cap?", "hypotheses": []}}

    def bundle_history(self, commands):
        """The evidence bundle's history.log after the queue's history.log got one row per command (the agent's
        writes)."""
        q = self.queue_dir()
        with open(os.path.join(q, "history.log"), "w") as f:
            f.write("".join(ROW + c + "\n" for c in commands))
        d = mmevidence.bundle(dict(self.REC), mmtest.base_settings(), time.time(), ad_queue_fifo.Queue({"dir": q}))
        with open(os.path.join(d, "history.log")) as f:
            return f.read()

    def assert_hidden(self, commands, password):
        """Neither mask() nor the bundle's history.log shows an 8-character piece of password."""
        for c in commands:
            with self.subTest(command=c):
                out = mmcore.mask(c)
                self.assertEqual(sorted(p for p in pieces(password, 8) if p in out), [], out)
        shown = self.bundle_history(commands)
        self.assertIn("words", shown, "the bundle copies the agent's rows (the fixture reaches mask())")
        leaked = sorted(p for p in pieces(password, 8) if p in shown)
        self.assertEqual(leaked, [], "the bundle's history.log shows a URL password: %r"
                         % [line for line in shown.splitlines() if any(p in line for p in leaked)])


class UrlPasswordWithNoUserIsMasked(Base):
    """R7C-1: `scheme://:<password>@host` never shows its password."""

    PASSWORD = "hunter2Qx7LmP4zR9kT"
    COMMANDS = [
        "redis-cli -u redis://:%s@example.com:6379/0 ping",
        "celery -A app worker --broker=redis://:%s@example.com:6379/0",
        "export REDIS_URL=rediss://:%s@example.com:6380",
    ]

    def test_no_user_name(self):
        self.assert_hidden([c % self.PASSWORD for c in self.COMMANDS], self.PASSWORD)


class UrlUserinfoWithRawAtIsMasked(Base):
    """R7C-2: a raw `@` in the password, or an e-mail address as the user name, shows no piece of the password."""

    # accepted limit AL-10 (the owner, 2026-10-16): the user info ends at the first @; invalid or rare forms only.
    @unittest.expectedFailure
    def test_raw_at_in_the_password(self):
        password = "Qx7@LmP4zR9kTw2Bn"
        self.assert_hidden(["redis-cli -u redis://default:%s@example.com:6379/0 ping" % password,
                            "python3 -m worker --broker amqp://app:%s@example.com:5672/vh" % password],
                           password)

    # accepted limit AL-10 (the owner, 2026-10-16): the user info ends at the first @; invalid or rare forms only.
    @unittest.expectedFailure
    def test_email_as_the_user_name(self):
        password = "hunter2Qx7LmP4zR9kT"
        self.assert_hidden(["git clone https://bob@example.com:%s@example.com/team/repo.git" % password,
                            "curl ftp://bob@example.com:%s@example.com/pub/" % password], password)


class UrlRuleStaysLinearOnCutLines(unittest.TestCase):
    """R7C-4 (C-24: the rule stays linear, each try stops at the next `://`). Each line is cut to TEXT_LINE_MAX
    (C-22), so a URL-shaped line is short; but the rule before round 6 (`[^@\\s]+` up to an `@`) still costs time
    quadratic in each cut line, about 40 times the time of plain text, and review 5's test of one long line no longer
    sees it. Expected: many cut lines of `://a:` words cost about as much as the same lines of plain text."""

    LINES = 128

    def seconds(self, unit):
        text = "\n".join((unit * 1000)[:4096] for _ in range(self.LINES))
        t0 = time.monotonic()
        out = mmcore.mask(text)
        return time.monotonic() - t0, out

    def check(self, unit, plain):
        base, _ = self.seconds(plain)
        took, out = self.seconds(unit)
        self.assertIn(unit * 10, out, "mask() keeps the words (no password: no `@`)")
        self.assertLess(took, 5 * base + 0.5, "%d cut lines of %r took %.2f s; the same lines of %r took %.2f s"
                        % (self.LINES, unit, took, plain, base))

    def test_url_words(self):
        self.check("://a:", "//a:-")

    def test_url_words_with_a_slash(self):
        self.check("://a:/", "//a:-/")


class UrlWithPortAndLaterAtStays(Base):
    """R7C-3: a URL with a port and an `@` later in its path or query, and no password, stays as it is."""

    COMMANDS = [
        "curl http://localhost:5173/@vite/client",
        "curl https://registry.example.com:443/@types%2fnode",
        "pip install git+https://git.example.com:8443/group/repo.git@v1.2.3",
        "curl http://localhost:8080/api/users?email=bob@example.com",
    ]

    # accepted limit AL-11 (the owner, 2026-10-16): a URL with a port and a later @ is over-masked; no secret shows.
    @unittest.expectedFailure
    def test_mask_keeps_them(self):
        for c in self.COMMANDS:
            with self.subTest(command=c):
                self.assertEqual(mmcore.mask(c), c)

    # accepted limit AL-11 (the owner, 2026-10-16): a URL with a port and a later @ is over-masked; no secret shows.
    @unittest.expectedFailure
    def test_bundle_keeps_them(self):
        shown = self.bundle_history(self.COMMANDS)
        for c in self.COMMANDS:
            with self.subTest(command=c):
                self.assertIn(c, shown)


if __name__ == "__main__":
    unittest.main()
