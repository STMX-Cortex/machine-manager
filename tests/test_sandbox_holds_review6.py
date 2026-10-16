# SPDX-License-Identifier: Apache-2.0
"""Review round 10, part C, review round 6 (the closing round of C-20 to C-23): the evidence bundle's copy of the
queue's history.log (agents write it, C-13) shows an agent's secret.

R6C-1 (README.md, "Agent-written files", items 6 and 7; mask()'s doc: "passwords in URLs" are replaced). Round 6
made the password-in-URL pattern linear by refusing a raw `/` in the password. A password that holds `/` (a base64
password, as `openssl rand -base64` and generated database passwords give it) is a working URL password for the
tools that read such URLs (SQLAlchemy's URL parser, for one, takes everything up to the `@`), and mask() masked it
before round 6. Now the bundle's history.log shows it whole. Expected: the password never shows; a URL with no
password stays as it is. (Linear time stays required: review 5's EvidenceMaskStaysLinear.)

R6C-2 (C-22: each line is cut before a pattern runs; C-22a: a cut never opens a gate). A secret that the cut splits
is masked by no rule: the URL rule needs the `@` the cut removed, and the token rules need a length the cut left
short. So a history.log command longer than TEXT_LINE_MAX shows the first part of a secret that ends past the cut,
up to all of a URL's password. Expected: no 8-character piece of the secret shows, wherever the cut falls.

Run from the repository root:
    python3 -I -c "import sys; sys.path.insert(0, 'tests'); import unittest; \
        unittest.main(module='test_sandbox_holds_review6', argv=['x'])"

Every fixture lives in the test's own temporary folder."""
import os
import time
import unittest

import mmtest
from mmtest import mmcore
import ad_queue_fifo
import mmevidence

TEXT_LINE_MAX = 4096  # C-22's default; the test profile keeps it
MARK_ROOM = 200  # room for the cut's mark (its text is the coder's choice)
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


class UrlPasswordWithSlashIsMasked(Base):
    """R6C-1: a URL password that holds a raw `/` never shows in the bundle."""

    PASSWORD = "Zx9/kQ7mWp+Lr3/Tn8vB="  # base64: holds `/`, `+` and `=`
    COMMANDS = [
        "psql postgresql://app:%s@example.com/prod -c 'select 1'",
        "alembic -x url=mysql://root:%s@example.com/app upgrade head",
        "python3 -m worker --broker redis://default:%s@example.com:6379/0",
    ]

    def test_slash_in_the_password(self):
        shown = self.bundle_history([c % self.PASSWORD for c in self.COMMANDS] + ["curl https://example.com/a/b:c"])
        self.assertIn("upgrade head", shown, "the bundle copies the agent's rows (the fixture reaches mask())")
        self.assertIn("curl https://example.com/a/b:c", shown, "a URL with no password stays as it is")
        leaked = sorted(p for p in pieces(self.PASSWORD, 8) if p in shown)
        self.assertEqual(leaked, [], "the bundle's history.log shows a URL password: %r"
                         % [line for line in shown.splitlines() if any(p in line for p in leaked)])

    def test_mask_itself(self):
        for c in self.COMMANDS:
            with self.subTest(command=c):
                out = mmcore.mask(c % self.PASSWORD)
                self.assertNotIn(self.PASSWORD, out)
                self.assertEqual([p for p in pieces(self.PASSWORD, 8) if p in out], [], out)


class SecretSplitByTheCutIsMasked(Base):
    """R6C-2: a secret that ends past a long line's cut shows no 8-character piece in the bundle."""

    def check(self, secret_text, secret):
        """One row per position: the secret text starts at each of the places around the cut, in steps of 5."""
        first = TEXT_LINE_MAX - MARK_ROOM - len(secret_text)
        commands = []
        for start in range(first, TEXT_LINE_MAX, 5):
            pad = "w " * (start // 2) + "w" * (start % 2)  # plain words, no secret
            commands.append(pad + secret_text)
        self.assertLessEqual(len(commands), 60, "the bundle copies the last 60 rows; all must be there")
        shown = self.bundle_history(commands)
        self.assertEqual(len(shown.splitlines()), len(commands), "the bundle copies every row")
        leaked = sorted(p for p in pieces(secret, 8) if p in shown)
        self.assertEqual(leaked, [], "a cut row shows a piece of the secret: %r"
                         % sorted({line[-60:] for line in shown.splitlines() if any(p in line for p in leaked)}))

    def test_url_password_across_the_cut(self):
        password = "hunter2Qx7LmP4zR9kT"
        self.check("psql postgresql://app:%s@example.com/prod" % password, password)

    def test_token_across_the_cut(self):
        body = "Ab3dEf6hIj9lMn2pQr5tUv8xYz1bCd4fGh7jKl0n"  # 40 characters
        self.check("printf %s " + "gh" + "p_" + body + " | gh auth login --with-token", body)


if __name__ == "__main__":
    unittest.main()
