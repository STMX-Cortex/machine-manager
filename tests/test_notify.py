# SPDX-License-Identifier: Apache-2.0
"""`mm notify` Part A (phone notifications): the [notify] profile section, `mm check`, the secret file rules as the CLI
shows them, grants, send, run, test, status, the outbox and sent.jsonl. Written from the contract (sections 1, 4, 4b,
4c, 4f), not from the code: every test drives `python3 -I bin/mm --profile P --data D notify ...` in a subprocess
with a temporary HOME, profile and data folder, against a local fake ntfy / Pushover server on 127.0.0.1 (port 0)
that records each request. No test reaches the internet.

Time: the contract fixes wall-clock windows (backoff 30 s, duplicates 600 s, a rolling hour). The tests do not wait for
them; they run bin/mm under a small wrapper that moves time.time() forward by an offset (assumption A3).

Assumptions (where the contract does not fix an exact output; each test asserts only what the contract fixes):
A1  Errors print as one `E_<CODE> what; fix: how` line on stdout (bin/mm's err()); stderr stays empty on every run.
A2  An E_NOTIFY_LIMIT / E_NOTIFY_DUPLICATE / E_NOTIFY_REFUSED outcome shows its code on stdout.
A3  bin/mm reads wall time through time.time() (the repo's practice), so a wrapper that shifts time.time() moves
    every notify clock (backoff, rolling hour, duplicate window, outbox age).
A4  `mm notify status` prints its fields as `key=value` words (one or more lines); --json gives one object with the
    same key names. Exit 0 whether notify is on or off.
A5  `mm check` prints a line holding `notify=off` without [notify] (or with enabled = false) and one holding
    `notify=ok service=<service>` for a valid section; with a bad section it exits 1 with an `E_PROFILE` line that
    names the key. All other check lines stay as they were (compared with the base commit when git has it).
A6  grants.json holds the key's sha256 as a lower-case hex digest (hashlib.sha256(key).hexdigest()), where the key is
    the key file's 64 hex characters without the trailing newline.
A7  Cleared alert records (level INFO, why "cleared", as AlertStore writes them) are sent as quiet when send_cleared is
    true, whatever alert_levels holds (the default alert_levels has no INFO, and send_cleared defaults to true).
A8  A bad grant NAME, --max-level or --per-hour, a bad send --level, a missing --title, an unknown notify word and an
    unknown option (such as --sender) exit 2 with one error line; the exact code is not asserted.
A9  A key file that does not exist or does not hold a granted key is refused with exit 2 (E_NOTIFY_KEY when the file
    can be read).
A10 With [notify] missing or enabled = false, `mm notify send` gives E_NOTIFY_OFF even before it reads --key-file.
A11 `mm notify run` with nothing to do and everything delivered exits 0; an over-long title or text is either cut
    to the contract's bounds or refused with exit 2 (never sent longer).
A12 The outbox is tested through `mm notify status queued=N` and the fake server's requests, not its file format.
A13 The suppression notice's words "N alerts suppressed" are in its title or its message.
A14 A sent.jsonl record holds at least the contract's fields; any extra field never holds the text or a secret.
A15 The ntfy JSON publish goes to the server base URL (path "/"); the Pushover form goes to the configured URL's path.
A16 (4c, 4f) A run that meets a state-file error delivers nothing it cannot account for: with state.json unreadable
    (a folder in its place: E_NOTIFY_STATE, exit 2) the run sends nothing, so after the file is restored each alert
    arrives exactly once. With the notify folder read-only (unless the run sets it back to 0700 itself and so meets
    no error) or sent.jsonl replaced by a folder, a duplicate after the restore is tolerated, a loss is not. A failing
    run prints an error line, never a traceback (stderr empty); a state-file write error exits 1 or 2.
A17 (4c) After a SIGKILL in the middle of a delivery, the request the fake server already received counts as
    delivered (the service got it); every other alert must arrive in later runs within 17 minutes (an outbox item
    left by the killed run may wait for its backoff, but is not dropped before 1 hour).
A18 (4c.3) "Nothing old is sent" covers old records that keep a higher seq earlier in the file: after a reset, only
    records appended after it are sent, and a new record wins over an old one with the same seq.
A19 (4c.4) The sent.jsonl rotation test pads sent.jsonl to just over 1 MiB with copies of its own last record
    (status limited) instead of 5000 CLI sends; the next CLI appends must rotate it to sent.jsonl.1.
A20 (4c.5) After a suppression, the first message of the next hour is the notice, and with alerts_per_hour = 1 it is
    the only message of that hour.
A21 (4c.6) The outbox holds at most 100 items; when a new failed delivery would make 101, one item is dropped, and
    the first dropped item is the one first attempted earliest (here an agent message, retried once before the other
    99 items were queued, so it may no longer be first in the list).
A22 Backoff runs from the time of the failed try; the 1-hour drop runs from the first attempt.
A23 (4f) The damaged-state tests change the document the code itself wrote, without assuming its schema: every
    whole number becomes a string (the cursor first), every string a number, every list gets a member {"junk": true},
    and a top-level schema_version (when there is one) becomes 999. Each change makes the document invalid. `mm notify
    run` and `mm notify send` both need the state; `mm notify status` is not required to fail.
A24 (4f.2) The E_NOTIFY_STATE line names state.json; nothing is written at all (state.json and sent.jsonl unchanged).
A25 (4f.3) While one run waits on its delivery, a second run prints `notify=busy` (exit 0, no request) and an agent's
    `mm notify send` still delivers within a few seconds (the state lock is never held during network I/O).
A26 (4f.4) A run started while a test holds state/alerts.lock (flock LOCK_EX) either waits for it or ends with one
    error line; it never sends before the lock is free.
A27 (4f.4e) An error after delivery is made by replacing state.json with a folder while the fake server holds the
    request, then restoring the bytes it held at that moment (the state after step (c)).
A28 (4f.1) An item's hour event is the time of its latest counted outcome, so a retry delivered at +2800 s still
    counts at +3700 s and stops counting after +6400 s; with alerts_per_hour = 1 the first message after that is the
    suppression notice.
A30 (4f.2) 4f fixes the start point only for a missing state.json, so every test runs its first `mm notify run`
    before any agent send.
A29 (4f.4b) When the oldest item is due in the overflow run, it is delivered and another (not selected) item is
    dropped; sent.jsonl ids are stable for one item across its records.
Not covered here (Part B or impractical in a CLI test): a secret file owned by another uid, the systemd/launchd
templates, NOTIFY.md."""
import hashlib
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import stat
import string
import subprocess
import sys
import threading
import time
import unicodedata
import unittest
import urllib.parse

from mmtest import BIN, CODE, FIX, TempData, mmcore

MM_PATH = os.path.join(BIN, "mm")
CHECK_FIX = os.path.join(FIX, "check-command.py")
BASE_COMMIT = "662284f"  # main before `mm notify`: the byte-for-byte comparison of the existing verbs
ERROR = re.compile(r"^E_[A-Z_]+ .+; fix: .+$")
KV = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|\S+)')
SENT_FIELDS = {"time", "id", "source", "sender", "level", "title", "status", "error"}
STATUSES = {"delivered", "queued", "failed", "refused", "suppressed", "dropped", "limited", "duplicate"}
MID = "test-machine"
AT = "@"  # userinfo in a URL, kept apart so the public scan sees no e-mail address

SHIFT_PY = """import runpy, sys, time
off = float(sys.argv[1])
_real = time.time
time.time = lambda: _real() + off
sys.argv = sys.argv[2:]
runpy.run_path(sys.argv[0], run_name="__main__")
"""
MODULES_PY = """import runpy, sys
out = sys.argv[1]
sys.argv = sys.argv[2:]
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
finally:
    with open(out, "w") as f:
        f.write("\\n".join(sorted(sys.modules)))
"""


def alnum(n):
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def kv(text):
    """Every `key=value` word of a text; JSON-quoted values unquoted."""
    out = {}
    for k, v in KV.findall(text):
        out[k] = json.loads(v) if v.startswith('"') else v
    return out


def controls(text):
    return [c for c in text if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")]


class FakeServer:
    """A threaded HTTP server on 127.0.0.1, port 0, that records every request and answers with the next queued status
    (else `default`). A 3xx answer points at /followed on itself; `hang` makes the next answer wait 3 s;
    `hold` makes it wait until `release` is set (at most 15 s)."""

    def __init__(self, kind="ntfy"):
        self.kind, self.requests, self.responses, self.default = kind, [], [], 200
        self.lock = threading.Lock()
        self.release = threading.Event()
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n > 0 else b""
                with fake.lock:
                    fake.requests.append({"method": self.command, "path": self.path, "body": body,
                                          "headers": {k.lower(): v for k, v in self.headers.items()}})
                    status = fake.responses.pop(0) if fake.responses else fake.default
                if status == "hang":
                    time.sleep(3)
                    status = 200
                if status == "hold":
                    fake.release.wait(15)
                    status = 200
                if 200 <= status < 300:
                    payload = b'{"status":1,"request":"fake"}' if fake.kind == "pushover" else \
                        b'{"id":"fakeid","event":"message"}'
                else:
                    payload = b'{"status":0,"errors":["fake refusal"]}'
                try:
                    self.send_response(status)
                    if 300 <= status < 400:
                        self.send_header("Location", "http://127.0.0.1:%d/followed" % fake.port)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except OSError:
                    pass

            do_POST = do_GET = do_PUT = _any

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.srv.daemon_threads = True
        self.srv.block_on_close = False
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def close(self):
        self.release.set()
        self.srv.shutdown()
        self.srv.server_close()

    def posts(self):
        with self.lock:
            return list(self.requests)

    def ntfy(self):
        """The JSON bodies of the requests, in order."""
        return [json.loads(r["body"]) for r in self.posts()]

    def forms(self):
        return [{k: v[0] for k, v in urllib.parse.parse_qs(r["body"].decode(), keep_blank_values=True).items()}
                for r in self.posts()]


def toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    return json.dumps(v)


class NotifyBase(TempData):
    service = "ntfy"

    def setUp(self):
        super().setUp()
        try:
            self.fake = FakeServer(self.service)
        except PermissionError as e:  # the command sandbox may forbid sockets
            self.skipTest("cannot bind 127.0.0.1: %s" % e)
        self.addCleanup(self.fake.close)
        self.prof = os.path.join(self.root, "profile.toml")
        self.secret_file = os.path.join(os.environ["HOME"], ".config", "machine-manager", "notify-secret.json")
        self.shift_py = os.path.join(self.root, "shift.py")
        with open(self.shift_py, "w") as f:
            f.write(SHIFT_PY)
        self.outputs = []
        self.ntfy_token = "tk_" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(29))
        self.app_token, self.user_key = "a" + alnum(29), "u" + alnum(29)
        self.write_profile(self.notify_cfg())

    # ---- profile, secret, runs

    def notify_cfg(self, **over):
        cfg = {"enabled": True, "service": self.service}
        if self.service == "ntfy":
            cfg.update(url=self.fake.url, topic="mm-alerts")
        else:
            cfg.update(url=self.fake.url + "/1/messages.json", secret_file=self.secret_file)
        cfg.update(over)
        return {k: v for k, v in cfg.items() if v is not None}

    def write_profile(self, notify=None, raw=""):
        lines = ['name = "notify-test"', 'machine_id = "%s"' % MID, ""]
        if notify is not None:
            lines.append("[notify]")
            lines += ["%s = %s" % (k, toml_value(v)) for k, v in notify.items()]
        with open(self.prof, "w") as f:
            f.write("\n".join(lines) + "\n" + raw)

    def write_secret(self, obj=None, mode=0o600, raw=None):
        os.makedirs(os.path.dirname(self.secret_file), exist_ok=True)
        if obj is None:
            obj = {"token": self.ntfy_token} if self.service == "ntfy" else \
                {"app_token": self.app_token, "user_key": self.user_key}
        if os.path.lexists(self.secret_file):
            os.unlink(self.secret_file)
        with open(self.secret_file, "w") as f:
            f.write(raw if raw is not None else json.dumps(obj))
        os.chmod(self.secret_file, mode)

    def cli(self, *args, offset=0, env=None, clean_stderr=True, timeout=60):
        pre = ["--profile", self.prof, "--data", self.data]
        if args and args[0] == "check":
            cmd = [sys.executable, "-I", CHECK_FIX, *args, *pre]
        elif offset:
            cmd = [sys.executable, "-I", self.shift_py, str(offset), MM_PATH, *pre, *args]
        else:
            cmd = [sys.executable, "-I", MM_PATH, *pre, *args]
        e = dict(os.environ)
        e.pop("MM_NOTIFY_KEY_FILE", None)
        e.update(env or {})
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=e)
        self.outputs.append((args, r.stdout, r.stderr))
        if clean_stderr:
            self.assertEqual(r.stderr, "", (args, r.stdout, r.stderr))
        self.assertIn(r.returncode, {0, 1, 2, 3, 10, 20}, (args, r.returncode, r.stdout))
        return r

    def assert_error(self, r, code, rc=2):
        self.assertEqual(r.returncode, rc, r.stdout)
        lines = [line for line in r.stdout.splitlines() if line.startswith("E_")]
        self.assertTrue(lines, r.stdout)
        if code:
            self.assertEqual(lines[0].split()[0], code, r.stdout)
        self.assertRegex(lines[0], ERROR)

    def assert_refused(self, r):
        """Exit 2 with one error line (A8)."""
        self.assert_error(r, None, 2)

    # ---- state

    def notify_dir(self):
        return os.path.join(self.data, "notify")

    def sent(self):
        p = os.path.join(self.notify_dir(), "sent.jsonl")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(line) for line in f if line.strip()]

    def status(self, offset=0):
        r = self.cli("notify", "status", offset=offset)
        self.assertEqual(r.returncode, 0, r.stdout)
        return kv(r.stdout)

    def grant(self, name="agent-one", *extra):
        r = self.cli("notify", "grant", name, *extra)
        self.assertEqual(r.returncode, 0, r.stdout)
        g = kv(r.stdout)
        self.assertEqual(g.get("grant"), name, r.stdout)
        return g["key_file"]

    def send(self, key_file, title, level="normal", text=None, *extra, offset=0, env=None):
        args = ["notify", "send"] + (["--key-file", key_file] if key_file else []) + ["--level", level, "--title", title]
        if text is not None:
            args += ["--text", text]
        return self.cli(*args, *extra, offset=offset, env=env)

    def assert_delivered(self, r):
        self.assertEqual(r.returncode, 0, r.stdout)
        out = kv(r.stdout)
        self.assertEqual(out.get("notify"), "delivered", r.stdout)
        self.assertTrue(out.get("id"), r.stdout)
        return out["id"]

    def assert_queued(self, r):
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertEqual(kv(r.stdout).get("notify"), "queued", r.stdout)

    def write_alerts(self, *records):
        with open(os.path.join(self.data, "alerts.jsonl"), "a") as f:
            for rec in records:
                f.write(json.dumps(rec, sort_keys=True) + "\n")

    @staticmethod
    def alert(seq, name, level="ATTENTION", text=None, why="new"):
        """One record as AlertStore._append writes it."""
        cleared = why == "cleared"
        return {"key": name, "name": name, "level": "INFO" if cleared else level,
                "text": "cleared: " + name if cleared else (text or "%s raised for the test" % name),
                "value": None, "command": None if cleared else "mm status", "investigate": None, "why": why,
                "seq": seq, "time": mmcore.now_local(), "machine_id": MID, "schema_version": mmcore.SCHEMA_VERSION}

    def all_files(self, skip=()):
        for d, _, files in os.walk(self.root):
            for name in files:
                p = os.path.join(d, name)
                if p in skip or os.path.islink(p):
                    continue
                with open(p, "rb") as f:
                    yield p, f.read()

    def assert_nowhere(self, needles, skip=()):
        """None of needles in any output so far, nor in any file under the test's folder (but skip)."""
        for args, out, err in self.outputs:
            for n in needles:
                self.assertNotIn(n, out + err, args)
        for p, data in self.all_files(skip):
            for n in needles:
                self.assertNotIn(n.encode(), data, p)


# =============================================================================================== 1. off


class Off(NotifyBase):
    def setUp(self):
        super().setUp()
        self.write_profile(None)

    def test_send_without_section_is_E_NOTIFY_OFF(self):
        key = os.path.join(self.root, "key")
        with open(key, "w") as f:
            f.write(secrets.token_hex(32) + "\n")
        for profile in (None, self.notify_cfg(enabled=False)):
            self.write_profile(profile)
            for key_file in (key, os.path.join(self.root, "no-such-key")):  # A10: before the key file is read
                with self.subTest(profile=bool(profile), key_file=key_file):
                    self.assert_error(self.send(key_file, "hello"), "E_NOTIFY_OFF", 2)
        self.assertEqual(self.fake.posts(), [])

    def test_status_and_check_say_off(self):
        self.assertEqual(self.status().get("notify"), "off")
        r = self.cli("check")  # no [notify] section: check output stays byte-for-byte as before (no notify line)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("notify", r.stdout)
        self.write_profile(self.notify_cfg(enabled=False))
        self.assertEqual(self.status().get("notify"), "off")
        self.assertIn("notify=off", self.cli("check").stdout)

    def test_run_and_test_send_nothing_when_off(self):
        self.write_alerts(self.alert(1, "MEM_RED", "ACTION"))
        self.cli("notify", "run")
        self.write_alerts(self.alert(2, "DISK_LOW", "ACTION"))
        self.cli("notify", "run")
        self.cli("notify", "test")
        self.assertEqual(self.fake.posts(), [])

    def _golden_data(self):
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps(mmcore.stamp({
            "kind": "machine", "time": now, "state": "AMBER", "reasons": ["free 45% < 50%"], "mode": "observe",
            "slots": 5, "slots_would": 3, "busy": 2, "waiting": 1, "disk_gb": 107.2,
            "readings": {"free_pct": 45, "swap_used_mb": 499.4, "comp_mb": 2100, "pressure": 2, "load5": 4.5,
                         "sys_pct": 12.3}}, mid=MID)))
        st = mmcore.AlertStore(self.s(), clock=lambda: now, mid=MID)
        st.begin()
        st.raise_("MEM", "MEM_AMBER", "ATTENTION", "memory AMBER: free 45% < 50%", command="mm status")
        st.raise_("DISK_LOW", "DISK_LOW", "ACTION", "disk 35 GB free < 40 GB", command="mm cleanup")
        st.raise_("IDLE_ROOM", "IDLE_ROOM", "INFO", "queue idle 40 min")

    VERBS = (("status",), ("--json", "status"), ("alerts",), ("--json", "alerts"), ("explain", "DISK_LOW"),
             ("settings", "show", "alerts"), ("place", "--kind", "other"))

    def _outputs(self, mm=None):
        out = []
        for verb in self.VERBS:
            cmd = [sys.executable, "-I", mm or MM_PATH, "--profile", self.prof, "--data", self.data, *verb]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            out.append((verb, r.returncode, self._ages(r.stdout), r.stderr))
        return out

    @staticmethod
    def _ages(text):
        """Mask whole-second ages (`x_s=N`, `"x_s": N`): two runs a second apart differ there and nowhere else."""
        text = re.sub(r'("\w+_s": )\d+', r"\1N", text)
        return re.sub(r"\b(\w+_s=)\d+", r"\1N", text)

    def test_other_verbs_unchanged_with_and_without_notify(self):
        self._golden_data()
        without = self._outputs()
        self.assertFalse(os.path.exists(self.notify_dir()), "no [notify]: no notify folder")
        self.write_profile(self.notify_cfg())
        with_notify = self._outputs()
        self.assertEqual(with_notify, without)
        self.assertEqual(self.fake.posts(), [], "status, alerts, explain, place never send")

    def test_existing_verbs_byte_for_byte_as_base_commit(self):
        """No [notify]: the existing verbs print what main printed before `mm notify` (A5: check only adds notify=off)."""
        git = shutil.which("git")
        if not git or subprocess.run([git, "-C", CODE, "rev-parse", "--verify", "-q", BASE_COMMIT + "^{commit}"],
                                     capture_output=True).returncode != 0:
            self.skipTest("no git checkout with %s" % BASE_COMMIT)
        old = os.path.join(self.root, "old")
        os.makedirs(old)
        arch = subprocess.run([git, "-C", CODE, "archive", "--format=tar", BASE_COMMIT, "bin", "core", "adapters",
                               "schemas", "settings.default.toml", "profiles"], capture_output=True)
        self.assertEqual(arch.returncode, 0, arch.stderr)
        subprocess.run(["tar", "-x", "-C", old], input=arch.stdout, check=True)
        self._golden_data()
        old_mm = os.path.join(old, "bin", "mm")
        self.assertEqual(self._outputs(), self._outputs(old_mm))
        old_check = subprocess.run([sys.executable, "-I", "-c", CHECK_SHIM, old_mm, "check", "--profile", self.prof,
                                    "--data", self.data], capture_output=True, text=True, timeout=60)
        new_check = self.cli("check")
        self.assertEqual([line for line in new_check.stdout.splitlines() if "notify=" not in line],
                         old_check.stdout.splitlines())
        self.assertEqual(new_check.returncode, old_check.returncode)


# the check fixture's stable readings, for any bin/mm (argv[1])
CHECK_SHIM = """import os, runpy, sys
mm = sys.argv[1]
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(mm)), "core"))
import mmread
from unittest.mock import patch
sys.argv = sys.argv[1:]
with patch.object(mmread, "check_readings", return_value=([], {}, {})):
    runpy.run_path(mm, run_name="__main__")
"""


# =============================================================================================== 1. validation


class Validation(NotifyBase):
    def check_lines(self):
        r = self.cli("check")
        return r.returncode, r.stdout.splitlines()

    def test_valid_sections_check_ok(self):
        port = self.fake.port
        cases = [{}, {"url": "http://localhost:%d" % port}, {"url": "http://[::1]:%d" % port},
                 {"url": "https://ntfy.example.net"}, {"url": "https://ntfy.example.net/base"},
                 {"topic": "a"}, {"topic": "A_b-9" * 12 + "abcd"},
                 {"alert_levels": ["INFO", "ATTENTION", "ACTION"], "ring_levels": []},
                 {"alert_levels": [], "send_cleared": False},
                 {"alerts_per_hour": 1, "timeout_s": 1, "ring_retry_s": 30, "ring_expire_s": 60},
                 {"alerts_per_hour": 600, "timeout_s": 30, "ring_retry_s": 3600, "ring_expire_s": 10800},
                 {"url": "https://" + "a" * 496 + ".example"}]  # 512 characters
        self.assertEqual(len(cases[-1]["url"]), 512)
        self.assertEqual(len(cases[6]["topic"]), 64)
        for over in cases:
            with self.subTest(over=over):
                self.write_profile(self.notify_cfg(**over))
                rc, lines = self.check_lines()
                self.assertEqual(rc, 0, lines)
                self.assertTrue(any("notify=ok" in line and "service=ntfy" in line for line in lines), lines)
        self.write_secret()
        self.write_profile(self.notify_cfg(secret_file=self.secret_file))
        rc, lines = self.check_lines()
        self.assertEqual(rc, 0, lines)
        self.assertEqual(self.fake.posts(), [])

    def test_check_online_sends_nothing(self):
        self.cli("check", "--online")
        self.assertEqual(self.fake.posts(), [])

    BAD = [
        ("colour", {"colour": "red"}),
        ("enabled", {"enabled": "yes"}),
        ("service", {"service": "email"}),
        ("service", {"service": 1}),
        ("url", {"url": None}),  # ntfy needs its server
        ("url", {"url": "ftp://127.0.0.1/x"}),
        ("url", {"url": "http://ntfy.example.net"}),  # http only to loopback
        ("url", {"url": "http://10.0.0.1:8080"}),
        ("url", {"url": "https://user:pw" + AT + "ntfy.example.net"}),
        ("url", {"url": "https://user" + AT + "ntfy.example.net"}),
        ("url", {"url": "https://ntfy.example.net/?a=1"}),
        ("url", {"url": "https://ntfy.example.net/#frag"}),
        ("url", {"url": "https://"}),
        ("url", {"url": "ntfy.example.net"}),
        ("url", {"url": "https://" + "a" * 497 + ".example"}),  # 513 characters
        ("url", {"url": 5}),
        ("topic", {"topic": None}),
        ("topic", {"topic": "bad topic"}),
        ("topic", {"topic": "a/b"}),
        ("topic", {"topic": ""}),
        ("topic", {"topic": "a" * 65}),
        ("secret_file", {"secret_file": 7}),
        ("alert_levels", {"alert_levels": ["CRITICAL"]}),
        ("alert_levels", {"alert_levels": "ACTION"}),
        ("ring_levels", {"ring_levels": ["LOUD"]}),
        ("send_cleared", {"send_cleared": 1}),
        ("alerts_per_hour", {"alerts_per_hour": 0}),
        ("alerts_per_hour", {"alerts_per_hour": 601}),
        ("alerts_per_hour", {"alerts_per_hour": True}),
        ("alerts_per_hour", {"alerts_per_hour": "30"}),
        ("timeout_s", {"timeout_s": 0}),
        ("timeout_s", {"timeout_s": 31}),
        ("ring_retry_s", {"ring_retry_s": 29}),
        ("ring_retry_s", {"ring_retry_s": 3601}),
        ("ring_expire_s", {"ring_expire_s": 59}),
        ("ring_expire_s", {"ring_expire_s": 10801}),
    ]

    def test_bad_sections_are_E_PROFILE_naming_the_key(self):
        for key, over in self.BAD:
            with self.subTest(key=key, over=over):
                self.write_profile(self.notify_cfg(**over))
                rc, lines = self.check_lines()
                self.assertEqual(rc, 1, lines)
                bad = [line for line in lines if line.startswith("E_PROFILE")]
                self.assertTrue(any(key in line for line in bad), lines)
                self.assertFalse(any("notify=ok" in line for line in lines), lines)
        self.assertEqual(self.fake.posts(), [])

    def test_bad_section_is_E_PROFILE_at_use(self):
        for key, over in (("url", {"url": "http://ntfy.example.net"}), ("colour", {"colour": "red"}),
                          ("timeout_s", {"timeout_s": 31})):
            with self.subTest(key=key):
                self.write_profile(self.notify_cfg(**over))
                for args in (("notify", "test"), ("notify", "run")):
                    r = self.cli(*args)
                    self.assert_error(r, "E_PROFILE", 2)
                    self.assertIn(key, r.stdout)
        self.assertEqual(self.fake.posts(), [])

    def test_pushover_rules(self):
        self.write_profile({"enabled": True, "service": "pushover", "url": self.fake.url + "/1/messages.json"})
        rc, lines = self.check_lines()
        self.assertEqual(rc, 1, lines)
        self.assertTrue(any(line.startswith("E_PROFILE") and "secret_file" in line for line in lines), lines)
        for url in ("http://api.example.net/1/messages.json", "https://u:p" + AT + "api.example.net/1/messages.json",
                    "https://api.example.net/1/messages.json?x=1"):
            with self.subTest(url=url):
                self.write_profile({"enabled": True, "service": "pushover", "url": url,
                                    "secret_file": self.secret_file})
                rc, lines = self.check_lines()
                self.assertEqual(rc, 1, lines)
                self.assertTrue(any(line.startswith("E_PROFILE") and "url" in line for line in lines), lines)
        self.write_secret({"app_token": self.app_token, "user_key": self.user_key})
        for over in ({}, {"url": None}):  # the default Pushover URL when left out
            self.write_profile({k: v for k, v in dict({"enabled": True, "service": "pushover",
                                                       "url": self.fake.url + "/1/messages.json",
                                                       "secret_file": self.secret_file}, **over).items()
                                if v is not None})
            rc, lines = self.check_lines()
            self.assertEqual(rc, 0, lines)
            self.assertTrue(any("notify=ok" in line and "service=pushover" in line for line in lines), lines)
        self.assertEqual(self.fake.posts(), [])


# =============================================================================================== 3. the secret file


class SecretFile(NotifyBase):
    service = "pushover"

    def assert_secret_refused(self, needles=()):
        r = self.cli("notify", "test")
        self.assert_error(r, "E_NOTIFY_SECRET", 2)
        for n in (self.app_token, self.user_key) + tuple(needles):
            self.assertNotIn(n, r.stdout + r.stderr)
        return r

    def test_good_secret_delivers(self):
        self.write_secret()
        r = self.cli("notify", "test")
        self.assertEqual(r.returncode, 0, r.stdout)
        form = self.fake.forms()[0]
        self.assertEqual((form["token"], form["user"]), (self.app_token, self.user_key))
        self.assertNotIn(self.app_token, r.stdout)

    def test_mode_bits_and_links_are_refused(self):
        for mode in (0o640, 0o604, 0o660, 0o644, 0o610, 0o601):
            with self.subTest(mode=oct(mode)):
                self.write_secret(mode=mode)
                self.assert_secret_refused()
                self.assertEqual(self.status().get("secret"), "bad")
        real = os.path.join(self.root, "real-secret.json")
        self.write_secret()
        os.replace(self.secret_file, real)
        os.symlink(real, self.secret_file)
        self.assert_secret_refused()
        os.unlink(self.secret_file)
        os.mkdir(self.secret_file)
        self.assert_secret_refused()
        self.assertEqual(self.fake.posts(), [])

    def test_bad_content_is_refused_without_showing_it(self):
        marker = "Zq" + alnum(20)
        a, u = self.app_token, self.user_key
        cases = [
            {"app_token": a, "user_key": u, "extra": marker},
            {"app_token": a},
            {"user_key": u},
            {"app_token": a + "!" + marker[:5], "user_key": u},
            {"app_token": a, "user_key": "u" * 65},
            {"app_token": "", "user_key": u},
            {"app_token": 12345, "user_key": u},
            {"token": marker},
            [a, u],
        ]
        raws = ['{"app_token": "%s", "app_token": "%s", "user_key": "%s"}' % (a, marker, u),
                '{"app_token": "%s", "user_key": "%s", "n": NaN}' % (a, u),
                '{"app_token": "%s", "user_key": "%s", "n": Infinity}' % (a, u),
                "not json " + marker,
                json.dumps({"app_token": a, "user_key": u, "pad": "x" * 4100}),
                ""]
        for obj in cases:
            with self.subTest(obj=obj):
                self.write_secret(obj)
                self.assert_secret_refused((marker,))
        for raw in raws:
            with self.subTest(raw=raw[:40]):
                self.write_secret(raw=raw)
                self.assert_secret_refused((marker,))
        self.assertEqual(self.fake.posts(), [])

    def test_missing_secret(self):
        r = self.cli("notify", "test")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertEqual(self.status().get("secret"), "missing")
        self.assertEqual(self.fake.posts(), [])

    def test_ntfy_token_rules(self):
        self.service = "ntfy"
        self.write_profile(self.notify_cfg(secret_file=self.secret_file))
        for obj in ({"token": self.ntfy_token, "other": "x"}, {"token": "bad token"}, {"token": "t" * 129},
                    {"app_token": self.app_token, "user_key": self.user_key}):
            with self.subTest(obj=obj):
                self.write_secret(obj)
                r = self.cli("notify", "test")
                self.assert_error(r, "E_NOTIFY_SECRET", 2)
                self.assertNotIn(self.ntfy_token, r.stdout)
                self.assertNotIn(self.app_token, r.stdout)
        self.write_secret({"token": self.ntfy_token}, mode=0o640)
        self.assert_error(self.cli("notify", "test"), "E_NOTIFY_SECRET", 2)
        self.assertEqual(self.fake.posts(), [])
        self.write_secret({"token": self.ntfy_token})
        self.assertEqual(self.cli("notify", "test").returncode, 0)
        self.assertEqual(self.fake.posts()[0]["headers"].get("authorization"), "Bearer " + self.ntfy_token)


# =============================================================================================== 4. grants


class Grants(NotifyBase):
    def test_grant_files_modes_and_hash_only(self):
        r = self.cli("notify", "grant", "agent-one")
        self.assertEqual(r.returncode, 0, r.stdout)
        g = kv(r.stdout)
        self.assertEqual((g["grant"], g["max_level"], g["per_hour"]), ("agent-one", "normal", "5"))
        key_file = g["key_file"]
        self.assertEqual(os.path.realpath(key_file),
                         os.path.realpath(os.path.join(self.notify_dir(), "keys", "agent-one.key")))
        self.assertEqual(stat.S_IMODE(os.lstat(key_file).st_mode), 0o600)
        self.assertTrue(stat.S_ISREG(os.lstat(key_file).st_mode))
        self.assertEqual(stat.S_IMODE(os.stat(self.notify_dir()).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.notify_dir(), "keys")).st_mode) & 0o077, 0)
        key = open(key_file).read().strip()
        self.assertRegex(key, r"^[0-9a-f]{64}$")
        grants = os.path.join(self.notify_dir(), "grants.json")
        self.assertEqual(stat.S_IMODE(os.stat(grants).st_mode), 0o600)
        text = open(grants).read()
        self.assertNotIn(key, text)
        self.assertIn(hashlib.sha256(key.encode()).hexdigest(), text)  # A6
        self.assertNotIn(key, r.stdout, "grant prints the key file, never the key")
        for args in (("notify", "grants"), ("--json", "notify", "grants"), ("notify", "status"),
                     ("--json", "notify", "status")):
            out = self.cli(*args)
            self.assertNotIn(key, out.stdout, args)
            if "grants" in args:
                self.assertIn("agent-one", out.stdout)
        listed = json.loads(self.cli("--json", "notify", "grants").stdout)
        self.assertIsInstance(listed, dict)
        self.assertEqual(self.status().get("grants"), "1")
        self.assert_nowhere([key], skip={key_file})

    def test_options_and_ranges(self):
        for extra, want in ((("--max-level", "ring", "--per-hour", "60"), ("ring", "60")),
                            (("--max-level", "quiet", "--per-hour", "1"), ("quiet", "1")),
                            (("--per-hour", "7"), ("normal", "7"))):
            with self.subTest(extra=extra):
                g = kv(self.cli("notify", "grant", "agent-x", *extra).stdout)
                self.assertEqual((g.get("max_level"), g.get("per_hour")), want)
        for extra in (("--max-level", "loud"), ("--max-level", ""), ("--per-hour", "0"), ("--per-hour", "61"),
                      ("--per-hour", "-1"), ("--per-hour", "x"), ("--per-hour", "1.5")):
            with self.subTest(extra=extra):
                self.assert_refused(self.cli("notify", "grant", "agent-y", *extra))
        self.assertFalse(os.path.exists(os.path.join(self.notify_dir(), "keys", "agent-y.key")))

    def test_name_rules(self):
        for name in ("a", "9", "a" * 40, "x-1-", "agent-two"):
            with self.subTest(name=name):
                self.grant(name)
                self.assertTrue(os.path.isfile(os.path.join(self.notify_dir(), "keys", name + ".key")))
        for name in ("Agent", "-x", "a" * 41, "a_b", "a.b", "../x", "x/y", "", "ag ent", "é"):
            with self.subTest(name=name):
                self.assert_refused(self.cli("notify", "grant", name))
        keys_dir = os.path.join(self.notify_dir(), "keys")
        keys = os.listdir(keys_dir) if os.path.isdir(keys_dir) else []
        self.assertEqual(sorted(keys), sorted(n + ".key" for n in ("a", "9", "a" * 40, "x-1-", "agent-two")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "x.key")))
        self.assertFalse(os.path.exists(os.path.join(self.data, "x.key")))

    def test_regrant_replaces_and_revoke_removes(self):
        key_file = self.grant("agent-one")
        old = open(key_file).read()
        old_copy = os.path.join(self.root, "old.key")
        with open(old_copy, "w") as f:
            f.write(old)
        os.chmod(old_copy, 0o600)
        self.assert_delivered(self.send(old_copy, "first"))
        self.assertEqual(self.grant("agent-one"), key_file)
        new = open(key_file).read()
        self.assertNotEqual(new.strip(), old.strip())
        r = self.send(old_copy, "second")
        self.assert_error(r, "E_NOTIFY_KEY", 2)
        self.assertNotIn(old.strip(), r.stdout)
        self.assert_delivered(self.send(key_file, "third"))
        new_copy = os.path.join(self.root, "new.key")
        with open(new_copy, "w") as f:
            f.write(new)
        r = self.cli("notify", "revoke", "agent-one")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertFalse(os.path.exists(key_file))
        self.assertNotIn("agent-one", self.cli("notify", "grants").stdout)
        self.assertEqual(self.status().get("grants"), "0")
        self.assert_error(self.send(new_copy, "fourth"), "E_NOTIFY_KEY", 2)
        self.assertEqual([b["title"] for b in self.fake.ntfy()], ["[agent-one] first", "[agent-one] third"])
        r = self.cli("notify", "revoke", "agent-one")  # nothing found: exit 1 (repo rule), nothing changed
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assert_refused(self.cli("notify", "revoke", "../grants"))


# =============================================================================================== 5. send


class Send(NotifyBase):
    def test_delivered_ntfy_request(self):
        key_file = self.grant("agent-one")
        r = self.send(key_file, "Build done", "normal", "all green", "--tag", "build", "--tag", "ci")
        msg_id = self.assert_delivered(r)
        [req] = self.fake.posts()
        self.assertEqual(req["method"], "POST")
        self.assertIn(req["path"], ("", "/"))  # A15
        self.assertTrue(req["headers"].get("content-type", "").startswith("application/json"), req["headers"])
        self.assertNotIn("authorization", req["headers"], "no token configured: no Authorization header")
        body = json.loads(req["body"])
        self.assertEqual(body["topic"], "mm-alerts")
        self.assertEqual(body["title"], "[agent-one] Build done")
        self.assertEqual(body["message"], "all green")
        self.assertEqual(body["priority"], 3)
        self.assertEqual(body.get("tags"), ["build", "ci"])
        [rec] = self.sent()
        self.assertEqual((rec["id"], rec["source"], rec["sender"], rec["level"], rec["status"]),
                         (msg_id, "agent", "agent-one", "normal", "delivered"))
        self.assertIn(rec["error"], (None, ""))
        self.assertNotEqual(self.status().get("last_delivery"), "none")

    def test_bearer_token_when_secret_file_set(self):
        self.write_secret()
        self.write_profile(self.notify_cfg(secret_file=self.secret_file))
        self.assert_delivered(self.send(self.grant(), "hello"))
        self.assertEqual(self.fake.posts()[0]["headers"].get("authorization"), "Bearer " + self.ntfy_token)
        self.assert_nowhere([self.ntfy_token], skip={self.secret_file})

    def test_sender_comes_from_the_grant(self):
        key_file = self.grant("agent-one")
        self.assert_refused(self.send(key_file, "spoof", "normal", None, "--sender", "mm"))  # A8
        self.assertEqual(self.fake.posts(), [])
        self.assert_delivered(self.send(key_file, "[mm] DISK_LOW"))
        self.assertEqual(self.fake.ntfy()[0]["title"], "[agent-one] [mm] DISK_LOW")

    def test_bad_keys(self):
        self.grant("agent-one")
        wrong = os.path.join(self.root, "wrong.key")
        other = secrets.token_hex(32)
        for content in (other + "\n", "not hex", "", other.upper()[:10]):
            with open(wrong, "w") as f:
                f.write(content)
            os.chmod(wrong, 0o600)
            with self.subTest(content=content[:12]):
                r = self.send(wrong, "hello")
                self.assert_error(r, "E_NOTIFY_KEY", 2)
                if content.strip():
                    self.assertNotIn(content.strip(), r.stdout)
        self.assertEqual(self.send(os.path.join(self.root, "missing.key"), "hello").returncode, 2)  # A9
        self.assertEqual(self.fake.posts(), [])

    def test_key_file_from_env(self):
        key_file = self.grant("agent-one")
        self.assert_delivered(self.send(None, "from env", env={"MM_NOTIFY_KEY_FILE": key_file}))
        self.assertEqual(self.fake.ntfy()[0]["title"], "[agent-one] from env")
        self.assertEqual(self.send(None, "no key").returncode, 2)

    def test_level_limit_of_the_grant(self):
        key_file = self.grant("agent-one")  # max normal
        self.assert_error(self.send(key_file, "loud", "ring"), "E_NOTIFY_LEVEL", 2)
        quiet = self.grant("agent-quiet", "--max-level", "quiet")
        self.assert_error(self.send(quiet, "normal", "normal"), "E_NOTIFY_LEVEL", 2)
        self.assertEqual(self.fake.posts(), [])
        ring = self.grant("agent-ring", "--max-level", "ring", "--per-hour", "10")
        for level in ("quiet", "normal", "ring"):
            self.assert_delivered(self.send(ring, "level " + level, level))
        self.assertEqual([b["priority"] for b in self.fake.ntfy()], [2, 3, 5])
        self.assert_refused(self.send(ring, "x", "loud"))

    def test_per_hour_limit(self):
        key_file = self.grant("agent-one", "--per-hour", "2")
        self.assert_delivered(self.send(key_file, "one"))
        self.assert_delivered(self.send(key_file, "two"))
        r = self.send(key_file, "three")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("E_NOTIFY_LIMIT", r.stdout)  # A2
        self.assertEqual(len(self.fake.posts()), 2)
        self.assertEqual(self.sent()[-1]["status"], "limited")
        self.assertEqual(self.send(key_file, "four", offset=1800).returncode, 1, "still inside the rolling hour")
        self.assert_delivered(self.send(key_file, "five", offset=3700))
        self.assertEqual([b["title"] for b in self.fake.ntfy()], ["[agent-one] one", "[agent-one] two",
                                                                   "[agent-one] five"])

    def test_duplicate_within_600_s(self):
        key_file = self.grant("agent-one", "--per-hour", "20")
        self.assert_delivered(self.send(key_file, "A", "normal", "x"))
        r = self.send(key_file, "A", "normal", "x")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("E_NOTIFY_DUPLICATE", r.stdout)
        self.assertEqual(self.sent()[-1]["status"], "duplicate")
        self.assert_delivered(self.send(key_file, "A", "normal", "y"))
        self.assert_delivered(self.send(key_file, "B", "normal", "x"))
        self.assertEqual(self.send(key_file, "A", "normal", "x", offset=500).returncode, 1)
        other = self.grant("agent-two")
        self.assert_delivered(self.send(other, "A", "normal", "x"))  # another sender
        self.assert_delivered(self.send(key_file, "A", "normal", "x", offset=1200))  # > 600 s after any try
        self.assertEqual(len(self.fake.posts()), 5)

    def test_text_cleaned_masked_and_bounded(self):
        key_file = self.grant("agent-one", "--per-hour", "20")
        ghp = "ghp_" + alnum(36)
        word = "hunter2" + alnum(12)
        r = self.send(key_file, "Build\x1b[31m red\x07 done\nnext", "normal",
                      "line one\nline\ttwo TOKEN=%s and %s ‮ end" % (word, ghp))
        self.assert_delivered(r)
        body = self.fake.ntfy()[0]
        for field in ("title", "message"):
            self.assertEqual(controls(body[field]), [], (field, body[field]))
        self.assertTrue(body["title"].startswith("[agent-one] Build"), body["title"])
        self.assertIn("line one", body["message"])
        self.assertNotIn(word, body["message"])
        self.assertNotIn(ghp, body["message"])
        self.assertIn("***", body["message"])
        self.assert_nowhere([word, ghp])
        r = self.send(key_file, "T" * 300, "normal", "x" * 5000)
        if r.returncode == 0:  # A11: cut, or refused
            body = self.fake.ntfy()[-1]
            self.assertLessEqual(len(body["title"]), len("[agent-one] ") + 100)
            self.assertLessEqual(len(body["message"]), 1000)
        else:
            self.assertEqual(r.returncode, 2, r.stdout)
            self.assertEqual(len(self.fake.posts()), 1)
        r = self.send(key_file, "tags", "normal", None, *sum((["--tag", t] for t in ("a", "b", "c", "d", "e")), []))
        if r.returncode == 0:
            tags = self.fake.ntfy()[-1].get("tags") or []
            self.assertLessEqual(len(tags), 4)
        else:
            self.assertEqual(r.returncode, 2)
        r = self.send(key_file, "badtag", "normal", None, "--tag", "a b\r\nX-Evil: 1")
        if r.returncode == 0:
            for t in self.fake.ntfy()[-1].get("tags") or []:
                self.assertRegex(t, r"^[A-Za-z0-9_-]{1,32}$")
        else:
            self.assertEqual(r.returncode, 2)

    def test_usage_errors(self):
        key_file = self.grant("agent-one")
        for args in (("notify", "send", "--key-file", key_file, "--level", "normal"),
                     ("notify", "send", "--key-file", key_file, "--title", "x", "--level", "loud"),
                     ("notify", "send", "--key-file", key_file, "--title", "x", "--level", "normal", "extra"),
                     ("notify", "bogus"), ("notify",)):
            with self.subTest(args=args):
                self.assert_refused(self.cli(*args))
        self.assertEqual(self.fake.posts(), [])

    def test_help_lists_the_verbs(self):
        out = self.cli("help").stdout  # help is at most 30 lines of 100 characters (test_cli): owner verbs share a line
        self.assertIn("mm notify send", out)
        line = next(l for l in out.splitlines() if "mm notify grant" in l)
        for verb in ("revoke", "grants", "run", "test", "status"):
            self.assertRegex(line, r"\b%s\b" % verb)


class SendPushover(NotifyBase):
    service = "pushover"

    def test_pushover_form_and_priorities(self):
        self.write_secret()
        self.write_profile(self.notify_cfg(ring_retry_s=45, ring_expire_s=900))
        key_file = self.grant("agent-one", "--max-level", "ring", "--per-hour", "10")
        for level in ("quiet", "normal", "ring"):
            self.assert_delivered(self.send(key_file, "p " + level, level, "body " + level))
        reqs = self.fake.posts()
        self.assertEqual([r["path"] for r in reqs], ["/1/messages.json"] * 3)
        for r in reqs:
            self.assertEqual(r["method"], "POST")
            self.assertTrue(r["headers"].get("content-type", "").startswith("application/x-www-form-urlencoded"))
            self.assertNotIn("authorization", r["headers"])
        forms = self.fake.forms()
        for form, level, prio in zip(forms, ("quiet", "normal", "ring"), ("-1", "0", "2")):
            self.assertEqual(form["token"], self.app_token)
            self.assertEqual(form["user"], self.user_key)
            self.assertEqual(form["title"], "[agent-one] p " + level)
            self.assertEqual(form["message"], "body " + level)
            self.assertEqual(form["priority"], prio)
        self.assertEqual((forms[2]["retry"], forms[2]["expire"]), ("45", "900"))
        self.assert_nowhere([self.app_token, self.user_key], skip={self.secret_file})


# =============================================================================================== 6. delivery failures


class Failures(NotifyBase):
    def test_500_queues_and_run_retries_after_backoff(self):
        key_file = self.grant("agent-one")
        self.fake.default = 500
        self.assert_queued(self.send(key_file, "retry me", "normal", "body"))
        self.assertEqual(len(self.fake.posts()), 1)
        self.assertEqual(self.status().get("queued"), "1")
        rec = self.sent()[-1]
        self.assertEqual((rec["status"], rec["error"]), ("queued", "E_NOTIFY_HTTP"))
        self.cli("notify", "run")  # not due yet
        self.assertEqual(len(self.fake.posts()), 1, "no retry before 30 s")
        self.cli("notify", "run", offset=40)  # due: tried again, fails again (backoff now 60 s)
        self.assertEqual(len(self.fake.posts()), 2)
        self.cli("notify", "run", offset=75)
        self.assertEqual(len(self.fake.posts()), 2, "the second backoff is 60 s")
        self.fake.default = 200
        r = self.cli("notify", "run", offset=115)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(len(self.fake.posts()), 3)
        self.assertEqual(self.fake.ntfy()[-1]["title"], "[agent-one] retry me")
        self.assertEqual(self.status(offset=115).get("queued"), "0")
        self.assertIn("delivered", [x["status"] for x in self.sent()])
        self.cli("notify", "run", offset=500)
        self.assertEqual(len(self.fake.posts()), 3, "delivered once")

    def test_outbox_item_dropped_after_one_hour(self):
        key_file = self.grant("agent-one")
        self.fake.default = 503
        self.assert_queued(self.send(key_file, "old"))
        self.cli("notify", "run", offset=3700)
        self.assertEqual(self.status(offset=3700).get("queued"), "0")
        self.assertIn("dropped", [x["status"] for x in self.sent()])

    def test_4xx_refused_not_retried(self):
        key_file = self.grant("agent-one")
        self.fake.responses = [400]
        r = self.send(key_file, "refused")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("E_NOTIFY_REFUSED", r.stdout)
        self.assertEqual(self.status().get("queued"), "0")
        self.assertEqual((self.sent()[-1]["status"], self.sent()[-1]["error"]), ("refused", "E_NOTIFY_REFUSED"))
        self.cli("notify", "run", offset=60)
        self.cli("notify", "run", offset=400)
        self.assertEqual(len(self.fake.posts()), 1)

    def test_redirect_not_followed(self):
        self.write_secret()
        self.write_profile(self.notify_cfg(secret_file=self.secret_file))
        key_file = self.grant("agent-one")
        self.fake.responses = [302]
        self.assert_queued(self.send(key_file, "moved"))
        self.assertEqual([r["path"] for r in self.fake.posts() if "followed" in r["path"]], [])
        self.assertEqual(len(self.fake.posts()), 1)
        self.assertEqual(self.sent()[-1]["error"], "E_NOTIFY_HTTP")

    def test_connection_refused_and_timeout_are_retryable(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
        s.close()
        self.write_profile(self.notify_cfg(url="http://127.0.0.1:%d" % closed))
        key_file = self.grant("agent-one")
        self.assert_queued(self.send(key_file, "nobody"))
        self.assertEqual(self.sent()[-1]["error"], "E_NOTIFY_NET")
        self.write_profile(self.notify_cfg(timeout_s=1))
        self.fake.responses = ["hang"]
        t0 = time.monotonic()
        self.assert_queued(self.send(key_file, "slow"))
        self.assertLess(time.monotonic() - t0, 2.9, "timeout_s bounds the request")
        self.assertEqual(self.sent()[-1]["error"], "E_NOTIFY_NET")
        self.assertEqual(self.status().get("queued"), "2")


# =============================================================================================== 7. run


class Run(NotifyBase):
    def test_first_run_starts_at_newest_then_sends_new(self):
        self.write_alerts(*[self.alert(i, "OLD_%d" % i, "ACTION") for i in (1, 2, 3)])
        r = self.cli("notify", "run")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(self.fake.posts(), [], "no history flood")
        self.assertEqual(self.status().get("cursor"), "3")
        self.write_alerts(self.alert(4, "MEM_RED", "ACTION", "memory RED: free 3%"),
                          self.alert(5, "IDLE_ROOM", "INFO", "queue idle 40 min"),
                          self.alert(6, "MEM_AMBER", "ATTENTION", "memory AMBER: free 45%"))
        r = self.cli("notify", "run")
        self.assertEqual(r.returncode, 0, r.stdout)
        bodies = self.fake.ntfy()
        self.assertEqual([(b["title"], b["priority"]) for b in bodies], [("[mm] MEM_RED", 5), ("[mm] MEM_AMBER", 3)])
        self.assertIn("memory RED: free 3%", bodies[0]["message"])
        self.assertIn("(machine %s)" % MID, bodies[0]["message"])
        self.assertEqual(self.status().get("cursor"), "6")
        recs = [x for x in self.sent() if x["status"] == "delivered"]
        self.assertEqual([(x["source"], x["sender"], x["level"]) for x in recs], [("mm", "mm", "ring"),
                                                                                 ("mm", "mm", "normal")])
        self.cli("notify", "run")
        self.assertEqual(len(self.fake.posts()), 2, "each alert once")

    def test_first_run_without_alerts_file(self):
        self.cli("notify", "run")
        self.write_alerts(self.alert(1, "DISK_LOW", "ACTION"))
        self.cli("notify", "run")
        self.assertEqual([b["title"] for b in self.fake.ntfy()], ["[mm] DISK_LOW"])

    def test_level_and_ring_maps_from_the_profile(self):
        self.write_profile(self.notify_cfg(alert_levels=["INFO", "ATTENTION"], ring_levels=["ATTENTION"]))
        self.write_alerts(self.alert(1, "BASE", "INFO"))
        self.cli("notify", "run")
        self.write_alerts(self.alert(2, "A_INFO", "INFO"), self.alert(3, "A_ATT", "ATTENTION"),
                          self.alert(4, "A_ACT", "ACTION"))
        self.cli("notify", "run")
        self.assertEqual([(b["title"], b["priority"]) for b in self.fake.ntfy()],
                         [("[mm] A_INFO", 3), ("[mm] A_ATT", 5)])

    def test_cleared_records(self):
        self.write_alerts(self.alert(1, "BASE", "ACTION"))
        self.cli("notify", "run")
        self.write_alerts(self.alert(2, "MEM_RED", why="cleared"))
        self.cli("notify", "run")
        [body] = self.fake.ntfy()
        self.assertEqual(body["priority"], 2, "cleared is quiet")
        self.assertIn("MEM_RED", body["title"] + body["message"])
        self.write_profile(self.notify_cfg(send_cleared=False))
        self.write_alerts(self.alert(3, "DISK_LOW", why="cleared"))
        self.cli("notify", "run")
        self.assertEqual(len(self.fake.posts()), 1)

    def test_alerts_per_hour_suppressed_then_notice_first(self):
        self.write_profile(self.notify_cfg(alerts_per_hour=2))
        self.write_alerts(self.alert(1, "BASE", "ACTION"))
        self.cli("notify", "run")
        self.write_alerts(*[self.alert(i, "ALERT_%d" % i, "ATTENTION") for i in range(2, 7)])
        self.cli("notify", "run")
        self.assertEqual([b["title"] for b in self.fake.ntfy()], ["[mm] ALERT_2", "[mm] ALERT_3"])
        self.assertEqual([x["status"] for x in self.sent()].count("suppressed"), 3)
        self.write_alerts(self.alert(7, "LATER", "ACTION"))
        self.cli("notify", "run", offset=3700)
        later = self.fake.ntfy()[2:]
        self.assertEqual(len(later), 2, later)
        self.assertIn("3 alerts suppressed", later[0]["title"] + " " + later[0]["message"])  # A13
        self.assertEqual(later[0]["priority"], 2)
        self.assertEqual((later[1]["title"], later[1]["priority"]), ("[mm] LATER", 5))

    def test_at_most_20_deliveries_per_run(self):
        self.write_profile(self.notify_cfg(alerts_per_hour=600))
        self.write_alerts(self.alert(1, "BASE", "ACTION"))
        self.cli("notify", "run")
        self.write_alerts(*[self.alert(i, "MANY_%02d" % i, "ACTION") for i in range(2, 27)])
        self.cli("notify", "run")
        self.assertEqual(len(self.fake.posts()), 20)
        self.cli("notify", "run")
        titles = [b["title"] for b in self.fake.ntfy()]
        self.assertEqual(sorted(titles), sorted("[mm] MANY_%02d" % i for i in range(2, 27)))

    def test_failed_alert_delivery_is_queued(self):
        self.write_alerts(self.alert(1, "BASE", "ACTION"))
        self.cli("notify", "run")
        self.fake.default = 500
        self.write_alerts(self.alert(2, "DISK_LOW", "ACTION"))
        self.assertEqual(self.cli("notify", "run").returncode, 1)
        self.assertEqual(self.status().get("queued"), "1")
        self.fake.default = 200
        self.assertEqual(self.cli("notify", "run", offset=40).returncode, 0)
        self.assertEqual([b["title"] for b in self.fake.ntfy()], ["[mm] DISK_LOW"] * 2)
        self.assertEqual(self.status(offset=40).get("queued"), "0")


# =============================================================================================== 8. sent.jsonl, secrets


class Records(NotifyBase):
    service = "pushover"

    def test_one_record_per_outcome_no_text_no_secret(self):
        self.write_secret()
        self.write_profile(self.notify_cfg(alerts_per_hour=1))
        text_marker = "TextMarker" + alnum(8)
        self.write_alerts(self.alert(1, "BASE", "ACTION"))
        self.cli("notify", "run")  # the first run before any send (A30)
        key_file = self.grant("agent-one", "--per-hour", "10")
        key = open(key_file).read().strip()
        self.assert_delivered(self.send(key_file, "ok", "normal", text_marker))       # delivered
        self.assertEqual(self.send(key_file, "ok", "normal", text_marker).returncode, 1)  # duplicate
        self.fake.responses = [500]
        self.assert_queued(self.send(key_file, "later", "normal", text_marker))      # queued
        self.fake.responses = [403]
        self.assertEqual(self.send(key_file, "no", "normal", text_marker).returncode, 2)  # refused
        small = self.grant("agent-two", "--per-hour", "1")
        self.assert_delivered(self.send(small, "b1", "normal", text_marker))          # delivered
        self.assertEqual(self.send(small, "b2", "normal", text_marker).returncode, 1)  # limited
        self.write_alerts(self.alert(2, "A_ONE", "ACTION", text_marker), self.alert(3, "A_TWO", "ACTION", text_marker))
        self.cli("notify", "run")                                                   # delivered + suppressed
        for args in (("notify", "status"), ("--json", "notify", "status"), ("notify", "grants"),
                     ("--json", "notify", "grants"), ("check",)):
            self.cli(*args)
        recs = self.sent()
        for rec in recs:
            self.assertTrue(SENT_FIELDS <= set(rec), rec)
            self.assertIn(rec["status"], STATUSES)
            self.assertIn(rec["source"], ("mm", "agent"))
            self.assertIn(rec["level"], ("quiet", "normal", "ring"))
            self.assertNotIn("text", rec)
            self.assertNotIn("message", rec)
        by = [(r["source"], r["status"]) for r in recs]
        for want, n in ((("agent", "delivered"), 2), (("agent", "duplicate"), 1), (("agent", "queued"), 1),
                        (("agent", "refused"), 1), (("agent", "limited"), 1), (("mm", "delivered"), 1),
                        (("mm", "suppressed"), 1)):
            self.assertEqual(by.count(want), n, (want, by))
        sent_file = os.path.join(self.notify_dir(), "sent.jsonl")
        self.assertEqual(stat.S_IMODE(os.stat(sent_file).st_mode) & 0o077, 0)
        raw = open(sent_file).read()
        self.assertNotIn(text_marker, raw)
        for name in os.listdir(self.notify_dir()):
            p = os.path.join(self.notify_dir(), name)
            if os.path.isfile(p):
                self.assertEqual(stat.S_IMODE(os.stat(p).st_mode) & 0o077, 0, name)
        self.assert_nowhere([self.app_token, self.user_key], skip={self.secret_file})
        self.assert_nowhere([key], skip={key_file})


# =============================================================================================== 9. test, status


class TestAndStatus(NotifyBase):
    def test_test_message(self):
        r = self.cli("notify", "test")
        self.assertEqual(r.returncode, 0, r.stdout)
        [body] = self.fake.ntfy()
        self.assertIn("machine-manager test from %s" % MID, body["title"] + " " + body["message"])
        self.assertEqual(self.cli("notify", "test", "--level", "ring").returncode, 0)
        self.assertEqual(self.fake.ntfy()[1]["priority"], 5)
        self.assertEqual(self.cli("notify", "test", "--level", "quiet").returncode, 0)
        self.assertEqual(self.fake.ntfy()[2]["priority"], 2)
        self.assert_refused(self.cli("notify", "test", "--level", "loud"))
        self.assertEqual(len(self.fake.posts()), 3)

    def test_status_fields(self):
        st = self.status()
        for key in ("notify", "service", "host", "secret", "cursor", "queued", "last_delivery", "grants"):
            self.assertIn(key, st)
        self.assertEqual((st["notify"], st["service"], st["host"], st["queued"], st["last_delivery"], st["grants"]),
                         ("on", "ntfy", "127.0.0.1", "0", "none", "0"))
        js = json.loads(self.cli("--json", "notify", "status").stdout)
        self.assertEqual((js["notify"], js["service"], js["host"]), ("on", "ntfy", "127.0.0.1"))  # A4
        self.write_profile(self.notify_cfg(url="http://localhost:%d" % self.fake.port))
        self.assertEqual(self.status()["host"], "localhost")
        self.grant("agent-one")
        self.grant("agent-two")
        self.assertEqual(self.status()["grants"], "2")
        self.cli("notify", "test")
        self.assertNotEqual(self.status()["last_delivery"], "none")
        self.write_alerts(self.alert(1, "A", "ACTION"), self.alert(2, "B", "ACTION"))
        self.cli("notify", "run")
        self.assertEqual(self.status()["cursor"], "2")

    def test_status_pushover_secret_states(self):
        self.service = "pushover"
        self.write_profile(self.notify_cfg())
        st = self.status()
        self.assertEqual((st["service"], st["host"], st["secret"]), ("pushover", "127.0.0.1", "missing"))
        self.write_secret()
        self.assertEqual(self.status()["secret"], "ok")
        self.write_secret(mode=0o644)
        self.assertEqual(self.status()["secret"], "bad")
        self.write_secret(raw="{")
        self.assertEqual(self.status()["secret"], "bad")
        self.assertEqual(self.fake.posts(), [], "status never sends")


# =============================================================================================== 10. the supervisor path


class SupervisorPath(NotifyBase):
    def test_supervisor_and_watchdog_do_not_import_notify(self):
        code = ("import sys; sys.path[:0] = [%r, %r]; import mmsuper, mmwatch, mmalerts; "
                "print(' '.join(sorted(m for m in sys.modules if 'notify' in m)))"
                % (os.path.join(CODE, "core"), os.path.join(CODE, "adapters")))
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "")

    def test_hook_and_status_send_nothing_and_hook_skips_network_module(self):
        self.write_alerts(self.alert(1, "MEM_RED", "ACTION"), self.alert(2, "DISK_LOW", "ATTENTION"))
        mods_py = os.path.join(self.root, "modules.py")
        with open(mods_py, "w") as f:
            f.write(MODULES_PY)
        for args, stdin in ((("hook", "--event", "PostToolUse"), json.dumps({"hook_event_name": "PostToolUse"})),
                            (("hook", "--event", "UserPromptSubmit"), json.dumps({"hook_event_name": "UserPromptSubmit",
                                                                                   "prompt": "hi"})),
                            (("status",), ""), (("alerts",), "")):
            out = os.path.join(self.root, "mods-%s.txt" % args[0])
            subprocess.run([sys.executable, "-I", mods_py, out, MM_PATH, "--profile", self.prof, "--data", self.data,
                            *args], input=stdin, capture_output=True, text=True, timeout=30)
            if args[0] == "hook":
                with open(out) as f:
                    mods = f.read().split()
                self.assertNotIn("mmnotify_send", mods, args)
                self.assertFalse([m for m in mods if "notify" in m], args)
        self.assertEqual(self.fake.posts(), [])


# =============================================================================================== 4c. durability, accounting


class Durability(NotifyBase):
    """Contract section 4c: no lost mm alert, alerts.jsonl rotation, sequence resets, hourly accounting outside the
    rotating sent.jsonl, the suppression notice's slot, outbox overflow, the whole backoff ladder and the 1-hour drop."""

    def titles(self):
        return [b["title"] for b in self.fake.ntfy()]

    def baseline(self, seq=1):
        """A first run at seq: the cursor starts there (no history), no alert is sent."""
        self.write_alerts(self.alert(seq, "BASE", "ACTION"))
        self.cli("notify", "run")
        self.assertEqual(self.status().get("cursor"), str(seq))
        self.assertNotIn("[mm] BASE", self.titles())

    def rotate_alerts(self):
        os.replace(os.path.join(self.data, "alerts.jsonl"), os.path.join(self.data, "alerts.jsonl.1"))

    # ---- 4c.1: no lost alert

    def test_unreadable_state_sends_nothing_then_each_alert_once(self):
        self.baseline()
        state = os.path.join(self.notify_dir(), "state.json")  # 4f.1: the one state file
        with open(state, "rb") as f:
            saved = f.read()
        self.write_alerts(self.alert(2, "W_2", "ACTION"), self.alert(3, "W_3", "ATTENTION"))
        os.unlink(state)
        os.mkdir(state)  # a folder in its place: it exists, but it is no valid document (4f.2)
        r = self.cli("notify", "run")
        self.assert_error(r, "E_NOTIFY_STATE", 2)
        self.assertEqual(self.fake.posts(), [], "A16: a run that cannot read its state sends nothing")
        os.rmdir(state)
        with open(state, "wb") as f:
            f.write(saved)
        os.chmod(state, 0o600)
        self.cli("notify", "run")
        self.cli("notify", "run")
        self.assertEqual(sorted(self.titles()), ["[mm] W_2", "[mm] W_3"], "each alert exactly once, nothing old")
        self.assertEqual(self.status().get("cursor"), "3")

    @unittest.skipIf(os.geteuid() == 0, "root ignores folder permissions")
    def test_read_only_notify_folder_loses_no_alert(self):
        self.baseline()
        self.write_alerts(*[self.alert(i, "RO_%d" % i, "ACTION") for i in (2, 3, 4)])
        os.chmod(self.notify_dir(), 0o500)  # read-only: no new file, no rename (write_atomic) in the notify folder
        try:
            r = self.cli("notify", "run")
        finally:
            os.chmod(self.notify_dir(), 0o700)
        if r.returncode == 0:  # the run set the folder back to 0700 itself: no write error happened
            self.assertEqual(sorted(self.titles()), ["[mm] RO_%d" % i for i in (2, 3, 4)])
        else:
            self.assertIn(r.returncode, (1, 2), "a state-file write error: exit 1 or 2 (%s)" % r.stdout)
            self.assertEqual(self.status().get("cursor"), "1", "the cursor did not move")
        self.assert_no_loss("RO_%d", (2, 3, 4))

    def test_sent_log_replaced_by_folder_loses_no_alert(self):
        self.baseline()
        self.write_alerts(*[self.alert(i, "SL_%d" % i, "ACTION") for i in (2, 3, 4)])
        sent = os.path.join(self.notify_dir(), "sent.jsonl")
        if os.path.exists(sent):
            os.unlink(sent)
        os.mkdir(sent)  # the record of each outcome cannot be appended
        r = self.cli("notify", "run")  # stderr empty: an error line, never a traceback (A16)
        self.assertIn(r.returncode, (0, 1, 2), r.stdout)
        os.rmdir(sent)
        self.assert_no_loss("SL_%d", (2, 3, 4))

    def assert_no_loss(self, pattern, seqs):
        """Runs now and over the next 17 minutes (past the longest backoff step, before the 1-hour drop): each alert
        arrived at least once (an outbox item counts only once delivered), BASE never; then no endless resending."""
        for offset in (0, 40, 120, 400, 1000):
            self.cli("notify", "run", offset=offset)
        got = self.titles()
        for i in seqs:
            self.assertGreaterEqual(got.count("[mm] " + pattern % i), 1,
                                    ("lost", i, got, self.status(offset=1000), self.sent()))
        self.assertNotIn("[mm] BASE", got)
        n = len(got)
        self.cli("notify", "run", offset=2000)
        self.assertEqual(len(self.fake.posts()), n, "no endless resending")

    def test_sigkill_during_delivery_loses_no_alert(self):
        self.baseline()
        self.write_alerts(*[self.alert(i, "K_%d" % i, "ACTION") for i in (2, 3, 4)])
        self.fake.responses = ["hold"]
        cmd = [sys.executable, "-I", MM_PATH, "--profile", self.prof, "--data", self.data, "notify", "run"]
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while not self.fake.posts() and time.monotonic() < deadline and p.poll() is None:
                time.sleep(0.02)
            self.assertEqual(len(self.fake.posts()), 1, "the run is inside its first delivery")
            p.kill()
        finally:
            if p.poll() is None:
                p.kill()
            p.wait(10)
        self.fake.release.set()
        self.assert_no_loss("K_%d", (2, 3, 4))  # the held request reached the service: it counts (A17)

    # ---- 4c.2: rotation

    def test_alert_rotated_to_dot_1_is_still_sent_once(self):
        self.baseline()
        self.write_alerts(self.alert(2, "R_2", "ACTION"))
        self.rotate_alerts()  # the record that made alerts.jsonl rotate; no alerts.jsonl yet
        self.cli("notify", "run")
        self.assertEqual(self.titles(), ["[mm] R_2"])
        self.write_alerts(self.alert(3, "R_3", "ACTION"))
        self.cli("notify", "run")
        self.assertEqual(self.titles(), ["[mm] R_2", "[mm] R_3"], "deduplicated by seq: R_2 not again")
        self.write_alerts(self.alert(4, "R_4", "ACTION"))
        self.rotate_alerts()  # .1 now holds R_3, R_4; a new alerts.jsonl gets R_5 before the next run
        self.write_alerts(self.alert(5, "R_5", "ACTION"))
        self.cli("notify", "run")
        self.cli("notify", "run")
        self.assertEqual(sorted(self.titles()), ["[mm] R_%d" % i for i in (2, 3, 4, 5)])
        self.assertEqual(self.status().get("cursor"), "5")

    # ---- 4c.3: sequence reset

    def test_sequence_reset_moves_cursor_and_sends_nothing_old(self):
        self.write_alerts(*[self.alert(i, "OLD_%d" % i, "ACTION") for i in range(1, 6)])
        self.cli("notify", "run")
        self.assertEqual(self.status().get("cursor"), "5")
        self.write_alerts(self.alert(1, "NEW_1", "ACTION"), self.alert(2, "NEW_2", "ACTION"))  # the store restarted
        self.cli("notify", "run")
        self.assertEqual(self.status().get("cursor"), "2", "the cursor resets to the last record's seq")
        self.assertEqual(self.titles(), [], "nothing old is sent")
        self.write_alerts(self.alert(3, "NEW_3", "ACTION"))
        self.cli("notify", "run")
        self.assertEqual(self.titles(), ["[mm] NEW_3"], "OLD_4 and OLD_5 stay unsent (A18)")
        self.cli("notify", "run")
        self.write_alerts(self.alert(4, "NEW_4", "ATTENTION"))
        self.cli("notify", "run")
        self.assertEqual(self.titles(), ["[mm] NEW_3", "[mm] NEW_4"])
        self.assertEqual(self.fake.ntfy()[1]["priority"], 3, "NEW_4 (ATTENTION), not OLD_4 (ACTION)")
        self.assertEqual(self.status().get("cursor"), "4")

    # ---- 4c.4: hourly accounting is not in sent.jsonl

    def test_rotating_sent_jsonl_resets_no_limit(self):
        self.write_profile(self.notify_cfg(alerts_per_hour=2))
        self.baseline()
        a = self.grant("agent-a", "--per-hour", "2")
        b = self.grant("agent-b", "--per-hour", "1")
        self.assert_delivered(self.send(a, "a1"))
        self.assert_delivered(self.send(a, "a2"))
        self.assert_delivered(self.send(b, "b1"))
        self.write_alerts(self.alert(2, "M_2", "ACTION"), self.alert(3, "M_3", "ACTION"))
        self.cli("notify", "run")
        self.assertEqual(len(self.fake.posts()), 5)
        sent = os.path.join(self.notify_dir(), "sent.jsonl")
        with open(sent) as f:
            last = json.loads(f.read().splitlines()[-1])
        with open(sent, "a") as f:  # A19: as if many `limited` records had been written
            i = 0
            while f.tell() < (1 << 20) + 1024:
                f.write(json.dumps(dict(last, id="pad%06d" % i, status="limited", error="E_NOTIFY_LIMIT")) + "\n")
                i += 1
        for key_file, title in ((b, "b2"), (b, "b3"), (a, "a3")):
            r = self.send(key_file, title)
            self.assertEqual(r.returncode, 1, (title, r.stdout))
            self.assertIn("E_NOTIFY_LIMIT", r.stdout)
        self.write_alerts(self.alert(4, "M_4", "ACTION"))
        self.cli("notify", "run")
        self.assertTrue(os.path.exists(sent + ".1"), "sent.jsonl rotated at 1 MiB")
        self.assertLess(os.path.getsize(sent), 1 << 20)
        self.assertEqual(len(self.fake.posts()), 5, "no limit was reset by the rotation")
        self.assertEqual(self.sent()[-1]["status"], "suppressed")

    def test_counted_outcomes_for_agent_limits(self):
        """Counted: delivered, queued, failed, refused; a duplicate or a limited try is not."""
        c = self.grant("agent-c", "--per-hour", "2")
        self.fake.responses = [403, 500]
        self.assertEqual(self.send(c, "c1").returncode, 2)  # refused
        self.assert_queued(self.send(c, "c2"))  # queued
        r = self.send(c, "c3")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("E_NOTIFY_LIMIT", r.stdout)
        self.assertEqual(len(self.fake.posts()), 2)
        d = self.grant("agent-d", "--per-hour", "2")
        self.assert_delivered(self.send(d, "d1"))
        self.assertIn("E_NOTIFY_DUPLICATE", self.send(d, "d1").stdout)
        self.assertIn("E_NOTIFY_DUPLICATE", self.send(d, "d1").stdout)
        self.assert_delivered(self.send(d, "d2"))  # the duplicates took no slot
        self.assertIn("E_NOTIFY_LIMIT", self.send(d, "d3").stdout)

    # ---- 4c.5: the notice takes a slot

    def test_notice_uses_the_only_slot(self):
        self.write_profile(self.notify_cfg(alerts_per_hour=1))
        self.baseline()
        self.write_alerts(*[self.alert(i, "S_%d" % i, "ACTION") for i in (2, 3, 4)])
        self.cli("notify", "run")
        self.assertEqual(self.titles(), ["[mm] S_2"])
        self.write_alerts(*[self.alert(i, "S_%d" % i, "ACTION") for i in (5, 6, 7)])
        self.cli("notify", "run", offset=3700)
        later = self.fake.ntfy()[1:]
        self.assertEqual(len(later), 1, ("at most 1 message in that hour, the notice included", later))
        self.assertIn("alerts suppressed", later[0]["title"] + " " + later[0]["message"])  # A20
        self.write_alerts(self.alert(8, "S_8", "ACTION"))
        self.cli("notify", "run", offset=3800)
        self.assertEqual(len(self.fake.posts()), 2, "still the same hour")

    # ---- 4c.6: outbox overflow

    def test_outbox_overflow_drops_oldest_first_attempt(self):
        self.write_profile(self.notify_cfg(alerts_per_hour=600))
        self.baseline()
        self.fake.default = 500
        key_file = self.grant("agent-one")
        self.assert_queued(self.send(key_file, "OLDEST"))  # first attempt at t0
        self.write_alerts(*[self.alert(i, "Q_%03d" % i, "ACTION") for i in range(2, 101)])  # 99 alerts
        offset = 35  # OLDEST is due: it is retried (and fails) before the alerts' first attempts
        while self.status(offset=offset).get("cursor") != "100":
            self.assertLess(offset, 50, "the runs do not take up the alerts")
            self.cli("notify", "run", offset=offset)
            offset += 1
        self.assertGreaterEqual(self.titles().count("[agent-one] OLDEST"), 2, "OLDEST was retried once")
        self.assertEqual(self.status(offset=offset).get("queued"), "100")
        self.assertNotIn("dropped", [x["status"] for x in self.sent()])
        self.write_alerts(self.alert(101, "Q_101", "ACTION"))
        self.cli("notify", "run", offset=offset)
        dropped = [x for x in self.sent() if x["status"] == "dropped"]
        self.assertTrue(dropped, "101 items: one is dropped")
        self.assertEqual((dropped[0]["source"], dropped[0]["sender"]), ("agent", "agent-one"), dropped[0])
        self.assertLessEqual(int(self.status(offset=offset).get("queued")), 100)

    # ---- backoff ladder and the 1-hour drop

    def test_backoff_doubles_to_15_minutes_then_drop_after_one_hour(self):
        key_file = self.grant("agent-one")
        self.fake.default = 500
        self.assert_queued(self.send(key_file, "ladder"))  # try 1 at 0: next in 30 s
        # (offset, retried?): each retry at due + 10 s; each check before it at due - 10 s (A22)
        plan = [(20, False), (40, True),      # due 30
                (90, False), (110, True),     # due 40 + 60
                (220, False), (240, True),    # due 110 + 120
                (470, False), (490, True),    # due 240 + 240
                (960, False), (980, True),    # due 490 + 480
                (1870, False), (1890, True),  # due 980 + 900 (not 960: capped at 15 minutes)
                (2780, False), (2800, True)]  # due 1890 + 900
        tries = 1
        for offset, retried in plan:
            self.cli("notify", "run", offset=offset)
            tries += retried
            self.assertEqual(len(self.fake.posts()), tries, (offset, retried))
        self.assertEqual(self.status(offset=2800).get("queued"), "1")
        self.assertNotIn("dropped", [x["status"] for x in self.sent()])
        self.cli("notify", "run", offset=3610)  # more than 1 hour after the first attempt
        self.assertEqual(self.status(offset=3610).get("queued"), "0")
        self.assertIn("dropped", [x["status"] for x in self.sent()])
        n = len(self.fake.posts())
        self.cli("notify", "run", offset=4000)
        self.assertEqual(len(self.fake.posts()), n)


# =============================================================================================== 4f. state and concurrency


class StateDesign(NotifyBase):
    """Contract section 4f: one state.json, strict validation, leftovers ignored, sent.jsonl audit-only, run.lock,
    the AlertStore lock, append-order resets, errors after delivery, hour events per item, overflow eviction."""

    titles, baseline, assert_no_loss = Durability.titles, Durability.baseline, Durability.assert_no_loss

    def state_file(self):
        return os.path.join(self.notify_dir(), "state.json")

    def read_bytes(self, p):
        try:
            with open(p, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def popen_run(self, offset=0):
        cmd = [sys.executable, "-I", MM_PATH, "--profile", self.prof, "--data", self.data, "notify", "run"]
        if offset:
            cmd = [sys.executable, "-I", self.shift_py, str(offset)] + cmd[2:]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: p.poll() is None and (p.kill(), p.wait(10)))
        return p

    def wait_posts(self, n, p=None, limit=10):
        deadline = time.monotonic() + limit
        while len(self.fake.posts()) < n and time.monotonic() < deadline and (p is None or p.poll() is None):
            time.sleep(0.02)
        self.assertGreaterEqual(len(self.fake.posts()), n, "the fake server got request %d" % n)

    # ---- 4f.2: damaged state

    @staticmethod
    def damaged_variants(doc, cursor):
        """(label, document) pairs, each with one change that makes the document invalid (A23)."""
        out, ints, strs, lists = [], [], [], []

        def walk(node, path):
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, path + (k,))
            elif isinstance(node, list):
                lists.append(path)
                for i, v in enumerate(node):
                    walk(v, path + (i,))
            elif isinstance(node, bool):
                pass
            elif isinstance(node, int):
                ints.append(path)
            elif isinstance(node, str):
                strs.append(path)

        def changed(path, fn):
            d = json.loads(json.dumps(doc))
            node = d
            for k in path[:-1]:
                node = node[k]
            node[path[-1]] = fn(node[path[-1]])
            return d

        walk(doc, ())
        ints.sort(key=lambda path: (doc_get(doc, path) != cursor, len(path)))  # the cursor first
        for path in ints[:4]:
            out.append(("int as string %s" % (path,), changed(path, str)))
        for path in strs[:3]:
            out.append(("string as number %s" % (path,), changed(path, lambda v: 7)))
        for path in lists[:3]:
            if path:
                out.append(("bad entry in %s" % (path,), changed(path, lambda v: v + [{"junk": True}])))
        if isinstance(doc.get("schema_version"), int):
            out.append(("schema_version 999", dict(doc, schema_version=999)))
        return out

    def test_damaged_state_is_E_NOTIFY_STATE_before_any_write_or_delivery(self):
        self.baseline(2)
        key_file = self.grant("agent-one", "--per-hour", "20")
        self.assert_delivered(self.send(key_file, "kept in the duplicate memory"))
        self.fake.responses = [500]
        self.write_alerts(self.alert(3, "D_3", "ACTION"))
        self.cli("notify", "run")  # a queued item, an hour event, a cursor
        self.write_alerts(self.alert(4, "D_4", "ACTION"))  # pending: a run would send it
        state, sent = self.state_file(), os.path.join(self.notify_dir(), "sent.jsonl")
        good = self.read_bytes(state)
        self.assertIsNotNone(good, "4f.1: notify/state.json exists after a run")
        self.assertEqual(stat.S_IMODE(os.stat(state).st_mode), 0o600)
        doc = json.loads(good)
        self.assertIsInstance(doc, dict)
        raws = [("bad JSON", b"{"), ("truncated", good[:len(good) // 2]), ("not an object", b"[]"),
                ("empty", b""), ("trailing garbage", good + b"x")]
        raws += [(label, json.dumps(d).encode()) for label, d in self.damaged_variants(doc, 3)]
        posts = len(self.fake.posts())
        for label, raw in raws:
            with self.subTest(label=label):
                with open(state, "wb") as f:
                    f.write(raw)
                os.chmod(state, 0o600)
                before_sent = self.read_bytes(sent)
                for args in (("notify", "run"), ("notify", "send", "--key-file", key_file, "--level", "normal",
                                                 "--title", "while damaged")):
                    r = self.cli(*args)
                    self.assert_error(r, "E_NOTIFY_STATE", 2)
                    self.assertIn("state.json", r.stdout)
                    self.assertEqual(self.read_bytes(state), raw, "state.json unchanged byte for byte")
                    self.assertEqual(self.read_bytes(sent), before_sent, "no audit line either")
                self.assertEqual(len(self.fake.posts()), posts, "no request")
        with open(state, "wb") as f:
            f.write(good)
        self.cli("notify", "run")
        self.assertEqual(self.titles().count("[mm] D_4"), 1, "the good state works again")

    def test_leftover_4c_files_are_ignored(self):
        os.makedirs(self.notify_dir(), mode=0o700, exist_ok=True)
        self.write_alerts(*[self.alert(i, "HIST_%d" % i, "ACTION") for i in (1, 2, 3)])
        leftovers = {"cursor.json": json.dumps({"cursor": 0, "seq": 0}),
                     "outbox.json": json.dumps([{"id": "left", "source": "agent", "sender": "agent-one",
                                                 "title": "LEFTOVER", "text": "", "level": "normal", "tries": 1,
                                                 "first": 0, "due": 0}]),
                     "hour.json": "{",
                     "recent.json": "not json"}
        for name, text in leftovers.items():
            with open(os.path.join(self.notify_dir(), name), "w") as f:
                f.write(text)
            os.chmod(os.path.join(self.notify_dir(), name), 0o600)
        r = self.cli("notify", "run")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(self.fake.posts(), [], "missing state.json: a first run from the newest alert, empty queue")
        st = self.status()
        self.assertEqual((st.get("cursor"), st.get("queued")), ("3", "0"))
        key_file = self.grant("agent-one", "--per-hour", "1")
        self.assert_delivered(self.send(key_file, "fresh"))
        self.write_alerts(self.alert(4, "NEW_4", "ACTION"))
        self.cli("notify", "run", offset=100)
        self.assertEqual(self.titles(), ["[agent-one] fresh", "[mm] NEW_4"])

    def test_sent_log_deleted_or_rotated_changes_no_limit(self):
        self.write_profile(self.notify_cfg(alerts_per_hour=1))
        self.baseline()
        sent = os.path.join(self.notify_dir(), "sent.jsonl")
        key_file = self.grant("agent-one", "--per-hour", "2")
        self.assert_delivered(self.send(key_file, "one", "normal", "x"))
        self.assert_delivered(self.send(key_file, "two", "normal", "x"))
        os.unlink(sent)
        r = self.send(key_file, "three")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("E_NOTIFY_LIMIT", r.stdout)
        other = self.grant("agent-two", "--per-hour", "5")
        self.assert_delivered(self.send(other, "same", "normal", "body"))
        os.unlink(sent)
        self.assertIn("E_NOTIFY_DUPLICATE", self.send(other, "same", "normal", "body").stdout)
        self.write_alerts(self.alert(2, "H_2", "ACTION"))
        self.cli("notify", "run")
        for seq in (3, 4):  # rotated twice: the audit log is gone from both names
            if os.path.exists(sent):
                os.replace(sent, sent + ".1")
            self.write_alerts(self.alert(seq, "H_%d" % seq, "ACTION"))
            self.cli("notify", "run", offset=seq * 10)
        self.assertEqual([t for t in self.titles() if t.startswith("[mm]")], ["[mm] H_2"])

    # ---- 4f.3: run.lock

    def test_overlapping_runs_second_is_busy(self):
        self.baseline()
        self.write_alerts(self.alert(2, "O_2", "ACTION"), self.alert(3, "O_3", "ACTION"))
        self.fake.responses = ["hold"]
        p = self.popen_run()
        self.wait_posts(1, p)
        r = self.cli("notify", "run")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(kv(r.stdout).get("notify"), "busy", r.stdout)
        self.assertEqual(len(self.fake.posts()), 1, "a busy run sends nothing")
        key_file = self.grant("agent-one")
        t0 = time.monotonic()
        self.assert_delivered(self.send(key_file, "while a run waits"))  # A25
        self.assertLess(time.monotonic() - t0, 5)
        self.fake.release.set()
        out, err = p.communicate(timeout=30)
        self.assertNotIn("Traceback", err)
        self.cli("notify", "run")
        self.cli("notify", "run", offset=100)
        got = self.titles()
        self.assertEqual((got.count("[mm] O_2"), got.count("[mm] O_3")), (1, 1), got)

    # ---- 4f.4a: the AlertStore lock and the read order

    def test_run_reads_alerts_under_the_alertstore_lock(self):
        import fcntl
        self.write_alerts(*[self.alert(i, "L_%d" % i, "ACTION") for i in (1, 2, 3)])
        self.cli("notify", "run")  # cursor 3
        self.write_alerts(*[self.alert(i, "L_%d" % i, "ACTION") for i in (4, 5, 6)])
        cur, dot1 = os.path.join(self.data, "alerts.jsonl"), os.path.join(self.data, "alerts.jsonl.1")
        with open(cur) as f:
            lines = f.read().splitlines(keepends=True)
        lock = os.path.join(self.data, "state", "alerts.lock")
        with open(lock, "a+") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                # half way through a rewrite: .1 still holds 1-3, the current file only 7 (4-6 are in neither yet)
                with open(dot1, "w") as f:
                    f.writelines(lines[:3])
                with open(cur, "w") as f:
                    f.write(json.dumps(self.alert(7, "L_7", "ACTION"), sort_keys=True) + "\n")
                p = self.popen_run()
                time.sleep(1.0)
                self.assertEqual(self.fake.posts(), [], "A26: nothing is sent before the lock is free")
                # the finished pair: .1 holds 4-6, the current file holds 7
                with open(dot1, "w") as f:
                    f.writelines(lines[3:6])
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)
        out, err = p.communicate(timeout=30)
        self.assertNotIn("Traceback", err)
        if p.returncode != 0:
            self.assertRegex(out.strip().splitlines()[-1], ERROR)
        self.cli("notify", "run")
        got = self.titles()
        self.assertEqual(sorted(got), ["[mm] L_%d" % i for i in (4, 5, 6, 7)], "each once, nothing old")

    def test_repeated_record_across_rotation_is_no_reset(self):
        self.cli("notify", "run")  # no alerts yet: a first run with an empty queue
        recs = [self.alert(i, "P_%d" % i, "ACTION") for i in (1, 2, 3, 4)]
        with open(os.path.join(self.data, "alerts.jsonl.1"), "w") as f:
            f.writelines(json.dumps(r, sort_keys=True) + "\n" for r in recs[:3])
        self.write_alerts(recs[2], recs[3])  # the same record 3 again, then 4
        self.cli("notify", "run")
        self.cli("notify", "run")
        self.assertEqual(sorted(self.titles()), ["[mm] P_%d" % i for i in (1, 2, 3, 4)])
        self.assertEqual(self.status().get("cursor"), "4")

    # ---- 4f.4: an error after delivery

    def test_error_after_delivery_at_most_duplicates(self):
        self.baseline()
        self.write_alerts(*[self.alert(i, "E_%d" % i, "ACTION") for i in (2, 3, 4)])
        self.fake.responses = ["hold"]
        p = self.popen_run()
        self.wait_posts(1, p)
        state = self.state_file()
        held = self.read_bytes(state)  # A27: written in step (c), before delivery
        self.assertIsNotNone(held)
        os.unlink(state)
        os.mkdir(state)
        self.fake.release.set()
        out, err = p.communicate(timeout=30)
        self.assertIn(p.returncode, (1, 2), out)
        self.assertNotIn("Traceback", err)
        os.rmdir(state)
        with open(state, "wb") as f:
            f.write(held)
        os.chmod(state, 0o600)
        self.assert_no_loss("E_%d", (2, 3, 4))

    # ---- 4f.1: hour events per item

    def test_retry_delivered_late_counts_until_an_hour_after_delivery(self):
        self.write_profile(self.notify_cfg(alerts_per_hour=1))
        self.baseline()
        self.fake.default = 500
        self.write_alerts(self.alert(2, "LATE", "ACTION"))
        self.cli("notify", "run")  # first attempt at 0
        for offset in (40, 110, 240, 490, 980, 1890):  # the backoff ladder of A22
            self.cli("notify", "run", offset=offset)
        self.fake.default = 200
        self.cli("notify", "run", offset=2800)  # delivered late in its hour
        self.assertEqual(self.titles()[-1], "[mm] LATE")
        self.assertEqual(self.status(offset=2800).get("queued"), "0")
        n = len(self.fake.posts())
        self.write_alerts(self.alert(3, "AFTER", "ACTION"))
        self.cli("notify", "run", offset=3700)  # over 1 hour after the first attempt, under 1 hour after delivery
        self.assertEqual(len(self.fake.posts()), n, "LATE still counts: AFTER is suppressed")
        self.write_alerts(self.alert(4, "MUCH_LATER", "ACTION"))
        self.cli("notify", "run", offset=6500)
        later = self.fake.ntfy()[n:]
        self.assertEqual(len(later), 1, later)
        self.assertIn("alerts suppressed", later[0]["title"] + " " + later[0]["message"])  # A28

    # ---- 4f.4b: overflow and the due oldest item

    def test_overflow_never_drops_an_item_selected_for_delivery(self):
        self.write_profile(self.notify_cfg(alerts_per_hour=600))
        self.baseline()
        self.fake.default = 500
        key_file = self.grant("agent-one")
        self.assert_queued(self.send(key_file, "OLDEST"))  # first attempt at 0: due at 30
        self.write_alerts(*[self.alert(i, "V_%03d" % i, "ACTION") for i in range(2, 101)])  # 99 alerts
        offset = 10  # every alert tried once (20 per run), at 10-15: due at 40 or later
        while len(self.fake.posts()) < 100:
            self.assertLess(offset, 18, "the runs do not try the alerts")
            self.cli("notify", "run", offset=offset)
            offset += 1
        self.assertEqual(self.status(offset=offset).get("queued"), "100")
        self.fake.default = 200
        self.write_alerts(self.alert(101, "V_101", "ACTION"))
        self.cli("notify", "run", offset=31)  # OLDEST and V_101 are due; 101 items: one other item goes
        recs = self.sent()
        dropped = {x["id"] for x in recs if x["status"] == "dropped"}
        delivered = {x["id"] for x in recs if x["status"] == "delivered"}
        self.assertTrue(dropped, "101 items: one is dropped")
        self.assertEqual(dropped & delivered, set(), "no item both dropped and delivered")
        self.assertIn("[agent-one] OLDEST", self.titles()[-2:])
        self.assertIn("[mm] V_101", self.titles()[-2:])
        self.assertTrue(all(x["source"] == "mm" for x in recs if x["status"] == "dropped"))
        self.assertLessEqual(int(self.status(offset=31).get("queued")), 100)


def doc_get(doc, path):
    for k in path:
        doc = doc[k]
    return doc


if __name__ == "__main__":
    unittest.main()
