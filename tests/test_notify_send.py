# SPDX-License-Identifier: Apache-2.0
"""Part B of `mm notify`: core/mmnotify_send.py, written from the contract (sections 1-3, 4b), not from the code.
read_secret: strict secret files. check_url: the URL rules. render: the exact ntfy and Pushover requests, bounds,
cleaning, no header injection. deliver: local threaded http.server fakes on 127.0.0.1 port 0 (never the internet):
status mapping, no redirects, total timeout, capped reads, a detail without secrets. Import: no side effects.

Assumptions where the contract fixes no exact value (each test that rests on one says so):
A1  A missing secret file is E_NOTIFY_SECRET too (it is not a regular file).
A2  Ownership is compared with os.getuid() or os.geteuid() (the test fakes another uid by patching both).
A3  read_secret returns the parsed values unchanged (result["token"], ["app_token"], ["user_key"]).
A4  The ntfy token's 128 limit counts the whole token, `tk_` included; its minimum length is 1.
A5  render's headers are a mapping or (name, value) pairs; names compare case-insensitively.
A6  The ntfy URL is cfg["url"] as given (a trailing "/" is accepted); a base path is kept.
A7  ntfy body keys are exactly topic, title, message, priority, tags (priority a JSON integer); Pushover form fields
    are exactly token, user, title, message, priority (+retry, expire for ring), utf-8 form encoding; Pushover sends
    no Authorization header; a Content-Type, when set, is application/json (ntfy) or form-urlencoded (Pushover).
A8  Over-long title, text, sender and too many or bad tags are cut or dropped, not refused (render does not raise).
    The 100 limit applies to the agent's title; the "[sender] " prefix comes on top. Valid tags keep their order.
A9  Control characters are removed or replaced (by one character each); the visible characters stay in order.
A10 A secret holding CR/LF or non-latin-1 characters makes render raise MMError or leave it out of every header.
A11 deliver's timeout_s argument (not cfg["timeout_s"]) is the total wall-clock limit of one request, headers
    included; the test allows 1.5-2 s of slack.
A12 A 3xx result carries the 3xx status; deliver makes exactly one request for a 4xx (do not retry).
A13 A 2xx answer with a body over 64 KiB is still ok (the read is capped, not an error).
A14 deliver sends render's request: the fake sees the same JSON body or form fields.
A15 A URL that holds CR, LF or TAB is refused by check_url.
A16 Proxy variables are removed for the deliver tests (a proxy would make 127.0.0.1 fakes unreachable), except in
    the 4d.7 proxy-trap test, which sets them to a trap.
Section 4d (hardening) assumptions:
A17 4d.1 "part" is checked as every 6-character substring of each configured secret (stricter than prefixes; both
    designs the contract allows, a fixed word or secrets replaced before the cut, meet it when the full value is sent).
A18 4d.2 Dropping a tag keeps the other valid tags in order; at most 4 tags are given, so the max-4 cut is not involved.
A19 4d.3 Each sample is first checked against mmtext: mask() alone hides its secret, mask(clean()) does not.
A20 4d.4 Name resolution and connecting go through socket.getaddrinfo / socket.create_connection (patched to be slow).
A21 4d.6 The body is read through http.client.HTTPResponse (read, read1, readinto, readinto1, readline); the test
    counts the bytes those calls return to the module (outermost calls only). Socket counts are not used: io's
    buffered reader reads ahead up to io.DEFAULT_BUFFER_SIZE (128 KiB here) on its own.
A22 4d.7 The secret file is opened with os.open, open() or io.open; the test swaps the file inside that call just
    before the real open, and skips if no such call happens.
A24 4e.1 A word cut short is dropped or replaced by a marker whose text the test does not fix; so the test asserts
    only that no run of the cut word (8+ characters) survives in the message and no 6-character piece of a secret
    survives in title or message. The word rule is asserted for the text only: "a text cut" may not cover the title,
    whose cut word the secret sweep still checks. Cut points are
    unknown inside the module, so the test moves each secret across 100, 1000 and mmtext's line cut (4e.1 sweep).
A25 4e.4 The slowed functions: socket.socket.connect (and connect_ex) for 127.0.0.1:<fake port>, socket.getaddrinfo
    for "localhost". Each must be called; the no-delay control proves the same path delivers once, on time.
A26 4e.3 The module reads its http response through socket.socket.recv_into or recv. In the first such read the
    test makes the module's descriptor number name an unrelated echo connection (os.dup2), holds the read past
    timeout_s so the watchdog fires, then fails the read. The unrelated connection must still work afterwards.
A28 4e.1 The contract does not fix where the pre-mask cut is (1000 is the bound after masking, where a word may be
    cut). So the cut word is 10000+ characters long, past any pre-mask cut. Then the message is the whole words
    before it (whitespace at the end may go), or those words and mmtext.CUT_MARK, or empty when no word comes before
    it: never any piece of the cut word. One lowercase word in the sweep gives the filler before the shape (no
    pre-mask cut; the shape itself is masked), empty or CUT_MARK. Inputs are lowercase: they are never masked.
A27 Byte counts (4d.6 with reads that raise): "api" is what HTTPResponse's read calls return to the module, plus
    IncompleteRead.partial when one raises; "wire" is what HTTPResponse takes from its buffered file after the
    headers, raising reads included. wire may exceed 65537 only by chunk framing (size lines, CRLF): at most 256.
A23 4d.7 The TLS context is made at call time by ssl.create_default_context / ssl._create_default_https_context, or
    honours SSL_CERT_FILE; a CA-signed certificate for IP 127.0.0.1 must deliver ok (control), else the test skips."""
import builtins
import contextlib
import http.client
import http.server
import importlib
import io
import json
import os
import random
import re
import shutil
import socket
import socketserver
import ssl
import string
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import unittest
import urllib.parse
from unittest import mock

import mmtest
from mmtest import mmcore
import mmtext

CORE = os.path.join(mmtest.CODE, "core")
BAD_CATEGORIES = ("Cc", "Cf", "Zl", "Zp")
NTFY_TOKEN = "tk_QzSecretMarker9x8w7v6u5t4s3"
PO_APP = "AppMarkerQz7Wx3Vy5Ut1Sr9Pq2"
PO_USER = "UserMarkerKj2Hg4Fd6Sa8Lm0Np"
MARKER = "Zq9FileContentMarker"
BODY_MARK = "BodyMarkerZq7"
TITLE_MARK = "TitleMarkerWv4"
REASON_TOKEN = "tk_q7ZxW9vB2nM4kP8lR3tY6hJ1"
TAG_TOKEN = "tk_aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW"  # 32 characters: also a valid tag
ALL_SECRETS = (NTFY_TOKEN, PO_APP, PO_USER, REASON_TOKEN, TAG_TOKEN)
PUSHOVER_DEFAULT = "https://api.pushover.net/1/messages.json"
TAG_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
              "FTP_PROXY")


def load():
    """The module under test, imported per test so this file is collected while the module is missing."""
    return importlib.import_module("mmnotify_send")


def ntfy_cfg(url="https://ntfy.example.net", **over):
    cfg = {"enabled": True, "service": "ntfy", "url": url, "topic": "mm-alerts",
           "alert_levels": ["ATTENTION", "ACTION"], "ring_levels": ["ACTION"], "send_cleared": True,
           "alerts_per_hour": 30, "timeout_s": 10, "ring_retry_s": 60, "ring_expire_s": 1800}
    cfg.update(over)
    return cfg


def pushover_cfg(url=None, **over):
    cfg = {"enabled": True, "service": "pushover", "secret_file": "~/.config/machine-manager/notify-secret.json",
           "alert_levels": ["ATTENTION", "ACTION"], "ring_levels": ["ACTION"], "send_cleared": True,
           "alerts_per_hour": 30, "timeout_s": 10, "ring_retry_s": 45, "ring_expire_s": 900}
    if url is not None:
        cfg["url"] = url
    cfg.update(over)
    return cfg


def msg(**over):
    m = {"title": "Build done", "text": "All 12 checks passed.", "level": "normal", "sender": "agent-x",
         "tags": ["ci", "build"]}
    m.update(over)
    return m


def header_items(headers):
    """(name, value) pairs as str (A5)."""
    items = headers.items() if hasattr(headers, "items") else headers
    out = []
    for k, v in items:
        k = k.decode("latin-1") if isinstance(k, bytes) else str(k)
        v = v.decode("latin-1") if isinstance(v, bytes) else str(v)
        out.append((k, v))
    return out


def header(headers, name):
    """Every value of the header `name` (case-insensitive)."""
    return [v for k, v in header_items(headers) if k.lower() == name.lower()]


def has_bad(text):
    return any(unicodedata.category(c) in BAD_CATEGORIES for c in text)


def parts(secret, n=6):
    """Every n-character part of a secret (A17)."""
    return {secret[i:i + n] for i in range(len(secret) - n + 1)}


def form(body):
    return urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)


def assert_cut_at_word(test, head, message, bound=1000):
    """4e.1 (A28): the input was `head` (whole words, shorter than bound) and one word past the pre-mask cut.
    The message is `head` (whitespace at the end may go), or `head` and mmtext.CUT_MARK, or empty with no head."""
    test.assertLessEqual(len(message), bound)
    run = message[:-len(mmtext.CUT_MARK)] if message.endswith(mmtext.CUT_MARK) else message
    test.assertEqual(run.rstrip(), head.rstrip(), "the message keeps a piece of the cut word or loses whole words: "
                     "%r" % message[-40:])


def distinct_word(rng, n):
    """One word of n lowercase letters, not one repeated character."""
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(n))


class Base(unittest.TestCase):
    def setUp(self):
        os.makedirs(mmtest.TMP_BASE, exist_ok=True)
        self.root = tempfile.mkdtemp(prefix="notify-send-", dir=mmtest.TMP_BASE)
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ns = load()


# --------------------------------------------------------------------------------------------- read_secret

class ReadSecret(Base):
    def write(self, content, mode=0o600, name="secret.json"):
        p = os.path.join(self.root, name)
        with open(p, "wb") as f:
            f.write(content if isinstance(content, bytes) else content.encode("utf-8"))
        os.chmod(p, mode)
        return p

    def refused(self, path, service, marker=MARKER):
        with self.assertRaises(mmcore.MMError) as cm:
            self.ns.read_secret(path, service)
        e = cm.exception
        self.assertEqual(e.code, "E_NOTIFY_SECRET")
        self.assertTrue(str(e).startswith("E_NOTIFY_SECRET "), str(e))
        self.assertIn("; fix: ", str(e))
        if marker:
            text = str(e) + " ".join(str(a) for a in e.args)
            self.assertNotIn(marker, text, "the error text never includes file content")
        return e

    def test_regular_files_are_read(self):
        p = self.write(json.dumps({"token": NTFY_TOKEN}))
        self.assertEqual(self.ns.read_secret(p, "ntfy")["token"], NTFY_TOKEN)  # A3
        p = self.write(json.dumps({"app_token": PO_APP, "user_key": PO_USER}), name="po.json")
        got = self.ns.read_secret(p, "pushover")
        self.assertEqual((got["app_token"], got["user_key"]), (PO_APP, PO_USER))

    def test_owner_only_modes_are_accepted(self):
        for mode in (0o600, 0o400, 0o700):
            with self.subTest(mode=oct(mode)):
                p = self.write(json.dumps({"token": "abc"}), mode=mode, name="m%o.json" % mode)
                self.assertEqual(self.ns.read_secret(p, "ntfy")["token"], "abc")

    def test_group_or_other_bits_are_refused(self):
        for mode in (0o640, 0o604, 0o620, 0o602, 0o610, 0o601, 0o644, 0o666):
            with self.subTest(mode=oct(mode)):
                p = self.write(json.dumps({"token": MARKER}), mode=mode, name="m%o.json" % mode)
                self.refused(p, "ntfy")

    def test_symlink_is_refused_even_to_a_good_file(self):
        good = self.write(json.dumps({"token": MARKER}))
        link = os.path.join(self.root, "link.json")
        os.symlink(good, link)
        self.refused(link, "ntfy")

    def test_directory_is_refused(self):
        d = os.path.join(self.root, "dir.json")
        os.mkdir(d, 0o700)
        self.refused(d, "ntfy")

    def test_missing_file_is_refused(self):  # A1
        self.refused(os.path.join(self.root, "absent.json"), "ntfy")

    def test_fifo_is_refused_without_blocking(self):
        p = os.path.join(self.root, "fifo.json")
        os.mkfifo(p, 0o600)
        box = {}

        def run():
            try:
                self.ns.read_secret(p, "ntfy")
            except BaseException as e:  # noqa: B902 (the test inspects it)
                box["e"] = e
        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(3)
        if t.is_alive():
            with contextlib.suppress(OSError):
                os.close(os.open(p, os.O_WRONLY | os.O_NONBLOCK))  # the reader sees end of file and returns
            t.join(3)
            self.fail("read_secret blocked on a FIFO")
        e = box.get("e")
        self.assertIsInstance(e, mmcore.MMError)
        self.assertEqual(e.code, "E_NOTIFY_SECRET")

    def test_other_owner_is_refused(self):  # A2
        p = self.write(json.dumps({"token": MARKER}))
        uid = os.getuid() + 1
        with mock.patch("os.getuid", return_value=uid), mock.patch("os.geteuid", return_value=uid):
            self.refused(p, "ntfy")

    def test_size_limit_is_4096_bytes(self):
        doc = json.dumps({"token": "abc"})
        p = self.write(doc + " " * (4096 - len(doc)), name="exact.json")
        self.assertEqual(os.path.getsize(p), 4096)
        self.assertEqual(self.ns.read_secret(p, "ntfy")["token"], "abc")
        p = self.write(doc + " " * (4097 - len(doc)), name="over.json")
        self.refused(p, "ntfy", marker=None)
        doc = json.dumps({"token": MARKER, "pad": "x" * 5000})
        self.refused(self.write(doc, name="big.json"), "ntfy")

    def test_bad_json_is_refused(self):
        cases = {
            "truncated": '{"token": "%s"' % MARKER,
            "not json": "token=%s" % MARKER,
            "duplicate keys": '{"token": "abc", "token": "%s"}' % MARKER,
            "nan": '{"token": NaN, "x": "%s"}' % MARKER,
            "infinity": '{"token": Infinity, "x": "%s"}' % MARKER,
            "minus infinity": '{"token": -Infinity, "x": "%s"}' % MARKER,
            "array": '["%s"]' % MARKER,
            "string": '"%s"' % MARKER,
            "number": "12345",
            "null": "null",
            "empty": "",
            "not utf-8": b'{"token": "\xff\xfe' + MARKER.encode() + b'"}',
        }
        for name, content in cases.items():
            with self.subTest(case=name):
                self.refused(self.write(content, name=name.replace(" ", "-") + ".json"), "ntfy")

    def test_unknown_keys_are_refused(self):
        cases = [
            ("ntfy", {"token": "abc", "extra": MARKER}),
            ("ntfy", {"app_token": PO_APP, "user_key": PO_USER, "x": MARKER}),
            ("ntfy", {"app_token": MARKER, "user_key": PO_USER}),
            ("pushover", {"app_token": PO_APP, "user_key": PO_USER, "extra": MARKER}),
            ("pushover", {"token": MARKER, "app_token": PO_APP, "user_key": PO_USER}),
        ]
        for i, (service, doc) in enumerate(cases):
            with self.subTest(service=service, keys=sorted(doc)):
                self.refused(self.write(json.dumps(doc), name="u%d.json" % i), service)

    def test_ntfy_token_forms(self):  # A4
        good = ["a", "abc123", "tk_" + "A1b2C3" * 4, "abc-def_ghi", "tk_x", "T" * 128, "tk_" + "z" * 125]
        for i, tok in enumerate(good):
            with self.subTest(good=tok[:20]):
                p = self.write(json.dumps({"token": tok}), name="g%d.json" % i)
                self.assertEqual(self.ns.read_secret(p, "ntfy")["token"], tok)
        bad = ["", MARKER + "a" * 120, "tk_" + MARKER + "z" * 117, MARKER + " space", MARKER + ".dot",
               MARKER + "/slash", MARKER + "t\u00f6k", MARKER + "\nline", MARKER + "\r", MARKER + "+plus",
               MARKER + "=", MARKER + ":"]
        for i, tok in enumerate(bad):
            with self.subTest(bad=repr(tok[-8:]), length=len(tok)):
                self.refused(self.write(json.dumps({"token": tok}), name="b%d.json" % i), "ntfy")
        for i, value in enumerate([12345, None, True, ["x"], {"t": "x"}]):
            with self.subTest(type=type(value).__name__):
                self.refused(self.write(json.dumps({"token": value}), name="t%d.json" % i), "ntfy")

    def test_pushover_key_forms(self):
        good = [("a", "b"), ("A" * 64, "z9" * 32), (PO_APP, PO_USER)]
        for i, (app, user) in enumerate(good):
            with self.subTest(good=(len(app), len(user))):
                p = self.write(json.dumps({"app_token": app, "user_key": user}), name="g%d.json" % i)
                got = self.ns.read_secret(p, "pushover")
                self.assertEqual((got["app_token"], got["user_key"]), (app, user))
        bad_values = ["", MARKER + "a" * 50, MARKER + "-dash", MARKER + "_under", MARKER + " sp", "tk_" + MARKER,
                      MARKER + "\u00e9", 123, None]
        n = 0
        for value in bad_values:
            for field, other in (("app_token", "user_key"), ("user_key", "app_token")):
                with self.subTest(field=field, value=repr(value)[-10:]):
                    doc = {field: value, other: "Good123"}
                    n += 1
                    self.refused(self.write(json.dumps(doc), name="b%d.json" % n), "pushover")
        for i, doc in enumerate([{"app_token": PO_APP}, {"user_key": PO_USER}, {}]):
            with self.subTest(missing=sorted(doc)):
                self.refused(self.write(json.dumps(doc), name="m%d.json" % i), "pushover", marker=None)


    def swapped_during_open(self, replace):
        """read_secret on a good file that `replace(path)` swaps inside the module's own open call, just before the
        real open (4d.7, A22). Returns the MMError (or fails when the swapped file was read)."""
        path = self.write(json.dumps({"token": "abc"}))
        target, done = os.path.abspath(path), []
        real = {"os": os.open, "builtins": builtins.open, "io": io.open}

        def hit(p):
            try:
                return not done and os.path.abspath(os.fsdecode(os.fspath(p))) == target
            except TypeError:
                return False

        def wrapper(kind):
            def opener(p, *a, **k):
                if hit(p):
                    done.append(kind)
                    replace(path)
                return real[kind](p, *a, **k)
            return opener
        got = err = None
        with mock.patch("os.open", wrapper("os")), mock.patch("builtins.open", wrapper("builtins")), \
                mock.patch("io.open", wrapper("io")):
            try:
                got = self.ns.read_secret(path, "ntfy")
            except mmcore.MMError as e:
                err = e
        if not done:
            self.skipTest("the secret file was not opened by os.open, open() or io.open (A22)")
        self.assertIsNone(got, "a file swapped between the check and the open was read")
        self.assertEqual(err.code, "E_NOTIFY_SECRET")
        self.assertNotIn(MARKER, str(err))
        return err

    def test_regular_file_swapped_at_open_is_refused(self):  # 4d.7
        def replace(path):
            other = path + ".new"
            with open(other, "w") as f:
                f.write(json.dumps({"token": MARKER}))
            os.chmod(other, 0o600)
            os.replace(other, path)
        self.swapped_during_open(replace)

    def test_symlink_swapped_at_open_is_refused(self):  # 4d.7
        def replace(path):
            good = os.path.join(self.root, "elsewhere.json")
            with open(good, "w") as f:
                f.write(json.dumps({"token": MARKER}))
            os.chmod(good, 0o600)
            os.symlink(good, path + ".lnk")
            os.replace(path + ".lnk", path)
        self.swapped_during_open(replace)


# --------------------------------------------------------------------------------------------- check_url

class CheckUrl(Base):
    def test_accepted(self):
        for url in ("https://ntfy.example.net", "https://ntfy.example.net/", "https://ntfy.example.net:8443/base",
                    "https://api.pushover.net/1/messages.json", "https://[2001:db8::1]:8443",
                    "http://127.0.0.1", "http://127.0.0.1:8080", "http://127.0.0.1:8080/ntfy",
                    "http://[::1]", "http://[::1]:8080/", "http://localhost", "http://localhost:2586",
                    "https://127.0.0.1:8443", "https://localhost"):
            with self.subTest(url=url):
                self.assertIs(self.ns.check_url(url), True)

    def test_refused(self):
        for url in ("http://ntfy.example.net", "http://10.0.0.1", "http://192.168.1.10:8080", "http://0.0.0.0",
                    "http://localhost.example.net", "http://127.0.0.1.example.net", "http://[2001:db8::1]",
                    "https://user:pw@example.com", "https://user@example.com",
                    "http://127.0.0.1@example.com", "https://:pw@example.com", "http://localhost:80@example.com",
                    "https://ntfy.example.net/?a=1", "https://ntfy.example.net/path?x", "https://ntfy.example.net/#f",
                    "https://ntfy.example.net#frag",
                    "https://", "https:///path", "http://:8080", "ntfy.example.net", "//ntfy.example.net",
                    "ftp://ntfy.example.net", "file:///etc/hosts", "ws://localhost", "wss://ntfy.example.net",
                    "javascript:alert(1)", "data:text/plain,hi", "",
                    "https://ntfy.example.net/a\r\nX-Evil: 1", "https://ntfy.example.net/a\nb",
                    "https://ntfy.example.net/\tb"):  # the last three: A15
            with self.subTest(url=url):
                self.assertIs(self.ns.check_url(url), False)

    def test_length_limit_512(self):
        base = "https://ntfy.example.net/"
        self.assertIs(self.ns.check_url(base + "a" * (512 - len(base))), True)
        self.assertIs(self.ns.check_url(base + "a" * (513 - len(base))), False)
        self.assertIs(self.ns.check_url(base + "a" * 5000), False)


# --------------------------------------------------------------------------------------------- render

class RenderNtfy(Base):
    def render(self, cfg=None, secret=None, m=None):
        url, headers, body = self.ns.render(cfg or ntfy_cfg(), secret, m or msg())
        self.assertIsInstance(url, str)
        self.assertIsInstance(body, bytes)
        for k, v in header_items(headers):
            self.assertFalse(re.search(r"[\r\n]", k + v), "no CR/LF in a header")
            v.encode("latin-1")
        return url, headers, json.loads(body.decode("utf-8"))

    def test_exact_request_per_level(self):
        for level, prio in (("quiet", 2), ("normal", 3), ("ring", 5)):
            with self.subTest(level=level):
                url, headers, doc = self.render(secret={"token": NTFY_TOKEN}, m=msg(level=level))
                self.assertIn(url, ("https://ntfy.example.net", "https://ntfy.example.net/"))  # A6
                self.assertEqual(set(doc), {"topic", "title", "message", "priority", "tags"})  # A7
                self.assertEqual(doc["topic"], "mm-alerts")
                self.assertEqual(doc["title"], "[agent-x] Build done")
                self.assertEqual(doc["message"], "All 12 checks passed.")
                self.assertEqual(doc["priority"], prio)
                self.assertIs(type(doc["priority"]), int)
                self.assertEqual(doc["tags"], ["ci", "build"])
                self.assertEqual(header(headers, "Authorization"), ["Bearer " + NTFY_TOKEN])
                ctype = header(headers, "Content-Type")
                self.assertEqual(len(ctype), 1)
                self.assertEqual(ctype[0].split(";")[0].strip().lower(), "application/json")

    def test_no_authorization_without_a_token(self):
        for secret in (None, {}):
            with self.subTest(secret=secret):
                _, headers, doc = self.render(secret=secret)
                self.assertEqual(header(headers, "Authorization"), [])
                self.assertEqual(doc["title"], "[agent-x] Build done")

    def test_base_path_is_kept(self):  # A6
        url, _, _ = self.render(cfg=ntfy_cfg("http://127.0.0.1:2586/ntfy"))
        self.assertIn(url, ("http://127.0.0.1:2586/ntfy", "http://127.0.0.1:2586/ntfy/"))

    def test_title_text_sender_bounds(self):  # A8
        # spaced words: 4e.1 cuts at a word boundary, so part of each field survives (A8)
        _, _, doc = self.render(m=msg(title="T " * 150, text="x " * 2500, sender="s " * 50))
        m = re.match(r"^\[([^\]]*)\] (.*)$", doc["title"], re.S)
        self.assertTrue(m, doc["title"])
        self.assertTrue(0 < len(m.group(1)) <= 40, len(m.group(1)))
        self.assertGreater(m.group(1).count("s"), 0)
        self.assertLessEqual(m.group(2).count("T"), 100)
        self.assertGreater(m.group(2).count("T"), 0)
        self.assertLessEqual(len(doc["title"]), 100 + 40 + 3)
        self.assertLessEqual(len(doc["message"]), 1000)
        self.assertGreater(doc["message"].count("x"), 0)

    def test_single_overlong_word_is_dropped_or_replaced(self):  # 4e.1, A24, A28
        rng = random.Random(28)
        for service, cfg, sec in (("ntfy", ntfy_cfg(), {"token": NTFY_TOKEN}),
                                  ("pushover", pushover_cfg(), {"app_token": PO_APP, "user_key": PO_USER})):
            for before in (0, 1, 2, 7, 500, 980, 990):  # characters of whole words before the overlong word
                head = ""
                while len(head) < before:
                    w = distinct_word(rng, min(rng.randint(1, 9), max(1, before - len(head) - 1)))
                    head = (head + " " + w) if head else w
                for length in (10001, 12000):  # distinct letters, past any pre-mask cut (A28)
                    text = (head + " " if head else "") + distinct_word(rng, length)
                    with self.subTest(service=service, head=len(head), word=length):
                        _, _, body = self.ns.render(cfg, sec, msg(title="Build done", text=text))
                        fields = json.loads(body) if service == "ntfy" else {k: v[0] for k, v in form(body).items()}
                        assert_cut_at_word(self, head, fields["message"])
                        self.assertEqual(fields["title"], "[agent-x] Build done")

    def test_text_that_fits_is_unchanged(self):  # 4e.1 does not touch a text at or under the bound
        rng = random.Random(29)
        for n in (1, 999, 1000):
            text = distinct_word(rng, n)
            with self.subTest(length=n):
                _, _, doc = self.render(m=msg(text=text))
                self.assertEqual(doc["message"], text)

    def test_exact_bounds_pass_unchanged(self):
        _, _, doc = self.render(m=msg(title="T" * 100, text="x" * 1000, sender="s" * 40))
        self.assertEqual(doc["title"], "[%s] %s" % ("s" * 40, "T" * 100))
        self.assertEqual(doc["message"], "x" * 1000)

    def test_tags_bounded_and_charset(self):  # A8
        _, _, doc = self.render(m=msg(tags=["a", "b-c", "d_e", "F9"]))
        self.assertEqual(doc["tags"], ["a", "b-c", "d_e", "F9"])
        given = ["ok1", "bad tag", "ok_2", "a/b", "x" * 33, "\u00e9", "", "ok-3", "t\r\n", "t5", "t6"]
        _, _, doc = self.render(m=msg(tags=given))
        tags = doc.get("tags", [])
        self.assertLessEqual(len(tags), 4)
        for t in tags:
            self.assertTrue(TAG_RE.fullmatch(t), t)
            self.assertIn(t, given)
        _, _, doc = self.render(m=msg(tags=["t%d" % i for i in range(10)]))
        self.assertLessEqual(len(doc.get("tags", [])), 4)
        _, _, doc = self.render(m=msg(tags=["y" * 32]))
        self.assertEqual(doc["tags"], ["y" * 32])

    def test_control_characters_are_stripped(self):  # A9
        dirty = "a\x00b\x1b[31mc\u202ed\u2028e\x7f\u0085f\r\ng\u200bh"
        _, headers, doc = self.render(m=msg(title=dirty, text=dirty, sender="ag\x07ent"))
        for field in ("title", "message"):
            with self.subTest(field=field):
                self.assertFalse(has_bad(doc[field]), repr(doc[field]))
                self.assertRegex(doc[field], r"a.?b.?\[31mc.?d.?e.?.?f.?.?g.?h")
        self.assertNotIn("\x07", doc["title"])

    def test_header_injection_never_reaches_a_header(self):  # A10
        for name, secret, m in (
                ("crlf token", {"token": "abc\r\nX-Evil: 1"}, msg()),
                ("lf token", {"token": "abc\nX-Evil: 1"}, msg()),
                ("non-latin-1 token", {"token": "t\u00f6ken\u20ac"}, msg()),
                ("crlf title", {"token": NTFY_TOKEN}, msg(title="hi\r\nX-Evil: 1", sender="a\r\nX-Evil: 2")),
                ("unicode title", {"token": NTFY_TOKEN}, msg(title="Pr\u00fcfung \u2603 \u65e5\u672c"))):
            with self.subTest(case=name):
                try:
                    _, headers, _ = self.ns.render(ntfy_cfg(), secret, m)
                except mmcore.MMError:
                    continue
                for k, v in header_items(headers):
                    self.assertNotEqual(k.lower(), "x-evil")
                    self.assertFalse(re.search(r"[\r\n]", k + v), (k, v))
                    v.encode("latin-1")
                    self.assertNotIn("\u20ac", v)

    def test_unicode_survives_in_the_body(self):
        text = "Gr\u00fc\u00dfe \u2603 \u65e5\u672c\u8a9e \U0001F680 ok"
        title = "Pr\u00fcfung \u2603 \u65e5\u672c"
        _, _, doc = self.render(secret={"token": NTFY_TOKEN}, m=msg(title=title, text=text))
        self.assertEqual(doc["message"], text)
        self.assertEqual(doc["title"], "[agent-x] " + title)

    def test_render_does_no_network(self):
        with mock.patch("socket.socket.connect", side_effect=AssertionError("network")), \
                mock.patch("socket.getaddrinfo", side_effect=AssertionError("network")), \
                mock.patch("socket.create_connection", side_effect=AssertionError("network")):
            self.render(secret={"token": NTFY_TOKEN})
            self.ns.render(pushover_cfg(), {"app_token": PO_APP, "user_key": PO_USER}, msg())


class RenderPushover(Base):
    SECRET = {"app_token": PO_APP, "user_key": PO_USER}

    def render(self, cfg=None, secret=None, m=None):
        url, headers, body = self.ns.render(cfg or pushover_cfg(), secret or self.SECRET, m or msg())
        self.assertIsInstance(url, str)
        self.assertIsInstance(body, bytes)
        for k, v in header_items(headers):
            self.assertFalse(re.search(r"[\r\n]", k + v))
            v.encode("latin-1")
        return url, headers, {k: v[0] for k, v in form(body).items()}, form(body)

    def test_default_url_without_url_key(self):
        url, _, _, _ = self.render()
        self.assertEqual(url, PUSHOVER_DEFAULT)

    def test_url_override(self):
        url, _, _, _ = self.render(cfg=pushover_cfg("http://127.0.0.1:9999/1/messages.json"))
        self.assertEqual(url, "http://127.0.0.1:9999/1/messages.json")

    def test_exact_fields_per_level(self):  # A7
        for level, prio in (("quiet", "-1"), ("normal", "0"), ("ring", "2")):
            with self.subTest(level=level):
                _, headers, f, raw = self.render(m=msg(level=level))
                self.assertTrue(all(len(v) == 1 for v in raw.values()), raw)
                want = {"token", "user", "title", "message", "priority"} | ({"retry", "expire"} if level == "ring"
                                                                          else set())
                self.assertEqual(set(f), want)
                self.assertEqual(f["token"], PO_APP)
                self.assertEqual(f["user"], PO_USER)
                self.assertEqual(f["title"], "[agent-x] Build done")
                self.assertEqual(f["message"], "All 12 checks passed.")
                self.assertEqual(f["priority"], prio)
                if level == "ring":
                    self.assertEqual((f["retry"], f["expire"]), ("45", "900"))
                self.assertEqual(header(headers, "Authorization"), [])
                for ctype in header(headers, "Content-Type"):
                    self.assertEqual(ctype.split(";")[0].strip().lower(), "application/x-www-form-urlencoded")

    def test_bounds_and_cleaning(self):  # A8, A9
        _, _, f, _ = self.render(m=msg(title="T " * 150 + "\x1b\r\n", text="x " * 2500 + "\x00", sender="s " * 50))
        m = re.match(r"^\[([^\]]*)\] (.*)$", f["title"], re.S)
        self.assertTrue(m, f["title"])
        self.assertTrue(0 < len(m.group(1)) <= 40)
        self.assertLessEqual(m.group(2).count("T"), 100)
        self.assertLessEqual(len(f["message"]), 1000)
        self.assertFalse(has_bad(f["title"]) or has_bad(f["message"]))

    def test_unicode_survives_in_the_body(self):
        text = "Gr\u00fc\u00dfe \u2603 \u65e5\u672c\u8a9e \U0001F680 ok"
        _, _, f, _ = self.render(m=msg(text=text, title="\u2603"))
        self.assertEqual(f["message"], text)
        self.assertEqual(f["title"], "[agent-x] \u2603")

    def test_form_injection_stays_in_its_field(self):
        _, _, f, raw = self.render(m=msg(title="a&priority=2&user=x", text="b=c&token=y"))
        self.assertEqual(raw["priority"], ["0"])
        self.assertEqual(raw["user"], [PO_USER])
        self.assertEqual(raw["token"], [PO_APP])
        self.assertIn("a&priority=2&user=x", f["title"])


class RenderHardening(Base):
    """Section 4d.2 and 4d.3: tags that would publish a secret, and masking before control characters go."""

    def test_secret_and_mask_changing_tags_are_dropped(self):  # 4d.2, A18
        rand32 = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV"
        known = ["gh" + "p_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn", "AK" + "IA" + "Z7Y6X5W4V3U2T1S0",
                 "s" + "k-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn"]  # built at run time: test_public forbids these shapes in source
        cases = [("equals the token", {"token": TAG_TOKEN}, TAG_TOKEN),
                 ("contains the token", {"token": "Qx7Lm2Np9"}, "pre-Qx7Lm2Np9-x"),
                 ("random 32", {"token": NTFY_TOKEN}, rand32)] + [("known prefix", {"token": NTFY_TOKEN}, k)
                                                                  for k in known]
        self.assertEqual(len(TAG_TOKEN), 32)
        for name, secret, bad in cases:
            with self.subTest(case=name, tag=bad[:6]):
                self.assertTrue(TAG_RE.fullmatch(bad), bad)
                if secret["token"] not in bad:
                    self.assertNotEqual(mmcore.mask(bad), bad, "precondition: mask() changes this tag")
                _, _, body = self.ns.render(ntfy_cfg(), secret, msg(tags=["ci", bad, "build"]))
                self.assertEqual(json.loads(body).get("tags", []), ["ci", "build"])
                self.assertNotIn(bad, body.decode("utf-8"))

    def test_secret_cut_short_never_survives(self):  # 4e.1, A24
        rng = random.Random(4)
        tail = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(36))
        shapes = {"ghp": ":" + "gh" + "p_" + tail, "github_pat": "/" + "github" + "_pat_" + tail + "_" + tail[:22],
                  "sk": ":" + "s" + "k-" + tail, "akia": "=" + "AK" + "IA" + tail[:16],
                  "xoxb": ":" + "xo" + "xb-" + tail}
        lower = "".join(rng.choice(string.ascii_lowercase) for _ in range(5000))
        fillers = {  # what comes before the secret, with no white space before a cut (but "words")
            "lower": lower, "words": " ".join(lower[i:i + 7] for i in range(0, 5000, 7)),
            "alnum": "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(5000)),  # a random word
            "printable": "".join(rng.choice(string.ascii_letters + string.digits + string.punctuation)
                                 for _ in range(5000))}
        line_cut = mmtext.TEXT_LINE_MAX
        cuts = {"title": (90, 100, 110, line_cut - len(mmtext.CUT_MARK), line_cut),
                "text": (1000, line_cut - len(mmtext.CUT_MARK), line_cut)}
        services = (("ntfy", ntfy_cfg(), {"token": NTFY_TOKEN}),
                    ("pushover", pushover_cfg(), {"app_token": PO_APP, "user_key": PO_USER}))

        def check(service, cfg, sec, field, text, **where):
            with self.subTest(service=service, field=field, **where):
                _, _, body = self.ns.render(cfg, sec, msg(**{field: text}))
                fields = json.loads(body) if service == "ntfy" else {k: v[0] for k, v in form(body).items()}
                shown = fields["title"] + "\n" + fields["message"]
                self.assertEqual(sorted(x for x in pieces if x in shown), [])
                if field == "text" and where.get("style") == "lower" and len(text) > 1000:  # one word (A28)
                    kept = text[:min(where["start"] - 1, 1000)]  # the filler before the shape (the shape is masked)
                    self.assertTrue(fields["message"] in ("", mmtext.CUT_MARK) or fields["message"].startswith(kept),
                                    "a piece of the cut word was kept: %r" % fields["message"][:40])
        for name, shape in shapes.items():
            pieces = parts(shape[1:])
            for service, cfg, sec in services if name == "ghp" else services[:1]:
                for field, points in cuts.items():
                    for point in points:  # the secret moved across each likely cut point
                        for start in range(point - len(shape), point + 2, 3):
                            for style, filler in fillers.items():
                                check(service, cfg, sec, field, filler[:start - 1] + shape, shape=name, cut=point,
                                      start=start, style=style)
                    for start in range(3940, 4110):  # 3940+ characters before the shape: every start, two fillers
                        for style in ("lower", "alnum", "printable"):
                            check(service, cfg, sec, field, fillers[style][:start - 1] + shape, shape=name,
                                  start=start, style=style)

    def test_short_secret_inside_a_tag_is_dropped(self):  # 4e.2
        for tok in ("x", "xq", "xqz", "xqz7", "xqz7k"):
            for tag in (tok, "pre-%s-post" % tok, tok + "post", "pre" + tok):
                with self.subTest(token=tok, tag=tag):
                    _, _, body = self.ns.render(ntfy_cfg(), {"token": tok}, msg(tags=["ci", tag, "build"]))
                    self.assertEqual(json.loads(body).get("tags", []), ["ci", "build"])

    SAMPLES = {"Secret123abcXYZ": "deploy Bearer\tSecret123abcXYZ done",
               "FlagSecret99x": "run --token\tFlagSecret99x now",
               "Pass2Secret55z": "login --password\tPass2Secret55z",
               "PwSecret77y": "PASSWORD\t=\tPwSecret77y"}

    def test_samples_need_mask_before_clean(self):  # A19: each sample tells the two orders apart
        for secret, sample in self.SAMPLES.items():
            with self.subTest(sample=sample):
                self.assertNotIn(secret, mmcore.mask(sample))
                self.assertIn(secret, mmcore.mask(mmtext.clean(sample)))

    def test_mask_runs_before_control_characters_are_replaced(self):  # 4d.3
        services = (("ntfy", ntfy_cfg(), {"token": NTFY_TOKEN}),
                    ("pushover", pushover_cfg(), {"app_token": PO_APP, "user_key": PO_USER}))
        for service, cfg, sec in services:
            for secret, sample in self.SAMPLES.items():
                for field in ("title", "text"):
                    with self.subTest(service=service, field=field, sample=sample):
                        _, _, body = self.ns.render(cfg, sec, msg(**{field: sample}))
                        raw = body.decode("utf-8")
                        shown = json.dumps(json.loads(raw), ensure_ascii=False) if service == "ntfy" else \
                            urllib.parse.unquote_plus(raw)
                        self.assertNotIn(secret, raw)
                        self.assertNotIn(secret, shown)
                        self.assertFalse(has_bad(shown.replace("\n", "")), "control characters are still replaced")


# --------------------------------------------------------------------------------------------- deliver

def reply(status, body=b"ok", headers=()):
    def respond(h, rec, release):
        h.send_response(status)
        for k, v in headers:
            h.send_header(k, v)
        h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        if body:
            h.wfile.write(body)
    return respond


class Fake:
    def __init__(self, server, requests, tls=False):
        self.server, self.requests = server, requests
        self.port = server.server_port
        self.url = "%s://127.0.0.1:%d" % ("https" if tls else "http", self.port)


class Deliver(Base):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for k in PROXY_VARS:  # A16
            os.environ.pop(k, None)
        os.environ["no_proxy"] = os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"

    @contextlib.contextmanager
    def fake(self, respond, tls_ctx=None):
        requests, lock, release = [], threading.Lock(), threading.Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            def handle_any(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(min(n, 1 << 20)) if n > 0 else b""
                rec = {"method": self.command, "path": self.path, "body": body,
                       "headers": [(k.lower(), v) for k, v in self.headers.items()]}
                with lock:
                    requests.append(rec)
                try:
                    respond(self, rec, release)
                except OSError:
                    pass  # the client hung up on purpose (cap, timeout)

            do_POST = do_GET = do_PUT = do_HEAD = handle_any

            def log_message(self, *args):
                pass

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass
        try:
            server = Server(("127.0.0.1", 0), Handler)
        except PermissionError:
            self.skipTest("loopback sockets unavailable in command sandbox")
        if tls_ctx is not None:
            server.socket = tls_ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        try:
            yield Fake(server, requests, tls=tls_ctx is not None)
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(5)

    def check(self, r):
        """The result shape every deliver call returns (contract section 3)."""
        self.assertIsInstance(r, dict)
        self.assertEqual(set(r), {"ok", "status", "error", "detail"})
        self.assertIsInstance(r["ok"], bool)
        self.assertTrue(r["status"] is None or (type(r["status"]) is int), r["status"])
        self.assertIn(r["error"], (None, "E_NOTIFY_HTTP", "E_NOTIFY_NET", "E_NOTIFY_REFUSED"))
        self.assertEqual(r["ok"], r["error"] is None)
        self.assertIsInstance(r["detail"], str)
        self.assertLessEqual(len(r["detail"]), 120)
        self.assertFalse(has_bad(r["detail"]), repr(r["detail"]))
        for secret in ALL_SECRETS:  # 4d.1: no 6+ character part of a configured secret (A17)
            leaked = sorted(p for p in parts(secret) if p in r["detail"])
            self.assertEqual(leaked, [], r["detail"])
        for mark in (BODY_MARK, TITLE_MARK):
            self.assertNotIn(mark, r["detail"])
        return r

    def deliver(self, cfg, secret=None, m=None, timeout_s=5):
        return self.check(self.ns.deliver(cfg, secret, m or msg(), timeout_s))

    def closed_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
        except PermissionError:
            self.skipTest("loopback sockets unavailable in command sandbox")
        port = s.getsockname()[1]
        s.close()
        return port

    def test_ntfy_ok_and_request_seen(self):  # A14
        m = msg(title=TITLE_MARK, text=BODY_MARK + " \u2603", tags=["ci"])
        for status in (200, 204):
            with self.subTest(status=status), self.fake(reply(status, b"" if status == 204 else b"{}")) as f:
                r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN}, m)
                self.assertEqual((r["ok"], r["status"], r["error"]), (True, status, None))
                self.assertEqual(len(f.requests), 1)
                rec = f.requests[0]
                self.assertEqual(rec["method"], "POST")
                self.assertEqual(rec["path"], "/")
                hdr = dict(rec["headers"])
                self.assertEqual(hdr.get("authorization"), "Bearer " + NTFY_TOKEN)
                self.assertEqual(hdr.get("content-type", "").split(";")[0].strip().lower(), "application/json")
                doc = json.loads(rec["body"].decode("utf-8"))
                self.assertEqual(doc, {"topic": "mm-alerts", "title": "[agent-x] " + TITLE_MARK,
                                       "message": BODY_MARK + " \u2603", "priority": 3, "tags": ["ci"]})
                self.assertEqual(json.loads(self.ns.render(ntfy_cfg(f.url), {"token": NTFY_TOKEN}, m)[2]), doc)

    def test_ntfy_without_token_sends_no_authorization(self):
        with self.fake(reply(200)) as f:
            r = self.deliver(ntfy_cfg(f.url + "/ntfy"), None, msg(level="ring"))
            self.assertTrue(r["ok"])
            rec = f.requests[0]
            self.assertNotIn("authorization", dict(rec["headers"]))
            self.assertEqual(rec["path"].rstrip("/"), "/ntfy")  # A6
            self.assertEqual(json.loads(rec["body"])["priority"], 5)

    def test_pushover_request_seen(self):
        with self.fake(reply(200, b'{"status":1}')) as f:
            cfg = pushover_cfg(f.url + "/1/messages.json")
            r = self.deliver(cfg, {"app_token": PO_APP, "user_key": PO_USER}, msg(level="ring", text=BODY_MARK))
            self.assertEqual((r["ok"], r["status"]), (True, 200))
            rec = f.requests[0]
            self.assertEqual((rec["method"], rec["path"]), ("POST", "/1/messages.json"))
            self.assertNotIn("authorization", dict(rec["headers"]))
            fields = {k: v[0] for k, v in form(rec["body"]).items()}
            self.assertEqual(fields, {"token": PO_APP, "user": PO_USER, "title": "[agent-x] Build done",
                                      "message": BODY_MARK, "priority": "2", "retry": "45", "expire": "900"})

    def test_refused_statuses(self):  # A12
        for status in (400, 401, 403):
            with self.subTest(status=status), self.fake(reply(status, b'{"error":"no"}')) as f:
                r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN})
                self.assertEqual((r["ok"], r["status"], r["error"]), (False, status, "E_NOTIFY_REFUSED"))
                self.assertEqual(len(f.requests), 1)

    def test_server_errors(self):
        for status in (500, 503):
            with self.subTest(status=status), self.fake(reply(status, b"<html>" + b"x" * 4000)) as f:
                r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN})
                self.assertEqual((r["ok"], r["status"], r["error"]), (False, status, "E_NOTIFY_HTTP"))
                self.assertGreaterEqual(len(f.requests), 1)

    def test_redirects_are_never_followed(self):  # A12
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status), self.fake(reply(200)) as second:
                target = second.url + "/stolen"
                with self.fake(reply(status, b"moved", headers=[("Location", target)])) as first:
                    r = self.deliver(ntfy_cfg(first.url), {"token": NTFY_TOKEN}, msg(text=BODY_MARK))
                    self.assertEqual((r["ok"], r["error"]), (False, "E_NOTIFY_HTTP"))
                    self.assertEqual(r["status"], status)
                    self.assertEqual(len(first.requests), 1)
                self.assertEqual(second.requests, [], "the redirect target got a request")
            with self.subTest(status=status, service="pushover"), self.fake(reply(200)) as second:
                with self.fake(reply(status, b"", headers=[("Location", second.url)])) as first:
                    r = self.deliver(pushover_cfg(first.url), {"app_token": PO_APP, "user_key": PO_USER})
                    self.assertEqual((r["ok"], r["error"]), (False, "E_NOTIFY_HTTP"))
                self.assertEqual(second.requests, [])

    def test_slow_server_is_a_network_error_in_bounded_time(self):  # A11
        def slow(h, rec, release):
            if release.wait(10):
                return
            reply(200)(h, rec, release)
        with self.fake(slow) as f:
            t0 = time.monotonic()
            r = self.deliver(ntfy_cfg(f.url, timeout_s=30), {"token": NTFY_TOKEN}, timeout_s=1)
            took = time.monotonic() - t0
            self.assertEqual((r["ok"], r["status"], r["error"]), (False, None, "E_NOTIFY_NET"))
            self.assertLess(took, 2.5)

    def test_trickling_headers_hit_the_total_timeout(self):  # A11
        def trickle(h, rec, release):
            h.wfile.write(b"HTTP/1.0 200 OK\r\n")
            h.wfile.flush()
            for i in range(60):  # 6 s of headers, one line each 0.1 s: no single read waits for a second
                if release.wait(0.1):
                    return
                h.wfile.write(b"X-Pad-%d: a\r\n" % i)
                h.wfile.flush()
            h.wfile.write(b"Content-Length: 2\r\n\r\nok")
        with self.fake(trickle) as f:
            t0 = time.monotonic()
            r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN}, timeout_s=1)
            took = time.monotonic() - t0
            self.assertLess(took, 3.0, "timeout_s is a total limit, not a per-read one")
            self.assertEqual((r["ok"], r["error"]), (False, "E_NOTIFY_NET"))

    def test_connection_refused_is_a_network_error(self):
        port = self.closed_port()
        t0 = time.monotonic()
        r = self.deliver(ntfy_cfg("http://127.0.0.1:%d" % port), {"token": NTFY_TOKEN}, timeout_s=2)
        self.assertEqual((r["ok"], r["status"], r["error"]), (False, None, "E_NOTIFY_NET"))
        self.assertLess(time.monotonic() - t0, 3.5)
        r = self.deliver(pushover_cfg("http://127.0.0.1:%d/1/messages.json" % port),
                         {"app_token": PO_APP, "user_key": PO_USER}, timeout_s=2)
        self.assertEqual((r["ok"], r["error"]), (False, "E_NOTIFY_NET"))

    @contextlib.contextmanager
    def counted_reads(self):
        """Body bytes the module reads (A21, A27): n["api"] is what HTTPResponse's read calls return to the module
        (outermost calls; IncompleteRead.partial when a read raises), n["wire"] is what HTTPResponse takes from its
        buffered file after the headers, raising reads included."""
        n, local = {"api": 0, "wire": 0}, threading.local()

        def size(got):
            return got if isinstance(got, int) else len(got or b"")

        def wrap(orig):
            def counted(resp, *a, **k):
                depth = getattr(local, "depth", 0)
                local.depth = depth + 1
                try:
                    got = orig(resp, *a, **k)
                except http.client.IncompleteRead as e:
                    if depth == 0:
                        n["api"] += len(e.partial or b"")
                    raise
                finally:
                    local.depth = depth
                if depth == 0:
                    n["api"] += size(got)
                return got
            return counted

        class Wire:
            def __init__(self, fp):
                self._fp = fp

            def __getattr__(self, name):
                return getattr(self._fp, name)

            def _take(self, name, *a):
                got = getattr(self._fp, name)(*a)
                n["wire"] += size(got)
                return got

            def read(self, *a):
                return self._take("read", *a)

            def read1(self, *a):
                return self._take("read1", *a)

            def readinto(self, b):
                return self._take("readinto", b)

            def readinto1(self, b):
                return self._take("readinto1", b)

            def readline(self, *a):
                return self._take("readline", *a)
        begin = http.client.HTTPResponse.begin

        def counting_begin(resp):
            begin(resp)
            if resp.fp is not None:
                resp.fp = Wire(resp.fp)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(http.client.HTTPResponse, "begin", counting_begin))
            for name in ("read", "read1", "readinto", "readinto1", "readline"):
                stack.enter_context(mock.patch.object(http.client.HTTPResponse, name,
                                                      wrap(getattr(http.client.HTTPResponse, name))))
            yield n

    def assert_read_bound(self, n, chunked):
        self.assertLessEqual(n["api"], 65537, "the response read is at most 64 KiB plus one sentinel byte")
        self.assertLessEqual(n["wire"], 65537 + (256 if chunked else 0), "bytes taken below the read calls")

    def test_oversize_body_read_is_at_most_65537_bytes(self):  # 4d.6, A13, A21
        chunk = b"z" * 65536

        def big(status, length=None, chunked=False):
            def respond(h, rec, release):
                h.send_response(status)
                if length:
                    h.send_header("Content-Length", str(length))
                if chunked:
                    h.send_header("Transfer-Encoding", "chunked")
                h.end_headers()
                sent = 0
                while sent < (length or 256 << 20) and not release.is_set():
                    h.wfile.write(b"10000\r\n" + chunk + b"\r\n" if chunked else chunk)
                    sent += len(chunk)
            return respond
        cases = [("200 content-length", 200, 16 << 20, False, True), ("200 close-delimited", 200, None, False, True),
                 ("200 chunked", 200, None, True, True), ("400 content-length", 400, 16 << 20, False, False),
                 ("500 close-delimited", 500, None, False, False)]
        for name, status, length, chunked, ok in cases:
            with self.subTest(case=name), self.fake(big(status, length, chunked)) as f, self.counted_reads() as n:
                t0 = time.monotonic()
                r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN}, timeout_s=3)
                took = time.monotonic() - t0
                self.assert_read_bound(n, chunked)
                self.assertLess(took, 4.5)
                self.assertEqual((r["ok"], r["status"]), (ok, status))

    def test_detail_never_holds_secrets_or_the_request(self):
        def echo(status):
            def respond(h, rec, release):
                auth = dict(rec["headers"]).get("authorization", "").encode("latin-1")
                body = b"\x1b[31m\r\n" + auth + b" " + rec["body"] + b" " + b"y" * 500
                reply(status, body)(h, rec, release)
            return respond
        m = msg(title=TITLE_MARK, text=BODY_MARK)
        for status in (200, 400, 401, 500):
            with self.subTest(status=status, service="ntfy"), self.fake(echo(status)) as f:
                self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN}, m)
            with self.subTest(status=status, service="pushover"), self.fake(echo(status)) as f:
                self.deliver(pushover_cfg(f.url), {"app_token": PO_APP, "user_key": PO_USER}, m)

    def test_header_injection_never_reaches_the_server(self):  # A10
        with self.fake(reply(200)) as f:
            for secret in ({"token": "abc\r\nX-Evil: 1"}, {"token": "t\u00f6ken\u20ac"}, {"token": NTFY_TOKEN}):
                try:  # A10: a bad secret may be refused (MMError) before any request; it never reaches a header
                    self.deliver(ntfy_cfg(f.url), secret, msg(title="a\r\nX-Evil: 2", sender="b\r\nX-Evil: 3"))
                except mmcore.MMError as e:
                    self.assertEqual(e.code, "E_NOTIFY_SECRET")
            self.assertTrue(f.requests, "the valid token must still deliver")
            for rec in f.requests:
                self.assertNotIn("x-evil", dict(rec["headers"]))

    def test_https_to_a_plain_server_is_a_network_error(self):
        with self.fake(reply(200)) as f:
            r = self.deliver(ntfy_cfg("https://127.0.0.1:%d" % f.port), {"token": NTFY_TOKEN}, timeout_s=2)
            self.assertEqual((r["ok"], r["status"], r["error"]), (False, None, "E_NOTIFY_NET"))
            self.assertEqual([x for x in f.requests if x["method"] == "POST"], [])

    @unittest.skipUnless(shutil.which("openssl"), "needs the openssl command for a self-signed certificate")
    def test_untrusted_certificate_is_refused(self):
        cert, key = os.path.join(self.root, "cert.pem"), os.path.join(self.root, "key.pem")
        made = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out",
                               cert, "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                              capture_output=True, timeout=30)
        if made.returncode != 0:
            self.skipTest("openssl could not make a certificate: %s" % made.stderr[-200:])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        with self.fake(reply(200), tls_ctx=ctx) as f:
            r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN}, timeout_s=3)
            self.assertEqual((r["ok"], r["error"]), (False, "E_NOTIFY_NET"))
            self.assertEqual(f.requests, [], "TLS verification is always on")

    def test_deliver_reads_no_profile(self):
        os.environ["MM_PROFILE"] = os.path.join(self.root, "absent-profile.toml")
        trap = mock.Mock(side_effect=AssertionError("profile read"))
        with self.fake(reply(200)) as f, mock.patch.object(mmcore, "load_profile", trap), \
                mock.patch.object(mmcore, "profile_file", trap):
            r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN})
            self.assertTrue(r["ok"])
        self.assertFalse(trap.called)


    # ----------------------------------------------------------------------------------- section 4d

    def test_reason_phrase_never_leaks_a_secret(self):  # 4d.1, A17
        def reason(status, text):
            def respond(h, rec, release):
                h.send_response(status, text)
                h.send_header("Content-Length", "2")
                h.end_headers()
                h.wfile.write(b"no")
            return respond
        tok = REASON_TOKEN
        placements = {"password= then 950 x": "password=" + "x" * 950 + " " + tok, "at the start": tok + " not allowed",
                      "after words": "denied for " + tok, "across a 120 cut": "x" * 100 + tok,
                      "after a tab": "Bearer\t" + tok, "twice": tok + " and " + tok}
        for status, error in ((400, "E_NOTIFY_REFUSED"), (401, "E_NOTIFY_REFUSED"), (500, "E_NOTIFY_HTTP")):
            for name, text in placements.items():
                with self.subTest(status=status, placement=name), self.fake(reason(status, text)) as f:
                    r = self.deliver(ntfy_cfg(f.url), {"token": tok})
                    self.assertEqual((r["ok"], r["status"], r["error"]), (False, status, error))
        for name, text in {"both keys": "app %s user %s" % (PO_APP, PO_USER), "across a 120 cut": "x" * 100 + PO_USER,
                           "password=": "password=" + "x" * 950 + " " + PO_APP}.items():
            with self.subTest(service="pushover", placement=name), self.fake(reason(400, text)) as f:
                r = self.deliver(pushover_cfg(f.url), {"app_token": PO_APP, "user_key": PO_USER})
                self.assertEqual((r["ok"], r["status"], r["error"]), (False, 400, "E_NOTIFY_REFUSED"))

    def test_secret_tag_is_never_published(self):  # 4d.2
        with self.fake(reply(200)) as f:
            r = self.deliver(ntfy_cfg(f.url), {"token": TAG_TOKEN}, msg(tags=["ci", TAG_TOKEN]))
            self.assertTrue(r["ok"])
            body = f.requests[0]["body"].decode("utf-8")
            self.assertNotIn(TAG_TOKEN, body)
            self.assertEqual(json.loads(body).get("tags", []), ["ci"])

    @contextlib.contextmanager
    def delayed(self, kind, port, delay):
        """kind "connect": socket.socket.connect (and connect_ex) to 127.0.0.1:port waits `delay` seconds; kind
        "resolve": socket.getaddrinfo for "localhost" waits. Yields the list of slowed calls (4e.4, A25)."""
        calls, gate = [], threading.Event()
        if kind == "connect":
            def slowed(real):
                def method(sock, address, *a, **k):
                    if isinstance(address, tuple) and tuple(address[:2]) == ("127.0.0.1", port):
                        calls.append(address)
                        gate.wait(delay)
                    return real(sock, address, *a, **k)
                return method
            patches = [mock.patch.object(socket.socket, name, slowed(getattr(socket.socket, name)))
                       for name in ("connect", "connect_ex")]
        else:
            real = socket.getaddrinfo

            def resolve(host, *a, **k):
                if host in ("localhost", b"localhost"):
                    calls.append(host)
                    gate.wait(delay)
                return real(host, *a, **k)
            patches = [mock.patch("socket.getaddrinfo", resolve)]
        try:
            with contextlib.ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                yield calls
        finally:
            gate.set()

    LATE = (("connect", "127.0.0.1"), ("resolve", "localhost"))

    def test_no_late_send_after_a_timeout(self):  # 4d.4, 4e.4, A25
        for kind, host in self.LATE:
            with self.subTest(delay=kind, host=host), self.fake(reply(200)) as f:
                t0 = time.monotonic()
                with self.delayed(kind, f.port, 1.6) as calls:
                    r = self.deliver(ntfy_cfg("http://%s:%d" % (host, f.port)), {"token": NTFY_TOKEN},
                                     msg(text=BODY_MARK), timeout_s=1)
                    took = time.monotonic() - t0
                    time.sleep(max(0.0, 2.4 - (time.monotonic() - t0)))  # the delay has ended: a late send lands now
                self.assertTrue(calls, "the injected delay ran")
                self.assertEqual((r["ok"], r["error"]), (False, "E_NOTIFY_NET"))
                self.assertLess(took, 2.5)
                self.assertEqual([x["path"] for x in f.requests if x["method"] == "POST"], [],
                                 "no request reaches the server after deliver returned E_NOTIFY_NET")

    def test_no_late_send_control_without_delay(self):  # 4e.4: the same path, no delay: one POST, on time
        for kind, host in self.LATE:
            with self.subTest(delay=kind, host=host), self.fake(reply(200)) as f:
                t0 = time.monotonic()
                with self.delayed(kind, f.port, 0) as calls:
                    r = self.deliver(ntfy_cfg("http://%s:%d" % (host, f.port)), {"token": NTFY_TOKEN}, timeout_s=1)
                took = time.monotonic() - t0
                time.sleep(0.3)
                self.assertTrue(calls, "the patched function is on the module's path")
                self.assertEqual((r["ok"], r["status"]), (True, 200))
                self.assertLess(took, 1.5)
                self.assertEqual(len([x for x in f.requests if x["method"] == "POST"]), 1)

    def echo_server(self):
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                with contextlib.suppress(OSError):
                    while True:
                        data = self.request.recv(64)
                        if not data:
                            return
                        self.request.sendall(data)

        class EchoServer(socketserver.ThreadingTCPServer):
            daemon_threads = True
        try:
            echo = EchoServer(("127.0.0.1", 0), Echo)
        except PermissionError:
            self.skipTest("loopback sockets unavailable in command sandbox")
        threading.Thread(target=echo.serve_forever, kwargs={"poll_interval": .01}, daemon=True).start()
        self.addCleanup(echo.server_close)
        self.addCleanup(echo.shutdown)
        return echo

    def test_watchdog_never_shuts_down_a_reused_descriptor(self):  # 4e.3, A26
        echo = self.echo_server()
        unrelated = socket.create_connection(echo.server_address, timeout=3)
        self.addCleanup(unrelated.close)
        swapped, release = [], threading.Event()
        self.addCleanup(release.set)

        def stalled(real):
            def method(sock, *a, **k):
                try:
                    peer = sock.getpeername()
                except OSError:
                    peer = None
                if not swapped and isinstance(peer, tuple) and peer[1] == port[0]:
                    fd = sock.fileno()
                    os.dup2(unrelated.fileno(), fd)  # the module's number now names the unrelated connection
                    swapped.append(fd)
                    release.wait(1.8)  # past timeout_s: the watchdog fires while the number is reused
                    raise TimeoutError("test: the read stalled")
                return real(sock, *a, **k)
            return method
        port = [None]
        with self.fake(lambda h, rec, release: release.wait(5)) as f:
            port[0] = f.port
            with mock.patch.object(socket.socket, "recv_into", stalled(socket.socket.recv_into)), \
                    mock.patch.object(socket.socket, "recv", stalled(socket.socket.recv)):
                r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN}, timeout_s=1)
        self.assertTrue(swapped, "the injected read ran (A26)")
        self.assertFalse(r["ok"])
        got, problem = b"", None
        try:
            unrelated.sendall(b"ping")
            while b"ping" not in got:
                data = unrelated.recv(64)
                if not data:
                    break
                got += data
        except OSError as e:
            problem = e
        self.assertIsNone(problem, "the watchdog shut down a socket it does not own")
        self.assertIn(b"ping", got, "the watchdog shut down a socket it does not own")

    def test_reads_that_raise_are_counted_and_bounded(self):  # 4d.6, A27
        chunk = b"c" * 16384

        def chunked(after):
            def respond(h, rec, release):
                h.send_response(200)
                h.send_header("Transfer-Encoding", "chunked")
                h.end_headers()
                h.wfile.write(after)
            return respond

        def truncated(h, rec, release):
            h.send_response(200)
            h.send_header("Content-Length", str(1 << 20))
            h.end_headers()
            h.wfile.write(b"t" * (200 << 10))  # then the connection closes: 1 MiB promised
        frames = b"".join(b"4000\r\n" + chunk + b"\r\n" for _ in range(10))
        cases = [("bad size line after 160 KiB", chunked(frames + b"zz\r\n"), True),
                 ("bad size line at 64 KiB", chunked(b"10000\r\n" + b"c" * 65536 + b"\r\nzz\r\n"), True),
                 ("chunk cut short after 160 KiB", chunked(frames + b"4000\r\n" + b"c" * 100), True),
                 ("first chunk cut short", chunked(b"100000\r\n" + b"c" * (200 << 10)), True),
                 ("content-length cut short", truncated, False)]
        for name, respond, is_chunked in cases:
            with self.subTest(case=name), self.fake(respond) as f, self.counted_reads() as n:
                t0 = time.monotonic()
                r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN}, timeout_s=3)
                self.assertLess(time.monotonic() - t0, 4.5)
                self.assertIn(r["status"], (200, None))
                self.assert_read_bound(n, is_chunked)

    def test_every_3xx_is_an_http_error_and_no_location_is_followed(self):  # 4d.5
        with self.fake(reply(200)) as other:
            locations = {"other server": other.url + "/x", "same server": "/again", "malformed": "http://[bad",
                         "absent": None, "empty": ""}
            for status in (300, 301, 302, 303, 304, 305, 307, 308):
                for name, loc in locations.items():
                    with self.subTest(status=status, location=name):
                        headers = [] if loc is None else [("Location", loc)]
                        with self.fake(reply(status, b"", headers=headers)) as first:
                            r = self.deliver(ntfy_cfg(first.url), {"token": NTFY_TOKEN})
                            self.assertEqual((r["ok"], r["status"], r["error"]), (False, status, "E_NOTIFY_HTTP"))
                            self.assertEqual(len(first.requests), 1)
            for name in ("malformed", "absent"):
                with self.subTest(service="pushover", location=name):
                    headers = [("Location", "http://[bad")] if name == "malformed" else []
                    with self.fake(reply(302, b"", headers=headers)) as first:
                        r = self.deliver(pushover_cfg(first.url), {"app_token": PO_APP, "user_key": PO_USER})
                        self.assertEqual((r["ok"], r["status"], r["error"]), (False, 302, "E_NOTIFY_HTTP"))
                        self.assertEqual(len(first.requests), 1)
            self.assertEqual(other.requests, [])

    def test_loopback_http_never_uses_an_environment_proxy(self):  # 4d.7
        with self.fake(reply(200, b"trapped")) as trap, self.fake(reply(200)) as f:
            for k in ("no_proxy", "NO_PROXY"):
                os.environ.pop(k, None)
            for k in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
                os.environ[k] = trap.url
            cases = [("ntfy 127.0.0.1", ntfy_cfg(f.url), {"token": NTFY_TOKEN}),
                     ("ntfy localhost", ntfy_cfg("http://localhost:%d" % f.port), {"token": NTFY_TOKEN}),
                     ("pushover 127.0.0.1", pushover_cfg(f.url + "/1/messages.json"),
                      {"app_token": PO_APP, "user_key": PO_USER})]
            for name, cfg, sec in cases:
                with self.subTest(case=name):
                    r = self.deliver(cfg, sec)
                    self.assertEqual((r["ok"], r["status"]), (True, 200))
            self.assertEqual(trap.requests, [], "a loopback delivery went to the proxy")
            self.assertEqual(len([x for x in f.requests if x["method"] == "POST"]), len(cases))

    def ca_and_certs(self):
        """A test CA and two server certificates it signs: IP 127.0.0.1 (the control) and DNS other.example."""
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("needs the openssl command to make a test CA")
        d = os.path.join(self.root, "pki")
        os.mkdir(d, 0o700)

        def run(*args):
            p = subprocess.run([openssl, *args], capture_output=True, timeout=30, cwd=d)
            if p.returncode:
                self.skipTest("openssl could not make the test CA: %s" % p.stderr[-200:])
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1",
            "-subj", "/CN=notify test CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        for name, cn, san in (("ip", "127.0.0.1", "IP:127.0.0.1"), ("other", "other.example", "DNS:other.example")):
            with open(os.path.join(d, name + ".ext"), "w") as f:
                f.write("subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\n"
                        "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n" % san)
            run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", name + ".key", "-out", name + ".csr",
                "-subj", "/CN=" + cn)
            run("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                "-out", name + ".pem", "-days", "1", "-extfile", name + ".ext")
        return {k: os.path.join(d, k) for k in ("ca.pem", "ip.pem", "ip.key", "other.pem", "other.key")}

    def test_trusted_certificate_for_another_host_name_is_refused(self):  # 4d.7, A23
        pki = self.ca_and_certs()
        os.environ["SSL_CERT_FILE"] = pki["ca.pem"]
        original = ssl.create_default_context

        def trusting(*a, **k):
            ctx = original(*a, **k)
            ctx.load_verify_locations(cafile=pki["ca.pem"])
            return ctx

        def server_ctx(name):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(pki[name + ".pem"], pki[name + ".key"])
            return ctx
        with mock.patch("ssl.create_default_context", trusting), \
                mock.patch("ssl._create_default_https_context", trusting):
            with self.fake(reply(200), tls_ctx=server_ctx("ip")) as f:
                r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN}, timeout_s=3)
                if not r["ok"]:
                    self.skipTest("the module's TLS context did not take the test CA (A23): %s" % r["detail"])
            with self.fake(reply(200), tls_ctx=server_ctx("other")) as f:
                r = self.deliver(ntfy_cfg(f.url), {"token": NTFY_TOKEN}, timeout_s=3)
                self.assertEqual((r["ok"], r["status"], r["error"]), (False, None, "E_NOTIFY_NET"))
                self.assertEqual(f.requests, [], "TLS checks the host name")


# --------------------------------------------------------------------------------------------- import

CHILD = r'''
import json, os, sys
core, secret = sys.argv[1], sys.argv[2]
sys.path.insert(0, core)
import mmcore, mmtext  # their own import is not this module's
events = {"import": [], "use": []}
phase = ["import"]
WATCH = ("socket.", "subprocess.", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.fork", "os.mkdir",
         "os.rename", "os.remove", "os.rmdir", "os.chmod", "os.chown", "os.link", "os.symlink", "os.truncate",
         "os.utime", "os.chflags", "shutil.", "urllib.Request", "http.client.")
def hook(event, args):
    if phase[0] not in events or not (event == "open" or event.startswith(WATCH)):
        return
    out = []
    for a in args:
        if isinstance(a, (bytes, bytearray)):
            a = os.fsdecode(bytes(a))
        elif hasattr(a, "__fspath__"):
            a = os.fspath(a)
        if event == "open" and not out and isinstance(a, str):
            a = os.path.abspath(a)
        out.append(a if isinstance(a, (str, int, float, type(None))) else repr(a))
    events[phase[0]].append([event, out])
sys.addaudithook(hook)
import mmnotify_send as ns
phase[0] = "use"
checks = [ns.check_url("https://ntfy.example.net"), ns.check_url("http://ntfy.example.net")]
sec = ns.read_secret(secret, "ntfy")
r = ns.render({"enabled": True, "service": "ntfy", "url": "https://ntfy.example.net", "topic": "mm-alerts",
               "alert_levels": ["ACTION"], "ring_levels": ["ACTION"], "send_cleared": True, "alerts_per_hour": 30,
               "timeout_s": 10, "ring_retry_s": 60, "ring_expire_s": 1800}, sec,
              {"title": "t", "text": "x", "level": "normal", "sender": "mm", "tags": []})
phase[0] = "done"
print(json.dumps({"events": events, "checks": checks, "rendered": isinstance(r, tuple) and len(r) == 3}))
'''


class ImportSideEffects(unittest.TestCase):
    def test_import_and_use_write_nothing_and_touch_no_network_or_profile(self):
        os.makedirs(mmtest.TMP_BASE, exist_ok=True)
        root = os.path.realpath(tempfile.mkdtemp(prefix="notify-import-", dir=mmtest.TMP_BASE))
        self.addCleanup(shutil.rmtree, root, True)
        for d in ("home", "data", "base", "cwd", "config", "secrets"):
            os.makedirs(os.path.join(root, d))
        profile = os.path.join(root, "profile.toml")
        with open(profile, "w") as f:
            f.write('name = "import-test"\n[notify]\nenabled = true\n')
        secret = os.path.join(root, "secrets", "notify-secret.json")
        with open(secret, "w") as f:
            json.dump({"token": "abc"}, f)
        os.chmod(secret, 0o600)

        def tree():
            out = set()
            for d, dirs, names in os.walk(root):
                out |= {os.path.join(d, n) for n in dirs + names}
            return out
        before = tree()
        env = {k: v for k, v in os.environ.items() if k not in PROXY_VARS}
        env.update(HOME=os.path.join(root, "home"), MM_DATA=os.path.join(root, "data"),
                   MM_BASE=os.path.join(root, "base"), MM_PROFILE=profile, XDG_CONFIG_HOME=os.path.join(root, "config"),
                   XDG_DATA_HOME=os.path.join(root, "data"))
        p = subprocess.run([sys.executable, "-I", "-B", "-c", CHILD, CORE, secret], cwd=os.path.join(root, "cwd"),
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        out = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertEqual(out["checks"], [True, False])
        self.assertTrue(out["rendered"])
        self.assertEqual(tree(), before, "no file written under HOME, data, base or cwd")
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        for phase, events in out["events"].items():
            for event, args in events:
                with self.subTest(phase=phase, event=event, args=args[:2]):
                    if event == "open":
                        path, mode = args[0], args[1] if len(args) > 1 else None
                        flags = args[2] if len(args) > 2 else 0
                        writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or \
                            (isinstance(flags, int) and flags & write_flags)
                        self.assertFalse(writes, "no file is opened for writing")
                        if isinstance(path, str):
                            real = os.path.realpath(path)
                            self.assertFalse(real.endswith(".toml"), "no profile or settings file is read")
                            if phase == "use" and real == os.path.realpath(secret):
                                continue
                            self.assertFalse(real == root or real.startswith(root + os.sep),
                                             "nothing under HOME, data, base or the profile is opened")
                    elif event == "socket.gethostname":
                        continue
                    else:
                        self.fail("no network, process or file-changing call: %s" % event)


if __name__ == "__main__":
    unittest.main()
