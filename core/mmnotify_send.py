# SPDX-License-Identifier: Apache-2.0
"""Phone notification delivery for `mm notify` (NOTIFY.md): the secret file reader, the request builder and one HTTP
send. Services: ntfy (JSON publish) and Pushover (form POST).

Only the `mm notify ...` verbs import this module; the supervisor, the watchdog and the hook never do. Importing it
does nothing; it never reads the profile and never writes a file. Secrets stay out of errors, results and headers
other than the one Authorization header. One request per deliver(): no redirects (a 3xx is a failure), TLS always
verified (default context), at most RESPONSE_MAX response bytes read, one wall timeout. Plain http goes only to a
loopback host, and never through a proxy (a proxy would see the token).
"""
import ipaddress
import json
import math
import os
import re
import stat
import threading
import time
import urllib.parse

import mmcore
import mmtext

SECRET_MAX = 4096                  # bytes in the secret file
RESPONSE_MAX = 64 << 10            # bytes read from a response
URL_MAX = 512
TITLE_MAX, TEXT_MAX, SENDER_MAX, TAGS_MAX = 100, 1000, 40, 4
DETAIL_MAX = 120
TIMEOUT_MAX = 30
PUSHOVER_URL = "https://api.pushover.net/1/messages.json"
SERVICES = ("ntfy", "pushover")
LEVELS = ("quiet", "normal", "ring")
NTFY_PRIORITY = {"quiet": 2, "normal": 3, "ring": 5}
PUSHOVER_PRIORITY = {"quiet": -1, "normal": 0, "ring": 2}
RING_RETRY = (30, 3600, 60)        # pushover emergency repeat: low, high, default (seconds)
RING_EXPIRE = (60, 10800, 1800)    # pushover emergency stop
TAG = re.compile(r"[A-Za-z0-9_-]{1,32}")
TOPIC = re.compile(r"[A-Za-z0-9_-]{1,64}")
PUSHOVER_KEY = re.compile(r"[A-Za-z0-9]{1,64}")
# ntfy access tokens look like `tk_` and 29 letters/digits; the wider set also takes other ntfy-compatible servers'
# tokens. Every character is header-safe.
NTFY_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,128}")
SECRET_KEYS = {"ntfy": frozenset(("token",)), "pushover": frozenset(("app_token", "user_key"))}
SECRET_RULES = {"token": NTFY_TOKEN, "app_token": PUSHOVER_KEY, "user_key": PUSHOVER_KEY}


def _secret_error(what, path):
    return mmcore.MMError("E_NOTIFY_SECRET", "notify secret file %s" % what,
                          "make %s a regular file you own, mode 0600, as NOTIFY.md shows"
                          % mmtext.quoted(mmtext.clean(str(path))))


def _strict_json(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out

    def no_constant(_):
        raise ValueError("nonfinite number")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=no_constant)


def read_secret(path, service=None):
    """The secret file as a dict: {"token"} (ntfy) or {"app_token", "user_key"} (pushover). service None takes either
    set. The file must be a regular file (not a link) owned by this uid, without group/other mode bits, at most
    SECRET_MAX bytes of strict JSON (no duplicate keys or nonfinite numbers) with exactly those keys, each value a
    string matching SECRET_RULES. Otherwise MMError E_NOTIFY_SECRET; its text never holds file content."""
    if service is not None and service not in SERVICES:
        raise mmcore.MMError("E_PROFILE", "notify service must be ntfy or pushover", "correct [notify] service")
    if not isinstance(path, (str, bytes, os.PathLike)):
        raise _secret_error("path is not a path", path)
    path = os.path.expanduser(os.fspath(path))
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise _secret_error("is missing", path) from None
    except (OSError, ValueError):
        raise _secret_error("cannot be read", path) from None
    _check_stat(st, path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (OSError, ValueError):
        raise _secret_error("cannot be opened (a link?)", path) from None
    try:
        with os.fdopen(fd, "rb") as f:
            st2 = os.fstat(f.fileno())
            if (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino):
                raise _secret_error("changed while it was read", path)
            _check_stat(st2, path)
            raw = f.read(SECRET_MAX + 1)
    except OSError:
        raise _secret_error("cannot be read", path) from None
    if len(raw) > SECRET_MAX:
        raise _secret_error("is larger than %d bytes" % SECRET_MAX, path)
    try:
        doc = _strict_json(raw)
    except (UnicodeError, ValueError, RecursionError):
        raise _secret_error("is not one strict JSON object", path) from None
    if not isinstance(doc, dict):
        raise _secret_error("is not a JSON object", path)
    sets = [SECRET_KEYS[service]] if service else list(SECRET_KEYS.values())
    if frozenset(doc) not in sets:
        want = " or ".join("{%s}" % ", ".join(sorted(s)) for s in sets)
        raise _secret_error("must hold exactly the keys %s" % want, path)
    for key in sorted(doc):
        value = doc[key]
        if not isinstance(value, str) or not SECRET_RULES[key].fullmatch(value):
            raise _secret_error("has an invalid %s value" % key, path)
    return dict(doc)


def _check_stat(st, path):
    if stat.S_ISLNK(st.st_mode):
        raise _secret_error("is a link", path)
    if not stat.S_ISREG(st.st_mode):
        raise _secret_error("is not a regular file", path)
    if st.st_uid != os.getuid():
        raise _secret_error("is not owned by you", path)
    if st.st_mode & 0o077:
        raise _secret_error("is readable or writable by others (mode %o)" % stat.S_IMODE(st.st_mode), path)
    if st.st_size > SECRET_MAX:
        raise _secret_error("is larger than %d bytes" % SECRET_MAX, path)


def _url_error(what):
    return mmcore.MMError("E_PROFILE", "[notify] url %s" % what,
                          "use https://HOST[:PORT][/PATH], or http:// only to localhost or a loopback address")


def _loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url):
    """True when url is a valid notify URL (the rules of validate_url), else False. Never raises."""
    try:
        validate_url(url)
    except mmcore.MMError:
        return False
    return True


def validate_url(url):
    """The url when it is a valid notify URL, else MMError E_PROFILE: a str of 1..URL_MAX printable ASCII characters
    without whitespace or backslash; scheme https, or http only to localhost or a loopback IP literal; a host; no
    userinfo, query (`?`) or fragment (`#`); a valid port (1..65535) if one is given. The error never repeats the URL."""
    if not isinstance(url, str) or not url:
        raise _url_error("must be a non-empty string")
    if len(url) > URL_MAX:
        raise _url_error("is longer than %d characters" % URL_MAX)
    if not url.isascii() or not url.isprintable() or any(c.isspace() or c == "\\" for c in url):
        raise _url_error("must be printable ASCII without spaces or backslashes")
    if "?" in url or "#" in url:
        raise _url_error("must not hold a query or fragment")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        raise _url_error("is not a valid URL") from None
    if parsed.scheme not in ("https", "http"):
        raise _url_error("must use https")
    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise _url_error("must not hold a user name or password")
    if not host:
        raise _url_error("needs a host")
    if port is not None and not 1 <= port <= 65535:
        raise _url_error("has an invalid port")
    if parsed.scheme == "http" and not _loopback(host):
        raise _url_error("may use http only to localhost or a loopback address")
    return url


def _text(value, limit):
    """A message text as it leaves the machine: str, no surrogates, controls and `|` cleaned, secrets masked, cut."""
    value = "" if value is None else value if isinstance(value, str) else str(value)
    value = value.encode("utf-8", "replace").decode("utf-8")  # a lone surrogate becomes "?"
    value = mmtext.clean(value)[:max(limit * 4, 4096)]  # bound the work before masking
    return mmtext.clean(mmcore.mask(value))[:limit]


def _tags(value):
    if not isinstance(value, (list, tuple)):
        return []
    return [t for t in value if isinstance(t, str) and TAG.fullmatch(t)][:TAGS_MAX]


def _header(value):
    if not isinstance(value, str) or not all(" " <= c <= "~" for c in value):
        raise ValueError("unsafe header value")
    return value


def _int_in(cfg, key, low, high, default):
    value = cfg.get(key, default)
    if type(value) is not int or not low <= value <= high:
        raise mmcore.MMError("E_PROFILE", "[notify] %s must be a whole number %d..%d" % (key, low, high),
                             "correct [notify] %s" % key)
    return value


def _secret_value(secret, key):
    value = secret.get(key) if isinstance(secret, dict) else None
    if value is None:
        return None
    if not isinstance(value, str) or not SECRET_RULES[key].fullmatch(value):
        raise mmcore.MMError("E_NOTIFY_SECRET", "notify secret %s is invalid" % key, "correct the secret file")
    return value


def render(cfg, secret, msg):
    """(url, headers, body bytes) for one message; pure (no I/O). cfg: the [notify] dict; secret: read_secret()'s
    dict or None; msg: {"title", "text", "level", "sender", "tags"}. Texts are cleaned, masked and cut again here
    (title 100, text 1000, sender 40); tags keep the first 4 valid ones. Config problems raise MMError E_PROFILE,
    a missing or invalid secret E_NOTIFY_SECRET, an unknown level E_USAGE."""
    if not isinstance(cfg, dict) or cfg.get("service") not in SERVICES:
        raise mmcore.MMError("E_PROFILE", "[notify] service must be ntfy or pushover", "correct [notify] service")
    msg = msg if isinstance(msg, dict) else {}
    level = msg.get("level")
    if level not in LEVELS:
        raise mmcore.MMError("E_USAGE", "notify level must be quiet, normal or ring", "pass --level quiet|normal|ring")
    title = "[%s] %s" % (_text(msg.get("sender"), SENDER_MAX), _text(msg.get("title"), TITLE_MAX))
    text = _text(msg.get("text"), TEXT_MAX)
    if cfg["service"] == "ntfy":
        url = validate_url(cfg.get("url"))
        topic = cfg.get("topic")
        if not isinstance(topic, str) or not TOPIC.fullmatch(topic):
            raise mmcore.MMError("E_PROFILE", "[notify] topic must be 1..64 of A-Z a-z 0-9 _ -",
                                 "correct [notify] topic")
        headers = {"Content-Type": "application/json"}
        token = _secret_value(secret, "token")
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        body = json.dumps({"topic": topic, "title": title, "message": text, "priority": NTFY_PRIORITY[level],
                           "tags": _tags(msg.get("tags"))}, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    else:
        url = validate_url(cfg["url"]) if cfg.get("url") is not None else PUSHOVER_URL
        app, user = _secret_value(secret, "app_token"), _secret_value(secret, "user_key")
        if app is None or user is None:
            raise mmcore.MMError("E_NOTIFY_SECRET", "pushover needs app_token and user_key",
                                 "set [notify] secret_file to a file with both keys (NOTIFY.md)")
        fields = [("token", app), ("user", user), ("title", title), ("message", text),
                  ("priority", str(PUSHOVER_PRIORITY[level]))]
        if level == "ring":
            fields += [("retry", str(_int_in(cfg, "ring_retry_s", *RING_RETRY))),
                       ("expire", str(_int_in(cfg, "ring_expire_s", *RING_EXPIRE)))]
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body = urllib.parse.urlencode(fields).encode("ascii")
    return url, {k: _header(v) for k, v in headers.items()}, body


def _secrets_of(secret):
    if not isinstance(secret, dict):
        return []
    return sorted((v for v in secret.values() if isinstance(v, str) and v), key=len, reverse=True)


def _detail(text, secret):
    text = mmtext.clean(str(text))[:1000]
    for value in _secrets_of(secret):
        text = text.replace(value, "***")
    return mmtext.clean(mmcore.mask(text))[:DETAIL_MAX]


def _result(ok, status, error, detail, secret):
    return {"ok": ok, "status": status, "error": error, "detail": _detail(detail, secret)}


def _net_detail(exc):
    import socket
    import ssl
    reason = getattr(exc, "reason", exc)  # URLError wraps the cause
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timed out"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "TLS certificate not trusted"
    if isinstance(reason, ssl.SSLError):
        return "TLS error"
    if isinstance(reason, socket.gaierror):
        return "DNS lookup failed"
    if isinstance(reason, ConnectionRefusedError):
        return "connection refused"
    if isinstance(reason, ConnectionResetError):
        return "connection reset"
    return "network error (%s)" % type(reason).__name__


def _send(url, headers, body, timeout_s, deadline):
    """One POST; returns (status, note) for an HTTP answer. Network failures raise."""
    import http.client
    import ssl
    import urllib.error
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None  # urllib then raises HTTPError with the 3xx code

    handlers = [NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())]
    if _loopback(urllib.parse.urlsplit(url).hostname or ""):
        handlers.append(urllib.request.ProxyHandler({}))  # plain http never goes through a proxy
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        response = opener.open(request, timeout=timeout_s)
    except urllib.error.HTTPError as e:
        try:
            e.close()
        except Exception:
            pass
        return e.code, "HTTP %d %s" % (e.code, e.reason if isinstance(e.reason, str) else "")
    with response:
        status = response.status
        note = "HTTP %d" % status
        got = 0
        try:
            while got <= RESPONSE_MAX:
                if time.monotonic() > deadline:
                    note += " (response not read in time)"
                    break
                chunk = response.read(min(8192, RESPONSE_MAX + 1 - got))
                if not chunk:
                    break
                got += len(chunk)
            if got > RESPONSE_MAX:
                note += " (response cut at %d bytes)" % RESPONSE_MAX
        except (OSError, http.client.HTTPException, ValueError):
            note += " (response not read)"  # the service answered; its status counts
    return status, note


def deliver(cfg, secret, msg, timeout_s):
    """Send one message; never raises for network or HTTP problems. Returns {"ok", "status", "error", "detail"}:
    2xx ok (error None); 4xx E_NOTIFY_REFUSED (do not retry); 3xx (never followed), 5xx and other codes
    E_NOTIFY_HTTP; DNS, connect, TLS, timeout and broken responses E_NOTIFY_NET (status None). detail: at most 120
    cleaned characters, never a secret or the request body. timeout_s (0 < t <= 30) bounds the whole call.
    Config problems raise MMError as render() does; a bad timeout_s raises MMError E_PROFILE."""
    if type(timeout_s) not in (int, float) or not math.isfinite(timeout_s) or not 0 < timeout_s <= TIMEOUT_MAX:
        raise mmcore.MMError("E_PROFILE", "[notify] timeout_s must be a number above 0 and at most %d" % TIMEOUT_MAX,
                             "correct [notify] timeout_s")
    url, headers, body = render(cfg, secret, msg)
    deadline = time.monotonic() + timeout_s
    box = {}

    def run():
        try:
            box["answer"] = _send(url, headers, body, timeout_s, deadline)
        except BaseException as e:  # reported below, never raised to the caller
            box["failure"] = e

    worker = threading.Thread(target=run, name="mm-notify-send", daemon=True)
    worker.start()
    worker.join(timeout_s + 0.5)  # small grace so a socket timeout inside reports itself
    if worker.is_alive() or not box:
        return _result(False, None, "E_NOTIFY_NET", "timed out", secret)
    if "failure" in box:
        e = box["failure"]
        if not isinstance(e, Exception):
            return _result(False, None, "E_NOTIFY_NET", "send interrupted", secret)
        return _result(False, None, "E_NOTIFY_NET", _net_detail(e), secret)
    status, note = box["answer"]
    if 200 <= status <= 299:
        return _result(True, status, None, note, secret)
    if 300 <= status <= 399:
        return _result(False, status, "E_NOTIFY_HTTP", "HTTP %d redirect not followed" % status, secret)
    if 400 <= status <= 499:
        return _result(False, status, "E_NOTIFY_REFUSED", note, secret)
    return _result(False, status, "E_NOTIFY_HTTP", note, secret)
