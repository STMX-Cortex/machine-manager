# SPDX-License-Identifier: Apache-2.0
"""Phone notifications (`mm notify`): the `[notify]` profile section, agent grants and keys, the outbox, the mm alert
feed, rate limits and the sent log. See NOTIFY.md.

Off unless the profile's `[notify]` has `enabled = true`. Only the `mm notify` verbs import this module; the
supervisor, the watchdog and the hook never do. The network module (mmnotify_send) is imported only on the paths that
deliver or read the secret file. State lives in <data>/notify/ (mode 0700, files 0600). The lock (notify.lock) is held
only to read and change state files, never while a message is on the network.
"""
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import time
import urllib.parse

import mmcore
import mmtext

DIR = "notify"
MSG_LEVELS = ("quiet", "normal", "ring")
RANK = {lv: i for i, lv in enumerate(MSG_LEVELS)}
ALERT_LEVELS = ("INFO", "ATTENTION", "ACTION")
SERVICES = ("ntfy", "pushover")
PUSHOVER_URL = "https://api.pushover.net/1/messages.json"
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
RESERVED_NAMES = frozenset(("mm",))  # the sender name of machine-manager's own alerts
TOPIC = re.compile(r"[A-Za-z0-9_-]{1,64}")
TAG = re.compile(r"[A-Za-z0-9_-]{1,32}")
KEY = re.compile(r"[0-9a-f]{64}")
TITLE_MAX, TEXT_MAX, SENDER_MAX, TAGS_MAX = 100, 1000, 40, 4
DEFAULTS = {"enabled": False, "service": None, "url": None, "topic": None, "secret_file": None,
            "alert_levels": ["ATTENTION", "ACTION"], "ring_levels": ["ACTION"], "send_cleared": True,
            "alerts_per_hour": 30, "timeout_s": 10, "ring_retry_s": 60, "ring_expire_s": 1800}
RANGES = {"alerts_per_hour": (1, 600, "int"), "timeout_s": (1, 30, "num"), "ring_retry_s": (30, 3600, "int"),
          "ring_expire_s": (60, 10800, "int")}
GRANT_DEFAULT_LEVEL, GRANT_DEFAULT_PER_HOUR, GRANT_PER_HOUR = "normal", 5, (1, 60)
GRANTS_MAX = 100
DUPLICATE_S = 600
HOUR_S = 3600
RUN_DELIVERIES = 20
RUN_DEADLINE_S = 240     # no new delivery starts after it (the service template allows 300 s)
BACKOFF_FIRST_S, BACKOFF_MAX_S = 30, 900
OUTBOX_MAX, OUTBOX_KEEP_S = 100, 3600
SENT_MAX_BYTES = 1 << 20
STATE_MAX_BYTES = 4 << 20  # each JSON state file (state.json: queue, hour events, duplicate memory)
KEY_FILE_MAX = 256
RECENT_MAX = 2000
RETRYABLE = frozenset(("E_NOTIFY_HTTP", "E_NOTIFY_NET"))
FIX_PROFILE = "correct [notify] in the profile (NOTIFY.md); mm check"


def _bad(key, what):
    return mmcore.MMError("E_PROFILE", "notify.%s %s" % (key, what), FIX_PROFILE)


def section(profile):
    """The raw `[notify]` table, or None when the profile has none."""
    raw = (profile or {}).get("notify")
    return None if raw is None else raw


def config(profile):
    """The validated `[notify]` settings with their defaults, or None when notify is off (no section, or
    enabled = false). Raises MMError E_PROFILE naming the key."""
    raw = section(profile)
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise mmcore.MMError("E_PROFILE", "notify must be a table", FIX_PROFILE)
    unknown = sorted(k for k in raw if k not in DEFAULTS)
    if unknown:
        raise _bad(mmtext.quoted(str(unknown[0]))[:60], "is not a known key")
    if "enabled" in raw and not isinstance(raw["enabled"], bool):
        raise _bad("enabled", "must be true or false")
    if not raw.get("enabled"):
        return None
    cfg = dict(DEFAULTS)
    cfg.update(raw)
    if cfg["service"] not in SERVICES:
        raise _bad("service", 'must be "ntfy" or "pushover"')
    for key in ("alert_levels", "ring_levels"):
        v = cfg[key]
        if not isinstance(v, list) or len(v) > 3 or any(x not in ALERT_LEVELS for x in v) or len(set(v)) != len(v):
            raise _bad(key, "must be a list of distinct levels from INFO, ATTENTION, ACTION")
        cfg[key] = list(v)
    if not isinstance(cfg["send_cleared"], bool):
        raise _bad("send_cleared", "must be true or false")
    for key, (lo, hi, kind) in RANGES.items():
        v = cfg[key]
        ok = type(v) is int or (kind == "num" and type(v) is float and math.isfinite(v))
        if not ok or not lo <= v <= hi:
            raise _bad(key, "must be a %s from %s to %s" % ("whole number" if kind == "int" else "number", lo, hi))
    if cfg["service"] == "ntfy":
        if cfg["url"] is None:
            raise _bad("url", "is required for ntfy (the server's base URL)")
        if not isinstance(cfg["topic"], str) or not TOPIC.fullmatch(cfg["topic"]):
            raise _bad("topic", "is required for ntfy: 1 to 64 of A-Z a-z 0-9 _ -")
    else:
        if cfg["url"] is None:
            cfg["url"] = PUSHOVER_URL
        if cfg["topic"] is not None and not isinstance(cfg["topic"], str):
            raise _bad("topic", "must be text (ntfy only)")
        if cfg["secret_file"] is None:
            raise _bad("secret_file", "is required for pushover")
    if not isinstance(cfg["url"], str):
        raise _bad("url", "must be text")
    import mmnotify_send  # the URL rules (NOTIFY.md); importing it loads no network code
    mmnotify_send.validate_url(cfg["url"])
    sf = cfg["secret_file"]
    if sf is not None:
        if not isinstance(sf, str) or not 0 < len(sf) <= 1024 or mmtext.clean(sf) != sf:
            raise _bad("secret_file", "must be a path of 1 to 1024 printable characters")
        sf = mmcore.expand(sf)
        if not os.path.isabs(sf):
            raise _bad("secret_file", "must be an absolute path (or start with ~)")
        cfg["secret_file"] = sf
    return cfg


def check_line(profile):
    """The `mm check` word for notify: None without a [notify] section (the output stays as before), else
    "notify=off" or "notify=ok service=S". Raises MMError like config()."""
    if section(profile) is None:
        return None
    cfg = config(profile)
    return "notify=off" if cfg is None else "notify=ok service=%s" % cfg["service"]


# --------------------------------------------------------------------------------------------- files

def folder(*parts):
    return mmcore.path(DIR, *parts)


def _own_dir(d):
    """Make d (mode 0700) and check it is a real folder of this user, never a link."""
    os.makedirs(d, mode=0o700, exist_ok=True)
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise mmcore.MMError("E_NOTIFY_STATE", "the notify folder is not a folder of this user",
                             "move %s away; mm notify makes it again" % mmcore.log_path(d))
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(d, 0o700)


def ensure():
    os.makedirs(mmcore.data_dir(), exist_ok=True)
    _own_dir(folder())
    _own_dir(folder("keys"))


def _read_bytes(p, limit):
    """At most limit bytes of a regular file, never through a link or from a FIFO; None when missing or not one."""
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb") as f:
            fd = None
            raw = f.read(limit + 1)
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)
    return raw if len(raw) <= limit else None


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _nonfinite(_):
    raise ValueError("nonfinite number")


def _loads(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes, parse_constant=_nonfinite)


def read_state(name, default):
    """One JSON state file of the notify folder (strict and bounded); default when missing or invalid."""
    raw = _read_bytes(folder(name), STATE_MAX_BYTES)
    if raw is None:
        return default
    try:
        doc = _loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return default
    return doc if isinstance(doc, dict) else default


def _state_error(name):
    return mmcore.MMError("E_NOTIFY_STATE", "cannot write notify/%s" % name,
                          "check free disk and that the data folder belongs to this user; then run again")


def write_state(name, doc):
    """One JSON state file, written atomically (mode 0600). A write error is E_NOTIFY_STATE (exit 2)."""
    try:
        mmcore.write_atomic(folder(name), json.dumps(doc, sort_keys=True, allow_nan=False) + "\n", mode=0o600)
    except OSError:
        raise _state_error(name) from None


def _open_lock(name):
    """A lock file of the notify folder: opened with O_NOFOLLOW and O_CLOEXEC, a regular file owned by this user, mode
    0600 set through the descriptor. A link or a foreign file is E_NOTIFY_STATE."""
    try:
        fd = os.open(folder(name), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        raise mmcore.MMError("E_NOTIFY_STATE", "notify/%s cannot be opened (a link, or not a file)" % name,
                             "move it away; mm notify makes it again") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
            raise mmcore.MMError("E_NOTIFY_STATE", "notify/%s is not a regular file of this user" % name,
                                 "move it away; mm notify makes it again")
        if stat.S_IMODE(st.st_mode) != 0o600:
            os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise _state_error(name) from None
    except mmcore.MMError:
        os.close(fd)
        raise
    return fd


class _Lock:
    """notify/notify.lock (state changes; never held during a delivery); busy for 5 s is E_NOTIFY_BUSY."""
    TIMEOUT_S = 5.0

    def __enter__(self):
        try:
            ensure()
        except OSError:
            raise mmcore.MMError("E_NOTIFY_STATE", "cannot make the notify folder",
                                 "check free disk and that the data folder belongs to this user") from None
        self.fd = _open_lock("notify.lock")
        deadline = time.monotonic() + self.TIMEOUT_S
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() > deadline:
                    os.close(self.fd)
                    raise mmcore.MMError("E_NOTIFY_BUSY", "the notify state is locked by another mm notify",
                                         "try again") from None
                time.sleep(0.05)
            except OSError:
                os.close(self.fd)
                raise _state_error("notify.lock") from None

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)


def _num_time(v):
    """A record's time: epoch seconds (abs below TIME_MAX), or a `YYYY-MM-DD HH:MM:SS` local time; None when
    neither."""
    if _num(v):
        return float(v)
    if isinstance(v, str):
        try:
            return time.mktime(time.strptime(v[:19], "%Y-%m-%d %H:%M:%S"))
        except (ValueError, OverflowError):
            return None
    return None


def log_sent(rec, now):
    """Append one record to sent.jsonl (mode 0600; over 1 MiB it first moves to sent.jsonl.1). No text, no secret."""
    p = folder("sent.jsonl")
    line = {"time": round(now, 3), "id": rec["id"], "source": rec["source"], "sender": rec["sender"],
            "level": rec["level"], "title": rec["title"], "status": rec["status"], "error": rec.get("error")}
    line = mmtext.clean_obj(mmcore.mask_obj(line))
    try:
        if os.lstat(p).st_size > SENT_MAX_BYTES:
            os.replace(p, p + ".1")
    except OSError:
        pass
    try:
        fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(json.dumps(line, sort_keys=True) + "\n")
    except OSError:
        raise _state_error("sent.jsonl") from None


# --------------------------------------------------------------------------------------------- grants

def _grant_ok(name, g):
    return (isinstance(name, str) and NAME.fullmatch(name) and name not in RESERVED_NAMES and isinstance(g, dict)
            and isinstance(g.get("key_sha256"), str) and KEY.fullmatch(g["key_sha256"])
            and g.get("max_level") in MSG_LEVELS and type(g.get("per_hour")) is int
            and GRANT_PER_HOUR[0] <= g["per_hour"] <= GRANT_PER_HOUR[1])


def read_grants():
    """{name: grant} from grants.json; an invalid entry is left out (and goes at the next write)."""
    doc = read_state("grants.json", {})
    raw = doc.get("grants") if isinstance(doc.get("grants"), dict) else {}
    return {n: g for n, g in raw.items() if _grant_ok(n, g)}


def _write_grants(grants):
    write_state("grants.json", {"schema_version": 1, "grants": grants})


def check_name(name):
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise mmcore.MMError("E_USAGE", "a grant name is 1 to 40 of a-z 0-9 -, starting with a letter or digit",
                             "mm notify grant NAME")
    if name in RESERVED_NAMES:
        raise mmcore.MMError("E_USAGE", "grant name %s is reserved for machine-manager's own alerts" % name,
                             "choose another name")


def key_path(name):
    return folder("keys", name + ".key")


def _digest(key):
    return hashlib.sha256(key.encode("ascii")).hexdigest()


def grant(name, max_level=GRANT_DEFAULT_LEVEL, per_hour=GRANT_DEFAULT_PER_HOUR, now=None):
    """A new key for NAME (a re-grant replaces the old key). Stores only the key's sha256; writes keys/NAME.key."""
    check_name(name)
    if max_level not in MSG_LEVELS:
        raise mmcore.MMError("E_USAGE", "--max-level must be quiet, normal or ring", "mm notify grant NAME --max-level normal")
    if type(per_hour) is not int or not GRANT_PER_HOUR[0] <= per_hour <= GRANT_PER_HOUR[1]:
        raise mmcore.MMError("E_RANGE", "--per-hour must be a whole number from %d to %d" % GRANT_PER_HOUR,
                             "mm notify grant NAME --per-hour 5")
    now = time.time() if now is None else now
    key = secrets.token_hex(32)
    with _Lock():
        grants = read_grants()
        if name not in grants and len(grants) >= GRANTS_MAX:
            raise mmcore.MMError("E_RANGE", "at most %d grants" % GRANTS_MAX, "mm notify revoke NAME first")
        grants[name] = {"key_sha256": _digest(key), "max_level": max_level, "per_hour": per_hour,
                        "created": round(now, 3)}
        try:
            mmcore.write_atomic(key_path(name), key + "\n", mode=0o600)
        except OSError:
            raise _state_error("keys/%s.key" % name) from None
        _write_grants(grants)
    return {"grant": name, "key_file": key_path(name), "max_level": max_level, "per_hour": per_hour}


def revoke(name):
    """Remove the grant and its key file. True when there was one."""
    check_name(name)
    with _Lock():
        grants = read_grants()
        had = grants.pop(name, None) is not None
        try:
            os.unlink(key_path(name))
            had = True
        except FileNotFoundError:
            pass
        if had:
            _write_grants(grants)
    return had


def list_grants():
    return [{"grant": n, "max_level": g["max_level"], "per_hour": g["per_hour"],
             "created": mmcore.now_local(g["created"]) if _num_time(g.get("created")) is not None else None}
            for n, g in sorted(read_grants().items())]


def _key_from_file(p):
    """The 64-hex key in an agent's key file (surrounding white space ignored), or None."""
    if not p:
        return None
    try:
        fd = os.open(os.path.expanduser(p), os.O_RDONLY | os.O_NONBLOCK)
    except (OSError, ValueError):
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb") as f:
            fd = None
            raw = f.read(KEY_FILE_MAX + 1)
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)
    try:
        key = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    return key if len(raw) <= KEY_FILE_MAX and KEY.fullmatch(key) else None


def find_grant(key, grants):
    """(name, grant) whose stored sha256 matches the key, compared with hmac.compare_digest over every grant."""
    hit = None
    d = _digest(key) if key else "-" * 64
    for name, g in sorted(grants.items()):
        if hmac.compare_digest(d.encode(), g["key_sha256"].encode()) and hit is None:
            hit = (name, g)
    return hit


# --------------------------------------------------------------------------------------------- messages

def one_line(text, limit):
    """A text as it may leave the machine: masked, white space folded, cleaned, at most limit characters. Before
    masking it is bounded at a whole word to min(4 * limit, TEXT_LINE_MAX - len(CUT_MARK)) characters (mmtext.bounded,
    the rule delivery uses too), so mask() sees every token whole and a secret cut short never escapes it."""
    text = mmtext.bounded(str(text), limit * 4)
    t = mmtext.clean(" ".join(mmcore.mask(text).split()))
    return t if len(t) <= limit else t[:limit - 3].rstrip() + "..."


def new_id():
    return secrets.token_hex(6)


def _secret(cfg):
    """The secret file's content (mmnotify_send.read_secret), or None when the profile names none."""
    if not cfg["secret_file"]:
        return None
    import mmnotify_send
    return mmnotify_send.read_secret(cfg["secret_file"], cfg["service"])


def secret_state(cfg):
    """ok, none (no secret_file), missing or bad: for `mm notify status`."""
    if not cfg or not cfg["secret_file"]:
        return "none"
    if not os.path.lexists(cfg["secret_file"]):
        return "missing"
    try:
        _secret(cfg)
    except (mmcore.MMError, ImportError, OSError, ValueError):
        return "bad"
    return "ok"


def deliver(cfg, secret, msg):
    """One delivery by mmnotify_send.deliver. Its MMError (a config problem: E_PROFILE, E_USAGE, E_NOTIFY_SECRET)
    goes to the caller; any other failure inside it is E_NOTIFY_NET (retryable)."""
    import mmnotify_send
    try:
        r = mmnotify_send.deliver(cfg, secret, msg, cfg["timeout_s"])
    except mmcore.MMError:
        raise
    except Exception:
        return {"ok": False, "status": None, "error": "E_NOTIFY_NET", "detail": "delivery failed"}
    if not isinstance(r, dict):
        return {"ok": False, "status": None, "error": "E_NOTIFY_NET", "detail": "delivery failed"}
    err = r.get("error") if r.get("error") in ("E_NOTIFY_HTTP", "E_NOTIFY_NET", "E_NOTIFY_REFUSED") else None
    ok = r.get("ok") is True and err is None
    if not ok and err is None:
        err = "E_NOTIFY_NET"
    return {"ok": ok, "status": r.get("status") if type(r.get("status")) is int else None, "error": err,
            "detail": one_line(r.get("detail") or "", 120)}


def _msg(item):
    return {"title": item["title"], "text": item["text"], "level": item["level"], "sender": item["sender"],
            "tags": list(item.get("tags") or [])}


def _backoff(tries):
    return min(BACKOFF_FIRST_S * 2 ** max(tries - 1, 0), BACKOFF_MAX_S)


# --------------------------------------------------------------------------------------------- state.json
# One state file holds every decision input (NOTIFY.md, Files): the alert cursor, the queue (outbox), the counted
# events of the last hour, the suppressed count, the duplicate memory and the last delivery time. It is read and
# written whole (write_atomic) under notify.lock, never held during a delivery. sent.jsonl is an audit log only.

STATE = "state.json"
STATE_KEYS = frozenset(("schema_version", "cursor", "suppressed", "last_delivery", "queue", "hour", "recent",
                        "delivering"))
ITEM_KEYS = frozenset(("id", "source", "sender", "level", "title", "text", "tags", "first", "next", "tries", "error"))
HOUR_KEYS = frozenset(("id", "source", "sender", "time"))
RECENT_KEYS = frozenset(("id", "sender", "digest", "time"))
ID = re.compile(r"[0-9a-f]{12}")
SENDER = re.compile(r"mm|[a-z0-9][a-z0-9-]{0,39}")
DIGEST = re.compile(r"(?:[0-9a-f]{64})?")
ERRORS = (None, "E_NOTIFY_HTTP", "E_NOTIFY_NET")
HOUR_MAX = 10000


def new_state():
    return {"schema_version": 1, "cursor": None, "suppressed": 0, "last_delivery": None, "queue": [], "hour": [],
            "recent": [], "delivering": []}


INT_MAX = 2 ** 53   # every integer of the state: 0 <= n <= INT_MAX
TIME_MAX = 10 ** 12  # every time: finite, abs below it


def _int(v, lo=0):
    return type(v) is int and lo <= v <= INT_MAX


def _num(v):
    """A finite time with abs below TIME_MAX; never raises (a huge int compares exactly, no float conversion)."""
    if type(v) is int:
        return -TIME_MAX < v < TIME_MAX
    return type(v) is float and math.isfinite(v) and -TIME_MAX < v < TIME_MAX


def _str(v, hi, lo=0):
    return isinstance(v, str) and lo <= len(v) <= hi


def _item_ok(i):
    return (isinstance(i, dict) and set(i) == ITEM_KEYS and isinstance(i["id"], str) and ID.fullmatch(i["id"])
            and i["source"] in ("mm", "agent") and isinstance(i["sender"], str) and SENDER.fullmatch(i["sender"])
            and (i["source"] == "mm") == (i["sender"] == "mm") and i["level"] in MSG_LEVELS
            and _str(i["title"], TITLE_MAX, 1) and _str(i["text"], TEXT_MAX) and isinstance(i["tags"], list)
            and len(i["tags"]) <= TAGS_MAX and all(isinstance(t, str) and TAG.fullmatch(t) for t in i["tags"])
            and _num(i["first"]) and _num(i["next"]) and _int(i["tries"]) and i["error"] in ERRORS)


def _hour_ok(e):
    return (isinstance(e, dict) and set(e) == HOUR_KEYS and isinstance(e["id"], str) and ID.fullmatch(e["id"])
            and e["source"] in ("mm", "agent") and isinstance(e["sender"], str) and SENDER.fullmatch(e["sender"])
            and _num(e["time"]))


def _recent_ok(e):
    return (isinstance(e, dict) and set(e) == RECENT_KEYS and isinstance(e["id"], str) and ID.fullmatch(e["id"])
            and isinstance(e["sender"], str) and SENDER.fullmatch(e["sender"]) and isinstance(e["digest"], str)
            and DIGEST.fullmatch(e["digest"]) and _num(e["time"]))


def valid_state(d):
    """state.json's schema (NOTIFY.md, Files): exact keys, types and bounds; every queue entry, hour event and duplicate
    entry valid; ids unique in the queue and in the hour events."""
    try:
        if not isinstance(d, dict) or set(d) not in (STATE_KEYS, STATE_KEYS - {"delivering"}) \
                or type(d["schema_version"]) is not int or d["schema_version"] != 1:
            return False
        dv = d.get("delivering", [])
        if not (isinstance(dv, list) and len(dv) <= RUN_DELIVERIES and len(set(dv)) == len(dv)
                and all(isinstance(x, str) and ID.fullmatch(x) for x in dv)):
            return False
        if not (d["cursor"] is None or _int(d["cursor"])) or not _int(d["suppressed"]) \
                or not (d["last_delivery"] is None or _num(d["last_delivery"])):
            return False
        q, h, r = d["queue"], d["hour"], d["recent"]
        if not (isinstance(q, list) and len(q) <= OUTBOX_MAX and all(_item_ok(i) for i in q)
                and len({i["id"] for i in q}) == len(q)):
            return False
        if not (isinstance(h, list) and len(h) <= HOUR_MAX and all(_hour_ok(e) for e in h)
                and len({e["id"] for e in h}) == len(h)):
            return False
        return isinstance(r, list) and len(r) <= RECENT_MAX and all(_recent_ok(e) for e in r)
    except (TypeError, KeyError, AttributeError, ValueError, OverflowError, RecursionError):
        return False


def load_state():
    """state.json, checked (valid_state). Missing: a new state (the first run). Anything else that is not a valid
    document (not a regular file, too large, bad JSON, a wrong type or entry): E_NOTIFY_STATE, before any write."""
    p = folder(STATE)
    if not os.path.lexists(p):
        return new_state()
    raw = _read_bytes(p, STATE_MAX_BYTES)
    try:
        doc = _loads(raw) if raw is not None else None
    except (ValueError, UnicodeDecodeError, RecursionError):
        doc = None
    if not valid_state(doc):
        raise mmcore.MMError("E_NOTIFY_STATE", "notify/state.json is not a valid notify state",
                             "move it away (the next run starts at the newest alert, with an empty queue)")
    doc.setdefault("delivering", [])  # a state written before `delivering` existed
    return doc


def save_state(st):
    """One atomic write of state.json (mode 0600), checked first with the load's check: a document that would not
    load is never written (E_NOTIFY_STATE, the file stays). A write error is E_NOTIFY_STATE (exit 2)."""
    if not valid_state(st):
        raise mmcore.MMError("E_NOTIFY_STATE", "refused to write an invalid notify/state.json",
                             "report this; the file was not changed")
    write_state(STATE, st)


def _prune(st, now):
    """Hour events of the last hour only; duplicate memory of the last DUPLICATE_S only."""
    st["hour"] = [e for e in st["hour"] if e["time"] > now - HOUR_S]
    st["recent"] = [e for e in st["recent"] if e["time"] > now - DUPLICATE_S]


def _full(st):
    """The state holds as many hour events or duplicate entries as it may: nothing new can be counted."""
    return len(st["hour"]) >= HOUR_MAX or len(st["recent"]) >= RECENT_MAX


def _hour_count(st, source, sender):
    return sum(1 for e in st["hour"] if e["source"] == source and e["sender"] == sender)


def _count(st, item, now):
    """Count the message item at now, its latest counted outcome (one event per id; the time moves forward)."""
    for e in st["hour"]:
        if e["id"] == item["id"]:
            e["time"] = max(e["time"], round(now, 3))
            return
    if len(st["hour"]) >= HOUR_MAX:  # full (pruned meanwhile and refilled): the outcome is not counted again
        return
    st["hour"].append({"id": item["id"], "source": item["source"], "sender": item["sender"], "time": round(now, 3)})


def _queued(item, **change):
    """A queue entry: exactly ITEM_KEYS."""
    out = {k: item.get(k) for k in ITEM_KEYS}
    out.update(change)
    out["tags"] = list(out["tags"] or [])
    out["tries"] = out["tries"] or 0
    return out


def _enqueue(st, item, keep=(), audit=None):
    """Add item to the queue; over OUTBOX_MAX the entry with the oldest first attempt that is not being delivered
    (st["delivering"], and keep) goes, with a `dropped` audit record."""
    keep = set(keep) | set(st["delivering"])
    st["queue"].append(item)
    while len(st["queue"]) > OUTBOX_MAX:
        cands = [i for i, x in enumerate(st["queue"]) if x["id"] not in keep] or [len(st["queue"]) - 1]
        old = st["queue"].pop(min(cands, key=lambda i: st["queue"][i]["first"]))
        if audit is not None:
            audit.append(dict(old, status="dropped", error="E_NOTIFY_QUEUE_FULL"))


def _audit(records, now):
    """Append audit records to sent.jsonl. Returns the first E_NOTIFY_STATE error (the state is already right)."""
    for rec in records:
        try:
            log_sent(rec, now)
        except mmcore.MMError as e:
            return e
    return None


class _RunLock:
    """notify/run.lock, held by `mm notify run` for its whole run (flock, non-blocking): busy = another run."""

    def __enter__(self):
        try:
            ensure()
        except OSError:
            raise mmcore.MMError("E_NOTIFY_STATE", "cannot make the notify folder",
                                 "check free disk and that the data folder belongs to this user") from None
        fd = _open_lock("run.lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return None
        except OSError:
            os.close(fd)
            raise _state_error("run.lock") from None
        self.fd = fd
        return self

    def __exit__(self, *exc):
        if getattr(self, "fd", None) is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)


def _record_result(st, item, r, now, audit, from_queue=False):
    """Record one delivery result in st: delivered or refused leaves the queue, a retryable failure backs off (or
    joins the queue). The message's hour event moves to now. from_queue: the item was in the queue when selected (a
    run), so a failed item that is gone now was evicted meanwhile and is re-queued with an extra audit line (4g.3).
    Returns the status word."""
    _count(st, item, now)
    pos = next((i for i, x in enumerate(st["queue"]) if x["id"] == item["id"]), None)
    if r["ok"]:
        status = "delivered"
        st["last_delivery"] = round(now, 3)
    elif r["error"] in RETRYABLE:
        tries = item.get("tries", 0) + 1
        status = "queued" if tries == 1 else "failed"
        entry = _queued(item, tries=tries, next=round(now + _backoff(tries), 3), error=r["error"])
        if pos is not None:
            st["queue"][pos] = entry
        else:  # an agent's first attempt, or an entry that left the queue meanwhile: queued (again)
            _enqueue(st, entry, audit=audit)
            if from_queue:
                audit.append(dict(entry, status="queued", error="E_NOTIFY_REQUEUED"))
    else:
        status = "refused"
    if status in ("delivered", "refused") and pos is not None:
        st["queue"].pop(pos)
    audit.append(dict(item, status=status, error=r["error"]))
    return status


# --------------------------------------------------------------------------------------------- send (agents)

def send(profile, key_file, level, title, text="", tags=(), now=None):
    """One agent message (NOTIFY.md, Agents). Returns {"notify": "delivered"|"queued", "id"}; raises MMError
    (E_NOTIFY_OFF, E_NOTIFY_KEY, E_NOTIFY_LEVEL, E_NOTIFY_LIMIT, E_NOTIFY_DUPLICATE, E_NOTIFY_SECRET,
    E_NOTIFY_REFUSED, E_NOTIFY_STATE)."""
    cfg = config(profile)
    if cfg is None:
        raise mmcore.MMError("E_NOTIFY_OFF", "phone notifications are off in this profile",
                             "ask the owner; [notify] enabled = true (NOTIFY.md)")
    if level not in MSG_LEVELS:
        raise mmcore.MMError("E_USAGE", "--level must be quiet, normal or ring", "mm notify send --level normal ...")
    title = one_line(title or "", TITLE_MAX)
    if not title:
        raise mmcore.MMError("E_USAGE", "--title is required", 'mm notify send --level normal --title "..."')
    text = one_line(text or "", TEXT_MAX)
    tags = list(tags)
    if len(tags) > TAGS_MAX or any(not isinstance(t, str) or not TAG.fullmatch(t) for t in tags):
        raise mmcore.MMError("E_USAGE", "at most %d tags, each 1 to 32 of A-Z a-z 0-9 _ -" % TAGS_MAX, "mm help")
    key = _key_from_file(key_file)
    now = time.time() if now is None else now
    with _Lock():
        hit = find_grant(key, read_grants()) if key else None
        if hit is None:
            raise mmcore.MMError("E_NOTIFY_KEY", "no valid notify key (missing, unreadable, not granted or revoked)",
                                 "ask the owner for a grant: mm notify grant NAME; pass --key-file or MM_NOTIFY_KEY_FILE")
        name, g = hit
        if RANK[level] > RANK[g["max_level"]]:
            raise mmcore.MMError("E_NOTIFY_LEVEL", "level %s is above this grant's max_level %s" % (level, g["max_level"]),
                                 "use --level %s, or ask the owner to grant more" % g["max_level"])
        st = load_state()
        _prune(st, now)
        if _full(st):  # nothing written, nothing delivered
            raise mmcore.MMError("E_NOTIFY_LIMIT", "the notify state is full (%d messages in the last hour or %d in "
                                 "the last %d s, for all senders)" % (HOUR_MAX, RECENT_MAX, DUPLICATE_S),
                                 "wait; the oldest entries leave after one hour")
        mid = new_id()
        base = {"id": mid, "source": "agent", "sender": name, "level": level, "title": title, "text": text,
                "tags": tags, "first": round(now, 3), "next": round(now, 3), "tries": 0, "error": None}
        if _hour_count(st, "agent", name) >= g["per_hour"]:
            _audit([dict(base, status="limited", error="E_NOTIFY_LIMIT")], now)
            raise mmcore.MMError("E_NOTIFY_LIMIT", "grant %s reached its limit of %d messages per hour" % (name, g["per_hour"]),
                                 "wait, or ask the owner to raise --per-hour")
        digest = hashlib.sha256(json.dumps([name, title, text]).encode()).hexdigest()
        if any(e["sender"] == name and e["digest"] == digest for e in st["recent"]):
            _audit([dict(base, status="duplicate", error="E_NOTIFY_DUPLICATE")], now)
            raise mmcore.MMError("E_NOTIFY_DUPLICATE", "the same message was sent in the last %d s" % DUPLICATE_S,
                                 "send it only once; change the title or text when something changed")
        secret = _secret(cfg)
        _count(st, base, now)  # counted in the same write that accepts it
        st["recent"].append({"id": mid, "sender": name, "digest": digest, "time": round(now, 3)})
        save_state(st)
    try:
        r = deliver(cfg, secret, _msg(base))
    except mmcore.MMError:  # a config problem: the same message may go again once it is fixed
        with _Lock():
            st = load_state()
            st["recent"] = [e for e in st["recent"] if e["id"] != mid]
            save_state(st)
        raise
    with _Lock():
        t = time.time()
        st = load_state()
        _prune(st, t)
        audit = []
        status = _record_result(st, base, r, t, audit)
        if status == "refused":  # refused: not a duplicate when sent again
            st["recent"] = [e for e in st["recent"] if e["id"] != mid]
        save_state(st)
        problem = _audit(audit, t)
    if status == "refused":
        raise mmcore.MMError("E_NOTIFY_REFUSED", "the service refused the message (HTTP %s)%s"
                             % (r["status"], ": " + r["detail"] if r["detail"] else ""),
                             "ask the owner to check [notify] and the secret file; mm notify test")
    if problem is not None:
        raise problem
    return {"notify": status, "id": mid}


# --------------------------------------------------------------------------------------------- test (owner)

def test(profile, level="normal"):
    """One test message now; never queued. Returns {"notify": "delivered", "id"}; raises MMError on a failure."""
    cfg = config(profile)
    if cfg is None:
        raise mmcore.MMError("E_NOTIFY_OFF", "phone notifications are off in this profile", "[notify] enabled = true (NOTIFY.md)")
    if level not in MSG_LEVELS:
        raise mmcore.MMError("E_USAGE", "--level must be quiet, normal or ring", "mm notify test --level normal")
    with _Lock():
        load_state()  # a broken state stops here, before any delivery
    secret = _secret(cfg)
    mid, mach = new_id(), one_line(mmcore.machine_id(profile), 80)
    item = {"id": mid, "source": "mm", "sender": "mm", "level": level, "title": "test",
            "text": "machine-manager test from %s" % mach, "tags": []}
    r = deliver(cfg, secret, _msg(item))
    with _Lock():
        t = time.time()
        st = load_state()
        _prune(st, t)
        _count(st, item, t)  # not counted when the state is full
        if r["ok"]:
            st["last_delivery"] = round(t, 3)
        save_state(st)
        problem = _audit([dict(item, status="delivered" if r["ok"] else "refused" if r["error"] == "E_NOTIFY_REFUSED"
                               else "failed", error=r["error"])], t)
    if not r["ok"]:
        raise mmcore.MMError(r["error"], "test message not delivered (HTTP %s)%s"
                             % (r["status"], ": " + r["detail"] if r["detail"] else ""),
                             "check [notify] url/topic and the secret file (NOTIFY.md)")
    if problem is not None:
        raise problem
    return {"notify": "delivered", "id": mid}


# --------------------------------------------------------------------------------------------- run (timer)

def _alert_message(rec, cfg, mid_default):
    """(level, title, text) for one alerts.jsonl record, or None when it is not sent."""
    cleared = rec.get("why") == "cleared"
    if cleared:
        if not cfg["send_cleared"]:
            return None
        level = "quiet"
    else:
        if rec.get("level") not in cfg["alert_levels"]:
            return None
        level = "ring" if rec["level"] in cfg["ring_levels"] else "normal"
    title = one_line(rec.get("name") or rec.get("key") or "alert", TITLE_MAX)
    mach = one_line(rec.get("machine_id") or mid_default, 80)
    tail = " (machine %s)" % mach
    text = one_line(rec.get("text") or "", TEXT_MAX - len(tail)) + tail
    return level, title, text


def _alert_snapshot():
    """alerts.jsonl.1 then alerts.jsonl (each the bounded tail mmcore.read_pushed reads), as one snapshot: read
    under state/alerts.lock, the lock AlertStore holds to append and rotate (AlertStore.lock_file)."""
    log = mmcore.path("alerts.jsonl")

    try:  # always locked; mmcore.Locked makes state/ as AlertStore does when it is missing
        with mmcore.Locked(mmcore.path("state", "alerts.lock")):
            return mmcore.read_pushed(-1, log + ".1") + mmcore.read_pushed(-1, log)
    except TimeoutError:
        raise mmcore.MMError("E_NOTIFY_BUSY", "the alert log is locked", "try again (the timer runs again soon)") from None
    except OSError:
        raise mmcore.MMError("E_NOTIFY_STATE", "cannot lock state/alerts.lock", "check the data folder") from None


def alert_sequence(recs):
    """The records of the current alert sequence, in append order. A record identical to one already read (same
    seq, same content) is a duplicate and skipped; a seq lower than the record before it starts a new sequence (a new
    alerts-state.json): only the records from the last such point on count. Another record with the seq of the one
    before it is skipped."""
    out, seen = [], {}
    for r in recs:
        canon = json.dumps(r, sort_keys=True, default=str)
        if seen.get(r["seq"]) == canon:
            continue
        if out and r["seq"] < out[-1]["seq"]:
            out, seen = [], {}
        elif out and r["seq"] == out[-1]["seq"]:
            continue
        out.append(r)
        seen[r["seq"]] = canon
    return out


def run(profile, now=None):
    """The timer's run (NOTIFY.md, crash rule): under notify/run.lock for the whole run; plan under the state lock
    (alerts read as one snapshot, queue, hourly limit, overflow), ONE write of state.json, delivery without the lock,
    then one write of the results. Returns (rc, counts): rc 0, or 1 when a delivery failed, was queued, refused or
    dropped; {"notify": "busy"} when another run holds run.lock."""
    cfg = config(profile)
    counts = {"delivered": 0, "queued": 0, "failed": 0, "refused": 0, "suppressed": 0, "dropped": 0}
    if cfg is None:
        return 0, dict({"notify": "off"}, **counts, cursor=None)
    with _RunLock() as held:
        if held is None:
            return 0, {"notify": "busy"}
        return _run(cfg, profile, counts, now)


def _run(cfg, profile, counts, now):
    start = time.monotonic()
    now = time.time() if now is None else now
    mid_default = mmcore.machine_id(profile)
    audit = []
    with _Lock():
        st = load_state()
        secret = _secret(cfg)
        _prune(st, now)
        st["delivering"] = []  # run.lock is held: a list left by a run that stopped is stale
        keep, todo = [], []
        for item in st["queue"]:  # (b) expire, then select the due entries (retries first)
            if now - item["first"] > OUTBOX_KEEP_S:
                audit.append(dict(item, status="dropped", error=item["error"] or "E_NOTIFY_EXPIRED"))
            else:
                keep.append(item)
                if item["next"] <= now and len(todo) < RUN_DELIVERIES:
                    todo.append(item)
        st["queue"] = keep
        every = alert_sequence(_alert_snapshot())  # (a)
        last = every[-1]["seq"] if every else 0
        seq = st["cursor"]
        if seq is None or last < seq:  # the first run, or a new sequence: start at its last record, send no history
            seq, recs = last, []
        else:
            recs = [r for r in every if r["seq"] > seq]
        in_hour = _hour_count(st, "mm", "mm")
        suppressed = st["suppressed"]
        new = []

        def item_for(level, title, text):
            return {"id": new_id(), "source": "mm", "sender": "mm", "level": level, "title": title, "text": text,
                    "tags": [], "first": round(now, 3), "next": round(now, 3), "tries": 0, "error": None}
        room = HOUR_MAX - len(st["hour"])  # the state's capacity: beyond it new alerts count as suppressed
        if suppressed and in_hour < cfg["alerts_per_hour"] and room > 0 and len(todo) < RUN_DELIVERIES:
            new.append(item_for("quiet", "alerts suppressed", "%d alerts suppressed (machine %s)"
                                % (suppressed, one_line(mid_default, 80))))
            in_hour += 1  # the notice takes one slot; the count goes back to 0 in the same write
            room -= 1
            suppressed = 0
        for r in recs:
            if len(todo) + len(new) >= RUN_DELIVERIES:
                break
            seq = r["seq"]
            m = _alert_message(r, cfg, mid_default)
            if m is None:
                continue
            item = item_for(*m)
            if in_hour >= cfg["alerts_per_hour"] or room <= 0:
                audit.append(dict(item, status="suppressed", error="E_NOTIFY_LIMIT"))
                counts["suppressed"] += 1
                suppressed += 1
                continue
            in_hour += 1
            room -= 1
            new.append(item)
        selected = [i["id"] for i in todo + new]
        st["delivering"] = selected  # every queue writer keeps these until the result write
        for item in new:
            _count(st, item, now)
            _enqueue(st, item, keep=selected, audit=audit)
        counts["dropped"] = sum(1 for x in audit if x["status"] == "dropped")
        st["cursor"], st["suppressed"] = seq, suppressed
        save_state(st)  # (c) the one write: queue, cursor, hour events, suppressed count and delivering together
        problem = _audit(audit, now)
    results = []
    for item in todo + new:  # (d) no lock
        if time.monotonic() - start > RUN_DEADLINE_S:
            break
        try:
            results.append((item, deliver(cfg, secret, _msg(item))))
        except mmcore.MMError as e:  # a config problem: record what was done, then report it (exit 2)
            problem = e
            break
    if selected:  # (e) entries not tried stay due for the next run
        with _Lock():
            t = time.time()
            st = load_state()
            _prune(st, t)
            st["delivering"] = []
            audit = []
            for item, r in results:
                counts[_record_result(st, item, r, t, audit, from_queue=True)] += 1
            save_state(st)
            problem = problem or _audit(audit, t)
    if problem is not None:
        raise problem
    rc = 1 if counts["queued"] or counts["failed"] or counts["refused"] or counts["dropped"] else 0
    return rc, dict({"notify": "run"}, **counts, cursor=seq)


# --------------------------------------------------------------------------------------------- status

def status(profile):
    """notify on|off, service, host, secret, cursor, queued, last delivery, grants. Reads files only; writes none."""
    cfg = config(profile)
    st = load_state() if os.path.isdir(folder()) else new_state()
    last = st["last_delivery"]
    host = urllib.parse.urlsplit(cfg["url"]).hostname if cfg else None
    return {"notify": "on" if cfg else "off", "service": cfg["service"] if cfg else None, "host": host,
            "secret": secret_state(cfg) if cfg else "none", "cursor": st["cursor"], "queued": len(st["queue"]),
            "last_delivery": mmcore.now_local(last) if last is not None else None, "grants": len(read_grants())}
