# SPDX-License-Identifier: Apache-2.0
"""Phone notifications (`mm notify`): the `[notify]` profile section, agent grants and keys, the outbox, the mm alert
feed, rate limits and the sent log. See NOTIFY.md.

Off unless the profile's `[notify]` has `enabled = true`. Only the `mm notify` verbs import this module; the
supervisor, the watchdog and the hook never do. The network module (mmnotify_send) is imported only on the paths that
deliver or read the secret file. State lives in <data>/notify/ (mode 0700, files 0600). The lock (notify.lock) is held
only to read and change state files, never while a message is on the network.
"""
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
LEASE_S = 300            # a claimed outbox item is not retried by another run before this
BACKOFF_FIRST_S, BACKOFF_MAX_S = 30, 900
OUTBOX_MAX, OUTBOX_KEEP_S = 100, 3600
SENT_MAX_BYTES = 1 << 20
STATE_MAX_BYTES = 1 << 20  # each JSON state file
KEY_FILE_MAX = 256
RECENT_MAX = 2000
COUNTED = frozenset(("delivered", "queued", "failed", "refused"))  # statuses that count toward a per-hour limit
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
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        raw = f.read(limit + 1)
    return raw if len(raw) <= limit else None


def _read_tail(p, limit):
    """The last limit bytes of a regular file from its first whole line (no link, no FIFO); b"" when none."""
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError:
        return b""
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            return b""
        if st.st_size <= limit:
            return f.read(limit)
        f.seek(st.st_size - limit)
        raw = f.read(limit)
    return raw[raw.find(b"\n") + 1:]


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


def write_state(name, doc):
    mmcore.write_atomic(folder(name), json.dumps(doc, sort_keys=True, allow_nan=False) + "\n", mode=0o600)


def lock():
    return mmcore.Locked(folder("notify.lock"))


class _Lock:
    """The notify lock; a busy lock is E_NOTIFY_BUSY."""

    def __enter__(self):
        ensure()
        self.l = lock()
        try:
            self.l.__enter__()
        except TimeoutError:
            raise mmcore.MMError("E_NOTIFY_BUSY", "the notify state is locked by another mm notify", "try again")
        try:
            os.chmod(self.l.target, 0o600)
        except OSError:
            pass
        return self

    def __exit__(self, *exc):
        return self.l.__exit__(*exc)


def _num_time(v):
    """A record's time: epoch seconds, or a `YYYY-MM-DD HH:MM:SS` local time; None when neither."""
    if type(v) in (int, float) and math.isfinite(v):
        return float(v)
    if isinstance(v, str):
        try:
            return time.mktime(time.strptime(v[:19], "%Y-%m-%d %H:%M:%S"))
        except (ValueError, OverflowError):
            return None
    return None


def sent_records(since=None):
    """The sent log's records (sent.jsonl.1, then sent.jsonl), each a dict with a numeric _t; since: only newer."""
    out = []
    for name in ("sent.jsonl.1", "sent.jsonl"):
        raw = _read_tail(folder(name), SENT_MAX_BYTES * 2)
        if not raw:
            continue
        for line in raw.decode("utf-8", "replace").split("\n"):
            if not line:
                continue
            try:
                r = _loads(line.encode())
            except (ValueError, RecursionError):
                continue
            if not isinstance(r, dict):
                continue
            t = _num_time(r.get("time"))
            if t is None or (since is not None and t < since):
                continue
            r["_t"] = t
            out.append(r)
    return out


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
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(json.dumps(line, sort_keys=True) + "\n")


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
        mmcore.write_atomic(key_path(name), key + "\n", mode=0o600)
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
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        raw = f.read(KEY_FILE_MAX + 1)
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
    """A text as it may leave the machine: masked, white space folded, cleaned, at most limit characters."""
    t = mmtext.clean(" ".join(mmcore.mask(str(text)[:limit * 4]).split()))
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


def _outbox():
    doc = read_state("outbox.json", {})
    items = doc.get("items") if isinstance(doc.get("items"), list) else []
    keep = ("id", "source", "sender", "level", "title", "text")
    return [i for i in items if isinstance(i, dict) and all(isinstance(i.get(k), str) for k in keep)
            and i["level"] in MSG_LEVELS and _num_time(i.get("first")) is not None
            and _num_time(i.get("next")) is not None and type(i.get("tries")) is int]


def _write_outbox(items):
    write_state("outbox.json", {"schema_version": 1, "items": items})


def _add_outbox(items, item, now):
    """Add item; over OUTBOX_MAX the oldest go first, each logged as dropped."""
    items.append(item)
    while len(items) > OUTBOX_MAX:
        old = items.pop(0)
        log_sent(dict(old, status="dropped", error="E_NOTIFY_QUEUE_FULL"), now)


def _counted_ids(source, sender, now, extra=()):
    """The ids that count toward a per-hour limit: sent-log records of the last hour, plus extra ids."""
    ids = {r.get("id") for r in sent_records(now - HOUR_S)
           if r.get("source") == source and r.get("sender") == sender and r.get("status") in COUNTED}
    return ids | set(extra)


def _record(item, r, now, outbox):
    """After one delivery attempt (outbox: the list to put a retryable failure in). Returns the status word."""
    if r["ok"]:
        status = "delivered"
    elif r["error"] in RETRYABLE:
        tries = item.get("tries", 0) + 1
        status = "queued" if tries == 1 else "failed"
        _add_outbox(outbox, dict(item, tries=tries, next=round(now + _backoff(tries), 3), error=r["error"]), now)
    else:
        status = "refused"
    log_sent(dict(item, status=status, error=r["error"]), now)
    return status


# --------------------------------------------------------------------------------------------- send (agents)

def _recent(now):
    doc = read_state("recent.json", {})
    ents = doc.get("entries") if isinstance(doc.get("entries"), list) else []
    return [e for e in ents if isinstance(e, dict) and isinstance(e.get("id"), str) and isinstance(e.get("sender"), str)
            and isinstance(e.get("digest"), str) and (_num_time(e.get("time")) or 0) >= now - HOUR_S][-RECENT_MAX:]


def send(profile, key_file, level, title, text="", tags=(), now=None):
    """One agent message (NOTIFY.md, Agents). Returns {"notify": "delivered"|"queued", "id"}; raises MMError
    (E_NOTIFY_OFF, E_NOTIFY_KEY, E_NOTIFY_LEVEL, E_NOTIFY_LIMIT, E_NOTIFY_DUPLICATE, E_NOTIFY_SECRET,
    E_NOTIFY_REFUSED)."""
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
        recent = _recent(now)
        mine = [e for e in recent if e["sender"] == name]
        mid = new_id()
        base = {"id": mid, "source": "agent", "sender": name, "level": level, "title": title, "text": text,
                "tags": tags, "first": round(now, 3), "next": round(now, 3), "tries": 0}
        if len(_counted_ids("agent", name, now, [e["id"] for e in mine])) >= g["per_hour"]:
            log_sent(dict(base, status="limited", error="E_NOTIFY_LIMIT"), now)
            raise mmcore.MMError("E_NOTIFY_LIMIT", "grant %s reached its limit of %d messages per hour" % (name, g["per_hour"]),
                                 "wait, or ask the owner to raise --per-hour")
        digest = hashlib.sha256(json.dumps([name, title, text]).encode()).hexdigest()
        if any(e["digest"] == digest and _num_time(e["time"]) >= now - DUPLICATE_S for e in mine):
            log_sent(dict(base, status="duplicate", error="E_NOTIFY_DUPLICATE"), now)
            raise mmcore.MMError("E_NOTIFY_DUPLICATE", "the same message was sent in the last %d s" % DUPLICATE_S,
                                 "send it only once; change the title or text when something changed")
        secret = _secret(cfg)
        recent.append({"time": round(now, 3), "id": mid, "sender": name, "digest": digest})
        write_state("recent.json", {"schema_version": 1, "entries": recent})
    try:
        r = deliver(cfg, secret, _msg(base))
    except mmcore.MMError:  # a config problem: the same message may go again once it is fixed
        with _Lock():
            write_state("recent.json", {"schema_version": 1, "entries": [
                dict(e, digest="") if e["id"] == mid else e for e in _recent(time.time())]})
        raise
    with _Lock():
        outbox = _outbox()
        status = _record(base, r, time.time(), outbox)
        if status == "queued":
            _write_outbox(outbox)
        elif status == "refused":
            recent = [dict(e, digest="") if e["id"] == mid else e for e in _recent(time.time())]
            write_state("recent.json", {"schema_version": 1, "entries": recent})
    if status == "refused":
        raise mmcore.MMError("E_NOTIFY_REFUSED", "the service refused the message (HTTP %s)%s"
                             % (r["status"], ": " + r["detail"] if r["detail"] else ""),
                             "ask the owner to check [notify] and the secret file; mm notify test")
    return {"notify": status, "id": mid}


# --------------------------------------------------------------------------------------------- test (owner)

def test(profile, level="normal"):
    """One test message now; never queued. Returns {"notify": "delivered", "id"}; raises MMError on a failure."""
    cfg = config(profile)
    if cfg is None:
        raise mmcore.MMError("E_NOTIFY_OFF", "phone notifications are off in this profile", "[notify] enabled = true (NOTIFY.md)")
    if level not in MSG_LEVELS:
        raise mmcore.MMError("E_USAGE", "--level must be quiet, normal or ring", "mm notify test --level normal")
    secret = _secret(cfg)
    mid, mach = new_id(), one_line(mmcore.machine_id(profile), 80)
    item = {"id": mid, "source": "mm", "sender": "mm", "level": level, "title": "test",
            "text": "machine-manager test from %s" % mach, "tags": []}
    r = deliver(cfg, secret, _msg(item))
    with _Lock():
        log_sent(dict(item, status="delivered" if r["ok"] else "refused" if r["error"] == "E_NOTIFY_REFUSED"
                      else "failed", error=r["error"]), time.time())
    if not r["ok"]:
        raise mmcore.MMError(r["error"], "test message not delivered (HTTP %s)%s"
                             % (r["status"], ": " + r["detail"] if r["detail"] else ""),
                             "check [notify] url/topic and the secret file (NOTIFY.md)")
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


def run(profile, now=None):
    """The timer's run: due outbox retries, then new mm alerts (alerts.jsonl after the cursor). Returns
    (rc, counts): rc 0, or 1 when a delivery failed, was queued, refused or dropped."""
    cfg = config(profile)
    counts = {"delivered": 0, "queued": 0, "failed": 0, "refused": 0, "suppressed": 0, "dropped": 0}
    if cfg is None:
        return 0, dict({"notify": "off"}, **counts, cursor=None)
    start = time.monotonic()
    now = time.time() if now is None else now
    mid_default = mmcore.machine_id(profile)
    with _Lock():
        secret = _secret(cfg)
        outbox, keep, todo = _outbox(), [], []
        for item in outbox:
            if now - _num_time(item["first"]) > OUTBOX_KEEP_S:
                log_sent(dict(item, status="dropped", error=item.get("error") or "E_NOTIFY_EXPIRED"), now)
                counts["dropped"] += 1
            elif _num_time(item["next"]) <= now and len(todo) < RUN_DELIVERIES:
                todo.append(item)
                keep.append(dict(item, next=round(now + LEASE_S, 3)))  # the lease: no other run retries it now
            else:
                keep.append(item)
        cur = read_state("cursor.json", {})
        seq = cur.get("seq") if type(cur.get("seq")) is int and cur["seq"] >= 0 else None
        suppressed = cur.get("suppressed") if type(cur.get("suppressed")) is int and cur["suppressed"] >= 0 else 0
        every = sorted(mmcore.read_pushed(0), key=lambda r: r["seq"])
        newest = every[-1]["seq"] if every else 0
        if seq is None or 0 < newest < seq:  # the first run, or the alert sequence started again (a new
            seq, recs = newest, []              # alerts-state.json): start at the newest alert, never the history
        else:
            recs = [r for r in every if r["seq"] > seq]
        sent_ids = _counted_ids("mm", "mm", now, [i["id"] for i in keep if i["source"] == "mm"])
        in_hour = len(sent_ids)
        new = []
        if suppressed and in_hour < cfg["alerts_per_hour"] and len(todo) < RUN_DELIVERIES:
            new.append({"id": new_id(), "source": "mm", "sender": "mm", "level": "quiet", "title": "alerts suppressed",
                        "text": "%d alerts suppressed (machine %s)" % (suppressed, one_line(mid_default, 80)),
                        "tags": [], "first": round(now, 3), "next": round(now + LEASE_S, 3), "tries": 0})
            suppressed = 0
        for r in recs:
            if len(todo) + len(new) >= RUN_DELIVERIES:
                break
            seq = r["seq"]
            m = _alert_message(r, cfg, mid_default)
            if m is None:
                continue
            level, title, text = m
            item = {"id": new_id(), "source": "mm", "sender": "mm", "level": level, "title": title, "text": text,
                    "tags": [], "first": round(now, 3), "next": round(now + LEASE_S, 3), "tries": 0}
            if in_hour >= cfg["alerts_per_hour"]:
                log_sent(dict(item, status="suppressed", error="E_NOTIFY_LIMIT"), now)
                counts["suppressed"] += 1
                suppressed += 1
                continue
            in_hour += 1
            new.append(item)
        for item in new:  # in the outbox before delivery: a run that dies here leaves them for the next run
            _add_outbox(keep, item, now)
        write_state("cursor.json", {"schema_version": 1, "seq": seq, "suppressed": suppressed})
        _write_outbox(keep)
    results, problem = [], None
    for item in todo + new:
        if time.monotonic() - start > RUN_DEADLINE_S:
            break
        try:
            results.append((item, deliver(cfg, secret, _msg(item))))
        except mmcore.MMError as e:  # a config problem: record what was done, then report it (exit 2)
            problem = e
            break
    with _Lock():
        t = time.time()
        done = {item["id"] for item, _ in results}
        planned = {item["id"] for item in todo + new}
        outbox = []
        for i in _outbox():
            if i["id"] in done:
                continue
            outbox.append(dict(i, next=round(t, 3)) if i["id"] in planned else i)  # not tried: due at the next run
        for item, r in results:
            counts[_record(item, r, t, outbox)] += 1
        _write_outbox(outbox)
    if problem is not None:
        raise problem
    rc = 1 if counts["queued"] or counts["failed"] or counts["refused"] or counts["dropped"] else 0
    return rc, dict({"notify": "run"}, **counts, cursor=seq)


# --------------------------------------------------------------------------------------------- status

def status(profile):
    """notify on|off, service, host, secret, cursor, queued, last delivery, grants. Reads files only; writes none."""
    cfg = config(profile)
    cur = read_state("cursor.json", {})
    last = max((r["_t"] for r in sent_records() if r.get("status") == "delivered"), default=None)
    host = urllib.parse.urlsplit(cfg["url"]).hostname if cfg else None
    return {"notify": "on" if cfg else "off", "service": cfg["service"] if cfg else None, "host": host,
            "secret": secret_state(cfg) if cfg else "none",
            "cursor": cur.get("seq") if type(cur.get("seq")) is int else None, "queued": len(_outbox()),
            "last_delivery": mmcore.now_local(last) if last is not None else None, "grants": len(read_grants())}
