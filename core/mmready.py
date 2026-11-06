# SPDX-License-Identifier: Apache-2.0
"""Ready work: the profile's `ready_work_dir` holds one JSON file per owner of work that waits for this machine,
`{"owner": str, "updated": ISO-8601 time, "ready_units": int >= 0, "next": str}`. The supervisor reads it each tick;
mmalerts turns the result into IDLE_WITH_WORK (free slots while ready work waits) and READY_WORK_STALE (a file that
is old or bad). Readings only: nothing here acts.

The idle timer's start survives a restart in state/ready-work.json (`{"since": number|null}`). Its reader is a
control reader: a missing file is "no record"; a file that exists but does not read is an error, never "no record".
"""
import datetime
import json
import os
import re
import stat

import mmcore
import mmfleet

FILE_MAX = 64 << 10  # bytes of one owner file; a larger file is bad
FILES_MAX = 64  # owner files read per scan (by sorted name); more is one alert
FUTURE_S = 300  # an `updated` time further ahead than this is bad
UNITS_MAX = 10 ** 9
OWNER_MAX = 40
NEXT_MAX = 120
WHY_MAX = 120
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json")
STATE_NAME = "ready-work.json"
STATE_MAX = 4096


def folder(profile):
    """The expanded ready_work_dir, or None when the profile has none (absent or "")."""
    p = (profile or {}).get("ready_work_dir")
    return mmcore.expand(p) if isinstance(p, str) and p else None


def _read_bytes(p, limit):
    """(raw, why): at most limit bytes of a regular file, opened without blocking on a FIFO."""
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError as e:
        return None, "cannot be opened (%s)" % (e.strerror or e.__class__.__name__)
    try:
        f = os.fdopen(fd, "rb")
    except OSError as e:
        os.close(fd)
        return None, "cannot be opened (%s)" % (e.strerror or e.__class__.__name__)
    try:
        with f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None, "is not a regular file"
            raw = f.read(limit + 1)
    except OSError as e:
        return None, "cannot be read (%s)" % (e.strerror or e.__class__.__name__)
    if len(raw) > limit:
        return None, "is over %d bytes" % limit
    return raw, None


def _strict(raw, limit):
    """(doc, why) through the code base's strict JSON reader (no duplicate keys, no NaN or Infinity, depth <= 32)."""
    try:
        return mmfleet._strict_json(raw, limit), None
    except (ValueError, RecursionError):
        return None, "is not strict JSON"


def _time(text):
    """The epoch time of an ISO-8601 text (naive = local time), or None."""
    try:
        return datetime.datetime.fromisoformat(text).timestamp()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def read_file(path, name, now, stale_minutes):
    """One owner record: {file, stem, owner, units, age_min, state (ok|stale|bad), why, next}. Never raises."""
    stem = name[:-5] if name.endswith(".json") else name
    rec = {"file": name, "stem": stem, "owner": stem, "units": 0, "age_min": None, "state": "bad", "why": None,
           "next": ""}
    raw, why = _read_bytes(path, FILE_MAX)
    doc = None
    if why is None:
        doc, why = _strict(raw, FILE_MAX)
    if why is None and not isinstance(doc, dict):
        why = "is not a JSON object"
    if why is not None:
        rec["why"] = why
        return rec
    if isinstance(doc.get("owner"), str) and doc["owner"]:
        rec["owner"] = doc["owner"][:OWNER_MAX]
    units, updated, nxt = doc.get("ready_units"), doc.get("updated"), doc.get("next", "")
    t = _time(updated) if isinstance(updated, str) else None
    if t is not None:
        rec["age_min"] = round(max(0.0, now - t) / 60, 1)
    if type(units) is not int:
        why = "ready_units is missing or not a whole number"
    elif units < 0:
        why = "ready_units is negative"
    elif units > UNITS_MAX:
        why = "ready_units is over %d" % UNITS_MAX
    elif not isinstance(updated, str):
        why = "updated is missing or not a text"
    elif t is None:
        why = "updated is not an ISO-8601 time"
    elif t - now > FUTURE_S:
        why = "updated is %.0f min in the future" % ((t - now) / 60)
    elif not isinstance(nxt, str):
        why = "next is not a text"
    if why is not None:
        rec["why"] = why
        return rec
    rec.update(units=units, next=nxt[:NEXT_MAX], state="stale" if now - t > stale_minutes * 60 else "ok")
    return rec


def scan(path, now, stale_minutes):
    """None when the feature is off (no path, or nothing at it). Else {folder, not_folder, owners, more}: the owner
    records of the folder's direct children named like NAME, by name, at most FILES_MAX of them."""
    if not path or not os.path.lexists(path):
        return None
    out = {"folder": path, "not_folder": False, "owners": [], "more": 0}
    if not os.path.isdir(path):
        out["not_folder"] = True
        return out
    try:
        names = sorted(n for n in os.listdir(path) if NAME.fullmatch(n))
    except OSError as e:
        out["owners"].append({"file": ".", "stem": "_list", "owner": "the folder", "units": 0, "age_min": None,
                              "state": "bad", "why": "the folder cannot be listed (%s)" % (e.strerror or "error"),
                              "next": ""})
        return out
    real = os.path.realpath(path)
    picked = []
    for n in names:
        p = os.path.join(path, n)
        if os.path.islink(p):
            target = os.path.realpath(p)
            if os.path.commonpath([real, target]) != real or target == real:
                continue  # a link that leaves the folder
            if os.path.dirname(target) == real and os.path.basename(target) in names \
                    and not os.path.islink(os.path.join(path, os.path.basename(target))):
                continue  # a link to another file that is read itself
            if os.path.isdir(target):
                continue
            p = target
        elif os.path.isdir(p):
            continue
        picked.append((n, p))
    out["more"] = max(0, len(picked) - FILES_MAX)
    out["owners"] = [read_file(p, n, now, stale_minutes) for n, p in picked[:FILES_MAX]]
    return out


def state_file():
    return mmcore.path("state", STATE_NAME)


def load_since():
    """(since, error) from state/ready-work.json. Missing: (None, None). Anything that is not {"since": number|null}
    (unreadable, a link, not a regular file, bad JSON, a wrong type): (None, why). Never raises."""
    p = state_file()
    if not os.path.lexists(p):
        return None, None
    raw, why = _read_bytes(p, STATE_MAX)
    doc = None
    if why is None:
        doc, why = _strict(raw, STATE_MAX)
    if why is None:
        v = doc.get("since") if isinstance(doc, dict) else None
        if not isinstance(doc, dict) or "since" not in doc or not (
                v is None or (isinstance(v, (int, float)) and not isinstance(v, bool))):
            why = "is not {\"since\": number or null}"
        else:
            return (None if v is None else float(v)), None
    return None, ("state/%s %s" % (STATE_NAME, why))[:WHY_MAX]


def save_since(since):
    mmcore.write_atomic(state_file(), json.dumps({"since": since}, sort_keys=True, allow_nan=False))


def status_part(rw):
    """status.json's `ready_work` from the snapshot part."""
    return {"free": rw["free"], "ready": rw["ready"],
            "idle_minutes": None if rw.get("idle_minutes") is None else round(rw["idle_minutes"], 1),
            "owners": [{"owner": mmcore.clean(o["owner"]), "file": mmcore.clean(o["file"]), "units": o["units"],
                        "age_min": o["age_min"], "state": o["state"]} for o in rw["owners"]]}
