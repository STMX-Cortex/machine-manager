# SPDX-License-Identifier: Apache-2.0
"""Ready work: the profile's `ready_work_dir` holds one JSON file per owner of work that waits for this machine,
`{"owner": str, "updated": ISO-8601 time, "ready_units": int >= 0, "next": str}`. The supervisor reads it each tick;
mmalerts turns the result into IDLE_WITH_WORK (free slots while ready work waits) and READY_WORK_STALE (a file that
is old or bad). Readings only: nothing here acts.

The idle timer's start survives a restart in state/ready-work.json (`{"since": number|null}`). Its reader is a
control reader: a missing file is "no record"; a file that exists but does not read is an error, never "no record".
"""
import datetime
import errno
import heapq
import json
import os
import re
import stat

import mmcore
import mmfleet

FILE_MAX = 64 << 10  # bytes of one owner file; a larger file is bad
FILES_MAX = 64  # owner files read per scan (by sorted name), besides the listed owners; more is one alert
LIST_MAX = 4096  # directory entries of any kind looked at per scan; more is one alert (the listing stopped)
FUTURE_S = 300  # an `updated` time further ahead than this is bad
UNITS_MAX = 10 ** 9
OWNER_MAX = 40
NEXT_MAX = 120
WHY_MAX = 120
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json")
OWNER_NAME, OWNERS_MAX = mmcore.READY_OWNER_NAME, mmcore.READY_OWNERS_MAX  # ready_work_owners (mmcore checks it)
STATE_NAME = "ready-work.json"
STATE_MAX = 4096


def folder(profile):
    """The expanded ready_work_dir, or None when the profile has none (absent or "")."""
    p = (profile or {}).get("ready_work_dir")
    return mmcore.expand(p) if isinstance(p, str) and p else None


LINK_WHY = "is a link (links are not followed)"
MISSING_WHY = "is missing"


def _read_bytes(p, limit, dir_fd=None):
    """(raw, why): at most limit bytes of a regular file, opened without blocking on a FIFO and never through a link
    (dir_fd: p is a name in that open folder). A link, a folder, a FIFO or any other type is a why."""
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError as e:
        if e.errno == errno.ELOOP:
            return None, LINK_WHY
        if e.errno == errno.ENOENT:
            return None, MISSING_WHY
        return None, "cannot be opened (%s)" % (e.strerror or e.__class__.__name__)
    try:
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
        f = os.fdopen(fd, "rb") if regular else None
    except OSError as e:
        os.close(fd)
        return None, "cannot be opened (%s)" % (e.strerror or e.__class__.__name__)
    if f is None:
        os.close(fd)
        return None, "is not a regular file"
    try:
        with f:
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


def read_file(path, name, now, stale_minutes, dir_fd=None):
    """One owner record: {file, stem, owner, units, age_min, state (ok|stale|bad), why, next}. path: the file, or its
    name in the open folder dir_fd. Only a regular file reads; a link is never followed. Never raises."""
    stem = name[:-5] if name.endswith(".json") else name
    rec = {"file": name, "stem": stem, "owner": stem, "units": 0, "age_min": None, "state": "bad", "why": None,
           "next": ""}
    raw, why = _read_bytes(path, FILE_MAX, dir_fd)
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


def _bad_folder(why):
    return {"file": ".", "stem": "_list", "owner": "the folder", "units": 0, "age_min": None, "state": "bad",
            "why": why, "next": ""}


def _missing(name):
    return {"file": name + ".json", "stem": name, "owner": name, "units": 0, "age_min": None, "state": "missing",
            "why": MISSING_WHY, "next": ""}


def _open_folder(path):
    """(fd, None) for the folder at the normalized absolute path, or (None, (not_folder, why)). The path is lstat-ed
    and refused when it is a link (O_NOFOLLOW alone misses a trailing "/" or "/."); the opened descriptor must be
    the same file (st_dev, st_ino) as the lstat, so a swap between the two is refused too."""
    try:
        st = os.lstat(path)
    except OSError as e:
        return None, (False, "the folder cannot be opened (%s)" % (e.strerror or "error"))
    if stat.S_ISLNK(st.st_mode):
        return None, (True, LINK_WHY)
    if not stat.S_ISDIR(st.st_mode):
        return None, (True, "is not a folder")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        if e.errno == errno.ELOOP:
            return None, (True, LINK_WHY)
        if e.errno == errno.ENOTDIR:
            return None, (True, "is not a folder")
        return None, (False, "the folder cannot be opened (%s)" % (e.strerror or "error"))
    try:
        got = os.fstat(fd)
        same = (got.st_dev, got.st_ino) == (st.st_dev, st.st_ino)
    except OSError:
        same = False
    if not same:
        os.close(fd)
        return None, (True, "changed while it was opened")
    return fd, None


def scan(path, now, stale_minutes, expected=()):
    """None when the feature is off (no path, or nothing at it). Else {folder, not_folder, folder_why, owners, more,
    truncated}. The path is normalized and must be absolute; the folder is opened once and never through a link
    (_open_folder). Every `expected` owner (the profile's ready_work_owners) is opened directly by name through the
    folder's descriptor: no file is a record in state "missing". The listing (through the same descriptor) stops
    after LIST_MAX entries of any kind (`truncated`); of the other names that match NAME, the FILES_MAX smallest are
    read (only those are held) and `more` counts the rest. Each file is opened by name in the folder, never through
    a link: a link, a folder, a FIFO or another type is a bad file. Owners come sorted by file name. Never raises.
    Read only from a local disk: a read on a stalled network file system blocks (README.md, "Ready work")."""
    if not path:
        return None
    norm = os.path.normpath(path)
    if not os.path.lexists(norm):
        return None
    out = {"folder": path, "not_folder": False, "folder_why": None, "owners": [], "more": 0, "truncated": False}
    if not os.path.isabs(norm):
        out.update(not_folder=True, folder_why="is not an absolute path")
        return out
    dfd, why = _open_folder(norm)
    if dfd is None:
        if why[0]:
            out.update(not_folder=True, folder_why=why[1])
        else:
            out["owners"].append(_bad_folder(why[1]))
        return out
    try:
        want = sorted({n + ".json" for n in expected})
        skip = set(want)
        seen, count = [0], [0]

        def names(it):
            for entry in it:
                seen[0] += 1
                if seen[0] > LIST_MAX:
                    out["truncated"] = True
                    return
                if entry.name not in skip and NAME.fullmatch(entry.name):
                    count[0] += 1
                    yield entry.name
        try:
            with os.scandir(dfd) as it:
                picked = heapq.nsmallest(FILES_MAX, names(it))
        except OSError as e:
            out["owners"].append(_bad_folder("the folder cannot be listed (%s)" % (e.strerror or "error")))
            picked = []
        out["more"] = max(0, count[0] - len(picked))
        recs = []
        for n in picked:
            rec = read_file(n, n, now, stale_minutes, dir_fd=dfd)
            if rec["why"] != MISSING_WHY:  # gone since the listing: not a file any more
                recs.append(rec)
        for n in want:
            rec = read_file(n, n, now, stale_minutes, dir_fd=dfd)
            recs.append(_missing(n[:-5]) if rec["why"] == MISSING_WHY else rec)
        out["owners"] += sorted(recs, key=lambda o: o["file"])
        return out
    finally:
        os.close(dfd)


def state_file():
    return mmcore.path("state", STATE_NAME)


def load_since():
    """(since, error) from state/ready-work.json. Missing: (None, None). Anything that is not {"since": number|null}
    (unreadable, a link, not a regular file, bad JSON, a wrong type): (None, why). Never raises."""
    p = state_file()
    if not os.path.lexists(p):
        return None, None
    raw, why = _read_bytes(p, STATE_MAX)
    if why == MISSING_WHY:  # gone since the lexists: no record
        return None, None
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
