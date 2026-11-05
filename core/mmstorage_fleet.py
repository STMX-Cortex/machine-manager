# SPDX-License-Identifier: Apache-2.0
"""Fleet storage snapshots: local `storage.json`, peer caches under `fleet-storage/`, and their bounded readers.

See STORAGE.md, Fleet storage export. Only `mm storage record` writes the local snapshot and only `mm collect`
fetches peers; serve/export read files only. The supervisor never imports this module. A failed or invalid read
never revives an earlier good snapshot; stale snapshots are returned as not fresh.
Run as `mmstorage_fleet.py --fetch`, it is the peer fetch worker: HTTP read, parse and full validation in one
process under the collector's wall timeout, printing only the canonical snapshot.
"""
import json
import math
import os
import secrets
import stat
import sys
import time

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mmcore
import mmfleet
import mmstorage
import mmstorage_io

SNAPSHOT_BYTES = 8 << 20            # one serialized snapshot (ASCII JSON plus newline: the file and the HTTP body)
CACHE_BYTES = SNAPSHOT_BYTES + 4096  # one peer cache file: a snapshot plus its small envelope
STORAGE_FRESH_S = 300               # local snapshot age limit; peers use storage_stale_after_s (default 300)
FUTURE_SKEW_S = mmfleet.FUTURE_SKEW_S
FILE = "storage.json"
PEER_DIR = "fleet-storage"
PEER_ERROR = "storage unavailable or invalid"
KEYS = frozenset(("kind", "schema_version", "machine_id", "time", "capacity", "io"))
PEER_KEYS = frozenset(("kind", "schema_version", "machine_id", "id", "collected_at", "snapshot", "error"))
ATTEMPT = "fleet-storage-attempt.json"  # data dir, outside PEER_DIR: the start time of the latest storage collection
ATTEMPT_KEYS = frozenset(("kind", "schema_version", "machine_id", "time"))
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def dumps(doc):
    """The one serialization for the local file and the HTTP body: compact, sorted, ASCII, one trailing newline."""
    return json.dumps(doc, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def valid(doc):
    """Envelope, exact keys, both sub-records by their own validators, one machine_id, time = min(sub-record times).
    Callers bound bytes/depth before decoding (read()); this checks structure, not freshness."""
    try:
        if not isinstance(doc, dict) or set(doc) != KEYS or doc["kind"] != "storage_snapshot" \
                or type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
            return False
        capacity, io, ident = doc["capacity"], doc["io"], doc["machine_id"]
        if not mmstorage.valid(capacity) or not mmstorage_io.valid(io):
            return False
        if not isinstance(ident, str) or capacity["machine_id"] != ident or io["machine_id"] != ident:
            return False
        return _number(doc["time"]) and doc["time"] == min(capacity["time"], io["time"])
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
        return False


def fresh(doc, now, limit=STORAGE_FRESH_S):
    return _number(doc.get("time")) and -FUTURE_SKEW_S <= now - doc["time"] < limit


def read(path, limit, dir_fd=None):
    """Strict bounded JSON from a regular file: no links, FIFOs, duplicate keys, nonfinite numbers or depth > 32.
    dir_fd: path is a name relative to that open directory."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=dir_fd)
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None
            raw = f.read(limit + 1)
        return mmfleet._strict_json(raw, limit)
    except (OSError, ValueError, RecursionError):
        return None


_CHECKED = {}  # per process (mm serve): key -> (file identity, file bytes, checked document or None)
CHECK_CACHE_BYTES = 64 << 20  # total file bytes of reused documents; the oldest entries leave first
CHECK_CACHE_ENTRIES = 64
READ_DEADLINE_S = 2.0  # soft: no new peer check starts after it; a check already running finishes
_NEXT = [0]  # the peer where the next scrape starts reading, so a deadline never starves the same peers


def _remember(key, ident, size, doc):
    _CHECKED.pop(key, None)
    if size > CHECK_CACHE_BYTES:
        return
    while _CHECKED and (len(_CHECKED) >= CHECK_CACHE_ENTRIES
                        or sum(v[1] for v in list(_CHECKED.values())) + size > CHECK_CACHE_BYTES):
        _CHECKED.pop(next(iter(_CHECKED)), None)
    _CHECKED[key] = (ident, size, doc)


def _read_checked(key, path, limit, check, dir_fd=None):
    """read() plus an expensive check, reused while the file identity (device, inode, size, times) is unchanged.
    Writers replace files atomically, so a new collection is a new identity. Returns the document or None.
    Nothing is remembered after an I/O failure, so a later scrape reads the file again."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError:
        _CHECKED.pop(key, None)
        return None
    try:
        try:
            f = os.fdopen(fd, "rb")
        except OSError:
            os.close(fd)
            raise
        with f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                _CHECKED.pop(key, None)
                return None
            ident = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            hit = _CHECKED.get(key)
            if hit is not None and hit[0] == ident:
                return hit[2]
            raw = f.read(limit + 1)
    except OSError:
        _CHECKED.pop(key, None)
        return None
    try:
        doc = mmfleet._strict_json(raw, limit)
        doc = doc if check(doc) else None
    except (ValueError, RecursionError, KeyError, TypeError):
        doc = None
    _remember(key, ident, st.st_size, doc)
    return doc


def _capacity_unknown(rec, reason):
    return {"schema_version": 1, "machine_id": rec["machine_id"], "time": rec["time"], "state": "UNKNOWN",
            "reason": reason, "devices": [], "filesystems": []}


def _io_unknown(rec, reason):
    return mmstorage_io.envelope(rec["machine_id"], rec["time"], rec["requested_interval_s"], reason)


def build(machine_id, capacity, io):
    """The snapshot from one capacity and one I/O observation (already collected and validated by their modules).

    Text is masked/cleaned like `mm storage`; a sub-record that masking would make invalid becomes UNKNOWN/invalid_data.
    If the serialized snapshot exceeds SNAPSHOT_BYTES, the largest sub-record (then the other) becomes UNKNOWN/truncated.
    """
    if not mmstorage.valid(capacity) or not mmstorage_io.valid(io) \
            or capacity["machine_id"] != machine_id or io["machine_id"] != machine_id:
        raise ValueError("invalid storage observation")
    parts = {}
    for key, rec, check, unknown in (("capacity", capacity, mmstorage.valid, _capacity_unknown),
                                     ("io", io, mmstorage_io.valid, _io_unknown)):
        masked = mmcore.clean_obj(mmcore.mask_obj(rec))
        parts[key] = masked if check(masked) and masked["machine_id"] == machine_id else unknown(rec, "invalid_data")

    def snapshot():
        return {"kind": "storage_snapshot", "schema_version": 1, "machine_id": machine_id,
                "time": min(parts["capacity"]["time"], parts["io"]["time"]),
                "capacity": parts["capacity"], "io": parts["io"]}

    doc = snapshot()
    order = sorted(("capacity", "io"), key=lambda k: -len(dumps(parts[k])))
    for key in order:
        if len(dumps(doc)) <= SNAPSHOT_BYTES:
            break
        parts[key] = (_capacity_unknown if key == "capacity" else _io_unknown)(parts[key], "truncated")
        doc = snapshot()
    if len(dumps(doc)) > SNAPSHOT_BYTES or not valid(doc):
        raise ValueError("invalid storage snapshot")
    return doc


def complete(doc):
    """Exit-0 condition of `mm storage record`: both inventories OK, every capacity and every rate known."""
    return doc["capacity"]["state"] == "OK" and doc["io"]["state"] == "OK" \
        and all(f["capacity_reason"] is None for f in doc["capacity"]["filesystems"]) \
        and all(d["rate_reason"] is None for d in doc["io"]["devices"])


def write_local(doc):
    mmcore.write_atomic(mmcore.path(FILE), dumps(doc), mode=0o600)


def local(profile, now):
    """The local snapshot when valid, of this machine and fresh (for /storage.json); otherwise None."""
    doc = read(mmcore.path(FILE), SNAPSHOT_BYTES)
    if not valid(doc) or doc["machine_id"] != mmcore.machine_id(profile) or not fresh(doc, now):
        return None
    return doc


def _clean_text(node):
    """True when no string (or key) would change under masking/cleaning (the same rule build() applies)."""
    stack = [node]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.keys())
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str) and mmcore.clean(mmcore.mmtext.mask_keep_quotes(node)) != node:
            return False
    return True


def peer_snapshot(doc, cfg, now):
    """A peer snapshot accepted for the cache, else None: valid, of this peer, source time not in the future and not
    older than storage_stale_after_s, and no text that masking would change (rejected, never rewritten, so a
    rewrite cannot break sorted/unique relations)."""
    if not valid(doc) or doc["machine_id"] != cfg["id"]:
        return None
    if doc["time"] > now + FUTURE_SKEW_S or now - doc["time"] >= cfg["storage_stale_after_s"]:
        return None
    return doc if _clean_text(doc) else None


def worker_output(raw, cfg, now):
    """Worker side: raw HTTP body -> canonical dumps() bytes of the validated snapshot, or FleetError."""
    snapshot = peer_snapshot(mmfleet._strict_json(raw, SNAPSHOT_BYTES), cfg, now)
    out = dumps(snapshot).encode("ascii") if snapshot is not None else b""
    if snapshot is None or len(out) > SNAPSHOT_BYTES:
        raise mmfleet.FleetError("storage snapshot invalid")
    return out


def fetch(cfg):
    """Fetch, parse and validate in the worker process, under the wall timeout timeout_s. Returns its canonical output;
    the caller strict-parses and validates it again with its own clock. URL and errors never reach arguments or
    messages."""
    request = {"url": cfg["storage_url"], "timeout": cfg["timeout_s"], "id": cfg["id"],
               "stale_after_s": cfg["storage_stale_after_s"]}
    return mmfleet.worker(os.path.abspath(__file__), request, cfg["timeout_s"], SNAPSHOT_BYTES)


def worker_main(request_bytes):
    """The worker: HTTP read, then the clock is read when the response is complete (a slow request never makes a
    current snapshot look future), then worker_output()."""
    args = json.loads(request_bytes)
    cfg = {"id": args["id"], "storage_stale_after_s": args["stale_after_s"]}
    raw = mmfleet._http(args["url"], args["timeout"], SNAPSHOT_BYTES)
    return worker_output(raw, cfg, time.time())


def _cache_dir(create=False):
    """The open cache directory, never through a link or a non-directory; None when unavailable."""
    path = mmcore.path(PEER_DIR)
    try:
        if create:
            try:
                os.mkdir(path, 0o700)
            except FileExistsError:
                pass
        return os.open(path, DIR_FLAGS)
    except OSError:
        return None


def _write_at(dir_fd, name, text):
    """Atomic write of name inside the open directory: new random temp (O_EXCL), mode 0600, fsync, rename."""
    tmp = ".%s.%s.tmp" % (name, secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        raise


def collect(profile, now=None, fetcher=None):
    """After fleet.json: fetch /storage.json for peers with storage_url and write one cache file each.

    First the attempt marker (data dir) records this collection's start; entries older than it are never fresh, even
    when a later replace and unlink both fail. Returns [(peer id, ok)] in profile order. A failure writes snapshot
    null. Without the marker or a real cache directory nothing is fetched and every storage peer is unavailable.
    """
    import concurrent.futures
    cfgs = [cfg for cfg in mmfleet.configs(profile) if "storage_url" in cfg]
    if not cfgs:
        return []
    clock = time.time if now is None else lambda: now
    fetcher = fetcher or (lambda cfg: fetch(cfg))
    central = mmcore.machine_id(profile)
    try:
        # Remove the old marker first (needs no free space): if the new one cannot be written, no earlier cache
        # entry stays fresh. Any unlink failure other than a missing file also stops the collection.
        try:
            os.unlink(mmcore.path(ATTEMPT))
        except FileNotFoundError:
            pass
        marker = {"kind": "fleet_storage_attempt", "schema_version": 1, "machine_id": central, "time": clock()}
        mmcore.write_atomic(mmcore.path(ATTEMPT), json.dumps(marker, allow_nan=False, sort_keys=True), mode=0o600)
    except (OSError, ValueError):
        return [(cfg["id"], False) for cfg in cfgs]
    dir_fd = _cache_dir(create=True)
    if dir_fd is None:
        return [(cfg["id"], False) for cfg in cfgs]

    def one(cfg):
        name = cfg["id"] + ".json"
        try:
            snapshot = peer_snapshot(mmfleet._strict_json(fetcher(cfg), SNAPSHOT_BYTES), cfg, clock())
        except Exception:
            snapshot = None
        rec = {"kind": "fleet_storage", "schema_version": 1, "machine_id": central, "id": cfg["id"],
               "collected_at": clock(), "snapshot": snapshot, "error": None if snapshot else PEER_ERROR}
        text = json.dumps(rec, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(text.encode("utf-8")) > CACHE_BYTES:
            rec.update(snapshot=None, error=PEER_ERROR)
            text = json.dumps(rec, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        try:
            _write_at(dir_fd, name, text)
        except OSError:
            try:
                os.unlink(name, dir_fd=dir_fd)  # the attempt marker already keeps an older entry from being fresh
            except OSError:
                pass
            return cfg["id"], False
        return cfg["id"], rec["snapshot"] is not None

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(4, len(cfgs)))) as executor:
            return list(executor.map(one, cfgs))
    finally:
        os.close(dir_fd)


def _attempt_time(central):
    doc = read(mmcore.path(ATTEMPT), 4096)
    if not isinstance(doc, dict) or set(doc) != ATTEMPT_KEYS or doc["kind"] != "fleet_storage_attempt" \
            or type(doc["schema_version"]) is not int or doc["schema_version"] != 1 \
            or doc["machine_id"] != central or not _number(doc["time"]):
        return None
    return doc["time"]


def _peer_ok(doc, cfg, central):
    if not isinstance(doc, dict) or set(doc) != PEER_KEYS or doc["kind"] != "fleet_storage" \
            or type(doc["schema_version"]) is not int or doc["schema_version"] != 1 \
            or doc["machine_id"] != central or doc["id"] != cfg["id"] or not _number(doc["collected_at"]):
        return False
    snapshot = doc["snapshot"]
    if snapshot is None or doc["error"] is not None:  # error is null exactly when a snapshot is present
        return False
    return valid(snapshot) and snapshot["machine_id"] == cfg["id"] and _clean_text(snapshot)


def _peer(cfg, central, now, dir_fd, attempt):
    name = cfg["id"] + ".json"
    doc = _read_checked(("peer", central, cfg["id"]), name, CACHE_BYTES, lambda d: _peer_ok(d, cfg, central),
                        dir_fd=dir_fd)
    if doc is None:
        return None, False
    snapshot = doc["snapshot"]
    limit = cfg["storage_stale_after_s"]
    is_fresh = doc["collected_at"] >= attempt and -FUTURE_SKEW_S <= now - doc["collected_at"] < limit \
        and fresh(snapshot, now, limit)
    return snapshot, is_fresh


def exported_snapshots(profile, now):
    """[(machine_id, snapshot or None, fresh)] for the exporter. Read-only: no network, collection or writes.

    The local machine comes first, only when storage.json exists; then each peer with storage_url, in profile order.
    Peers need a valid attempt marker and a real cache directory (not a link); otherwise each is (id, None, False).
    Checked documents are reused while their file identity is unchanged; no peer check starts after
    READ_DEADLINE_S, and the next call starts with the first peer not reached. Output keeps profile order.
    """
    ident, out, started = mmcore.machine_id(profile), [], time.monotonic()
    path = mmcore.path(FILE)
    try:
        os.lstat(path)
        exists = True
    except OSError:
        exists = False
    if exists:
        doc = _read_checked(("local", path, ident), path, SNAPSHOT_BYTES,
                            lambda d: valid(d) and d["machine_id"] == ident)
        if doc is not None:
            out.append((ident, doc, fresh(doc, now)))
        else:
            out.append((ident, None, False))
    cfgs = [cfg for cfg in mmfleet.configs(profile) if "storage_url" in cfg]
    if not cfgs:
        return out
    attempt = _attempt_time(ident)
    dir_fd = _cache_dir() if attempt is not None else None
    start, results = _NEXT[0] % len(cfgs), {}
    try:
        for n in range(len(cfgs)):
            # A scrape never starts storage work after the deadline: peers not reached are unknown this time, and
            # the next scrape starts with the first of them, so every peer is reached and then reused.
            i = (start + n) % len(cfgs)
            if dir_fd is not None and time.monotonic() - started > READ_DEADLINE_S:
                _NEXT[0] = i
                break
            results[i] = _peer(cfgs[i], ident, now, dir_fd, attempt) if dir_fd is not None else (None, False)
        else:
            _NEXT[0] = 0
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    return out + [(cfg["id"],) + results.get(i, (None, False)) for i, cfg in enumerate(cfgs)]


if __name__ == "__main__":
    if sys.argv[1:] != ["--fetch"]:
        sys.exit(2)
    try:
        sys.stdout.buffer.write(worker_main(sys.stdin.buffer.read(mmfleet.MAX_URL * 2)))
    except Exception:
        sys.exit(1)  # URLs and transport/validation exceptions never reach logs or output.
