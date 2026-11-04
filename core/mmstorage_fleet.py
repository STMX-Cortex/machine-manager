# SPDX-License-Identifier: Apache-2.0
"""Fleet storage snapshots: local `storage.json`, peer caches under `fleet-storage/`, and their bounded readers.

See STORAGE.md, Fleet storage export. Only `mm storage record` writes the local snapshot and only `mm collect`
fetches peers; serve/export read files only. The supervisor never imports this module. A failed or invalid read
never revives an earlier good snapshot; stale snapshots are returned as not fresh.
"""
import json
import math
import os
import stat
import time
import urllib.parse

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
SECRET_MIN = 8  # shorter URL query values are not treated as endpoint secrets


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


def read(path, limit):
    """Strict bounded JSON from a regular file: no links, FIFOs, duplicate keys, nonfinite numbers or depth > 32."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None
            raw = f.read(limit + 1)
        return mmfleet._strict_json(raw, limit)
    except (OSError, ValueError, RecursionError):
        return None


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


def _secrets(url):
    parsed = urllib.parse.urlsplit(url)
    values = [url, parsed.query] + [v for _, v in urllib.parse.parse_qsl(parsed.query)] + \
        [part.partition("=")[2] for part in parsed.query.split("&")]
    return [v for v in values if len(v) >= SECRET_MIN]


def _clean_text(node, secrets):
    """True when no string (or key) would change under masking/cleaning or holds this endpoint's URL secrets."""
    stack = [node]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.keys())
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            if mmcore.clean(mmcore.mmtext.mask_keep_quotes(node)) != node or any(s in node for s in secrets):
                return False
    return True


def peer_snapshot(doc, cfg, now):
    """A peer snapshot accepted for the cache, else None: valid, of this peer, source time not in the future and not
    older than storage_stale_after_s, and no text that masking would change or that repeats storage_url secrets.
    Peer text is rejected rather than rewritten, so a rewrite can never break sorted/unique relations."""
    if not valid(doc) or doc["machine_id"] != cfg["id"]:
        return None
    if doc["time"] > now + FUTURE_SKEW_S or now - doc["time"] >= cfg["storage_stale_after_s"]:
        return None
    return doc if _clean_text(doc, _secrets(cfg["storage_url"])) else None


def peer_path(ident):
    return mmcore.path(PEER_DIR, ident + ".json")


def collect(profile, now=None, fetcher=None):
    """After fleet.json: fetch /storage.json for peers with storage_url and write one cache file each.
    Returns [(peer id, ok)] in profile order. A failure writes snapshot null, never keeps an older good file."""
    import concurrent.futures
    cfgs = [cfg for cfg in mmfleet.configs(profile) if "storage_url" in cfg]
    if not cfgs:
        return []
    fetcher = fetcher or (lambda cfg: mmfleet.fetch(cfg, "storage_url", SNAPSHOT_BYTES))
    clock = time.time if now is None else lambda: now
    central = mmcore.machine_id(profile)
    try:
        os.makedirs(mmcore.path(PEER_DIR), mode=0o700, exist_ok=True)
    except OSError:
        return [(cfg["id"], False) for cfg in cfgs]

    def one(cfg):
        snapshot = None
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
            mmcore.write_atomic(peer_path(cfg["id"]), text, mode=0o600)
        except OSError:
            try:
                os.unlink(peer_path(cfg["id"]))  # never leave an older good snapshot in place of this failure
            except OSError:
                pass
            return cfg["id"], False
        return cfg["id"], rec["snapshot"] is not None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(4, len(cfgs)))) as executor:
        return list(executor.map(one, cfgs))


def _peer(cfg, central, now):
    doc = read(peer_path(cfg["id"]), CACHE_BYTES)
    if not isinstance(doc, dict) or set(doc) != PEER_KEYS or doc["kind"] != "fleet_storage" \
            or type(doc["schema_version"]) is not int or doc["schema_version"] != 1 \
            or doc["machine_id"] != central or doc["id"] != cfg["id"] or not _number(doc["collected_at"]):
        return None, False
    snapshot = doc["snapshot"]
    if not valid(snapshot) or snapshot["machine_id"] != cfg["id"] \
            or not _clean_text(snapshot, _secrets(cfg["storage_url"])):
        return None, False
    limit = cfg["storage_stale_after_s"]
    is_fresh = -FUTURE_SKEW_S <= now - doc["collected_at"] < limit and fresh(snapshot, now, limit)
    return snapshot, is_fresh


def exported_snapshots(profile, now):
    """[(machine_id, snapshot or None, fresh)] for the exporter. Read-only: no network, collection or writes.

    The local machine comes first, only when storage.json exists; then each peer with storage_url, in profile order.
    """
    ident, out = mmcore.machine_id(profile), []
    path = mmcore.path(FILE)
    try:
        os.lstat(path)
        exists = True
    except OSError:
        exists = False
    if exists:
        doc = read(path, SNAPSHOT_BYTES)
        if valid(doc) and doc["machine_id"] == ident:
            out.append((ident, doc, fresh(doc, now)))
        else:
            out.append((ident, None, False))
    for cfg in mmfleet.configs(profile):
        if "storage_url" in cfg:
            out.append((cfg["id"],) + _peer(cfg, ident, now))
    return out
