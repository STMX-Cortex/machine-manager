# SPDX-License-Identifier: Apache-2.0
"""Pure storage contract; no discovery, filesystem access, commands, or runtime writes.

See STORAGE.md. Platform collectors must bound their work before building these records.
"""
import hashlib
import json
import math
import re
import unicodedata
import uuid

RECORDS_MAX = 128                  # independently: devices and filesystems
MOUNTS_MAX = 32                    # aliases per filesystem
POLICY_MAX = 256                   # exact paths in either selection list
TEXT_MAX = 1024
BYTES_MAX = 2**63 - 1
CATEGORIES = ("local", "network", "memory", "pseudo", "overlay", "unknown")
REASONS = ("unsupported", "permission_denied", "timeout", "read_failed", "invalid_data", "truncated")
ID = re.compile(r"(device|filesystem|capacity):(uuid|wwn|native|session):[0-9a-f]{64}")
CAPACITY_KEYS = {"total_bytes", "free_bytes", "available_bytes", "used_bytes"}


def _text(value, limit=TEXT_MAX):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and not any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Cs") or c == "|" for c in value))


def storage_id(kind, basis, value):
    """Opaque machine-local identity. Session values MUST include boot/namespace identity.

    UUIDs normalize case/spelling; other bases use the adapter's exact canonical value.
    Hashing is for bounded identifiers, not secrecy, access control, or clone detection.
    """
    if kind not in ("device", "filesystem", "capacity") or basis not in ("uuid", "wwn", "native", "session"):
        raise ValueError("invalid storage identity kind or basis")
    if not _text(value):
        raise ValueError("invalid storage identity value")
    if basis == "uuid":
        value = str(uuid.UUID(value))
    raw = json.dumps([kind, basis, value], ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return "%s:%s:%s" % (kind, basis, hashlib.sha256(raw).hexdigest())


def _bytes(value):
    return value is None or (type(value) is int and 0 <= value <= BYTES_MAX)


def capacity(total_bytes=None, free_bytes=None, available_bytes=None):
    """Exact byte counts. Used = total - free; reserved bytes are not used bytes.

    Missing operands remain None; invalid or inconsistent counters raise ValueError.
    """
    values = (total_bytes, free_bytes, available_bytes)
    if not all(_bytes(v) for v in values):
        raise ValueError("invalid storage capacity")
    for smaller, larger in ((free_bytes, total_bytes), (available_bytes, total_bytes), (available_bytes, free_bytes)):
        if smaller is not None and larger is not None and smaller > larger:
            raise ValueError("inconsistent storage capacity")
    used = None if total_bytes is None or free_bytes is None else total_bytes - free_bytes
    return dict(zip(("total_bytes", "free_bytes", "available_bytes", "used_bytes"), (*values, used)))


def _path(path):
    return (_text(path) and path.startswith("/")
            and (path == "/" or all(p and p not in (".", "..") for p in path[1:].split("/"))))


def _paths(values, limit):
    return isinstance(values, (list, tuple)) and len(values) <= limit and all(_path(p) for p in values)


def select_mounts(category, mounts, include=(), exclude=()):
    """Sorted unique exact paths: local mounts + container overlay root by default.

    Explicit includes can opt other categories in; exact excludes always win. No probing.
    """
    if category not in CATEGORIES or not _paths(mounts, MOUNTS_MAX):
        raise ValueError("invalid storage mounts")
    if not _paths(include, POLICY_MAX) or not _paths(exclude, POLICY_MAX):
        raise ValueError("invalid storage selection")
    wanted, denied = set(include), set(exclude)
    return sorted(p for p in set(mounts) if p not in denied
                  and (category == "local" or (category == "overlay" and p == "/") or p in wanted))


def _ident(value, kind):
    return isinstance(value, str) and len(value) <= 96 and ID.fullmatch(value) is not None and value.startswith(kind + ":")


def _device(row):
    return (isinstance(row, dict) and set(row) == {"id", "name", "kind", "size_bytes"}
            and _ident(row["id"], "device") and _text(row["name"])
            and row["kind"] in ("block", "virtual", "unknown") and _bytes(row["size_bytes"]))


def _filesystem(row, devices):
    keys = {"id", "fs_type", "category", "mounts", "read_only", "device_ids", "capacity_group", "capacity", "capacity_reason"}
    if not isinstance(row, dict) or set(row) != keys:
        return False
    if not (_ident(row["id"], "filesystem") and _text(row["fs_type"], 64) and row["category"] in CATEGORIES
            and _paths(row["mounts"], MOUNTS_MAX) and row["mounts"] and isinstance(row["mounts"], list)
            and row["mounts"] == sorted(set(row["mounts"]))
            and (row["read_only"] is None or type(row["read_only"]) is bool)):
        return False
    refs = row["device_ids"]
    if not (isinstance(refs, list) and len(refs) <= RECORDS_MAX and all(_ident(r, "device") for r in refs)
            and refs == sorted(set(refs)) and set(refs) <= devices):
        return False
    group = row["capacity_group"]
    if group is not None and not _ident(group, "capacity"):
        return False
    cap = row["capacity"]
    if not isinstance(cap, dict) or set(cap) != CAPACITY_KEYS:
        return False
    try:
        expected = capacity(cap["total_bytes"], cap["free_bytes"], cap["available_bytes"])
    except ValueError:
        return False
    if not _bytes(cap["used_bytes"]) or cap != expected:
        return False
    missing = any(v is None for v in cap.values())
    return row["capacity_reason"] in REASONS if missing else row["capacity_reason"] is None


def valid(record):
    """Validate a decoded bounded storage record, including relations beyond JSON Schema.

    Callers must bound JSON byte size/depth BEFORE decoding; this is not a JSON reader.
    """
    keys = {"schema_version", "machine_id", "time", "state", "reason", "devices", "filesystems"}
    if not isinstance(record, dict) or set(record) != keys:
        return False
    if not (type(record["schema_version"]) is int and record["schema_version"] == 1
            and _text(record["machine_id"], 120) and type(record["time"]) in (int, float)
            and 0 <= record["time"] <= 2**53 - 1 and math.isfinite(record["time"])
            and record["state"] in ("OK", "PARTIAL", "UNKNOWN")):
        return False
    if record["state"] == "OK":
        if record["reason"] is not None:
            return False
    elif record["reason"] not in REASONS:
        return False
    devices, filesystems = record["devices"], record["filesystems"]
    if not all(isinstance(rows, list) and len(rows) <= RECORDS_MAX for rows in (devices, filesystems)):
        return False
    if record["state"] == "UNKNOWN" and (devices or filesystems):
        return False
    if not all(_device(d) for d in devices):
        return False
    ids = [d["id"] for d in devices]
    if ids != sorted(set(ids)) or not all(_filesystem(f, set(ids)) for f in filesystems):
        return False
    fids = [f["id"] for f in filesystems]
    mounts = [p for f in filesystems for p in f["mounts"]]
    return fids == sorted(set(fids)) and len(mounts) == len(set(mounts))
