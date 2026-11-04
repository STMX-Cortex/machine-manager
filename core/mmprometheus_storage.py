# SPDX-License-Identifier: Apache-2.0
"""Prometheus storage families from fleet storage snapshots; pure, no reads, network, commands or writes.

Callers pass (machine_id, snapshot_or_None, fresh) tuples from a validating reader. This renderer stays
defensive anyway: malformed rows are skipped, unknown values are absent (never zero), and a stale or missing
snapshot exports only freshness 0, its source time when known, and UNKNOWN inventory state. Each filesystem
and device is its own series; nothing is summed across filesystems, capacity groups or devices.
"""
import math

ROWS_MAX = 128  # mmstorage.RECORDS_MAX: devices and filesystems, independently
STATES = ("OK", "PARTIAL", "UNKNOWN")
SCOPES = ("whole_device", "driver")
CAPACITY = (("total_bytes", "size_bytes", "Filesystem size in bytes."),
            ("free_bytes", "free_bytes", "Filesystem unallocated bytes, including reserved space."),
            ("available_bytes", "available_bytes", "Filesystem bytes available to the collecting account."),
            ("used_bytes", "used_bytes", "Filesystem size minus free bytes."))
RATES = (("read_bytes_per_s", "read_bytes_per_second", "Device read bytes per second over the sample interval."),
         ("write_bytes_per_s", "write_bytes_per_second", "Device write bytes per second over the sample interval."),
         ("read_ops_per_s", "read_ops_per_second", "Device completed read operations per second over the sample interval."),
         ("write_ops_per_s", "write_ops_per_second", "Device completed write operations per second over the sample interval."))


def _number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def _text(value):
    return isinstance(value, str) and value != ""


def _record(snapshot, key, ident):
    doc = snapshot.get(key)
    return doc if isinstance(doc, dict) and doc.get("machine_id") == ident and doc.get("state") in STATES else None


def _rows(doc, key):
    rows = doc.get(key) if doc is not None and doc["state"] != "UNKNOWN" else None
    return [row for row in rows[:ROWS_MAX] if isinstance(row, dict)] if isinstance(rows, list) else []


def _filesystem(out, ident, row):
    mounts, group, cap = row.get("mounts"), row.get("capacity_group"), row.get("capacity")
    if not (_text(row.get("id")) and _text(row.get("fs_type")) and isinstance(mounts, list) and mounts
            and all(_text(m) for m in mounts) and (group is None or _text(group)) and isinstance(cap, dict)):
        return
    reason = row.get("capacity_reason")
    if reason is None and not all(type(cap.get(k)) is int and cap[k] >= 0 for k, _, _ in CAPACITY):
        return  # a "known" reading with a missing value is malformed, not partially known
    labels = {"machine_id": ident, "filesystem_id": row["id"], "mount": min(mounts), "fs_type": row["fs_type"],
              "capacity_group": group or ""}
    out.add("storage_filesystem_capacity_known", "Whether every filesystem capacity value is known (1/0).",
            labels, int(reason is None))
    for key, name, help_text in CAPACITY:
        value = cap.get(key)
        if type(value) is int and value >= 0:
            out.add("storage_filesystem_" + name, help_text, labels, value)
    if type(row.get("read_only")) is bool:
        out.add("storage_filesystem_read_only", "Whether the selected filesystem aliases are read-only (1/0).",
                labels, int(row["read_only"]))


def _device(out, ident, row):
    rates = row.get("rates")
    if not (_text(row.get("id")) and _text(row.get("name")) and row.get("scope") in SCOPES
            and isinstance(rates, dict)):
        return
    known = row.get("rate_reason") is None
    if known and not all(_number(rates.get(k)) for k, _, _ in RATES):
        return
    labels = {"machine_id": ident, "device_id": row["id"], "device": row["name"], "scope": row["scope"]}
    out.add("storage_device_rates_known", "Whether the device I/O rates are known (1/0).", labels, int(known))
    for key, name, help_text in RATES if known else ():
        out.add("storage_device_" + name, help_text, labels, rates[key])


def add(out, machine_id, snapshot, fresh):
    """Add one machine's storage series to an mmprometheus.Metrics; returns whether measurements were exported."""
    labels = {"machine_id": machine_id}
    if not isinstance(snapshot, dict) or snapshot.get("machine_id") != machine_id:
        snapshot = None
    is_fresh = fresh is True and snapshot is not None
    out.add("storage_snapshot_fresh", "Whether the storage snapshot is valid and fresh.", labels, int(is_fresh))
    if snapshot is not None and _number(snapshot.get("time")):
        out.add("storage_snapshot_timestamp_seconds", "Storage snapshot source time in Unix seconds.",
                labels, snapshot["time"])
    docs = {"capacity": _record(snapshot, "capacity", machine_id) if is_fresh else None,
            "io": _record(snapshot, "io", machine_id) if is_fresh else None}
    for source, doc in docs.items():
        state = doc["state"] if doc is not None else "UNKNOWN"
        for name in STATES:
            out.add("storage_inventory_state", "Storage inventory state (one hot); stale snapshots are UNKNOWN.",
                    dict(labels, source=source, state=name), int(state == name))
    for row in _rows(docs["capacity"], "filesystems"):
        _filesystem(out, machine_id, row)
    for row in _rows(docs["io"], "devices"):
        _device(out, machine_id, row)
    return is_fresh
