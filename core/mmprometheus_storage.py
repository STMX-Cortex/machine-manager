# SPDX-License-Identifier: Apache-2.0
"""Prometheus storage families from fleet storage snapshots; pure, no reads, network, commands or writes.

Callers pass (machine_id, snapshot_or_None, fresh) tuples from a validating reader. This renderer stays
defensive anyway: malformed rows are skipped, unknown values are absent (never zero), and a stale or missing
snapshot exports only freshness 0, its source time when known, and UNKNOWN inventory state. Each filesystem
and device is its own series; nothing is summed across filesystems, capacity groups or devices.

Storage text has one byte budget per exposition (STORAGE_TEXT_BYTES), filled in tuple order (local first, then
peers). A machine whose filesystem/device series would exceed it exports none of them (never part of a machine)
and reports storage_export_complete 0; freshness, time and inventory state series are always exported.
"""
import math

ROWS_MAX = 128  # mmstorage.RECORDS_MAX: devices and filesystems, independently
STORAGE_TEXT_BYTES = 8 << 20  # half of mm serve's 16 MiB response cap; the rest stays for legacy families
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


class Budget:
    """Encoded storage exposition bytes (sample lines plus new family headers) shared by all machines."""
    def __init__(self, limit=None):
        self.limit = STORAGE_TEXT_BYTES if limit is None else limit
        self.used = 0


class _Pending:
    """Collects one machine's measurement samples so their size is known before any is exported."""
    def __init__(self, out):
        self.out, self.samples = out, []

    def add(self, name, help_text, labels, value):
        sample = self.out.sample(name, labels, value)
        if sample is not None:
            self.samples.append((help_text, sample))


def _size(out, help_text, key, line, families):
    size = len(line.encode("utf-8")) + 1
    if key[0] not in out.families and key[0] not in families:
        families.add(key[0])
        size += len(out.header(key[0], help_text).encode("utf-8"))
    return size


def _put(out, budget, name, help_text, labels, value, counted=True):
    sample = out.sample(name, labels, value)
    if sample is not None:
        size = _size(out, help_text, *sample, set())
        if out.put(help_text, sample) and counted:
            budget.used += size


COMPLETE = ("storage_export_complete",
            "Whether every filesystem and device series of a fresh snapshot fit the storage byte budget (1/0).")


def _state(out, budget, machine_id, snapshot, fresh):
    """Freshness, time and inventory state (always exported); returns the fresh sub-records or None."""
    labels = {"machine_id": machine_id}
    if not isinstance(snapshot, dict) or snapshot.get("machine_id") != machine_id:
        snapshot = None
    is_fresh = fresh is True and snapshot is not None
    _put(out, budget, "storage_snapshot_fresh", "Whether the storage snapshot is valid and fresh.", labels,
         int(is_fresh))
    if snapshot is not None and _number(snapshot.get("time")):
        _put(out, budget, "storage_snapshot_timestamp_seconds", "Storage snapshot source time in Unix seconds.",
             labels, snapshot["time"])
    docs = {"capacity": _record(snapshot, "capacity", machine_id) if is_fresh else None,
            "io": _record(snapshot, "io", machine_id) if is_fresh else None}
    for source, doc in docs.items():
        state = doc["state"] if doc is not None else "UNKNOWN"
        for name in STATES:
            _put(out, budget, "storage_inventory_state",
                 "Storage inventory state (one hot); stale snapshots are UNKNOWN.",
                 dict(labels, source=source, state=name), int(state == name))
    if not is_fresh:
        return None
    key, line = out.sample(COMPLETE[0], labels, 0)
    if key not in out.seen:
        budget.used += _size(out, COMPLETE[1], key, line, set())  # reserved now, exported after measurement
    return docs


def _measure(out, budget, machine_id, docs):
    """All of one fresh machine's filesystem/device series if they fit the remaining budget, else none."""
    pending = _Pending(out)
    for row in _rows(docs["capacity"], "filesystems"):
        _filesystem(pending, machine_id, row)
    for row in _rows(docs["io"], "devices"):
        _device(pending, machine_id, row)
    keys, families, size = set(), set(), 0
    for help_text, (key, line) in pending.samples:
        if key not in out.seen and key not in keys:
            keys.add(key)
            size += _size(out, help_text, key, line, families)
    complete = size == 0 or budget.used + size <= budget.limit
    if complete:
        for help_text, sample in pending.samples:
            out.put(help_text, sample)
        budget.used += size
    _put(out, budget, *COMPLETE, {"machine_id": machine_id}, int(complete), counted=False)
    return complete


def add(out, machine_id, snapshot, fresh, budget=None):
    """Add one machine's storage series to an mmprometheus.Metrics; returns whether measurements were exported."""
    budget = Budget() if budget is None else budget
    docs = _state(out, budget, machine_id, snapshot, fresh)
    return docs is not None and _measure(out, budget, machine_id, docs)


def add_all(out, storage, budget=None):
    """Section-5 tuples in order: every machine's state series first, then measurements while the budget lasts."""
    budget = Budget() if budget is None else budget
    states = [(machine_id, _state(out, budget, machine_id, snapshot, fresh)) for machine_id, snapshot, fresh in storage]
    for machine_id, docs in states:
        if docs is not None:
            _measure(out, budget, machine_id, docs)
    return budget
