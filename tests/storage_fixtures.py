# SPDX-License-Identifier: Apache-2.0
"""Valid fleet storage snapshots for tests, built only from the storage contract helpers and vectors/storage_*.

Every record passes mmstorage.valid / mmstorage_io.valid; snapshot() follows the storage.json envelope (contract
section 1: kind, schema_version, machine_id, time = min(capacity.time, io.time), capacity, io).
"""
import json
from pathlib import Path

import mmtest  # noqa: F401 (paths)
import mmstorage
import mmstorage_io

CODE = Path(__file__).resolve().parent.parent
MID = "test-machine"
NOW = 1_800_000_000.0
BOOT = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
TICK = 100_000_000_000


def vector(function, case):
    return json.loads((CODE / "vectors" / function / (case + ".json")).read_text())["input"]


def sid(kind, value):
    return mmstorage.storage_id(kind, "native", value)


DISK = sid("device", "fixture-disk")
GROUP = sid("capacity", "fixture-container")


def filesystem(name, mounts, case="reserved-space", fs_type="ext4", read_only=False, group=None, reason=None,
               category="local", device_ids=()):
    """One filesystem whose capacity comes from vectors/storage_capacity/CASE; missing values get REASON."""
    cap = mmstorage.capacity(**vector("storage_capacity", case))
    if any(v is None for v in cap.values()):
        reason = reason or "unsupported"
    return {"id": sid("filesystem", name), "fs_type": fs_type, "category": category, "mounts": sorted(mounts),
            "read_only": read_only, "device_ids": sorted(device_ids), "capacity_group": group, "capacity": cap,
            "capacity_reason": reason}


def filesystems():
    return [
        filesystem("root", ["/"], device_ids=[DISK]),
        filesystem("data", ["/data", "/Volumes/Data"], fs_type="apfs", read_only=None, group=GROUP),
        filesystem("other", ["/Volumes/Other"], case="full", fs_type="apfs", read_only=True, group=GROUP),
        filesystem("remote", ["/mnt/remote"], case="unknown", fs_type="nfs", category="network"),
        filesystem("partial", ["/srv"], case="partial", reason="read_failed"),
        filesystem("zero", ["/boot/efi"], case="zero", fs_type="vfat"),
        filesystem("large", ["/large"], case="exact-large-integer", fs_type="xfs"),
    ]


def capacity_record(machine_id=MID, time=NOW, rows=None, state="OK", reason=None):
    rows = filesystems() if rows is None else rows
    if state == "UNKNOWN":
        rows = []
    devices = [{"id": DISK, "name": "disk0", "kind": "block", "size_bytes": 1000}] if rows else []
    record = {"schema_version": 1, "machine_id": machine_id, "time": time, "state": state, "reason": reason,
              "devices": devices, "filesystems": sorted(rows, key=lambda f: f["id"])}
    if not mmstorage.valid(record):
        raise ValueError("invalid storage fixture")
    return record


IO_CASES = ("actual-interval", "idle", "reset", "invalid-interval", "first-sample")


def io_record(machine_id=MID, time=NOW, cases=IO_CASES, state="OK", reason=None):
    """Device rates from vectors/storage_io_rates/CASE through mmstorage_io.observation (device name = case)."""
    if state == "UNKNOWN":
        record = mmstorage_io.envelope(machine_id, time, 1, reason or "unsupported")
    else:
        before, after = [], []
        for index, case in enumerate(cases):
            data = vector("storage_io_rates", case)
            end = TICK + int(data["elapsed_s"] * 1e9)
            row = {"key": "8:%d" % (16 * index), "generation": "1", "name": case, "scope": "whole_device",
                   "time": time, "monotonic_ns": end, "counters": mmstorage_io.counters(**data["after"]),
                   "reason": None}
            after.append(row)
            if data["before"] is not None:
                before.append(dict(row, time=time - data["elapsed_s"], monotonic_ns=TICK,
                                   counters=mmstorage_io.counters(**data["before"])))
        source = {"boot": BOOT, "domain": "fixture-v1", "state": "OK", "reason": None}
        record = mmstorage_io.observation(
            machine_id, dict(source, time=time - 1, monotonic_ns=TICK, devices=before),
            dict(source, time=time, monotonic_ns=TICK + 10**9, devices=after), 1)
        if state != "OK":
            record.update(state=state, reason=reason or "timeout")
    if not mmstorage_io.valid(record):
        raise ValueError("invalid storage I/O fixture")
    return record


def snapshot(machine_id=MID, time=NOW, capacity=None, io=None):
    capacity = capacity_record(machine_id, time) if capacity is None else capacity
    io = io_record(machine_id, time) if io is None else io
    return {"kind": "storage_snapshot", "schema_version": 1, "machine_id": machine_id,
            "time": min(capacity["time"], io["time"]), "capacity": capacity, "io": io}


def device_id(name, cases=IO_CASES, machine_id=MID, time=NOW):
    return next(d["id"] for d in io_record(machine_id, time, cases)["devices"] if d["name"] == name)
