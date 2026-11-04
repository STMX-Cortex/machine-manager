# SPDX-License-Identifier: Apache-2.0
"""Opt-in macOS storage observation. Read-only, bounded workers; no runtime writes.

Native ABI access is lazy and worker-only; importing this module on Linux loads no ctypes.
"""
import collections
import json
import os
import plistlib
import re
import sys
import time
import uuid
from xml.parsers.expat import ExpatError

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mmstorage as model
import mmstorage_linux as common
import mmtext

TOTAL_TIMEOUT = 5.0
DISCOVERY_TIMEOUT = 1.5
METADATA_TIMEOUT = 0.8
PROBE_TIMEOUT = 0.35
MOUNTS_MAX = 4096
PLIST_BYTES = 2 << 20
NODES_MAX = 16384
DISK = re.compile(r"disk[0-9]{1,6}(?:s[0-9]{1,6}){0,2}")
LOCAL = frozenset("apfs hfs msdos exfat ntfs cd9660 udf zfs ufs".split())
NETWORK = frozenset("nfs smbfs afpfs webdav cifs".split())
PSEUDO = frozenset("autofs devfs fdesc volfs".split())


def category(fs_type):
    for types, name in ((LOCAL, "local"), (NETWORK, "network"), (PSEUDO, "pseudo")):
        if fs_type in types:
            return name
    return "memory" if fs_type in ("tmpfs", "ramfs") else "unknown"


def _uuid(value):
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) and len(value) <= 64 else None
    except ValueError:
        return None


def _disk(value):
    return isinstance(value, str) and DISK.fullmatch(value) is not None


def _safe(value, path=False, limit=model.TEXT_MAX):
    return (model._path(value) if path else model._text(value, limit)) and mmtext.mask(value) == value


def _bounded_tree(doc):
    stack, count = [(doc, 0)], 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > NODES_MAX or depth > 12:
            raise common.Cut("metadata tree limit")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return doc


def _plist(raw):
    # diskutil emits XML; reject entities and binary offset-table expansion before decoding.
    if not isinstance(raw, bytes) or len(raw) > PLIST_BYTES:
        raise common.Cut("metadata byte limit")
    if not raw.lstrip().startswith(b'<?xml') or b'<!ENTITY' in raw.upper():
        raise ValueError("invalid metadata format")
    if raw.count(b'<') > NODES_MAX * 3:
        raise common.Cut("metadata node limit")
    depth = 0
    for tag in re.finditer(rb'<(/?)(dict|array)\b[^>]*>', raw):
        if tag[1]:
            depth -= 1
        elif not tag[0].endswith(b'/>'):
            depth += 1
        if depth > 12 or depth < 0:
            raise common.Cut("metadata depth limit")
    return _bounded_tree(plistlib.loads(raw))


def parse_disks(doc):
    """Sanitize diskutil list -plist; never retain names, labels, sources or mount options."""
    _bounded_tree(doc)
    roots = doc.get("AllDisksAndPartitions")
    if not isinstance(roots, list):
        raise ValueError("missing disk inventory")
    pending, found, duplicates, reason = list(roots), {}, set(), None
    while pending:
        row = pending.pop()
        if not isinstance(row, dict) or not _disk(row.get("DeviceIdentifier")):
            reason = reason or "invalid_data"
            continue
        dev = row["DeviceIdentifier"]
        if dev in found:
            duplicates.add(dev)
        size = row.get("Size")
        if not model._bytes(size):
            size = None
            reason = reason or "invalid_data"
        found[dev] = {"dev": dev, "size_bytes": size, "uuid": _uuid(row.get("DiskUUID")),
                      "volume_uuid": _uuid(row.get("VolumeUUID"))}
        for key in ("Partitions", "APFSVolumes"):
            children = row.get(key, [])
            if not isinstance(children, list):
                reason = reason or "invalid_data"
            else:
                pending.extend(children)
    for dev in duplicates:
        del found[dev]
        reason = reason or "invalid_data"
    values = sorted(found.values(), key=lambda r: tuple(int(n) for n in re.findall(r'\d+', r['dev'])))
    if len(values) > model.RECORDS_MAX:
        reason = "truncated"
    return {"disks": values[:model.RECORDS_MAX], "reason": reason}


def parse_apfs(doc):
    """Proven APFS container membership only; no aggregate capacity and no guessed topology."""
    _bounded_tree(doc)
    containers = doc.get("Containers")
    if not isinstance(containers, list):
        raise ValueError("missing APFS inventory")
    out, refs, reason = {}, set(), None
    if len(containers) > model.RECORDS_MAX:
        reason = "truncated"
    for container in containers[:model.RECORDS_MAX]:
        ref = container.get("ContainerReference")
        if not _disk(ref) or ref in refs:
            raise ValueError("ambiguous APFS container")
        refs.add(ref)
        cuuid = _uuid(container.get("APFSContainerUUID"))
        volumes = container.get("Volumes")
        if not isinstance(volumes, list):
            raise ValueError("invalid APFS volumes")
        for volume in volumes:
            dev = volume.get("DeviceIdentifier")
            if not _disk(dev) or dev in out:
                raise ValueError("ambiguous APFS volume")
            if len(out) >= model.RECORDS_MAX:
                reason = "truncated"
                break
            out[dev] = {"volume_uuid": _uuid(volume.get("APFSVolumeUUID")),
                        "container": ref, "container_uuid": cuuid}
    return {"volumes": out, "reason": reason}


def _native():
    """Darwin statfs64 ABI (xnu bsd/sys/mount.h), for supported 64-bit macOS Python only."""
    if sys.platform != "darwin":
        raise OSError("unsupported platform")
    import ctypes as c
    class StatFS(c.Structure):
        _fields_ = [("bsize", c.c_uint32), ("iosize", c.c_int32),
                    *[(k, c.c_uint64) for k in ("blocks", "bfree", "bavail", "files", "ffree")],
                    ("fsid", c.c_int32 * 2), ("owner", c.c_uint32), ("type", c.c_uint32),
                    ("flags", c.c_uint32), ("subtype", c.c_uint32), ("fstype", c.c_char * 16),
                    ("mount", c.c_char * 1024), ("source", c.c_char * 1024),
                    ("flags_ext", c.c_uint32), ("reserved", c.c_uint32 * 7)]
    if c.sizeof(StatFS) != 2168 or c.sizeof(c.c_void_p) != 8:
        raise ValueError("unsupported statfs ABI")
    libc = c.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.getfsstat64.argtypes = [c.POINTER(StatFS), c.c_int, c.c_int]
    libc.getfsstat64.restype = c.c_int
    libc.fstatfs64.argtypes = [c.c_int, c.POINTER(StatFS)]
    libc.fstatfs64.restype = c.c_int
    libc.sysctlbyname.argtypes = [c.c_char_p, c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p, c.c_size_t]
    libc.sysctlbyname.restype = c.c_int
    return c, libc, StatFS


def _mount(st):
    path = bytes(st.mount).decode("utf-8", "surrogateescape")
    fs_type = bytes(st.fstype).decode("ascii", "strict")
    if len(bytes(st.mount)) >= 1024 or len(bytes(st.fstype)) >= 16 or not _safe(path, True) or not _safe(fs_type, limit=64):
        raise ValueError("invalid mount metadata")
    source = bytes(st.source).decode("utf-8", "surrogateescape")
    dev = source[5:] if source.startswith("/dev/") and _disk(source[5:]) else None
    return {"mount": path, "fs_type": fs_type, "fsid": list(st.fsid), "dev": dev,
            "category": category(fs_type), "read_only": bool(st.flags & 1)}


def mounts():
    """MNT_NOWAIT copies cached mount metadata; it does not refresh unreachable mount capacity."""
    c, libc, cls = _native()
    rows = (cls * (MOUNTS_MAX + 1))()
    count = libc.getfsstat64(rows, c.sizeof(rows), 2)  # MNT_NOWAIT
    if count < 0:
        raise OSError(c.get_errno(), "mount inventory unavailable")
    reason = "truncated" if count > MOUNTS_MAX else None
    result = []
    for st in rows[:min(count, MOUNTS_MAX)]:
        try:
            result.append(_mount(st))
        except (ValueError, UnicodeError):
            reason = reason or "invalid_data"
    if not any(r["mount"] == "/" for r in result):
        raise ValueError("root identity missing")
    boot = c.create_string_buffer(128)
    size = c.c_size_t(len(boot))
    if libc.sysctlbyname(b"kern.bootsessionuuid", boot, c.byref(size), None, 0) != 0:
        raise OSError(c.get_errno(), "boot identity unavailable")
    boot_uuid = _uuid(boot.value.decode("ascii"))
    if not boot_uuid:
        raise ValueError("invalid boot identity")
    return {"boot": boot_uuid, "mounts": result, "reason": reason}


def _key(row):
    return row["fsid"], row["fs_type"], row["dev"]


def probe(path, candidates):
    """Pin a metadata-only descriptor; verify fsid/type/source/mount before and after sampling."""
    c, libc, cls = _native()
    def sample(fd):
        st = cls()
        if libc.fstatfs64(fd, c.byref(st)) != 0:
            raise OSError(c.get_errno(), "filesystem unavailable")
        return st, _mount(st)
    fd = os.open(path, 0x8000 | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)  # O_EVTONLY
    try:
        st, row = sample(fd)
        if row["mount"] != path or not any(_key(row) == _key(r) for r in candidates):
            return {"row": None, "capacity": model.capacity(), "reason": "read_failed"}
        if not st.bsize:
            raise ValueError("invalid block size")
        cap = model.capacity(st.blocks * st.bsize, st.bfree * st.bsize, st.bavail * st.bsize)
        check = os.open(path, 0x8000 | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            _, after = sample(check)
            if after != row:
                return {"row": None, "capacity": model.capacity(), "reason": "read_failed"}
        finally:
            os.close(check)
        return {"row": row, "capacity": cap, "reason": None}
    finally:
        os.close(fd)


def _work(mode, payload, timeout):
    import mmread
    if mode in ("--mounts", "--probe"):
        argv = [sys.executable, "-I", os.path.abspath(__file__), mode]
        if payload is not None:
            argv.append(json.dumps(payload, ensure_ascii=True))
    else:
        if mode == "--info" and not _disk(payload):
            return None, "invalid_data"
        argv = ["/usr/sbin/diskutil", *({"--disks": ["list", "-plist"], "--apfs": ["apfs", "list", "-plist"],
                                          "--info": ["info", "-plist", payload]}[mode])]
    rc, raw, error = mmread.run_bounded(argv, timeout=timeout, max_bytes=PLIST_BYTES)
    if error:
        return None, "timeout" if "timed out" in error else "truncated" if "exceeded" in error else "read_failed"
    if rc != 0:
        return None, "read_failed"
    try:
        doc = common._json(raw) if mode in ("--mounts", "--probe") else _plist(raw)
        if isinstance(doc, dict) and doc.get("error") in model.REASONS:
            return None, doc["error"]
        if mode == "--disks":
            doc = parse_disks(doc)
        elif mode == "--apfs":
            doc = parse_apfs(doc)
        elif mode == "--info":
            # Only safe device identifiers enter this fixed argv; no path, shell or user label.
            if not _disk(payload) or doc.get("DeviceIdentifier") != payload:
                raise ValueError("device info mismatch")
            doc = {"volume_uuid": _uuid(doc.get("VolumeUUID")), "snapshot_uuid": _uuid(doc.get("APFSSnapshotUUID")),
                   "container": doc.get("APFSContainerReference"), "snapshot": doc.get("APFSSnapshot") is True}
            if doc["container"] is not None and not _disk(doc["container"]):
                raise ValueError("invalid container reference")
        return doc, None
    except (ValueError, TypeError, AttributeError, RecursionError, UnicodeError, plistlib.InvalidFileException, ExpatError) as exc:
        return None, common._error(exc)


def collect(machine_id, include=(), exclude=(), timeout_s=TOTAL_TIMEOUT):
    model.select_mounts("local", [], include, exclude)
    if (not _safe(machine_id, limit=120) or type(timeout_s) not in (int, float) or not 0.05 <= timeout_s <= 30):
        raise ValueError("invalid storage collection arguments")
    now, deadline = time.time(), time.monotonic() + timeout_s
    if sys.platform != "darwin":
        return common._envelope(machine_id, now, "unsupported")
    data, error = _work("--mounts", None, min(DISCOVERY_TIMEOUT, timeout_s))
    if error:
        return common._envelope(machine_id, now, error)
    def work(mode, payload=None, limit=METADATA_TIMEOUT):
        remaining = deadline - time.monotonic()
        return (None, "timeout") if remaining <= 0 else _work(mode, payload, min(limit, remaining))
    try:
        return _assemble(machine_id, now, data, include, exclude, work)
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        return common._envelope(machine_id, now, "invalid_data")


def _assemble(machine_id, now, data, include, exclude, work):
    rows = data["mounts"]
    if not isinstance(rows, list) or len(rows) > MOUNTS_MAX or _uuid(data["boot"]) != data["boot"]:
        raise ValueError("invalid mount inventory")
    problem = data["reason"]
    bypath = collections.defaultdict(list)
    for row in rows:
        if not (_safe(row["mount"], True) and _safe(row["fs_type"], limit=64)
                and isinstance(row["fsid"], list) and len(row["fsid"]) == 2
                and all(type(n) is int and -2**31 <= n < 2**31 for n in row["fsid"])
                and (row["dev"] is None or _disk(row["dev"]))
                and row["category"] == category(row["fs_type"]) and type(row["read_only"]) is bool):
            problem = problem or "invalid_data"
            continue
        bypath[row["mount"]].append(row)
    disks, failure = work("--disks")
    problem = problem or failure or (disks or {}).get("reason")
    disks = (disks or {}).get("disks", [])
    apfs, failure = work("--apfs") if any(r["fs_type"] == "apfs" for r in rows) else ({"volumes": {}, "reason": None}, None)
    problem = problem or failure or (apfs or {}).get("reason")
    volumes = (apfs or {}).get("volumes", {})
    nonce = str(uuid.uuid4())  # fallback IDs cannot mistake a recycled diskN/fsid for persistent hardware
    def session(kind, *values):
        return model.storage_id(kind, "session", common._token(data["boot"], "darwin-global", nonce, *values))
    duuids = collections.Counter(d["uuid"] for d in disks if d["uuid"])
    device_map, devices = {}, []
    for disk in disks:
        dev = disk["dev"]
        ident = (model.storage_id("device", "uuid", disk["uuid"]) if disk["uuid"] and duuids[disk["uuid"]] == 1
                 else session("device", dev))
        device_map[dev] = ident
        devices.append({"id": ident, "name": "/dev/" + dev, "kind": "unknown", "size_bytes": disk["size_bytes"]})
    # Count UUID ownership by distinct native objects, not mounted aliases. Clones stay distinct.
    fsuuids = {d["dev"]: d["volume_uuid"] for d in disks if d["volume_uuid"]}
    fsuuids.update({dev: v["volume_uuid"] for dev, v in volumes.items() if v["volume_uuid"]})
    cuuids = collections.defaultdict(set)
    for v in volumes.values():
        if v["container_uuid"]:
            cuuids[v["container_uuid"]].add(v["container"])
    info = {}
    automounts = common._automount_tree(rows)
    wanted = [p for p, candidates in bypath.items()
              if any(model.select_mounts(r["category"], [p], include, exclude) for r in candidates)]
    samples = []
    for path in sorted(wanted, key=lambda p: (p != "/", p)):
        candidates = bypath[path]
        if common._under_automount(automounts, path):
            result, failure = None, "unsupported"
        else:
            result, failure = work("--probe", {"path": path, "candidates": candidates}, PROBE_TIMEOUT)
        row = None
        if result is not None:
            row = result.get("row")
            if row not in candidates:
                problem = problem or "read_failed"
                continue
        elif len(candidates) == 1:
            row = candidates[0]
            problem = problem or failure or "read_failed"
        else:
            problem = problem or failure or "read_failed"
            continue
        if not model.select_mounts(row["category"], [path], include, exclude):
            continue
        samples.append((path, row, result, failure))
    # Probe capacity first: optional diskutil info cannot starve the root capacity sample.
    # Mounted devices with missing UUIDs, and APFS mounts outside `apfs list` membership, may supply
    # snapshot/container facts. Recent `diskutil list` reports a mounted root snapshot with a VolumeUUID
    # but no container, so a known UUID alone does not prove live-volume identity or membership.
    for path, row, _, _ in samples:
        dev = row["dev"]
        if (dev and dev not in info and (dev not in fsuuids or (row["fs_type"] == "apfs" and dev not in volumes))
                and not common._under_automount(automounts, path)):
            value, failure = work("--info", dev, PROBE_TIMEOUT)
            info[dev] = value or {}
            if failure:
                problem = problem or failure
            elif value["volume_uuid"]:
                fsuuids[dev] = value["volume_uuid"]
    counts = collections.Counter(value for dev, value in fsuuids.items()
                                 if not re.fullmatch(r"disk[0-9]+s[0-9]+s[0-9]+", dev)
                                 and not info.get(dev, {}).get("snapshot", False))
    groups = {}
    for path, row, result, failure in samples:
        key = tuple(row["fsid"]), row["fs_type"], row["dev"]
        if key not in groups:
            if len(groups) >= model.RECORDS_MAX:
                problem = "truncated"
                continue
            dev, extra = row["dev"], info.get(row["dev"], {})
            snapshot = bool(dev and re.fullmatch(r"disk[0-9]+s[0-9]+s[0-9]+", dev)) or extra.get("snapshot", False)
            fsuuid = extra.get("snapshot_uuid") if snapshot else fsuuids.get(dev)
            stable = bool(fsuuid and (snapshot or counts[fsuuid] == 1))
            ident = model.storage_id("filesystem", "uuid", fsuuid) if stable else session("filesystem", *key)
            volume = volumes.get(dev)
            if volume is None and extra.get("container"):
                options = [v for v in volumes.values() if v["container"] == extra["container"]]
                volume = options[0] if options else None
            group = None
            if volume:
                cuuid = volume["container_uuid"]
                group = (model.storage_id("capacity", "uuid", cuuid) if cuuid and len(cuuids[cuuid]) == 1
                         else session("capacity", volume["container"]))
            groups[key] = {"id": ident, "fs_type": row["fs_type"], "category": row["category"], "mounts": [],
                           "read_only": row["read_only"], "device_ids": [device_map[dev]] if dev in device_map else [],
                           "capacity_group": group, "capacity": model.capacity(), "capacity_reason": "read_failed"}
        fs = groups[key]
        if len(fs["mounts"]) >= model.MOUNTS_MAX:
            problem = "truncated"
            continue
        fs["mounts"].append(path)
        if fs["read_only"] != row["read_only"]:
            fs["read_only"] = None
        cap, reason = (result["capacity"], result["reason"]) if result else (model.capacity(), failure)
        if fs["capacity_reason"] is not None and (reason is None or len(fs["mounts"]) == 1):
            fs["capacity"], fs["capacity_reason"] = cap, reason
    identities = collections.Counter(f["id"] for f in groups.values())
    for key, fs in groups.items():
        if identities[fs["id"]] > 1:
            fs["id"] = session("filesystem", *key)
            problem = problem or "invalid_data"
    record = common._envelope(machine_id, now)
    record["devices"] = sorted(devices, key=lambda d: d["id"])
    record["filesystems"] = sorted(groups.values(), key=lambda f: f["id"])
    for fs in record["filesystems"]:
        fs["mounts"].sort()
    if problem:
        record.update(state="PARTIAL", reason=problem)
    if not model.valid(record):
        raise ValueError("invalid storage observation")
    return record


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--mounts"]:
            value = mounts()
        elif len(sys.argv) == 3 and sys.argv[1] == "--probe":
            args = common._json(sys.argv[2])
            model.select_mounts("local", [args["path"]])
            if not isinstance(args["candidates"], list) or len(args["candidates"]) > MOUNTS_MAX:
                raise ValueError("invalid probe candidates")
            value = probe(args["path"], args["candidates"])
        else:
            sys.exit(2)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        value = {"error": common._error(exc)}
    print(json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")))
