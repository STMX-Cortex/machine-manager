# SPDX-License-Identifier: Apache-2.0
"""Opt-in Linux storage observation. No raw-device reads, mounts, runtime writes or control.

All /proc, /sys, udev and mount access runs in bounded owned workers. The supervisor does not call this collector.
"""
import collections
import errno
import json
import os
import re
import sys
import time
import uuid

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mmstorage as model
import mmtext

MOUNT_BYTES = 1 << 20
MOUNT_LINES = 4096
LINE_BYTES = 32768
SYS_ENTRIES = 1024
WORK_BYTES = 2 << 20
TOTAL_TIMEOUT = 5.0
DISCOVERY_TIMEOUT = 1.5
PROBE_TIMEOUT = 0.35
LOCAL = frozenset("ext2 ext3 ext4 xfs btrfs f2fs vfat msdos exfat ntfs ntfs3 hfs hfsplus ufs jfs reiserfs reiser4 nilfs2 squashfs iso9660 udf bcachefs zfs".split())
NETWORK = frozenset("nfs nfs4 cifs smb3 smbfs 9p ceph afs coda ncpfs glusterfs lustre fuse.sshfs fuse.glusterfs fuse.ceph".split())
MEMORY = frozenset("tmpfs ramfs hugetlbfs".split())
PSEUDO = frozenset("proc sysfs devtmpfs devpts cgroup cgroup2 securityfs tracefs debugfs pstore configfs fusectl mqueue rpc_pipefs binfmt_misc autofs bpf nsfs efivarfs selinuxfs smackfs resctrl nfsd functionfs".split())
DEVT = re.compile(r"[0-9]{1,10}:[0-9]{1,10}")


class Cut(ValueError):
    pass


def category(fs_type):
    if fs_type == "overlay":
        return "overlay"
    for values, name in ((LOCAL, "local"), (NETWORK, "network"), (MEMORY, "memory"), (PSEUDO, "pseudo")):
        if fs_type in values:
            return name
    return "unknown"


def _devt(value):
    return (isinstance(value, str) and DEVT.fullmatch(value) is not None
            and all(int(v) <= 2**32 - 1 for v in value.split(":")))


def _word(value):
    if re.search(r"\\(?!040|011|012|134)", value):
        raise ValueError("invalid mount escape")
    return re.sub(r"\\(040|011|012|134)", lambda m: chr(int(m[1], 8)), value)


def parse_mountinfo(text):
    """Bounded pure parser. Keep kernel mount IDs; never return sources, options or credentials."""
    if not isinstance(text, str) or len(text.encode("utf-8", "surrogateescape")) > MOUNT_BYTES:
        raise Cut("mount table too large")
    rows, seen, bad, reason = [], set(), set(), None
    for n, line in enumerate(text.split("\n")):
        if n >= MOUNT_LINES:
            reason = "truncated"
            break
        if not line:
            continue
        try:
            if len(line.encode("utf-8", "surrogateescape")) > LINE_BYTES:
                raise Cut("mount line too large")
            left, sep, right = line.partition(" - ")
            a, b = left.split(), right.split()
            if not sep or len(a) < 6 or len(b) != 3 or not _devt(a[2]):
                raise ValueError("invalid mount row")
            if not all(re.fullmatch(r"[0-9]{1,19}", v) for v in a[:2]):
                raise ValueError("invalid mount identity")
            mid, parent = int(a[0]), int(a[1])
            if not 0 < mid <= model.BYTES_MAX or parent > model.BYTES_MAX or mid == parent:
                raise ValueError("invalid mount identity")
            mount, fs_type = _word(a[4]), b[0]
            if not model._path(mount) or not model._text(fs_type, 64):
                raise ValueError("invalid mount name")
            flags, superflags = set(a[5].split(",")), set(b[2].split(","))
            if len(flags & {"ro", "rw"}) != 1 or len(superflags & {"ro", "rw"}) != 1:
                raise ValueError("invalid mount flags")
            if mid in seen:
                bad.add(mid)
                raise ValueError("duplicate mount identity")
            seen.add(mid)
            rows.append({"mount_id": mid, "parent_id": parent, "dev": ":".join(str(int(x)) for x in a[2].split(":")),
                         "mount": mount, "fs_type": fs_type, "category": category(fs_type),
                         "read_only": "ro" in flags or "ro" in superflags})
        except Cut:
            reason = "truncated"
        except ValueError:
            if reason != "truncated":
                reason = "invalid_data"
    return {"mounts": [r for r in rows if r["mount_id"] not in bad], "reason": reason}


def _read(path, limit=16384):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        chunks, size = [], 0
        while size <= limit:
            part = os.read(fd, min(65536, limit + 1 - size))
            if not part:
                break
            chunks.append(part)
            size += len(part)
        if size > limit:
            raise Cut("metadata too large")
        return b"".join(chunks).decode("utf-8", "surrogateescape")
    finally:
        os.close(fd)


def _optional(path, limit=16384):
    try:
        return _read(path, limit).strip()
    except (OSError, ValueError):
        return None


def _properties(text, prefix):
    out = {}
    for line in (text or "").split("\n"):
        if not line.startswith(prefix):
            continue
        key, sep, value = line[len(prefix):].partition("=")
        if sep and model._text(value):
            out[key] = value if key not in out else None
    return out


def _token(*values):
    return json.dumps(values, ensure_ascii=True, separators=(",", ":"))


def _uuid_identity(value):
    try:
        return "uuid", str(uuid.UUID(value))
    except (ValueError, AttributeError):
        return "native", "linux-fs-uuid:" + value.lower()


def _device_identity(row, boot, namespace):
    part_uuid, wwn = row.get("part_uuid"), row.get("wwn")
    if row["partition"] and part_uuid:
        try:
            return model.storage_id("device", "uuid", part_uuid)
        except ValueError:
            pass
    if wwn:
        if not row["partition"]:
            return model.storage_id("device", "wwn", wwn)
        if row.get("start") is not None:
            return model.storage_id("device", "native", _token("linux-partition", wwn, row["start"]))
    return model.storage_id("device", "session", _token(boot, namespace, row["dev"], row.get("diskseq")))


def _disks(boot, namespace, sysroot="/sys/dev/block", udev="/run/udev/data"):
    entries, reason = [], None
    with os.scandir(sysroot) as scan:
        for n, entry in enumerate(scan):
            if n >= SYS_ENTRIES:
                reason = "truncated"
                break
            if _devt(entry.name):
                entries.append(entry.name)
    entries.sort(key=lambda d: tuple(int(x) for x in d.split(":")))
    if len(entries) > model.RECORDS_MAX:
        reason = "truncated"
    rows = []
    for dev in entries[:model.RECORDS_MAX]:
        root = os.path.join(sysroot, dev)
        attrs = _properties(_optional(os.path.join(root, "uevent")), "")
        props = _properties(_optional(os.path.join(udev, "b" + dev)), "E:")
        name = attrs.get("DEVNAME")
        if not name or not model._path("/dev/" + name) or mmtext.mask("/dev/" + name) != "/dev/" + name:
            reason = reason or "invalid_data"
            continue
        size = _optional(os.path.join(root, "size"))
        size = int(size) * 512 if size and re.fullmatch(r"[0-9]{1,19}", size) else None
        if not model._bytes(size):
            size = None
        if size is None:
            reason = reason or "read_failed"
        partition = attrs.get("DEVTYPE") == "partition" or _optional(os.path.join(root, "partition")) is not None
        wwn = props.get("ID_WWN_WITH_EXTENSION") or props.get("ID_WWN")
        wwn = wwn or _optional(os.path.join(root, "wwid"), 1024) or _optional(os.path.join(root, "device", "wwid"), 1024)
        wwn = wwn.lower() if wwn and model._text(wwn, 512) else None
        start = _optional(os.path.join(root, "start"), 64)
        start = int(start) if start and re.fullmatch(r"[0-9]{1,19}", start) else None
        diskseq = _optional(os.path.join(root, "diskseq"), 64)
        if partition and diskseq is None:
            diskseq = _optional(os.path.join(root, "..", "diskseq"), 64)
        fs_uuid = props.get("ID_FS_UUID")
        fs_uuid = fs_uuid if fs_uuid and re.fullmatch(r"[0-9A-Fa-f-]{1,128}", fs_uuid) else None
        row = {"dev": dev, "name": "/dev/" + name, "kind": "block", "size_bytes": size,
               "partition": partition, "part_uuid": props.get("ID_PART_ENTRY_UUID"), "wwn": wwn,
               "fs_uuid": fs_uuid, "start": start, "diskseq": diskseq}
        try:
            if "/virtual/" in os.path.realpath(root):
                row["kind"] = "virtual"
            row["id"] = _device_identity(row, boot, namespace)
        except ValueError:
            row["id"] = model.storage_id("device", "session", _token(boot, namespace, dev, diskseq))
        rows.append(row)
    counts = collections.Counter(r["id"] for r in rows)
    for row in rows:
        if counts[row["id"]] > 1:  # cloned WWNs/PARTUUIDs must not merge native objects
            row["id"] = model.storage_id("device", "session", _token(boot, namespace, row["dev"], row["diskseq"]))
    return rows, reason


def discover():
    """Worker-only metadata scan; never opens mount paths or block devices."""
    boot = str(uuid.UUID(_read("/proc/sys/kernel/random/boot_id", 128).strip()))
    namespace = os.readlink("/proc/self/ns/mnt")
    if not re.fullmatch(r"mnt:\[[0-9]{1,20}\]", namespace):
        raise ValueError("invalid mount namespace")
    parsed = parse_mountinfo(_read("/proc/self/mountinfo", MOUNT_BYTES))
    if not any(r["mount"] == "/" for r in parsed["mounts"]):
        raise ValueError("root mount unavailable")
    try:
        disks, reason = _disks(boot, namespace)
    except OSError as exc:
        disks, reason = [], _error(exc)
    return {"boot": boot, "namespace": namespace, "mounts": parsed["mounts"], "disks": disks,
            "reason": parsed["reason"] or reason}


def _error(exc):
    if isinstance(exc, Cut):
        return "truncated"
    if isinstance(exc, PermissionError):
        return "permission_denied"
    if isinstance(exc, OSError):
        return "unsupported" if exc.errno in (errno.ENOSYS, errno.ENOTSUP) else "read_failed"
    return "invalid_data"


def _mount_id(fd):
    text = _read("/proc/self/fdinfo/" + str(fd), 4096)
    for line in text.split("\n"):
        if re.fullmatch(r"mnt_id:\s+[0-9]{1,19}", line):
            return int(line.split()[1])
    raise ValueError("mount identity unavailable")


def probe(path, mount_ids):
    """Worker-only: pin an O_PATH descriptor, identify its mount, read capacity, recheck the path."""
    result = {"mount_id": None, "dev": None, "capacity": model.capacity(), "reason": "read_failed"}
    fd = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        result["mount_id"] = _mount_id(fd)
        st = os.fstat(fd)
        result["dev"] = "%s:%s" % (os.major(st.st_dev), os.minor(st.st_dev))
        if result["mount_id"] not in mount_ids:
            return dict(result, reason="unsupported")  # identity only: never sample an unselected overmount
        try:
            v = os.fstatvfs(fd)
            if type(v.f_frsize) is not int or v.f_frsize <= 0:
                raise ValueError("invalid filesystem block size")
            cap = model.capacity(v.f_blocks * v.f_frsize, v.f_bfree * v.f_frsize, v.f_bavail * v.f_frsize)
            check = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                if _mount_id(check) != result["mount_id"]:
                    return dict(result, mount_id=None)
            finally:
                os.close(check)
            result.update(capacity=cap, reason=None)
        except (OSError, ValueError) as exc:
            result["reason"] = _error(exc)
        return result
    finally:
        os.close(fd)


def _json(raw):
    def pairs(items):
        obj = {}
        for k, v in items:
            if k in obj:
                raise ValueError("duplicate key")
            obj[k] = v
        return obj
    def constant(value):
        raise ValueError("nonfinite JSON")
    doc = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    stack = [(doc, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth >= 8:
                raise ValueError("deep worker JSON")
            stack.extend((v, depth + 1) for v in (node.values() if isinstance(node, dict) else node))
    return doc


def _work(mode, payload, timeout):
    import mmread
    argv = [sys.executable, "-I", os.path.abspath(__file__), mode]
    if payload is not None:
        argv.append(json.dumps(payload, ensure_ascii=True))
    rc, raw, error = mmread.run_bounded(argv, timeout=timeout, max_bytes=WORK_BYTES if mode == "--discover" else 4096)
    if error:
        return None, "timeout" if "timed out" in error else "truncated" if "exceeded" in error else "read_failed"
    if rc != 0:
        return None, "read_failed"
    try:
        doc = _json(raw)
        if isinstance(doc, dict) and doc.get("error") in model.REASONS:
            return None, doc["error"]
        if mode == "--probe" and not _valid_probe(doc):
            return None, "invalid_data"
        return doc, None
    except (ValueError, RecursionError, UnicodeError):
        return None, "invalid_data"


def _valid_probe(doc):
    if not isinstance(doc, dict) or set(doc) != {"mount_id", "dev", "capacity", "reason"}:
        return False
    mid = doc["mount_id"]
    if mid is not None and (type(mid) is not int or not 0 < mid <= model.BYTES_MAX or not _devt(doc["dev"])):
        return False
    if mid is None and doc["reason"] is None:
        return False
    cap = doc["capacity"]
    if not isinstance(cap, dict) or set(cap) != model.CAPACITY_KEYS or not all(model._bytes(v) for v in cap.values()):
        return False
    expected = model.capacity(cap["total_bytes"], cap["free_bytes"], cap["available_bytes"])
    return cap == expected and (doc["reason"] in model.REASONS if any(v is None for v in cap.values()) else doc["reason"] is None)


def _automount_tree(rows):
    tree = {}
    for row in rows:
        if row["fs_type"] != "autofs":
            continue
        node = tree
        for part in row["mount"].strip("/").split("/") if row["mount"] != "/" else ():
            node = node.setdefault(part, {})
        node[None] = True
    return tree


def _under_automount(tree, path):
    node = tree
    for part in path.strip("/").split("/") if path != "/" else ():
        if None in node:
            return True
        if part not in node:
            return False
        node = node[part]
    return None in node


def _envelope(machine_id, now, reason=None):
    return {"schema_version": 1, "machine_id": machine_id, "time": now,
            "state": "UNKNOWN" if reason else "OK", "reason": reason, "devices": [], "filesystems": []}


def collect(machine_id, include=(), exclude=(), timeout_s=TOTAL_TIMEOUT):
    """One bounded foreground observation, with no cache writes. Non-Linux returns UNKNOWN/unsupported."""
    model.select_mounts("local", [], include, exclude)  # validate policy before any worker
    if (not model._text(machine_id, 120) or mmtext.mask(machine_id) != machine_id
            or type(timeout_s) not in (int, float) or not 0.05 <= timeout_s <= 30):
        raise ValueError("invalid storage collection arguments")
    now, deadline = time.time(), time.monotonic() + timeout_s
    if sys.platform != "linux":
        return _envelope(machine_id, now, "unsupported")
    data, error = _work("--discover", None, min(DISCOVERY_TIMEOUT, timeout_s))
    if error:
        return _envelope(machine_id, now, error)
    try:
        return _assemble(machine_id, now, data, include, exclude, deadline)
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        return _envelope(machine_id, now, "invalid_data")


def _assemble(machine_id, now, data, include, exclude, deadline):
    # Worker output is internal, but final records still pass the full shared validator before leaving this module.
    rows, disks = data["mounts"], data["disks"]
    if not isinstance(rows, list) or len(rows) > MOUNT_LINES or not isinstance(disks, list) or len(disks) > model.RECORDS_MAX:
        raise ValueError("invalid discovery output")
    if str(uuid.UUID(data["boot"])) != data["boot"] or not re.fullmatch(r"mnt:\[[0-9]{1,20}\]", data["namespace"]):
        raise ValueError("invalid discovery identity")
    rec, bypath, groups = _envelope(machine_id, now), {}, {}
    problem = data["reason"]
    safe_rows = [r for r in rows if model._path(r["mount"]) and mmtext.mask(r["mount"]) == r["mount"]
                 and model._text(r["fs_type"], 64) and mmtext.mask(r["fs_type"]) == r["fs_type"]]
    safe_disks = [d for d in disks if model._text(d["name"]) and mmtext.mask(d["name"]) == d["name"]]
    if len(safe_rows) != len(rows) or len(safe_disks) != len(disks):
        problem = problem or "invalid_data"
    rows, disks = safe_rows, safe_disks
    diskmap = {d["dev"]: d for d in disks}
    uuids = collections.Counter(_uuid_identity(d["fs_uuid"]) for d in disks if d["fs_uuid"])
    byid, first = {}, {}
    for row in rows:
        bypath.setdefault(row["mount"], []).append(row)
        byid[row["mount_id"]] = row
        key = row["dev"], row["fs_type"]
        first[key] = min(first.get(key, row["mount_id"]), row["mount_id"])
    wanted = [p for p, values in bypath.items() if any(model.select_mounts(r["category"], [p], include, exclude) for r in values)]
    automounts = _automount_tree(rows)
    for path in sorted(wanted, key=lambda p: (p != "/", p)):
        candidates = bypath[path]
        remaining = deadline - time.monotonic()
        if _under_automount(automounts, path):
            result, failure = None, "unsupported"  # never wake an automount, including explicit selection
        else:
            payload = {"path": path, "mount_ids": [r["mount_id"] for r in candidates
                       if model.select_mounts(r["category"], [path], include, exclude)]}
            result, failure = (None, "timeout") if remaining <= 0 else _work("--probe", payload, min(PROBE_TIMEOUT, remaining))
        row = None
        if result and result.get("mount_id") is not None:
            row = next((r for r in candidates if r["mount_id"] == result["mount_id"] and r["dev"] == result["dev"]), None)
            if row is None:
                # A hidden child/overmount cannot supply another filesystem's capacity.
                actual = byid.get(result["mount_id"])
                if not actual or actual["dev"] != result["dev"] or not path.startswith(actual["mount"].rstrip("/") + "/"):
                    problem = problem or "read_failed"
                continue
        elif len(candidates) == 1:
            row = candidates[0]
            problem = problem or failure or (result or {}).get("reason") or "read_failed"
        else:
            problem = problem or failure or "read_failed"
            continue
        if not model.select_mounts(row["category"], [path], include, exclude):
            continue
        key = (row["dev"], row["fs_type"])
        if key not in groups:
            if len(groups) >= model.RECORDS_MAX:
                problem = "truncated"
                continue
            disk = diskmap.get(row["dev"])
            fs_uuid = disk.get("fs_uuid") if disk else None
            basis, value = _uuid_identity(fs_uuid) if fs_uuid and uuids[_uuid_identity(fs_uuid)] == 1 else (
                "session", _token(data["boot"], data["namespace"], row["dev"], row["fs_type"],
                                  first[key],
                                  disk.get("diskseq") if disk else None))
            groups[key] = {"id": model.storage_id("filesystem", basis, value), "fs_type": row["fs_type"],
                           "category": row["category"], "mounts": [], "read_only": row["read_only"],
                           "device_ids": [disk["id"]] if disk else [], "capacity_group": None,
                           "capacity": model.capacity(), "capacity_reason": "read_failed"}
        fs = groups[key]
        if len(fs["mounts"]) >= model.MOUNTS_MAX:
            problem = "truncated"
            continue
        fs["mounts"].append(path)
        if fs["read_only"] != row["read_only"]:
            fs["read_only"] = None
        cap, reason = (result["capacity"], result["reason"]) if result and row["mount_id"] == result.get("mount_id") else (model.capacity(), failure or "read_failed")
        # Free space can change between aliases. Keep the first successful sample, not a sum or an average.
        if fs["capacity_reason"] is not None and (reason is None or len(fs["mounts"]) == 1):
            fs["capacity"], fs["capacity_reason"] = cap, reason
    rec["devices"] = sorted(({k: d[k] for k in ("id", "name", "kind", "size_bytes")} for d in disks), key=lambda d: d["id"])
    rec["filesystems"] = sorted(groups.values(), key=lambda f: f["id"])
    for fs in rec["filesystems"]:
        fs["mounts"].sort()
    if problem:
        rec.update(state="PARTIAL", reason=problem)
    if not model.valid(rec):
        raise ValueError("invalid storage observation")
    return rec


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--discover"]:
            value = discover()
        elif len(sys.argv) == 3 and sys.argv[1] == "--probe":
            args = _json(sys.argv[2])
            model.select_mounts("local", [args["path"]])
            mids = args["mount_ids"]
            if not isinstance(mids, list) or not 0 < len(mids) <= MOUNT_LINES or not all(type(i) is int and 0 < i <= model.BYTES_MAX for i in mids):
                raise ValueError("invalid probe identities")
            value = probe(args["path"], mids)
        else:
            sys.exit(2)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        value = {"error": _error(exc)}
    print(json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")))
