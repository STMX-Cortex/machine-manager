# SPDX-License-Identifier: Apache-2.0
"""Worker-only Linux whole-device counters from pinned sysfs directories. No block-device opens."""
import os
import re
import time
import uuid

import mmstorage as storage
import mmstorage_linux as linux
import mmstorage_io as model

ENTRIES_MAX = 1024


def parse_stat(text):
    """Linux block/stat sectors are always 512-byte units, independent of logical block size."""
    if not isinstance(text, str) or len(text) > 4096:
        raise ValueError('invalid block statistics')
    values = text.split()
    if not 11 <= len(values) <= 32 or not all(re.fullmatch(r'[0-9]{1,20}', v) for v in values):
        raise ValueError('invalid block statistics')
    v = [int(x) for x in values]
    if any(n > model.MAX_COUNTER for n in v):
        raise ValueError('invalid block counter')
    return model.counters(v[2] * 512, v[6] * 512, v[0], v[4])


def _read(fd, name, limit=4096):
    child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
    try:
        raw = os.read(child, limit + 1)
        if len(raw) > limit:
            raise linux.Cut('metadata limit')
        return raw.decode('ascii', 'strict').strip()
    finally:
        os.close(child)


def _sequence(fd):
    try:
        value = _read(fd, 'diskseq', 64)
    except FileNotFoundError:
        return None
    if not re.fullmatch(r'[0-9]{1,20}', value) or not 0 < int(value) <= model.MAX_COUNTER:
        raise ValueError('invalid disk sequence')
    return str(int(value))


def _row(root, dev):
    fd = os.open(os.path.join(root, dev), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        props = linux._properties(_read(fd, 'uevent'), '')
        if props.get('DEVTYPE') == 'partition':
            return None  # no duplicate parent/partition traffic
        if props.get('DEVTYPE') != 'disk' or _read(fd, 'dev', 64) != dev:
            raise ValueError('invalid device identity')
        name = '/dev/' + (props.get('DEVNAME') or '')
        if not storage._path(name) or not model._safe(name):
            raise ValueError('invalid device name')
        seq = _sequence(fd)
        start, wall = time.monotonic_ns(), time.time()
        reason = None
        try:
            count = parse_stat(_read(fd, 'stat'))
        except (OSError, ValueError, UnicodeError) as exc:
            count, reason = model.counters(), linux._error(exc)
        end = time.monotonic_ns()
        if _sequence(fd) != seq or linux._properties(_read(fd, 'uevent'), '') != props:
            raise ValueError('device changed')
        check = os.open(os.path.join(root, dev), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            if os.fstat(check).st_ino != os.fstat(fd).st_ino or _sequence(check) != seq:
                raise ValueError('device replaced')
        finally:
            os.close(check)
        return {'key': dev, 'generation': seq, 'name': name, 'scope': 'whole_device',
                'time': wall + (end - start) / 2e9, 'monotonic_ns': (start + end) // 2,
                'counters': count, 'reason': reason}
    finally:
        os.close(fd)


def sample(sysroot='/sys/dev/block'):
    boot = str(uuid.UUID(linux._read('/proc/sys/kernel/random/boot_id', 128).strip()))
    namespace = os.readlink('/proc/self/ns/mnt')
    if not re.fullmatch(r'mnt:\[[0-9]{1,20}\]', namespace):
        raise ValueError('invalid namespace')
    names, problem, rows = [], None, []
    with os.scandir(sysroot) as scan:
        for n, entry in enumerate(scan):
            if n >= ENTRIES_MAX:
                problem = 'truncated'
                break
            if linux._devt(entry.name):
                names.append(entry.name)
    for dev in sorted(names, key=lambda d: tuple(int(x) for x in d.split(':'))):
        if len(rows) >= storage.RECORDS_MAX:
            problem = 'truncated'
            break
        try:
            row = _row(sysroot, dev)
            if row is not None:
                rows.append(row)
        except (OSError, ValueError, UnicodeError) as exc:
            problem = problem or linux._error(exc)
    return {'boot': boot, 'domain': 'linux-sysfs-v1:' + namespace, 'time': time.time(),
            'monotonic_ns': time.monotonic_ns(), 'state': 'PARTIAL' if problem else 'OK',
            'reason': problem, 'devices': rows}
