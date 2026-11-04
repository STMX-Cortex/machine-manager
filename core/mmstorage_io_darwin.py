# SPDX-License-Identifier: Apache-2.0
"""Worker-only IOKit storage driver counters. No per-APFS-volume traffic attribution."""
import os
import re
import subprocess
import time
import uuid

import mmstorage as storage
import mmstorage_darwin as mac
import mmstorage_io as model

# -l is required: without it ioreg prints properties only for the matched drivers, never the child IOMedia's
# BSD Name/Whole, so no whole-media mapping could be proven on a real host.
IOREG = ['/usr/sbin/ioreg', '-a', '-l', '-r', '-c', 'IOBlockStorageDriver', '-d', '2']
REGISTRY_DEPTH = 32
STAT_KEYS = ('Bytes (Read)', 'Bytes (Write)', 'Operations (Read)', 'Operations (Write)')


def _media(driver):
    pending, names = list(driver.get('IORegistryEntryChildren', [])), set()
    while pending:
        node = pending.pop()
        if not isinstance(node, dict):
            raise ValueError('invalid media metadata')
        if node.get('IOObjectClass') == 'IOBlockStorageDriver':
            continue
        name = node.get('BSD Name')
        if node.get('Whole') is True and isinstance(name, str) and re.fullmatch(r'disk[0-9]{1,6}', name):
            entry = node.get('IORegistryEntryID')
            if type(entry) is int and 0 < entry <= model.MAX_COUNTER:
                names.add((name, entry))
        children = node.get('IORegistryEntryChildren', [])
        if not isinstance(children, list):
            raise ValueError('invalid media children')
        pending.extend(children)
    if len(names) == 1:
        name, entry = next(iter(names))
        return '/dev/' + name, entry
    return 'IOBlockStorageDriver', None


def parse_ioreg(doc):
    """Whitelisted driver counters only. Device serials, user labels and other properties are discarded."""
    mac._bounded_tree(doc, depth_max=REGISTRY_DEPTH)
    if not isinstance(doc, list):
        raise ValueError('invalid registry inventory')
    rows, seen, problem = [], set(), None
    for driver in doc:
        if len(rows) >= storage.RECORDS_MAX:
            problem = 'truncated'
            break
        try:
            entry = driver.get('IORegistryEntryID')
            if type(entry) is not int or not 0 < entry <= model.MAX_COUNTER or entry in seen:
                raise ValueError('invalid registry identity')
            seen.add(entry)
            stats = driver.get('Statistics')
            reason = None
            if not isinstance(stats, dict):
                count, reason = model.counters(), 'unsupported'
            else:
                try:
                    count = model.counters(*(stats.get(k) for k in STAT_KEYS))
                    if any(v is None for v in count.values()):
                        reason = 'unsupported'
                except ValueError:
                    count, reason = model.counters(), 'invalid_data'
            name, media_id = _media(driver)
            generation = mac.common._token(entry, media_id)
            rows.append({'key': str(entry), 'generation': generation, 'name': name,
                         'scope': 'whole_device' if name.startswith('/dev/') else 'driver',
                         'counters': count, 'reason': reason})
        except (ValueError, TypeError, AttributeError) as exc:
            problem = problem or 'invalid_data'
    # Duplicate registry IDs invalidate every claimant; never merge or retain arbitrary counters.
    ids = [str(d.get('IORegistryEntryID')) for d in doc if isinstance(d, dict)]
    from collections import Counter
    duplicates = {i for i, n in Counter(ids).items() if n > 1}
    if duplicates:
        rows = [r for r in rows if r['key'] not in duplicates]
        problem = problem or 'invalid_data'
    rows.sort(key=lambda r: int(r['key']))
    return {'devices': rows, 'reason': problem}


def _boot():
    import ctypes as c
    libc = c.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    fn = libc.sysctlbyname
    fn.argtypes = [c.c_char_p, c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p, c.c_size_t]
    fn.restype = c.c_int
    buf, size = c.create_string_buffer(128), c.c_size_t(128)
    if fn(b'kern.bootsessionuuid', buf, c.byref(size), None, 0) != 0:
        raise OSError(c.get_errno(), 'boot identity unavailable')
    return str(uuid.UUID(buf.value.decode('ascii')))


def _registry():
    # Inherit the outer bounded worker's process group: timeout kills this child too.
    p = subprocess.Popen(IOREG, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        raw = p.stdout.read(mac.PLIST_BYTES + 1)
        if len(raw) > mac.PLIST_BYTES:
            raise mac.common.Cut('registry output limit')
        if p.wait() != 0:
            raise OSError('registry unavailable')
        return mac._plist(raw, depth_max=REGISTRY_DEPTH)
    finally:
        if p.poll() is None:
            p.kill()
        p.stdout.close()
        try:
            p.wait(timeout=.1)
        except subprocess.TimeoutExpired:
            pass  # the outer owned worker deadline still bounds caller latency


def sample():
    boot = _boot()
    start, wall = time.monotonic_ns(), time.time()
    data = parse_ioreg(_registry())
    end = time.monotonic_ns()
    for row in data['devices']:
        row.update(time=wall + (end - start) / 2e9, monotonic_ns=(start + end) // 2)
    return {'boot': boot, 'domain': 'darwin-iokit-v1', 'time': time.time(), 'monotonic_ns': time.monotonic_ns(),
            'state': 'PARTIAL' if data['reason'] else 'OK', 'reason': data['reason'], 'devices': data['devices']}
