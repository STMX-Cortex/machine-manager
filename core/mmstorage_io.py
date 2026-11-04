# SPDX-License-Identifier: Apache-2.0
"""Pure device I/O contract and rate arithmetic. No discovery, commands, cache or control."""
import math
import uuid

import mmstorage as storage
import mmstorage_linux as common
import mmtext

MAX_COUNTER = 2**64 - 1
COUNTERS = ('read_bytes', 'write_bytes', 'read_ops', 'write_ops')
RATE_KEYS = ('read_bytes_per_s', 'write_bytes_per_s', 'read_ops_per_s', 'write_ops_per_s')
RATE_REASONS = (*storage.REASONS, 'baseline_missing', 'counter_reset', 'identity_changed', 'interval_invalid')
SCOPES = ('whole_device', 'driver')


def _number(value, low=0, high=2**53 - 1):
    return type(value) in (int, float) and low <= value <= high and math.isfinite(value)


def counters(read_bytes=None, write_bytes=None, read_ops=None, write_ops=None):
    values = read_bytes, write_bytes, read_ops, write_ops
    if not all(v is None or type(v) is int and 0 <= v <= MAX_COUNTER for v in values):
        raise ValueError('invalid I/O counters')
    return dict(zip(COUNTERS, values))


def _counters(value):
    return (isinstance(value, dict) and set(value) == set(COUNTERS)
            and all(v is None or type(v) is int and 0 <= v <= MAX_COUNTER for v in value.values()))


def rates(before, after, elapsed_s):
    """All rates unavailable on any reset/missing counter. Idle zero is a valid rate."""
    result = {'rates': dict.fromkeys(RATE_KEYS), 'reason': None}
    if not _number(elapsed_s, .001, 60):
        return dict(result, reason='interval_invalid')
    if not _counters(after) or before is not None and not _counters(before):
        raise ValueError('invalid I/O rate counters')
    if before is None:
        return dict(result, reason='baseline_missing')
    if any(before[k] is None or after[k] is None for k in COUNTERS):
        return dict(result, reason='read_failed')
    if any(after[k] < before[k] for k in COUNTERS):
        return dict(result, reason='counter_reset')
    return {'rates': {r: (after[k] - before[k]) / elapsed_s for k, r in zip(COUNTERS, RATE_KEYS)}, 'reason': None}


def _safe(value, limit=1024):
    return storage._text(value, limit) and mmtext.mask(value) == value


def snapshot_valid(doc):
    if not isinstance(doc, dict) or set(doc) != {'boot', 'domain', 'time', 'monotonic_ns', 'state', 'reason', 'devices'}:
        return False
    try:
        if str(uuid.UUID(doc['boot'])) != doc['boot']:
            return False
    except (TypeError, ValueError, AttributeError):
        return False
    if (not _safe(doc['domain']) or not _number(doc['time'])
            or type(doc['monotonic_ns']) is not int or not 0 <= doc['monotonic_ns'] <= 2**63 - 1
            or doc['state'] not in ('OK', 'PARTIAL')
            or (doc['reason'] is not None if doc['state'] == 'OK' else doc['reason'] not in storage.REASONS)
            or not isinstance(doc['devices'], list) or len(doc['devices']) > storage.RECORDS_MAX):
        return False
    keys = set()
    for d in doc['devices']:
        if not isinstance(d, dict) or set(d) != {'key', 'generation', 'name', 'scope', 'time', 'monotonic_ns', 'counters', 'reason'}:
            return False
        if (not _safe(d['key'], 256) or not _safe(d['name']) or d['scope'] not in SCOPES
                or d['generation'] is not None and not _safe(d['generation'], 256)
                or not _number(d['time']) or type(d['monotonic_ns']) is not int
                or not 0 <= d['monotonic_ns'] <= 2**63 - 1 or not _counters(d['counters'])):
            return False
        missing = any(v is None for v in d['counters'].values())
        if (d['reason'] not in storage.REASONS if missing else d['reason'] is not None):
            return False
        key = d['key'], d['scope']
        if key in keys:
            return False
        keys.add(key)
        try:
            _id(doc, d)  # reject an identity encoding that exceeds the shared input bound
        except ValueError:
            return False
    return True


def _id(snapshot, row):
    # Unknown generation has no continuity claim; namespace sample time disambiguates it.
    value = common._token(snapshot['boot'], snapshot['domain'], row['scope'], row['key'],
                          row['generation'], snapshot['monotonic_ns'] if row['generation'] is None else None)
    return storage.storage_id('device', 'session', value)


def envelope(machine_id, now, interval_s, reason=None):
    return {'schema_version': 1, 'kind': 'storage_io', 'machine_id': machine_id, 'time': now,
            'state': 'UNKNOWN' if reason else 'OK', 'reason': reason, 'requested_interval_s': interval_s,
            'devices': [], 'removed_ids': []}


def observation(machine_id, before, after, requested_interval_s, baseline_error=None):
    """Pair source samples by boot/domain/native generation, never by display name alone."""
    if (not _safe(machine_id, 120) or not _number(requested_interval_s, .1, 30)
            or not snapshot_valid(after) or before is not None and not snapshot_valid(before)
            or baseline_error is not None and baseline_error not in storage.REASONS):
        raise ValueError('invalid I/O observation inputs')
    record = envelope(machine_id, after['time'], requested_interval_s)
    previous = {_id(before, d): d for d in before['devices']} if before else {}
    names = {d['name'] for d in before['devices']} if before else set()
    current_ids = set()
    for row in after['devices']:
        ident = _id(after, row)
        current_ids.add(ident)
        old = previous.get(ident)
        elapsed = (row['monotonic_ns'] - old['monotonic_ns']) / 1e9 if old else None
        interval = elapsed if _number(elapsed, .001, 60) else None
        reason = row['reason']
        result = {'rates': dict.fromkeys(RATE_KEYS), 'reason': reason}
        if reason is None:
            if row['generation'] is None:
                result['reason'] = 'unsupported'
            elif old is None:
                result['reason'] = 'identity_changed' if row['name'] in names else 'baseline_missing'
            elif old['reason'] is not None:
                result['reason'] = 'baseline_missing'
            else:
                result = rates(old['counters'], row['counters'], elapsed)
        record['devices'].append({'id': ident, 'name': row['name'], 'scope': row['scope'], 'time': row['time'],
                                  'counters': row['counters'], 'counter_reason': reason, 'interval_s': interval,
                                  'rates': result['rates'], 'rate_reason': result['reason']})
    if before and after['state'] == 'OK':
        uncertain = {(r['key'], r['scope']) for r in after['devices'] if r['generation'] is None}
        record['removed_ids'] = sorted(ident for ident, r in previous.items()
                                       if ident not in current_ids and r['generation'] is not None
                                       and (r['key'], r['scope']) not in uncertain)
    problem = after['reason'] or baseline_error or (before['reason'] if before else None)
    if problem:
        record.update(state='PARTIAL', reason=problem)
    record['devices'].sort(key=lambda d: d['id'])
    if not valid(record):
        raise ValueError('invalid I/O observation')
    return record


def valid(record):
    if not isinstance(record, dict) or set(record) != {'schema_version', 'kind', 'machine_id', 'time', 'state', 'reason',
                                                       'requested_interval_s', 'devices', 'removed_ids'}:
        return False
    if (type(record['schema_version']) is not int or record['schema_version'] != 1 or record['kind'] != 'storage_io'
            or not _safe(record['machine_id'], 120) or not _number(record['time'])
            or not _number(record['requested_interval_s'], .1, 30) or record['state'] not in ('OK', 'PARTIAL', 'UNKNOWN')
            or (record['reason'] is not None if record['state'] == 'OK' else record['reason'] not in storage.REASONS)):
        return False
    devices, removed = record['devices'], record['removed_ids']
    if not all(isinstance(v, list) and len(v) <= storage.RECORDS_MAX for v in (devices, removed)):
        return False
    if record['state'] == 'UNKNOWN' and (devices or removed):
        return False
    ids = []
    for d in devices:
        if not isinstance(d, dict) or set(d) != {'id', 'name', 'scope', 'time', 'counters', 'counter_reason', 'interval_s', 'rates', 'rate_reason'}:
            return False
        if (not storage._ident(d['id'], 'device') or not _safe(d['name']) or d['scope'] not in SCOPES
                or not _number(d['time']) or not _counters(d['counters'])):
            return False
        missing = any(v is None for v in d['counters'].values())
        if (d['counter_reason'] not in storage.REASONS if missing else d['counter_reason'] is not None):
            return False
        if d['interval_s'] is not None and not _number(d['interval_s'], .001, 60):
            return False
        rv = d['rates']
        if not isinstance(rv, dict) or set(rv) != set(RATE_KEYS):
            return False
        if all(v is None for v in rv.values()):
            if d['rate_reason'] not in RATE_REASONS:
                return False
        elif (any(not _number(v, 0, MAX_COUNTER * 1000) for v in rv.values()) or d['rate_reason'] is not None
              or d['interval_s'] is None or missing):
            return False
        ids.append(d['id'])
    return (ids == sorted(set(ids)) and all(storage._ident(i, 'device') for i in removed)
            and removed == sorted(set(removed)) and not set(ids) & set(removed))
