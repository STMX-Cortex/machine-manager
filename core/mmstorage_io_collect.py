# SPDX-License-Identifier: Apache-2.0
"""Opt-in two-sample I/O collection. Bounded workers, no cache or service changes."""
import json
import os
import sys
import time

if __name__ == '__main__':
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mmstorage_io as model
import mmstorage_linux as common

SAMPLE_TIMEOUT = 2.0
WORK_BYTES = 2 << 20


def snapshot(timeout_s=SAMPLE_TIMEOUT):
    import mmread
    argv = [sys.executable, '-I', os.path.abspath(__file__), '--sample']
    rc, raw, error = mmread.run_bounded(argv, timeout=timeout_s, max_bytes=WORK_BYTES)
    if error:
        return None, 'timeout' if 'timed out' in error else 'truncated' if 'exceeded' in error else 'read_failed'
    if rc != 0:
        return None, 'read_failed'
    try:
        doc = common._json(raw)
        if isinstance(doc, dict) and doc.get('error') in model.storage.REASONS:
            return None, doc['error']
        if not model.snapshot_valid(doc):
            return None, 'invalid_data'
        return doc, None
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return None, 'invalid_data'


def collect(machine_id, interval_s=1.0):
    if not model._safe(machine_id, 120) or not model._number(interval_s, .1, 30):
        raise ValueError('invalid I/O collection arguments')
    if sys.platform not in ('linux', 'darwin'):
        return model.envelope(machine_id, time.time(), interval_s, 'unsupported')
    before, failure = snapshot()
    time.sleep(interval_s)  # explicit CLI wait; never called by the supervisor
    after, error = snapshot()
    if error:
        return model.envelope(machine_id, time.time(), interval_s, error)
    return model.observation(machine_id, before, after, interval_s, failure)


if __name__ == '__main__':
    try:
        if sys.argv[1:] != ['--sample']:
            sys.exit(2)
        if sys.platform == 'linux':
            import mmstorage_io_linux as backend
        elif sys.platform == 'darwin':
            import mmstorage_io_darwin as backend
        else:
            raise NotImplementedError
        result = backend.sample()
        if not model.snapshot_valid(result):
            raise ValueError('invalid I/O snapshot')
    except NotImplementedError:
        result = {'error': 'unsupported'}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        result = {'error': common._error(exc)}
    print(json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(',', ':')))
