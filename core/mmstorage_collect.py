# SPDX-License-Identifier: Apache-2.0
"""Explicit storage collection on the actual host, independent of MM_PLATFORM test overrides."""
import sys
import mmstorage as model


def collect(machine_id, include=(), exclude=(), timeout_s=5.0):
    if sys.platform == "darwin":
        import mmstorage_darwin as backend
    else:
        import mmstorage_linux as backend
    return backend.collect(machine_id, include=include, exclude=exclude, timeout_s=timeout_s)
