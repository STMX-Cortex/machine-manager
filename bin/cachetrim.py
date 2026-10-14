#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The guarded build cache trim. Runs ONLY inside an exclusive queue call that the supervisor takes, so no queued
build is live. Usage: cachetrim.py --cache C --age MIN --wait S --log DELETES_LOG --live JSON [--marker-file F
--marker-text T] [--dry]

It refuses (exit 3, deletes nothing) while any live tool runs by NAME (profile live_tools) for longer than --wait
seconds. It checks again after the find. Only `<2 hex>/*` files unused for --age minutes go. One line in the deletes
log: count and bytes. Exit 0 trimmed (or nothing to trim), 2 not the expected cache, 3 refused.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), "core"), os.path.join(os.path.dirname(HERE), "adapters")]
import mmcore  # noqa: E402
import mmdelete  # noqa: E402
import mmread  # noqa: E402


def live(spec):
    procs = mmread.read_ps()
    if procs is None:
        return ["ps failed"]
    return ["%d:%s" % (p["pid"], os.path.basename(p["comm"])) for p in mmread.live_named(procs, spec) if p["pid"] != os.getpid()]


MACHINE = [None]


def log(path, line):
    mmcore.append_line(path, "%s %s machine=%s v=%d" % (mmcore.now_local(), line, MACHINE[0] or mmcore.machine_id(),
                                                         mmcore.SCHEMA_VERSION))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", required=True)
    ap.add_argument("--age", type=float, default=360)
    ap.add_argument("--wait", type=float, default=60)
    ap.add_argument("--poll", type=float, default=5)
    ap.add_argument("--log", required=True)
    ap.add_argument("--live", default="{}")
    ap.add_argument("--marker-file")
    ap.add_argument("--marker-text", default="")
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--machine")
    a = ap.parse_args(argv)
    MACHINE[0] = a.machine
    spec = json.loads(a.live)
    if not mmdelete.has_marker(a.cache, a.marker_file, a.marker_text):
        print("E_NOT_CACHE not the expected cache: %s; fix: check profile trim.cache and its marker" % mmcore.log_path(a.cache))
        log(a.log, "KEEP rule=trim path=%s guard=not the expected cache (marker missing)" % mmcore.log_path(a.cache))
        return 2
    deadline = time.monotonic() + a.wait
    while True:
        lv = live(spec)
        if not lv:
            break
        if time.monotonic() >= deadline:
            print("refused live_tools=%s after_s=%g" % (",".join(lv[:5]), a.wait))
            log(a.log, "KEEP rule=trim path=%s guard=live_tools=%s after %gs" % (mmcore.log_path(a.cache), ",".join(lv[:5]), a.wait))
            return 3
        time.sleep(a.poll)
    files, nbytes = mmdelete.old_cache_entries(a.cache, a.age, time.time())
    lv = live(spec)
    if lv:
        print("refused live_tools_after_find=%s" % ",".join(lv[:5]))
        log(a.log, "KEEP rule=trim path=%s guard=live_tools after the find=%s" % (mmcore.log_path(a.cache), ",".join(lv[:5])))
        return 3
    if a.dry:
        log(a.log, "WOULD-DELETE rule=trim path=%s bytes=%d guard=pass: live_tools=none entries=%d age>%gmin"
            % (mmcore.log_path(a.cache), nbytes, len(files), a.age))
        print("would_trim entries=%d bytes=%d" % (len(files), nbytes))
        return 0
    n, b = mmdelete.delete_entries(files)
    log(a.log, "DELETE rule=trim path=%s bytes=%d guard=pass: live_tools=none before and after the find entries=%d age>%gmin"
        % (mmcore.log_path(a.cache), b, n, a.age))
    print("trimmed entries=%d bytes=%d" % (n, b))
    return 0


if __name__ == "__main__":
    sys.exit(main())
