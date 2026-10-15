#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the machine-manager tests: python3 -I tests/run_tests.py [GROUP ...] [--quick]
One result file per group in tests/results/. --quick skips the slow and live groups (for `mm selftest`).
Temporary folders go under MM_TEST_TMP (default: the system temp folder); each test removes its own."""
import glob
import io
import os
from pathlib import Path
import sys
import time
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

GROUPS = {
    "core": ["test_core"],            # T1 parsers, T6 alerts, T7 controller, T10 names, T12 settings, B1 masking
    "usage_rows": ["test_usage_rows", "test_usage_rows_transcript"] + [
        path.stem for path in sorted(Path(HERE).glob("test_usage_rows_review*.py"))
    ],                              # coarse rule items 1-6, transcripts and every review round
    "vectors": ["test_vectors"],      # every vector, the replays (T2-T4), the schemas
    "supervisor": ["test_supervisor"] + [  # T5 tick errors and dry run, T7 slot writes and pause, T12, B2 off, B3 check
        os.path.basename(path)[:-3]
        for path in sorted(glob.glob(os.path.join(HERE, "test_slot_trial*review*.py")))
    ],
    "watchdog": ["test_watchdog"],    # T5
    "hook": ["test_hook"],            # T9, the 3-line limit, fail-open
    "place": ["test_place"],          # T8
    "deletes": ["test_deletes"],      # T14a-h, T15
    "sandbox_holds": ["test_sandbox_holds"],  # rules 46-48: git, the pause and deletes against agent-written files
    "sandbox_holds_r1": ["test_sandbox_holds_r1"],  # C-10 read-write openers, regular slot file; C-11 markers, DELETES_FAILED
    "sandbox_holds_r2": ["test_sandbox_holds_r2"],  # C-14: QUEUE_FILE_UNREADABLE, list alerts, A1, fresh snapshot, QWAIT
    "sandbox_holds_review": ["test_sandbox_holds_review"],    # review round 1, part C: relative launcher (R10C-1)
    "sandbox_holds_review2": ["test_sandbox_holds_review2"],  # review round 2, part C: R2C-1 to R2C-3
    "sandbox_holds_review3": ["test_sandbox_holds_review3"],  # review round 3, part C: R3C-1 to R3C-3
    "install": ["test_install"],      # install, stop, start, rollback, init, check (temporary HOME)
    "cli": ["test_cli"],              # golden outputs and limits
    "drill": ["test_drill"],          # the drill's stop rules on a fake reader
    "public": ["test_public"],        # no internal names in the public tree
    "recovery": ["test_recovery"],    # R1-R8: restart, self-check, safe mode, paused processes, reboot, ping
    "live": ["test_live"],            # T13: the fast readings agree with the macOS commands, here and now
}
SLOW = ("live", "drill")


def main(argv):
    quick = "--quick" in argv
    want = [a for a in argv if not a.startswith("--")] or [g for g in GROUPS if not (quick and g in SLOW)]
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    bad, total = 0, 0
    for g in want:
        buf = io.StringIO()
        suite = unittest.TestSuite()
        for m in GROUPS[g]:
            suite.addTests(unittest.defaultTestLoader.loadTestsFromName(m))
        t0 = time.time()
        res = unittest.TextTestRunner(stream=buf, verbosity=2).run(suite)
        ok = res.wasSuccessful()
        bad += not ok
        total += res.testsRun
        text = "%s %s: %d tests, %d failures, %d errors, %d skipped, %.1f s, at %s\n\n%s" % (
            g, "PASS" if ok else "FAIL", res.testsRun, len(res.failures), len(res.errors), len(res.skipped),
            time.time() - t0, time.strftime("%Y-%m-%d %H:%M:%S"), buf.getvalue())
        with open(os.path.join(HERE, "results", g + ".txt"), "w") as f:
            f.write(text)
        print(text.splitlines()[0])
    print("groups=%d tests=%d failed_groups=%d" % (len(want), total, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
