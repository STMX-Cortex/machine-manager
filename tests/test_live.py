# SPDX-License-Identifier: Apache-2.0
"""T13: on this machine, now, the fast readings agree with the macOS commands (the same check `mm check` and the daily
macOS change check run). Read only. MM_LIVE_QUEUE=<queue folder> also reads a live queue and proves it unchanged."""
import json
import os
import subprocess
import sys
import time
import unittest

from mmtest import FIX, mmread
import mmsuper
import ad_queue_fifo


class Live(unittest.TestCase):
    def test_fast_readings_match_the_commands(self):
        bad = None
        for _ in range(3):  # the two reads are a moment apart; a busy machine can move between them
            bad, fast, cmd = mmread.check_readings()
            if not bad:
                break
            time.sleep(2)
        self.assertEqual(bad, [], (fast, cmd))
        for k in ("free_pct", "swap_total_mb", "swap_used_mb", "comp_mb", "pressure", "seg_pct", "load1", "load5"):
            self.assertIsNotNone(fast.get(k), k)

    def test_disk_matches_df(self):
        rc, out = mmread.run(["/bin/df", "-k", "/System/Volumes/Data"], timeout=10)
        self.assertEqual(rc, 0)
        self.assertLessEqual(abs(mmread.disk_free_gb() - mmread.parse_df_free_gb(out)), 1.0)

    def test_interval_sys_pct_and_power(self):
        s1, t = mmread.memory_sample(time.time())
        time.sleep(1.0)
        s2, _ = mmread.memory_sample(time.time(), t)
        self.assertTrue(0 <= s2["sys_pct"] <= 100)
        rc, out = mmread.run(["/usr/bin/pmset", "-g", "ps"], timeout=10)
        self.assertIn(mmread.parse_pmset(out), (True, False))

    def test_kernel_stream_parses_and_stops(self):
        lines = open(os.path.join(FIX, "kernel-sample.ndjson")).read()
        ks = mmsuper.KernelStream([sys.executable, "-I", "-c", "import sys,time\nsys.stdout.write(sys.argv[1])\n"
                                   "sys.stdout.flush()\ntime.sleep(30)", lines])
        self.assertTrue(ks.ensure())
        evs = []
        for _ in range(50):
            evs += ks.drain()
            if len(evs) >= 4:
                break
            time.sleep(0.1)
        self.assertEqual([e["kind"] for e in evs], ["no-paging-space", "suspending", "no-paging-space", "suspending"])
        self.assertTrue(ks.alive())
        ks.stop()
        ks.proc.wait(5)
        self.assertFalse(ks.alive())
        self.assertFalse(ks.ensure(), "a restart waits a minute")

    def test_live_queue_is_only_read(self):
        q = os.environ.get("MM_LIVE_QUEUE")
        if not q:
            self.skipTest("MM_LIVE_QUEUE not set")

        def snap():
            out = {}
            for d, dirs, files in os.walk(q):
                for f in files:
                    st = os.lstat(os.path.join(d, f))
                    out[os.path.join(d, f)] = (st.st_mtime_ns, st.st_size)
            return out
        before = snap()
        r = ad_queue_fifo.read_queue(q)
        self.assertIsInstance(r["slots"], int)
        after = snap()
        changed = [p for p in set(before) & set(after) if before[p] != after[p] and not p.endswith(".log")]
        self.assertEqual(changed, [], "the reader wrote nothing (logs may grow by themselves)")


if __name__ == "__main__":
    unittest.main()
