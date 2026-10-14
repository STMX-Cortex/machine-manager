# SPDX-License-Identifier: Apache-2.0
"""The memory drill on a fake reader and a fake memory child: each stop rule, the refusals, the release on every exit
path, the pass checks. One real child holds 16 MB to prove grow and release. No test fills real memory beyond that."""
import json
import os
import subprocess
import sys
import time
import unittest

from mmtest import TempData, base_settings, mmcore, mmread
import mmdrill

S = base_settings()  # red_free_pct 35 -> floor 45; amber swap growth from settings
FLOOR = S["slots.red_free_pct"] + 10


class FakeChild:
    def __init__(self, fail_at=None, interrupt_at=None):
        self.held, self.released, self.fail_at, self.interrupt_at = 0, 0, fail_at, interrupt_at

    def release(self):
        self.released += 1

    def grow(self, mb):
        if self.fail_at is not None and self.held >= self.fail_at:
            raise RuntimeError("planted grow fault")
        if self.interrupt_at is not None and self.held >= self.interrupt_at:
            raise KeyboardInterrupt
        self.held += mb
        return self.held


class World:
    """A fake machine: free falls by step_mb*100/total per step; the supervisor turns AMBER below amber_at."""

    def __init__(self, free=80.0, total=16384, amber_at=None, swap_per_step=0.0, step_mb=512):
        self.free0, self.total, self.amber_at, self.swap_per_step, self.step = free, total, amber_at, swap_per_step, step_mb
        self.t = time.time()
        self.child = None

    def clock(self):
        return self.t

    def sleep(self, s):
        self.t += s

    def held(self):
        return self.child.held if self.child else 0

    def reader(self, now):
        free = self.free0 - self.held() * 100.0 / self.total
        state = "AMBER" if self.amber_at is not None and free < self.amber_at else "GREEN"
        return {"free_pct": free, "swap_used_mb": 100 + self.swap_per_step * self.held() / self.step, "state": state,
                "status_fresh": True}

    def factory(self, **kw):
        def make():
            self.child = FakeChild(**kw)
            return self.child
        return make


class Drill(TempData):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir()
        os.makedirs(os.path.join(self.data, "guard"))
        mmcore.write_atomic(os.path.join(self.data, "guard", "state.json"), json.dumps({"heartbeat_epoch": time.time()}))
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": time.time(), "state": "GREEN"}))

    def run_drill(self, w, probe=lambda: [], **kw):
        import ad_queue_fifo
        q = ad_queue_fifo.Queue(self.profile()["queue"])
        args = dict(step_mb=w.step, settle_s=25, time_limit_s=900, reader=w.reader, child_factory=w.factory(), clock=w.clock,
                    sleep=w.sleep, total=w.total, after_s=60, probe=probe)
        args.update(kw)
        return mmdrill.run(self.profile(), S, q, **args)

    def test_stops_at_amber_and_passes_when_the_response_follows(self):
        w = World(amber_at=50)

        def probe():
            return [{"name": "MEM_AMBER"}]
        st = mmcore.AlertStore(S, clock=w.clock)

        def sleep(s):  # the supervisor answers during the drill's wait after the stop
            w.t += s
            if s == 60:
                with open(os.path.join(self.data, "state", "decisions.log"), "a") as f:
                    f.write("%s WOULD slots 5 -> 4: AMBER: free 49%% < 50%%\n" % mmcore.now_local(w.t))
                st.begin()
                st.raise_("MEM", "MEM_AMBER", "ATTENTION", "amber")
        rec = self.run_drill(w, probe=probe, sleep=sleep)
        self.assertEqual(rec["stop_reason"], "supervisor AMBER")
        self.assertEqual(w.child.released, 1)
        self.assertEqual(rec["checks"], {"amber_reached": True, "slot_decision": True, "alert_pushed": True, "alert_in_hook": True})
        self.assertTrue(rec["passed"])
        self.assertTrue(os.path.exists(rec["file"]))
        saved = json.load(open(rec["file"]))
        self.assertEqual((saved["machine_id"], saved["schema_version"], saved["floor_free_pct"]), ("test-machine", 1, FLOOR))
        self.assertTrue(all(x["free_pct"] > FLOOR for x in saved["steps"]))

    def test_floor_is_never_crossed(self):
        w = World()
        rec = self.run_drill(w)
        self.assertTrue(rec["stop_reason"].startswith("floor next"), rec["stop_reason"])
        self.assertTrue(all(x["free_pct"] > FLOOR for x in rec["steps"]), rec["steps"])
        self.assertFalse(rec["passed"], "no AMBER: the drill did not pass")
        self.assertEqual(rec["checks"]["amber_reached"], False)

    def test_swap_growth_and_time_limit(self):
        w = World(swap_per_step=S["slots.amber_swap_growth_mb_30m"] / 2 + 1)
        self.assertTrue(self.run_drill(w)["stop_reason"].startswith("swap +"))
        w = World(total=10 ** 7)
        rec = self.run_drill(w, time_limit_s=100)
        self.assertEqual(rec["stop_reason"], "time limit 100s")
        self.assertEqual(len(rec["steps"]), 4)

    def test_interrupt_and_error_release_at_once(self):
        released = []

        class Rel(FakeChild):
            def release(self):
                released.append(self.held)
        for kw, reason in (({"interrupt_at": 1024}, "interrupted"), ({"fail_at": 512}, "error: RuntimeError('planted grow fault')")):
            w = World()
            rec = self.run_drill(w, child_factory=lambda kw=kw: Rel(**kw))
            self.assertEqual(rec["stop_reason"], reason)
        self.assertEqual(released, [1024, 512], "the child is released on every exit path")

    def test_refusals(self):
        w = World()
        mmcore.write_atomic(os.path.join(self.data, "guard", "state.json"), json.dumps({"heartbeat_epoch": time.time() - 600}))
        self.assertEqual(self.run_drill(w), {"refused": "E_DRILL memory guard not alive; fix: start the memory guard first"})
        mmcore.write_atomic(os.path.join(self.data, "guard", "state.json"), json.dumps({"heartbeat_epoch": time.time()}))
        os.remove(os.path.join(self.data, "status.json"))
        self.assertEqual(self.run_drill(w)["refused"], "E_DRILL supervisor status not fresh; fix: mm start, then retry")
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": time.time(), "state": "GREEN"}))
        h = subprocess.Popen([sys.executable, "-I", "-c", "import fcntl,sys,time\nf=open(sys.argv[1],'a+')\n"
                              "fcntl.flock(f,fcntl.LOCK_EX)\nf.write('S 1 x\\n');f.flush()\nprint('held',flush=True)\n"
                              "time.sleep(60)", os.path.join(self.q, ".slot.1")], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (h.kill(), h.wait(5)))
        h.stdout.readline()
        self.assertEqual(self.run_drill(w)["refused"],
                         "E_DRILL queue busy=1 waiting=0; fix: run the drill when the queue is empty")
        import fcntl
        os.makedirs(os.path.join(self.data, "drills"), exist_ok=True)
        with open(os.path.join(self.data, "drills", ".lock"), "a") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            self.assertEqual(self.run_drill(w)["refused"], "E_DRILL another drill runs; fix: wait for it")

    def test_cli_refuses_with_one_line(self):
        os.remove(os.path.join(self.data, "status.json"))
        r = self.mm("drill", "memory")
        self.assertEqual((r.returncode, r.stdout.strip()), (2, "E_DRILL supervisor status not fresh; fix: mm start, then retry"))

    def test_real_child_grows_and_releases(self):
        c = mmdrill.Child()
        try:
            self.assertEqual(c.grow(8), 8)
            self.assertEqual(c.grow(8), 16)
            rss = [p for p in mmread.read_ps() if p["pid"] == c.p.pid][0]["rss_mb"]
            self.assertGreater(rss, 15, "the pages are written, so they are resident")
        finally:
            c.release()
        self.assertIsNotNone(c.p.poll())


if __name__ == "__main__":
    unittest.main()
