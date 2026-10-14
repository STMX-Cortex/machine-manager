# SPDX-License-Identifier: Apache-2.0
"""The supervisor on a fixture queue: slot writes by mode (T7), observe mode and the off switch (B2), status.json and
the pool record (schemas), bad settings (T12), tick errors and the dry run (T5), the pause on fixture processes (T7),
the macOS change check (B3) and masking in what it writes (B1)."""
import json
import os
import stat
import subprocess
import sys
import time
import unittest

import mmtest
from mmtest import TempData, mmcore, mmread
import mmschema
import mmsuper

SECRET = "GH_TOKEN=ghp_PLANTEDPLANTEDPLANTEDPLANTED1234"


def sampler_of(**kw):
    def f(now, ticks):
        d = {"t": now, "free_pct": 80, "swap_used_mb": 100, "swap_total_mb": 2048, "comp_mb": 300, "pressure": 1,
             "seg_pct": 1, "load1": 1, "load5": 1, "sys_pct": None, "sys_pct_fixture": 10}
        d.update(kw)
        return d, ticks
    return f


RED = sampler_of(free_pct=30)
CALM = sampler_of()

HOLDER = r'''
import fcntl, os, subprocess, sys, time
f = open(sys.argv[1], "a+")
fcntl.flock(f, fcntl.LOCK_EX)
f.seek(0); f.truncate(); f.write("S %d " % os.getpid() + sys.argv[2] + "\n"); f.flush()
child = subprocess.Popen(["/bin/sleep", "300"])
time.sleep(300)
'''


class Base(TempData):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir(slots=5)
        fake = os.path.join(self.root, "fake-gh.sh")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(fake, stat.S_IRWXU)
        self._gh = os.environ.get("MM_GH")
        os.environ["MM_GH"] = fake

    def tearDown(self):
        if self._gh is None:
            os.environ.pop("MM_GH", None)
        super().tearDown()

    def sup(self, sampler=CALM, clock=None, **kw):
        kw.setdefault("check_readings", False)
        return mmsuper.Supervisor(self.profile(), kernel=False, clock=clock or time.time, sampler=sampler, sizes=False,
                                  slow_jobs=False, **kw)

    def ticks(self, sup, n, clock):
        for _ in range(n):
            sup.tick()
            clock["t"] += 10

    def decisions(self):
        try:
            return open(os.path.join(self.data, "state", "decisions.log")).read()
        except OSError:
            return ""

    def holder(self, label):
        p = subprocess.Popen([sys.executable, "-I", "-c", HOLDER, os.path.join(self.q, ".slot.1"), label])
        for _ in range(50):
            q = mmread.flock_held(os.path.join(self.q, ".slot.1"))
            if q[0]:
                break
            time.sleep(0.1)
        self.addCleanup(self.kill_tree, p)
        return p

    def kill_tree(self, p):
        for pid in [x["pid"] for x in (mmread.read_ps() or []) if x["ppid"] == p.pid]:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        p.kill()
        p.wait(5)


class SlotWrites(Base):
    def run_mode(self, mode, observe=False, n=2):
        test_slots = os.path.join(self.root, "test-slots")
        mmcore.write_slots(test_slots, 6)
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": observe,
                               "mode.slot_writes": mode, "mode.slots_file": test_slots})
        clock = {"t": time.time()}
        sup = self.sup(RED, clock=lambda: clock["t"])
        self.ticks(sup, n, clock)
        return test_slots

    def test_test_mode_writes_only_the_test_file(self):
        f = self.run_mode("test")
        self.assertEqual(open(f).read(), "3\n")
        self.assertEqual(open(os.path.join(self.q, "slots")).read(), "5\n", "the queue's slots file is untouched")
        self.assertIn("SET slots 6 -> 3: RED", self.decisions())
        st = json.load(open(os.path.join(self.data, "status.json")))
        self.assertEqual((st["state"], st["mode"], st["machine_id"]), ("RED", "act", "test-machine"))
        self.assertTrue(any(r["name"] == "MEM_RED" for r in self.pushed()))

    def test_observe_mode_only_records_would(self):
        f = self.run_mode("test", observe=True)
        self.assertEqual(open(f).read(), "6\n")
        self.assertIn("WOULD slots 5 -> 3", self.decisions())
        self.assertEqual(json.load(open(os.path.join(self.data, "status.json")))["mode"], "observe")

    def test_off_switch_turns_actions_off_and_alerts(self):
        mmcore.write_atomic(os.path.join(self.data, "off.json"), json.dumps({"off": True, "since": "x", "reason": "test"}))
        f = self.run_mode("test")
        self.assertEqual(open(f).read(), "6\n", "off: no write")
        self.assertIn("WOULD slots", self.decisions())
        self.assertEqual(json.load(open(os.path.join(self.data, "status.json")))["mode"], "off")
        self.assertIn("OFF", [r["name"] for r in self.pushed()])

    def test_live_mode_needs_the_flag(self):
        self.run_mode("live")
        self.assertEqual(open(os.path.join(self.q, "slots")).read(), "5\n")
        self.assertIn("WOULD slots 5 -> 3", self.decisions())
        self.assertIn("(live writes refused: this run lacks --allow-live-slots)", self.decisions())

    def test_live_mode_with_flag_writes_the_queue(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "mode.slot_writes": "live"})
        clock = {"t": time.time()}
        sup = self.sup(RED, clock=lambda: clock["t"], allow_live_slots=True)
        self.ticks(sup, 1, clock)
        self.assertEqual(open(os.path.join(self.q, "slots")).read(), "3\n")


class Banner(Base):
    def run_red(self, dry):
        for f in ("alerts-state.json", "alerts.jsonl"):
            if os.path.exists(os.path.join(self.data, f)):
                os.remove(os.path.join(self.data, f))
        rec = os.path.join(self.root, "banners.txt")
        tool = os.path.join(self.root, "banner.sh")
        with open(tool, "w") as f:
            f.write('#!/bin/sh\necho "$1" >> %s\n' % rec)
        os.chmod(tool, stat.S_IRWXU)
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "banner.enabled": True})
        os.environ["MM_BANNER_CMD"] = tool
        try:
            clock = {"t": time.time()}
            self.ticks(self.sup(RED, clock=lambda: clock["t"], dry_run=dry), 2, clock)
        finally:
            os.environ.pop("MM_BANNER_CMD", None)
        return open(rec).read().splitlines() if os.path.exists(rec) else []

    def test_banner_on_action_but_never_in_a_dry_run(self):
        self.assertEqual(self.run_red(dry=True), [])
        lines = self.run_red(dry=False)
        self.assertTrue(lines and lines[0].startswith("ACTION MEM_RED"), lines)


class Records(Base):
    def test_status_and_pool_records_match_their_schemas(self):
        clock = {"t": time.time()}
        sup = self.sup(clock=lambda: clock["t"])
        self.ticks(sup, 2, clock)
        st = json.load(open(os.path.join(self.data, "status.json")))
        self.assertEqual(mmschema.validate(st, mmschema.load("status")), [])
        self.assertEqual((st["kind"], st["schema_version"], st["heartbeat"]["tick"]), ("machine", 1, 2))
        pool = json.load(open(os.path.join(self.data, "pools", "ci_example_project.json")))
        self.assertEqual(mmschema.validate(pool, mmschema.load("status")), [])
        self.assertEqual((pool["kind"], pool["machine_id"], pool["state"]), ("pool", "ci:example/project", "UNKNOWN"))
        for r in self.pushed():
            self.assertEqual(mmschema.validate(r, mmschema.load("alert")), [], r)
        head = open(os.path.join(self.data, "metrics.csv")).readline()
        self.assertTrue(head.startswith("time,machine_id,state"))


class PoolStart(Base):
    def test_no_stale_pool_alert_before_the_first_read_is_due(self):
        clock = {"t": time.time()}
        sup = self.sup(clock=lambda: clock["t"])
        sup.tick()
        self.assertNotIn("SOURCE_STALE:gh", [r["key"] for r in self.pushed()])
        clock["t"] += 31 * 60
        sup.tick()
        self.assertIn(("SOURCE_STALE:gh", "ATTENTION"), [(r["key"], r["level"]) for r in self.pushed()],
                      "never read after the stale limit: the alert comes")


class BadSettings(Base):
    def test_raises_and_clears_settings_bad(self):
        clock = {"t": time.time()}
        sup = self.sup(clock=lambda: clock["t"])
        sup.tick()
        f = os.path.join(self.data, "settings.toml")
        good = open(f).read()
        with open(f, "w") as fh:
            fh.write("[slots\n")
        os.utime(f, (time.time(), time.time() + 5))
        clock["t"] += 10
        sup.tick()
        bad = [r for r in self.pushed() if r["name"] == "SETTINGS_BAD"]
        self.assertEqual([(b["level"], b["command"]) for b in bad], [("ACTION", "mm check")])
        with open(f, "w") as fh:
            fh.write(good)
        os.utime(f, (time.time(), time.time() + 10))
        for _ in range(2):
            clock["t"] += 400
            sup.tick()
        self.assertEqual([r["why"] for r in self.pushed() if r["name"] == "SETTINGS_BAD"], ["new", "cleared"])

    def test_no_settings_at_all_still_alerts(self):
        with open(os.path.join(self.data, "settings.toml"), "w") as fh:
            fh.write("[broken\n")
        sup = self.sup()
        sup.tick()
        self.assertEqual([(r["name"], r["level"]) for r in self.pushed()], [("SETTINGS_BAD", "ACTION")])
        self.assertEqual(json.load(open(os.path.join(self.data, "status.json")))["heartbeat"]["note"], "no valid settings")


class TickErrorsAndDryRun(Base):
    def test_failing_ticks_raise_supervisor_error(self):
        old = mmread.memory_sample

        def boom(*a, **k):
            raise RuntimeError("planted sampler fault")
        mmread.memory_sample = boom
        try:
            orig = mmsuper.Supervisor.__init__

            def init(self_, profile, **kw):
                kw.update(check_readings=False, slow_jobs=False, sizes=False)
                orig(self_, profile, **kw)
            mmsuper.Supervisor.__init__ = init
            try:
                mmsuper.run_loop(self.profile(), ticks=4, tick_seconds=0, kernel=False)
            finally:
                mmsuper.Supervisor.__init__ = orig
        finally:
            mmread.memory_sample = old
        self.assertEqual(len(open(os.path.join(self.data, "state", "errors.log")).read().splitlines()), 4)
        self.assertIn("planted sampler fault", json.load(open(os.path.join(self.data, "status.json")))["heartbeat"]["note"])
        self.assertEqual([(x["name"], x["level"]) for x in self.pushed()], [("SUPERVISOR_ERROR", "ACTION")])

    def test_dry_run_writes_only_in_its_data_folder(self):
        def snap(root):
            out = {}
            for d, dirs, files in os.walk(root):
                dirs[:] = [x for x in dirs if x not in ("__pycache__", "results")]
                for f in files:
                    st = os.stat(os.path.join(d, f))
                    out[os.path.relpath(os.path.join(d, f), root)] = (st.st_mtime_ns, st.st_size)
            return out
        code_before = snap(mmtest.CODE)
        q_before = snap(self.q)
        r = self.mm("run", "--dry-run", "--ticks", "2", "--tick-seconds", "1", "--no-kernel-stream", timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(code_before, snap(mmtest.CODE), "nothing in the code folder changed")
        self.assertEqual(q_before, snap(self.q), "nothing in the queue folder changed")
        self.assertEqual(json.load(open(os.path.join(self.data, "status.json")))["mode"], "dry")
        self.assertFalse(os.path.exists(os.path.join(self.root, "home", "Library")), "no LaunchAgent")


class Pause(Base):
    def test_pause_and_resume_fixture_tree_only(self):
        p = self.holder("sleep fixture")
        q = mmread.read_ps()
        kids = [x["pid"] for x in q if x["ppid"] == p.pid]
        busy = [{"slot": ".slot.1", "pid": p.pid, "since": time.time(), "label": "S fixture"}]
        state = {}
        got = mmsuper.Pauser(state).pause(busy, q)
        self.assertEqual(got[1], sorted([p.pid] + kids))

        def stat_(pid):
            return subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True,
                                  timeout=5).stdout.strip()
        self.assertTrue(stat_(p.pid).startswith("T") and stat_(kids[0]).startswith("T"))
        self.assertEqual(sorted(mmsuper.Pauser(state).resume()), sorted([p.pid] + kids))
        self.assertFalse(stat_(p.pid).startswith("T"))

    def test_observe_mode_logs_would_pause_masked(self):
        self.holder("go test " + SECRET)
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "pause_newest_call.enabled": True})
        clock = {"t": time.time()}
        sup = self.sup(sampler_of(free_pct=70, pressure=4), clock=lambda: clock["t"])
        self.ticks(sup, 2, clock)
        log = self.decisions()
        self.assertIn("WOULD-PAUSE", log)
        self.assertNotIn("ghp_PLANTED", log)
        import mmrecover
        self.assertEqual(mmrecover.read_paused(), {}, "nothing stopped in observe mode")


class ReadingsCheck(Base):
    def test_mismatch_raises_action_and_falls_back(self):
        old_check, old_cmd = mmread.check_readings, mmread.command_sample
        mmread.check_readings = lambda t=None: (["free_pct fast=80.0 command=60.0"], {}, {})
        used = []

        def cmd_sample(now, ticks):
            used.append(now)
            return CALM(now, ticks)
        mmread.command_sample = cmd_sample
        try:
            sup = mmsuper.Supervisor(self.profile(), kernel=False, sizes=False, slow_jobs=False, check_readings=True)
            sup.tick()
        finally:
            mmread.check_readings, mmread.command_sample = old_check, old_cmd
        self.assertTrue(used, "the fallback sampler ran")
        self.assertIn(("READINGS_MISMATCH", "ACTION"), [(r["name"], r["level"]) for r in self.pushed()])
        self.assertEqual(json.load(open(os.path.join(self.data, "status.json")))["sampler"], "commands")


class Masking(Base):
    def test_queue_label_secret_never_reaches_alerts_or_evidence(self):
        self.holder("go test " + SECRET)
        old = time.time() - 3600
        os.utime(os.path.join(self.q, ".slot.1"), (old, old))  # a long call: LONG_CALL carries the label
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10})
        clock = {"t": time.time()}
        sup = self.sup(RED, clock=lambda: clock["t"])
        self.ticks(sup, 2, clock)
        names = [r["name"] for r in self.pushed()]
        self.assertIn("LONG_CALL", names)
        self.assertIn("MEM_RED", names)
        for d, dirs, files in os.walk(self.data):
            dirs[:] = [x for x in dirs if x != "queue"]  # the fixture queue itself holds the planted label
            for f in files:
                with open(os.path.join(d, f), errors="replace") as fh:
                    self.assertNotIn("ghp_PLANTED", fh.read(), os.path.join(d, f))
        self.assertTrue(os.listdir(os.path.join(self.data, "evidence")), "MEM_RED made an evidence bundle")


if __name__ == "__main__":
    unittest.main()
