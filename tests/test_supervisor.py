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


class SlotTrialCallCPU(unittest.TestCase):
    """Item 3 through _proc_facts and the actual alert evaluator, without ps or live data."""

    def sup(self, cores=5.8, holders=None):
        from slot_trial_helpers import busy
        sup = object.__new__(mmsuper.Supervisor)
        sup.state = {}
        # The wrapper, child and grandchild together use `cores`. The outsider must not count.
        sup.cache = {"queue": {"slots": 5, "busy": busy() if holders is None else holders, "tickets": []},
                     "procs": [{"pid": 4100, "ppid": 1, "cpu": 20.0, "rss_mb": 10, "comm": "wrapper"},
                               {"pid": 4101, "ppid": 4100, "cpu": 30.0, "rss_mb": 20, "comm": "child"},
                               {"pid": 4102, "ppid": 4101, "cpu": cores * 100 - 50, "rss_mb": 30, "comm": "worker"},
                               {"pid": 9000, "ppid": 1, "cpu": 900.0, "rss_mb": 1000, "comm": "outsider"}]}
        return sup

    def read(self, sup, now, **over):
        import mmalerts
        from slot_trial_helpers import settings
        sup._proc_facts(now)
        return [c for c in mmalerts.evaluate(dict(sup.cache), settings(**over), now) if c["name"] == "SLOT_CPU"]

    def sustained(self, sup, **over):
        from slot_trial_helpers import NOW
        self.read(sup, NOW, **over)
        return self.read(sup, NOW + 60, **over)

    def test_item3_trial_wide_5_8_cores_over_two_slots_is_quiet(self):
        self.assertEqual(self.sustained(self.sup(5.8)), [])

    def test_item3_wide_8_5_cores_gives_exactly_one_attention(self):
        alerts = self.sustained(self.sup(8.5))
        self.assertEqual(len(alerts), 1, alerts)
        self.assertEqual(alerts[0]["level"], "ATTENTION")
        self.assertIn("8.5", alerts[0]["text"])

    def test_item3_shared_4_5_cores_still_alerts(self):
        from slot_trial_helpers import busy
        alerts = self.sustained(self.sup(4.5, busy(slots=(".slot.1",), mode="S")))
        self.assertEqual(len(alerts), 1, alerts)
        self.assertEqual(alerts[0]["level"], "ATTENTION")

    def test_item3_cap_is_strict_and_scales_with_actual_held_slots(self):
        from slot_trial_helpers import busy
        for slots, mode, cores, count in (((".slot.1",), "S", 4, 0),
                                           ((".slot.1", ".slot.2"), "W", 8, 0),
                                           ((".slot.1", ".slot.2"), "W", 8.01, 1),
                                           ((".slot.1", ".slot.2", ".slot.3"), "W", 12, 0),
                                           ((".slot.1", ".slot.2", ".slot.3"), "W", 12.01, 1),
                                           ((".slot.1",), "W", 4.5, 1)):
            with self.subTest(slots=slots, mode=mode, cores=cores):
                self.assertEqual(len(self.sustained(self.sup(cores, busy(slots=slots, mode=mode)))), count)

    def test_item3_configured_per_slot_cpu_cap_applies_to_call_width(self):
        self.assertEqual(self.sustained(self.sup(5.8), **{"queue.slot_cpu_cores": 3}), [])
        self.assertEqual(len(self.sustained(self.sup(6.1), **{"queue.slot_cpu_cores": 3})), 1)

    def test_item3_call_alert_key_survives_slot_rename_and_order(self):
        from slot_trial_helpers import NOW, busy
        sup = self.sup(8.5)
        before = self.sustained(sup)
        sup.cache["queue"]["busy"] = busy(slots=(".slot.4", ".slot.3"))
        self.read(sup, NOW + 120)
        after = self.read(sup, NOW + 180)
        self.assertEqual(len(before), 1, before)
        self.assertEqual(len(after), 1, after)
        self.assertEqual(before[0]["key"], after[0]["key"], "identity belongs to the call, not its slot names")
        self.assertNotIn(".slot.", after[0]["key"])
        self.assertNotIn(".gate.lock", after[0]["key"])

    def test_item3_distinct_calls_get_distinct_alerts_even_with_same_command(self):
        from slot_trial_helpers import busy
        holders = busy(slots=(".slot.1",), mode="S") + busy(pid=4200, slots=(".slot.2",), mode="S")
        for holder in holders:
            holder["label"] = "S %d identical command" % holder["pid"]
        sup = self.sup(4.5, holders)
        sup.cache["procs"].append({"pid": 4200, "ppid": 1, "cpu": 450, "rss_mb": 10, "comm": "second"})
        alerts = self.sustained(sup)
        self.assertEqual(len(alerts), 2, alerts)
        self.assertEqual(len({a["key"] for a in alerts}), 2)
        self.assertTrue(all(".slot." not in a["key"] for a in alerts), alerts)

    def test_item3_replacement_call_cannot_inherit_previous_call_cpu_history(self):
        from slot_trial_helpers import NOW, busy
        sup = self.sup(4.5, busy(slots=(".slot.1",), mode="S"))
        self.sustained(sup)
        sup.cache["queue"]["busy"] = busy(pid=4200, slots=(".slot.1",), mode="S")
        sup.cache["procs"] = [{"pid": 4200, "ppid": 1, "cpu": 450, "rss_mb": 10, "comm": "replacement"}]
        self.assertEqual(self.read(sup, NOW + 120), [], "a new call needs its own two readings")
        self.assertEqual(len(self.read(sup, NOW + 180)), 1)

    def test_item3_duplicate_holder_row_does_not_inflate_width(self):
        from slot_trial_helpers import busy
        holders = busy(slots=(".slot.1",), mode="S")
        holders.append(dict(holders[0]))
        self.assertEqual(len(self.sustained(self.sup(4.5, holders))), 1)

    def test_item4_cpu_alert_still_needs_two_above_cap_readings(self):
        from slot_trial_helpers import NOW, busy
        sup = self.sup(4.5, busy(slots=(".slot.1",), mode="S"))
        self.assertEqual(self.read(sup, NOW), [])
        self.assertEqual(len(self.read(sup, NOW + 60)), 1)
        sup.cache["procs"][2]["cpu"] = 300  # The whole call drops to 3.5 cores.
        self.assertEqual(self.read(sup, NOW + 120), [])
        sup.cache["procs"][2]["cpu"] = 400
        self.assertEqual(self.read(sup, NOW + 180), [])
        self.assertEqual(len(self.read(sup, NOW + 240)), 1)

    def test_item4_process_tree_outsider_accounting_stays(self):
        sup = self.sup(5.8)
        self.sustained(sup)
        self.assertEqual(sup.cache["top_outside"], [("outsider", 1000)])


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


class ActFromTheRealFile(Base):
    """2026-10-14 23:50: after the drill's RED the observe controller held 3 while the file said 5. In act mode the
    controller must start from, and step from, the real file at every tick; an observe value never carries over."""
    ACT = {"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False, "mode.slot_writes": "live"}

    def slots(self):
        return open(os.path.join(self.q, "slots")).read()

    def observe_red_then_green(self, clock):
        sup = self.sup(RED, clock=lambda: clock["t"], allow_live_slots=True)
        self.ticks(sup, 1, clock)
        sup.sampler = CALM
        self.ticks(sup, 3, clock)
        st = json.load(open(os.path.join(self.data, "status.json")))
        self.assertEqual((st["mode"], st["slots"], st["slots_would"]), ("observe", 5, 3), "observe holds its own 3")
        self.assertIn("WOULD slots 5 -> 3", self.decisions())
        return sup

    def test_the_switch_to_act_starts_from_the_file_in_the_same_run_and_after_a_start(self):
        clock = {"t": time.time()}
        sup = self.observe_red_then_green(clock)
        self.write_settings(**self.ACT)  # the switch, read at the next tick of the running supervisor
        self.ticks(sup, 3, clock)
        st = json.load(open(os.path.join(self.data, "status.json")))
        self.assertEqual((st["mode"], st["slots"], st["slots_would"]), ("act", 5, 5))
        self.assertEqual(self.slots(), "5\n", "a GREEN Mac keeps the file's 5: no write of the observe 3")
        self.assertNotIn(" SET slots ", self.decisions())
        clock2 = {"t": clock["t"]}
        fresh = self.sup(CALM, clock=lambda: clock2["t"], allow_live_slots=True)  # a supervisor start in act mode
        self.ticks(fresh, 2, clock2)
        self.assertEqual(self.slots(), "5\n")
        self.assertEqual(json.load(open(os.path.join(self.data, "status.json")))["slots_would"], 5)
        rc, out = self.mm("status").returncode, self.mm("status").stdout.splitlines()
        self.assertIn(" mode=act slots=5 would=5 ", " %s " % out[0])

    def test_a_hand_change_is_kept_and_decisions_step_from_it(self):
        self.write_settings(**self.ACT)
        clock = {"t": time.time()}
        sup = self.sup(CALM, clock=lambda: clock["t"], allow_live_slots=True)
        self.ticks(sup, 2, clock)
        mmcore.write_slots(os.path.join(self.q, "slots"), 7)  # a person sets 7 (or a rollback sets 5)
        self.ticks(sup, 3, clock)
        self.assertEqual(self.slots(), "7\n", "GREEN: the hand value stays")
        sup.sampler = sampler_of(free_pct=45)  # AMBER: one step down, from the file's 7
        self.ticks(sup, 1, clock)
        self.assertEqual(self.slots(), "6\n")
        self.assertIn("SET slots 7 -> 6: AMBER", self.decisions())

    def test_an_unreadable_file_gets_no_decision_and_no_write(self):
        self.write_settings(**self.ACT)
        clock = {"t": time.time()}
        with open(os.path.join(self.q, "slots"), "w") as f:
            f.write("garbage\n")
        sup = self.sup(RED, clock=lambda: clock["t"], allow_live_slots=True)
        sup.state["virtual_slots"] = 5
        self.ticks(sup, 3, clock)
        self.assertEqual(self.slots(), "garbage\n", "no guess written over a file it cannot read")
        self.assertEqual(self.decisions().count(" SKIP slots: "), 1, "logged once per 10 min")
        self.assertIsNone(json.load(open(os.path.join(self.data, "status.json")))["slots_would"])


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
        """Changed for rule 47 (design part C, rule 47 and settlement C-5): only a process that has the slot file open
        and runs the configured queue launcher is paused, so the holder is now a real call of the fixture launcher
        (a `python -c` holder is no longer paused). Still proved: its tree is paused, nothing else, and resume continues it."""
        import mmrecover
        p = subprocess.Popen([sys.executable, "-I", os.path.join(self.q, "launcher.py"), "--", "/bin/sleep", "300"])
        self.addCleanup(self.kill_tree, p)
        other = subprocess.Popen(["/bin/sleep", "300"])  # not in the queue: never paused
        self.addCleanup(self.kill_tree, other)
        kids = []
        for _ in range(100):
            kids = [x["pid"] for x in mmread.read_ps() or [] if x["ppid"] == p.pid]
            if kids and mmread.flock_held(os.path.join(self.q, ".slot.1"))[0]:
                break
            time.sleep(0.1)
        self.assertTrue(kids, "the launcher runs its command")
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "pause_newest_call.enabled": True})
        clock = {"t": time.time()}
        sup = self.sup(sampler_of(free_pct=70, pressure=4), clock=lambda: clock["t"])
        self.ticks(sup, 2, clock)
        self.assertEqual(sorted(int(x) for x in mmrecover.read_paused()), sorted([p.pid] + kids))

        def stat_(pid):
            return subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True,
                                  timeout=5).stdout.strip()
        self.assertTrue(stat_(p.pid).startswith("T") and stat_(kids[0]).startswith("T"))
        self.assertFalse(stat_(other.pid).startswith("T"), "a process outside the call's tree is never paused")
        self.assertEqual(sorted(mmsuper.Pauser({}).resume()), sorted([p.pid] + kids))
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
