# SPDX-License-Identifier: Apache-2.0
"""Self-recovery: `mm restart` (R1), the self-check and its restart or safe mode (R2), the crash-loop guard and safe
mode (R3), no process left stopped by a crash, a hang, a stop or a rollback (R4), the watchdog's stamp (R5), the Mac
reboot report (R6), the outside dead-man ping (R7), and what the tool never does (R8).
Every process signalled here is a `sleep` or a fixture queue call this test started; launchctl is a fake; nothing
touches a real install."""
import ast
import http.server
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import unittest

import mmtest
from mmtest import TempData, mmcore, mmread
import ad_deliver_claude
import mmdecide
import mmrecover
import mmsuper

SUP = "com.example.machine-manager-test"
WD = SUP + "-watchdog"


def sampler_of(**kw):
    def f(now, ticks):
        d = {"t": now, "free_pct": 80, "swap_used_mb": 100, "swap_total_mb": 2048, "comp_mb": 300, "pressure": 1,
             "seg_pct": 1, "load1": 1, "load5": 1, "sys_pct": None, "sys_pct_fixture": 10}
        d.update(kw)
        return d, ticks
    return f


CALM = sampler_of()

FAKE_LAUNCHCTL = '''#!%s -I
import json, os, sys, time
with open(%r, "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\\n")
a = sys.argv[1:]
if a[:1] == ["bootstrap"] and a[-1].endswith("%s.plist") and os.environ.get("FAKE_HEARTBEAT_PID"):
    p = os.path.join(os.environ["MM_DATA"], "status.json")
    with open(p + ".tmp", "w") as f:
        json.dump({"time": time.time(), "state": "GREEN", "heartbeat": {"pid": int(os.environ["FAKE_HEARTBEAT_PID"]), "tick": 1}}, f)
    os.replace(p + ".tmp", p)
'''


def proc_stat(pid):
    return subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, timeout=5).stdout.strip()


class Base(TempData):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir(slots=5)
        self.kids = []
        self.calls = os.path.join(self.root, "launchctl.txt")
        self.fake = os.path.join(self.root, "launchctl.py")
        with open(self.fake, "w") as f:
            f.write(FAKE_LAUNCHCTL % (sys.executable, self.calls, SUP))
        os.chmod(self.fake, stat.S_IRWXU)
        self._extra = {k: os.environ.get(k) for k in ("FAKE_HEARTBEAT_PID",)}
        os.environ.update(MM_LAUNCHCTL=self.fake)  # MM_GH: the fake gh of mmtest.TempData

    def tearDown(self):
        for p in self.kids:  # only the sleeps this test started
            try:
                os.kill(p.pid, signal.SIGCONT)
                p.kill()
                p.wait(timeout=10)
            except OSError:
                pass
        for k, v in self._extra.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        super().tearDown()

    def sleeper(self):
        p = subprocess.Popen(["/bin/sleep", "300"])
        self.kids.append(p)
        return p

    def stop_and_record(self, p):
        """What the pause does: the record first, then SIGSTOP."""
        mmrecover.add_paused({str(p.pid): mmrecover.start_time(p.pid)})
        os.kill(p.pid, signal.SIGSTOP)
        self.assertTrue(proc_stat(p.pid).startswith("T"))

    def sup(self, sampler=CALM, clock=None, **kw):
        kw.setdefault("check_readings", False)
        kw.setdefault("boot", lambda: {"boot_time": 1000.0, "panics": [], "missing_jobs": []})
        return mmsuper.Supervisor(self.profile(), kernel=False, clock=clock or time.time, sampler=sampler, sizes=False,
                                  slow_jobs=kw.pop("slow_jobs", False), **kw)

    def run_mm(self, *args, timeout=120, **env):
        r = self.mm(*args, env=env, timeout=timeout)
        return r.returncode, r.stdout.strip().splitlines(), r.stderr

    def launchctl(self):
        try:
            return [l.split() for l in open(self.calls).read().splitlines()]
        except OSError:
            return []

    def names(self):
        return [(r["name"], r["level"]) for r in self.pushed() if r.get("why") != "cleared"]

    def recovery_log(self):
        try:
            return open(os.path.join(self.data, "state", "recovery.log")).read()
        except OSError:
            return ""

    def status(self):
        return json.load(open(os.path.join(self.data, "status.json")))


class R1Restart(Base):
    @mmtest.darwin_only
    def test_restart_stops_starts_and_waits_for_a_fresh_heartbeat(self):
        mmcore.write_atomic(os.path.join(self.data, "status.json"),
                            json.dumps({"time": time.time() - 5, "heartbeat": {"pid": 1111}}))
        rc, out, err = self.run_mm("restart", FAKE_HEARTBEAT_PID="4242")
        self.assertEqual((rc, out), (0, ["restart=ok pid=4242"]), err)
        uid = os.getuid()
        self.assertEqual([c[:2] for c in self.launchctl()], [["bootout", "gui/%d/%s" % (uid, WD)],
                         ["bootout", "gui/%d/%s" % (uid, SUP)], ["bootstrap", "gui/%d" % uid], ["bootstrap", "gui/%d" % uid]])
        self.assertNotIn("STOPPED", [n for n, _ in self.names()], "a restart is not a stop: no STOPPED alert")
        self.assertFalse(os.path.exists(os.path.join(self.data, "state", "stopped.json")))

    @mmtest.darwin_only
    def test_restart_without_a_fresh_heartbeat_is_one_error_line(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "self.restart_wait_s": 5})
        mmcore.write_atomic(os.path.join(self.data, "status.json"),
                            json.dumps({"time": time.time() - 5, "heartbeat": {"pid": 1111}}))
        t = time.monotonic()
        rc, out, _ = self.run_mm("restart")
        self.assertEqual((rc, out), (2, ["E_RESTART no fresh heartbeat in 5 s; fix: mm status; mm explain SELF_STALE"]))
        self.assertLess(time.monotonic() - t, 20)

    @mmtest.darwin_only
    def test_restart_retries_a_load_that_fails_right_after_the_unload(self):
        """Seen live 2026-10-14 21:44: bootout ends a service in the background; the bootstrap right after it failed
        and `mm restart` left nothing running."""
        counter = os.path.join(self.root, "bootstrap-count")
        with open(self.fake, "a") as f:  # the first two loads fail with rc 5, as launchctl does then
            f.write('if a[:1] == ["bootstrap"]:\n'
                    '    n = int(open(%r).read()) if os.path.exists(%r) else 0\n'
                    '    open(%r, "w").write(str(n + 1))\n'
                    '    if n < 2:\n'
                    '        sys.exit(5)\n' % (counter, counter, counter))
        with open(self.fake) as f:  # the heartbeat must come only from a load that worked: move it after the check
            text = f.read()
        hb = text[text.index('if a[:1] == ["bootstrap"] and a[-1].endswith'):text.index('if a[:1] == ["bootstrap"]:\n    n =')]
        with open(self.fake, "w") as f:
            f.write(text.replace(hb, "") + hb)
        mmcore.write_atomic(os.path.join(self.data, "status.json"),
                            json.dumps({"time": time.time() - 5, "heartbeat": {"pid": 1111, "tick": 9}}))
        rc, out, err = self.run_mm("restart", FAKE_HEARTBEAT_PID="4646")
        self.assertEqual((rc, out), (0, ["restart=ok pid=4646"]), err)
        boots = [c for c in self.launchctl() if c[0] == "bootstrap"]
        self.assertEqual(len(boots), 4, "the supervisor's load tried 3 times, then the watchdog's once")

    @mmtest.darwin_only
    def test_restart_says_so_when_a_load_keeps_failing(self):
        with open(self.fake, "a") as f:
            f.write('if a[:1] in (["bootstrap"], ["print"]):\n    sys.exit(5)\n')
        rc, out, _ = self.run_mm("restart", timeout=120)  # 10 tries a second apart for each of the two agents
        self.assertEqual(rc, 2)
        self.assertTrue(out[0].startswith("E_RESTART load failed: %s=rc5 %s=rc5; fix: mm start; mm status" % (SUP, WD)), out)

    @mmtest.darwin_only
    def test_restart_clear_safe_ends_safe_mode(self):
        mmrecover.enter_safe("test", time.time())
        rc, out, _ = self.run_mm("restart", "--clear-safe", FAKE_HEARTBEAT_PID="4343")
        self.assertEqual((rc, out), (0, ["restart=ok pid=4343 safe=cleared"]))
        self.assertIsNone(mmcore.safe_state())


class R2SelfCheck(Base):
    def test_own_memory_over_the_limit_restarts_with_a_held_alert(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "self.max_rss_mb": 10})
        rc, out, err = self.run_mm("run", "--ticks", "5", "--tick-seconds", "0.2", "--no-kernel-stream")
        self.assertEqual(rc, mmsuper.EXIT_RESTART, out + [err])
        self.assertIn("SELF RESTART: own memory", self.recovery_log())
        run = json.load(open(os.path.join(self.data, "state", "run.json")))
        self.assertFalse(run["clean"], "a self restart counts as an unclean end")
        held = json.load(open(os.path.join(self.data, "state", "controller.json")))["held"]
        self.assertEqual(held["SELF_RESTART"]["level"], "ACTION")
        # the next start delivers the held alert and counts one unclean start
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10})
        rc, out, err = self.run_mm("run", "--ticks", "1", "--tick-seconds", "0.2", "--no-kernel-stream")
        self.assertEqual(rc, 0, out + [err])
        self.assertIn(("SELF_RESTART", "ACTION"), self.names())
        self.assertEqual(len(json.load(open(os.path.join(self.data, "state", "starts.json")))), 1)
        self.assertTrue(json.load(open(os.path.join(self.data, "state", "run.json")))["clean"])

    def test_a_fault_a_restart_cannot_fix_gives_safe_mode(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "self.min_free_mb": 1000000})
        rc, out, err = self.run_mm("run", "--ticks", "3", "--tick-seconds", "0.2", "--no-kernel-stream")
        self.assertEqual(rc, 0, out + [err])
        self.assertIn("self-check: the data folder's disk has", mmcore.safe_state()["reason"])
        self.assertEqual(self.status()["mode"], "safe")
        self.assertIn(("SAFE_MODE", "ACTION"), self.names())

    def test_wrong_readings_for_six_ticks_give_safe_mode(self):
        clock = {"t": time.time()}
        sup = self.sup(sampler_of(free_pct=None), clock=lambda: clock["t"])
        for k in range(6):
            sup.tick()
            r = sup.check_self(0.1, 0)
            clock["t"] += 10
            self.assertEqual(r["action"], "safe" if k == 5 else "ok", (k, r))
        self.assertIn("readings wrong 6 ticks in a row: free_pct missing", mmcore.safe_state()["reason"])

    def test_slot_count_that_keeps_changing_gives_safe_mode(self):
        sup = self.sup()
        sup.state["slot_changes"] = [time.time() - 60 * k for k in range(13)]
        self.assertEqual(sup.check_self(0.1, 0)["action"], "safe")


class R3SafeMode(Base):
    def test_three_unclean_starts_in_15_minutes_give_safe_mode_and_no_exit_loop(self):
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "state", "run.json"), json.dumps({"pid": 1, "started": now - 100, "clean": False}))
        mmcore.write_atomic(os.path.join(self.data, "state", "starts.json"), json.dumps([now - 600, now - 300]))
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "self.max_rss_mb": 10})
        rc, out, err = self.run_mm("run", "--ticks", "4", "--tick-seconds", "0.2", "--no-kernel-stream")
        self.assertEqual(rc, 0, "in safe mode a self-check never exits: " + "\n".join(out) + err)
        self.assertIn("3 unclean starts in 15 min (crash loop)", mmcore.safe_state()["reason"])
        self.assertEqual(self.status()["mode"], "safe")
        names = self.names()
        self.assertIn(("SAFE_MODE", "ACTION"), names)
        held = json.load(open(os.path.join(self.data, "state", "controller.json")))["held"]
        self.assertIn("own memory", held["SELF_CHECK"]["text"])
        rc, out, _ = self.run_mm("on")
        self.assertEqual((rc, out), (0, ["actions=on safe=cleared"]))
        self.assertIsNone(mmcore.safe_state())
        self.assertFalse(os.path.exists(os.path.join(self.data, "state", "starts.json")), "the unclean starts are forgotten")
        self.assertEqual(self.run_mm("on")[1], ["actions=on"])

    def act_settings(self, slots_file, **kw):
        self.write_settings(**dict({"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                                    "mode.slot_writes": "test", "mode.slots_file": slots_file}, **kw))

    def test_one_slot_write_down_to_safe_slots_and_no_raise_after(self):
        f = os.path.join(self.root, "test-slots")
        with open(f, "w") as fh:
            fh.write("8\n")
        self.act_settings(f)
        mmrecover.enter_safe("test", time.time())
        sup = self.sup()
        sup.tick()
        self.assertEqual(open(f).read().split()[0], "5")
        self.assertIn("SET 8 -> 5", mmcore.safe_state()["slot_write"])
        old = mmdecide.slot_decide
        mmdecide.slot_decide = lambda st, inp, s: {"slots": inp["slots"] + 2, "why": "raise", "state": {}}
        try:
            sup.tick()
            self.assertEqual(open(f).read().split()[0], "5", "no raise in safe mode")
            mmdecide.slot_decide = lambda st, inp, s: {"slots": inp["slots"] - 1, "why": "lower", "state": {}}
            sup.tick()
            self.assertEqual(open(f).read().split()[0], "4", "lowering stays allowed")
        finally:
            mmdecide.slot_decide = old

    def test_safe_slots_never_raise_a_lower_count(self):
        f = os.path.join(self.root, "test-slots")
        with open(f, "w") as fh:
            fh.write("3\n")
        self.act_settings(f)
        mmrecover.enter_safe("test", time.time())
        self.sup().tick()
        self.assertEqual(open(f).read().split()[0], "3")
        self.assertEqual(mmcore.safe_state()["slot_write"], "SET 3 -> 3")

    def test_observe_mode_writes_no_slot_in_safe_mode(self):
        mmrecover.enter_safe("test", time.time())
        with open(os.path.join(self.q, "slots"), "w") as fh:
            fh.write("8\n")
        self.sup().tick()
        self.assertEqual(open(os.path.join(self.q, "slots")).read().split()[0], "8")
        self.assertIn("WOULD 8 -> 5", mmcore.safe_state()["slot_write"])

    def test_no_delete_and_an_open_gate_in_safe_mode(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "deletes.enabled": True, "launch_gate.enabled": True})
        got = []
        for safe in (False, True):
            if safe:
                mmrecover.enter_safe("test", time.time())
            sup = self.sup(slow_jobs=True)
            sup.gh = None
            sup.deletes.kick = lambda *a: got.append(a[2]) or False
            sup.tick()
        self.assertEqual(got, [True, False], "deletes on, then off in safe mode")
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"),
                            json.dumps({"time": now, "state": "RED", "red_since": now - 10, "reasons": ["free 30%"]}))
        s = self.s()
        cfg = {"launch_tools": ["Agent"]}
        self.assertIsNone(ad_deliver_claude.gate_decision({"tool_name": "Agent"}, s, now, cfg), "safe mode: gate open")
        mmrecover.clear_safe("test")
        self.assertTrue(ad_deliver_claude.gate_decision({"tool_name": "Agent"}, s, now, cfg).startswith("E_GATE_RED"))

    def test_no_pause_in_safe_mode_and_a_held_pause_is_continued(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "pause_newest_call.enabled": True})
        p, other = self.sleeper(), self.sleeper()
        self.stop_and_record(p)
        safe = mmrecover.enter_safe("test", time.time())
        sup = self.sup()
        sup.cache["queue"] = {"busy": [{"slot": ".slot.1", "pid": other.pid, "since": time.time(), "label": "x"}],
                              "tickets": [], "slots": 5}
        sup.cache["procs"] = [{"pid": other.pid, "ppid": 1, "rss_mb": 1, "cpu": 0, "comm": "sleep"}]
        sup._gate_and_pause(time.time(), self.s(), "RED", ["kernel pressure 4"], False, safe)
        self.assertFalse(proc_stat(other.pid).startswith("T"), "no pause in safe mode")
        self.assertFalse(proc_stat(p.pid).startswith("T"), "the paused process was continued")
        self.assertEqual(mmrecover.read_paused(), {})


class R4Paused(Base):
    @mmtest.needs_proc
    def test_the_record_is_written_before_the_sigstop(self):
        """Changed for rule 47 (design part C, rule 47 and settlement C-5): the pause takes its pids from the process
        that has the slot file open and runs the configured queue launcher, so the paused process is now a real call
        of the fixture launcher (with its sleep), reached through a supervisor tick at a critical RED.
        Still proved: each pid is in the record before its SIGSTOP."""
        p = subprocess.Popen([sys.executable, "-I", os.path.join(self.q, "launcher.py"), "--", "/bin/sleep", "300"])
        tree = []

        def end_tree():
            for pid in reversed(tree):
                try:
                    os.kill(pid, signal.SIGCONT)
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            p.wait(10)
        self.addCleanup(end_tree)
        for _ in range(100):
            kids = [x["pid"] for x in mmread.read_ps() or [] if x["ppid"] == p.pid]
            if kids and mmread.flock_held(os.path.join(self.q, ".slot.1"))[0]:
                break
            time.sleep(0.1)
        tree[:] = [p.pid] + kids
        self.assertEqual(len(tree), 2, "the launcher runs its sleep")
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "pause_newest_call.enabled": True})
        seen = []
        real = mmrecover.signal_process

        def spy(pid, expected, sig):
            if sig == signal.SIGSTOP:
                if pid not in tree:  # never stop a process this test did not start
                    seen.append(("not ours", pid))
                    return None
                seen.append(str(pid) in mmrecover.read_paused())
            return real(pid, expected, sig)
        mmrecover.signal_process = spy
        try:
            self.sup(sampler=sampler_of(free_pct=70, pressure=4)).tick()
        finally:
            mmrecover.signal_process = real
        self.assertEqual(seen, [True, True], "one SIGSTOP per pid of the call, each after its record")
        self.assertEqual(sorted(int(x) for x in mmrecover.read_paused()), sorted(tree))
        self.assertTrue(all(proc_stat(pid).startswith("T") for pid in tree))

    def test_a_crash_during_a_pause_is_undone_by_the_next_start(self):
        p = self.sleeper()
        self.stop_and_record(p)  # then the supervisor dies (kill -9): nothing continues it
        rc, out, err = self.run_mm("run", "--ticks", "1", "--tick-seconds", "0.2", "--no-kernel-stream")
        self.assertEqual(rc, 0, out + [err])
        self.assertFalse(proc_stat(p.pid).startswith("T"))
        self.assertIn("RESUME pids [%d] skipped [] (start)" % p.pid, self.recovery_log())
        self.assertEqual(mmrecover.read_paused(), {})

    def test_a_reused_pid_gets_no_signal(self):
        p = self.sleeper()
        os.kill(p.pid, signal.SIGSTOP)  # stopped by someone else: the record names an older process with this pid
        mmrecover.add_paused({str(p.pid): "Thu Jan  1 00:00:01 2026"})
        self.assertEqual(mmrecover.resume_paused("test"), [])
        self.assertTrue(proc_stat(p.pid).startswith("T"), "not ours: left as it is")
        self.assertEqual(mmrecover.read_paused(), {}, "the stale record is forgotten")

    def test_watchdog_continues_paused_processes_of_a_stale_supervisor_only(self):
        p = self.sleeper()
        self.stop_and_record(p)
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": now - 30, "state": "GREEN"}))
        self.run_mm("watchdog", MM_NOW=str(now))
        self.assertTrue(proc_stat(p.pid).startswith("T"), "a fresh supervisor keeps its pause")
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": now - 130, "state": "GREEN"}))
        self.run_mm("watchdog", MM_NOW=str(now))
        self.assertFalse(proc_stat(p.pid).startswith("T"), "stale over 120 s: continued")
        self.assertIn("resumed paused pids [%d]" % p.pid, open(os.path.join(self.data, "state", "watchdog.log")).read())

    @mmtest.darwin_only
    def test_stop_and_rollback_continue_paused_processes(self):
        for verb in ("stop", "rollback"):
            p = self.sleeper()
            self.stop_and_record(p)
            rc, out, err = self.run_mm(verb)
            self.assertEqual(rc, 0, out + [err])
            self.assertFalse(proc_stat(p.pid).startswith("T"), verb)


class R5Watchdog(Base):
    def install_record(self):
        os.makedirs(os.path.join(self.root, "base"), exist_ok=True)
        mmcore.write_atomic(os.path.join(self.root, "base", "install.json"), json.dumps({"data": self.data}))

    def test_watchdog_run_writes_its_stamp(self):
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": time.time(), "state": "GREEN"}))
        self.run_mm("watchdog")
        self.assertLess(mmrecover.watchdog_age(time.time()), 30)

    @mmtest.darwin_only
    def test_stale_watchdog_alert_and_one_kickstart_per_10_minutes(self):
        self.install_record()
        clock = {"t": time.time()}
        mmrecover.stamp_watchdog(clock["t"] - 400)
        sup = self.sup(clock=lambda: clock["t"])
        sup.tick()
        clock["t"] += 10
        sup.tick()
        self.assertIn(("WATCHDOG_STALE", "ATTENTION"), self.names())
        self.assertEqual(self.launchctl(), [["print", "gui/%d/%s" % (os.getuid(), WD)],
                                            ["kickstart", "-k", "gui/%d/%s" % (os.getuid(), WD)]])
        mmrecover.stamp_watchdog(clock["t"])
        clock["t"] += 10
        sup.tick()
        self.assertEqual(len(self.launchctl()), 2)

    def test_not_installed_or_fresh_is_quiet(self):
        mmrecover.stamp_watchdog(time.time() - 400)
        self.sup().tick()  # no install record: a run by hand
        self.install_record()
        mmrecover.stamp_watchdog(time.time() - 30)
        self.sup().tick()
        self.assertNotIn("WATCHDOG_STALE", [n for n, _ in self.names()])
        self.assertEqual(self.launchctl(), [])


class R6Reboot(Base):
    def test_reboot_report_once_with_down_time_panics_and_missing_jobs(self):
        now = time.time()
        mmrecover.save_boot({"boot_time": now - 86400, "panics": ["panic-old.panic"]})
        mmcore.write_atomic(os.path.join(self.data, "status.json"),
                            json.dumps({"time": now - 1200, "state": "AMBER", "slots": 4}))
        cur = {"boot_time": now - 300, "panics": ["panic-old.panic", "panic-full-new.panic"], "missing_jobs": ["load sampler"]}
        sup = self.sup(boot=lambda: dict(cur))
        sup.tick()
        recs = [r for r in self.pushed() if r["name"] == "MAC_REBOOTED"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["level"], "ACTION")
        self.assertIn("Mac rebooted: up 5 min; tool down 20 min; before: AMBER slots 4; 1 new panic report; "
                      "not running: load sampler", recs[0]["text"])
        files = [f for f in os.listdir(os.path.join(self.data, "state")) if f.startswith("reboot-")]
        self.assertEqual(len(files), 1)
        self.assertEqual(json.load(open(os.path.join(self.data, "state", files[0])))["new_panics"], ["panic-full-new.panic"])
        self.sup(boot=lambda: dict(cur)).tick()  # the same boot again: no second report
        self.assertEqual(len([f for f in os.listdir(os.path.join(self.data, "state")) if f.startswith("reboot-")]), 1)

    def test_first_start_has_no_reboot_report(self):
        self.sup(boot=lambda: {"boot_time": time.time() - 300, "panics": [], "missing_jobs": []}).tick()
        self.assertNotIn("MAC_REBOOTED", [n for n, _ in self.names()])

    @mmtest.needs_proc
    def test_real_facts(self):
        self.assertGreater(mmrecover.boot_time(), 1.0e9)
        self.assertLess(mmrecover.boot_time(), time.time())
        d = os.path.join(self.root, "reports")
        os.makedirs(d)
        for n in (".contents.panic", "panic-full-2026-10-14.panic", "Kernel-2026.panic", "app_2026.diag"):
            open(os.path.join(d, n), "w").close()
        self.assertEqual(mmrecover.panic_names(d), ["Kernel-2026.panic", "panic-full-2026-10-14.panic"])
        self.assertIsNone(mmrecover.panic_names(os.path.join(self.root, "none")))
        p = subprocess.Popen(["/bin/sleep", "301"])
        self.kids.append(p)
        self.assertEqual(mmrecover.missing_jobs([{"name": "sleeper", "match": r"^/bin/sleep 301$"},
                                                 {"name": "gone", "match": r"no-such-job-[0-9]{9}"}]), ["gone"])


class R7Heartbeat(Base):
    def serve(self):
        hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1], hits

    def test_off_by_default_no_network(self):
        port, hits = self.serve()
        sup = self.sup()
        for _ in range(3):
            sup.tick()
        self.assertEqual(hits, [])
        self.assertFalse(os.path.exists(os.path.join(self.data, "state", "heartbeat.log")))

    def test_ping_when_set_and_the_log_names_only_the_host(self):
        port, hits = self.serve()
        token = "4f1c2d3e-4f1c-2d3e-4f1c-2d3e4f1c2d3e"
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10,
                               "heartbeat.url": "http://127.0.0.1:%d/ping/%s" % (port, token)})
        sup = self.sup()
        log = os.path.join(self.data, "state", "heartbeat.log")
        for _ in range(50):
            sup.tick()
            if os.path.exists(log):
                break
            time.sleep(0.1)
        self.assertEqual(hits, ["/ping/" + token])
        text = open(log).read()
        self.assertIn("ping host=127.0.0.1 status=200", text)
        for d, _, files in os.walk(self.data):
            for f in files:
                with open(os.path.join(d, f), errors="replace") as fh:
                    if f not in ("settings.toml", "settings.lastgood.json"):  # the owner's own settings
                        self.assertNotIn(token, fh.read(), f)

    def test_url_must_be_http(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "heartbeat.url": "file:///etc/hosts"})
        st = mmcore.Settings()
        st.load()
        self.assertIn("heartbeat.url must be empty or an http(s) URL", st.problem)


class C1StartGrace(Base):
    """Install fault 1: the watchdog ran before the supervisor's first status.json and restarted it."""

    @mmtest.darwin_only
    def test_no_restart_and_no_alert_inside_the_start_grace(self):
        now = time.time()
        mmrecover.note_loaded(now - 10)  # mm install or mm start loaded the agents 10 s ago; no status.json yet
        rc, out, _ = self.run_mm("watchdog", MM_NOW=str(now))
        self.assertEqual(self.launchctl(), [], "no kickstart inside the grace")
        self.assertNotIn("SELF_STALE", [n for n, _ in self.names()])
        self.assertIn("supervisor starting", open(os.path.join(self.data, "state", "watchdog.log")).read())
        rc, out, _ = self.run_mm("watchdog", MM_NOW=str(now + 100))  # past 90 s and still no status.json
        self.assertEqual([c[0] for c in self.launchctl()], ["print", "kickstart"])
        self.assertIn(("SELF_STALE", "ACTION"), self.names())

    def test_the_grace_counts_from_the_supervisors_own_start_too(self):
        now = time.time()
        mmrecover.note_loaded(now - 3600)
        mmcore.write_atomic(os.path.join(self.data, "state", "run.json"), json.dumps({"pid": 1, "started": now - 20, "clean": False}))
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": now - 3000, "state": "GREEN"}))
        self.run_mm("watchdog", MM_NOW=str(now))
        self.assertEqual(self.launchctl(), [])

    def test_status_at_once_and_a_sigterm_during_the_start_ends_clean(self):
        seen = {}
        real, old = mmsuper.Supervisor, signal.getsignal(signal.SIGTERM)

        class Slow:
            kernel = None

            def __init__(self, *a, **kw):
                seen["status"] = json.load(open(os.path.join(self.data_dir, "status.json")))
                os.kill(os.getpid(), signal.SIGTERM)  # launchd stops it while it starts
        Slow.data_dir = self.data
        mmsuper.Supervisor = Slow
        try:
            rc = mmsuper.run_loop(self.profile(), ticks=1, tick_seconds=0.1, kernel=False)
        finally:
            mmsuper.Supervisor = real
            signal.signal(signal.SIGTERM, old)
        self.assertEqual(rc, 0)
        self.assertEqual((seen["status"]["heartbeat"]["tick"], seen["status"]["heartbeat"]["note"]), (0, "starting"))
        import mmschema
        self.assertEqual(mmschema.validate(seen["status"], mmschema.load("status")), [])
        self.assertTrue(json.load(open(os.path.join(self.data, "state", "run.json")))["clean"], "a stop while starting is clean")
        # the stop deadline is cancelled once run_loop returns in time (else its os._exit ends the caller later:
        # 2026-10-14, the test runner itself ended at once with rc 0 and no output)
        self.assertEqual([t for t in threading.enumerate() if isinstance(t, threading.Timer) and t.is_alive()], [])

    def test_a_start_that_fails_is_unclean(self):
        real = mmsuper.Supervisor

        def boom(*a, **kw):
            raise RuntimeError("planted")
        mmsuper.Supervisor = boom
        try:
            with self.assertRaises(RuntimeError):
                mmsuper.run_loop(self.profile(), ticks=1, tick_seconds=0.1, kernel=False)
        finally:
            mmsuper.Supervisor = real
        self.assertFalse(json.load(open(os.path.join(self.data, "state", "run.json")))["clean"])

    def test_restart_waits_for_tick_1_not_the_starting_record(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "self.restart_wait_s": 5})
        with open(self.fake, "a") as f:  # the new supervisor only writes its starting record
            f.write('if a[:1] == ["bootstrap"] and a[-1].endswith("%s.plist"):\n'
                    '    p = os.path.join(os.environ["MM_DATA"], "status.json")\n'
                    '    json.dump({"time": time.time() + 1, "heartbeat": {"pid": 5151, "tick": 0}}, open(p, "w"))\n' % SUP)
        rc, out, _ = self.run_mm("restart")
        self.assertEqual(rc, 2, out)


class C2Commands(Base):
    """Install fault 2: gh was not on the LaunchAgents' PATH (rc=None)."""

    def profile_with(self, tool):
        text = open(mmtest.PROFILE).read().replace('guard_argv = ["/usr/bin/false"]', 'guard_argv = ["%s"]' % tool)
        p = os.path.join(self.root, "profile-cmd.toml")
        with open(p, "w") as f:
            f.write(text)
        return p

    @mmtest.darwin_only
    def test_install_puts_each_commands_folder_on_the_service_path_and_check_proves_it(self):
        tools = os.path.join(self.root, "tools bin")
        os.makedirs(tools)
        tool = os.path.join(tools, "mmfaketool")
        with open(tool, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(tool, 0o700)
        prof = self.profile_with("mmfaketool")
        env = {"MM_PROFILE": prof, "PATH": tools + ":/usr/bin:/bin"}
        rc, out, err = self.run_mm("check", **env)
        self.assertEqual((rc, out), (0, ["check=ok"]), err)
        rc, out, err = self.run_mm("install", **env)
        self.assertEqual(rc, 0, out + [err])
        import plistlib
        pl = os.path.join(self.root, "home", "Library", "LaunchAgents", SUP + ".plist")
        path_ = plistlib.load(open(pl, "rb"))["EnvironmentVariables"]["PATH"].split(":")
        self.assertEqual(path_[-4:], ["/usr/bin", "/bin", "/usr/sbin", "/sbin"])
        self.assertIn(tools, path_[:-4])
        self.assertIn(os.path.dirname(self.fake_gh), path_[:-4])
        rec = json.load(open(os.path.join(self.root, "base", "install.json")))
        self.assertEqual(rec["commands"]["mmfaketool"], tool)
        self.assertEqual(self.run_mm("check", **env)[:2], (0, ["check=ok"]))
        # an install from before this fix: the system folders only
        d = plistlib.load(open(pl, "rb"))
        d["EnvironmentVariables"]["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        with open(pl, "wb") as f:
            plistlib.dump(d, f)
        rc, out, _ = self.run_mm("check", **env)
        self.assertEqual(rc, 1)
        self.assertIn("E_COMMAND mmfaketool on the installed service PATH is missing, not %s; fix: mm install again" % tool, out)

    def test_a_missing_command_and_a_gh_that_cannot_read_github(self):
        prof = self.profile_with("no-such-tool-mm")
        rc, out, _ = self.run_mm("check", MM_PROFILE=prof)
        self.assertEqual(rc, 1)
        self.assertIn("E_COMMAND no-such-tool-mm not found on PATH; fix: install it, or add its folder to "
                      "service.path_extra", out)
        rc, out, _ = self.run_mm("check", "--online")
        self.assertIn("E_GH gh cannot read GitHub in the service environment (rc=1); fix: gh auth login", out)

    def test_profile_path_extra_comes_first(self):
        import mminstall
        p = self.profile()
        p["service"]["path_extra"] = ["/opt/extra/bin"]
        path_, found = mminstall.service_path(p, "/usr/bin:/bin")
        self.assertEqual(path_.split(":")[0], "/opt/extra/bin")
        self.assertEqual(found["/usr/bin/false"], "/usr/bin/false")


class C4Loads(Base):
    """Reinstall faults (21:50): the supervisor was not loaded after `mm install`, which still said installed=yes;
    a not-loaded supervisor or watchdog cannot be kickstarted; a good gh read left SOURCE_STALE active 5 min."""

    def fail_controls(self, verb_label_rc):
        """Make the fake launchctl fail: {(verb, label suffix): rc}; `print` of a failing label says not found (113)."""
        with open(self.fake, "a") as f:
            for (verb, lab), rc in verb_label_rc.items():
                f.write('if a[:1] == [%r] and a[-1].endswith(%r):\n    sys.exit(%d)\n' % (verb, lab, rc))

    @mmtest.darwin_only
    def test_install_says_so_when_the_supervisor_does_not_load(self):
        self.fail_controls({("bootstrap", SUP + ".plist"): 5, ("print", SUP): 113})
        rc, out, err = self.run_mm("install", timeout=120)
        self.assertEqual(rc, 2, out + [err])
        self.assertEqual(len(out), 1, out)
        self.assertTrue(out[0].startswith("E_INSTALL load failed: %s=rc5; fix: mm start, then mm status" % SUP), out)
        self.assertNotIn("installed=yes", "\n".join(out))
        rec = json.load(open(os.path.join(self.root, "base", "install.json")))
        self.assertEqual(rec["bootstrap"], [[SUP, 5], [WD, 0]], "the record stays, so rollback works")

    @mmtest.darwin_only
    def test_install_retries_a_failed_load(self):
        counter = os.path.join(self.root, "n")
        with open(self.fake, "a") as f:
            f.write('if a[:1] == ["bootstrap"] and a[-1].endswith("%s.plist"):\n'
                    '    n = int(open(%r).read()) if os.path.exists(%r) else 0\n'
                    '    open(%r, "w").write(str(n + 1))\n'
                    '    sys.exit(5 if n < 2 else 0)\n' % (SUP, counter, counter, counter))
        rc, out, err = self.run_mm("install", timeout=120)
        self.assertEqual(rc, 0, out + [err])
        self.assertTrue(out[0].startswith("installed=yes"))

    @mmtest.darwin_only
    def test_watchdog_loads_an_unloaded_supervisor_and_says_so(self):
        self.fail_controls({("print", SUP): 113})
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": now - 600, "state": "GREEN"}))
        rc, out, _ = self.run_mm("watchdog", MM_NOW=str(now))
        calls = self.launchctl()
        self.assertIn(["bootstrap", "gui/%d" % os.getuid(), os.path.join(self.root, "home", "Library", "LaunchAgents",
                                                                         SUP + ".plist")], calls)
        self.assertNotIn("kickstart", [c[0] for c in calls], "kickstart cannot start a service that is not loaded")
        self.assertIn(("SELF_UNLOADED", "ACTION"), self.names())
        self.assertIn("not loaded, bootstrap rc=0", open(os.path.join(self.data, "state", "watchdog.log")).read())

    @mmtest.darwin_only
    def test_watchdog_kickstarts_a_loaded_stale_supervisor(self):
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": now - 600, "state": "GREEN"}))
        self.run_mm("watchdog", MM_NOW=str(now))
        self.assertEqual([c[0] for c in self.launchctl()], ["print", "kickstart"])
        self.assertNotIn("SELF_UNLOADED", [n for n, _ in self.names()])

    @mmtest.darwin_only
    def test_supervisor_loads_an_unloaded_watchdog(self):
        os.makedirs(os.path.join(self.root, "base"), exist_ok=True)
        mmcore.write_atomic(os.path.join(self.root, "base", "install.json"), json.dumps({"data": self.data}))
        self.fail_controls({("print", WD): 113})
        mmrecover.stamp_watchdog(time.time() - 400)
        self.sup().tick()
        self.assertEqual([c[0] for c in self.launchctl()], ["print", "bootstrap"])
        self.assertIn(("SELF_UNLOADED", "ACTION"), self.names())
        active = json.load(open(os.path.join(self.data, "alerts-state.json")))["active"]
        self.assertIn("SELF_UNLOADED:watchdog", active)

    def test_a_good_gh_read_clears_its_source_stale_at_once(self):
        st = mmcore.AlertStore(self.s())
        st.begin()
        for part in ("billing", "runs"):
            st.raise_("SOURCE_STALE:gh-" + part, "SOURCE_STALE", "ATTENTION", "GitHub %s read failed: rc=None" % part)
        sup = self.sup(slow_jobs=True)
        sup.deletes.kick = lambda *a: False

        class OneRead:
            def __init__(self, rec):
                self.rec = rec

            def take(self):
                r, self.rec = self.rec, None
                return r

            def kick(self, *a):
                return False
        sup.gh = OneRead({"time": time.time(), "errors": {"runs": "rc=1"}, "pool_id": "ci:example/project"})
        sup.tick()
        active = json.load(open(os.path.join(self.data, "alerts-state.json")))["active"]
        self.assertNotIn("SOURCE_STALE:gh-billing", active, "billing read fine: cleared at once")
        self.assertIn("SOURCE_STALE:gh-runs", active, "runs still fails")
        cleared = [r for r in self.pushed() if r.get("why") == "cleared"]
        self.assertEqual([r["key"] for r in cleared], ["SOURCE_STALE:gh-billing"])


class C3SizesInterval(Base):
    def test_sizes_interval_is_a_setting(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "disk.sizes_interval_minutes": 5})
        clock = {"t": time.time()}
        sup = mmsuper.Supervisor(self.profile(), kernel=False, clock=lambda: clock["t"], sampler=CALM, sizes=True,
                                 slow_jobs=False, check_readings=False,
                                 boot=lambda: {"boot_time": 1000.0, "panics": [], "missing_jobs": []})
        kicks = []
        sup.bg.kick = lambda *a: kicks.append(clock["t"]) or True
        for _ in range(31):  # 0 .. 300 s, every 10 s
            sup.tick()
            clock["t"] += 10
        self.assertEqual(len(kicks), 2, "at the start and after 5 min")


SUP_SCRIPT = r"""
import os, sys, time
sys.path[:0] = [sys.argv[1], sys.argv[2]]
import mmcore, mmread, mmsuper
if sys.argv[3] == "hang":  # tick 1 as usual; tick 2 runs a command that does not end
    real, n = mmsuper.Supervisor.tick, {"i": 0}

    def tick(self):
        n["i"] += 1
        if n["i"] == 1:
            return real(self)
        open(os.path.join(os.environ["MM_DATA"], "hanging"), "w").close()
        mmread.run(["/bin/sleep", "300"], timeout=600)
    mmsuper.Supervisor.tick = tick
sys.exit(mmsuper.run_loop(mmcore.load_profile(), dry_run=True, tick_seconds=float(sys.argv[4]), kernel=False))
"""


class C5CleanStop(Base):
    """Live fault 2026-10-14 22:28: `mm restart` logged an unclean start; launchd's ExitTimeOut (5 s) most likely
    killed the supervisor in its wait or a tick. A SIGTERM must always give a clean, quick end."""

    def spawn(self, mode, tick_s):
        code = os.path.dirname(mmtest.HERE)
        p = subprocess.Popen([sys.executable, "-I", "-c", SUP_SCRIPT, os.path.join(code, "core"), os.path.join(code, "adapters"),
                              mode, str(tick_s)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             text=True)
        self.addCleanup(lambda: p.poll() is None and (p.kill(), p.wait(5)))
        return p

    def wait_for(self, fn, limit):
        end = time.time() + limit
        while time.time() < end:
            v = fn()
            if v:
                return v
            time.sleep(0.05)
        self.fail("not reached in %g s" % limit)

    def tick_n(self):
        st = mmcore.read_json(os.path.join(self.data, "status.json"), None) or {}
        return int((st.get("heartbeat") or {}).get("tick") or 0)

    def run_json(self):
        return json.load(open(os.path.join(self.data, "state", "run.json")))

    def test_sigterm_in_the_wait_between_ticks_ends_clean_at_once(self):
        p = self.spawn("wait", 30)
        self.wait_for(lambda: self.tick_n() >= 1, 60)
        time.sleep(0.5)  # now inside the 30 s wait
        t = time.monotonic()
        p.send_signal(signal.SIGTERM)
        rc = p.wait(10)
        took = time.monotonic() - t
        self.assertEqual(rc, 0, p.stderr.read())
        self.assertLess(took, 2.0, "the wait ends at once, far under launchd's ExitTimeOut")
        self.assertTrue(self.run_json()["clean"])
        loop, unclean, _ = mmrecover.note_start(time.time(), self.s())
        self.assertFalse(unclean, "the next start is not unclean")
        self.assertEqual(loop["starts"], [])

    def test_sigterm_in_a_hung_tick_marks_clean_at_once_and_ends_by_the_deadline(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "self.stop_deadline_s": 2})
        p = self.spawn("hang", 0.5)
        self.wait_for(lambda: os.path.exists(os.path.join(self.data, "hanging")), 60)
        kid = self.wait_for(lambda: subprocess.run(["/usr/bin/pgrep", "-P", str(p.pid), "-x", "sleep"], capture_output=True,
                                                   text=True).stdout.split(), 10)
        kid = int(kid[0])
        t = time.monotonic()
        p.send_signal(signal.SIGTERM)
        self.wait_for(lambda: self.run_json()["clean"], 1.0)  # marked at once: a SIGKILL now still leaves a clean run
        self.assertIsNone(p.poll(), "still in the tick when it is marked")
        rc = p.wait(10)
        took = time.monotonic() - t
        self.assertEqual(rc, 0, p.stderr.read())
        self.assertGreater(took, 1.5)
        self.assertLess(took, 4.0, "ends by the 2 s deadline, under ExitTimeOut")
        with self.assertRaises(ProcessLookupError):  # its command is killed with it, not left behind
            for _ in range(50):
                # A Linux subreaper can inherit the dead command after the supervisor's forced exit.
                # Reap only this fixture child, so a zombie is not mistaken for a still-running command.
                if sys.platform == "linux":
                    try:
                        os.waitpid(kid, os.WNOHANG)
                    except ChildProcessError:
                        pass
                os.kill(kid, 0)
                time.sleep(0.05)
        log = open(os.path.join(self.data, "state", "recovery.log")).read()
        self.assertIn("STOP deadline: the tick did not end in 2 s after SIGTERM; killed 1 commands; exit", log)
        self.assertFalse(mmrecover.note_start(time.time(), self.s())[1], "the next start is not unclean")

    @mmtest.darwin_only
    def test_the_plist_gives_launchd_time_and_check_finds_an_old_plist(self):
        import mminstall
        import plistlib
        d = plistlib.loads(mminstall.plist(SUP, ["run"], {"MM_DATA": self.data, "PATH": "/usr/bin"}, True))
        self.assertEqual(d["ExitTimeOut"], 20)
        self.assertGreater(d["ExitTimeOut"], mmcore.SCHEMA["self.stop_deadline_s"][2],
                           "every allowed deadline ends before launchd's SIGKILL")
        rc, out, err = self.run_mm("install")
        self.assertEqual(rc, 0, out + [err])
        pl = os.path.join(self.root, "home", "Library", "LaunchAgents", SUP + ".plist")
        self.assertEqual(plistlib.load(open(pl, "rb"))["ExitTimeOut"], 20)
        self.assertEqual(self.run_mm("check")[:2], (0, ["check=ok"]))
        d = plistlib.load(open(pl, "rb"))
        del d["ExitTimeOut"]  # an install from before this fix (launchd then used 5 s)
        with open(pl, "wb") as f:
            plistlib.dump(d, f)
        rc, out, _ = self.run_mm("check")
        self.assertEqual(rc, 1)
        self.assertIn("E_PLIST the installed supervisor has ExitTimeOut unset, not 20 (a stop can be killed mid-tick); "
                      "fix: mm install again", out)


class C6RealSlots(Base):
    """Live fault 2026-10-14: in observe mode `mm status` printed slots=3 (the controller's count) while the slots
    file said 5. status.json slots is the real file; slots_would is the controller's count."""

    def test_observe_mode_shows_the_real_count_and_the_decision(self):
        import mmschema
        sup = mmsuper.Supervisor(self.profile(), dry_run=False, kernel=False)
        sup.state["virtual_slots"] = 3
        sup._control = lambda *a, **kw: None  # the controller's count stays 3 (observe: it writes nothing)
        sup.tick()
        st = json.load(open(os.path.join(self.data, "status.json")))
        self.assertEqual((st["slots"], st["slots_would"]), (5, 3))
        self.assertEqual(mmschema.validate(st, mmschema.load("status")), [])
        self.assertEqual(open(os.path.join(self.q, "slots")).read().split()[0], "5", "observe mode writes no slots")
        rc, out, _ = self.run_mm("status")
        self.assertIn(" slots=5 would=3 ", out[0])


class R8Never(unittest.TestCase):
    """The code never reboots the Mac and never signals a process except: SIGSTOP and SIGCONT by the pause record,
    and signal 0 (is it alive?)."""

    def sources(self):
        for sub in ("core", "adapters", "bin"):
            d = os.path.join(mmtest.CODE, sub)
            for f in sorted(os.listdir(d)):
                p = os.path.join(d, f)
                if f.endswith(".py") or f in ("mm",):
                    yield p, open(p).read()

    def test_no_reboot_shutdown_or_other_signal(self):
        cmd = re.compile(r"""["'](?:/sbin/|/usr/sbin/)?(?:reboot|shutdown|halt)["' ]""")
        for p, text in self.sources():
            for n, line in enumerate(text.splitlines(), 1):
                self.assertIsNone(cmd.search(line), "%s:%d: %s" % (p, n, line.strip()))
                if "killpg" in line or "SIGKILL" in line:
                    self.assertEqual(os.path.basename(p), "mmread.py")
                    self.assertEqual(line.strip(), "os.killpg(p.pid, signal.SIGKILL)")
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "killpg":
                    self.assertEqual(os.path.basename(p), "mmread.py")
                    tree = ast.parse(text)
                    helper = next(f for f in tree.body if isinstance(f, ast.FunctionDef) and f.name == "_kill_owned_group")
                    self.assertLess(helper.lineno, node.lineno)
                    self.assertLessEqual(node.lineno, helper.end_lineno)
                    self.assertTrue(any(isinstance(x, ast.If) and ast.unparse(x.test) == "p not in _LIVE_GROUPS" and
                                        any(isinstance(y, ast.Return) for y in x.body) for x in ast.walk(helper)))
                if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "kill" and \
                        getattr(node.func.value, "id", None) == "os":
                    self.assertIn(ast.unparse(node.args[1]), {"0", "signal.SIGSTOP", "signal.SIGCONT"},
                                  "%s: %s" % (p, ast.unparse(node)))
                if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "pidfd_send_signal":
                    self.assertEqual(os.path.basename(p), "mmplat_linux.py", p)
                    self.assertEqual(ast.unparse(node.args[1]), "sig")
                    tree = ast.parse(text)
                    functions = [f for f in tree.body if isinstance(f, ast.FunctionDef) and f.name == "signal_process"]
                    self.assertEqual(len(functions), 1)
                    guarded = [n for n in functions[0].body if isinstance(n, ast.If) and
                               ast.unparse(n.test) == "sig not in (signal.SIGSTOP, signal.SIGCONT)" and
                               any(isinstance(x, ast.Raise) for x in n.body)]
                    self.assertEqual(len(guarded), 1, "the transport must reject other signals before opening a pidfd")
                    self.assertLess(guarded[0].lineno, node.lineno)

    def test_only_the_pause_stops_and_only_the_record_continues(self):
        stops, guarded_calls = [], []
        for p, text in self.sources():
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "kill" and \
                        getattr(node.func.value, "id", None) == "os":
                    stops.append((os.path.basename(p), ast.unparse(node.args[1])))
                if isinstance(node, ast.Call) and (isinstance(node.func, ast.Name) and node.func.id == "signal_process" or
                        isinstance(node.func, ast.Attribute) and node.func.attr == "signal_process" and
                        isinstance(node.func.value, ast.Name) and node.func.value.id == "mmrecover"):
                    guarded_calls.append((os.path.basename(p), ast.unparse(node.args[2])))
        self.assertEqual(sorted(set(stops)), [("mmread.py", "0"), ("mmrecover.py", "0"),
                                              ("mmrecover.py", "signal.SIGCONT"),
                                              ("mmrecover.py", "signal.SIGSTOP")])
        self.assertEqual(sorted(set(guarded_calls)), [("mmrecover.py", "signal.SIGCONT"),
                                                     ("mmsuper.py", "signal.SIGSTOP")])

    def test_signal_transports_reject_every_other_signal_before_any_process_access(self):
        import mmplat_linux
        from unittest.mock import patch
        backend_send = mmplat_linux.signal_process
        with patch.object(mmrecover.mmread.plat, "signal_process", create=True) as send, \
                patch.object(mmplat_linux.os, "pidfd_open", create=True) as opened, \
                patch.object(mmrecover, "start_time") as identity, patch.object(mmrecover.os, "kill") as kill:
            for sig in (0, signal.SIGTERM, signal.SIGINT, signal.SIGKILL, -1, 123456):
                with self.subTest(sig=sig), self.assertRaises(ValueError):
                    mmrecover.signal_process(123, "birth", sig)
                with self.subTest(backend_sig=sig), self.assertRaises(ValueError):
                    backend_send(123, "birth", sig)
            send.assert_not_called()
            opened.assert_not_called()
            identity.assert_not_called()
            kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
