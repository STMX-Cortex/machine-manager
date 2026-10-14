# SPDX-License-Identifier: Apache-2.0
"""Self-recovery: `mm restart` (R1), the self-check and its restart or safe mode (R2), the crash-loop guard and safe
mode (R3), no process left stopped by a crash, a hang, a stop or a rollback (R4), the watchdog's stamp (R5), the Mac
reboot report (R6), the outside dead-man ping (R7), and what the tool never does (R8).
Every process signalled here is a `sleep` this test started; launchctl is a fake; nothing touches a real install."""
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
from mmtest import TempData, mmcore
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
        json.dump({"time": time.time(), "state": "GREEN", "heartbeat": {"pid": int(os.environ["FAKE_HEARTBEAT_PID"])}}, f)
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
        gh = os.path.join(self.root, "fake-gh.sh")
        with open(gh, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(gh, stat.S_IRWXU)
        self._extra = {k: os.environ.get(k) for k in ("MM_GH", "FAKE_HEARTBEAT_PID")}
        os.environ.update(MM_GH=gh, MM_LAUNCHCTL=self.fake)

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

    def test_restart_without_a_fresh_heartbeat_is_one_error_line(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "self.restart_wait_s": 5})
        mmcore.write_atomic(os.path.join(self.data, "status.json"),
                            json.dumps({"time": time.time() - 5, "heartbeat": {"pid": 1111}}))
        t = time.monotonic()
        rc, out, _ = self.run_mm("restart")
        self.assertEqual((rc, out), (2, ["E_RESTART no fresh heartbeat in 5 s; fix: mm status; mm explain SELF_STALE"]))
        self.assertLess(time.monotonic() - t, 20)

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
    def test_the_record_is_written_before_the_sigstop(self):
        p = self.sleeper()
        seen = []
        real = os.kill

        def spy(pid, sig):
            if sig == signal.SIGSTOP:
                seen.append(str(pid) in mmrecover.read_paused())
            return real(pid, sig)
        mmsuper.os.kill = spy
        try:
            got = mmsuper.Pauser().pause([{"pid": p.pid, "since": time.time(), "label": "x"}],
                                         [{"pid": p.pid, "ppid": 1, "rss_mb": 1, "cpu": 0, "comm": "sleep"}])
        finally:
            mmsuper.os.kill = real
        self.assertEqual(got[1], [p.pid])
        self.assertEqual(seen, [True])
        self.assertTrue(proc_stat(p.pid).startswith("T"))

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

    def test_stale_watchdog_alert_and_one_kickstart_per_10_minutes(self):
        self.install_record()
        clock = {"t": time.time()}
        mmrecover.stamp_watchdog(clock["t"] - 400)
        sup = self.sup(clock=lambda: clock["t"])
        sup.tick()
        clock["t"] += 10
        sup.tick()
        self.assertIn(("WATCHDOG_STALE", "ATTENTION"), self.names())
        self.assertEqual(self.launchctl(), [["kickstart", "-k", "gui/%d/%s" % (os.getuid(), WD)]])
        mmrecover.stamp_watchdog(clock["t"])
        clock["t"] += 10
        sup.tick()
        self.assertEqual(len(self.launchctl()), 1)

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
        cmd = re.compile(r"""["'](?:/sbin/|/usr/sbin/)?(?:reboot|shutdown|halt)["' ]|killpg|SIGKILL""")
        for p, text in self.sources():
            for n, line in enumerate(text.splitlines(), 1):
                self.assertIsNone(cmd.search(line), "%s:%d: %s" % (p, n, line.strip()))
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "kill" and \
                        getattr(node.func.value, "id", None) == "os":
                    self.assertIn(ast.unparse(node.args[1]), {"0", "signal.SIGSTOP", "signal.SIGCONT"},
                                  "%s: %s" % (p, ast.unparse(node)))

    def test_only_the_pause_stops_and_only_the_record_continues(self):
        stops = []
        for p, text in self.sources():
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "kill" and \
                        getattr(node.func.value, "id", None) == "os":
                    stops.append((os.path.basename(p), ast.unparse(node.args[1])))
        self.assertEqual(sorted(set(stops)), [("mmread.py", "0"), ("mmrecover.py", "signal.SIGCONT"),
                                              ("mmsuper.py", "signal.SIGSTOP")])


if __name__ == "__main__":
    unittest.main()
