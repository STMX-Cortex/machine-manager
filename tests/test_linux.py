# SPDX-License-Identifier: Apache-2.0
"""Linux memory, process identity and systemd lifecycle, without changing a real service."""
import json
import os
from pathlib import Path
import signal
import shutil
import shlex
import subprocess
import sys
import unittest
from unittest import mock

import mmtest
from mmtest import TempData, base_settings, mmcore, mmread
import mmdecide
import mminstall
import mmplat_linux as linux
import mmrecover
import mmsuper
import mmsystemd

MEM = "MemTotal: 1024000 kB\nMemAvailable: 819200 kB\nSwapTotal: 204800 kB\nSwapFree: 102400 kB\n"
PSI = "some avg10=0.50 avg60=0.20 avg300=0.10 total=10\nfull avg10=0.10 avg60=0.05 avg300=0.01 total=1\n"


def sample(**kw):
    return dict(linux.parse_memory(MEM, PSI), t=1000, load1=1, load5=1, sys_pct=1, **kw)


class Memory(unittest.TestCase):
    def test_available_memory_swap_and_inapplicable_compressor(self):
        got = linux.parse_memory(MEM, PSI)
        self.assertEqual(got["free_pct"], 80)
        self.assertEqual((got["swap_total_mb"], got["swap_used_mb"]), (200, 100))
        self.assertIsNone(got["comp_mb"])
        self.assertIsNone(got["seg_pct"])

    def test_bad_memory_never_becomes_healthy(self):
        for text in ("", MEM.replace("819200", "9999999"), MEM.replace("819200", "-1"), MEM.replace(" kB", " MB")):
            self.assertIsNone(linux.parse_memory(text, PSI)["free_pct"], text)
        self.assertIsNone(linux.parse_memory(MEM.replace("102400 kB", "999999 kB"), PSI)["swap_used_mb"])

    def test_swap_disabled_is_valid(self):
        s = linux.parse_memory(MEM.replace("204800", "0").replace("102400 kB", "0 kB"), PSI)
        self.assertEqual((s["swap_total_mb"], s["swap_used_mb"]), (0, 0))

    def test_psi_normal_warning_critical_and_invalid(self):
        settings = base_settings()
        for some, full, state in ((0, 0, "GREEN"), (12, 0, "AMBER"), (12, 11, "RED")):
            s = dict(sample(), psi_some_pct=some, psi_full_pct=full)
            result = mmdecide.classify([s], settings, disk_gb=100)
            self.assertEqual((result[0], result[2]), (state, True), result)
        for bad in ("nan", "inf", "-1", "101", "oops"):
            self.assertNotIn("some", linux.parse_psi("some avg10=" + bad))

    def test_supported_but_unreadable_psi_blocks_automation(self):
        s = dict(sample(), psi_some_pct=None)
        normalized = mmdecide.linux_sample(s, base_settings())
        self.assertIn("pressure missing", mmdecide.sample_problems(normalized))
        self.assertFalse(mmdecide.classify([s], base_settings())[2])
        self.assertFalse(mmsuper.memory_readings_present(True, normalized))

    def test_kernel_without_psi_has_no_fabricated_reading(self):
        s = dict(sample(), psi_supported=0, psi_some_pct=None, psi_full_pct=None)
        self.assertEqual(mmdecide.sample_problems(s), [])
        self.assertTrue(mmdecide.classify([s], base_settings(), disk_gb=100)[2])
        self.assertIsNone(s["pressure"])
        self.assertTrue(mmsuper.memory_readings_present(True, s))

    def test_missing_memory_blocks_pause_release(self):
        s = mmdecide.linux_sample(dict(sample(), free_pct=None), base_settings())
        self.assertFalse(mmdecide.classify([s], base_settings())[2])
        self.assertFalse(mmsuper.pause_readings_present(False, [s]))

    def test_cgroup_limit_uses_tightest_ancestor_and_room(self):
        files = {"/proc/self/cgroup": b"0::/a/b\n",
                 "/proc/self/mountinfo": b"1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
                 "/sys/fs/cgroup/memory.max": b"max",
                 "/sys/fs/cgroup/a/b/memory.max": b"104857600",
                 "/sys/fs/cgroup/a/b/memory.current": b"10485760", "/sys/fs/cgroup/a/memory.max": b"209715200",
                 "/sys/fs/cgroup/a/memory.current": b"199229440"}
        with mock.patch.object(linux, "_read", side_effect=lambda p, *a: files.get(p)):
            self.assertEqual(linux.cgroup_memory(), (100, 10))
        files["/sys/fs/cgroup/a/memory.current"] = None
        with mock.patch.object(linux, "_read", side_effect=lambda p, *a: files.get(p)):
            self.assertEqual(linux.cgroup_memory(), (100, None))

    def test_cgroup_availability_and_facts_agree(self):
        files = {"/proc/meminfo": MEM.encode(), "/proc/pressure/memory": PSI.encode()}
        with mock.patch.object(linux, "_read", side_effect=lambda p, *a: files.get(p)), \
                mock.patch.object(linux, "cgroup_memory", return_value=(100, 5)):
            self.assertEqual(linux.memory_readings()["free_pct"], 5)
            self.assertEqual(linux.machine_facts()["ram_mb"], 100)

    def test_cgroup_delegated_mount_and_zero_or_bad_bounds(self):
        files = {"/proc/self/cgroup": b"0::/delegated/child\n",
                 "/proc/self/mountinfo": b"1 0 0:1 /delegated /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
                 "/sys/fs/cgroup/memory.max": b"max", "/sys/fs/cgroup/child/memory.current": b"10"}
        for value, expected in ((b"104857600", (100, (104857600-10)/2**20)), (b"0", (0, 0)),
                                (b"broken", (0, None)), (None, (0, None))):
            files["/sys/fs/cgroup/child/memory.max"] = value
            with mock.patch.object(linux, "_read", side_effect=lambda p, *a: files.get(p)):
                self.assertEqual(linux.cgroup_memory(), expected)

    def test_cgroup_v1_memory_limit(self):
        files = {"/proc/self/cgroup": b"5:memory:/job\n",
                 "/proc/self/mountinfo": b"1 0 0:1 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
                 "/sys/fs/cgroup/memory/memory.limit_in_bytes": str(1 << 62).encode(),
                 "/sys/fs/cgroup/memory/job/memory.limit_in_bytes": b"104857600",
                 "/sys/fs/cgroup/memory/job/memory.usage_in_bytes": b"94371840"}
        with mock.patch.object(linux, "_read", side_effect=lambda p, *a: files.get(p)):
            self.assertEqual(linux.cgroup_memory(), (100, 10))

    def test_hybrid_cgroup_uses_the_v1_memory_controller(self):
        files = {"/proc/self/cgroup": b"0::/unified\n5:memory:/limited\n",
                 "/proc/self/mountinfo": b"1 0 0:1 / /sys/fs/cgroup/unified rw - cgroup2 cgroup rw\n"
                                         b"2 0 0:2 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
                 "/sys/fs/cgroup/memory/memory.limit_in_bytes": str(1 << 62).encode(),
                 "/sys/fs/cgroup/memory/limited/memory.limit_in_bytes": b"104857600",
                 "/sys/fs/cgroup/memory/limited/memory.usage_in_bytes": b"94371840"}
        with mock.patch.object(linux, "_read", side_effect=lambda p, *a: files.get(p)), \
                mock.patch.object(linux.os.path, "isdir", return_value=True), \
                mock.patch.object(linux.os.path, "lexists", return_value=False):
            self.assertEqual(linux.cgroup_memory(), (100, 10))

    def test_full_mount_keeps_parent_limit_when_subtree_is_also_mounted(self):
        files = {"/proc/self/cgroup": b"0::/parent/job\n",
                 "/proc/self/mountinfo": b"1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n2 0 0:1 /parent/job /view rw - cgroup2 cgroup rw\n",
                 "/sys/fs/cgroup/memory.max": b"max", "/sys/fs/cgroup/parent/job/memory.max": b"max",
                 "/sys/fs/cgroup/parent/memory.max": b"104857600", "/sys/fs/cgroup/parent/memory.current": b"94371840",
                 "/view/memory.max": b"max"}
        with mock.patch.object(linux, "_read", side_effect=lambda p, *a: files.get(p)):
            self.assertEqual(linux.cgroup_memory(), (100, 10))


class Processes(unittest.TestCase):
    def test_start_ticks_ignore_spaces_and_parentheses_in_comm(self):
        text = "123 (long ) name) S " + " ".join(["0"] * 18 + ["987654", "0"])
        self.assertEqual(linux.parse_proc_start(text), "987654")
        for bad in ("", "123 (x) S", None):
            self.assertIsNone(linux.parse_proc_start(bad))

    @unittest.skipUnless(sys.platform == "linux", "requires real /proc")
    def test_current_process_identity_is_stable(self):
        first = linux.proc_start(os.getpid())
        self.assertTrue(first.startswith("linux:"), first)
        self.assertEqual(first, linux.proc_start(os.getpid()))
        self.assertIsNone(linux.proc_start(2**30))

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "pidfds unavailable")
    def test_pidfd_rechecks_identity_before_signalling(self):
        with mock.patch.object(linux, "proc_start", return_value="new"), \
                mock.patch.object(signal, "pidfd_send_signal") as send:
            with self.assertRaises(ProcessLookupError):
                linux.signal_process(os.getpid(), "old", signal.SIGSTOP)
            send.assert_not_called()

    def test_truncated_name_cannot_hide_live_tool(self):
        p = {"pid": 1, "comm": "very-long-build", "name_truncated": True}
        self.assertEqual(mmread.live_named([p], {"names": ["very-long-build-tool"]}), [p])

    def test_readable_executable_does_not_hide_a_truncated_test_alias(self):
        with mock.patch.object(mmread, "plat", linux), \
                mock.patch.object(mmread, "run", return_value=(0, "123 1 1024 0.0 very-long-build\n")), \
                mock.patch.object(linux, "proc_start", return_value="birth"), \
                mock.patch.object(linux, "proc_parent", return_value=1), \
                mock.patch.object(linux, "proc_exe", return_value="/usr/bin/sleep"):
            procs = mmread.read_ps()
        self.assertTrue(procs[0]["alias_truncated"])
        for spec in ({"suffixes":[".test"]}, {"path_regexes":[r"/build/.+\.test$"]}):
            self.assertEqual([p["pid"] for p in mmread.live_named(procs, spec)], [123], spec)


class Services(TempData):
    def setUp(self):
        super().setUp()
        self.queue_dir()
        self.calls = Path(self.root) / "systemctl.jsonl"
        fake = Path(self.root) / "systemctl.py"
        fake.write_text('#!' + sys.executable + '\nimport json, os, sys\n'
                        'with open(' + repr(str(self.calls)) + ', "a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
                        'if os.environ.get("FAIL_SYSTEMCTL") == sys.argv[2]: sys.exit(7)\n'
                        'if sys.argv[2] == "enable" and sys.argv[-1].endswith("-test.service"):\n'
                        ' import time\n'
                        ' with open(os.path.join(os.environ["MM_DATA"], "status.json"), "w") as f:\n'
                        '  json.dump({"time":time.time(),"heartbeat":{"pid":time.time_ns(),"tick":1}}, f)\n')
        fake.chmod(0o700)
        self.env = {"MM_PLATFORM": "linux", "MM_SYSTEMCTL": str(fake)}

    def linux(self, *args, **env):
        return self.mm(*args, env=dict(self.env, **env))

    def recorded(self):
        return [json.loads(x) for x in self.calls.read_text().splitlines()]

    def test_install_restart_stop_start_rollback(self):
        r = self.linux("install")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        folder = Path(os.environ["XDG_CONFIG_HOME"]) / "systemd/user"
        sup = folder / "com.example.machine-manager-test.service"
        wd = folder / "com.example.machine-manager-test-watchdog.service"
        timer = wd.with_suffix(".timer")
        self.assertTrue(all(p.is_file() for p in (sup, wd, timer)))
        self.assertIn("Restart=always", sup.read_text())
        self.assertIn("recover-paused", sup.read_text())
        self.assertIn("OnUnitActiveSec=60s", timer.read_text())
        self.assertIn('"--allow-live-slots"', sup.read_text())
        for verb in ("restart", "stop", "start", "rollback"):
            r = self.linux(verb)
            self.assertEqual(r.returncode, 0, (verb, r.stdout, r.stderr))
        self.assertFalse(any(p.exists() for p in (sup, wd, timer)))
        calls = self.recorded()
        self.assertTrue(all(x[0] == "--user" for x in calls))
        self.assertIn(["--user", "daemon-reload"], calls)
        self.assertIn(["--user", "enable", "--now", timer.name], calls)
        self.assertFalse(os.path.exists(os.path.join(self.root, "home", "Library")))

    def test_unavailable_manager_changes_no_units(self):
        r = self.linux("install", FAIL_SYSTEMCTL="show-environment")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("systemd user manager unavailable", r.stdout)
        self.assertFalse((Path(os.environ["XDG_CONFIG_HOME"]) / "systemd/user").exists())

    def test_units_preserve_install_record_and_unit_directory_overrides(self):
        self.assertEqual(self.linux("install").returncode, 0)
        folder = Path(os.environ["XDG_CONFIG_HOME"]) / "systemd/user"
        unit = folder / "com.example.machine-manager-test.service"
        env = {"HOME": os.environ["HOME"]}
        for line in unit.read_text().splitlines():
            if line.startswith("Environment="):
                key, value = shlex.split(line.split("=", 1)[1])[0].split("=", 1)
                env[key] = value
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(mmsystemd.directory(), str(folder))
            self.assertEqual(mmcore.install_record()["data"], self.data)

    def test_failed_enable_is_reported_and_can_be_rolled_back(self):
        r = self.linux("install", FAIL_SYSTEMCTL="enable")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("E_INSTALL load failed", r.stdout)
        self.assertEqual(self.linux("rollback").returncode, 0)

    def test_failed_stop_preserves_installed_files(self):
        self.assertEqual(self.linux("install").returncode, 0)
        folder = Path(os.environ["XDG_CONFIG_HOME"]) / "systemd/user"
        before = {p.name:p.read_text() for p in folder.iterdir() if p.suffix in (".service", ".timer")}
        for verb in ("install", "rollback", "stop"):
            r = self.linux(verb, FAIL_SYSTEMCTL="disable")
            self.assertEqual(r.returncode, 2, (verb, r.stdout))
            self.assertIn("E_STOP", r.stdout)
            self.assertEqual({p.name:p.read_text() for p in folder.iterdir() if p.suffix in (".service", ".timer")}, before)

    def test_service_label_ending_in_watchdog_is_still_a_service(self):
        folder = Path(os.environ["XDG_CONFIG_HOME"]) / "systemd/user"
        folder.mkdir(parents=True)
        (folder / "custom-watchdog.service").write_text("[Service]\n")
        self.assertEqual(mmsystemd.unit("custom-watchdog"), "custom-watchdog.service")

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze unavailable")
    def test_generated_unit_syntax(self):
        self.assertEqual(self.linux("install").returncode, 0)
        folder = Path(os.environ["XDG_CONFIG_HOME"]) / "systemd/user"
        files = [str(p) for p in folder.iterdir() if p.suffix in (".service", ".timer")]
        result = subprocess.run(["systemd-analyze", "verify", *files], text=True, capture_output=True, timeout=30)
        if "Operation not permitted" in result.stderr:
            self.skipTest("systemd-analyze requires local sockets outside the command sandbox")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_quoting_is_literal_and_single_line(self):
        got = mmsystemd.command(['/a b/x%"$\\\n', "two words"])
        self.assertNotIn("\n", got)
        self.assertIn("%%", got)
        self.assertIn("$$", got)
        self.assertIn('\\"', got)

    def test_invalid_label_cannot_escape_unit_directory(self):
        for label in ("../bad", "x\ny", "bad/name", "-bad"):
            with self.assertRaises(mmcore.MMError):
                mmsystemd.valid_label(label)

    def test_watchdog_uses_user_service_restart(self):
        mmcore.write_atomic(mmcore.path("status.json"), json.dumps({"time": 1}))
        r = self.linux("watchdog")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(["--user", "restart", "com.example.machine-manager-test.service"], self.recorded())

    def test_reused_opener_is_not_adopted_for_a_pause(self):
        import ad_queue_fifo
        queue = ad_queue_fifo.Queue(self.profile()["queue"])
        slot = queue.slot_file(".slot.0")
        Path(slot).write_text("fixture")
        with mock.patch.object(mmread, "file_writers", return_value=[123]), \
                mock.patch.object(mmread.plat, "proc_interpreter", return_value=True, create=True), \
                mock.patch.object(queue, "runs_launcher", return_value=True), \
                mock.patch.object(mmsuper.Pauser, "start_time", side_effect=["old", "old", "new"]), \
                mock.patch.object(mmread, "read_ps", return_value=[{"pid":123,"ppid":1,"start_time":"old"}]), \
                mock.patch.object(mmrecover, "signal_process") as send:
            got = mmsuper.Pauser().pause([{"since":1,"slot":".slot.0"}], queue, 5)
            self.assertEqual(got["paused"], [])
            send.assert_not_called()
            self.assertEqual(mmrecover.read_paused(), {})

    @unittest.skipUnless(sys.platform == "linux", "requires real /proc descriptors")
    def test_opener_reused_before_birth_capture_must_still_hold_the_slot(self):
        import ad_queue_fifo
        queue = ad_queue_fifo.Queue(self.profile()["queue"])
        Path(queue.slot_file(".slot.0")).write_text("fixture")
        with mock.patch.object(mmread, "file_writers", side_effect=[[123], []]), \
                mock.patch.object(mmread.plat, "proc_interpreter", return_value=True, create=True), \
                mock.patch.object(queue, "runs_launcher", return_value=True), \
                mock.patch.object(mmsuper.Pauser, "start_time", return_value="replacement"), \
                mock.patch.object(mmread, "read_ps", return_value=[{"pid":123,"ppid":1,"start_time":"replacement"}]), \
                mock.patch.object(mmrecover, "signal_process") as send:
            got = mmsuper.Pauser().pause([{"since":1,"slot":".slot.0"}], queue, 5)
        self.assertEqual(got["paused"], [])
        self.assertEqual(got["refused"], [123])
        send.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "requires real /proc descriptors")
    def test_lsof_uses_a_pinned_slot_when_the_path_is_replaced(self):
        import ad_queue_fifo
        queue = ad_queue_fifo.Queue(self.profile()["queue"])
        slot = Path(queue.slot_file(".slot.0"))
        slot.write_text("original")
        seen = []
        def writers(query, timeout):
            seen.append(Path(query).read_text())
            if len(seen) == 1:
                slot.unlink()
                slot.write_text("replacement")
            return [123]
        with mock.patch.object(mmread, "file_writers", side_effect=writers), \
                mock.patch.object(mmread.plat, "proc_interpreter", return_value=True, create=True), \
                mock.patch.object(queue, "runs_launcher", return_value=True), \
                mock.patch.object(mmsuper.Pauser, "start_time", return_value="birth"), \
                mock.patch.object(mmrecover, "signal_process") as send:
            got = mmsuper.Pauser().pause([{"since":1,"slot":".slot.0"}], queue, 5)
        self.assertEqual(seen, ["original", "original"])
        self.assertIn("slot changed", got["failed"])
        send.assert_not_called()

    def test_linux_readings_do_not_enter_safe_mode_for_missing_compressor(self):
        now = [1000]
        def sampler(t, prev):
            return dict(sample(), t=t, psi_supported=0, psi_some_pct=None, psi_full_pct=None), None
        sup = mmsuper.Supervisor(self.profile(), dry_run=True, kernel=False, sizes=False, slow_jobs=False,
                                 clock=lambda:now[0], sampler=sampler, boot=lambda:{"boot_time":None})
        for _ in range(8):
            sup.tick()
            now[0] += 10
        self.assertEqual(sup.reading_problems, [])
        self.assertIsNone(mmcore.safe_state())

    def test_check_notices_changed_timer_interval(self):
        self.assertEqual(self.linux("install").returncode, 0)
        timer = Path(os.environ["XDG_CONFIG_HOME"]) / "systemd/user/com.example.machine-manager-test-watchdog.timer"
        timer.write_text(timer.read_text().replace("OnUnitActiveSec=60s", "OnUnitActiveSec=90s"))
        with mock.patch.object(mmread, "plat", linux):
            messages = mminstall.watchdog_interval_lines(self.profile(), self.s())
        self.assertEqual(len(messages), 1)
        self.assertIn("OnUnitActiveSec is 90", messages[0])


if __name__ == "__main__":
    unittest.main()
