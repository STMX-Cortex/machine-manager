# SPDX-License-Identifier: Apache-2.0
"""The platform layer (core/mmplat.py) and Linux backend, with fixture commands and temporary data folders.

1. The choice: MM_PLATFORM, sys.platform, the data folder and the common command surface.
2. The Linux backend's pure parsers on fixture text (/proc/stat, /proc/<pid>/cmdline), and that it loads no ctypes.
3. Every module loads with MM_PLATFORM=linux without macOS bindings. Linux commands never run launchctl;
   dry runs write real Linux readings, and check skips LaunchAgent files. Linux-specific memory, process and
   systemd lifecycle proofs also live in test_linux.py.
4. Fail closed: with no lsof or no ps nothing is deleted, trimmed or paused (on every platform).
Every fixture lives in the test's own temporary folder; the only processes signalled are ones the test started."""
import contextlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import time
import unittest
from unittest import mock

import mmtest
from mmtest import TempData, base_settings, mmcore, mmplat, mmread
import mmdelete
import mmplat_linux
import mmrecover

LINUX = {"MM_PLATFORM": "linux"}
MODULES = sorted(os.path.splitext(n)[0] for d in ("core", "adapters") for n in os.listdir(os.path.join(mmtest.CODE, d))
                 if n.endswith(".py"))


def fixture(name, mode="r"):
    with open(os.path.join(mmtest.FIX, name), mode) as f:
        return f.read()


# ------------------------------------------------------------------------------------------------ 1. the choice

class Choice(unittest.TestCase):
    def test_mm_platform_replaces_sys_platform(self):
        self.assertEqual(mmplat.choose("", "darwin"), "darwin")
        self.assertEqual(mmplat.choose("", "linux"), "linux")
        self.assertEqual(mmplat.choose("", "freebsd14"), "linux", "any other system loads as linux")
        self.assertEqual(mmplat.choose("linux", "darwin"), "linux")
        self.assertEqual(mmplat.choose("darwin", "linux"), "darwin")
        self.assertEqual(mmplat.choose("windows", "darwin"), "darwin", "a value outside NAMES is ignored")

    def test_the_platform_follows_the_environment(self):
        want = mmplat.choose(os.environ.get("MM_PLATFORM", ""), sys.platform)
        self.assertEqual(mmplat.PLATFORM, want)
        self.assertEqual(mmread.plat.__name__, "mmplat_" + want)

    def test_the_linux_data_folder(self):
        with mock.patch.object(mmplat, "DARWIN", False):
            self.assertEqual(mmplat.default_base({}), "~/.local/share/machine-manager")
            self.assertEqual(mmplat.default_base({"XDG_DATA_HOME": "/srv/xdg"}), "/srv/xdg/machine-manager")
            self.assertEqual(mmplat.default_base({"XDG_DATA_HOME": "rel/xdg"}), "~/.local/share/machine-manager",
                             "a relative XDG_DATA_HOME is ignored (XDG spec)")
        with mock.patch.object(mmplat, "DARWIN", True):
            self.assertEqual(mmplat.default_base({"XDG_DATA_HOME": "/srv/xdg"}),
                             "~/Library/Application Support/machine-manager")

    def test_mm_base_still_wins(self):
        with mock.patch.dict(os.environ, {"MM_BASE": "/srv/mm-base"}), mock.patch.object(mmplat, "DARWIN", False):
            self.assertEqual(mmcore.base_dir(), "/srv/mm-base")

    def test_refusal_lines(self):
        with mock.patch.object(mmplat, "DARWIN", True):
            self.assertIsNone(mmplat.refusal("install"))
        with mock.patch.object(mmplat, "DARWIN", False), mock.patch.object(mmplat, "PLATFORM", "linux"):
            for verb in ("install", "rollback", "stop", "start", "restart", "drill"):
                self.assertIsNone(mmplat.refusal(verb), verb)
            for verb in ("run", "status", "check", "watchdog", "hook", "place"):
                self.assertIsNone(mmplat.refusal(verb), verb)


# ------------------------------------------------------------------------------------------------ 2. the Linux backend

class LinuxParsers(unittest.TestCase):
    def test_proc_stat_cpu(self):
        t = mmplat_linux.parse_proc_stat_cpu(fixture("proc-stat.txt"))
        self.assertEqual(t, (4705, 584, 3699176, 356, 23060, 0, 277, 12), "user, system, idle, nice, then the rest")
        self.assertEqual(mmplat_linux.parse_proc_stat_cpu("cpu  1 2 3 4\n"), (1, 3, 4, 2, 0, 0, 0, 0), "an old kernel")
        for bad in ("", "cpu0 1 2 3 4 5\n", "cpu  1 x 3 4\n", "cpu  1 2\n", None):
            self.assertIsNone(mmplat_linux.parse_proc_stat_cpu(bad), repr(bad))

    def test_system_cpu_from_two_linux_readings(self):
        a = mmplat_linux.parse_proc_stat_cpu("cpu  100 0 100 800 0 0 0 0\n")
        b = mmplat_linux.parse_proc_stat_cpu("cpu  150 0 150 850 50 0 0 0\n")  # +50 user, +50 system, +50 idle, +50 io
        self.assertAlmostEqual(mmread.sys_pct(a, b), 25.0)

    def test_proc_stat_btime(self):
        self.assertEqual(mmplat_linux.parse_proc_stat_btime(fixture("proc-stat.txt")), 1792900000.0)
        for bad in ("", "btime\n", "btime x\n", "cpu 1 2 3 4\n", None):
            self.assertIsNone(mmplat_linux.parse_proc_stat_btime(bad), repr(bad))

    def test_cmdline(self):
        self.assertEqual(mmplat_linux.parse_cmdline(fixture("proc-cmdline.bin", "rb")),
                         ["/usr/bin/python3", "-I", "/opt/example/queue/run-queued.py", "--", "go", "test", "./..."])
        self.assertEqual(mmplat_linux.parse_cmdline(b"a\0\0b\0"), ["a", "", "b"], "an empty word stays a word")
        self.assertEqual(mmplat_linux.parse_cmdline(b"no-final-nul"), ["no-final-nul"])
        self.assertEqual(mmplat_linux.parse_cmdline(b"x\xff\0"), ["x\udcff"], "bytes kept as macOS keeps them")
        self.assertIsNone(mmplat_linux.parse_cmdline(b""), "a kernel thread or a zombie")
        self.assertIsNone(mmplat_linux.parse_cmdline(None))

    def test_unknown_readings_and_no_macos_symbols(self):
        self.assertIsNone(mmplat_linux.memory_readings()["comp_mb"])
        self.assertIsNone(mmplat_linux.sysctl_int("hw.ncpu"))
        with mock.patch.object(mmplat_linux, "_read", return_value=None):
            self.assertIsNone(mmplat_linux.swapusage())
        self.assertIsNone(mmplat_linux.vm_stats())
        self.assertGreaterEqual(mmplat_linux.CORES, 1)
        src = fixture(os.path.join(os.pardir, os.pardir, "core", "mmplat_linux.py"))
        for word in ("import ctypes", "_libc", "sysctlbyname", "mach_host_self", "host_statistics"):
            self.assertNotIn(word, src)

    def test_the_backends_carry_the_same_names(self):
        import ast
        names = {}
        for b in ("mmplat_darwin", "mmplat_linux"):
            tree = ast.parse(fixture(os.path.join(os.pardir, os.pardir, "core", b + ".py")))
            got = set()
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    got.add(node.name)
                elif isinstance(node, ast.Assign):
                    for t in node.targets:
                        got.update(e.id for e in (t.elts if isinstance(t, ast.Tuple) else [t]) if isinstance(e, ast.Name))
            names[b] = {n for n in got if not n.startswith("_")}
        for n in ("sysctl_raw", "sysctl_int", "swapusage", "vm_stats", "cpu_ticks", "memory_readings", "proc_argv",
                  "boot_time", "PAGE", "CORES", "PS_ARGV", "PS_ARGS_ARGV", "ps_lstart_argv", "LSOF", "DATA_VOLUME",
                  "COMMAND_READINGS", "KERNEL_LOG", "PMSET", "PANIC_DIR", "USER_TEMP_ARGV", "SERVICE", "EVIDENCE_ARGVS",
                  "banner_argv"):
            self.assertIn(n, names["mmplat_darwin"], n)
            self.assertIn(n, names["mmplat_linux"], n)


# ------------------------------------------------------------------------------------------------ 3. MM_PLATFORM=linux

class LinuxImports(unittest.TestCase):
    def test_every_module_loads_without_ctypes(self):
        code = ("import sys; sys.path[:0] = [%r, %r]\n" % (os.path.join(mmtest.CODE, "core"),
                                                            os.path.join(mmtest.CODE, "adapters")) +
                "for m in %r: __import__(m)\n" % [m for m in MODULES if m != "mmplat_darwin"] +
                "import mmplat, mmread\n"
                "assert mmplat.PLATFORM == 'linux', mmplat.PLATFORM\n"
                "assert mmread.plat.__name__ == 'mmplat_linux'\n"
                "assert 'ctypes' not in sys.modules and 'mmplat_darwin' not in sys.modules, 'a macOS binding loaded'\n"
                "s, _ = mmread.memory_sample(0)\n"
                "assert s['linux'] == 1 and s['comp_mb'] is None and s['seg_pct'] is None, s\n"
                "assert mmread.command_readings() == {} and mmread.check_readings()[0] == []\n"
                "print('ok', len(%r))\n" % MODULES)
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, **LINUX))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertGreaterEqual(len(MODULES), 20)
        self.assertIn("mmplat_linux", MODULES)


class LinuxCli(TempData):
    """`mm` with MM_PLATFORM=linux on this machine's temporary data folder, with a fake launchctl that records calls."""

    def setUp(self):
        super().setUp()
        self.queue_dir()
        self.calls = os.path.join(self.root, "launchctl.txt")
        fake = os.path.join(self.root, "launchctl.sh")
        with open(fake, "w") as f:
            f.write('#!/bin/sh\necho "$@" >> %s\nexit 0\n' % self.calls)
        os.chmod(fake, stat.S_IRWXU)
        self.env = dict(LINUX, MM_LAUNCHCTL=fake)

    def linux(self, *args, timeout=60, **extra):
        return self.mm(*args, env=dict(self.env, **extra), timeout=timeout)

    def assert_no_launchctl(self):
        self.assertFalse(os.path.exists(self.calls), "launchctl ran on linux")

    def test_service_verbs_use_systemd_and_drill_keeps_its_guards(self):
        for args in (["install"], ["stop"], ["start"], ["rollback"]):
            r = self.linux(*args)
            self.assertEqual(r.returncode, 0, (args, r.stdout, r.stderr))
        r = self.linux("drill", "memory")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertTrue(r.stdout.startswith("E_DRILL"), r.stdout)
        self.assert_no_launchctl()
        self.assertFalse(os.path.exists(os.path.join(self.root, "home", "Library")), "no LaunchAgents folder")
        self.assertFalse(os.path.exists(os.path.join(self.root, "base", "install.json")))

    def test_status_without_status_json(self):
        r = self.linux("status")
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertTrue(r.stdout.startswith("E_NO_STATUS no status.json in %s;" % self.data), r.stdout)

    def test_the_linux_data_folder_by_default(self):
        env = dict(os.environ, **self.env)
        for k in ("MM_DATA", "MM_BASE"):
            env.pop(k, None)
        for xdg, want in ((os.path.join(self.root, "xdg"), os.path.join(self.root, "xdg", "machine-manager")),
                          (None, os.path.join(self.root, "home", ".local", "share", "machine-manager"))):
            env.pop("XDG_DATA_HOME", None)
            if xdg:
                env["XDG_DATA_HOME"] = xdg
            r = subprocess.run(mmtest.MM + ["status"], capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(r.returncode, 3, r.stdout)
            self.assertIn("no status.json in %s;" % os.path.join(want, "profile-test"), r.stdout)

    def test_a_dry_run_writes_status_json(self):
        r = self.linux("run", "--dry-run", "--ticks", "2", "--tick-seconds", "0.1", timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = mmcore.read_json(os.path.join(self.data, "status.json"), None)
        self.assertIsInstance(st, dict)
        self.assertEqual(st["mode"], "dry")
        self.assertEqual(st["heartbeat"]["tick"], 2)
        self.assertIn(st["state"], ("UNKNOWN", "GREEN", "STEADY", "AMBER", "RED"))
        for k in ("comp_mb",):
            self.assertIsNone(st["readings"][k], k)
        self.assertEqual(st["sampler"], "fast", "no fallback sampler on linux")
        active = (mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {}) or {}).get("active") or {}
        names = {a.get("name") for a in active.values()}
        self.assertNotIn("READINGS_MISMATCH", names)
        self.assertNotIn("POWER", names)
        texts = " ".join(a.get("text") or "" for a in active.values())
        self.assertNotIn("log stream", texts, "no kernel stream is started, so none is stale")
        ctl = mmcore.read_json(os.path.join(self.data, "state", "controller.json"), {}) or {}
        self.assertEqual((ctl.get("readings_check") or {}).get("problems"), [])
        r = self.linux("status")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("free_pct=", r.stdout)
        self.assert_no_launchctl()

    def test_check_names_the_platform(self):
        # an installed-looking LaunchAgent with a wrong ExitTimeOut: macOS reports E_PLIST, linux never reads it
        agents = os.path.join(self.root, "home", "Library", "LaunchAgents")
        os.makedirs(agents)
        import plistlib
        with open(os.path.join(agents, "com.example.machine-manager-test.plist"), "wb") as f:
            plistlib.dump({"Label": "x", "ExitTimeOut": 5, "EnvironmentVariables": {"PATH": "/nonexistent"}}, f)
        r = self.linux("check")
        out = r.stdout.strip().splitlines()
        self.assertFalse(any(l.startswith("W_PLATFORM linux runs in a reduced form") for l in out), out)
        self.assertFalse([l for l in out if l.startswith(("E_PLIST", "E_READINGS"))], out)
        self.assertEqual(r.returncode, 0, out)
        self.assertEqual(out[-1], "check=ok")
        self.assert_no_launchctl()

    def test_the_watchdog_restarts_nothing(self):
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": time.time() - 3600}))
        r = self.linux("watchdog")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("status.json", r.stdout)
        self.assert_no_launchctl()
        active = (mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {}) or {}).get("active") or {}
        self.assertIn("SELF_STALE", {a.get("name") for a in active.values()}, "a stale supervisor is still said")


class LinuxSkips(TempData):
    """In process, with the Linux backend swapped in: the macOS-only parts are skipped with an unknown result."""

    def test_skipped_parts(self):
        import ad_deliver_claude
        import mmevidence
        import mminstall
        import mmsuper
        with mock.patch.object(mmread, "plat", mmplat_linux), mock.patch.object(mmrecover, "PANIC_DIR", None), \
                mock.patch.dict(os.environ, {"MM_BANNER_CMD": ""}), \
                mock.patch.object(mmread, "run", return_value=(None, "")) as run:
            self.assertFalse(ad_deliver_claude.banner("ACTION MEM_RED x", True), "no osascript")
            self.assertEqual(mminstall.launchctl(["print", "x"]), (None, ""))
            self.assertIsNone(mmrecover.panic_names())
            self.assertEqual(mmdelete.user_tmp(), os.path.realpath(__import__("tempfile").gettempdir()).rstrip("/"))
            sup = mmsuper.Supervisor(self.profile(), dry_run=True, kernel=True, sizes=False, slow_jobs=False,
                                     sampler=lambda t, p: ({"t": t}, None), boot=lambda: {"boot_time": None})
            self.assertIsNone(sup.kernel, "no log stream")
            d = mmevidence.bundle({"key": "X", "name": "X", "level": "ATTENTION", "text": "t"}, self.s(), time.time())
            with open(os.path.join(d, "readings.txt")) as f:
                self.assertIn("skipped", f.read())
            self.assertEqual([c for c in run.call_args_list if c.args and c.args[0] and c.args[0][0] in (
                "/usr/bin/osascript", "/bin/launchctl", "/usr/bin/getconf", "/usr/bin/vm_stat", "/usr/bin/pmset")], [])


# ------------------------------------------------------------------------------------------------ 4. fail closed

def old_tree(path):
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "a.o"), "w") as f:
        f.write("x" * 4096)
    old = time.time() - 30 * 86400
    for d, dirs, files in os.walk(path):
        for n in dirs + files:
            os.utime(os.path.join(d, n), (old, old))
    os.utime(path, (old, old))
    return path


class FailClosedDeletes(TempData):
    """No lsof, a failing lsof or no process list: the delete guard keeps everything (deletes on)."""

    def run_rules(self, rules, procs=lambda: []):
        ctx = mmdelete.Ctx({"rules": rules}, extra={"t": self.root, "user_tmp": self.root}, data=self.data)
        r = mmdelete.Run(base_settings(**{"deletes.lsof_timeout_s": 30}), ctx, enabled=True, procs=procs,
                         live_spec={"names": ["go"]}, mid="m1")
        r.all()
        return r

    def folders_rule(self):
        base = os.path.join(self.root, "scratch")
        old_tree(os.path.join(base, "item-1"))
        os.utime(base, (time.time() - 30 * 86400,) * 2)
        return base, {"id": "S1", "type": "folders", "roots": [base], "patterns": ["item-*"], "age_minutes": 60}

    def test_no_lsof_keeps(self):
        base, rule = self.folders_rule()
        for lsof, why in ((None, "lsof not available"), (os.path.join(self.root, "no-such-lsof"), "lsof failed")):
            with mock.patch.object(mmread.plat, "LSOF", lsof):
                r = self.run_rules([rule])
            self.assertTrue(os.path.isdir(os.path.join(base, "item-1")), lsof)
            self.assertFalse([l for l in r.lines if " DELETE " in l], r.lines)
            self.assertTrue(any(" KEEP " in l and why in l for l in r.lines), r.lines)

    def test_a_failing_lsof_keeps(self):
        base, rule = self.folders_rule()
        bad = os.path.join(self.root, "bad-lsof")
        with open(bad, "w") as f:
            f.write("#!/bin/sh\nexit 7\n")
        os.chmod(bad, 0o700)
        with mock.patch.object(mmread.plat, "LSOF", bad):
            r = self.run_rules([rule])
        self.assertTrue(os.path.isdir(os.path.join(base, "item-1")))
        self.assertTrue(any(" KEEP " in l and "lsof rc=7" in l for l in r.lines), r.lines)

    def test_no_process_list_keeps_a_live_tools_rule(self):
        cache = os.path.join(self.root, "cache")
        old_tree(os.path.join(cache, "0b"))
        rule = {"id": "S5", "type": "cache_entries", "cache": cache, "age_minutes": 60, "no_live_tools": True}
        r = self.run_rules([rule], procs=lambda: None)
        self.assertTrue(os.path.exists(os.path.join(cache, "0b", "a.o")), r.lines)
        self.assertFalse([l for l in r.lines if " DELETE " in l], r.lines)
        self.assertTrue(any(" KEEP " in l and "live_tools=ps failed" in l for l in r.lines), r.lines)

    def test_no_process_list_keeps_an_apps_while_closed_folders(self):
        base = os.path.join(self.root, "App")
        old_tree(os.path.join(base, "Derived", "proj-1"))
        rule = {"id": "S6", "type": "app_folders", "app": "AppX", "base": base,
                "while_closed": {"dir": "Derived", "age_minutes": 60}}
        r = self.run_rules([rule], procs=lambda: None)
        self.assertTrue(os.path.isdir(os.path.join(base, "Derived", "proj-1")), r.lines)
        self.assertTrue(any(" KEEP " in l and "ps failed: AppX may be running" in l for l in r.lines), r.lines)
        r = self.run_rules([rule], procs=lambda: [])  # a list without the app: the app is closed, the folder goes
        self.assertFalse(os.path.isdir(os.path.join(base, "Derived", "proj-1")), r.lines)

    def test_no_process_list_refuses_the_trim(self):
        import cachetrim
        cache = os.path.join(self.root, "gocache")
        old_tree(os.path.join(cache, "0b"))
        log = os.path.join(self.root, "deletes.log")
        with mock.patch.object(mmread, "read_ps", lambda: None), contextlib.redirect_stdout(io.StringIO()) as out:
            rc = cachetrim.main(["--cache", cache, "--age", "1", "--wait", "0", "--poll", "0", "--log", log,
                                 "--live", json.dumps({"names": ["go"]}), "--machine", "m1"])
        self.assertEqual(rc, 3)
        self.assertIn("refused live_tools=ps failed", out.getvalue())
        self.assertTrue(os.path.exists(os.path.join(cache, "0b", "a.o")))
        self.assertIn("live_tools=ps failed", open(log).read())


class FailClosedReads(unittest.TestCase):
    def test_missing_commands_read_as_unknown(self):
        with mock.patch.object(mmread.plat, "LSOF", None):
            self.assertIsNone(mmread.file_writers("/dev/null", 5))
            self.assertIsNone(mmread.proc_cwd(os.getpid(), 5))
        with mock.patch.object(mmread.plat, "PS_ARGV", None):
            self.assertIsNone(mmread.read_ps())
        with mock.patch.object(mmread.plat, "PS_ARGV", ["/nonexistent/ps", "-axo", "pid="]):
            self.assertIsNone(mmread.read_ps())
        if mmread.plat.SERVICE == "systemd":
            with mock.patch.object(mmread.plat, "proc_start", lambda pid: None):
                self.assertIsNone(mmrecover.start_time(os.getpid()))
        else:
            with mock.patch.object(mmread.plat, "ps_lstart_argv", lambda pid: None):
                self.assertIsNone(mmrecover.start_time(os.getpid()))
        with mock.patch.object(mmread.plat, "PS_ARGS_ARGV", None):
            self.assertEqual(mmrecover.missing_jobs([{"name": "x", "match": "x"}]), ["(ps failed)"])


sys.path.insert(0, mmtest.HERE)
import test_sandbox_holds_r2 as r2  # noqa: E402
sys.path.insert(0, mmtest.BIN)


class FailClosedPause(r2.Stepped):
    """With no lsof the pause cannot see the slot's write openers: it refuses, and signals nothing."""

    def setUp(self):
        super().setUp()
        self.settings()

    def test_no_lsof_pauses_nothing(self):
        call = self.call_of(["/bin/sleep", "300"])
        sup = self.supervisor()
        self.step(sup)
        self.red = True
        with mock.patch.object(mmread.plat, "LSOF", None):
            self.step(sup, n=2)
        self.assertEqual([pid for pid, sig in self.signals if sig == signal.SIGSTOP], [])
        self.assertFalse(self.stopped(call.pid))
        self.assertEqual(mmrecover.read_paused(), {})
        refused = [a for a in r2.tsh.alert_records(self.data) if a.get("name") == "PAUSE_REFUSED"]
        self.assertTrue(refused and "lsof failed" in refused[0].get("text", ""), refused)


if __name__ == "__main__":
    unittest.main()
