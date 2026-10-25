# SPDX-License-Identifier: Apache-2.0
"""`mm resources` and what it reads: the verb on a temporary data folder (lines, --json, exits 0, 2 and 3), files only
(no child process, no fork, fast, no mmread), the tick-error status.json, the static facts (the Linux parsers on
fixtures, macOS machine_facts on a patched sysctl), cpu_pct, the runner list and its safe failure (a fake gh), the
pool record's alerts, queue_idle as the IDLE_ROOM rule, and the schemas of the new status and pool fields."""
import contextlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import time
import unittest
from importlib.machinery import SourceFileLoader
from unittest import mock

import mmtest
from mmtest import TempData, base_settings, mmcore, mmread
import ad_ci_github
import ad_deliver_claude
import mmalerts
import mmdecide
import mmplat_linux
import mmschema
import mmsuper


def fixture(name):
    with open(os.path.join(mmtest.FIX, name)) as f:
        return f.read()


def load_cli():
    """bin/mm as a module (its main() runs a verb in this process)."""
    path = os.path.join(mmtest.BIN, "mm")
    loader = SourceFileLoader("mm_cli_resources", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


FACTS = {"cores": 12, "p_cores": 8, "e_cores": 4, "cpu_model": "Example M1 Pro", "ram_mb": 32768, "disk_gb_total": 994.7}


def status_rec(now, **over):
    rec = mmcore.stamp({
        "kind": "machine", "time": now, "state": "GREEN", "reasons": ["all readings in the green band"],
        "red_since": None, "mode": "observe", "slots": 6, "slots_would": 6, "busy": 3, "waiting": 0,
        "readings": {"free_pct": 50, "swap_used_mb": 100.0, "swap_total_mb": 2048.0, "comp_mb": 300.0, "pressure": 1,
                     "load5": 2.0, "sys_pct": 8.0, "cpu_pct": 41.27},
        "disk_gb": 210.4, "sampler": "fast", "alerts": {"ACTION": 0, "ATTENTION": 0, "INFO": 0}, "facts": FACTS,
        "calls": 2, "idle_minutes": None, "heartbeat": {"pid": 1, "tick": 3, "note": "ok"}}, mid="lab1")
    rec.update(over)
    return rec


def pool_rec(now, **over):
    rec = mmcore.stamp({
        "kind": "pool", "time": now, "state": "GREEN", "reasons": ["budget and queue fine"],
        "capacity": {"minutes_left": 1234.5, "reserve_minutes": 300, "unit": "minutes"},
        "money": {"used_usd": 0.0, "allowed_usd": 0}, "load": {"running": 2, "queued": 1}, "alerts": [],
        "read_time": now - 60,
        "runners": [{"name": "build-1", "online": True, "busy": False, "labels": ["self-hosted", "lab"]},
                    {"name": "build 2\x07", "online": True, "busy": True, "labels": ["self-hosted", "lab"]},
                    {"name": "build-3", "online": False, "busy": False, "labels": ["self-hosted", "lab"]}]},
        mid="ci:example/project")
    rec.update(over)
    return rec


def usage_state(now):
    return {"checked_at": now - 60, "max_age_seconds": 1800,
            "levels": {"claude_5h": {"used_percent": 41.0, "status": "ok", "read_at": now - 60, "reset_at": now + 3600},
                       "claude_weekly": {"used_percent": 63.5, "status": "ok", "read_at": now - 60,
                                         "reset_at": now + 86400},
                       "codex_5h": {"status": "not_offered"},
                       "codex_weekly": {"used_percent": 20, "status": "error", "read_at": now - 60}}}


class Verb(TempData):
    def write(self, name, obj):
        os.makedirs(os.path.dirname(os.path.join(self.data, name)), exist_ok=True)
        with open(os.path.join(self.data, name), "w") as f:
            json.dump(obj, f)

    def files(self, now, **status):
        self.write("status.json", status_rec(now, **status))
        self.write("pools/ci_example_project.json", pool_rec(now))
        self.write("usage.json", usage_state(now))

    def test_lines_json_and_exit_codes(self):
        now = time.time()
        self.files(now)
        r = self.mm("resources")
        self.assertEqual((r.returncode, r.stderr), (0, ""), r.stdout)
        lines = r.stdout.splitlines()
        self.assertEqual([l.split()[0] for l in lines], ["resource=machine", "resource=pool"] + ["resource=runner"] * 3 +
                         ["resource=service"] * 2)
        self.assertTrue(lines[0].startswith("resource=machine id=lab1 location=local state=GREEN cores=12 p_cores=8 "
                                            'e_cores=4 cpu_model="Example M1 Pro" ram_mb=32768 ram_avail_mb=16384 '
                                            "disk_gb_total=994.7 disk_free_gb=210.4 cpu_pct=41.3 slots=6 busy=3 calls=2 "
                                            "waiting=0 idle=no idle_min=none age_s="), lines[0])
        self.assertTrue(lines[1].startswith("resource=pool id=ci:example/project location=cloud state=GREEN unit=minutes "
                                            "minutes_left=1234.5 reserve_minutes=300 used_usd=0 allowed_usd=0 running=2 "
                                            "queued=1 read_age_s=6"), lines[1])
        self.assertIn("id=build-1 pool=ci:example/project location=self-hosted state=GREEN online=yes busy=no", lines[2])
        self.assertIn('id="build 2?" pool=ci:example/project location=self-hosted state=STEADY', lines[3],
                      "an outside name shows cleaned and quoted")
        self.assertIn("id=build-3 pool=ci:example/project location=self-hosted state=RED online=no", lines[4])
        self.assertRegex(lines[5], r"^resource=service id=claude location=cloud used_5h_pct=41 reset_5h=\d+ "
                                   r"used_week_pct=63.5 reset_week=\d+ age_s=6\d fresh=yes state=none$")
        self.assertRegex(lines[6], r'^resource=service id=codex location=cloud used_week_pct=none reset_week=none '
                                   r'age_s=6\d fresh=yes state=UNKNOWN why="codex_weekly: status error"$')
        self.assertNotIn("used_5h_pct", lines[6], "a level the plan does not offer is left out")
        for line in lines:
            self.assertNotIn("\x07", line)
        j = self.mm("resources", "--json")
        self.assertEqual(j.returncode, 0)
        self.assertEqual(len(j.stdout.strip().splitlines()), 1)
        obj = json.loads(j.stdout)
        self.assertEqual(list(obj), ["resources"])
        self.assertEqual([x["resource"] for x in obj["resources"]], [l.split()[0][9:] for l in lines])
        self.assertEqual(obj["resources"][3]["id"], "build 2?")
        self.assertIsNone(obj["resources"][5]["state"])

    def test_stale_and_missing_status_exit_3_with_rows(self):
        now = time.time()
        self.files(now - 600)
        r = self.mm("resources")
        self.assertEqual(r.returncode, 3, r.stdout)
        lines = r.stdout.splitlines()
        self.assertIn("state=UNKNOWN", lines[0])
        self.assertIn('why="status 6', lines[0])
        self.assertIn("idle=none", lines[0])
        self.assertIn("resource=pool", lines[1])
        self.assertIn("state=UNKNOWN", lines[1], "the pool file is old too: the supervisor is gone")
        os.remove(os.path.join(self.data, "status.json"))
        r = self.mm("resources")
        self.assertEqual(r.returncode, 3)
        self.assertTrue(r.stdout.startswith("resource=machine id=test-machine location=local state=UNKNOWN"), r.stdout)
        self.assertIn('why="no status.json"', r.stdout.splitlines()[0])

    def test_tick_error_status_is_fresh_unknown(self):
        now = time.time()
        self.files(now, state="UNKNOWN", reasons=["tick error"])
        r = self.mm("resources")
        self.assertEqual(r.returncode, 0, "a fresh status.json, though its state is UNKNOWN")
        self.assertIn("state=UNKNOWN", r.stdout.splitlines()[0])

    def test_usage_errors(self):
        for args in (["resources", "extra"], ["resources", "--bogus"]):
            r = self.mm(*args)
            self.assertEqual(r.returncode, 2, args)
            self.assertEqual(len(r.stdout.splitlines()), 1)
            self.assertTrue(r.stdout.startswith("E_USAGE unknown words: "), r.stdout)
            self.assertTrue(r.stdout.rstrip().endswith("; fix: mm help"), r.stdout)

    def test_runner_error_row_and_no_service_rows_without_a_usage_file(self):
        now = time.time()
        self.files(now)
        self.write("pools/ci_example_project.json", pool_rec(now, runners=[], runners_error="gh api runners rc=1"))
        prof = os.path.join(self.root, "no-usage.toml")
        with open(mmtest.PROFILE) as f:
            text = f.read()
        with open(prof, "w") as f:
            f.write(text.replace('usage_state = "{data}/usage.json"\n', ""))
        r = self.mm("resources", env={"MM_PROFILE": prof})
        self.assertEqual(r.returncode, 0, r.stdout)
        lines = r.stdout.splitlines()
        self.assertEqual(len(lines), 3, lines)
        self.assertEqual(lines[2], 'resource=runner id=runners pool=ci:example/project location=self-hosted '
                                   'state=UNKNOWN why="gh api runners rc=1"')

    def test_help_and_agents_name_the_verb(self):
        self.assertIn("mm resources", self.mm("help").stdout)
        self.assertIn("| `mm resources` |", open(os.path.join(mmtest.CODE, "AGENTS.md")).read())


class FilesOnly(TempData):
    """No reading, no child process, no fork: patched to fail, the verb runs in this process, and fast."""

    def setUp(self):
        super().setUp()
        now = time.time()
        Verb.write(self, "status.json", status_rec(now))
        Verb.write(self, "pools/ci_example_project.json", pool_rec(now))
        Verb.write(self, "usage.json", usage_state(now))
        self.cli = load_cli()

    def test_no_subprocess_no_fork_and_fast(self):
        def boom(*a, **kw):
            raise AssertionError("a child process or a reading at command time")
        out = io.StringIO()
        with mock.patch.object(subprocess, "run", boom), mock.patch.object(subprocess, "Popen", boom), \
                mock.patch.object(os, "fork", boom), mock.patch.object(mmread, "memory_sample", boom), \
                mock.patch.object(mmread, "disk_free_gb", boom), mock.patch.object(mmread, "machine_facts", boom), \
                contextlib.redirect_stdout(out):
            t0 = time.monotonic()
            rc = self.cli.main(["resources"])
            took = time.monotonic() - t0
        self.assertEqual(rc, 0, out.getvalue())
        self.assertEqual(len(out.getvalue().splitlines()), 7)
        self.assertLess(took, 0.3, "fast enough for a launch hook")

    def test_a_fresh_process_loads_no_reading_module(self):
        code = ("import runpy, sys\nsys.argv = ['mm', 'resources']\n"
                "try:\n    runpy.run_path(%r, run_name='__main__')\nexcept SystemExit as e:\n    rc = e.code\n"
                "bad = sorted(m for m in ('mmread', 'mmsuper', 'ctypes', 'mmplat_darwin', 'mmplat_linux', 'subprocess')"
                " if m in sys.modules)\nprint('rc=%%s loaded=%%s' %% (rc, ','.join(bad) or 'none'))\n"
                % os.path.join(mmtest.BIN, "mm"))
        for plat in ("linux", "darwin") if sys.platform == "darwin" else ("linux",):
            r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60,
                               env=dict(os.environ, MM_PLATFORM=plat))
            self.assertEqual(r.stdout.splitlines()[-1], "rc=0 loaded=none", (plat, r.stdout, r.stderr))


class TickErrorStatus(TempData):
    def test_the_tick_error_record_validates_and_gives_rows(self):
        self.queue_dir(slots=5)
        sup = mmsuper.Supervisor(self.profile(), kernel=False, sampler=lambda now, t: ({"t": now}, t), sizes=False,
                                 slow_jobs=False, check_readings=False)
        sup._status(time.time(), "UNKNOWN", ["tick error"], None, None, "tick error: boom")
        st = json.load(open(os.path.join(self.data, "status.json")))
        self.assertEqual(mmschema.validate(st, mmschema.load("status")), [])
        self.assertEqual((st["calls"], st["idle_minutes"]), (None, None))
        self.assertIsNone(st["readings"]["cpu_pct"])
        self.assertEqual(set(st["facts"]), {"cores", "p_cores", "e_cores", "cpu_model", "ram_mb", "disk_gb_total"})
        row = mmdecide.resource_row("machine", st, time.time(), self.s())
        self.assertEqual((row["state"], row["calls"], row["idle"], row["busy"]), ("UNKNOWN", None, False, 0))
        self.assertEqual(self.mm("resources").returncode, 0)


# ------------------------------------------------------------------------------------------------ static facts

class LinuxFacts(unittest.TestCase):
    def test_meminfo(self):
        self.assertEqual(mmplat_linux.parse_meminfo_total_mb(fixture("proc-meminfo.txt")), 16000)
        for bad in ("", None, "MemFree: 5 kB\n", "MemTotal: x kB\n", "MemTotal:\n", "MemTotal: 0 kB\n"):
            self.assertIsNone(mmplat_linux.parse_meminfo_total_mb(bad), repr(bad))

    def test_cpuinfo(self):
        self.assertEqual(mmplat_linux.parse_cpuinfo_model(fixture("proc-cpuinfo-x86.txt")), "Example CPU E-2000 @ 3.00GHz")
        self.assertEqual(mmplat_linux.parse_cpuinfo_model(fixture("proc-cpuinfo-arm.txt")), "Example Board Rev 2",
                         "Hardware before Processor")
        self.assertEqual(mmplat_linux.parse_cpuinfo_model("Processor\t: ARMv7 Processor rev 4 (v7l)\nprocessor\t: 0\n"),
                         "ARMv7 Processor rev 4 (v7l)")
        self.assertIsNone(mmplat_linux.parse_cpuinfo_model(fixture("proc-cpuinfo-arm64.txt")), "no name: none")
        for bad in ("", None, "model name\t:\n", "processor\t: 0\n"):
            self.assertIsNone(mmplat_linux.parse_cpuinfo_model(bad), repr(bad))

    def test_machine_facts_here(self):
        f = mmplat_linux.machine_facts()
        self.assertEqual(set(f), {"cores", "p_cores", "e_cores", "cpu_model", "ram_mb"})
        self.assertEqual((f["p_cores"], f["e_cores"]), (None, None))
        self.assertEqual(f["cores"], os.cpu_count())

    def test_the_supervisor_facts_and_disk_total(self):
        with mock.patch.object(mmread, "machine_facts", lambda: {"cores": 4, "cpu_model": "x\x00y" + "z" * 300,
                                                                 "ram_mb": True}), \
                mock.patch.object(mmread, "disk_total_gb", lambda: 499.96):
            f = mmsuper.machine_facts()
        self.assertEqual(f, {"cores": 4, "p_cores": None, "e_cores": None, "cpu_model": "x?y" + "z" * 117,
                             "ram_mb": None, "disk_gb_total": 500.0})
        with mock.patch.object(mmread, "machine_facts", mock.Mock(side_effect=OSError("no"))), \
                mock.patch.object(mmread, "disk_total_gb", lambda: None):
            self.assertEqual(set(mmsuper.machine_facts().values()), {None}, "a failed read never stops the start")
        self.assertGreater(mmread.disk_total_gb(mmtest.HERE), 0)
        self.assertGreaterEqual(mmread.disk_total_gb(mmtest.HERE), mmread.disk_free_gb(mmtest.HERE))
        self.assertIsNone(mmread.disk_total_gb("/nonexistent/folder"))


class DarwinFacts(unittest.TestCase):
    """macOS machine_facts by its sysctl names, on any machine: the backend loads with a stand-in libc."""

    def load(self):
        import ctypes
        path = os.path.join(mmtest.CODE, "core", "mmplat_darwin.py")
        spec = importlib.util.spec_from_file_location("mmplat_darwin_resources_test", path)
        mod = importlib.util.module_from_spec(spec)
        with mock.patch.object(ctypes, "CDLL", lambda *a, **kw: mock.MagicMock()):
            spec.loader.exec_module(mod)
        return mod

    def test_apple_silicon(self):
        mod = self.load()
        ints = {"hw.ncpu": 12, "hw.perflevel0.logicalcpu": 8, "hw.perflevel1.logicalcpu": 4, "hw.memsize": 32 << 30}
        with mock.patch.object(mod, "sysctl_int", ints.get), \
                mock.patch.object(mod, "sysctl_raw", {"machdep.cpu.brand_string": b"Example M1 Pro\x00\x00"}.get):
            self.assertEqual(mod.machine_facts(), {"cores": 12, "p_cores": 8, "e_cores": 4, "cpu_model": "Example M1 Pro",
                                                   "ram_mb": 32768})

    def test_intel_or_older(self):
        mod = self.load()
        with mock.patch.object(mod, "sysctl_int", {"hw.ncpu": 8, "hw.memsize": 16 << 30}.get), \
                mock.patch.object(mod, "sysctl_raw", {}.get):
            self.assertEqual(mod.machine_facts(), {"cores": 8, "p_cores": None, "e_cores": None, "cpu_model": None,
                                                   "ram_mb": 16384})

    def test_both_backends_carry_machine_facts(self):
        src = open(os.path.join(mmtest.CODE, "core", "mmplat_darwin.py")).read()
        self.assertIn("\ndef machine_facts():", src)
        self.assertTrue(callable(mmplat_linux.machine_facts))
        self.assertIs(mmread.machine_facts, mmread.plat.machine_facts)


class CpuPct(unittest.TestCase):
    def test_all_cpu_busy(self):
        self.assertAlmostEqual(mmread.cpu_pct((100, 50, 800, 0), (200, 100, 850, 0)), 75.0, msg="macOS ticks")
        a = mmplat_linux.parse_proc_stat_cpu("cpu  100 0 100 800 0 0 0 0\n")
        b = mmplat_linux.parse_proc_stat_cpu("cpu  150 0 150 850 50 0 0 0\n")
        self.assertAlmostEqual(mmread.cpu_pct(a, b), 75.0, msg="Linux ticks: 100 minus the idle share")
        for prev, cur in ((None, (1, 2, 3, 4)), ((1, 2, 3, 4), None), ((1, 2, 3, 4), (1, 2, 3, 4))):
            self.assertIsNone(mmread.cpu_pct(prev, cur))

    def test_a_missing_cpu_pct_changes_no_decision(self):
        s = base_settings()
        sample = {"t": 0, "free_pct": 80, "swap_used_mb": 1, "swap_total_mb": 2048, "comp_mb": 1, "pressure": 1,
                  "seg_pct": 1, "load1": 1, "load5": 1, "sys_pct": 5}
        self.assertEqual(mmdecide.sample_problems(dict(sample, cpu_pct=None)), mmdecide.sample_problems(sample))
        self.assertEqual(mmdecide.classify([dict(sample, cpu_pct=None)], s, 100.0), mmdecide.classify([sample], s, 100.0))
        self.assertTrue(mmsuper.memory_readings_present(True, dict(sample, cpu_pct=None)))


# ------------------------------------------------------------------------------------------------ runners

RUNNERS = {"total_count": 4, "runners": [
    {"id": 1, "name": "build-1", "os": "macOS", "status": "online", "busy": False,
     "labels": [{"name": "self-hosted"}, {"name": "macOS"}, {"name": "Lab"}]},
    {"id": 2, "name": "build-2", "os": "macOS", "status": "online", "busy": True,
     "labels": [{"name": "self-hosted"}, {"name": "lab"}]},
    {"id": 3, "name": "other-1", "os": "Linux", "status": "offline", "busy": False, "labels": [{"name": "self-hosted"}]},
    {"id": 4, "name": "build\u2028-4", "status": "offline", "busy": False,
     "labels": [{"name": "self-hosted"}, {"name": "lab"}]}]}


class Runners(TempData):
    def test_parse_runners(self):
        got = ad_ci_github.parse_runners(json.dumps(RUNNERS), ["self-hosted", "lab"])
        self.assertEqual(got, [
            {"name": "build-1", "online": True, "busy": False, "labels": ["self-hosted", "macOS", "Lab"]},
            {"name": "build-2", "online": True, "busy": True, "labels": ["self-hosted", "lab"]},
            {"name": "build?-4", "online": False, "busy": False, "labels": ["self-hosted", "lab"]}])
        self.assertEqual(len(ad_ci_github.parse_runners(json.dumps(RUNNERS), ["self-hosted"])), 4)
        self.assertEqual(ad_ci_github.parse_runners('{"runners": [7, {"name": "x"}]}', ["a"]), [])
        for bad in ("", "nope", "[]", '{"runners": 3}', "{}"):
            with self.assertRaises(ValueError, msg=bad):
                ad_ci_github.parse_runners(bad, ["self-hosted"])
        for r in got:
            self.assertEqual(mmschema.validate(r, mmschema.load("status")["properties"]["runners"]["items"]), [])

    def runner_gh(self, runners):
        """A gh that answers the run list and billing; the runner list from a file, else rc 1 (a 403)."""
        rf = os.path.join(self.root, "runners.json")
        if runners is None:
            if os.path.exists(rf):
                os.remove(rf)
        else:
            with open(rf, "w") as f:
                f.write(runners)
        gh = os.path.join(self.root, "gh-runners.sh")
        with open(gh, "w") as f:
            f.write('#!/bin/sh\ncase "$*" in\n'
                    '  *actions/runners*) [ -f %s ] && { cat %s; exit 0; }; echo "HTTP 403" >&2; exit 1 ;;\n'
                    '  "run list"*) echo "[]" ;;\n'
                    '  *billing*) echo \'{"usageItems": []}\' ;;\n'
                    '  *) exit 1 ;;\nesac\n' % (rf, rf))
        os.chmod(gh, stat.S_IRWXU)
        os.environ["MM_GH"] = gh

    def read(self, labels):
        cfg = dict(self.profile()["ci"])
        if labels:
            cfg["runner_labels"] = labels
        else:
            cfg.pop("runner_labels", None)
        return ad_ci_github.read_all(cfg, self.s(), time.time(), {})

    def facts(self, gh):
        s, now = self.s(), time.time()
        pool = ad_ci_github.Pool(self.profile()["ci"])
        conds = sorted((c["key"], c["level"], c["text"]) for c in pool.conditions(gh, s, now, mmalerts._c, "x"))
        rec = pool.status(gh, s, now, ["SOURCE_STALE:gh-runs", "GH_STUCK"])
        return {"errors": gh["errors"], "state": ad_ci_github.pool_state(gh, s, now), "good": pool.good_keys(gh),
                "conditions": conds, "alerts": rec["alerts"], "reasons": rec["reasons"]}

    def test_a_403_fails_safe(self):
        self.runner_gh(None)
        plain = self.read(None)
        self.assertNotIn("runners", plain)
        self.assertNotIn("runners_error", plain)
        got = self.read(["self-hosted", "lab"])
        self.assertEqual(got["runners"], [])
        self.assertTrue(got["runners_error"].startswith("gh api runners rc=1"), got["runners_error"])
        self.assertEqual(got["errors"], {})
        self.assertEqual(self.facts(got), self.facts(plain), "errors, state, good keys, conditions and alerts unchanged")
        self.assertEqual(self.facts(got)["state"][0], "GREEN")
        rec = ad_ci_github.Pool(self.profile()["ci"]).status(got, self.s(), time.time())
        self.assertEqual((rec["runners"], rec["runners_error"][:16]), ([], "gh api runners r"))
        self.assertEqual(mmschema.validate(rec, mmschema.load("status")), [])

    def test_text_that_does_not_parse_fails_safe(self):
        self.runner_gh("<html>not json</html>")
        got = self.read(["self-hosted"])
        self.assertEqual((got["runners"], got["runners_error"], got["errors"]), ([], "runners is not JSON", {}))
        self.assertIn("billing", got)
        self.assertIn("runs", got)

    def test_a_good_list(self):
        self.runner_gh(json.dumps(RUNNERS))
        got = self.read(["self-hosted", "lab"])
        self.assertIsNone(got["runners_error"])
        self.assertEqual([r["name"] for r in got["runners"]], ["build-1", "build-2", "build?-4"])
        rec = ad_ci_github.Pool(self.profile()["ci"]).status(got, self.s(), time.time())
        self.assertEqual(mmschema.validate(rec, mmschema.load("status")), [])
        self.assertEqual(rec["capacity"]["unit"], "minutes")
        self.assertEqual(rec["money"], {"used_usd": 0.0, "allowed_usd": 0})


class PoolRecord(TempData):
    def test_owns_and_the_alert_list_are_unchanged(self):
        s, now = self.s(), time.time()
        pool = ad_ci_github.Pool(self.profile()["ci"])
        active = ["SOURCE_STALE:gh", "SOURCE_STALE:gh-runs", "GH_FAIL:1", "GUARD", "MEM_RED", "GUARD_KILL", "QWAIT"]
        keys = [k for k in active if pool.owns(k)]
        self.assertEqual(keys, ["SOURCE_STALE:gh", "SOURCE_STALE:gh-runs", "GH_FAIL:1", "GUARD"])
        for gh in (None, {"time": now, "errors": {}, "runners": [], "runners_error": "gh api runners rc=1"}):
            rec = pool.status(gh, s, now, keys)
            self.assertEqual(rec["alerts"], keys)
            self.assertFalse(any(pool.owns(k) for k in ("RUNNERS", "SOURCE_STALE:runners")))
            self.assertEqual(mmschema.validate(rec, mmschema.load("status")), [])

    def test_schema_rejects_bad_new_fields(self):
        st = status_rec(time.time())
        self.assertEqual(mmschema.validate(st, mmschema.load("status")), [])
        for bad in ({"facts": {"cores": "12"}}, {"facts": {"gpu": 1}}, {"calls": 1.5}, {"idle_minutes": "3"},
                    {"money": {"used_usd": "1"}}, {"runners": [{"name": "a"}]}, {"runners_error": 3}):
            self.assertTrue(mmschema.validate(dict(st, **bad), mmschema.load("status")), bad)


# ------------------------------------------------------------------------------------------------ the idle rule

def old_idle(q, state):
    """The supervisor's IDLE_ROOM condition before queue_idle (kept here as the reference)."""
    return bool(q and q.get("slots") and len(q["busy"]) < q["slots"] and not q["tickets"] and state == "GREEN")


class QueueIdle(TempData):
    def test_queue_idle_equals_the_old_rule(self):
        b = {"slot": ".slot.1", "pid": 1, "since": 1.0}
        for q in (None, {}, {"slots": None, "busy": [], "tickets": []}, {"slots": 0, "busy": [], "tickets": []},
                  {"slots": 3, "busy": [], "tickets": []}, {"slots": 3, "busy": [b, b], "tickets": []},
                  {"slots": 3, "busy": [b, b, b], "tickets": []}, {"slots": 3, "busy": [b], "tickets": [{"mode": "S"}]},
                  {"slots": 2, "busy": [b, b, b], "tickets": []}):
            for state in ("GREEN", "STEADY", "AMBER", "RED", "UNKNOWN"):
                new = bool(q) and mmdecide.queue_idle(q.get("slots"), len(q.get("busy") or []),
                                                      len(q.get("tickets") or []), state)
                self.assertEqual(new, old_idle(q, state), (q, state))
        for args in (("3", 0, 0, "GREEN"), (3, None, 0, "GREEN"), (3, 0, None, "GREEN"), (True, 0, 0, "GREEN")):
            self.assertFalse(mmdecide.queue_idle(*args), args)

    def test_idle_room_and_idle_minutes_through_the_supervisor(self):
        self.queue_dir(slots=5)
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "queue.idle_room_minutes": 1})

        def calm(now, ticks):
            return {"t": now, "free_pct": 80, "swap_used_mb": 100, "swap_total_mb": 2048, "comp_mb": 300, "pressure": 1,
                    "seg_pct": 1, "load1": 1, "load5": 1, "sys_pct": None, "sys_pct_fixture": 10, "cpu_pct": 12.5}, ticks
        clock = {"t": time.time()}
        with mock.patch.object(mmread, "disk_free_gb", lambda *a: 500.0):
            sup = mmsuper.Supervisor(self.profile(), kernel=False, clock=lambda: clock["t"], sampler=calm, sizes=False,
                                     slow_jobs=False, check_readings=False)
            got = []
            for _ in range(9):
                sup.tick()
                st = json.load(open(os.path.join(self.data, "status.json")))
                act = json.load(open(os.path.join(self.data, "alerts-state.json")))["active"]
                got.append((st["state"], st["idle_minutes"], "IDLE_ROOM" in act))
                clock["t"] += 10
        self.assertEqual(got[0], ("GREEN", 0.0, False))
        self.assertEqual(got[6], ("GREEN", 1.0, True), got)
        self.assertEqual((st["readings"]["cpu_pct"], st["calls"]), (12.5, 0))
        self.assertEqual(mmschema.validate(st, mmschema.load("status")), [])
        row = mmdecide.resource_row("machine", st, clock["t"] - 10, self.s())
        self.assertEqual((row["idle"], row["idle_min"], row["state"]), (True, 1, "GREEN"))


class UsageResets(TempData):
    def test_resets_and_read_usage_unchanged(self):
        now = time.time()
        f = os.path.join(self.data, "usage.json")
        with open(f, "w") as fh:
            json.dump(usage_state(now), fh)
        got = ad_deliver_claude.usage_resets(f)
        self.assertEqual(got["claude_5h"], {"reset_at": now + 3600, "not_offered": False})
        self.assertEqual(got["codex_5h"], {"reset_at": None, "not_offered": True})
        self.assertNotIn("other", got)
        self.assertEqual(ad_deliver_claude.usage_resets(os.path.join(self.data, "none.json")), {})
        with open(f, "w") as fh:
            fh.write('{"levels": {"claude_5h": {"reset_at": "soon"}, "codex_weekly": {"reset_at": 1e999}}}')
        self.assertEqual(ad_deliver_claude.usage_resets(f), {"claude_5h": {"reset_at": None, "not_offered": False},
                                                             "codex_weekly": {"reset_at": None, "not_offered": False}})


if __name__ == "__main__":
    unittest.main()
