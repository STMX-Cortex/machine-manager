# SPDX-License-Identifier: Apache-2.0
"""`mm resources` and the resource records: the verb on a temporary data folder (status.json and resources.json; lines,
--json, exits 0, 2 and 3, the file's versions, the caps), files only (no child process, no fork, fast, no mmread and no
adapter), the writer (resources.json each tick, mmadapters.records on bad adapters, hostile text), a seeded fuzz of
the readers, the tick-error status.json, the static facts (the Linux parsers on fixtures, macOS machine_facts on a
patched sysctl), cpu_pct, the runner list and its safe failure (a fake gh), the pool file as in Part 1, queue_idle as
the IDLE_ROOM rule, and the schemas."""
import contextlib
import importlib.util
import io
import json
import os
import re
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
import ad_queue_fifo
import mmadapters
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


RUNNERS_READ = [{"name": "build-1", "online": True, "busy": False, "labels": ["self-hosted", "lab"]},
                {"name": "build 2\x07", "online": True, "busy": True, "labels": ["self-hosted", "lab"]},
                {"name": "build-3", "online": False, "busy": False, "labels": ["self-hosted", "lab"]}]


def gh_read(now, **over):
    """A GitHub read as state/github.json holds it (ad_ci_github.read_all), with runner labels."""
    rec = {"time": now - 60, "errors": {}, "pool_id": "ci:example/project",
           "runs": {"in_progress": 2, "queued": 1, "running": [11, 12], "failed_1h": [], "oldest_queued_min": 0,
                    "oldest_queued_job_min": 0, "longest_running_min": 5},
           "billing": {"minutes": 1265.5, "gross": 0.04, "net": 0.0}, "watched": {},
           "runners": RUNNERS_READ, "runners_error": None}
    rec.update(over)
    return rec


def usage_state(now):
    return {"checked_at": now - 60, "max_age_seconds": 1800,
            "levels": {"claude_5h": {"used_percent": 41.0, "status": "ok", "read_at": now - 60, "reset_at": now + 3600},
                       "claude_weekly": {"used_percent": 63.5, "status": "ok", "read_at": now - 60,
                                         "reset_at": now + 86400},
                       "codex_5h": {"status": "not_offered"},
                       "codex_weekly": {"used_percent": 20, "status": "error", "read_at": now - 60}}}


def resources_doc(now, recs, **over):
    doc = mmcore.stamp({"kind": "resources", "time": now, "resources": [dict(r, time=now) for r in recs]}, mid="lab1")
    doc.update(over)
    return doc


def no_nan(text):
    def refuse(c):
        raise ValueError("not strict JSON: %s" % c)
    return json.loads(text, parse_constant=refuse)


TOKEN = "gh" + "p_" + "A" * 36  # built here: no token shape in the tree (test_public)
POOL_KEYS_PART1 = {"kind", "time", "state", "reasons", "capacity", "load", "alerts", "read_time", "machine_id",
                   "schema_version"}  # Pool.status at 39f7800 (Part 1), as on origin/main


class Files(TempData):
    """A data folder with status.json and resources.json."""
    settings_over = {"github.allowed_gross_usd": 5}  # paid use allowed: the pool is GREEN with a small gross

    def write(self, name, obj, raw=None):
        os.makedirs(os.path.dirname(os.path.join(self.data, name)), exist_ok=True)
        with open(os.path.join(self.data, name), "w") as f:
            f.write(raw if raw is not None else json.dumps(obj))

    def records(self, now):
        """The writers' records as the supervisor's last tick gave them: the pool, its runners, the services."""
        s = self.s()
        self.write("usage.json", usage_state(now))
        f = os.path.join(self.data, "usage.json")
        return (ad_ci_github.pool_resources(gh_read(now), s, now, "ci:example/project")
                + ad_deliver_claude.usage_resources(ad_deliver_claude.read_usage(f, now, s),
                                                    ad_deliver_claude.usage_resets(f), now, s))


class Verb(Files):
    def files(self, now, res_time=None, **status):
        self.write("status.json", status_rec(now, **status))
        t = now if res_time is None else res_time
        self.write("resources.json", resources_doc(t, self.records(t)))

    def lines(self, *args, rc=0):
        r = self.mm("resources", *args)
        self.assertEqual((r.returncode, r.stderr), (rc, ""), r.stdout)
        return r.stdout.splitlines()

    def test_lines_json_and_exit_codes(self):
        now = time.time()
        self.files(now)
        lines = self.lines()
        self.assertEqual([l.split()[0] for l in lines], ["resource=machine", "resource=pool"] + ["resource=runner"] * 3 +
                         ["resource=service"] * 2)
        self.assertTrue(lines[0].startswith(
            "resource=machine id=lab1 location=local state=GREEN unit=slots total=6 left=3 reserve=none running=2 "
            'queued=0 cores=12 p_cores=8 e_cores=4 cpu_model="Example M1 Pro" ram_mb=32768 ram_avail_mb=16384 '
            "disk_gb_total=994.7 disk_free_gb=210.4 cpu_pct=41.3 idle=no idle_min=none age_s="), lines[0])
        self.assertRegex(lines[0], r" age_s=\d fresh=yes$")
        self.assertRegex(lines[1], r"^resource=pool id=ci:example/project location=cloud state=GREEN unit=minutes "
                                   r"total=3000 left=1734.5 reserve=300 running=2 queued=1 used_usd=0.04 allowed_usd=5 "
                                   r"age_s=6\d fresh=yes$")
        self.assertRegex(lines[2], r"^resource=runner id=build-1 parent=ci:example/project location=self-hosted "
                                   r"state=GREEN online=yes busy=no age_s=6\d fresh=yes$")
        self.assertRegex(lines[3], r'^resource=runner id="build 2\?" parent=ci:example/project location=self-hosted '
                                   r"state=STEADY online=yes busy=yes age_s=6\d fresh=yes$")
        self.assertRegex(lines[4], r"^resource=runner id=build-3 parent=ci:example/project location=self-hosted "
                                   r"state=RED online=no busy=no age_s=6\d fresh=yes$")
        self.assertRegex(lines[5], r"^resource=service id=claude location=cloud state=none used_5h_pct=41 reset_5h=\d+ "
                                   r"used_week_pct=63.5 reset_week=\d+ age_s=6\d fresh=yes$")
        self.assertRegex(lines[6], r'^resource=service id=codex location=cloud state=UNKNOWN used_week_pct=none '
                                   r'reset_week=none age_s=6\d fresh=yes why="codex_weekly: status error"$')
        self.assertNotIn("used_5h_pct", lines[6], "a window the plan does not offer is left out")
        for line in lines:
            self.assertNotIn("\x07", line)
        j = self.mm("resources", "--json")
        self.assertEqual((j.returncode, len(j.stdout.strip().splitlines())), (0, 1))
        obj = no_nan(j.stdout)
        self.assertEqual(list(obj), ["resources"])
        self.assertEqual([x["resource"] for x in obj["resources"]], [l.split()[0][9:] for l in lines])
        self.assertEqual(obj["resources"][3]["id"], "build 2?")
        self.assertEqual(obj["resources"][1]["used_usd"], 0.04)
        self.assertIsNone(obj["resources"][5]["state"])

    def test_stale_and_missing_status_exit_3_with_rows(self):
        now = time.time()
        self.files(now - 600)
        lines = self.lines(rc=3)
        self.assertRegex(lines[0], r' state=UNKNOWN .* idle=none idle_min=none age_s=60\d fresh=no why="record 60\d s old"$')
        self.assertEqual(len(lines), 7, "the rows are still printed")
        for line in lines[1:]:
            self.assertRegex(line, r' state=UNKNOWN .*fresh=no why="record 60\d s old', "an old file: the supervisor is gone")
        os.remove(os.path.join(self.data, "status.json"))
        lines = self.lines(rc=3)
        self.assertTrue(lines[0].startswith("resource=machine id=test-machine location=local state=UNKNOWN unit=slots "
                                            "total=none left=none reserve=none running=none queued=none"), lines[0])
        self.assertTrue(lines[0].endswith(' idle=none idle_min=none age_s=none fresh=no why="no record time; no status.json"'),
                        lines[0])
        self.assertEqual(len(lines), 7)

    def test_resources_file_cases(self):
        now = time.time()
        self.files(now, res_time=now - 600)
        lines = self.lines()
        self.assertEqual(len(lines), 7)
        self.assertIn("state=GREEN", lines[0], "a fresh machine with an old resources.json")
        self.assertTrue(all('state=UNKNOWN' in l and 'why="record 60' in l for l in lines[1:]), lines)
        f = os.path.join(self.data, "resources.json")
        os.remove(f)
        self.assertEqual([l.split()[0] for l in self.lines()], ["resource=machine"], "a missing file: the machine only")
        self.write("resources.json", resources_doc(now, self.records(now), schema_version=2))
        lines = self.lines()
        self.assertEqual(lines[1:], ["resource=file id=resources.json location=none state=UNKNOWN age_s=none fresh=yes "
                                     'why="schema_version 2 not known"'])
        for v in (True, 1.0, "1", None):
            self.write("resources.json", resources_doc(now, self.records(now), schema_version=v))
            self.assertEqual(self.lines()[1].split()[0], "resource=file", v)
        self.write("resources.json", resources_doc(now, self.records(now), kind="pool"))
        self.assertEqual(len(self.lines()), 1, "a wrong kind is ignored")
        self.write("resources.json", None, raw="[" * 100000 + "]" * 100000)
        r = self.mm("resources")
        self.assertEqual((r.returncode, r.stderr, len(r.stdout.splitlines())), (0, "", 1), "nested too deep: no file")
        self.write("resources.json", None, raw='{"kind": "resources", "resources": ' + "[" * 100000 + "]" * 100000 + "}")
        r = self.mm("resources")
        self.assertEqual((r.returncode, r.stderr, len(r.stdout.splitlines())), (0, "", 1))

    def test_tick_error_status_is_fresh_unknown(self):
        now = time.time()
        self.files(now, state="UNKNOWN", reasons=["tick error"])
        lines = self.lines()
        self.assertIn("state=UNKNOWN", lines[0], "a fresh status.json, though its state is UNKNOWN")
        self.assertTrue(lines[0].endswith('fresh=yes why="tick error"'), lines[0])

    def test_usage_errors(self):
        for args in (["resources", "extra"], ["resources", "--bogus"]):
            r = self.mm(*args)
            self.assertEqual(r.returncode, 2, args)
            self.assertEqual(len(r.stdout.splitlines()), 1)
            self.assertTrue(r.stdout.startswith("E_USAGE unknown words: "), r.stdout)
            self.assertTrue(r.stdout.rstrip().endswith("; fix: mm help"), r.stdout)

    def test_runner_error_row(self):
        now = time.time()
        self.write("status.json", status_rec(now))
        recs = ad_ci_github.pool_resources(gh_read(now, runners=[], runners_error="gh api runners rc=1"), self.s(), now,
                                           "ci:example/project")
        self.write("resources.json", resources_doc(now, recs))
        lines = self.lines()
        self.assertEqual(len(lines), 3, lines)
        self.assertRegex(lines[2], r'^resource=runner id=runners parent=ci:example/project location=self-hosted '
                                   r'state=UNKNOWN age_s=6\d fresh=yes why="gh api runners rc=1"$')
        self.assertIn("state=GREEN", lines[1], "a failed runner read never changes the pool")

    def test_any_resource_without_a_code_change(self):
        now = time.time()
        self.write("status.json", status_rec(now))
        rec = {"resource": "agent-service", "id": "tasks-1", "location": "cloud", "read_time": now - 30,
               "stale_after_s": 600, "state": "GREEN", "why": None,
               "capacity": {"unit": "tasks", "total": 20, "left": 7, "reserve": 2},
               "load": {"running": 3, "queued": 0}, "values": [{"key": "credits_left", "value": 12.5}]}
        doc = resources_doc(now, [rec])
        self.assertEqual(mmschema.validate(doc, mmschema.load("resource")), [])
        self.write("resources.json", doc)
        self.assertRegex(self.lines()[1], r"^resource=agent-service id=tasks-1 location=cloud state=GREEN unit=tasks "
                                          r"total=20 left=7 reserve=2 running=3 queued=0 credits_left=12.5 age_s=3\d "
                                          r"fresh=yes$")

    def test_hostile_text_cleaned_quoted_and_masked(self):
        now = time.time()
        self.write("status.json", status_rec(now))
        bad = "x|y\x07z\u2028 " + TOKEN
        rec = {"resource": "runner", "id": bad, "parent": bad, "location": "self-hosted", "read_time": now - 30,
               "stale_after_s": 600, "state": "GREEN", "why": bad, "values": [{"key": "note", "value": bad}]}
        self.write("resources.json", resources_doc(now, [rec]))
        line = self.lines()[1]
        want = json.dumps("x?y?z? ***")
        self.assertRegex(line, "^%s age_s=3\\d %s$" % (
            re.escape("resource=runner id=%s parent=%s location=self-hosted state=GREEN note=%s" % (want, want, want)),
            re.escape("fresh=yes why=%s" % want)))
        row = no_nan(self.mm("resources", "--json").stdout)["resources"][1]
        self.assertEqual([row[k] for k in ("id", "parent", "note", "why")], ["x?y?z? ***"] * 4)

    def test_help_and_agents_name_the_verb(self):
        self.assertIn("mm resources", self.mm("help").stdout)
        self.assertIn("| `mm resources` |", open(os.path.join(mmtest.CODE, "AGENTS.md")).read())


class Caps(Files):
    def test_5000_records_read_in_time(self):
        now = time.time()
        self.write("status.json", status_rec(now))
        recs = [{"resource": "runner", "id": "build-%d" % k, "parent": "ci:example/project", "location": "self-hosted",
                 "read_time": now, "stale_after_s": 1800, "state": "GREEN", "why": None,
                 "values": [{"key": "online", "value": True}, {"key": "busy", "value": False}]} for k in range(5000)]
        self.write("resources.json", resources_doc(now, recs))
        cli, out = load_cli(), io.StringIO()
        with contextlib.redirect_stdout(out):
            t0 = time.monotonic()
            rc = cli.main(["resources"])
            took = time.monotonic() - t0
        lines = out.getvalue().splitlines()
        self.assertEqual((rc, len(lines)), (0, 1001))
        self.assertEqual(lines[999].split()[1], "id=build-998")
        self.assertEqual(lines[1000], 'resource=file id=resources.json location=none state=UNKNOWN age_s=none fresh=yes '
                                      'why="4001 records left out"')
        self.assertLess(took, 0.5, "1000 rows at most, fast")


class FilesOnly(Files):
    """No reading, no child process, no fork, no adapter: patched to fail, the verb runs in this process, and fast."""

    def setUp(self):
        super().setUp()
        now = time.time()
        self.write("status.json", status_rec(now))
        self.write("resources.json", resources_doc(now, self.records(now)))
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

    def test_a_fresh_process_loads_no_reading_module_and_no_adapter(self):
        code = ("import runpy, sys\nsys.argv = ['mm', 'resources']\n"
                "try:\n    runpy.run_path(%r, run_name='__main__')\nexcept SystemExit as e:\n    rc = e.code\n"
                "bad = sorted(m for m in ('mmread', 'mmsuper', 'ctypes', 'mmplat_darwin', 'mmplat_linux', 'subprocess',"
                " 'mmadapters', 'ad_ci_github', 'ad_deliver_claude') if m in sys.modules)\n"
                "print('rc=%%s loaded=%%s' %% (rc, ','.join(bad) or 'none'))\n" % os.path.join(mmtest.BIN, "mm"))
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
        now = time.time()
        row = mmdecide.resource_row(mmdecide.machine_resource(st, "test-machine", now, self.s()), now, self.s())
        self.assertEqual((row["state"], row["running"], row["idle"], row["left"], row["why"]),
                         ("UNKNOWN", None, False, None, "tick error"))
        self.assertEqual(self.mm("resources").returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.data, "resources.json")), "the tick-error path writes none")


# ------------------------------------------------------------------------------------------------ the writer

def calm(now, ticks):
    return {"t": now, "free_pct": 80, "swap_used_mb": 100, "swap_total_mb": 2048, "comp_mb": 300, "pressure": 1,
            "seg_pct": 1, "load1": 1, "load5": 1, "sys_pct": None, "sys_pct_fixture": 10, "cpu_pct": 12.5}, ticks


class Tick(TempData):
    def setUp(self):
        super().setUp()
        self.queue_dir(slots=5)
        self.now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "state", "github.json"), json.dumps(gh_read(self.now)))
        with open(os.path.join(self.data, "usage.json"), "w") as f:
            json.dump(usage_state(self.now), f)
        self.clock = {"t": self.now}

    def sup(self, profile=None):
        with mock.patch.object(mmread, "disk_free_gb", lambda *a: 500.0):
            return mmsuper.Supervisor(profile or self.profile(), kernel=False, clock=lambda: self.clock["t"],
                                      sampler=calm, sizes=False, slow_jobs=False, check_readings=False)

    def tick(self, sup):
        with mock.patch.object(mmread, "disk_free_gb", lambda *a: 500.0):
            t0 = time.monotonic()
            sup.tick()
            took = time.monotonic() - t0
        self.clock["t"] += 10
        with open(os.path.join(self.data, "resources.json")) as f:
            return no_nan(f.read()), took

    def errors(self):
        try:
            with open(os.path.join(self.data, "state", "errors.log")) as f:
                return f.read().splitlines()
        except OSError:
            return []

    def test_the_file_its_order_times_and_schema(self):
        doc, _ = self.tick(self.sup())
        schema = mmschema.load("resource")
        self.assertEqual(mmschema.validate(doc, schema), [])
        self.assertEqual((doc["kind"], doc["time"], doc["machine_id"], doc["schema_version"]),
                         ("resources", self.now, "test-machine", 1))
        recs = doc["resources"]
        self.assertEqual([(r["resource"], r["id"]) for r in recs],
                         [("pool", "ci:example/project"), ("runner", "build-1"), ("runner", "build 2?"),
                          ("runner", "build-3"), ("service", "claude"), ("service", "codex")])
        self.assertEqual({r["time"] for r in recs}, {self.now}, "every record carries the tick's time")
        self.assertTrue(all(r.get("parent") == "ci:example/project" for r in recs[1:4]))
        pool = json.load(open(os.path.join(self.data, "pools", "ci_example_project.json")))
        self.assertEqual(set(pool), POOL_KEYS_PART1)
        self.assertEqual(set(pool["capacity"]), {"minutes_left", "reserve_minutes"})
        self.assertEqual(mmschema.validate(pool, mmschema.load("status")), [])
        st = json.load(open(os.path.join(self.data, "status.json")))
        rec = mmdecide.machine_resource(st, "test-machine", self.now, self.s())
        self.assertEqual(mmschema.validate(rec, schema["$defs"]["record"], schema), [])
        self.assertEqual(self.errors(), [])

    def test_other_profiles(self):
        p = self.profile()
        p.pop("ci")
        doc, _ = self.tick(self.sup(p))
        self.assertEqual([r["id"] for r in doc["resources"]], ["claude", "codex"])
        p.pop("delivery")
        doc, _ = self.tick(self.sup(p))
        self.assertEqual(doc["resources"], [], "the file is written even when empty")
        self.assertEqual(mmschema.validate(doc, mmschema.load("resource")), [])

    def test_a_write_failure_costs_one_line(self):
        os.makedirs(os.path.join(self.data, "resources.json"))
        sup = self.sup()
        for n in (1, 2):
            with mock.patch.object(mmread, "disk_free_gb", lambda *a: 500.0):
                sup.tick()
            self.clock["t"] += 10
            self.assertEqual(len([l for l in self.errors() if " resources.json " in l]), n, self.errors())
            st = json.load(open(os.path.join(self.data, "status.json")))
            self.assertEqual((st["heartbeat"]["tick"], st["heartbeat"]["note"]), (n, "ok"))
            ctl = json.load(open(os.path.join(self.data, "state", "controller.json")))
            self.assertIn("offsets", ctl)

    def test_a_write_failure_without_errors_log_ends_the_tick(self):
        os.makedirs(os.path.join(self.data, "resources.json"))
        os.makedirs(os.path.join(self.data, "state", "errors.log"))
        sup = self.sup()
        for n in (1, 2):
            with mock.patch.object(mmread, "disk_free_gb", lambda *a: 500.0):
                sup.tick()
            self.clock["t"] += 10
            st = json.load(open(os.path.join(self.data, "status.json")))
            self.assertEqual((st["heartbeat"]["tick"], st["heartbeat"]["note"]), (n, "ok"), "never a tick error")
            self.assertIn("offsets", json.load(open(os.path.join(self.data, "state", "controller.json"))))

    def adapter_case(self, fake):
        """One tick with the pool adapter's resources() replaced: the tick ends, the file is strict JSON."""
        with mock.patch.object(ad_ci_github.Pool, "resources", fake):
            doc, took = self.tick(self.sup())
        self.assertEqual(mmschema.validate(doc, mmschema.load("resource")), [])
        self.assertLess(took, 5.0)
        return doc["resources"]

    def test_records_turns_a_bad_adapter_into_one_unknown_record(self):
        def raises(self_, gh, s, now):
            raise RuntimeError("boom " + TOKEN)
        nested = []
        for _ in range(100000):
            nested = [nested]
        for name, fake in (("raises", raises), ("not a list", lambda *a: {"resource": "pool"}),
                           ("nan", lambda *a: [{"resource": "pool", "id": "p", "read_time": None, "stale_after_s": None,
                                                "state": None, "values": [{"key": "v", "value": float("nan")}]}]),
                           ("nested", lambda *a: [{"resource": "pool", "id": "p", "values": nested}]),
                           ("keys that do not sort", lambda *a: [{"resource": "pool", "id": "p", "read_time": None,
                                                                  "stale_after_s": None, "state": None,
                                                                  "extra": {1: "a", "b": 2}}])):
            recs = self.adapter_case(fake)
            self.assertEqual([r["resource"] for r in recs], ["adapter", "service", "service"], name)
            self.assertEqual((recs[0]["id"], recs[0]["state"]), ("ci", "UNKNOWN"), name)
            self.assertTrue(recs[0]["why"].startswith("ci.resources failed: "), recs[0]["why"])
            self.assertNotIn(TOKEN, recs[0]["why"])
        log = [l for l in self.errors() if " resources ci " in l]
        self.assertEqual(len(log), 5, self.errors())
        self.assertTrue(all(TOKEN not in l for l in log))
        self.assertIn("RuntimeError", log[0])

    def test_records_cuts_a_long_list_before_its_work(self):
        one = {"resource": "runner", "id": "r", "read_time": None, "stale_after_s": None, "state": None,
               "values": [{"key": "v%d" % j, "value": "x%d" % j} for j in range(100)]}
        recs = self.adapter_case(lambda *a: [one] * 10000)
        self.assertEqual(len(recs), mmdecide.RECORDS_MAX)
        self.assertEqual(recs[-1]["why"], "3 records left out", "1000 from ci and 2 services: 999 kept")
        self.assertEqual(len(recs[0]["values"]), mmdecide.VALUES_MAX)

    def test_records_without_the_method(self):
        class Bare:
            pass
        for ad in (None, Bare(), ad_queue_fifo.Queue(self.profile()["queue"])):
            self.assertEqual(mmadapters.records(ad, {}, self.s(), self.now, "queue"), [])
        self.assertEqual(self.errors(), [])

    def test_hostile_text_in_the_file(self):
        bad = "x|y\x07z\u2028 " + TOKEN
        recs = self.adapter_case(lambda *a: [{"resource": "runner", "id": bad, "parent": bad, "location": "self-hosted",
                                              "read_time": self.now, "stale_after_s": 60, "state": "GREEN", "why": bad,
                                              "values": [{"key": "note", "value": bad}]}])
        self.assertEqual([recs[0][k] for k in ("id", "parent", "why")], ["x?y?z? ***"] * 3)
        self.assertEqual(recs[0]["values"], [{"key": "note", "value": "x?y?z? ***"}])
        with open(os.path.join(self.data, "resources.json")) as f:
            text = f.read()
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("\\u0007", text)


class Fuzz(unittest.TestCase):
    """Seeded odd values in every field: the readers never raise, and every row is strict JSON."""

    def test_rows_never_raise(self):
        import random
        rnd = random.Random(20261025)
        s, now = base_settings(), 1_800_000_000.0
        deep = []
        for _ in range(50):
            deep = [deep]
        odd = [float("nan"), float("inf"), -float("inf"), [], "x", {}, None, True, False, deep, "y" * 5000, -1, 0,
               10 ** 30, 10 ** 400, 1.5, now, now - 30, "GREEN", "Pool", {"unit": "x"},
               [{"key": "a", "value": float("nan")}]]
        keys = ["resource", "id", "parent", "location", "time", "read_time", "stale_after_s", "state", "why", "capacity",
                "load", "values"]

        def pick():
            return rnd.choice(odd)
        for n in range(2000):
            rec = {k: pick() for k in keys if rnd.random() < 0.8}
            rec["capacity"] = {k: pick() for k in ("unit", "total", "left", "reserve")} if rnd.random() < 0.5 else pick()
            rec["load"] = {k: pick() for k in ("running", "queued")} if rnd.random() < 0.5 else pick()
            rec["values"] = [rnd.choice([{"key": rnd.choice(["a", "b_1", "state", "Bad", pick()]), "value": pick()},
                                         pick()]) for _ in range(rnd.randrange(0, 80))]
            st = {k: pick() for k in ("time", "state", "reasons", "slots", "busy", "calls", "waiting", "disk_gb",
                                      "idle_minutes", "machine_id")}
            st["facts"] = {k: pick() for k in mmsuper.FACT_KEYS + ("disk_gb_total",)} if n % 2 else pick()
            st["readings"] = {k: pick() for k in ("free_pct", "cpu_pct")} if n % 3 else pick()
            usage = {k: pick() for k in ("age_s", "max_age_s", "stale_levels", "claude_5h", "claude_week", "codex_5h",
                                         "codex_week")} if n % 4 else pick()
            resets = {lv: {"reset_at": pick(), "not_offered": pick()} for lv in ad_deliver_claude.USAGE_LEVELS} \
                if n % 5 else pick()
            recs = [rec, pick(), mmdecide.machine_resource(st if n % 7 else pick(), pick(), now, s)]
            recs += ad_deliver_claude.usage_resources(usage, resets, now, s)
            for r in recs:
                json.dumps(mmdecide.resource_row(r, now, s), allow_nan=False)


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
        schema = mmschema.load("resource")
        odd = [7, None, {"online": True, "busy": False}, {"name": "", "online": True}, {"name": 5, "online": False}]
        recs = ad_ci_github.pool_resources({"time": time.time(), "errors": {}, "runners": got + odd}, self.s(),
                                           time.time(), "ci:example/project")
        self.assertEqual([r["id"] for r in recs[1:]], ["build-1", "build-2", "build?-4"], "no name: no record")
        for r in recs:
            self.assertEqual(mmschema.validate(r, schema["$defs"]["record"], schema), [], r)

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
        now = time.time()
        rec = ad_ci_github.Pool(self.profile()["ci"]).status(got, self.s(), now)
        self.assertEqual(set(rec), POOL_KEYS_PART1, "the pool file holds no runners")
        self.assertEqual(mmschema.validate(rec, mmschema.load("status")), [])
        recs = ad_ci_github.pool_resources(got, self.s(), now, "ci:example/project")
        self.assertEqual([(r["resource"], r["id"], r["state"]) for r in recs],
                         [("pool", "ci:example/project", "GREEN"), ("runner", "runners", "UNKNOWN")])
        self.assertTrue(recs[1]["why"].startswith("gh api runners rc=1"), recs[1]["why"])

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
        now = time.time()
        rec = ad_ci_github.Pool(self.profile()["ci"]).status(got, self.s(), now)
        self.assertEqual(mmschema.validate(rec, mmschema.load("status")), [])
        self.assertEqual((set(rec), set(rec["capacity"])), (POOL_KEYS_PART1, {"minutes_left", "reserve_minutes"}),
                         "no runners, money or unit in the pool file")
        recs = ad_ci_github.pool_resources(got, self.s(), now, "ci:example/project")
        self.assertEqual([(r["id"], r["state"]) for r in recs[1:]],
                         [("build-1", "GREEN"), ("build-2", "STEADY"), ("build?-4", "RED")])
        self.assertEqual((recs[0]["capacity"]["unit"], recs[0]["values"]),
                         ("minutes", [{"key": "used_usd", "value": 0.0}, {"key": "allowed_usd", "value": 0}]))


class PoolRecord(TempData):
    def test_owns_and_the_alert_list_are_unchanged(self):
        s, now = self.s(), time.time()
        pool = ad_ci_github.Pool(self.profile()["ci"])
        active = ["SOURCE_STALE:gh", "SOURCE_STALE:gh-runs", "GH_FAIL:1", "GUARD", "MEM_RED", "GUARD_KILL", "QWAIT"]
        keys = [k for k in active if pool.owns(k)]
        self.assertEqual(keys, ["SOURCE_STALE:gh", "SOURCE_STALE:gh-runs", "GH_FAIL:1", "GUARD"])
        for gh in (None, {"time": now, "errors": {}, "runners": [], "runners_error": "gh api runners rc=1"},
                   {"time": now, "errors": {}, "runners": RUNNERS_READ, "runners_error": None}):
            rec = pool.status(gh, s, now, keys)
            self.assertEqual(rec["alerts"], keys)
            self.assertEqual(set(rec), POOL_KEYS_PART1, "a read with runners gives a pool file without them")
            self.assertFalse(any(pool.owns(k) for k in ("RUNNERS", "SOURCE_STALE:runners")))
            self.assertEqual(mmschema.validate(rec, mmschema.load("status")), [])

    def test_schema_rejects_bad_new_fields(self):
        st = status_rec(time.time())
        self.assertEqual(mmschema.validate(st, mmschema.load("status")), [])
        for bad in ({"facts": {"cores": "12"}}, {"facts": {"gpu": 1}}, {"calls": 1.5}, {"idle_minutes": "3"},
                    {"money": {"used_usd": 1}}, {"runners": []}, {"runners_error": None}):
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
        now = clock["t"] - 10
        row = mmdecide.resource_row(mmdecide.machine_resource(st, "test-machine", now, self.s()), now, self.s())
        self.assertEqual((row["idle"], row["idle_min"], row["state"]), (True, 1, "GREEN"))
        row = mmdecide.resource_row(mmdecide.machine_resource(st, "test-machine", now + 60, self.s()), now + 60, self.s())
        self.assertEqual((row["idle"], row["idle_min"], row["state"]), (None, None, "UNKNOWN"), "never idle when stale")


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
