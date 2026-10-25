# SPDX-License-Identifier: Apache-2.0
"""The [schedule] settings: defaults equal the old literals, ranges, the old last good values; the jobs' intervals
(Supervisor.due), the loop's wait read before each wait (`mm run --tick-seconds` overrides it), the watchdog's
StartInterval (mm install, byte-identical at the default), `mm check`'s W_SCHEDULE lines, the drill's tick limit, the
evidence bundle's metrics rows and `mm settings show` (read-only)."""
import json
import os
import plistlib
import re
import time
import unittest
from unittest import mock

import mmtest
from mmtest import TempData, mmcore, mmread
import mmdecide
import mmdrill
import mmevidence
import mminstall
import mmsuper

KEYS = ("schedule.tick_s", "schedule.disk_s", "schedule.ps_s", "schedule.minute_s", "schedule.metrics_s",
        "schedule.readings_check_hours", "schedule.watchdog_s")
TODAY = {"schedule.tick_s": 10, "schedule.disk_s": 300, "schedule.ps_s": 30, "schedule.minute_s": 60,
         "schedule.metrics_s": 60, "schedule.readings_check_hours": 24, "schedule.watchdog_s": 60}
ERROR = re.compile(r"^E_[A-Z_]+ .+; fix: .+$")
TOKEN = "ghp" + "_" + "PLANTED" * 3 + "12"  # a token shape, built here so the source holds none


def old_plist(label, args, env, keepalive):
    """mminstall.plist before schedule.watchdog_s, verbatim (the bytes the default must keep)."""
    d = {"Label": label, "ProgramArguments": mminstall.mm_argv(*args), "EnvironmentVariables": env, "RunAtLoad": True,
         "ExitTimeOut": mminstall.EXIT_TIMEOUT_S,
         "ProcessType": "Interactive", "StandardOutPath": os.path.join(env["MM_DATA"], "state", label + ".out"),
         "StandardErrorPath": os.path.join(env["MM_DATA"], "state", label + ".out")}
    if keepalive:
        d.update(KeepAlive=True, ThrottleInterval=10)
    else:
        d["StartInterval"] = 60
    return plistlib.dumps(d)


class Table(TempData):
    def test_defaults_are_the_old_intervals_and_the_file_says_so(self):
        d = mmcore.defaults()
        self.assertEqual({k: d[k] for k in KEYS}, TODAY)
        self.assertEqual([k for k in d if k.startswith("schedule.")], list(KEYS), "settings.default.toml's order")
        self.assertEqual(list(d)[3:10], list(KEYS), "[schedule] right after [mode]")
        self.assertIsInstance(d["schedule.watchdog_s"], int)
        # each line names its default and its range, and they match the code's table
        text = open(mmcore.DEFAULT_SETTINGS).read()
        for k in KEYS:
            kind, lo, hi = mmcore.SCHEMA[k]
            line = [l for l in text.splitlines() if l.startswith(k.split(".")[1] + " = ")][0]
            self.assertIn("default %g; range %g-%g; authority: the owner" % (d[k], lo, hi), line, k)
            self.assertTrue(lo <= d[k] <= hi, k)

    def test_ranges(self):
        good = mmtest.base_settings()
        self.assertEqual(mmcore.validate(good), [])
        for k, bad in (("schedule.tick_s", 4.9), ("schedule.tick_s", 31), ("schedule.tick_s", 0), ("schedule.disk_s", 59),
                       ("schedule.disk_s", 601), ("schedule.ps_s", 9), ("schedule.ps_s", 61), ("schedule.minute_s", 301),
                       ("schedule.metrics_s", 601), ("schedule.readings_check_hours", 0.5),
                       ("schedule.watchdog_s", 60.5), ("schedule.watchdog_s", 9), ("schedule.watchdog_s", 601),
                       ("schedule.tick_s", True), ("schedule.tick_s", "10")):
            self.assertTrue(mmcore.validate(dict(good, **{k: bad})), (k, bad))
        for k, ok in (("schedule.tick_s", 5), ("schedule.tick_s", 30), ("schedule.tick_s", 12.5),
                      ("schedule.watchdog_s", 10), ("schedule.watchdog_s", 600), ("schedule.metrics_s", 10)):
            self.assertEqual(mmcore.validate(dict(good, **{k: ok})), [], (k, ok))

    def test_an_older_last_good_file_restores_the_schedule_defaults(self):
        got = mmtest.restored_without(*KEYS)
        self.assertEqual({k: got[k] for k in KEYS}, TODAY)

    def test_a_bad_file_keeps_the_last_good_schedule(self):
        self.write_settings(**{"schedule.tick_s": 15})
        st = mmcore.Settings()
        self.assertEqual(st.load()["schedule.tick_s"], 15)
        self.write_settings(**{"schedule.tick_s": 0})
        self.assertEqual(st.load()["schedule.tick_s"], 15)
        self.assertIn("schedule.tick_s: 0 is not num in 5..30", st.problem)
        self.assertEqual(mmcore.Settings().load()["schedule.tick_s"], 15, "a new reader: the last good values")

    def test_no_timing_check_makes_settings_bad(self):
        over = {"other.heartbeat_max_age_s": 20, "other.status_fresh_s": 15, "self.max_tick_s": 3600,
                "schedule.ps_s": 10, "schedule.tick_s": 30, "schedule.watchdog_s": 600}
        s = dict(mmtest.base_settings(), **over)
        self.assertEqual(mmcore.validate(s), [])
        self.assertGreaterEqual(len(mmdecide.timing_warnings({"service": True, "pool": True}, s)), 5)
        self.write_settings(**over)
        st = mmcore.Settings()
        self.assertIsNotNone(st.load())
        self.assertIsNone(st.problem)

    def test_each_fix_names_a_value_the_settings_take(self):
        """Every W_SCHEDULE line of the vectors: its fix value passes validate and ends that line."""
        import run_vectors
        self.assertEqual(mmdecide.GITHUB_STALE_MINUTES_MAX, mmcore.SCHEMA["github.stale_minutes"][2])
        n = 0
        for fn, case, v, s in run_vectors.load_all():
            if fn != "timing_warnings":
                continue
            for line in v["expected"]:
                m = re.search(r"; fix: set (\S+) to ([0-9.]+) or (?:more|less)", line)
                if not m:
                    continue
                n += 1
                value = float(m.group(2)) if "." in m.group(2) else int(m.group(2))
                fixed = dict(s, **{m.group(1): value})
                self.assertEqual(mmcore.validate(fixed), [], (case, line))
                subject = line.split(" ")[1] + " "
                self.assertFalse([x for x in mmdecide.timing_warnings(v["input"], fixed)
                                  if x.startswith("W_SCHEDULE " + subject)], (case, line))
        self.assertGreaterEqual(n, 20)


class Jobs(TempData):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir(slots=5)

    def sup(self, clock):
        def sampler(now, ticks):
            return {"t": now, "free_pct": 80, "swap_used_mb": 100, "swap_total_mb": 2048, "comp_mb": 300,
                    "pressure": 1, "seg_pct": 1, "load1": 1, "load5": 1, "sys_pct": None, "sys_pct_fixture": 10}, ticks
        sup = mmsuper.Supervisor(self.profile(), kernel=False, clock=lambda: clock["t"], sampler=sampler, sizes=False,
                                 slow_jobs=False, check_readings=False)
        sup.check_on = True  # the readings check too (its commands faked below)
        calls = []
        orig = sup.due

        def due(name, every, now):
            r = orig(name, every, now)
            calls.append((name, every, r))
            return r
        sup.due = due
        return sup, calls

    def every(self, calls):
        return {name: every for name, every, _ in calls}

    def test_each_job_takes_its_interval_from_the_settings(self):
        clock = {"t": time.time()}
        with mock.patch.object(mmsuper.mmread, "check_readings", lambda now: ([], {}, {})):
            sup, calls = self.sup(clock)
            sup.tick()
            got = self.every(calls)
            self.assertEqual({k: got[k] for k in ("readings_check", "disk", "ps", "minute", "metrics")},
                             {"readings_check": 86400, "disk": 300, "ps": 30, "minute": 60, "metrics": 60})
            self.assertTrue(all(r for name, _, r in calls if name in ("readings_check", "disk", "ps", "minute",
                                                                      "metrics")), "each runs on the first tick")
            self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "schedule.disk_s": 120,
                                   "schedule.ps_s": 20, "schedule.minute_s": 45, "schedule.metrics_s": 90,
                                   "schedule.readings_check_hours": 2})
            del calls[:]
            clock["t"] += 10
            sup.tick()  # the changed file counts from this tick on, without a restart
            got = self.every(calls)
            self.assertEqual({k: got[k] for k in ("readings_check", "disk", "ps", "minute", "metrics")},
                             {"readings_check": 7200, "disk": 120, "ps": 20, "minute": 45, "metrics": 90})

    def test_an_interval_rounds_up_to_whole_ticks(self):
        clock = {"t": time.time()}
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "schedule.ps_s": 25})
        sup, calls = self.sup(clock)
        sup.check_on = False
        for _ in range(7):
            sup.tick()
            clock["t"] += 10
        self.assertEqual([r for name, _, r in calls if name == "ps"], [True, False, False, True, False, False, True],
                         "ps_s 25 at 10 s ticks: every 30 s")
        lines = open(os.path.join(self.data, "metrics.csv")).read().splitlines()
        self.assertEqual(len(lines), 1 + 2, "a metrics.csv row at 0 and 60 s (schedule.metrics_s 60)")


class StubSupervisor:
    """A supervisor whose tick only reads the settings (and lets the test change the file before it)."""

    def __init__(self, before_tick, starts, clock):
        self.settings, self.kernel, self.mid = mmcore.Settings(), None, "lab1"
        self.n, self.before, self.starts, self.clock = 0, before_tick, starts, clock

    def tick(self):
        self.n += 1
        self.starts.append(self.clock.t)
        self.before(self.n)
        self.settings.load()

    def check_self(self, tick_s, errors):
        return {"action": "ok", "reasons": []}


class FakeTime:
    """mmsuper's time: monotonic and sleep on a fake clock, everything else real."""

    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t

    def sleep(self, d):
        self.t += d

    def __getattr__(self, name):
        return getattr(time, name)


class Loop(TempData):
    def waits(self, before_tick, **kw):
        clock, starts = FakeTime(), []
        with mock.patch.object(mmsuper, "time", clock), \
                mock.patch.object(mmsuper, "Supervisor", lambda *a, **k: StubSupervisor(before_tick, starts, clock)):
            self.assertEqual(mmsuper.run_loop(self.profile(), ticks=3, kernel=False, **kw), 0)
        return [round(b - a, 6) for a, b in zip(starts, starts[1:])]

    def rewrite(self, value):
        def before(n):
            if n == 2:
                self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "schedule.tick_s": value})
        return before

    def test_the_wait_follows_settings_toml_without_a_restart(self):
        self.assertEqual(self.waits(self.rewrite(7)), [10, 7])

    def test_a_bad_value_keeps_the_last_good_wait(self):
        self.assertEqual(self.waits(self.rewrite(0)), [10, 10])

    def test_the_option_overrides_the_setting(self):
        self.assertEqual(self.waits(self.rewrite(7), tick_seconds=0.5), [0.5, 0.5])

    def test_tick_wait_s(self):
        class Sup:
            settings = mmcore.Settings()
        Sup.settings.values = {"schedule.tick_s": 12}
        self.assertEqual(mmsuper.tick_wait_s(None, Sup, {"schedule.tick_s": 10}), 12)
        self.assertEqual(mmsuper.tick_wait_s(0, Sup, {"schedule.tick_s": 10}), 0, "0 stays 0 (tests)")
        self.assertEqual(mmsuper.tick_wait_s(None, None, {"schedule.tick_s": 10}), 10)
        Sup.settings.values = None  # never a good read: the settings at start, or the defaults
        self.assertEqual(mmsuper.tick_wait_s(None, Sup, {"schedule.tick_s": 10}), 10)


class Watchdog(TempData):
    ENV = {"MM_PROFILE": "/p.toml", "MM_DATA": "/d", "PATH": "/usr/bin:/bin"}

    def test_the_plist_at_the_default_is_byte_identical(self):
        for keep in (True, False):
            want = old_plist("lab", ["x"], self.ENV, keep)
            self.assertEqual(mminstall.plist("lab", ["x"], self.ENV, keep), want, keep)
            self.assertEqual(mminstall.plist("lab", ["x"], self.ENV, keep, 60), want, keep)
        self.assertEqual(mminstall.plist("lab", ["x"], self.ENV, True, 120), old_plist("lab", ["x"], self.ENV, True),
                         "the supervisor (KeepAlive) never gets a StartInterval")
        got = mminstall.plist("lab", ["x"], self.ENV, False, 120)
        self.assertEqual(plistlib.loads(got)["StartInterval"], 120)
        self.assertIn(b"<key>StartInterval</key>\n\t<integer>120</integer>", got)

    def fake_launchctl(self):
        f = os.path.join(self.root, "fake-launchctl")
        with open(f, "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")  # loaded at once: no bootstrap retry
        os.chmod(f, 0o700)
        os.environ["MM_LAUNCHCTL"] = f

    def plists(self):
        sup, wd = mminstall.labels(self.profile())
        d = os.path.join(self.root, "home", "Library", "LaunchAgents")
        return [open(os.path.join(d, label + ".plist"), "rb").read() for label in (sup, wd)]

    def test_install_writes_the_setting_and_check_compares_it(self):
        self.fake_launchctl()
        prof = self.profile()
        sup, wd = mminstall.labels(prof)
        with mock.patch.object(mmread.plat, "SERVICE", "launchd"):
            rec = mminstall.install(prof)
            self.assertEqual([w for w in rec["warnings"] if w.startswith("W_SCHEDULE")], [])
            env = {"MM_PROFILE": prof["_file"], "MM_DATA": self.data, "PATH": mminstall.service_path(prof)[0]}
            self.assertEqual(self.plists(), [old_plist(sup, ("run", "--allow-live-slots"), env, True),
                                             old_plist(wd, ("watchdog",), env, False)], "byte-identical at the default")
            s = mmcore.Settings().load()
            self.assertEqual(mminstall.watchdog_interval_lines(prof, s), [])
            self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "schedule.watchdog_s": 120})
            s = mmcore.Settings().load()
            self.assertEqual(mminstall.watchdog_interval_lines(prof, s), [
                "W_SCHEDULE the installed watchdog's StartInterval is 60, schedule.watchdog_s is 120; fix: mm install "
                "again (with mode.observe = true)"])
            self.assertIn(mminstall.watchdog_interval_lines(prof, s)[0], mminstall.check())
            mminstall.install(prof)
            got = [plistlib.loads(b) for b in self.plists()]
            self.assertEqual((got[0].get("StartInterval"), got[1]["StartInterval"]), (None, 120))
            self.assertEqual(mminstall.watchdog_interval_lines(prof, s), [])
            self.assertFalse([x for x in mminstall.check() if x.startswith("W_SCHEDULE")])

    def test_install_prints_the_w_schedule_lines_of_mm_check(self):
        self.fake_launchctl()
        prof = self.profile()
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10,
                               "other.heartbeat_max_age_s": 59})
        with mock.patch.object(mmread.plat, "SERVICE", "launchd"):
            rec = mminstall.install(prof)
            want = [w for w in mminstall.check() if w.startswith("W_SCHEDULE")]
        self.assertEqual([w.split(" ")[1] for w in want], ["other.heartbeat_max_age_s"])
        self.assertEqual([w for w in rec["warnings"] if w.startswith("W_SCHEDULE")], want)

    def test_watchdog_interval_lines(self):
        prof = self.profile()
        wd = mminstall.labels(prof)[1]
        d = os.path.join(self.root, "home", "Library", "LaunchAgents")
        os.makedirs(d)
        f = os.path.join(d, wd + ".plist")
        s = dict(mmtest.base_settings(), **{"schedule.watchdog_s": 90})
        with mock.patch.object(mmread.plat, "SERVICE", "launchd"):
            self.assertEqual(mminstall.watchdog_interval_lines(prof, s), [], "not installed")
            with open(f, "wb") as fh:
                fh.write(mminstall.plist(wd, ["watchdog"], self.ENV, True))  # no StartInterval
            self.assertEqual(mminstall.watchdog_interval_lines(prof, s), [
                "W_SCHEDULE the installed watchdog's StartInterval is unset, schedule.watchdog_s is 90; fix: mm install "
                "again (with mode.observe = true)"])
            for junk in (b"not a plist\x00\x01", b"<?xml version='1.0'?><plist><dict><key>x</key>", b""):
                with open(f, "wb") as fh:
                    fh.write(junk)
                self.assertEqual(mminstall.watchdog_interval_lines(prof, s), [], junk)
            with open(f, "wb") as fh:
                fh.write(mminstall.plist(wd, ["watchdog"], self.ENV, False, 90))
            self.assertEqual(mminstall.watchdog_interval_lines(prof, s), [])
        with mock.patch.object(mmread.plat, "SERVICE", None):
            with open(f, "wb") as fh:
                fh.write(mminstall.plist(wd, ["watchdog"], self.ENV, False, 60))
            self.assertEqual(mminstall.watchdog_interval_lines(prof, s), [], "no launchd: nothing to compare")

    def test_timing_context(self):
        prof = self.profile()
        with mock.patch.object(mmread.plat, "SERVICE", "launchd"):
            self.assertEqual(mminstall.timing_context(prof), {"service": True, "pool": True})
        with mock.patch.object(mmread.plat, "SERVICE", None):
            self.assertEqual(mminstall.timing_context(dict(prof, ci={})), {"service": False, "pool": False})


class Check(TempData):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir()

    def check(self, *args):
        r = self.mm("check", *args)
        return r.returncode, mmtest.without_platform(r.stdout.strip().splitlines())

    def test_w_schedule_lines_never_fail_the_check(self):
        self.assertEqual(self.check(), (0, ["check=ok"]), "the defaults: no warning")
        self.write_settings(**{"slots.cores": 10, "other.heartbeat_max_age_s": 59, "schedule.tick_s": 15,
                               "schedule.ps_s": 10})
        rc, out = self.check()
        self.assertEqual(rc, 0, out)
        self.assertEqual(out[-1], "check=ok")
        self.assertEqual([x.split(" ")[1] for x in out[:-1]], ["other.heartbeat_max_age_s", "schedule.ps_s"])
        self.assertTrue(all(re.match(r"^W_SCHEDULE .+; fix: .+$", x) for x in out[:-1]), out)
        r = self.mm("check", "--json")
        obj = json.loads(r.stdout)
        self.assertEqual((r.returncode, obj["problems"]), (0, []))
        self.assertEqual([w for w in obj["warnings"] if w.startswith("W_SCHEDULE")], out[:-1])
        self.write_settings(**{"other.heartbeat_max_age_s": 59, "schedule.tick_s": 0})
        rc, out = self.check()
        self.assertEqual(rc, 1)
        self.assertEqual([x.split(" ")[0] for x in out], ["E_SETTINGS"], "a bad file first; no W_SCHEDULE line")

    def test_the_supervisors_settings(self):
        import mmadapters
        prof = self.profile()
        self.assertEqual(mmadapters.settings(prof).real_slots, os.path.join(self.q, "slots"))
        self.assertIsNone(mmadapters.settings(dict(prof, queue={"adapter": "nope"})).real_slots)
        self.assertIsNone(mmadapters.settings(dict(prof, queue={})).real_slots)

    def test_check_refuses_what_the_supervisor_refuses(self):
        self.write_settings(**{"mode.slot_writes": "test", "mode.slots_file": os.path.join(self.q, "slots")})
        rc, out = self.check()
        self.assertEqual(rc, 1)
        self.assertIn("mode.slot_writes test must not name the real gates/slots", out[0])
        self.assertTrue(out[0].startswith("E_SETTINGS "), out)


class Drill(TempData):
    def test_the_drill_refuses_a_tick_over_20_s(self):
        prof, now = self.profile(), time.time()
        s = dict(mmtest.base_settings(), **{"schedule.tick_s": 20.5})
        why = mmdrill.preconditions(prof, None, now, s)
        self.assertEqual(why, "E_DRILL schedule.tick_s 20.5 is over 20 s: the drill trusts status.json only up to 30 s "
                              "old; fix: set schedule.tick_s to 20 or less for the drill")
        self.assertRegex(why, ERROR)
        for ok in (dict(s, **{"schedule.tick_s": 20}), None):
            self.assertNotIn("schedule.tick_s", mmdrill.preconditions(prof, None, now, ok) or "")
        rec = mmdrill.run(prof, s, None, sleep=lambda x: None)
        self.assertEqual(rec, {"refused": why})


class Evidence(TempData):
    def bundle_rows(self, metrics_s, window, n, setting=None):
        """A bundle's metrics.csv rows: n rows written every metrics_s, the bundle made at schedule.metrics_s setting
        (default: metrics_s)."""
        now = time.time()
        with open(os.path.join(self.data, "metrics.csv"), "w") as f:
            f.write("time,machine_id,state\n")
            for k in range(n - 1, -1, -1):
                f.write("%s,lab1,GREEN\n" % mmcore.now_local(now - k * metrics_s))
        s = dict(mmtest.base_settings(), **{"schedule.metrics_s": setting or metrics_s, "evidence.window_minutes": window})
        d = mmevidence.bundle({"seq": 1, "key": "X", "name": "X", "level": "ATTENTION", "text": "x"}, s, now,
                              extra={"profile": self.profile()})
        return open(os.path.join(d, "metrics.csv")).read().splitlines()

    def test_a_bundle_holds_every_metrics_row_of_its_window(self):
        rows = self.bundle_rows(10, 240, 1600)
        self.assertEqual(rows[0], "time,...", "the header is past the tail")
        self.assertGreaterEqual(len(rows) - 1, 1440, "a row every 10 s for 240 min")
        rows = self.bundle_rows(10, 240, 1600, setting=60)
        self.assertGreaterEqual(len(rows) - 1, 1440, "rows of 10 s still fill the window after metrics_s went to 60")
        rows = self.bundle_rows(60, 30, 600)
        self.assertEqual(len(rows) - 1, 31, "the default: the last 400 lines are read, 31 in the window")


class Show(TempData):
    def show(self, *args):
        r = self.mm("settings", *args)
        return r.returncode, r.stdout.strip().splitlines()

    def test_forms(self):
        rc, out = self.show("show", "schedule")
        self.assertEqual(rc, 0)
        self.assertEqual(out, ["%s=%s default=%s differs=no" % (k, TODAY[k], TODAY[k]) for k in KEYS])
        self.assertEqual(self.show("show", "mode.observe"), (0, ["mode.observe=true default=true differs=no"]))
        self.assertEqual(self.show("show", "slots.cores"), (0, ["slots.cores=10 default=0 differs=yes"]),
                         "the test's own slots.cores")
        rc, out = self.show("show")
        self.assertEqual(rc, 0)
        self.assertEqual([line.split("=")[0] for line in out], list(mmcore.defaults()))
        self.assertEqual(len(out), len(mmcore.SCHEMA))
        self.assertEqual(sum(line.endswith(" differs=yes") for line in out), 3, "the test's cores, floor, ceiling")
        r = self.mm("settings", "show", "schedule", "--json")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(len(r.stdout.strip().splitlines()), 1)
        obj = json.loads(r.stdout)
        self.assertEqual(obj, {"in_force": "current", "problem": None,
                               "settings": {k: {"value": v, "default": v, "differs": False} for k, v in TODAY.items()}})

    def test_values_are_as_written(self):
        self.write_settings(**{"slots.cores": 0, "slots.floor": 3, "slots.ceiling": 10})
        self.assertEqual(self.show("show", "slots.cores"), (0, ["slots.cores=0 default=0 differs=no"]),
                         "slots.cores 0, not the core count")
        r = self.mm("settings", "show", "slots.cores", "--json")
        self.assertEqual(json.loads(r.stdout)["settings"], {"slots.cores": {"value": 0, "default": 0, "differs": False}})

    def test_values_are_quoted_masked_and_cleaned(self):
        self.write_settings(**{"slots.cores": 10, "schedule.tick_s": 12.5, "slots.green_load1_per_core": 1.0,
                               "mode.slots_file": "/tmp/a\u0007b‮c", "launch_gate.enabled": True,
                               "heartbeat.url": "https://user:pw@example.com:8443/x?token=" + TOKEN})
        out = dict(line.split("=", 1) for line in self.show("show")[1])
        self.assertEqual(out["schedule.tick_s"], "12.5 default=10 differs=yes")
        self.assertEqual(out["slots.green_load1_per_core"], "1 default=0.8 differs=yes")
        self.assertEqual(out["mode.slots_file"], '"/tmp/a?b?c" default="" differs=yes')
        self.assertEqual(out["mode.slot_writes"], "off default=off differs=no")
        self.assertEqual(out["launch_gate.enabled"], "true default=false differs=yes")
        self.assertEqual(out["heartbeat.url"], '"https://example.com/..." default="" differs=yes')
        r = self.mm("settings", "show", "--json")
        self.assertNotIn("PLANTED", r.stdout)
        self.assertNotIn("pw@", r.stdout)
        got = json.loads(r.stdout)["settings"]
        self.assertEqual(got["heartbeat.url"]["value"], "https://example.com/...")
        self.assertEqual(got["mode.slots_file"]["value"], "/tmp/a?b?c")
        self.assertIs(got["launch_gate.enabled"]["value"], True)
        self.assertEqual(got["schedule.tick_s"], {"value": 12.5, "default": 10, "differs": True})
        self.write_settings(**{"mode.slots_file": "true"})
        self.assertEqual(self.show("show", "mode.slots_file")[1], ['mode.slots_file="true" default="" differs=yes'],
                         "a string never reads as a word of the tool's own")
        self.write_settings(**{"mode.slots_file": "/tmp/" + TOKEN})
        self.assertEqual(self.show("show", "mode.slots_file")[1], ['mode.slots_file="/tmp/***" default="" differs=yes'],
                         "a text setting is masked")
        r = self.mm("settings", "show", "mode.slots_file", "--json")
        self.assertNotIn("PLANTED", r.stdout)
        self.assertEqual(json.loads(r.stdout)["settings"]["mode.slots_file"]["value"], "/tmp/***")

    def test_a_bad_file_shows_the_values_in_force_and_its_problem(self):
        self.write_settings(**{"slots.cores": 10, "schedule.tick_s": 15})
        mmcore.Settings().load()  # the supervisor's read: saves the last good values
        with open(os.path.join(self.data, "settings.toml"), "w") as f:
            f.write('[schedule]\ntick_s = 0\n"odd\\u0007key" = 1\n')
        rc, out = self.show("show", "schedule.tick_s")
        self.assertEqual(rc, 1)
        self.assertEqual(out, ["ACTION SETTINGS_BAD settings invalid; the last good values stay: schedule.odd?key: "
                               "unknown setting; schedule.tick_s: 0 is not num in 5..30 | do: mm check",
                               "schedule.tick_s=15 default=10 differs=yes"])
        r = self.mm("settings", "show", "schedule.tick_s", "--json")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(r.stdout), {
            "in_force": "last_good", "problem": "schedule.odd?key: unknown setting; schedule.tick_s: 0 is not num in "
            "5..30", "settings": {"schedule.tick_s": {"value": 15, "default": 10, "differs": True}}})
        with open(os.path.join(self.data, "settings.toml"), "w") as f:
            f.write('[mode]\nslot_writes = "%s"\n' % TOKEN)  # a bad value reaches the problem text: masked
        rc, out = self.show("show", "mode.slot_writes")
        self.assertEqual((rc, out), (1, ["ACTION SETTINGS_BAD settings invalid; the last good values stay: "
                                         "mode.slot_writes: '***' is not choice:off?test?live | do: mm check",
                                         "mode.slot_writes=off default=off differs=no"]))
        r = self.mm("settings", "show", "mode.slot_writes", "--json")
        self.assertNotIn("PLANTED", r.stdout)
        self.assertEqual(json.loads(r.stdout)["problem"], "mode.slot_writes: '***' is not choice:off?test?live")
        os.remove(os.path.join(self.data, "state", "settings.lastgood.json"))
        rc, out = self.show("show", "schedule.tick_s")
        self.assertEqual(rc, 1)
        self.assertTrue(out[0].startswith("ACTION SETTINGS_BAD settings invalid and no last good values: the tool reads "
                                          "and controls nothing (shown: the defaults): "), out)
        self.assertLessEqual(len(out[0]), mmcore.LINE_MAX)
        self.assertEqual(out[1:], ["schedule.tick_s=10 default=10 differs=no"])
        self.assertEqual(json.loads(self.mm("settings", "show", "schedule.tick_s", "--json").stdout)["in_force"], "none")

    def test_a_value_only_the_supervisor_refuses_is_a_problem(self):
        q = self.queue_dir()
        self.write_settings(**{"mode.slot_writes": "test", "mode.slots_file": os.path.join(q, "slots")})
        rc, out = self.show("show", "mode.slot_writes")
        self.assertEqual(rc, 1)
        self.assertIn("mode.slot_writes test must not name the real gates/slots", out[0])
        self.assertEqual(out[1], "mode.slot_writes=off default=off differs=no", "no last good values: the defaults")

    def test_it_writes_nothing(self):
        os.rmdir(os.path.join(self.data, "state"))  # mm makes it for every other verb

        def snap():
            out = []
            for d, _, files in os.walk(self.root):
                out.append((os.path.relpath(d, self.root), -1))
                out += [(os.path.relpath(os.path.join(d, f), self.root), os.stat(os.path.join(d, f)).st_mtime_ns)
                        for f in files]
            return sorted(out)
        before = snap()
        for args in (("show",), ("show", "schedule", "--json"), ("show", "nope"), ()):
            self.mm("settings", *args)
        self.assertEqual(snap(), before, "no file and no folder made")
        with open(os.path.join(self.data, "settings.toml"), "a") as f:
            f.write("[broken\n")
        before = snap()
        self.assertEqual(self.show("show")[0], 1)
        self.assertEqual(snap(), before, "a bad file: still nothing made")
        self.assertFalse(os.path.exists(os.path.join(self.data, "state")))

    def test_usage_errors_are_one_line(self):
        for args in ((), ("list",), ("show", "a", "b"), ("show", "nope"), ("show", "schedule.nope"),
                     ("show", "sched\u0007ule")):
            rc, out = self.show(*args)
            self.assertEqual((rc, len(out)), (2, 1), (args, out))
            self.assertRegex(out[0], r"^E_USAGE .+; fix: .+$")
            self.assertNotIn("\u0007", out[0])
        self.assertEqual(self.show("show", "nope")[1], ["E_USAGE no setting or section nope; fix: mm settings show, or "
                                                        "mm settings show SECTION"])
        self.assertEqual(self.show("show", "sched\u0007ule")[1][0].split(";")[0],
                         'E_USAGE no setting or section "sched?ule"')
        self.assertEqual(self.show()[1], ["E_USAGE settings show [KEY|SECTION]; fix: mm help"])
        help_ = self.mm("help").stdout
        self.assertIn("  mm settings show [KEY|SECTION]   the settings in force", help_)


if __name__ == "__main__":
    unittest.main()
