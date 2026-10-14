# SPDX-License-Identifier: Apache-2.0
"""T1 parsers, T6 alert rules and the alert store, T7 the slot controller, T10 live tools by name, T12 settings,
and secret masking (B1) at the core level."""
import json
import os
import subprocess
import time
import unittest

from mmtest import FIX, TempData, at, base_settings, mmcore, mmread
import ad_ci_github
import ad_deliver_claude
import ad_queue_fifo
import mmalerts

R = lambda n: open(os.path.join(FIX, n)).read()  # noqa: E731
S = base_settings()
NOW = 1_800_000_000.0
T0 = NOW
G = "GREEN"
LIVE = {"names": ["go", "testshard", "test2json"], "suffixes": [".test"], "path_regexes": ["/go-build[0-9]+/"]}


class T1Parsers(unittest.TestCase):
    def test_vm_stat_pressure_swap_load_df(self):
        d = mmread.parse_vm_stat(R("vm_stat.txt"))
        self.assertEqual(d["page_size"], 16384)
        self.assertIn("Pages occupied by compressor", d)
        self.assertIn("Translation faults", d)
        self.assertEqual(mmread.parse_vm_stat("garbage\n"), {})
        self.assertEqual(mmread.parse_memory_pressure("System-wide memory free percentage: 57%"), 57.0)
        self.assertIsNone(mmread.parse_memory_pressure("nothing"))
        self.assertEqual(mmread.parse_swapusage("vm.swapusage: total = 2048.00M  used = 499.38M  free = 1.5G"), (2048.0, 499.38))
        self.assertEqual(mmread.parse_swapusage("total = 2.00G  used = 512.00K  free = 2.0G"), (2048.0, 0.5))
        self.assertIsNone(mmread.parse_swapusage("total = ?"))
        self.assertEqual(mmread.parse_loadavg("{ 1.13 1.60 1.82 }"), (1.13, 1.60, 1.82))
        self.assertIsNone(mmread.parse_loadavg("{ }"))
        self.assertGreater(mmread.parse_df_free_gb(R("df.txt")), 1)
        self.assertIsNone(mmread.parse_df_free_gb("x"))

    def test_queue_sampler_and_history_lines(self):
        s = ad_queue_fifo.parse_load_line("10-14 09:14 load 347.39 97.03 38.93 free 69% swap 1001.69M comp 2023M sys 24.97% "
                                          "fsev 9M slots 5/5 waiting 7", 2026)
        self.assertEqual((s["load1"], s["free_pct"], s["swap_used_mb"], s["comp_mb"], s["busy"], s["slots"], s["waiting"]),
                         (347.39, 69.0, 1001.69, 2023.0, 5, 5, 7))
        self.assertEqual(s["t"], at("2026-10-14 09:14"))
        self.assertIsNone(ad_queue_fifo.parse_load_line("", 2026))
        rows = [ad_queue_fifo.parse_history_line(l) for l in open(os.path.join(FIX, "history-sample.log"))]
        self.assertTrue(rows and all(rows), "every fixture history row parses")
        self.assertIsNone(ad_queue_fifo.parse_history_line("short\tline"))

    def test_usage_state(self):
        checked = json.load(open(os.path.join(FIX, "usage-state.json")))["checked_at"]
        u = ad_deliver_claude.read_usage(os.path.join(FIX, "usage-state.json"), checked + 60)
        self.assertEqual(u["codex_week"], 100)
        self.assertAlmostEqual(u["age_s"], 60, delta=1)
        self.assertIsNone(ad_deliver_claude.read_usage(os.path.join(FIX, "pmset-ac.txt"), 0))

    def test_pmset_kernel_ps(self):
        self.assertTrue(mmread.parse_pmset(R("pmset-ac.txt")))
        self.assertFalse(mmread.parse_pmset("Now drawing from 'Battery Power'"))
        self.assertIsNone(mmread.parse_pmset(""))
        evs = [mmread.parse_kernel_line(l) for l in open(os.path.join(FIX, "kernel-sample.txt"))]
        self.assertEqual([e["kind"] for e in evs if e], ["no-paging-space", "suspending", "no-paging-space", "suspending"])
        sus = [e for e in evs if e and e["kind"] == "suspending"]
        self.assertEqual((sus[0]["process"], sus[0]["pid"], sus[0]["why"]), ("AppA", 4242, "swap exhaustion"))
        nd = [mmread.parse_kernel_line(l) for l in open(os.path.join(FIX, "kernel-sample.ndjson"))]
        self.assertEqual([e["kind"] for e in nd if e], ["no-paging-space", "suspending", "no-paging-space", "suspending"])
        ps = mmread.parse_ps("  1 0 1024 0.5 /sbin/launchd\n 20 1 2048 12.0 /usr/bin/go\nbad line\n")
        self.assertEqual([(p["pid"], p["comm"]) for p in ps], [(1, "/sbin/launchd"), (20, "/usr/bin/go")])
        self.assertEqual(mmread.descendants([{"pid": 2, "ppid": 1}, {"pid": 3, "ppid": 2}, {"pid": 4, "ppid": 9}], 1), [1, 2, 3])

    def test_billing_parser_exponent_and_errors(self):
        month = "2026-10"
        text = json.dumps({"usageItems": [
            {"date": "2026-10-01T00:00:00Z", "product": "actions", "sku": "Actions Linux", "quantity": 33582,
             "grossAmount": 201.492, "netAmount": 0},
            {"date": "2026-10-02T00:00:00Z", "product": "Actions", "sku": "Actions storage", "quantity": 1.5,
             "grossAmount": 4.987e-06, "netAmount": 0},
            {"date": "2026-10-02T00:00:00Z", "product": "copilot", "sku": "x", "quantity": 9, "grossAmount": 9, "netAmount": 9}]})
        m, g, n = ad_ci_github.parse_billing(text, month)
        self.assertEqual(str(m), "33582")
        self.assertEqual(str(g), "201.492004987", "the exponent number adds exactly")
        self.assertEqual(n, 0)
        for bad in ('{"usageItems": [{"date": "2026-10-01", "product": "actions", "sku": "Actions Linux", "quantity": "5"}]}',
                    '{"usageItems": [{"date": "2026-10-01", "product": "actions", "sku": "Actions Linux", "quantity": true}]}',
                    '{"usageItems": [{"date": "2026-10-01", "product": "actions", "sku": "Actions Linux", "quantity": -1}]}',
                    '{"usageItems": [{"product": "actions"}]}', '{"x": 1}', "<html>"):
            with self.assertRaises(ad_ci_github.BillingError, msg=bad):
                ad_ci_github.parse_billing(bad, month)


class T10Names(unittest.TestCase):
    def test_names_only(self):
        def is_live(c):
            return bool(mmread.live_named([{"comm": c}], LIVE))
        for c in ["go", "/sdk/go/bin/go", "testshard", "test2json", "/var/folders/T/go-build123456/b001/methods.test",
                  "pkg.test", "/var/folders/ab/T/go-build98/b001/exe/app"]:
            self.assertTrue(is_live(c), c)
        for c in ["/bin/zsh", "zsh", "python3", "gofmt", "go-build", "testshard.py", "/w/go/src/main.go",
                  "/tmp/go-buildx/b001/exe/app", "cargo", "-zsh"]:
            self.assertFalse(is_live(c), c)

    def test_shell_text_naming_go_test_is_not_live(self):
        """Live processes started for this test: ps shows the program name, never the command text."""
        import tempfile
        d = os.path.join(tempfile.mkdtemp(prefix="mm-names-"), "go-build123", "b001")
        os.makedirs(d)
        os.symlink("/bin/sleep", os.path.join(d, "pkg.test"))
        shell = subprocess.Popen(["/bin/sh", "-c", "/bin/sleep 5; : go test ./... testshard"])
        named = subprocess.Popen([os.path.join(d, "pkg.test"), "5"])
        try:
            time.sleep(0.4)
            live = {p["pid"] for p in mmread.live_named(mmread.read_ps(), LIVE)}
            self.assertIn(named.pid, live)
            self.assertNotIn(shell.pid, live)
        finally:
            for p in [x["pid"] for x in (mmread.read_ps() or []) if x["ppid"] == shell.pid]:
                os.kill(p, 9)
            for p in (shell, named):
                p.kill()
                p.wait(5)


# name -> (snapshot planting the condition, expected level)
DRILLS = {
    "MEM_RED": ({"state": ("RED", ["compressor +2000 MB in 60 s"]), "top_outside": [("AppC", 3100.0)]}, "ACTION"),
    "MEM_AMBER": ({"state": ("AMBER", ["free 45% < 50%"])}, "ATTENTION"),
    "KERNEL_SUSPEND": ({"kernel_events": [{"kind": "suspending", "process": "AppA", "pid": 1, "why": "swap exhaustion",
                                           "time": "2026-01-01 09:13:09"}]}, "ACTION"),
    "GUARD_KILL": ({"kills_new": ['{"pid": 5, "reason": "proc-cap"}']}, "ACTION"),
    "DISK_LOW": ({"disk_gb": 35.0}, "ACTION"),
    "DISK_TREND": ({"disk_gb": 50.0, "disk_rate_gb_h": 5.0}, "ATTENTION"),
    "CACHE_BIG": ({"cache_gb": 50.0, "disk_gb": 100.0}, "ACTION"),
    "CODEX98": ({"usage": {"codex_week": 98}}, "ACTION"),
    "CODEX95": ({"usage": {"codex_week": 95}}, "ATTENTION"),
    "CLAUDE98": ({"usage": {"claude_week": 98, "claude_5h": 10}}, "ACTION"),
    "CLAUDE_PROJ": ({"usage": {"proj": 120.0}}, "ATTENTION"),
    "FIVE_H": ({"usage": {"claude_5h": 85}}, "ATTENTION"),
    "QWAIT": ({"queue": {"slots": 5, "busy": [], "tickets": [{"name": "1-2", "mode": "S", "age_s": 1500, "label": "S x"}]}},
              "ATTENTION"),
    "HEAD_BLOCK": ({"queue": {"slots": 5, "busy": [{"slot": ".slot.1", "mode": "S", "pid": 9, "label": "S 9 x",
                                                     "since": NOW - 60}],
                              "tickets": [{"name": "1-3", "mode": "X", "age_s": 700, "label": "X trim"}]}}, "ATTENTION"),
    "LONG_CALL": ({"queue": {"slots": 5, "busy": [{"slot": ".slot.2", "mode": "S", "pid": 8, "label": "S 8 go test",
                                                    "since": NOW - 1500}], "tickets": []}}, "ATTENTION"),
    "REFUSED": ({"refused_recent": [{"pid": 7, "end": NOW - 10, "mode": "A", "cwd": "/w", "cmd": "go test ./..."}]}, "ATTENTION"),
    "SLOT_CPU": ({"slot_cpu": {".slot.3": 9.0}}, "ATTENTION"),
    "IDLE_ROOM": ({"idle_minutes": 40}, "INFO"),
    "FSEV": ({"fsev_mb": 1500}, "ATTENTION"),
    "CACHE_5M": ({"cache5m": {"m5": 3e6, "h1": 1e6}}, "ATTENTION"),
    "POWER": ({"on_ac": False}, "ACTION"),
    "RESUMED": ({"resumed_gap_s": 2280}, "INFO"),
    "RECIPIENT_WAIT": ({"recipient_wait": ("Read", 900)}, "ATTENTION"),
    "SOURCE_STALE": ({"stale_sources": {"queue-sampler": "last line 400 s old"}}, "ATTENTION"),
    "GUARD_DOWN": ({"stale_sources": {"memory-guard": "heartbeat 300 s old"}}, "ACTION"),
    "JOB_DEAD": ({"jobs_dead": [(4242, "/tmp/x.rc")]}, "ATTENTION"),
    "READINGS_MISMATCH": ({"readings_mismatch": ["free_pct fast=80.0 command=60.0"]}, "ACTION"),
    "OFF": ({"off": {"off": True, "since": "2026-01-01 10:00:00", "reason": "test"}}, "ATTENTION"),
    "TRIM_NEEDED": ({"trim": {"needed_min": 70}, "trim_needed_ok": True}, "ACTION"),
    "CLEANUP_LIST": ({"cleanup": {"count": 1, "bytes": 4e9, "top": [{"rule": "R1", "path": "/w/a", "bytes": 4e9}]}}, "INFO"),
}
QUIET = [{"disk_gb": 41.0}, {"disk_gb": 100.0, "disk_rate_gb_h": 5.0}, {"cache_gb": 29.0, "disk_gb": 100.0},
         {"usage": {"codex_week": 94, "claude_week": 97, "claude_5h": 84, "proj": 95.0}},
         {"queue": {"slots": 5, "busy": [], "tickets": [{"name": "1-2", "mode": "S", "age_s": 1100, "label": "S"}]}},
         {"slot_cpu": {".slot.3": 3.9}}, {"idle_minutes": 29}, {"fsev_mb": 900}, {"cache5m": {"m5": 0.5e6, "h1": 0}},
         {"on_ac": True}, {"recipient_wait": ("Read", 600)}, {"state": ("GREEN", ["ok"])}, {"state": ("STEADY", ["x"])},
         {"readings_mismatch": []}, {"off": None}, {"trim": {"needed_min": 70}, "trim_needed_ok": False}]


class T6Alerts(TempData):
    def test_each_alert_fires_with_its_level_and_one_line(self):
        for name, (snap, level) in DRILLS.items():
            got = [c for c in mmalerts.evaluate(snap, S, NOW) if c["name"] == name]
            self.assertTrue(got, name)
            self.assertEqual(got[0]["level"], level, name)
            line = mmcore.alert_line(dict(got[0], why="new"))
            self.assertLessEqual(len(line), 200, line)
            self.assertNotIn("\n", line)

    def test_quiet_values_fire_nothing(self):
        for snap in QUIET:
            self.assertEqual(mmalerts.evaluate(snap, S, NOW), [], snap)

    def test_store_lifecycle_for_every_alert(self):
        """new -> pushed once; same -> silent; repeat time -> pushed (not INFO); absent 5 min -> cleared."""
        clock = {"t": NOW}
        st = mmcore.AlertStore(S, clock=lambda: clock["t"], mid="m1")
        for name, (snap, level) in DRILLS.items():
            c = [x for x in mmalerts.evaluate(snap, S, NOW) if x["name"] == name][0]

            def raise_once():
                st.begin()
                st.raise_(c["key"], c["name"], c["level"], c["text"], value=c["value"], band=c["band"], worse=c["worse"])
                return list(st.pushed)
            clock["t"] = NOW
            first = raise_once()
            self.assertEqual(len(first), 1, name + " first push")
            self.assertEqual((first[0]["machine_id"], first[0]["schema_version"]), ("m1", 1))
            clock["t"] = NOW + 60
            self.assertEqual(raise_once(), [], name + " dedupe")
            rep = {"ACTION": 30 * 60, "ATTENTION": 3 * 3600, "INFO": 10 * 3600}[level]
            clock["t"] = NOW + 60 + rep
            self.assertEqual(len(raise_once()), 0 if level == "INFO" else 1, name + " repeat")
            clock["t"] += 10
            st.begin()
            st.finish()
            self.assertIn(c["key"], json.load(open(os.path.join(self.data, "alerts-state.json")))["active"], name + " held")
            clock["t"] += 301
            st.begin()
            st.finish()
            self.assertNotIn(c["key"], json.load(open(os.path.join(self.data, "alerts-state.json")))["active"], name)
            if level != "INFO":
                self.assertEqual(st.pushed[-1]["why"], "cleared", name)

    def test_band_ack_and_level_rise(self):
        clock = {"t": NOW}
        st = mmcore.AlertStore(S, clock=lambda: clock["t"])

        def disk(v):
            st.begin()
            c = mmalerts.evaluate({"disk_gb": v}, S, clock["t"], active={"DISK_LOW"})[0]
            st.raise_(c["key"], c["name"], c["level"], c["text"], value=c["value"], band=c["band"], worse=c["worse"])
            return st.pushed
        self.assertEqual(len(disk(38)), 1)
        clock["t"] += 60
        self.assertEqual(disk(30), [], "8 GB worse: inside the band")
        clock["t"] += 60
        self.assertEqual(disk(27)[0]["why"], "worse by a band")
        self.assertTrue(st.ack("DISK_LOW"))
        clock["t"] += 31 * 60
        self.assertEqual(disk(27), [], "acked: no repeat")
        clock["t"] += 60
        self.assertEqual(disk(16)[0]["why"], "worse by a band")
        st.begin()
        st.raise_("MEM", "MEM_AMBER", "ATTENTION", "amber")
        st.ack("MEM")
        clock["t"] += 60
        st.begin()
        st.raise_("MEM", "MEM_RED", "ACTION", "red")
        self.assertEqual(st.pushed[0]["why"], "level rose")
        self.assertFalse(st.ack("NOPE"))

    def test_disk_hysteresis_and_flap(self):
        self.assertFalse(mmalerts.evaluate({"disk_gb": 42.0}, S, NOW))
        self.assertTrue(mmalerts.evaluate({"disk_gb": 42.0}, S, NOW, active={"DISK_LOW"}))
        self.assertFalse(mmalerts.evaluate({"disk_gb": 46.0}, S, NOW, active={"DISK_LOW"}))
        clock = {"t": NOW}
        st = mmcore.AlertStore(S, clock=lambda: clock["t"])
        seq = []
        for state in ["RED", "AMBER", "RED", "AMBER", "RED"]:
            st.begin()
            for c in mmalerts.evaluate({"state": (state, ["x"])}, S, clock["t"]):
                st.raise_(c["key"], c["name"], c["level"], c["text"])
            st.finish()
            seq += [(r["name"], r["why"]) for r in st.pushed]
            clock["t"] += 60
        self.assertEqual(seq, [("MEM_RED", "new")])

    def test_watchdog_keys_survive_the_supervisor(self):
        st = mmcore.AlertStore(S, clock=lambda: NOW)
        st.begin()
        st.raise_("SELF_STALE", "SELF_STALE", "ACTION", "x")
        st.begin()
        st.finish()
        self.assertIn("SELF_STALE", json.load(open(os.path.join(self.data, "alerts-state.json")))["active"])

    def test_names_in_texts_come_from_the_profile(self):
        c = mmalerts.evaluate({"usage": {"codex_week": 98}}, S, NOW, names={"owner": "Ada"})[0]
        self.assertIn("tell Ada", c["text"])
        c = mmalerts.evaluate({"cache_gb": 50.0, "disk_gb": 100.0}, S, NOW, names={"trim_command": "trim-now"})[0]
        self.assertEqual(c["command"], "trim-now")


class T7Controller(unittest.TestCase):
    def ctl(self):
        return mmcore.SlotController(S, {})

    def test_raise_needs_15_min_green_demand_and_one_step(self):
        c = self.ctl()
        self.assertEqual(c.decide(T0, G, [], 5, 5, 3, False), (None, None))
        self.assertIsNone(c.decide(T0 + 14 * 60, G, [], 5, 5, 3, False)[0])
        self.assertEqual(c.decide(T0 + 15 * 60, G, [], 5, 5, 3, False)[0], 6)
        self.assertIsNone(c.decide(T0 + 16 * 60, G, [], 6, 6, 3, False)[0])
        self.assertEqual(c.decide(T0 + 30 * 60, G, [], 6, 6, 3, False)[0], 7)

    def test_down_at_once_floor_ceiling_events_holds_pin(self):
        c = self.ctl()
        self.assertEqual(c.decide(T0, "RED", ["x"], 8, 8, 0, False)[0], 3)
        self.assertIsNone(c.decide(T0 + 10, "RED", ["x"], 3, 3, 0, False)[0])
        c = self.ctl()
        self.assertEqual(c.decide(T0, "AMBER", ["x"], 6, 6, 0, False)[0], 5)
        self.assertIsNone(c.decide(T0 + 60, "AMBER", ["x"], 5, 5, 0, False)[0])
        self.assertEqual(c.decide(T0 + 121, "AMBER", ["x"], 5, 5, 0, False)[0], 4)
        for ev in ("timing-failure", "guard-kill"):
            self.assertEqual(self.ctl().decide(T0, G, [], 6, 6, 0, False, events=(ev,))[0], 5)
        c = self.ctl()
        c.decide(T0, G, [], 10, 10, 5, False)
        self.assertIsNone(c.decide(T0 + 3600, G, [], 10, 10, 5, False)[0])
        c = self.ctl()
        c.decide(T0, "RED", ["x"], 3, 3, 5, False)
        c.decide(T0 + 60, G, [], 3, 3, 5, False)
        self.assertIsNone(c.decide(T0 + 25 * 60, G, [], 3, 3, 5, False)[0])
        self.assertEqual(c.decide(T0 + 31 * 60, G, [], 3, 3, 5, False)[0], 4)
        pin = {"slots": 7, "until": T0 + 3600, "reason": "test"}
        c = self.ctl()
        self.assertEqual(c.decide(T0, G, [], 5, 5, 0, False, override=pin)[0], 7)
        self.assertEqual(c.decide(T0 + 120, "RED", ["x"], 7, 7, 0, False, override=pin)[0], 3)

    def test_write_slots_atomic(self):
        import tempfile
        p = os.path.join(tempfile.mkdtemp(prefix="mm-slots-"), "slots")
        mmcore.write_slots(p, 4)
        self.assertEqual(open(p).read(), "4\n")
        self.assertFalse(os.path.exists(p + ".new"))


class T12Settings(TempData):
    def file(self):
        return os.path.join(self.data, "settings.toml")

    def bump(self):
        st = os.stat(self.file())
        os.utime(self.file(), (st.st_atime, st.st_mtime + 5))

    def test_validate_catches_each_kind(self):
        good = base_settings()
        self.assertEqual(mmcore.validate(good), [])
        for k, v in {"slots.floor": 0, "slots.ceiling": "8", "launch_gate.enabled": "false", "mode.slot_writes": "on",
                     "slots.sustain_samples": 2.5, "disk.low_gb": True}.items():
            self.assertTrue(any(p.startswith(k) for p in mmcore.validate(dict(good, **{k: v}))), k)
        missing = dict(good)
        del missing["repeat.action_minutes"]
        self.assertIn("repeat.action_minutes: missing", mmcore.validate(missing))
        self.assertIn("slots.floor > slots.ceiling", mmcore.validate(dict(good, **{"slots.floor": 9, "slots.ceiling": 8})))
        self.assertIn("disk.low_gb >= disk.recover_gb", mmcore.validate(dict(good, **{"disk.low_gb": 50})))
        self.assertEqual(mmcore.validate(dict(good, **{"mode.slot_writes": "test", "mode.slots_file": "/q/slots"}), "/q/slots"),
                         ["mode.slot_writes test must not name the real gates/slots"])

    def test_defaults_are_safe(self):
        d = mmcore.defaults()
        self.assertEqual((d["mode.observe"], d["mode.slot_writes"], d["deletes.enabled"], d["launch_gate.enabled"],
                          d["pause_newest_call.enabled"], d["banner.enabled"]), (True, "off", False, False, False, False))
        self.assertEqual(mmcore.validate(d), [])
        self.assertEqual(mmcore.resolve(d)["slots.cores"], os.cpu_count())

    def test_overrides_unknown_keys_bad_file_keep_last_good(self):
        st = mmcore.Settings()
        self.assertEqual(st.load()["slots.floor"], 3)
        self.assertIsNone(st.problem)
        for bad in ["[slots\nfloor = 3", "[slots]\nfloor = 0\n", "[slots]\nflor = 3\n"]:
            with open(self.file(), "w") as f:
                f.write(bad)
            self.bump()
            self.assertEqual(st.load()["slots.floor"], 3, "the last good value stays")
            self.assertTrue(st.problem, bad)
        self.assertIn("slots.flor: unknown setting", st.problem)
        st2 = mmcore.Settings()  # a restart with a bad file reads the saved last good values
        self.assertEqual(st2.load()["slots.floor"], 3)
        self.assertTrue(st2.problem)
        os.remove(self.file())
        st3 = mmcore.Settings()
        self.assertEqual(st3.load()["slots.floor"], 2, "no settings.toml: the defaults")


class Logs(TempData):
    def test_own_logs_rotate_to_one_old_copy(self):
        f = os.path.join(self.data, "x.log")
        for i in range(50):
            mmcore.append_line(f, "line %03d " % i + "x" * 100, max_bytes=1000)
        self.assertLessEqual(os.path.getsize(f), 1000 + 120)
        self.assertTrue(os.path.exists(f + ".1"))
        self.assertFalse(os.path.exists(f + ".2"))
        self.assertTrue(open(f).read().splitlines()[-1].startswith("line 049"))


class B1Masking(unittest.TestCase):
    SECRETS = ["GH_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE1234", "AWS_SECRET_ACCESS_KEY=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg",
               "--password hunter2-planted", "Authorization: Bearer planted.token.value.123456",
               "https://bob:planted-pass@example.com/x", "sk-plantedplantedplanted12345",
               "MY_API_KEY='planted value'", "x7Kq9Lm2Np4Rs6Tv8Wx0Yz1Ab3Cd5Ef7Gh9"]
    PLANTED = ["ghp_FAKEFAKE", "Zm9vYmFy", "hunter2", "planted.token", "planted-pass", "sk-planted", "planted value",
               "x7Kq9Lm2Np4Rs6Tv8Wx0"]

    def test_each_planted_secret_is_masked(self):
        for text, part in zip(self.SECRETS, self.PLANTED):
            out = mmcore.mask("cmd " + text + " tail")
            self.assertNotIn(part, out, out)
            self.assertIn("tail", out)

    def test_ordinary_text_stays(self):
        for t in ["/Users/a/Projects/x/go-build123/b001/exe/main", "go test -p 3 ./...", "free 30% < 35%",
                  "commit 4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e", "session 4f1c2d3e-4f1c-2d3e-4f1c-2d3e4f1c2d3e",
                  "KEY=DISK_LOW level=ACTION"]:
            self.assertEqual(mmcore.mask(t), t)

    def test_mask_obj_walks_structures(self):
        o = mmcore.mask_obj({"a": ["TOKEN=abcdefgh123"], "b": ("--token x1y2z3w4",), "c": 5})
        self.assertEqual(o, {"a": ["TOKEN=***"], "b": ("--token ***",), "c": 5})


if __name__ == "__main__":
    unittest.main()
