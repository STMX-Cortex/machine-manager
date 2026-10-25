# SPDX-License-Identifier: Apache-2.0
"""Parts that must agree with each other: the queue's slot count file (read = write path), the pool record's alerts
(only the pool adapter's own), the status.json age limits (other.heartbeat_max_age_s, other.status_fresh_s), and
`mm run`'s arguments (every list mm install writes into a plist parses; a bad tick or an unknown word is refused)."""
import importlib.machinery
import importlib.util
import json
import os
import plistlib
import time

import mmtest
from mmtest import TempData, mmcore
from test_install import SetupBase
import ad_ci_github
import ad_deliver_claude
import mmplace
import mmsuper


def load_cli():
    """bin/mm as a module (its main does not run on import)."""
    loader = importlib.machinery.SourceFileLoader("mm_cli", os.path.join(mmtest.BIN, "mm"))
    spec = importlib.util.spec_from_loader("mm_cli", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class QueueSlotsFile(TempData):
    def test_read_uses_the_profile_slots_file(self):
        q = self.queue_dir(slots=2)  # `slots` holds 2: the reader must not take it
        with open(os.path.join(q, "count"), "w") as f:
            f.write("5\n")
        queue = mmtest.ad_queue_fifo.Queue({"dir": q, "slots_file": "count"})
        self.assertEqual(queue.slots_path(), os.path.join(q, "count"))
        self.assertEqual(queue.read()["slots"], 5)

    def test_default_name_is_slots(self):
        q = self.queue_dir(slots=4)
        queue = mmtest.ad_queue_fifo.Queue({"dir": q})
        self.assertEqual(queue.slots_path(), os.path.join(q, "slots"))
        self.assertEqual(queue.read()["slots"], 4)


class PoolAlerts(TempData):
    OWN = ["SOURCE_STALE:gh", "SOURCE_STALE:gh-billing", "SOURCE_STALE:gh-runs", "GH_FAIL:123", "GH_STUCK", "GUARD",
           "GH_PACE", "GH_DONE:456"]
    OTHER = ["SOURCE_STALE:memory-guard", "WD:memory-guard", "KILL:0123456789ab", "SOURCE_STALE:ps",
             "SOURCE_STALE:usage", "SOURCE_STALE:queue-sampler", "MEM", "SOURCE_STALE:ghost"]

    def test_every_key_conditions_raises_is_owned(self):
        now = 1_800_000_000.0
        s = mmtest.base_settings(**{"github.stop_minutes": 10, "github.pace_minutes": 10})
        gh = {"time": now - 3 * 3600, "errors": {"runs": "boom", "billing": "boom"},
              "runs": {"failed_1h": [{"id": 1, "workflow": "w", "branch": "b", "title": "t", "url": "u"}],
                       "oldest_queued_min": 10 ** 4},
              "billing": {"minutes": 1000, "gross": 0.0},
              "watched": {"7": {"done_at": now - 60, "conclusion": "success"}}}
        conds = ad_ci_github.conditions(gh, s, now, mmsuper.mmalerts._c)
        names = {c["name"] for c in conds}
        self.assertEqual(names, {"SOURCE_STALE", "GH_FAIL", "GH_STUCK", "GUARD_STOP", "GH_PACE", "GH_DONE"})
        pool = ad_ci_github.Pool(self.profile()["ci"])
        self.assertEqual([c["key"] for c in conds if not pool.owns(c["key"])], [])
        near = ad_ci_github.conditions(dict(gh, billing={"minutes": 1000, "gross": 0.0}), dict(
            s, **{"github.stop_minutes": 10 ** 6, "github.near_minutes": 10}), now, mmsuper.mmalerts._c)
        self.assertIn("GUARD_NEAR", {c["name"] for c in near})
        self.assertTrue(all(pool.owns(c["key"]) for c in near))

    def test_pool_record_keeps_only_the_pool_alerts(self):
        names = {"SOURCE_STALE:memory-guard": "GUARD_DOWN", "WD:memory-guard": "GUARD_DOWN",
                 "KILL:0123456789ab": "GUARD_KILL", "GUARD": "GUARD_NEAR"}
        active = {k: {"key": k, "name": names.get(k, k.split(":")[0]), "level": "ATTENTION"} for k in self.OWN + self.OTHER}

        class Fake:
            pool = ad_ci_github.Pool(self.profile()["ci"])
        mmsuper.Supervisor._pool_status(Fake(), time.time(), self.s(), None, active)
        f = os.path.join(self.data, "pools", "ci_example_project.json")
        rec = json.load(open(f))
        self.assertEqual(sorted(rec["alerts"]), sorted(self.OWN))
        self.assertNotIn("SOURCE_STALE:memory-guard", rec["alerts"])  # GUARD_DOWN
        self.assertNotIn("KILL:0123456789ab", rec["alerts"])  # GUARD_KILL


class StatusAge(TempData):
    def status(self, age, state="GREEN", red_for=0):
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps(
            {"time": now - age, "state": state, "reasons": ["x"], "red_since": now - red_for if red_for else None,
             "readings": {"free_pct": 70}}))
        return now

    def test_mm_status_follows_heartbeat_max_age(self):
        self.status(120)
        r = self.mm("status")
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertIn("E_STALE", r.stdout)
        self.write_settings(**{"other.heartbeat_max_age_s": 300})
        r = self.mm("status")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("E_STALE", r.stdout)
        self.assertTrue(r.stdout.startswith("state=GREEN"), r.stdout)

    def test_mm_status_writes_no_settings_file_and_bad_settings_fall_back_to_90(self):
        lastgood = os.path.join(self.data, "state", "settings.lastgood.json")
        self.write_settings(**{"other.heartbeat_max_age_s": 300})
        self.status(60)
        r = self.mm("status")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertFalse(os.path.exists(lastgood), "mm status writes no file")
        with open(os.path.join(self.data, "settings.toml"), "w") as f:
            f.write("[other\nbroken")
        self.status(80)
        r = self.mm("status")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.status(100)
        r = self.mm("status")
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertEqual([x for x in r.stdout.splitlines() if x.startswith("E_")],
                         ["E_STALE status.json 100 s old; fix: mm start; launch gate open"])
        self.assertFalse(os.path.exists(lastgood))

    def test_place_uses_status_fresh_s(self):
        prof = self.profile()
        now = self.status(40, state="AMBER")
        self.assertEqual(mmplace.machine_view(now, self.s(), None, prof)["source"], "supervisor")
        s = dict(self.s(), **{"other.status_fresh_s": 30})
        self.assertNotEqual(mmplace.machine_view(now, s, None, prof)["source"], "supervisor")

    def test_launch_gate_uses_status_fresh_s(self):
        cfg = self.profile()["delivery"]
        now = self.status(90, state="RED", red_for=120)
        s = dict(self.s(), **{"launch_gate.enabled": True})
        self.assertIsNone(ad_deliver_claude.gate_decision({"tool_name": "Agent"}, s, now, cfg), "60 s by default")
        s["other.status_fresh_s"] = 120
        self.assertTrue(ad_deliver_claude.gate_decision({"tool_name": "Agent"}, s, now, cfg).startswith("E_GATE_RED"))

    def test_status_fresh_s_range(self):
        self.write_settings(**{"other.status_fresh_s": 5})
        st = mmcore.Settings()
        st.load()
        self.assertIn("other.status_fresh_s", st.problem or "")
        self.assertEqual(mmcore.defaults()["other.status_fresh_s"], 60)


class RunArgs(SetupBase):
    @mmtest.darwin_only
    def test_installed_argument_lists_parse(self):
        rc, out, err = self.run_mm("install")
        self.assertEqual(rc, 0, out + [err])
        cli = load_cli()
        lists = []
        for name in sorted(os.listdir(self.agents)):
            if name.endswith(".plist"):
                argv = plistlib.load(open(os.path.join(self.agents, name), "rb"))["ProgramArguments"]
                self.assertEqual(argv[2], os.path.join(mmtest.BIN, "mm"))
                lists.append(argv[3:])
        self.assertIn(["run", "--allow-live-slots"], lists)
        for args in lists:
            if args[0] == "run":
                got = cli.run_options(mmcore.take_data_arg(args[1:]))
                self.assertIsNone(got["tick_seconds"], "the installed supervisor follows schedule.tick_s")
                self.assertTrue(got["allow_live_slots"])
                self.assertFalse(got["dry_run"])

    def test_test_forms_parse(self):
        cli = load_cli()
        got = cli.run_options(["--dry-run", "--ticks", "2", "--tick-seconds", "0.2", "--no-kernel-stream",
                               "--duration", "5"])
        self.assertEqual(got, {"dry_run": True, "ticks": 2, "duration": 5.0, "tick_seconds": 0.2, "kernel": False,
                               "allow_live_slots": False})
        got = cli.run_options([])  # no --tick-seconds: the loop waits schedule.tick_s (the installed form's case)
        self.assertEqual(got, {"dry_run": False, "ticks": 0, "duration": 0, "tick_seconds": None, "kernel": True,
                               "allow_live_slots": False})
        self.assertIsNone(cli.run_options(["--allow-live-slots"])["tick_seconds"])

    def test_bad_ticks_and_unknown_words_are_refused(self):
        for bad in ("0", "-1", "nan", "inf", "-inf"):
            r = self.mm("run", "--ticks", "1", "--no-kernel-stream", "--tick-seconds", bad, timeout=30)
            self.assertEqual(r.returncode, 2, (bad, r.stdout, r.stderr))
            lines = r.stdout.strip().splitlines()
            self.assertEqual(len(lines), 1, lines)
            self.assertTrue(lines[0].startswith("E_RANGE --tick-seconds "), lines)
        r = self.mm("run", "--tick-seconds", "abc", timeout=30)
        self.assertEqual((r.returncode, r.stdout.split(" ")[0]), (2, "E_USAGE"))
        for extra in (["--allow-live-slot"], ["--ticks", "1", "extra"], ["--dryrun"]):
            r = self.mm("run", "--no-kernel-stream", *extra, timeout=30)
            self.assertEqual(r.returncode, 2, (extra, r.stdout))
            lines = r.stdout.strip().splitlines()
            self.assertEqual(len(lines), 1, lines)
            self.assertTrue(lines[0].startswith("E_USAGE mm run does not take "), lines)
        self.assertFalse(os.path.exists(os.path.join(self.data, "status.json")), "a refused run never started")


if __name__ == "__main__":
    import unittest
    unittest.main()
