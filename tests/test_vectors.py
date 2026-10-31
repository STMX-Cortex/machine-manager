# SPDX-License-Identifier: Apache-2.0
"""Every vector passes; the meaning of the important vectors is pinned by hand (T2-T4 replays, placement, deletes);
every schema is valid and the records the tool writes match their schemas."""
import json
import os
import unittest

import mmtest
from mmtest import mmcore
import run_vectors
import mmschema

VEC = os.path.join(mmtest.CODE, "vectors")


def vec(fn, case):
    return json.load(open(os.path.join(VEC, fn, case + ".json")))


class Vectors(unittest.TestCase):
    def test_every_vector_passes(self):
        self.assertEqual(run_vectors.main([]), 0)

    def test_counts(self):
        counts = {}
        for fn, case, v, s in run_vectors.load_all():
            counts[fn] = counts.get(fn, 0) + 1
            self.assertEqual(v["function"], fn)
        for fn in ("classify", "slot_decide", "alert_raise", "alert_absent", "conditions", "delete_guard", "place",
                   "drill_stop", "replay", "parse_billing", "mask", "sample_problems", "self_check", "crash_loop",
                   "resume_targets", "reboot_check", "resource_row", "machine_resource", "pool_resources",
                   "usage_resources", "cap_records", "timing_warnings"):
            self.assertGreaterEqual(counts.get(fn, 0), 3 if fn != "alert_absent" else 3, fn)
        mmtest.write_result("vector-counts.txt", ["%s=%d" % kv for kv in sorted(counts.items())])

    def rows(self, case):
        v = vec("replay", case)
        return [(v["input"]["labels"][r["i"]], r) for r in v["expected"]]

    def test_t2_replay_0913(self):
        rows = self.rows("incident-0913")
        red = [(t, r) for t, r in rows if r["state"] == "RED"]
        t, r = red[0]
        self.assertEqual(t, "09:11")
        self.assertTrue(any("compressor +" in x for x in r["reasons"]), r["reasons"])
        self.assertEqual(r["slots"], 3, "slots at the floor at 09:11")
        self.assertIn(["MEM_RED", "ACTION", "level rose"], r["pushed"])
        self.assertTrue(all(r["slots"] <= 6 for t, r in rows if t < "09:11"))
        steps = [b[1]["slots"] - a[1]["slots"] for a, b in zip(rows, rows[1:])]
        self.assertTrue(all(s <= 1 for s in steps), "raises are one step at a time")
        k = [t for t, r in rows if ["KERNEL_SUSPEND", "ACTION", "new"] in r["pushed"]]
        self.assertEqual(k[0], "09:14")
        self.assertTrue(all(r["slots"] == 3 for t, r in rows if "09:11" <= t <= "09:30"), "no raise within 30 min")
        mmtest.write_result("T2-replay-rows.txt", ["%s %-6s slots=%d %s | %s" % (t, r["state"], r["slots"], r["pushed"],
                                                                                 "; ".join(r["reasons"])[:150]) for t, r in rows])

    def test_t3_replay_1010(self):
        rows = self.rows("incident-1010")
        self.assertEqual([t for t, r in rows if r["state"] == "RED"][0], "20:11")
        self.assertEqual([t for t, r in rows if r["state"] == "AMBER"][0], "20:00")
        self.assertEqual([r for t, r in rows if t == "20:11"][0]["slots"], 3)
        mmtest.write_result("T3-replay-rows.txt", ["%s %-6s slots=%d %s" % (t, r["state"], r["slots"], r["pushed"]) for t, r in rows])

    def test_t4_replay_1013(self):
        rows = self.rows("incident-1013")
        t, r = [(t, r) for t, r in rows if r["state"] == "RED"][0]
        self.assertEqual(t, "19:12")
        self.assertTrue(any(x.startswith("load1 >") for x in r["reasons"]))
        self.assertEqual([t for t, r in rows if ["RESUMED", "INFO", "new"] in r["pushed"]][0], "20:06")
        mmtest.write_result("T4-replay-rows.txt", ["%s %-6s slots=%d %s" % (t, r["state"], r["slots"], r["pushed"]) for t, r in rows])

    def test_meaning_of_key_vectors(self):
        self.assertEqual(vec("place", "machine-only-never-pool")["expected"]["place"], "MACHINE")
        self.assertEqual(vec("place", "red-wait")["expected"]["place"], "WAIT")
        self.assertEqual(vec("place", "busy-needs-guard")["expected"]["need_guard"], "ci:example/project")
        self.assertEqual(vec("place", "busy-guard-ok-pool")["expected"]["place"], "POOL")
        self.assertEqual(vec("place", "busy-guard-refused")["expected"]["place"], "MACHINE")
        self.assertEqual(vec("place", "busy-reserve")["expected"]["place"], "MACHINE")
        self.assertEqual(vec("place", "busy-stop-active")["expected"]["place"], "MACHINE")
        self.assertEqual(vec("place", "wide-waits-free")["expected"]["place"], "WAIT")
        self.assertEqual(vec("delete_guard", "live-tool")["expected"]["verb"], "KEEP")
        self.assertEqual(vec("delete_guard", "pass-would")["expected"]["verb"], "WOULD-DELETE")
        self.assertEqual(vec("slot_decide", "red-to-floor")["expected"]["slots"], 3)
        self.assertEqual(vec("slot_decide", "green-raise-one-step")["expected"]["slots"], 6)
        self.assertIsNone(vec("drill_stop", "go-on")["expected"])
        self.assertEqual(vec("drill_stop", "floor-next-step")["expected"][:10], "floor next")
        self.assertIsNone(vec("drill_stop", "cap-not-reached")["expected"])
        self.assertEqual(vec("drill_stop", "cap-reached")["expected"][:4], "cap:")
        self.assertEqual(vec("drill_stop", "cap-unknown")["expected"][:11], "cap unknown")
        self.assertEqual(vec("drill_stop", "memory-not-used")["expected"][:15], "memory not used")
        self.assertIsNone(vec("drill_stop", "memory-used")["expected"])
        self.assertEqual(vec("drill_stop", "memory-compressed-partly")["expected"][:15], "memory not used")
        self.assertIsNone(vec("drill_stop", "two-steps-too-early-to-judge")["expected"])
        b = vec("parse_billing", "exponent-number")["expected"]
        self.assertEqual((b["minutes"], b["gross"]), ("1200", "4.800004987"))
        for c in ("env-token", "bearer", "flag", "url-password", "known-prefix", "random-word", "private-key"):
            self.assertIn("***", vec("mask", c)["expected"], c)
        for c in ("keeps-paths", "keeps-hex", "keeps-uuid"):
            self.assertNotIn("***", vec("mask", c)["expected"], c)
        for fn, case, v, s in run_vectors.load_all():
            if fn == "alert_line":
                self.assertLessEqual(len(v["expected"]), 200)

    def test_meaning_of_timing_vectors(self):
        """Pinned by hand: the defaults and the longest tick warn about nothing; every line is one W_SCHEDULE line with
        its fix; the status.json gap is max(tick_s, max_tick_s) + max_tick_s (60 at the defaults)."""
        self.assertEqual(vec("timing_warnings", "defaults")["expected"], [])
        self.assertEqual(vec("timing_warnings", "defaults")["settings_over"], {})
        self.assertEqual(vec("timing_warnings", "tick-30")["expected"], [])
        self.assertEqual(vec("timing_warnings", "heartbeat-60")["expected"], [])
        self.assertTrue(vec("timing_warnings", "heartbeat-59")["expected"][0].startswith(
            "W_SCHEDULE other.heartbeat_max_age_s 59 is under 60 s"))
        self.assertTrue(all("240 or more" in x for x in vec("timing_warnings", "max-tick-120")["expected"]))
        self.assertEqual(len(vec("timing_warnings", "max-tick-120")["expected"]), 2)
        for c in ("watchdog-no-service", "github-no-pool"):
            self.assertEqual(vec("timing_warnings", c)["expected"], [], c)
        self.assertEqual([x.split(" ")[1] for x in vec("timing_warnings", "every-check")["expected"]], [
            "other.heartbeat_max_age_s", "other.status_fresh_s", "self.resume_paused_after_s", "schedule.watchdog_s",
            "self.watchdog_stale_s", "github.stale_minutes", "schedule.ps_s", "schedule.metrics_s"], "checks 1 to 8")
        self.assertTrue(vec("timing_warnings", "github-read-86400")["expected"][0].endswith(
            "; fix: set github.read_interval_s to 1200 or less (github.stale_minutes is at most 1440)"))
        for fn, case, v, s in run_vectors.load_all():
            if fn == "timing_warnings":
                self.assertEqual(sorted(v["input"]), ["pool", "service"] if v["input"] else [], case)
                for line in v["expected"]:
                    self.assertRegex(line, r"^W_SCHEDULE \S+ .+; fix: .+$", case)
                    self.assertEqual(line.count("; fix: "), 1, case)


class Schemas(unittest.TestCase):
    def test_meaning_of_recovery_vectors(self):
        """Pinned by hand: which fault restarts, which gives safe mode, and that safe mode never exits."""
        def act(case):
            return vec("self_check", case)["expected"]["action"]
        self.assertEqual([act(c) for c in ("all-fine", "rss-over", "slow-2-of-3", "slow-3-restart", "tick-errors-6-restart")],
                         ["ok", "restart", "ok", "restart", "restart"])
        self.assertEqual([act(c) for c in ("bad-readings-5", "bad-readings-6-safe", "data-not-writable-safe",
                                           "data-disk-low-safe", "slot-changes-12-ok", "slot-changes-13-safe")],
                         ["ok", "safe", "safe", "safe", "ok", "safe"])
        self.assertEqual(act("safe-beats-restart"), "safe")
        self.assertEqual((act("in-safe-mode-only-alert"), act("in-safe-mode-fine")), ("alert", "ok"))
        self.assertEqual([vec("crash_loop", c)["expected"]["safe"] for c in ("two-in-window", "three-in-window",
                                                                               "old-dropped", "longer-window")],
                         [False, True, False, True])
        self.assertEqual(vec("resume_targets", "match")["expected"], [101, 102])
        self.assertEqual([vec("resume_targets", c)["expected"] for c in ("reused-pid", "gone", "unknown-start")], [[], [], []])
        self.assertIsNone(vec("reboot_check", "same-boot")["expected"])
        self.assertEqual(vec("reboot_check", "reboot-clean")["expected"]["level"], "ATTENTION")
        self.assertEqual(vec("reboot_check", "reboot-panic-and-jobs")["expected"]["level"], "ACTION")
        self.assertEqual(vec("sample_problems", "fine")["expected"], [])
        self.assertEqual(len(vec("sample_problems", "empty")["expected"]), 7)

    def test_schema_files_load_and_settings_schema_matches_code(self):
        names = sorted(f[:-12] for f in os.listdir(mmschema.SCHEMAS) if f.endswith(".schema.json"))
        self.assertEqual(names, ["alert", "delete-line", "off", "override", "placement", "placement-request", "pool-read", "profile",
                                 "reading", "resource", "settings", "status"])
        self.assertEqual(mmschema.load("settings"), mmcore.settings_json_schema(), "regenerate schemas/settings.schema.json")
        self.assertEqual(mmschema.validate(mmcore.defaults(), mmschema.load("settings")), [])
        self.assertTrue(mmschema.validate(dict(mmcore.defaults(), **{"slots.floor": 0}), mmschema.load("settings")))

    def test_vector_settings_match_code(self):
        """vectors/_settings/base.json is the settings table with the vectors' fixed machine values: a port reads every
        key there, and a pure function never needs a default of its own."""
        with open(os.path.join(run_vectors.VEC, "_settings", "base.json")) as f:
            base = json.load(f)
        self.assertEqual(base, mmtest.base_settings(), "run python3 -I tests/gen_vectors.py --settings")

    def test_profiles_validate(self):
        for f in (mmtest.PROFILE, os.path.join(mmtest.CODE, "profiles", "example.toml")):
            self.assertEqual(mmschema.validate(mmcore.load_toml(f), mmschema.load("profile")), [], f)
        self.assertTrue(mmschema.validate({"name": "x", "queue": {"adapter": "nope", "dir": "/q"}}, mmschema.load("profile")))
        self.assertTrue(mmschema.validate({"nam": "x"}, mmschema.load("profile")))

    def test_vector_inputs_match_record_schemas(self):
        for fn, case, v, s in run_vectors.load_all():
            if fn == "classify":
                for x in v["input"]["window"]:
                    self.assertEqual(mmschema.validate(x, mmschema.load("reading")), [], case)
            if fn == "place":
                self.assertEqual(mmschema.validate(v["input"]["req"], mmschema.load("placement-request")), [], case)


if __name__ == "__main__":
    unittest.main()
