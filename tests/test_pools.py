# SPDX-License-Identifier: Apache-2.0
"""Multiple pools: isolated snapshots, budgets, alerts, watches, workers and placement; legacy [ci] is unchanged."""
import copy
import json
import os
from pathlib import Path
import time
import unittest
from unittest import mock

from mmtest import TempData, mmcore, mmread
import ad_ci_github
import mmadapters
import mmalerts
import mmdecide
import mmplace
import mmschema
import mmsuper
from test_resources import calm


def reading(now, used=100, gross=0):
    return {"time": now, "errors": {}, "billing": {"minutes": used, "gross": gross},
            "runs": {"in_progress": 1, "queued": 2}, "watched": {}}


class Pools(TempData):
    def setUp(self):
        super().setUp()
        self.queue_dir(slots=3)
        self.now = time.time()

    def config(self, ident, **over):
        cfg = copy.deepcopy(self.profile()["ci"])
        cfg.pop("pool_id")
        return dict(cfg, id=ident, **over)

    def profile_pools(self, *configs):
        p = self.profile()
        p["ci"] = {}
        p["pools"] = list(configs or [self.config("one"), self.config("two")])
        return p

    def adapters(self, *configs):
        return mmadapters.pools(self.profile_pools(*configs))

    def write_read(self, pool, used=100, gross=0):
        data = reading(self.now, used, gross)
        mmcore.write_atomic(pool.cache_file(), json.dumps(data))
        return data

    def status(self, state="RED"):
        mmcore.write_atomic(mmcore.path("status.json"), json.dumps(
            {"time": self.now, "state": state, "reasons": ["busy"], "readings": {"free_pct": 30}}))

    def test_config_normalization_and_schema(self):
        p = self.profile_pools(self.config("build-a", reserve_minutes=42, included_minutes=500))
        raw = {k: v for k, v in p.items() if not k.startswith("_") and k != "ci"}
        self.assertEqual(mmschema.validate(raw, mmschema.load("profile")), [])
        pools = mmadapters.pools(p)
        self.assertEqual([x.id for x in pools], ["build-a"])
        self.assertEqual(pools[0].settings(self.s())["github.reserve_minutes"], 42)
        self.assertEqual(pools[0].settings(self.s())["github.included_minutes"], 500)
        self.assertEqual(mmadapters.pool(p).id, "build-a")

    def test_invalid_or_ambiguous_config_refuses_before_workers(self):
        for configs in ([self.config("same"), self.config("same")], [self.config("Build"), self.config("build")],
                        [self.config("../outside")], [self.config("nan", reserve_minutes=float("nan"))],
                        [self.config("inf", included_minutes=float("inf"))],
                        [self.config("has:colon")], [self.config("bad", reserve_minutes=-1)],
                        [dict(id="missing", adapter="github-gh")], {"id": "not-a-list"}):
            p = self.profile_pools()
            p["pools"] = configs
            with self.subTest(configs=configs), self.assertRaises(mmcore.MMError):
                mmadapters.pools(p)
        p = self.profile_pools()
        p["ci"] = self.profile()["ci"]
        with self.assertRaises(mmcore.MMError):
            mmadapters.pools(p)

    def test_legacy_paths_and_keys_stay_unchanged(self):
        pool = mmadapters.pool(self.profile())
        self.assertFalse(pool.scoped)
        self.assertEqual(pool.cache_file(), mmcore.path("state", "github.json"))
        self.assertEqual(pool.watch_file(), ad_ci_github.watch_file())
        self.assertEqual(pool.good_keys(reading(self.now)), ["SOURCE_STALE:gh", "SOURCE_STALE:gh-runs",
                                                             "SOURCE_STALE:gh-billing"])
        self.assertTrue(pool.owns("GUARD"))

    def test_pool_budgets_snapshots_alert_keys_and_resources_are_isolated(self):
        first, second = self.adapters(self.config("one", included_minutes=500, reserve_minutes=40),
                                      self.config("two", included_minutes=900, reserve_minutes=80))
        a, b = self.write_read(first, 100, gross=1), self.write_read(second, 200)
        self.assertEqual(first.minutes_left(self.s(), self.now)[0], 400)
        self.assertEqual(second.minutes_left(self.s(), self.now)[0], 700)
        cond = first.conditions(a, self.s(), self.now, mmalerts._c, "owner")
        self.assertIn("POOL:one:GUARD", [x["key"] for x in cond])
        self.assertTrue(all(first.owns(x["key"]) and not second.owns(x["key"]) for x in cond))
        self.assertFalse(first.owns("GUARD_KILL"))
        self.assertEqual(first.good_keys(a)[0], "POOL:one:SOURCE_STALE:gh")
        rows = first.resources(a, self.s(), self.now) + second.resources(b, self.s(), self.now)
        self.assertEqual([(x["id"], x["capacity"]["reserve"]) for x in rows], [("one", 40), ("two", 80)])

    def test_worker_job_reads_and_watches_do_not_cross_pools(self):
        first, second = self.adapters()
        ad_ci_github.watch_add(123, "first", self.now, first.id)
        ad_ci_github.watch_add(123, "second", self.now, second.id)
        seen = []

        def read(cfg, s, now, watch):
            seen.append((cfg["pool_id"], watch["123"]["note"]))
            return dict(reading(now), watched=watch)

        with mock.patch.object(ad_ci_github, "read_all", read):
            first.job(self.s(), self.now)
            second.job(self.s(), self.now)
        self.assertEqual(seen, [("one", "first"), ("two", "second")])
        self.assertNotEqual(first.cache_file(), second.cache_file())
        self.assertFalse(os.path.exists(ad_ci_github.watch_file()))
        self.assertEqual(mmcore.read_json(first.watch_file())["123"]["note"], "first")

    def test_malformed_watch_state_cannot_break_other_pool_or_supervisor(self):
        first, second = self.adapters()
        mmcore.write_atomic(first.watch_file(), json.dumps({"123": "broken", "456": {"done_at": "broken"}}))
        ad_ci_github.watch_add(789, "second", self.now, second.id)
        with mock.patch.object(mmread, "disk_free_gb", return_value=500):
            sup = mmsuper.Supervisor(self.profile_pools(), kernel=False, sizes=False, slow_jobs=False,
                                     clock=lambda: self.now, sampler=calm, check_readings=False)
            self.assertTrue(sup._watch_pending(self.now, self.s(), first), "invalid completion time is retried")
            self.assertTrue(sup._watch_pending(self.now, self.s(), second))
            sup.tick()

        def read(cfg, s, now, watch):
            self.assertEqual(watch, {"456": {"done_at": None}})
            return dict(reading(now), watched=watch)

        with mock.patch.object(ad_ci_github, "read_all", read):
            result = first.job(self.s(), self.now)
        self.assertIn("watched", result["errors"])
        self.assertEqual(mmcore.read_json(first.watch_file()), {"456": {"done_at": None}})
        self.assertEqual(mmcore.read_json(second.watch_file())["789"]["note"], "second")

    def test_watch_metadata_added_during_read_survives_status_update(self):
        pool = self.adapters()[0]
        ad_ci_github.watch_add(123, "old note", self.now, pool.id)

        def read(cfg, s, now, watch):
            ad_ci_github.watch_add(123, "new note", now + 1, pool.id)
            ad_ci_github.watch_add(456, "new run", now + 1, pool.id)
            watch["123"].update(status="completed", conclusion="success", done_at=now)
            return dict(reading(now), watched=watch)

        with mock.patch.object(ad_ci_github, "read_all", read):
            pool.job(self.s(), self.now)
        watch = mmcore.read_json(pool.watch_file())
        self.assertEqual((watch["123"]["note"], watch["123"]["added"]), ("new note", self.now + 1))
        self.assertEqual(watch["123"]["status"], "completed")
        self.assertEqual(watch["456"]["note"], "new run")

    def test_placement_tries_next_guard_and_prints_only_selected_pool_commands(self):
        pools = self.adapters()
        for p in pools:
            self.write_read(p)
        self.status()
        p = self.profile_pools()
        req = {"kind": "go-test", "shards": 1, "sha": "abcd"}
        calls = []

        def guard(pool, args):
            calls.append(pool.id)
            return (1, "refused") if pool.id == "one" else (0, "fits")

        with mock.patch.object(ad_ci_github.Pool, "guard", guard):
            rec = mmplace.place(req, self.s(), p, pool=pools, now=self.now)
        self.assertEqual(calls, ["one", "two"])
        self.assertEqual((rec["place"], rec["candidate"]), ("POOL", "two"))
        self.assertTrue(rec["commands"][-1].endswith("--pool two"))

    def test_pool_reserve_and_active_stop_do_not_block_the_other_pool(self):
        pools = self.adapters(self.config("one", reserve_minutes=2900), self.config("two", reserve_minutes=5))
        for p in pools:
            self.write_read(p)
        self.status()
        with mock.patch.object(ad_ci_github.Pool, "guard", return_value=(0, "fits")):
            rec = mmplace.place({"kind": "go-test", "shards": 1}, self.s(), self.profile_pools(), pool=pools, now=self.now)
        self.assertEqual(rec["candidate"], "two")
        mmcore.write_atomic(mmcore.path("alerts-state.json"), json.dumps({"active": {
            "POOL:one:GUARD": {"name": "GUARD_STOP"}}}))
        pools = self.adapters()
        with mock.patch.object(ad_ci_github.Pool, "guard", return_value=(0, "fits")):
            rec = mmplace.place({"kind": "go-test"}, self.s(), self.profile_pools(), pool=pools, now=self.now)
        self.assertEqual(rec["candidate"], "two")

    def test_supervisor_writes_each_status_and_keeps_alerts_separate(self):
        profile = self.profile_pools()
        for p in mmadapters.pools(profile):
            self.write_read(p, gross=1 if p.id == "one" else 0)
        with mock.patch.object(mmread, "disk_free_gb", return_value=500):
            sup = mmsuper.Supervisor(profile, kernel=False, sizes=False, slow_jobs=False, clock=lambda: self.now,
                                     sampler=calm, check_readings=False)
            sup.tick()
        first = mmcore.read_json(mmcore.path("pools", "one.json"))
        second = mmcore.read_json(mmcore.path("pools", "two.json"))
        self.assertEqual(mmschema.validate(first, mmschema.load("status")), [])
        self.assertEqual(first["state"], "RED")
        self.assertEqual(second["state"], "GREEN")
        self.assertIn("POOL:one:GUARD", first["alerts"])
        self.assertFalse(second["alerts"])
        rows = mmcore.read_json(mmcore.path("resources.json"))["resources"]
        self.assertEqual([r["id"] for r in rows if r["resource"] == "pool"], ["one", "two"])
        self.assertNotEqual(sup.pool_workers["one"], sup.pool_workers["two"])

    def test_missing_one_pool_does_not_stale_the_other(self):
        profile = self.profile_pools()
        pools = mmadapters.pools(profile)
        self.write_read(pools[1])
        with mock.patch.object(mmread, "disk_free_gb", return_value=500):
            sup = mmsuper.Supervisor(profile, kernel=False, sizes=False, slow_jobs=False, clock=lambda: self.now,
                                     sampler=calm, check_readings=False)
            sup.started -= 7200
            sup.tick()
        active = mmcore.read_json(mmcore.path("alerts-state.json"))["active"]
        self.assertIn("POOL:one:SOURCE_STALE:gh", active)
        self.assertNotIn("POOL:two:SOURCE_STALE:gh", active)
        self.assertEqual(mmcore.read_json(mmcore.path("pools", "two.json"))["state"], "GREEN")

    def test_malformed_snapshot_does_not_stop_healthy_pool_or_machine_status(self):
        profile = self.profile_pools()
        first, second = self.adapters()
        invalid = [dict(reading(self.now), time="broken"), dict(reading(self.now), time=float("inf")),
                   dict(reading(self.now), time=10**400), dict(reading(self.now), time=True),
                   dict(reading(self.now), billing={"minutes": "broken", "gross": 0}),
                   dict(reading(self.now), runs={"failed_1h": ["broken"]}),
                   dict(reading(self.now), errors={"billing": {"unexpected": "object"}}),
                   dict(reading(self.now), watched={"123": {"done_at": "broken"}})]
        for data in invalid:
            with self.subTest(data=data), mock.patch.object(mmread, "disk_free_gb", return_value=500):
                mmcore.write_atomic(first.cache_file(), json.dumps(data))
                self.write_read(second)
                sup = mmsuper.Supervisor(profile, kernel=False, sizes=False, slow_jobs=False, clock=lambda: self.now,
                                         sampler=calm, check_readings=False)
                sup.started -= 7200
                sup.tick()
                self.assertEqual(mmcore.read_json(mmcore.path("pools", "one.json"))["state"], "UNKNOWN")
                self.assertEqual(mmcore.read_json(mmcore.path("pools", "two.json"))["state"], "GREEN")
                self.assertEqual(mmcore.read_json(mmcore.path("status.json"))["heartbeat"]["tick"], 1)
                active = mmcore.read_json(mmcore.path("alerts-state.json"))["active"]
                self.assertIn("POOL:one:SOURCE_STALE:gh", active)
                self.assertNotIn("POOL:two:SOURCE_STALE:gh", active)

    def test_malformed_billing_cache_does_not_block_placement_on_other_pool(self):
        pools = self.adapters()
        self.write_read(pools[1])
        mmcore.write_atomic(pools[0].cache_file(), json.dumps(dict(reading(self.now), time="broken")))
        self.status()
        with mock.patch.object(ad_ci_github, "gh_run", return_value=(1, "unavailable")), \
                mock.patch.object(ad_ci_github.Pool, "guard", return_value=(0, "fits")):
            rec = mmplace.place({"kind": "go-test", "shards": 1}, self.s(), self.profile_pools(), pool=pools, now=self.now)
        self.assertEqual((rec["place"], rec["candidate"]), ("POOL", "two"))

    def test_deep_or_oversized_pool_cache_is_unavailable_without_blocking_other_placement(self):
        pools = self.adapters()
        self.write_read(pools[1])
        self.status()
        invalid = [b'{"nested":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}",
                   b" " * (ad_ci_github.CACHE_BYTES + 1),
                   b'{"time":1,"time":2}', b'{"time":NaN}', b"\xff"]
        for raw in invalid:
            with self.subTest(prefix=raw[:40]):
                Path(pools[0].cache_file()).parent.mkdir(parents=True, exist_ok=True)
                Path(pools[0].cache_file()).write_bytes(raw)
                self.assertIsNone(pools[0].load_cache())
                self.assertEqual(pools[0].status(pools[0].load_cache(), self.s(), self.now)["state"], "UNKNOWN")
                with mock.patch.object(ad_ci_github, "gh_run", return_value=(1, "unavailable")), \
                        mock.patch.object(ad_ci_github.Pool, "guard", return_value=(0, "fits")):
                    rec = mmplace.place({"kind": "go-test", "shards": 1}, self.s(), self.profile_pools(), pool=pools, now=self.now)
                self.assertEqual((rec["place"], rec["candidate"]), ("POOL", "two"))

    def test_deep_watch_cache_recovers_without_breaking_the_pool_read(self):
        pool = self.adapters()[0]
        path = Path(pool.watch_file())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'{"nested":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}")
        self.assertEqual(pool.load_watch(), {})
        with mock.patch.object(ad_ci_github, "read_all", return_value=reading(self.now)):
            result = pool.job(self.s(), self.now)
        self.assertIn("watched", result["errors"])
        self.assertEqual(pool.load_watch(), {})
        self.assertEqual(pool.status(result, self.s(), self.now)["state"], "AMBER")

    def test_deep_or_oversized_cache_does_not_break_initialization_or_healthy_pool(self):
        profile = self.profile_pools()
        first, second = self.adapters()
        invalid = [b'{"nested":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}",
                   b" " * (ad_ci_github.CACHE_BYTES + 1)]
        for raw in invalid:
            with self.subTest(prefix=raw[:40]), mock.patch.object(mmread, "disk_free_gb", return_value=500):
                Path(first.cache_file()).parent.mkdir(parents=True, exist_ok=True)
                Path(first.cache_file()).write_bytes(raw)
                self.write_read(second)
                # A legacy cache left behind after a switch to [[pools]] is unused and must not be parsed.
                Path(mmcore.path("state", "github.json")).write_bytes(raw)
                sup = mmsuper.Supervisor(profile, kernel=False, sizes=False, slow_jobs=False, clock=lambda: self.now,
                                         sampler=calm, check_readings=False)
                sup.started -= 7200
                sup.tick()
                self.assertIsNone(sup.pool_reads["one"])
                self.assertEqual(sup.pool_reads["two"]["billing"]["minutes"], 100)
                self.assertEqual(mmcore.read_json(mmcore.path("pools", "one.json"))["state"], "UNKNOWN")
                self.assertEqual(mmcore.read_json(mmcore.path("pools", "two.json"))["state"], "GREEN")
                self.assertEqual(mmcore.read_json(mmcore.path("status.json"))["heartbeat"]["tick"], 1)

    def test_deep_legacy_cache_and_watch_file_do_not_break_supervisor(self):
        pool = mmadapters.pool(self.profile())
        raw = b'{"nested":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"
        Path(pool.cache_file()).write_bytes(raw)
        Path(pool.watch_file()).write_bytes(raw)
        with mock.patch.object(mmread, "disk_free_gb", return_value=500):
            sup = mmsuper.Supervisor(self.profile(), kernel=False, sizes=False, slow_jobs=False,
                                     clock=lambda: self.now, sampler=calm, check_readings=False)
            self.assertFalse(sup._watch_pending(self.now, self.s(), pool))
            sup.started -= 7200
            sup.tick()
        self.assertIsNone(sup.cache["github"])
        self.assertEqual(mmcore.read_json(mmcore.path("status.json"))["heartbeat"]["tick"], 1)
        active = mmcore.read_json(mmcore.path("alerts-state.json"))["active"]
        self.assertIn("SOURCE_STALE:gh", active)

    def test_failed_worker_does_not_discard_successful_other_pool_read(self):
        def job(pool, settings, now):
            if pool.id == "one":
                raise OSError("one pool is unavailable")
            return reading(now)

        with mock.patch.object(ad_ci_github.Pool, "job", job), \
                mock.patch.object(mmread, "disk_free_gb", return_value=500):
            sup = mmsuper.Supervisor(self.profile_pools(), kernel=False, sizes=False, slow_jobs=False,
                                     clock=lambda: self.now, sampler=calm, check_readings=False)
            sup.started -= 7200
            for worker in sup.pool_workers.values():
                worker.kick(self.s(), self.now)
                worker.thread.join(5)
            self.assertIn("unavailable", sup.pool_workers["one"].error)
            sup.slow_jobs = True
            with mock.patch.object(sup.deletes, "kick", return_value=False):
                sup.tick()
        self.assertIsNone(sup.pool_reads["one"])
        self.assertEqual(sup.pool_reads["two"]["billing"]["minutes"], 100)
        self.assertEqual(mmcore.read_json(mmcore.path("pools", "two.json"))["state"], "GREEN")

    def cli_profile(self):
        """The normal fixture profile, replacing its [ci] block with two pool entries."""
        text = Path(self.profile()["_file"]).read_text()
        begin = text.index("[ci]\n")
        end = text.index("\n[delivery]", begin)
        ci = text[begin:end]
        entries = []
        for ident in ("one", "two"):
            entry = ci.replace("[ci]\n", '[[pools]]\nid = "%s"\n' % ident)
            entry = "\n".join(line for line in entry.splitlines() if not line.startswith("pool_id ="))
            entries.append(entry)
        path = os.path.join(self.root, "multi.toml")
        Path(path).write_text(text[:begin] + "\n".join(entries) + text[end:])
        return path

    def test_watch_cli_requires_pool_and_saves_only_selected_watch(self):
        env = {"MM_PROFILE": self.cli_profile()}
        result = self.mm("watch", "123", env=env)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("needs --pool", result.stdout)
        result = self.mm("watch", "123", "--pool", "two", "--note", "chosen", env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(mmcore.read_json(ad_ci_github.watch_file("two"))["123"]["note"], "chosen")
        self.assertFalse(os.path.exists(ad_ci_github.watch_file("one")))
        result = self.mm("watch", "123", "--pool", "../bad", env=env)
        self.assertEqual(result.returncode, 2)

    def test_place_cli_uses_second_pool_when_first_is_over_reserve(self):
        path = self.cli_profile()
        p = mmcore.load_profile(path)
        pools = mmadapters.pools(p)
        self.write_read(pools[0], used=2999)
        self.write_read(pools[1], used=100)
        self.status()
        r = self.mm("place", "--kind", "go-test", "--json", env={"MM_PROFILE": path, "MM_GUARD": "/usr/bin/true"})
        self.assertEqual(r.returncode, 10, r.stdout + r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["candidate"], "two")
        self.assertIn("--pool two", doc["commands"][-1])


if __name__ == "__main__":
    unittest.main()
