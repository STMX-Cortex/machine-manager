# SPDX-License-Identifier: Apache-2.0
"""Fleet collection and placement: remote status is evidence, never a remote-control instruction.

All files are temporary. Most reads use injected byte responses; the loopback HTTP test starts only its own
fixture server and skips when the command sandbox forbids sockets. No external service is contacted.
"""
import copy
import http.server
import json
import os
from pathlib import Path
import shlex
import subprocess
import threading
import time
import unittest
from unittest import mock

from mmtest import TempData, base_settings, mmcore
import mmdecide
import mmfleet
import mmplace


NOW = 1_800_000_000.0


def machine_config(ident="remote-a", **over):
    return dict({"id":ident, "status_url":"https://example.invalid/status.json", "kinds":{"go-test": 8, "other": 1},
                 "ssh_argv":["ssh", ident], "start_argv":["run-job", "--kind", "{kind}", "--shards", "{shards}"]}, **over)


def status(ident="remote-a", **over):
    return dict({"kind":"machine", "schema_version":1, "machine_id":ident, "time":NOW, "state":"GREEN", "mode":"act",
                 "reasons":["all readings in the green band"], "slots":4, "busy":0, "waiting":0,
                 "readings":{"free_pct":80}}, **over)


def blob(doc):
    return json.dumps(doc, allow_nan=True).encode()


class Collection(TempData):
    def setUp(self):
        super().setUp()
        self.settings = self.s()

    def fleet_profile(self, *configs):
        profile = self.profile()
        profile["machines"] = list(configs or [machine_config()])
        return profile

    def collect(self, profile=None, response=None, now=NOW):
        profile = profile or self.fleet_profile()
        response = blob(status()) if response is None else response
        return mmfleet.collect(profile, self.settings, now=now, fetcher=lambda cfg:response)

    def view(self, profile=None, now=NOW):
        return mmfleet.views(profile or self.fleet_profile(), now, self.settings)[0]

    def test_configuration_rejects_ambiguous_ids_and_unsafe_urls(self):
        bad_lists = [
            [machine_config("same"), machine_config("same")],
            [machine_config("Build"), machine_config("build")],
            [machine_config("../escape")],
            [machine_config(self.profile()["machine_id"])],
            [machine_config(status_url="file:///tmp/status.json")],
            [machine_config(status_url="https://user:password@example.com/status.json")],
            [machine_config(status_url="https://example.invalid/status.json#fragment")],
            [machine_config(timeout_s=float("nan"))],
            [machine_config(stale_after_s=-1)],
            [machine_config(kinds={"go-test":0})],
            [machine_config(start_argv=["{branch}", "--kind", "{kind}"])],
            [machine_config(start_argv=["ssh", "remote-a", "run-job", "{branch}"])],
            [machine_config(start_argv=["sh", "-c", "run-job {branch}"])],
        ]
        for configs in bad_lists:
            with self.subTest(configs=configs), self.assertRaises(mmcore.MMError):
                mmfleet.configs(self.fleet_profile(*configs))
        p = self.fleet_profile(machine_config("build-pool"))
        p["ci"] = {}
        p["pools"] = [{"id":"build-pool", "adapter":"static"}]
        with self.assertRaises(mmcore.MMError):
            mmfleet.configs(p)

    def test_success_is_cached_with_source_time_and_schema_stamp(self):
        result = self.collect()
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["kind"], "fleet")
        import mmschema
        self.assertEqual(mmschema.validate(result, mmschema.load("fleet")), [])
        row = result["machines"][0]
        self.assertEqual(row["id"], "remote-a")
        self.assertEqual(row["status"]["time"], NOW)
        self.assertEqual(row["collected_at"], NOW)
        self.assertIsNone(row["error"])
        cached = mmcore.read_json(mmcore.path("fleet.json"), None)
        self.assertEqual(cached, result)
        self.assertTrue(self.view()["eligible"])

    def test_one_failed_machine_does_not_hide_another(self):
        p = self.fleet_profile(machine_config("remote-a"), machine_config("remote-b"))
        def fetch(cfg):
            return b"not json" if cfg["id"] == "remote-a" else blob(status("remote-b"))
        result = mmfleet.collect(p, self.settings, now=NOW, fetcher=fetch)
        rows = {row["id"]:row for row in result["machines"]}
        self.assertTrue(rows["remote-a"]["error"])
        self.assertIsNone(rows["remote-b"]["error"])
        views = {row["id"]:row for row in mmfleet.views(p, NOW, self.settings)}
        self.assertFalse(views["remote-a"]["eligible"])
        self.assertTrue(views["remote-b"]["eligible"])

    def test_wrong_machine_version_or_invalid_counts_never_becomes_eligible(self):
        invalid = [status("other-host"), dict(status(), schema_version=2), dict(status(), schema_version=True),
                   dict(status(), kind="pool"), dict(status(), slots=True),
                   dict(status(), busy=-1), dict(status(), waiting=-1), dict(status(), waiting=float("inf")),
                   dict(status(), readings={"free_pct":float("nan")}),
                   dict(status(), readings={"free_pct":101}), dict(status(), time=NOW+3600)]
        for doc in invalid:
            with self.subTest(doc=doc):
                result = self.collect(response=blob(doc))
                self.assertTrue(result["machines"][0]["error"])
                self.assertFalse(self.view()["eligible"])

    def test_malformed_deep_oversized_or_duplicate_json_fails_closed(self):
        duplicate = blob(status()).decode().replace('"state": "GREEN"', '"state": "RED", "state": "GREEN"').encode()
        for raw in (b"{", b"\xff", b"["*200+b"0"+b"]"*200, b" "*(2**20+1), duplicate):
            with self.subTest(prefix=raw[:40]):
                result = self.collect(response=raw)
                self.assertTrue(result["machines"][0]["error"])
                self.assertFalse(self.view()["eligible"])

    def test_old_source_does_not_become_fresh_when_collected_now(self):
        result = self.collect(response=blob(dict(status(), time=NOW-600)))
        self.assertTrue(result["machines"][0]["error"])
        self.assertFalse(self.view()["eligible"])
        records = mmfleet.resources(self.fleet_profile(), NOW, self.settings)
        rows = [mmdecide.resource_row(rec, NOW, self.settings) for rec in records]
        self.assertFalse(rows[0]["fresh"])
        self.assertEqual(rows[0]["state"], "UNKNOWN")

    def test_old_collection_does_not_trust_a_previously_healthy_peer(self):
        self.collect()
        cached = mmcore.read_json(mmcore.path("fleet.json"))
        cached["machines"][0]["status"]["time"] = NOW+600
        mmcore.write_atomic(mmcore.path("fleet.json"), json.dumps(cached))
        self.assertFalse(self.view(now=NOW+600)["eligible"])

    def test_source_modes_and_states_gate_remote_launches(self):
        for state, mode, expected in (("GREEN","act",True), ("STEADY","act",True),
                                      ("AMBER","act",False), ("RED","act",False), ("UNKNOWN","act",False),
                                      ("GREEN","safe",False), ("GREEN","off",False),
                                      ("GREEN","observe",False), ("GREEN","dry",False)):
            with self.subTest(state=state, mode=mode):
                self.collect(response=blob(dict(status(), state=state, mode=mode)))
                self.assertEqual(self.view()["eligible"], expected)

    def test_cached_views_and_resources_do_not_perform_network_reads(self):
        self.collect()
        forbidden = AssertionError("network collection from a reader")
        with mock.patch.object(mmfleet, "collect", side_effect=forbidden), \
                mock.patch("urllib.request.build_opener", side_effect=forbidden), \
                mock.patch("subprocess.Popen", side_effect=forbidden):
            view = self.view()
            records = mmfleet.resources(self.fleet_profile(), NOW, self.settings)
        self.assertTrue(view["eligible"])
        self.assertEqual(records[0]["resource"], "machine")
        self.assertEqual(records[0]["id"], "remote-a")
        self.assertEqual(records[0]["location"], "remote")

    def test_fifo_or_symlink_cache_never_blocks_or_supplies_a_candidate(self):
        cache = Path(mmcore.path("fleet.json"))
        os.mkfifo(cache)
        started = time.monotonic()
        self.assertFalse(self.view()["eligible"])
        self.assertLess(time.monotonic()-started, 1)
        cache.unlink()
        target = Path(self.root) / "untrusted-cache.json"
        target.write_text("{}")
        cache.symlink_to(target)
        self.assertFalse(self.view()["eligible"])

    def test_url_or_query_secrets_are_not_written_to_cache(self):
        secret = "query-secret-never-store"
        p = self.fleet_profile(machine_config(status_url="https://example.invalid/status.json?token="+secret))
        def fail(cfg):
            raise OSError("request failed for " + cfg["status_url"])
        result = mmfleet.collect(p, self.settings, now=NOW, fetcher=fail)
        self.assertTrue(result["machines"][0]["error"])
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn(secret, Path(mmcore.path("fleet.json")).read_text())
        self.assertNotIn(secret, json.dumps(mmfleet.resources(p,NOW,self.settings)))

    def test_endpoint_echoed_by_remote_status_is_scrubbed(self):
        secret = "endpoint-secret-never-store"
        url = "https://example.invalid/status.json?token="+secret
        p = self.fleet_profile(machine_config(status_url=url))
        result = self.collect(profile=p, response=blob(dict(status(), reasons=["requested " + url])))
        self.assertIsNone(result["machines"][0]["error"])
        self.assertNotIn(secret,json.dumps(result))
        self.assertNotIn(secret,Path(mmcore.path("fleet.json")).read_text())

    def test_cache_is_revalidated_and_a_forged_eligible_flag_does_not_revive_it(self):
        self.collect()
        cached = mmcore.read_json(mmcore.path("fleet.json"))
        cached["machines"][0]["eligible"] = True
        cached["machines"][0]["status"]["machine_id"] = "wrong-host"
        mmcore.write_atomic(mmcore.path("fleet.json"),json.dumps(cached))
        self.assertFalse(self.view()["eligible"])

    def test_success_payload_cannot_store_query_tokens_in_arbitrary_keys(self):
        secret = "query-secret-never-store"
        cfg = machine_config(status_url="https://example.invalid/status.json?token="+secret)
        response = dict(status(), capacity={secret:1}, load={secret:2},
                        readings={"free_pct":80,secret:3})
        result = self.collect(profile=self.fleet_profile(cfg), response=blob(response))
        self.assertIsNone(result["machines"][0]["error"])
        self.assertNotIn(secret, json.dumps(result))

    def test_remote_command_comes_from_profile_and_keeps_each_argument_one_word(self):
        cfg = machine_config(start_argv=["run-job", "--branch", "{branch}", "--kind", "{kind}"])
        branch = "b;touch nope $(false)"
        commands = mmfleet.commands(cfg, {"kind":"go-test", "branch":branch, "shards":1})
        self.assertEqual(len(commands), 1)
        local = shlex.split(commands[0])
        self.assertEqual(local[:2], ["ssh", "remote-a"])
        self.assertEqual(shlex.split(local[2]), ["run-job", "--branch", branch, "--kind", "go-test"])

    def test_source_does_not_choose_executable_or_change_local_runtime_files(self):
        protected = ("settings.toml", "safe.json", "off.json", "state/paused.json")
        before = {}
        for name in protected:
            path = Path(mmcore.path(name))
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture " + name)
            before[name] = path.read_bytes()
        malicious = dict(status(), start_argv=["touch","/tmp/should-not-exist"])
        result = self.collect(response=blob(malicious))
        self.assertTrue(result["machines"][0]["error"])
        self.assertEqual({name:Path(mmcore.path(name)).read_bytes() for name in protected}, before)

    def test_status_with_no_available_slots_is_not_scheduled(self):
        self.collect(response=blob(dict(status(), slots=0)))
        self.assertFalse(self.view()["eligible"])

    def test_fetch_worker_deadline_kills_and_reaps_without_putting_url_in_argv(self):
        cfg = dict(machine_config(status_url="https://example.invalid/status.json?token=secret-do-not-log"), timeout_s=1)
        process = mock.Mock()
        process.communicate.side_effect = [subprocess.TimeoutExpired("fixture",1), (b"",b"")]
        with mock.patch("subprocess.Popen", return_value=process) as popen:
            with self.assertRaises(ValueError):
                mmfleet.fetch(cfg)
        process.kill.assert_called_once_with()
        self.assertEqual(process.communicate.call_count, 2)
        self.assertNotIn("secret-do-not-log", repr(popen.call_args))

    def test_loopback_transport_reads_status_but_never_follows_redirects_or_large_bodies(self):
        hits = []
        body = blob(status())
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                hits.append(self.path)
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location","/redirect-target")
                    self.end_headers()
                elif self.path == "/large":
                    self.send_response(200)
                    self.send_header("Content-Length",str(2**20+1))
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Type","application/json")
                    self.send_header("Content-Length",str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        except PermissionError:
            self.skipTest("loopback sockets require execution outside the command sandbox")
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            base = "http://127.0.0.1:%d" % server.server_port
            for path, expected in (("/ok",True),("/redirect",False),("/large",False)):
                p = self.fleet_profile(machine_config(status_url=base+path))
                result = mmfleet.collect(p,self.settings,now=NOW)
                self.assertEqual(result["machines"][0]["error"] is None,expected,(path,result))
            self.assertNotIn("/redirect-target",hits)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_cli_collect_resources_and_remote_placement_use_only_profile_commands(self):
        body = blob(status(time=time.time()))
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        except PermissionError:
            self.skipTest("loopback sockets require execution outside the command sandbox")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            profile = Path(self.root) / "fleet-profile.toml"
            original = Path(mmcore.profile_file()).read_text()
            profile.write_text(original + '\n[[machines]]\nid = "remote-a"\nstatus_url = "http://127.0.0.1:%d/status.json"\n'
                               'ssh_argv = ["ssh", "remote-a"]\n'
                               'start_argv = ["run-job", "--kind", "{kind}", "--branch", "{branch}"]\n'
                               '[machines.kinds]\ngo-test = 8\n' % server.server_port)
            self.queue_dir()
            mmcore.write_atomic(mmcore.path("status.json"), json.dumps({"time":time.time(), "state":"RED",
                                "reasons":["fixture"], "readings":{"free_pct":20}}))
            result = self.mm("collect", "--profile", str(profile), "--json")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["machines"][0]["status"]["machine_id"], "remote-a")
            rows = self.mm("resources", "--profile", str(profile), "--json")
            self.assertEqual(rows.returncode, 0, rows.stdout + rows.stderr)
            self.assertIn("remote-a", [r["id"] for r in json.loads(rows.stdout)["resources"]])
            marker = str(Path(self.root) / "never-created")
            branch = "b;touch %s $(false)" % marker
            placed = self.mm("place", "--profile", str(profile), "--kind", "go-test", "--branch", branch, "--json")
            self.assertEqual(placed.returncode, 0, placed.stdout + placed.stderr)
            record = json.loads(placed.stdout)
            self.assertEqual((record["place"],record["candidate"]), ("MACHINE","remote-a"))
            local = shlex.split(record["commands"][0])
            self.assertEqual(local[:2], ["ssh","remote-a"])
            self.assertEqual(shlex.split(local[2]), ["run-job","--kind","go-test","--branch",branch])
            self.assertFalse(Path(marker).exists())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def context(local_state="GREEN", local_wait=0):
    slots = 2
    q = {"slots":slots, "busy":[], "tickets":[]}
    if local_wait:
        q["busy"] = [{"kind":"go-test","since":NOW} for _ in range(slots)]
        q["tickets"] = [{"kind":"go-test"} for _ in range(2)]
    return {"now":NOW, "wide_kind":"wide", "kinds":{"machine_only":{"other":"machine only"}, "pool":{"go-test":8}},
            "machine":{"id":"local", "state":local_state, "reasons":["fixture"], "free_pct":80,
                       "queue":q, "medians":{"go-test":local_wait/2 if local_wait else 10}},
            "pools":[], "machines":[]}


def remote(ident="remote-a", wait=0, **over):
    return dict({"id":ident, "state":"GREEN", "reasons":["fixture"], "eligible":True, "kinds":{"go-test":8,"other":1},
                 "wait_minutes":wait}, **over)


class FleetPlacement(unittest.TestCase):
    def setUp(self):
        self.settings = base_settings()
        self.req = {"kind":"go-test", "shards":1}

    def place(self, ctx, **req):
        return mmdecide.place_fleet(dict(self.req, **req), ctx, self.settings)

    def test_no_remote_candidates_exactly_preserves_local_contract(self):
        for state in ("GREEN","AMBER","RED"):
            ctx = context(state, 30)
            self.assertEqual(self.place(ctx), mmdecide.place(self.req,ctx,self.settings))

    def test_fleet_and_native_unit_pools_share_placement_and_fail_over(self):
        ctx = context("RED")
        ctx["machines"] = [remote()]
        ctx["pools"] = [{"id":"credits", "generic":True, "unit":"credits", "capacity_left":80,
                         "reserve":10, "plan_cost":1, "job_cost":2, "source":"fixture",
                         "stop_active":False, "guard_why":None}]
        result = self.place(ctx)
        self.assertEqual((result["place"], result["candidate"]), ("MACHINE", "remote-a"))
        ctx["machines"][0]["eligible"] = False
        result = self.place(ctx)
        self.assertEqual((result["place"], result["candidate"]), ("POOL", "credits"))
        ctx["pools"][0]["capacity_left"] = 12
        self.assertEqual(self.place(ctx)["place"], "WAIT")

    def test_idle_local_machine_wins_tie(self):
        ctx = context()
        ctx["machines"] = [remote()]
        result = self.place(ctx)
        self.assertEqual((result["place"],result["candidate"]), ("MACHINE","local"))

    def test_fast_remote_relieves_busy_local_machine(self):
        ctx = context(local_wait=60)
        ctx["machines"] = [remote("slow",5),remote("fast",0)]
        result = self.place(ctx)
        self.assertEqual((result["place"],result["candidate"]), ("MACHINE","fast"))

    def test_pool_is_preferred_to_a_long_remote_queue(self):
        ctx = context("RED",60)
        ctx["machines"] = [remote(wait=60)]
        ctx["pools"] = [{"id":"ci", "minutes_left":5000,"minutes_source":"fixture","plan_minutes":1,
                         "job_minutes":10,"reserve_minutes":1,"guard":"skip","guard_why":None,"stop_active":False}]
        result = self.place(ctx)
        self.assertEqual((result["place"],result["candidate"]), ("POOL","ci"))

    def test_stale_wrong_kind_or_excess_shards_never_selects_remote(self):
        for candidate, req in ((remote(eligible=False),{}), (remote(kinds={"py-suite":1}),{}),
                               (remote(),{"shards":9}), (remote(state="RED"),{})):
            with self.subTest(candidate=candidate,req=req):
                ctx = context("RED",60)
                ctx["machines"] = [candidate]
                self.assertEqual(self.place(ctx,**req)["place"], "WAIT")

    def test_agent_and_wide_checks_stay_local(self):
        ctx = context("RED",60)
        ctx["machines"] = [remote()]
        for req in ({"agents":2}, {"wide":True}, {"kind":"wide"}):
            with self.subTest(req=req):
                self.assertEqual(self.place(ctx,**req)["place"], "WAIT")

    def test_machine_only_kind_can_use_an_explicitly_supported_machine(self):
        ctx = context("RED",60)
        ctx["machines"] = [remote()]
        result = self.place(ctx,kind="other")
        self.assertEqual((result["place"],result["candidate"]), ("MACHINE","remote-a"))


if __name__ == "__main__":
    unittest.main()
