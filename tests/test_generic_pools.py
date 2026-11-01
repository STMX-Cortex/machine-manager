# SPDX-License-Identifier: Apache-2.0
"""Generic pool capacity and command reads, isolated from live services and dispatch commands."""
import copy
import json
import os
from pathlib import Path
import shlex
import sys
import subprocess
import threading
import time
import unittest
from unittest import mock

from mmtest import TempData, mmcore, mmread
import ad_pool_generic
import mmadapters
import mmplace
import mmschema
import mmsuper
from test_resources import calm


class GenericPools(TempData):
    def setUp(self):
        super().setUp()
        self.now = time.time()
        self.queue_dir()

    def config(self, adapter="static", ident="workers", **over):
        cfg = {"adapter": adapter, "id": ident, "unit": "credits", "reserve": 10, "job_cost": 2,
               "start_argv": ["launch-worker", "--kind", "{kind}", "--shards", "{shards}"]}
        cfg.update({"total": 100} if adapter == "static" else {"read_argv": [sys.executable, "-c", "print('{}')"]})
        cfg.update(over)
        return cfg

    def profile_for(self, *configs):
        p = self.profile()
        p["ci"] = {}
        p["pools"] = list(configs or [self.config()])
        return p

    def pools(self, *configs):
        return mmadapters.pools(self.profile_for(*configs))

    def state(self, **over):
        data = {"schema_version": 1, "read_time": self.now, "state": "GREEN",
                "capacity": {"unit": "credits", "total": 100, "left": 80},
                "load": {"running": 1, "queued": 2}}
        data.update(over)
        return data

    def command(self, data=None, code=None, **over):
        if code is None:
            code = "print(" + repr(json.dumps(data or self.state())) + ")"
        return self.config("command", read_argv=[sys.executable, "-I", "-c", code], **over)

    def local_red(self):
        mmcore.write_atomic(mmcore.path("status.json"), json.dumps(
            {"time":self.now,"state":"RED","reasons":["fixture busy"],"readings":{"free_pct":10}}))

    def place(self, *configs, **request):
        self.local_red()
        profile = self.profile_for(*configs)
        return mmplace.place(dict({"kind":"go-test","shards":1}, **request), self.s(), profile,
                             pool=mmadapters.pools(profile), now=self.now)

    def test_mixed_static_command_and_github_preserve_schema(self):
        github = copy.deepcopy(self.profile()["ci"])
        github["id"] = "github"
        github.pop("pool_id")
        configs = [self.config(), self.command(ident="cloud"), github]
        p = self.profile_for(*configs)
        raw = {k:v for k,v in p.items() if not k.startswith("_") and k != "ci"}
        self.assertEqual(mmschema.validate(raw, mmschema.load("profile")), [])
        self.assertEqual([p.id for p in self.pools(*configs)], ["workers","cloud","github"])

    def test_invalid_config_fails_before_reader_runs(self):
        for over in ({"job_cost":-1}, {"reserve":True}, {"total":float("inf")}, {"job_cost":float("nan")},
                     {"unit":"credits\n"}, {"start_argv":[]}, {"start_argv":["{branch}"]},
                     {"start_argv":["{sha.__class__}"]}, {"start_argv":["ssh","host","{branch}"]},
                     {"start_argv":["sh","-c","echo {branch}"]},
                     {"start_argv":["{sha!r}"]}, {"left":101}, {"job_costs":{"go-test":-1}}):
            with self.subTest(over=over), self.assertRaises(mmcore.MMError):
                self.pools(self.config(**over))
        with self.assertRaises(mmcore.MMError):
            self.pools(self.command(timeout_s=60))

    def test_static_places_in_own_units_and_does_not_run_start_command(self):
        marker = str(Path(self.root) / "should-not-exist")
        cfg = self.config(start_argv=[sys.executable,"-c","open(" + repr(marker) + ",'w').write('bad')"])
        result = self.place(cfg, shards=3)
        self.assertEqual((result["place"], result["candidate"]), ("POOL", "workers"))
        self.assertIn("worst case 6", result["reasons"][-1])
        self.assertEqual(len(result["commands"]), 1)
        self.assertFalse(Path(marker).exists())

    def test_each_pool_uses_its_own_unit_reserve_and_per_kind_cost(self):
        first = self.config(ident="credits", total=15, job_costs={"go-test":3}, plan_cost=1)
        second = self.config(ident="slots", unit="slots", total=8, reserve=1, job_cost=1)
        result = self.place(first, second, shards=2)
        self.assertEqual(result["candidate"], "slots")
        self.assertIn("8 slots left", result["reasons"][-1])

    def test_reserve_boundary_refuses(self):
        result = self.place(self.config(total=12), shards=1)
        self.assertEqual(result["place"], "WAIT")
        self.assertEqual(result["commands"], [])

    def test_printed_arguments_are_shell_quoted_and_required_values_are_checked(self):
        cfg = self.config(start_argv=["deploy", "--branch", "{branch}"])
        result = self.place(cfg, branch="feature; echo hidden")
        self.assertEqual(shlex.split(result["commands"][0]), ["deploy","--branch","feature; echo hidden"])
        missing = self.place(cfg)
        self.assertEqual(missing["place"], "WAIT")
        self.assertIn("start command needs --branch", " ".join(missing["reasons"]))

    def test_ssh_transport_preserves_arguments_through_both_shells(self):
        branch = "topic; printf hidden > /tmp/should-never-run"
        cfg = self.config(ssh_argv=["ssh","build-host"],start_argv=["/opt/run-job","--branch","{branch}"])
        result = self.place(cfg, branch=branch)
        outer = shlex.split(result["commands"][0])
        self.assertEqual(outer[:2],["ssh","build-host"])
        self.assertEqual(len(outer),3)
        self.assertEqual(shlex.split(outer[2]),["/opt/run-job","--branch",branch])
        for ssh in (["ssh"], ["ssh","{branch}"], ["ssh","host\n"]):
            with self.assertRaises(mmcore.MMError):
                self.pools(self.config(ssh_argv=ssh))

    def test_command_caches_valid_state_and_placement_only_reads_cache(self):
        cfg = self.command()
        pool = self.pools(cfg)[0]
        with mock.patch.object(mmread, "run_bounded", wraps=mmread.run_bounded) as run:
            self.assertEqual(self.place(cfg)["place"], "WAIT")
            run.assert_not_called()
            read = pool.job(self.s(), self.now)
            self.assertIsNone(read["error"])
            self.assertEqual(read["data"]["read_time"], self.now)
            self.assertEqual(self.place(cfg)["place"], "POOL")
            self.assertEqual(run.call_count, 1)

    def test_error_unknown_and_stopped_state_are_not_candidates(self):
        for state in ("RED", "UNKNOWN"):
            cfg = self.command(self.state(state=state))
            self.pools(cfg)[0].job(self.s(), self.now)
            self.assertEqual(self.place(cfg)["place"], "WAIT")

    def test_stale_and_future_source_times_are_not_refreshed_by_command(self):
        for when in (self.now - 301, self.now + 100):
            cfg = self.command(self.state(read_time=when))
            pool = self.pools(cfg)[0]
            pool.job(self.s(), self.now)
            result = pool.candidate({"kind":"go-test"}, self.s(), self.now)
            self.assertIsNone(result["capacity_left"])
            self.assertEqual(self.place(cfg)["place"], "WAIT")

    def test_invalid_script_state_cannot_choose_commands_or_override_reserve(self):
        for data in (self.state(commands=["touch /tmp/never"]), self.state(capacity={"unit":"credits","total":10,"left":11}),
                     self.state(capacity={"unit":"minutes","total":100,"left":80}),
                     self.state(capacity={"unit":"credits","total":100,"left":80,"reserve":0}),
                     self.state(read_time=float("nan"))):
            with self.subTest(data=data):
                cfg = self.command(data)
                read = self.pools(cfg)[0].job(self.s(), self.now)
                self.assertIsNotNone(read["error"])
                self.assertEqual(self.place(cfg)["place"], "WAIT")

    def test_nonfinite_duplicate_and_deep_json_fail_closed(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'['*40+b'0'+b']'*40):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ad_pool_generic.parse_state(raw)

    def test_command_output_and_time_are_bounded(self):
        cases = [("print('x'*10000)", {"max_bytes":1024}), ("import time; time.sleep(1)", {"timeout_s":0.1}),
                 ("import sys; sys.exit(7)", {}), ("print('broken json')", {})]
        for code, limits in cases:
            with self.subTest(code=code):
                pool = self.pools(self.command(code=code, **limits))[0]
                started = time.monotonic()
                result = pool.job(self.s(), self.now)
                self.assertIsNotNone(result["error"])
                self.assertLess(time.monotonic()-started, 2)

    def test_inherited_stdout_does_not_defeat_deadline(self):
        code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time;time.sleep(.3)'])"
        started = time.monotonic()
        rc, _, why = mmread.run_bounded([sys.executable,"-I","-c",code], timeout=0.1)
        self.assertIsNone(rc)
        self.assertIn("timed out", why)
        self.assertLess(time.monotonic()-started, 0.5)

    def test_bounded_reader_is_registered_for_supervisor_stop(self):
        marker = Path(self.root) / "reader-started"
        code = "import pathlib,time;pathlib.Path(" + repr(str(marker)) + ").write_text('ready');time.sleep(10)"
        result = []
        thread = threading.Thread(target=lambda:result.append(mmread.run_bounded([sys.executable,"-I","-c",code], 5)))
        thread.start()
        end = time.monotonic()+2
        while not marker.exists() and time.monotonic()<end:
            time.sleep(.01)
        self.assertTrue(marker.exists())
        self.assertGreaterEqual(mmread.kill_children(),1)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertNotEqual(result[0][0], 0)

    def test_owned_reader_group_is_cleaned_on_success_timeout_and_overflow(self):
        unrelated = subprocess.Popen([sys.executable,"-I","-c","import time;time.sleep(10)"])
        try:
            for mode in ("success","timeout","overflow"):
                marker = Path(self.root)/(mode+"-child")
                child = "import time;time.sleep(10)"
                code = ("import subprocess,sys,pathlib,time; p=subprocess.Popen([sys.executable,'-I','-c'," + repr(child) +
                        "],stdout=subprocess.DEVNULL);pathlib.Path(" + repr(str(marker)) + ").write_text(str(p.pid));")
                if mode == "timeout":
                    code += "time.sleep(10)"
                elif mode == "overflow":
                    code += "print('x'*10000,flush=True);time.sleep(10)"
                else:
                    code += "print('{}')"
                result = mmread.run_bounded([sys.executable,"-I","-c",code],timeout=.2,max_bytes=1024)
                self.assertTrue(marker.exists(),result)
                pid = int(marker.read_text())
                end = time.monotonic()+1
                while time.monotonic()<end:
                    try:
                        os.waitpid(pid,os.WNOHANG)
                    except ChildProcessError:
                        pass
                    state = subprocess.run(["/bin/ps","-o","stat=","-p",str(pid)],capture_output=True,text=True).stdout.strip()
                    if not state or state.startswith("Z"):
                        break
                    time.sleep(.01)
                self.assertTrue(not state or state.startswith("Z"), (mode,state))
                self.assertIsNone(unrelated.poll(), "cleanup must not signal an unrelated process")
        finally:
            unrelated.kill()
            unrelated.wait(timeout=2)

    def test_group_cleanup_rejects_an_unregistered_process(self):
        class Outside:
            pid = 123
        with mock.patch.object(mmread.os,"killpg") as send:
            self.assertFalse(mmread._kill_owned_group(Outside()))
            send.assert_not_called()

    def test_malformed_cached_data_does_not_poison_healthy_static_pool(self):
        bad = self.command(ident="bad")
        good = self.config(ident="good")
        first, second = self.pools(bad, good)
        for read in ({"time":"broken"}, {"time":self.now,"data":[]}, {"time":self.now,"data":self.state(capacity={})}):
            mmcore.write_atomic(first.cache_file(), json.dumps(read))
            self.assertEqual(self.place(bad, good)["candidate"], "good")
            self.assertEqual(first.status(read,self.s(),self.now)["state"],"UNKNOWN")
            self.assertEqual(second.resources(None,self.s(),self.now)[0]["state"],"GREEN")

    def test_deep_and_oversized_on_disk_cache_cannot_poison_supervisor_or_placement(self):
        bad, good = self.command(ident="bad",max_bytes=1024), self.config(ident="good")
        pool = self.pools(bad)[0]
        Path(pool.cache_file()).parent.mkdir(parents=True,exist_ok=True)
        for raw in ("["*2000+"0"+"]"*2000,"x"*10000):
            Path(pool.cache_file()).write_text(raw)
            self.assertIsNone(pool.load_cache())
            self.assertEqual(self.place(bad,good)["candidate"],"good")
            with mock.patch.object(mmread,"disk_free_gb",return_value=500):
                sup = mmsuper.Supervisor(self.profile_for(bad,good), kernel=False,sizes=False,slow_jobs=False,
                                         sampler=calm,clock=lambda:self.now,check_readings=False)
                sup.tick()
            self.assertEqual(mmcore.read_json(mmcore.path("pools","good.json"))["state"],"GREEN")

    def test_worker_result_and_status_mask_external_text_before_first_tick(self):
        secret = "token=abcdef1234567890abcdef1234567890"
        cfg = self.command(self.state(why=secret+"\nraw\\value"))
        pool = self.pools(cfg)[0]
        read = pool.job(self.s(),self.now)
        status = json.dumps(pool.status(read,self.s(),self.now))
        self.assertNotIn("abcdef1234567890",status)
        self.assertNotIn("abcdef1234567890",json.dumps(read))

    def test_supervisor_writes_generic_status_and_resource_schema(self):
        cfg = self.command()
        self.pools(cfg)[0].job(self.s(), self.now)
        with mock.patch.object(mmread,"disk_free_gb",return_value=500):
            sup = mmsuper.Supervisor(self.profile_for(cfg), kernel=False, sizes=False, slow_jobs=False,
                                     sampler=calm, clock=lambda:self.now, check_readings=False)
            sup.tick()
        status = mmcore.read_json(mmcore.path("pools","workers.json"))
        resources = mmcore.read_json(mmcore.path("resources.json"))
        self.assertEqual(mmschema.validate(status,mmschema.load("status")), [])
        self.assertEqual(mmschema.validate(resources,mmschema.load("resource")), [])
        row = next(r for r in resources["resources"] if r["id"]=="workers")
        self.assertEqual(row["capacity"], {"unit":"credits","total":100,"left":80,"reserve":10})

    def test_watch_rejects_generic_pool(self):
        profile = Path(self.root)/"generic.toml"
        profile.write_text('name="generic"\n[[pools]]\nid="fixed"\nadapter="static"\nunit="slots"\n'
                           'total=10\nreserve=1\njob_cost=1\nstart_argv=["start", "{kind}"]\n')
        result = self.mm("watch","123","--pool","fixed",env={"MM_PROFILE":str(profile)})
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn("does not support watched runs",result.stdout)


if __name__ == "__main__":
    unittest.main()
