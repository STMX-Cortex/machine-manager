# SPDX-License-Identifier: Apache-2.0
"""Golden outputs of each `mm` command on a fixed data folder, and the output limits for agents:
status at most 5 lines, alert lines at most 200 characters, errors one `E_CODE what; fix: how` line,
only the documented exit codes, no colour codes, --json is one JSON object."""
import json
import os
import re
import time
import unittest

from mmtest import TempData, mmcore

T = 1_800_000_000.0
EXITS = {0, 1, 2, 3, 10, 20}
ERROR = re.compile(r"^E_[A-Z_]+ .+; fix: .+$")


class Golden(TempData):
    def setUp(self):
        super().setUp()
        self.queue_dir()
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps(mmcore.stamp({
            "kind": "machine", "time": now, "state": "AMBER", "reasons": ["free 45% < 50%"], "mode": "observe", "slots": 5,
            "busy": 2, "waiting": 1, "disk_gb": 107.2,
            "readings": {"free_pct": 45, "swap_used_mb": 499.4, "comp_mb": 2100, "pressure": 2, "load5": 4.5, "sys_pct": 12.3}},
            mid="test-machine")))
        clock = {"t": T}
        st = mmcore.AlertStore(self.s(), clock=lambda: clock["t"], mid="test-machine")
        st.begin()
        st.raise_("MEM", "MEM_AMBER", "ATTENTION", "memory AMBER: free 45% < 50%; slots go down one step", command="mm status")
        st.raise_("DISK_LOW", "DISK_LOW", "ACTION", "disk 35 GB free < 40 GB", command="mm cleanup")
        st.raise_("IDLE_ROOM", "IDLE_ROOM", "INFO", "queue idle 40 min")
        st.raise_("LONG", "LONG_CALL", "ATTENTION", "a call runs " + "very " * 60 + "long",
                  command="QUEUE_X=1 /opt/q/run-queued.py --exclusive -- /opt/bin/some-long-command --with --many --flags 360")

    def run_mm(self, *args):
        r = self.mm(*args)
        self.assertIn(r.returncode, EXITS, (args, r.returncode))
        self.assertNotIn("\x1b[", r.stdout, "no colour codes")
        self.assertEqual(r.stderr, "", (args, r.stderr))
        return r.returncode, r.stdout.rstrip("\n").splitlines()

    def test_status(self):
        rc, out = self.run_mm("status")
        self.assertEqual(rc, 0)
        self.assertEqual(out, [
            "state=AMBER mode=observe slots=5 busy=2 waiting=1 machine=test-machine",
            "free_pct=45 swap_mb=499.4 comp_mb=2100 pressure=2 load5=4.5 sys_pct=12.3 disk_gb=107.2",
            "action=1 attention=2 info=1 top=DISK_LOW,LONG_CALL,MEM_AMBER",
            'why="free 45% < 50%"'])
        self.assertLessEqual(len(out), 5)

    def test_status_stale_and_missing(self):
        p = os.path.join(self.data, "status.json")
        d = json.load(open(p))
        d["time"] -= 500
        mmcore.write_atomic(p, json.dumps(d))
        rc, out = self.run_mm("status")
        self.assertEqual(rc, 3)
        self.assertTrue(out[0].startswith("state=UNKNOWN "))
        self.assertRegex(out[-1], r"^E_STALE status.json 50\d s old; fix: mm start; launch gate open$")
        os.remove(p)
        rc, out = self.run_mm("status")
        self.assertEqual(rc, 3)
        self.assertEqual(len(out), 1)
        self.assertRegex(out[0], ERROR)

    def test_alerts_and_explain(self):
        rc, out = self.run_mm("alerts")
        self.assertEqual(rc, 0)
        self.assertEqual(out[0], "ACTION DISK_LOW disk 35 GB free < 40 GB | do: mm cleanup")
        self.assertTrue(out[1].startswith("ATTENTION LONG_CALL a call runs very very"), out[1])
        self.assertEqual(len(out[1]), 200, "a long text is cut to the line limit")
        self.assertTrue(out[1].endswith("| do: mm explain LONG_CALL"), out[1])
        self.assertEqual(out[2], "ATTENTION MEM_AMBER memory AMBER: free 45% < 50%; slots go down one step | do: mm status")
        self.assertEqual(out[3], "INFO IDLE_ROOM queue idle 40 min")
        self.assertTrue(all(len(l) <= 200 for l in out), [len(l) for l in out])
        rc, out = self.run_mm("explain", "LONG_CALL")
        self.assertEqual(rc, 0)
        self.assertRegex(out[0], r"^id=LONG_CALL level=ATTENTION since=\S+ \S+ count=1 acked=no$".replace("since=\\S+ \\S+",
                                                                                                          'since="[^"]+"'))
        self.assertTrue(out[1].startswith('text="a call runs very'))
        self.assertEqual(out[2], 'command="QUEUE_X=1 /opt/q/run-queued.py --exclusive -- /opt/bin/some-long-command --with '
                                 '--many --flags 360"')
        rc, out = self.run_mm("explain", "NOPE")
        self.assertEqual((rc, out), (1, ["alert=none id=NOPE"]))

    def test_ack(self):
        self.assertEqual(self.run_mm("ack", "DISK_LOW"), (0, ["acked=yes id=DISK_LOW"]))
        rc, out = self.run_mm("alerts")
        self.assertEqual(out[0], "ACTION DISK_LOW disk 35 GB free < 40 GB (acked) | do: mm cleanup")
        self.assertEqual(self.run_mm("ack", "NOPE"), (1, ["acked=no id=NOPE reason=not_active"]))

    def test_off_on_and_pin(self):
        rc, out = self.run_mm("off", "--reason", "maintenance")
        self.assertEqual(rc, 0)
        self.assertRegex(out[0], r"^actions=off since=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d$")
        rec = json.load(open(os.path.join(self.data, "off.json")))
        self.assertEqual((rec["off"], rec["reason"], rec["machine_id"], rec["schema_version"]), (True, "maintenance", "test-machine", 1))
        import mmschema
        self.assertEqual(mmschema.validate(rec, mmschema.load("off")), [])
        self.assertEqual(self.run_mm("on"), (0, ["actions=on"]))
        self.assertFalse(os.path.exists(os.path.join(self.data, "off.json")))
        rc, out = self.run_mm("slots", "pin", "4", "--minutes", "60")
        self.assertEqual(rc, 0)
        self.assertRegex(out[0], r"^pin=4 until=\S+$")
        self.assertEqual(mmschema.validate(json.load(open(os.path.join(self.data, "override.json"))), mmschema.load("override")), [])
        for args in (("slots", "pin", "40", "--minutes", "60"), ("slots", "pin", "4"), ("slots", "pin", "x", "--minutes", "5"),
                     ("slots",)):
            rc, out = self.run_mm(*args)
            self.assertEqual(rc, 2, args)
            self.assertEqual(len(out), 1)
            self.assertRegex(out[0], ERROR)
        self.assertEqual(self.run_mm("slots", "unpin"), (0, ["pin=none"]))

    def test_cleanup_event_watch(self):
        self.assertEqual(self.run_mm("cleanup"), (1, ["cleanup=none reason=no_list_yet"]))
        mmcore.write_atomic(os.path.join(self.data, "state", "cleanup-list.json"), json.dumps(
            {"time": T, "items": [{"rule": "R1", "path": "/w/a b", "bytes": 4.2e9, "why": "merged",
                                   "command": "git -C /r worktree remove '/w/a b'"}]}))
        self.assertEqual(self.run_mm("cleanup"), (0, ['rule=R1 gb=4.2 path="/w/a b" do="git -C /r worktree remove \'/w/a b\'"']))
        self.assertEqual(self.run_mm("event", "timing-failure", "--note", "TOKEN=abcdefgh1234"),
                         (0, ["event=timing-failure recorded=yes"]))
        ev = json.loads(open(os.path.join(self.data, "state", "events.jsonl")).read().splitlines()[-1])
        self.assertEqual(ev["note"], "TOKEN=***", "masked")
        self.assertEqual(self.run_mm("watch", "123456", "--note", "x"), (0, ["watch=123456"]))
        rc, out = self.run_mm("watch", "abc")
        self.assertEqual(rc, 2)
        self.assertRegex(out[0], ERROR)

    def test_help_usage_and_errors(self):
        rc, out = self.run_mm("help")
        self.assertEqual(rc, 0)
        self.assertLessEqual(len(out), 30)
        self.assertTrue(all(len(l) <= 100 for l in out), max(len(l) for l in out))
        self.assertEqual(self.run_mm()[0], 2)
        for args in (("frobnicate",), ("explain",), ("ack",), ("place", "--bogus"), ("place", "--shards", "x"),
                     ("event", "x"), ("drill", "cpu"), ("status", "--profile", "/nonexistent/p.toml")):
            rc, out = self.run_mm(*args)
            self.assertEqual(rc, 2, args)
            self.assertEqual(len(out), 1, (args, out))
            self.assertRegex(out[0], ERROR)

    def test_json_outputs_are_one_object(self):
        for args in (("status",), ("alerts",), ("explain", "MEM_AMBER")):
            r = self.mm(*args, "--json")
            self.assertIsInstance(json.loads(r.stdout), dict, args)
            self.assertEqual(len(r.stdout.strip().splitlines()), 1)

    def test_bad_settings_is_one_error_line(self):
        with open(os.path.join(self.data, "settings.toml"), "w") as f:
            f.write("[broken\n")
        self.assertEqual(self.run_mm("slots", "pin", "4", "--minutes", "5")[0], 0, "a bad file: the last good values")
        os.remove(os.path.join(self.data, "state", "settings.lastgood.json"))
        rc, out = self.run_mm("slots", "pin", "4", "--minutes", "5")
        self.assertEqual(rc, 2)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].startswith("E_SETTINGS "), out)


if __name__ == "__main__":
    unittest.main()
