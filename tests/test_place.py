# SPDX-License-Identifier: Apache-2.0
"""T8: `mm place` on a fixture queue held by live test processes, a fake budget guard and a fake billing record.
Machine-only kinds never go to the pool; the reserve, a refused guard or an active stop keep the job on the machine;
RED waits; POOL prints the exact commands and runs none of them; --wide waits while another wide holds."""
import json
import os
import shlex
import stat
import subprocess
import sys
import time
import unittest

from mmtest import TempData, mmcore

HOLD = r'''
import fcntl, sys, time
fs = []
for i in range(1, len(sys.argv), 2):
    f = open(sys.argv[i], "a+")
    fcntl.flock(f, fcntl.LOCK_EX)
    f.seek(0); f.truncate(); f.write(sys.argv[i + 1] + "\n"); f.flush()
    fs.append(f)
print("held", flush=True)
time.sleep(120)
'''


class Place(TempData):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir(slots=2)
        self.guard_calls = os.path.join(self.root, "guard-calls.txt")
        self.set_guard(0, "fits: 120 of 50000 minutes")
        self.billing(used=1000)
        self.status("GREEN")

    def set_guard(self, rc, line):
        g = os.path.join(self.root, "fake-guard.sh")
        with open(g, "w") as f:
            f.write('#!/bin/sh\necho "$@" >> %s\necho "%s"\nexit %d\n' % (self.guard_calls, line, rc))
        os.chmod(g, stat.S_IRWXU)
        self.guard = g

    def billing(self, used):
        mmcore.write_atomic(os.path.join(self.data, "state", "github.json"),
                            json.dumps({"time": time.time(), "billing": {"minutes": used}}))

    def status(self, state, reasons=("ok",), free=80):
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps(
            {"time": time.time(), "state": state, "reasons": list(reasons), "readings": {"free_pct": free}}))

    def busy(self, wide=False):
        """Both slots held for 30 min and six tickets waiting: the expected wait (31 min) is above the 20 min limit."""
        args = []
        for i in (1, 2):
            p = os.path.join(self.q, ".slot.%d" % i)
            args += [p, "%s %d go test ./pkg%d" % ("W" if wide and i == 1 else "S", 4000 + i, i)]
        for i in range(1, 7):
            args += [os.path.join(self.q, "queue", "%d-%d" % (time.time_ns() - 600 * 10 ** 9, i)), "S 50%d go test ./x" % i]
        h = subprocess.Popen([sys.executable, "-I", "-c", HOLD] + args, stdout=subprocess.PIPE, text=True)
        self.assertEqual(h.stdout.readline().strip(), "held")
        self.addCleanup(lambda: (h.kill(), h.wait(5)))
        old = time.time() - 1800
        for i in (1, 2):
            os.utime(os.path.join(self.q, ".slot.%d" % i), (old, old))

    def place(self, *args, settings=None):
        if settings:
            self.write_settings(**dict({"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10}, **settings))
        r = self.mm("place", *args, env={"MM_GUARD": self.guard, "MM_GH": "/usr/bin/false"})
        lines = r.stdout.splitlines()
        return r.returncode, lines, r.stderr

    def first(self, lines):
        return dict(x.split("=", 1) for x in lines[0].split())

    def test_free_machine_takes_pool_kind(self):
        rc, lines, err = self.place("--kind", "go-test", "--shards", "4")
        self.assertEqual((rc, self.first(lines)["place"]), (0, "MACHINE"), lines + [err])
        self.assertFalse(os.path.exists(self.guard_calls), "no guard read when the machine is free")

    def test_machine_only_kinds_never_go_to_the_pool(self):
        self.busy()
        for kind in ("merge-wide", "timing-rerun", "other", "never-heard-of"):
            rc, lines, _ = self.place("--kind", kind)
            self.assertEqual((rc, self.first(lines)["place"]), (0, "MACHINE"), (kind, lines))
            self.assertNotIn("POOL", "\n".join(lines))
        self.assertFalse(os.path.exists(self.guard_calls))

    def test_busy_machine_sends_to_pool_with_exact_commands(self):
        self.busy()
        rc, lines, _ = self.place("--kind", "go-test", "--shards", "4", "--sha", "0123456789abcdef", "--race")
        self.assertEqual((rc, self.first(lines)["place"], self.first(lines)["candidate"]), (10, "POOL", "ci:example/project"), lines)
        dos = [json.loads(x[3:]) for x in lines if x.startswith("do=")]
        self.assertEqual(dos, ["git push origin 0123456789abcdef:refs/heads/scratch-go-test-01234567",
                               "ci-dispatch --branch scratch-go-test-01234567 --kind go-test --shards 4 --race true "
                               "--packages ./...",
                               "mm watch <run-id> --note go-test"])
        self.assertEqual(open(self.guard_calls).read().split(),
                         ["--kind", "go-test", "--shards", "4", "--race", "true", "--packages", "./..."])
        self.assertTrue(any("guard: fits" in x for x in lines))

    def test_non_dispatch_kind_gets_the_scratch_command(self):
        self.busy()
        rc, lines, _ = self.place("--kind", "py-suite", "--shards", "8", "--branch", "b1")
        self.assertEqual(rc, 10, lines)
        self.assertEqual([json.loads(x[3:]) for x in lines if x.startswith("do=")],
                         ["make-scratch-branch b1", "mm watch <run-id> --note py-suite"])

    def test_filled_values_stay_one_word_in_shell_commands(self):
        self.busy()
        rc, lines, _ = self.place("--kind", "py-suite", "--branch", "b1;touch x $(y)")
        self.assertEqual(rc, 10, lines)
        dos = [json.loads(x[3:]) for x in lines if x.startswith("do=")]
        self.assertEqual(dos[0], "make-scratch-branch 'b1;touch x $(y)'")
        self.assertEqual(shlex.split(dos[0]), ["make-scratch-branch", "b1;touch x $(y)"])

    def test_refusals_keep_the_job_on_the_machine(self):
        self.busy()
        self.set_guard(1, "refused: over the limit")
        rc, lines, _ = self.place("--kind", "go-test", "--shards", "4")
        self.assertEqual((rc, self.first(lines)["place"]), (0, "MACHINE"))
        self.assertTrue(any("guard refused" in x for x in lines), lines)
        self.set_guard(0, "fits")
        self.billing(used=2700)  # 3000 - 2700 = 300 left; worst case 2 + 4 x 40 = 162; reserve 300
        rc, lines, _ = self.place("--kind", "go-test", "--shards", "4")
        self.assertEqual(rc, 0)
        self.assertTrue(any("<= reserve 300" in x for x in lines), lines)
        self.billing(used=1000)
        rc, lines, _ = self.place("--kind", "go-test", "--shards", "9")
        self.assertEqual(rc, 0)
        self.assertTrue(any("9 shards > 8" in x for x in lines), lines)
        rc, lines, _ = self.place("--kind", "rust-mutants", "--shards", "4")
        self.assertEqual(rc, 0)
        self.assertTrue(any("needs --crate and --diff-base" in x for x in lines), lines)
        st = mmcore.AlertStore(mmcore.Settings().load())
        st.begin()
        st.raise_("GUARD_STOP", "GUARD_STOP", "ACTION", "stop")
        rc, lines, _ = self.place("--kind", "go-test", "--shards", "4")
        self.assertEqual(rc, 0)
        self.assertTrue(any("GUARD_STOP is active" in x for x in lines), lines)

    def test_unknown_minutes_keep_the_job_on_the_machine(self):
        self.busy()
        os.remove(os.path.join(self.data, "state", "github.json"))
        rc, lines, _ = self.place("--kind", "go-test")
        self.assertEqual(rc, 0)
        self.assertTrue(any("minutes left unknown" in x for x in lines), lines)

    def test_red_offloads_or_waits_and_agents(self):
        self.status("RED", ["free 30% < 35%"], free=30)
        rc, lines, _ = self.place("--kind", "go-test")
        self.assertEqual((rc, self.first(lines)["place"]), (10, "POOL"), "RED: a pool kind goes to the pool when it fits")
        self.set_guard(1, "refused")
        rc, lines, _ = self.place("--kind", "go-test")
        self.assertEqual((rc, self.first(lines)["place"]), (20, "WAIT"), "RED and no pool: wait")
        rc, lines, _ = self.place("--kind", "timing-rerun")
        self.assertEqual((rc, self.first(lines)["place"]), (20, "WAIT"), "RED: a machine-only kind waits")
        rc, lines, _ = self.place("--agents", "2")
        self.assertEqual(rc, 20)
        self.status("AMBER", ["free 45% < 50%"], free=45)
        self.assertEqual(self.place("--agents", "2")[0], 20)
        self.assertEqual(self.place("--agents", "1")[0], 0)
        self.status("GREEN")
        rc, lines, _ = self.place("--agents", "3")
        self.assertEqual((rc, self.first(lines)["place"]), (0, "GO"))

    def test_wide(self):
        rc, lines, _ = self.place("--wide")
        self.assertEqual((rc, self.first(lines)["place"]), (0, "MACHINE"), lines)
        self.busy(wide=True)
        rc, lines, _ = self.place("--wide")
        self.assertEqual(rc, 20)
        self.assertTrue(any("another wide or exclusive call" in x for x in lines), lines)

    def test_json_record_matches_schema(self):
        import mmschema
        self.busy()
        r = self.mm("place", "--kind", "go-test", "--json", env={"MM_GUARD": self.guard, "MM_GH": "/usr/bin/false"})
        rec = json.loads(r.stdout)
        self.assertEqual(mmschema.validate(rec, mmschema.load("placement")), [])
        self.assertEqual((rec["machine_id"], rec["schema_version"], rec["place"]), ("test-machine", 1, "POOL"))


if __name__ == "__main__":
    unittest.main()
