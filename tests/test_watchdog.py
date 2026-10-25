# SPDX-License-Identifier: Apache-2.0
"""T5: a stale supervisor, memory guard or queue sampler is seen: the watchdog alerts and restarts the supervisor
(a fake launchctl); after `mm stop` it restarts nothing."""
import json
import os
import stat
import time
import unittest

import mmtest
from mmtest import TempData, mmcore


class Watchdog(TempData):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir()
        os.makedirs(os.path.join(self.data, "guard"))
        self.calls = os.path.join(self.root, "launchctl-calls.txt")
        self.fake = os.path.join(self.root, "fake-launchctl.sh")
        with open(self.fake, "w") as f:
            f.write('#!/bin/sh\necho "$@" >> %s\n' % self.calls)
        os.chmod(self.fake, stat.S_IRWXU)
        self.now = time.time()
        self.fresh()

    def fresh(self, st_age=5, guard_age=5, ll_age=30):
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": self.now - st_age, "state": "GREEN"}))
        mmcore.write_atomic(os.path.join(self.data, "guard", "state.json"), json.dumps({"heartbeat_epoch": self.now - guard_age}))
        ll = os.path.join(self.q, "load.log")
        os.utime(ll, (self.now - ll_age, self.now - ll_age))

    def wd(self, at=None, *extra):
        r = self.mm("watchdog", *extra, env={"MM_LAUNCHCTL": self.fake, "MM_NOW": str(at or self.now)})
        line = r.stdout.strip()
        return r.returncode, line

    def test_all_fresh_is_quiet(self):
        self.assertEqual(self.wd(), (0, "problems=0"))
        self.assertFalse(os.path.exists(self.calls))
        self.assertEqual(self.pushed(), [])

    @mmtest.darwin_only
    def test_stale_supervisor_alerts_and_restarts(self):
        self.fresh(st_age=200)
        rc, line = self.wd()
        self.assertEqual(rc, 1)
        self.assertIn("status.json 200 s old", line)
        self.assertEqual(open(self.calls).read().split(),  # loaded? then the restart
                         ["print", "gui/%d/com.example.machine-manager-test" % os.getuid(),
                          "kickstart", "-k", "gui/%d/com.example.machine-manager-test" % os.getuid()])
        recs = self.pushed()
        self.assertEqual([(r["name"], r["level"]) for r in recs], [("SELF_STALE", "ACTION")])
        self.assertIn("kickstart rc=0", recs[0]["text"])
        self.now += 60
        self.fresh(st_age=260)
        self.wd()
        self.assertEqual([l.split()[0] for l in open(self.calls).read().splitlines()], ["print", "kickstart"] * 2)
        self.assertEqual(len(self.pushed()), 1, "dedupe")
        self.now += 120
        self.fresh()
        self.wd()
        self.now += 301
        self.fresh()
        self.wd()
        self.assertEqual([r["why"] for r in self.pushed()], ["new", "cleared"])

    def test_no_restart_flag_and_missing_status(self):
        os.remove(os.path.join(self.data, "status.json"))
        rc, line = self.wd(None, "--no-restart")
        self.assertIn("no status.json", line)
        self.assertFalse(os.path.exists(self.calls))

    def test_guard_and_sampler_stale(self):
        self.fresh(guard_age=300, ll_age=400)
        self.wd()
        self.assertEqual({r["name"]: r["level"] for r in self.pushed()}, {"GUARD_DOWN": "ACTION", "SOURCE_STALE": "ATTENTION"})
        self.assertFalse(os.path.exists(self.calls), "only the supervisor is restarted")

    @mmtest.darwin_only
    def test_failing_launchctl_is_reported(self):
        with open(self.fake, "w") as f:
            f.write('#!/bin/sh\n[ "$1" = print ] && exit 0\nexit 113\n')  # loaded, but the kickstart fails
        self.fresh(st_age=500)
        self.wd()
        self.assertIn("kickstart rc=113", self.pushed()[0]["text"])

    def test_stopped_marker_means_no_restart(self):
        mmcore.write_atomic(os.path.join(self.data, "state", "stopped.json"), json.dumps({"time": self.now}))
        self.fresh(st_age=900)
        self.assertEqual(self.wd()[0], 0)
        self.assertFalse(os.path.exists(self.calls))


if __name__ == "__main__":
    unittest.main()
