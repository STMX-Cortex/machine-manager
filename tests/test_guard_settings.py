# SPDX-License-Identifier: Apache-2.0
"""Three guard values (owner approval, step 2 of the settings review):

1. `names.disk_command` (profile, default ""): DISK_LOW and CLEANUP_LIST name it as their command; without it DISK_LOW
   has no command and CLEANUP_LIST names `mm cleanup`.
3. `slots.red_comp_mb` (setting, default 0 = off, range 0-100000): a compressor strictly over it is RED with the
   reason `compressor at N MB (near its ceiling)`, a critical reason (review F4: 0 is off, so no compressor size
   changes the state at the default).
4. `slots.green_disk_gb` (setting, default 0 = follow disk.recover_gb, range 0-10000): GREEN needs free disk of at least
   this; it must be 0 or at least `slots.red_disk_gb`.

Expectations come from the meaning of each value, never from the code: each fires and does not fire, the boundary,
and the defaults change nothing. Supervisor tests run in a temporary data folder (mmtest.TempData)."""
import json
import os
import unittest

import mmtest
from mmtest import base_settings, mmcore, mmread
import mmalerts
import mmdecide
import mmschema
import mmsuper
from test_supervisor import Base, sampler_of

NOW = 1_800_000_000.0
CMD = "/opt/example/bin/disk-cleanup --full"
CL = {"count": 2, "bytes": 3.3e9, "top": [{"rule": "R1", "path": "/w/a", "bytes": 3e9}]}


def named(conds, name):
    return [c for c in conds if c["name"] == name]


def calm(t, **kw):
    d = {"t": t, "free_pct": 80, "swap_used_mb": 0, "swap_total_mb": 0, "comp_mb": 500, "pressure": 1, "seg_pct": 1,
         "load1": 2, "load5": 2, "sys_pct": 10}
    d.update(kw)
    return d


def window(**kw):
    return [calm(NOW - 180 + 60 * k, **kw) for k in range(4)]


# ------------------------------------------------------------------------------------------- 1. names.disk_command

class DiskCommand(unittest.TestCase):
    def setUp(self):
        self.s = base_settings()

    def evaluate(self, snap, active=frozenset(), names=None):
        return mmalerts.evaluate(snap, self.s, NOW, active=active, names=names)

    def test_disk_low_names_the_profile_command(self):
        c = named(self.evaluate({"disk_gb": 35.0}, names={"disk_command": CMD}), "DISK_LOW")
        self.assertEqual([(x["level"], x["command"]) for x in c], [("ACTION", CMD)])
        line = mmcore.alert_line(dict(c[0], why="new"))
        self.assertTrue(line.endswith(" | do: " + CMD), line)

    def test_disk_low_held_by_hysteresis_keeps_the_command(self):
        c = named(self.evaluate({"disk_gb": 42.0}, active={"DISK_LOW"}, names={"disk_command": CMD}), "DISK_LOW")
        self.assertEqual([x["command"] for x in c], [CMD])

    def test_disk_not_low_raises_no_disk_low(self):
        # disk.low_gb 40: 40.0 is not under it; with no earlier alert nothing fires, whatever the command
        self.assertEqual(named(self.evaluate({"disk_gb": 40.0}, names={"disk_command": CMD}), "DISK_LOW"), [])
        self.assertEqual(named(self.evaluate({"disk_gb": 39.9}, names={"disk_command": CMD}), "DISK_LOW")[0]["command"],
                         CMD)

    def test_without_the_name_nothing_changes(self):
        for names in (None, {}, {"disk_command": ""}):
            with self.subTest(names=names):
                self.assertIsNone(named(self.evaluate({"disk_gb": 35.0}, names=names), "DISK_LOW")[0]["command"])
                self.assertEqual(named(self.evaluate({"disk_gb": 100.0, "cleanup": CL}, names=names),
                                       "CLEANUP_LIST")[0]["command"], "mm cleanup")

    def test_cleanup_list_names_the_profile_command(self):
        for disk, level in ((45.0, "ATTENTION"), (100.0, "INFO")):
            c = named(self.evaluate({"disk_gb": disk, "cleanup": CL}, names={"disk_command": CMD}), "CLEANUP_LIST")
            self.assertEqual([(x["level"], x["command"]) for x in c], [(level, CMD)])

    def test_other_disk_alerts_keep_their_commands(self):
        conds = self.evaluate({"disk_gb": 50.0, "disk_rate_gb_h": 5.0}, names={"disk_command": CMD})
        self.assertIsNone(named(conds, "DISK_TREND")[0]["command"])
        trim = named(self.evaluate({"disk_gb": 35.0, "trim": {"needed_min": 70}, "trim_needed_ok": True},
                                   names={"disk_command": CMD, "trim_command": "trim-by-hand"}), "TRIM_NEEDED")
        self.assertEqual([x["command"] for x in trim], ["trim-by-hand"])

    def test_profile_default_and_schema(self):
        self.assertEqual(mmcore.PROFILE_DEFAULTS["names"]["disk_command"], "")
        schema = mmschema.load("profile")
        self.assertEqual(mmschema.validate({"name": "x", "names": {"disk_command": CMD}}, schema), [])
        self.assertTrue(mmschema.validate({"name": "x", "names": {"disk_command": 7}}, schema))
        example = mmcore.load_toml(os.path.join(mmtest.CODE, "profiles", "example.toml"))
        self.assertIsInstance(example["names"].get("disk_command"), str, "the example profile shows the key")


class DiskCommandSupervisor(Base):
    """The supervisor passes the profile's names to the alert rules: DISK_LOW in alerts.jsonl carries the command."""

    def setUp(self):
        super().setUp()
        real = mmread.disk_free_gb
        mmread.disk_free_gb = lambda *a, **k: 35.0
        self.addCleanup(setattr, mmread, "disk_free_gb", real)

    def profile_with(self, disk_command):
        text = open(mmtest.PROFILE).read()
        if disk_command is not None:
            text = text.replace("[names]\n", "[names]\ndisk_command = %s\n" % json.dumps(disk_command), 1)
        p = os.path.join(self.root, "profile.toml")
        with open(p, "w") as f:
            f.write(text)
        os.environ["MM_PROFILE"] = p  # TempData restores it
        self.assertEqual(self.profile()["names"]["disk_command"], disk_command or "", "fixture: the profile holds it")

    def disk_low_command(self):
        self.sup().tick()
        recs = [r for r in self.pushed() if r.get("name") == "DISK_LOW"]
        self.assertEqual(len(recs), 1, recs)
        return recs[0].get("command")

    def test_profile_command_reaches_the_pushed_alert(self):
        self.profile_with(CMD)
        self.assertEqual(self.disk_low_command(), CMD)

    def test_profile_without_the_key_pushes_no_command(self):
        self.profile_with(None)
        self.assertIsNone(self.disk_low_command())


# ------------------------------------------------------------------------------------------- 3. slots.red_comp_mb

class RedCompressor(unittest.TestCase):
    def test_default_is_off(self):
        s = base_settings()
        self.assertEqual(s["slots.red_comp_mb"], 0)
        state, reasons, _ = mmdecide.classify(window(comp_mb=99999), s, disk_gb=100)
        self.assertEqual((state, reasons), ("AMBER", ["compressor 99999 MB"]))

    def test_default_keeps_a_steady_large_compressor_amber(self):
        """Review C1 (F4): base 8043d1d gives AMBER `compressor N MB` for a steady compressor over amber_comp_mb at any
        size (a Mac with 192-512 GB can hold more than 100000 MB); the defaults keep that, and nothing pauses."""
        s = base_settings()
        for comp in (99999, 100000, 100001, 120000, 250000):
            with self.subTest(comp_mb=comp):
                state, reasons, complete = mmdecide.classify(window(comp_mb=comp), s, disk_gb=100)
                self.assertEqual((state, reasons, complete), ("AMBER", ["compressor %d MB" % comp], True))
                self.assertFalse(mmsuper.critical(reasons))

    def test_zero_is_off_at_any_size(self):
        s = base_settings(**{"slots.red_comp_mb": 0})
        self.assertEqual(mmdecide.classify(window(comp_mb=250000), s, disk_gb=100)[:2],
                         ["AMBER", ["compressor 250000 MB"]])

    def test_the_top_of_the_range_is_a_real_ceiling(self):
        s = base_settings(**{"slots.red_comp_mb": 100000})
        self.assertEqual(mmdecide.classify(window(comp_mb=100000), s, disk_gb=100)[:2],
                         ["AMBER", ["compressor 100000 MB"]])
        self.assertEqual(mmdecide.classify(window(comp_mb=100001), s, disk_gb=100)[:2],
                         ["RED", ["compressor at 100001 MB (near its ceiling)"]])

    def test_over_the_value_is_red_with_its_reason(self):
        s = base_settings(**{"slots.red_comp_mb": 6000})
        self.assertEqual(mmdecide.classify(window(comp_mb=6000.4), s, disk_gb=100)[:2],
                         ["RED", ["compressor at 6000 MB (near its ceiling)"]])
        self.assertEqual(mmdecide.classify(window(comp_mb=7000), s, disk_gb=100)[:2],
                         ["RED", ["compressor at 7000 MB (near its ceiling)"]])

    def test_at_or_under_the_value_is_not_red(self):
        s = base_settings(**{"slots.red_comp_mb": 6000})
        for comp, want in ((6000, ("AMBER", ["compressor 6000 MB"])), (5000, ("GREEN", ["all readings in the green band"]))):
            with self.subTest(comp=comp):
                self.assertEqual(tuple(mmdecide.classify(window(comp_mb=comp), s, disk_gb=100)[:2]), want)

    def test_a_missing_compressor_reading_never_fires(self):
        s = base_settings(**{"slots.red_comp_mb": 1})
        self.assertNotEqual(mmdecide.classify(window(comp_mb=None), s, disk_gb=100)[0], "RED")

    def test_the_reason_is_critical(self):
        self.assertTrue(mmsuper.critical(["compressor at 7000 MB (near its ceiling)"]))
        self.assertTrue(mmsuper.critical(["free 30% < 35%", "compressor at 7000 MB (near its ceiling)"]))
        self.assertFalse(mmsuper.critical(["compressor 7000 MB"]))  # the AMBER reason is not critical
        self.assertFalse(mmsuper.critical(["free 30% < 35%"]))

    def test_range(self):
        for bad in (-1, 100001, "6000", True):
            self.assertTrue(mmcore.validate(dict(base_settings(), **{"slots.red_comp_mb": bad})), bad)
        for good in (0, 1, 6000, 100000):
            self.assertEqual(mmcore.validate(dict(base_settings(), **{"slots.red_comp_mb": good})), [], good)


# ------------------------------------------------------------------------------------------- 4. slots.green_disk_gb

class GreenDisk(unittest.TestCase):
    def test_zero_follows_recover_gb(self):
        s = base_settings()
        self.assertEqual((s["slots.green_disk_gb"], s["disk.recover_gb"]), (0, 45))
        self.assertEqual(mmdecide.classify(window(), s, disk_gb=44.9)[:2], ["STEADY", ["disk under 45 GB"]])
        self.assertEqual(mmdecide.classify(window(), s, disk_gb=45)[0], "GREEN")

    def test_own_value_replaces_recover_gb_for_green(self):
        s = base_settings(**{"slots.green_disk_gb": 30})
        self.assertEqual(mmdecide.classify(window(), s, disk_gb=44)[0], "GREEN")
        self.assertEqual(mmdecide.classify(window(), s, disk_gb=30)[0], "GREEN")
        self.assertEqual(mmdecide.classify(window(), s, disk_gb=29.9)[:2], ["STEADY", ["disk under 30 GB"]])
        self.assertEqual(mmdecide.classify(window(), s, disk_gb=19)[0], "RED")  # red_disk_gb 20 still holds

    def test_a_higher_value_holds_green_longer(self):
        s = base_settings(**{"slots.green_disk_gb": 80})
        self.assertEqual(mmdecide.classify(window(), s, disk_gb=79)[:2], ["STEADY", ["disk under 80 GB"]])
        self.assertEqual(mmdecide.classify(window(), s, disk_gb=80)[0], "GREEN")

    def test_no_disk_reading_does_not_block_green(self):
        self.assertEqual(mmdecide.classify(window(), base_settings(**{"slots.green_disk_gb": 80}))[0], "GREEN")

    def test_range_and_pair(self):
        for bad in (-1, 10001, "30"):
            self.assertTrue(mmcore.validate(dict(base_settings(), **{"slots.green_disk_gb": bad})), bad)
        self.assertEqual(mmcore.validate(dict(base_settings(), **{"slots.green_disk_gb": 0})), [])
        self.assertEqual(mmcore.validate(dict(base_settings(), **{"slots.green_disk_gb": 20})), [])  # = red_disk_gb
        self.assertEqual(mmcore.validate(dict(base_settings(), **{"slots.green_disk_gb": 10000})), [])
        self.assertEqual(mmcore.validate(dict(base_settings(), **{"slots.green_disk_gb": 19.9})),
                         ["slots.green_disk_gb must be 0 or >= slots.red_disk_gb"])
        self.assertEqual(mmcore.validate(dict(base_settings(), **{"slots.green_disk_gb": 5, "slots.red_disk_gb": 0})), [])


class GreenDiskSupervisor(Base):
    """The setting reaches the supervisor's state through the data folder's settings.toml."""

    def setUp(self):
        super().setUp()
        real = mmread.disk_free_gb
        mmread.disk_free_gb = lambda *a, **k: 40.0  # under disk.recover_gb 45; not under disk.low_gb 40 (no DISK_LOW)
        self.addCleanup(setattr, mmread, "disk_free_gb", real)

    def state_after_tick(self):
        sup = self.sup(sampler_of(load1=2, load5=2))
        sup.tick()
        return json.load(open(os.path.join(self.data, "status.json")))

    def test_default_keeps_steady_under_recover_gb(self):
        st = self.state_after_tick()
        self.assertEqual((st["state"], st["reasons"]), ("STEADY", ["disk under 45 GB"]))

    def test_own_value_gives_green(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "slots.green_disk_gb": 30})
        self.assertEqual(self.state_after_tick()["state"], "GREEN")

    def test_a_bad_pair_is_settings_bad_and_keeps_the_last_good_values(self):
        self.assertEqual(self.state_after_tick()["state"], "STEADY")  # last good: the defaults
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "slots.green_disk_gb": 10})
        sup = self.sup(sampler_of(load1=2, load5=2))
        sup.tick()
        st = json.load(open(os.path.join(self.data, "status.json")))
        self.assertEqual(st["state"], "STEADY", "the bad value is not used")
        bad = [r for r in self.pushed() if r.get("name") == "SETTINGS_BAD"]
        self.assertTrue(bad and "slots.green_disk_gb" in bad[-1]["text"], bad)


# ------------------------------------------------------------------------------------------- defaults change nothing

class DefaultsChangeNothing(unittest.TestCase):
    def test_new_defaults(self):
        d = mmcore.defaults()
        self.assertEqual((d["slots.red_comp_mb"], d["slots.green_disk_gb"], d["pause_newest_call.max_minutes"]),
                         (0, 0, 0))
        self.assertEqual(mmcore.validate(d), [])

    def test_classify_is_the_same_without_the_new_keys(self):
        """Last good settings saved by an older table (without the new keys) are restored over the defaults, so they
        give the same state and reasons as the defaults."""
        new = base_settings()
        old = mmtest.restored_without("slots.red_comp_mb", "slots.green_disk_gb")
        self.assertEqual(old, new)
        cases = [window(), window(comp_mb=9000), window(free_pct=30), window(pressure=4), window(free_pct=52)]
        for w in cases:
            for disk in (None, 15, 41, 44.9, 45, 100):
                self.assertEqual(mmdecide.classify(w, new, disk_gb=disk), mmdecide.classify(w, old, disk_gb=disk))


del Base  # imported for its helpers only; its tests run in their own module


if __name__ == "__main__":
    unittest.main()
