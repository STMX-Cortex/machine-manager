# SPDX-License-Identifier: Apache-2.0
"""IDLE_WITH_WORK and READY_WORK_STALE: free slots while ready work waits, and the ready-work files behind it.

Written from the feature's contract, through the supervisor's own tick (a fake clock, a calm sampler, a fixed queue
read and a fixed `would`), `mm status --json` and `mm explain`. Owners are fake names (alpha, beta, gamma)."""
import datetime
import json
import os
import re
import shutil
import time
import unittest
from unittest import mock

import mmtest
from mmtest import TempData, mmcore, mmread
import mmdecide
import mmready
import mmschema
import mmsuper

NOW = mmtest.at("2026-11-06 10:00")
MIN = 60.0


def calm(now, ticks):
    return {"t": now, "free_pct": 80, "swap_used_mb": 100, "swap_total_mb": 2048, "comp_mb": 300, "pressure": 1,
            "seg_pct": 1, "load1": 1, "load5": 1, "sys_pct": None, "sys_pct_fixture": 10}, ticks


def iso(t, kind="aware"):
    """`t` (epoch) as ISO-8601: aware local time, naive local time, or UTC."""
    if kind == "naive":
        return datetime.datetime.fromtimestamp(t).isoformat()
    if kind == "utc":
        return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat()
    return datetime.datetime.fromtimestamp(t).astimezone().isoformat()


class Base(TempData):
    """A data folder, the test profile with ready_work_dir, a fixed queue read (slots, busy) and a fixed `would`."""
    ready_value = "ready"  # ready_work_dir in the profile: a name under the test root; None leaves the key out

    def setUp(self):
        super().setUp()
        self.queue_dir(slots=5)
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "banner.enabled": False})
        self.ready = os.path.join(self.root, "ready")
        os.makedirs(self.ready)
        self.set_profile(None if self.ready_value is None else os.path.join(self.root, self.ready_value))
        self.t = NOW
        self.would, self.busy = 5, 2
        p = mock.patch.object(mmread, "disk_free_gb", lambda *a: 500.0)
        p.start()
        self.addCleanup(p.stop)
        self.sup = None

    # ---- the profile and the ready-work files
    def set_profile(self, value, extra=""):
        with open(mmtest.PROFILE) as f:
            text = f.read()
        head = 'machine_id = "test-machine"\n'
        self.assertIn(head, text)
        if value is not None:
            text = text.replace(head, head + "ready_work_dir = %s\n" % json.dumps(value), 1)
        if extra:
            text = text.replace(head, head + extra, 1)
        p = os.path.join(self.root, "profile.toml")
        with open(p, "w") as f:
            f.write(text)
        os.environ["MM_PROFILE"] = p

    def put(self, name, doc=None, raw=None, **over):
        """<ready>/<name>.json: a good document (owner = name, updated = now, 10 units) with `over` on top."""
        if raw is None:
            d = {"owner": name, "updated": iso(self.t), "ready_units": 10, "next": "next step of " + name}
            d.update(over)
            d = {k: v for k, v in d.items() if v is not DROP}
            raw = json.dumps(doc if doc is not None else d)
        p = os.path.join(self.ready, name + ".json")
        with open(p, "w") as f:
            f.write(raw)
        return p

    # ---- the supervisor
    def queue_read(self, now):
        return {"slots": 5, "tickets": [],
                "busy": [{"slot": ".slot.%d" % (i + 1), "pid": None, "mode": "S", "since": now, "label": "job"}
                         for i in range(self.busy)]}

    def start(self, **kw):
        sup = mmsuper.Supervisor(self.profile(), kernel=False, clock=lambda: self.t, sampler=calm, sizes=False,
                                 slow_jobs=False, check_readings=False, **kw)
        sup.queue.read = self.queue_read

        def control(now, s, *a, **k):  # `would`: the admitted slots now, as status.json prints it (slots_would)
            sup.state["virtual_slots"] = self.would
        sup._control = control
        self.sup = sup
        return sup

    def tick(self, n=1, step=MIN):
        """n ticks, `step` seconds apart; the clock stands on the last tick's time."""
        if self.sup is None:
            self.start()
        for i in range(n):
            self.sup.tick()
            if i < n - 1:
                self.t += step

    def advance(self, seconds, step=MIN):
        """Tick every `step` seconds until `seconds` have passed (a tick at the end)."""
        end = self.t + seconds
        while self.t + step <= end + 1e-6:
            self.t += step
            self.sup.tick()

    def active(self, name=None):
        act = (mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {}) or {}).get("active") or {}
        return {k: a for k, a in act.items() if name is None or a.get("name") == name}

    def idle(self):
        got = self.active("IDLE_WITH_WORK")
        self.assertLessEqual(len(got), 1, got)
        return next(iter(got.values()), None)

    def stale(self):
        return self.active("READY_WORK_STALE")

    def status(self):
        return mmcore.read_json(os.path.join(self.data, "status.json"), {})


DROP = object()


# ------------------------------------------------------------------------------------------ settings and profile

class Settings(unittest.TestCase):
    def test_defaults_and_ranges(self):
        d = mmcore.defaults()
        self.assertEqual((d["ready_work.idle_minutes"], d["ready_work.stale_minutes"]), (15, 90))
        base = mmtest.base_settings()
        for key, good, bad in (("ready_work.idle_minutes", (5, 15, 120), (4, 121, 0, -1, "15", True)),
                               ("ready_work.stale_minutes", (15, 90, 720), (14, 721, 0, "90", True))):
            for v in good:
                self.assertEqual(mmcore.validate(dict(base, **{key: v})), [], (key, v))
            for v in bad:
                self.assertTrue(mmcore.validate(dict(base, **{key: v})), (key, v))

    def test_settings_schema_file_lists_both(self):
        props = mmschema.load("settings")["properties"]
        self.assertEqual((props["ready_work.idle_minutes"].get("minimum"), props["ready_work.idle_minutes"].get("maximum")),
                         (5, 120))
        self.assertEqual((props["ready_work.stale_minutes"].get("minimum"),
                          props["ready_work.stale_minutes"].get("maximum")), (15, 720))


class SettingsFile(Base):
    def test_out_of_range_takes_the_settings_error_path(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "banner.enabled": False,
                               "ready_work.idle_minutes": 4})
        st = mmcore.Settings()
        st.load(save=False)
        self.assertTrue(st.problem and "ready_work.idle_minutes" in st.problem, st.problem)
        self.tick()
        self.assertIn("SETTINGS_BAD", self.active())

    def test_settings_show(self):
        r = self.mm("settings", "show", "ready_work")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ready_work.idle_minutes", r.stdout)
        self.assertIn("ready_work.stale_minutes", r.stdout)

    def test_profile_schema_takes_the_key(self):
        prof = self.profile()
        self.assertEqual(prof.get("ready_work_dir"), self.ready)
        doc = {k: v for k, v in prof.items() if not k.startswith("_")}
        self.assertEqual(mmschema.validate(doc, mmschema.load("profile")), [])
        self.assertTrue(mmschema.validate(dict(doc, ready_work_dir=5), mmschema.load("profile")))


# ------------------------------------------------------------------------------------------------ off / not a folder

class OffWhenAbsent(Base):
    ready_value = None

    def test_no_key_no_alerts_no_status_part(self):
        self.put("alpha", ready_units=50)
        self.tick(20)
        self.assertEqual((self.idle(), self.stale()), (None, {}))
        self.assertNotIn("ready_work", self.status())
        self.assertEqual(self.status().get("state"), "GREEN")


class OffWhenEmpty(Base):
    def setUp(self):
        super().setUp()
        self.set_profile("")

    def test_empty_value_is_off(self):
        self.put("alpha", ready_units=50)
        self.tick(20)
        self.assertEqual((self.idle(), self.stale()), (None, {}))
        self.assertNotIn("ready_work", self.status())


class OffWhenMissingFolder(Base):
    ready_value = "no-such-folder"

    def test_missing_folder_is_off_and_no_error(self):
        self.tick(20)
        self.assertEqual((self.idle(), self.stale()), (None, {}))
        self.assertNotIn("ready_work", self.status())
        errs = os.path.join(self.data, "state", "errors.log")
        self.assertFalse(os.path.exists(errs) and "ready" in open(errs).read().lower())


class NotAFolder(Base):
    ready_value = "a-file"

    def test_a_file_gives_one_attention_alert(self):
        with open(os.path.join(self.root, "a-file"), "w") as f:
            f.write("{}")
        self.tick(20)
        got = self.stale()
        self.assertEqual(len(got), 1, got)
        a = next(iter(got.values()))
        self.assertEqual(a["level"], "ATTENTION")
        self.assertIn("ready_work_dir is not a folder", a["text"])
        self.assertIsNone(self.idle())


class TildeExpansion(Base):
    def test_tilde_and_placeholders_expand(self):
        home_ready = os.path.join(os.environ["HOME"], "rw")
        os.makedirs(home_ready)
        self.ready = home_ready
        self.set_profile("~/rw")
        self.assertEqual(mmcore.expand(self.profile()["ready_work_dir"]), home_ready)
        self.put("alpha", ready_units=7)
        self.tick()
        rw = self.status().get("ready_work")
        self.assertIsNotNone(rw, "a ~ path names the folder under HOME")
        self.assertEqual(rw["ready"], 7)


# ------------------------------------------------------------------------------------------------ good and stale files

class GoodFiles(Base):
    def test_status_part_and_no_stale_alert(self):
        self.put("alpha", ready_units=120)
        self.put("beta", ready_units=20)
        self.tick()
        rw = self.status().get("ready_work")
        self.assertEqual((rw["free"], rw["ready"]), (3, 140))
        owners = {o["owner"]: o for o in rw["owners"]}
        self.assertEqual({k: owners[k]["units"] for k in owners}, {"alpha": 120, "beta": 20})
        for o in rw["owners"]:
            self.assertLessEqual({"owner", "units", "age_min", "state"}, set(o))
            self.assertEqual(o["state"], "ok")
            self.assertIsInstance(o["age_min"], (int, float))
            self.assertLess(o["age_min"], 1)
        self.assertEqual(self.stale(), {})
        self.assertEqual(mmschema.validate(self.status(), mmschema.load("status")), [])

    def test_mm_status_json_shows_ready_work(self):
        self.put("alpha", ready_units=120)
        self.put("beta", ready_units=20)
        self.tick()
        r = self.mm("status", "--json")
        self.assertIn(r.returncode, (0, 3), r.stdout + r.stderr)  # 3: the fixed clock is far from real time
        obj = json.loads(r.stdout)
        self.assertEqual((obj["ready_work"]["free"], obj["ready_work"]["ready"]), (3, 140))
        self.assertEqual(sorted(o["owner"] for o in obj["ready_work"]["owners"]), ["alpha", "beta"])

    def test_owner_missing_or_not_a_string_uses_the_file_stem(self):
        self.put("alpha", owner=DROP, ready_units=3)
        self.put("beta", owner=17, ready_units=4)
        self.put("gamma", owner="delta", ready_units=5)
        self.tick()
        units = {o["owner"]: o["units"] for o in self.status()["ready_work"]["owners"]}
        self.assertEqual(units, {"alpha": 3, "beta": 4, "delta": 5})
        self.assertEqual(self.stale(), {})

    def test_zero_units_is_good(self):
        self.put("alpha", ready_units=0)
        self.tick()
        self.assertEqual(self.stale(), {})
        self.assertEqual(self.status()["ready_work"]["ready"], 0)

    def test_naive_time_is_local_and_utc_is_understood(self):
        self.put("alpha", updated=iso(self.t - 10 * MIN, "naive"))
        self.put("beta", updated=iso(self.t - 20 * MIN, "utc"))
        self.tick()
        ages = {o["owner"]: o["age_min"] for o in self.status()["ready_work"]["owners"]}
        self.assertAlmostEqual(ages["alpha"], 10, delta=1)
        self.assertAlmostEqual(ages["beta"], 20, delta=1)
        self.assertEqual(self.stale(), {})

    def test_up_to_five_minutes_ahead_is_good(self):
        self.put("alpha", updated=iso(self.t + 4 * MIN))
        self.tick()
        self.assertEqual(self.stale(), {})
        self.assertEqual(self.status()["ready_work"]["ready"], 10)

    def test_only_direct_json_children_count(self):
        self.put("alpha", ready_units=5)
        with open(os.path.join(self.ready, "notes.txt"), "w") as f:
            f.write(json.dumps({"owner": "x", "updated": iso(self.t), "ready_units": 99, "next": "n"}))
        os.makedirs(os.path.join(self.ready, "sub"))
        with open(os.path.join(self.ready, "sub", "beta.json"), "w") as f:
            f.write(json.dumps({"owner": "beta", "updated": iso(self.t), "ready_units": 99, "next": "n"}))
        os.makedirs(os.path.join(self.ready, ".hidden"))
        self.tick()
        rw = self.status()["ready_work"]
        self.assertEqual(rw["ready"], 5)
        self.assertEqual([o["owner"] for o in rw["owners"]], ["alpha"])
        self.assertEqual(self.stale(), {}, "names that are not *.json are ignored, not bad")

    def test_folder_link_and_fifo_named_json_are_bad(self):
        """Decision (review): ready files follow no link; a link, FIFO, folder or other non-regular file is bad."""
        self.put("alpha", ready_units=5)
        os.makedirs(os.path.join(self.ready, "folder.json"))
        outside = os.path.join(self.root, "outside.json")
        with open(outside, "w") as f:
            f.write(json.dumps({"owner": "gamma", "updated": iso(self.t), "ready_units": 99, "next": "n"}))
        os.symlink(outside, os.path.join(self.ready, "gamma.json"))          # a link out of the folder
        os.symlink(os.path.join(self.ready, "alpha.json"), os.path.join(self.ready, "inside.json"))  # in it
        os.symlink("alpha.json", os.path.join(self.ready, "relative.json"))  # a relative link in it
        os.mkfifo(os.path.join(self.ready, "pipe.json"))
        import signal
        def hang(*_):
            raise AssertionError("the tick blocked on a FIFO")
        old = signal.signal(signal.SIGALRM, hang)
        signal.alarm(30)
        try:
            self.tick()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        rw = self.status()["ready_work"]
        self.assertEqual(rw["ready"], 5, "no link is followed: alpha is counted once, the outside file never")
        states = {o["file"]: (o["state"], o["units"]) for o in rw["owners"]}
        for n in ("folder.json", "gamma.json", "inside.json", "relative.json", "pipe.json"):
            self.assertEqual(states.get(n), ("bad", 0), (n, states))
        self.assertEqual(states["alpha.json"], ("ok", 5))
        texts = " ".join(a["text"] for a in self.stale().values())
        self.assertEqual(len(self.stale()), 5, self.stale())
        for n in ("folder.json", "gamma.json", "inside.json", "relative.json", "pipe.json"):
            self.assertIn(n, texts)

    def test_a_parent_swapped_for_a_link_is_never_read(self):
        """The folder is opened once (a pinned fd); swapping its path for a link right after that is never followed."""
        self.put("alpha", ready_units=5)
        evil = os.path.join(self.root, "evil")
        os.makedirs(evil)
        with open(os.path.join(evil, "alpha.json"), "w") as f:
            f.write(json.dumps({"owner": "alpha", "updated": iso(self.t), "ready_units": 99, "next": "n"}))
        real_open, swapped = os.open, []

        def opener(path, flags, *a, **k):
            fd = real_open(path, flags, *a, **k)
            if not swapped and isinstance(path, str) and os.path.realpath(path) == os.path.realpath(self.ready):
                os.rename(self.ready, self.ready + "-orig")
                os.symlink(evil, self.ready)
                swapped.append(path)
            return fd
        self.start()
        with mock.patch.object(os, "open", opener):
            self.sup.tick()
        self.assertTrue(swapped, "the folder is opened through os.open (a pinned folder fd)")
        rw = self.status()["ready_work"]
        self.assertEqual(rw["ready"], 5, "the pinned folder is read, not the link's target")

    def test_exactly_64_kib_is_good(self):
        doc = json.dumps({"owner": "alpha", "updated": iso(self.t), "ready_units": 6, "next": "n"})
        self.put("alpha", raw=doc + " " * (65536 - len(doc)))
        self.assertEqual(os.path.getsize(os.path.join(self.ready, "alpha.json")), 65536)
        self.tick()
        self.assertEqual(self.stale(), {})
        self.assertEqual(self.status()["ready_work"]["ready"], 6)


class StaleFiles(Base):
    def test_stale_file_alerts_and_its_units_count(self):
        self.put("alpha", ready_units=30, updated=iso(self.t - 100 * MIN))
        self.put("beta", ready_units=5)
        self.tick()
        got = self.stale()
        self.assertEqual(len(got), 1, got)
        a = next(iter(got.values()))
        self.assertEqual(a["level"], "ATTENTION")
        self.assertIn("alpha ready-work file is 100 min old (limit 90)", a["text"])
        self.assertEqual(self.status()["ready_work"]["ready"], 35)

    def test_at_the_limit_is_not_stale(self):
        self.put("alpha", updated=iso(self.t - 90 * MIN))
        self.tick()
        self.assertEqual(self.stale(), {})

    def test_the_limit_follows_the_setting(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "banner.enabled": False,
                               "ready_work.stale_minutes": 30})
        self.put("alpha", updated=iso(self.t - 31 * MIN))
        self.tick()
        texts = [a["text"] for a in self.stale().values()]
        self.assertEqual(len(texts), 1, texts)
        self.assertIn("(limit 30)", texts[0])

    def test_owners_clear_independently(self):
        self.put("alpha", updated=iso(self.t - 100 * MIN))
        self.put("beta", updated=iso(self.t - 120 * MIN))
        self.tick()
        got = self.stale()
        self.assertEqual(len(got), 2, got)
        self.assertEqual(len(set(got)), 2, "one key per owner")
        self.assertTrue(any("alpha" in k for k in got) and any("beta" in k for k in got), got)
        self.t += MIN
        self.put("alpha")  # fresh again
        self.tick()
        got = self.stale()
        self.assertEqual(len(got), 1, got)
        self.assertIn("beta", next(iter(got.values()))["text"])

    def test_a_stale_file_ages_while_time_passes(self):
        self.put("alpha", updated=iso(self.t - 80 * MIN))
        self.tick()
        self.assertEqual(self.stale(), {})
        self.advance(11 * MIN)
        texts = [a["text"] for a in self.stale().values()]
        self.assertEqual(len(texts), 1, texts)
        self.assertIn("91 min old", texts[0])

    def test_explain(self):
        self.put("alpha", updated=iso(self.t - 100 * MIN))
        self.tick()
        r = self.mm("explain", "READY_WORK_STALE")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("level=ATTENTION", r.stdout)
        self.assertIn("alpha ready-work file is 100 min old", r.stdout)


class BadFiles(Base):
    """Each bad kind: one ATTENTION READY_WORK_STALE for that owner (text names the file), units counted as 0."""
    KINDS = {
        "not_json": dict(raw="{not json"),
        "empty": dict(raw=""),
        "array": dict(raw="[1, 2]"),
        "units_missing": dict(ready_units=DROP),
        "units_bool": dict(ready_units=True),
        "units_float": dict(ready_units=5.0),
        "units_string": dict(ready_units="5"),
        "units_negative": dict(ready_units=-1),
        "units_null": dict(ready_units=None),
        "updated_missing": dict(updated=DROP),
        "updated_not_a_time": dict(updated="yesterday"),
        "updated_number": dict(updated=1762419600),
        "next_not_a_string": dict(next=5),
        "far_future": "future",
        "nan_units": dict(raw='{"owner": "x", "updated": "%s", "ready_units": NaN, "next": "n"}'),
        "duplicate_keys": dict(raw='{"owner": "x", "updated": "%s", "ready_units": 5, "ready_units": 7, "next": "n"}'),
        "too_big": "big",
    }

    def write_kind(self, kind):
        spec = self.KINDS[kind]
        name = "bad_" + kind
        if spec == "future":
            return self.put(name, updated=iso(self.t + 7 * MIN))  # 6 min ahead at the tick below
        if spec == "big":
            doc = json.dumps({"owner": name, "updated": iso(self.t), "ready_units": 5, "next": "n"})
            return self.put(name, raw=doc + " " * (65537 - len(doc)))
        spec = dict(spec)
        if "raw" in spec and "%s" in spec["raw"]:
            spec["raw"] = spec["raw"].replace('"x"', json.dumps(name)) % iso(self.t)
        return self.put(name, **spec)

    def test_each_bad_kind(self):
        for kind in self.KINDS:
            with self.subTest(kind=kind):
                for n in os.listdir(self.ready):
                    os.unlink(os.path.join(self.ready, n))
                self.put("alpha", ready_units=4)
                path = self.write_kind(kind)
                self.t += MIN
                self.tick()
                got = self.stale()
                self.assertEqual(len(got), 1, (kind, got))
                a = next(iter(got.values()))
                self.assertEqual(a["level"], "ATTENTION")
                self.assertIn(os.path.basename(path), a["text"], "the text names the file")
                self.assertNotIn("alpha", "".join(got), "the good owner has no alert")
                rw = self.status()["ready_work"]
                self.assertEqual(rw["ready"], 4, "a bad file's units count as 0")

    def test_bad_text_names_a_reason(self):
        self.put("beta", ready_units=-3)
        self.tick()
        a = next(iter(self.stale().values()))
        base = "beta.json"
        self.assertIn(base, a["text"])
        self.assertGreater(len(a["text"].replace(base, "").strip(" :")), 5, "a reason follows the file name")

    def test_unreadable_file(self):
        if os.geteuid() == 0:
            self.skipTest("root reads a mode-000 file")
        p = self.put("beta", ready_units=9)
        os.chmod(p, 0)
        self.addCleanup(lambda: os.path.lexists(p) and os.chmod(p, 0o600))
        self.put("alpha", ready_units=4)
        self.tick()
        got = self.stale()
        self.assertEqual(len(got), 1, got)
        self.assertIn("beta.json", next(iter(got.values()))["text"])
        self.assertEqual(self.status()["ready_work"]["ready"], 4)

    def test_bad_file_clears_when_repaired(self):
        self.put("beta", raw="{")
        self.tick()
        self.assertEqual(len(self.stale()), 1)
        self.t += MIN
        self.put("beta", ready_units=2)
        self.tick()
        self.assertEqual(self.stale(), {})

    def test_bad_files_do_not_raise_idle_alone(self):
        self.put("beta", ready_units=-5)
        self.put("gamma", raw="nope")
        self.tick()
        self.advance(20 * MIN)
        self.assertIsNone(self.idle(), "bad files count 0 units: no ready work")


# ------------------------------------------------------------------------------------------------ the idle rule

IDLE_TEXT = re.compile(r"^(\d+) free slots? while (\d+) ready units? wait for (\d+) min: (.*)$")


class IdleRule(Base):
    def setUp(self):
        super().setUp()
        self.put("alpha", ready_units=120, next="build the alpha parts")
        self.put("beta", ready_units=20, next="build the beta parts")
        self.put("gamma", ready_units=0)

    def keep_fresh(self):
        for n in ("alpha", "beta"):
            self.put(n, ready_units=120 if n == "alpha" else 20, next="build the %s parts" % n)

    def test_raised_after_more_than_idle_minutes(self):
        self.tick()
        t0 = self.t
        self.assertIsNone(self.idle())
        self.advance(15 * MIN)
        self.assertEqual(self.t - t0, 15 * MIN)
        self.assertIsNone(self.idle(), "exactly idle_minutes is not more than idle_minutes")
        self.advance(MIN)
        a = self.idle()
        self.assertIsNotNone(a)
        self.assertEqual(a["level"], "ACTION")
        m = IDLE_TEXT.match(a["text"])
        self.assertTrue(m, a["text"])
        self.assertEqual((m.group(1), m.group(2), m.group(3)), ("3", "140", "16"))
        self.assertTrue(m.group(4).startswith("alpha 120, beta 20"), m.group(4))
        self.assertNotIn("gamma", a["text"], "owners with 0 units are not named")
        self.assertRegex(a["text"], r'\(next: "?build the alpha parts"?\)$')
        self.assertNotIn("build the beta parts", a["text"])

    def test_owner_order_is_by_units(self):
        self.put("alpha", ready_units=3, next="a")
        self.put("beta", ready_units=50, next="b")
        self.tick()
        self.advance(16 * MIN)
        a = self.idle()
        self.assertIsNotNone(a)
        self.assertIn("beta 50, alpha 3", a["text"])
        self.assertRegex(a["text"], r'\(next: "?b"?\)$')

    def test_next_text_is_at_most_120_characters(self):
        self.put("alpha", ready_units=120, next="x" * 300)
        self.tick()
        self.advance(16 * MIN)
        a = self.idle()
        m = re.search(r"\(next: (.*)\)$", a["text"])
        self.assertTrue(m, a["text"])
        self.assertLessEqual(len(m.group(1).strip('"')), 120)
        self.assertTrue(m.group(1).startswith("xxxxx"))

    def test_idle_minutes_follows_the_setting(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "banner.enabled": False,
                               "ready_work.idle_minutes": 5})
        self.tick()
        self.advance(5 * MIN)
        self.assertIsNone(self.idle())
        self.advance(MIN)
        self.assertIsNotNone(self.idle())

    def test_the_start_time_holds_across_a_restart(self):
        self.tick()
        self.advance(10 * MIN)
        self.assertIsNone(self.idle())
        self.sup = None  # a new supervisor on the same data folder: the start time is not reset
        self.t += MIN
        self.tick()
        self.advance(4 * MIN)
        self.assertIsNone(self.idle(), "15 min since the start")
        self.advance(MIN)
        self.assertIsNotNone(self.idle(), "16 min since the start, 5 min after the restart")

    def test_restart_while_raised_keeps_the_minutes(self):
        self.tick()
        self.advance(20 * MIN)
        self.assertIsNotNone(self.idle())
        self.sup = None
        self.t += MIN
        self.tick()
        a = self.idle()
        self.assertIsNotNone(a, "a restart does not clear it")
        self.assertEqual(IDLE_TEXT.match(a["text"]).group(3), "21")

    def test_a_break_restarts_the_timer(self):
        self.tick()
        self.advance(10 * MIN)
        self.would = self.busy  # free == 0 for one tick
        self.advance(MIN)
        self.would = 5
        self.advance(MIN)
        t1 = self.t
        self.advance(15 * MIN)
        self.assertIsNone(self.idle(), "the timer starts again at %s" % t1)
        self.advance(MIN)
        self.assertIsNotNone(self.idle())

    def test_clears_when_free_is_zero(self):
        self.tick()
        self.advance(16 * MIN)
        self.assertIsNotNone(self.idle())
        self.would = self.busy
        self.advance(MIN)
        self.assertIsNone(self.idle())
        pushed = [r for r in self.pushed() if r.get("name") == "IDLE_WITH_WORK"]
        self.assertEqual(pushed[-1].get("why"), "cleared", pushed)

    def test_clears_when_ready_is_zero(self):
        self.tick()
        self.advance(16 * MIN)
        self.assertIsNotNone(self.idle())
        self.put("alpha", ready_units=0)
        self.put("beta", ready_units=0)
        self.advance(MIN)
        self.assertIsNone(self.idle())

    def test_clears_when_files_go_bad(self):
        self.tick()
        self.advance(16 * MIN)
        self.assertIsNotNone(self.idle())
        self.put("alpha", raw="{")
        self.put("beta", ready_units=-1)
        self.advance(MIN)
        self.assertIsNone(self.idle(), "bad files count 0 units")

    def test_free_zero_never_raises(self):
        self.would = self.busy = 5
        self.tick()
        self.advance(30 * MIN)
        self.assertIsNone(self.idle())
        self.assertEqual(self.status()["ready_work"]["free"], 0)

    def test_ready_zero_never_raises(self):
        self.put("alpha", ready_units=0)
        self.put("beta", ready_units=0)
        self.tick()
        self.advance(30 * MIN)
        self.assertIsNone(self.idle())
        self.assertEqual(self.status()["ready_work"]["ready"], 0)

    def test_busy_over_would_is_zero_free(self):
        self.would, self.busy = 3, 5
        self.tick()
        self.assertEqual(self.status()["ready_work"]["free"], 0, "free = max(0, would - busy)")
        self.advance(30 * MIN)
        self.assertIsNone(self.idle())

    def test_free_uses_would_not_the_slot_file(self):
        self.would, self.busy = 4, 1  # the queue's slot file says 5
        self.tick()
        self.assertEqual(self.status()["ready_work"]["free"], 3)
        self.advance(16 * MIN)
        self.assertTrue(self.idle()["text"].startswith("3 free slot"), self.idle()["text"])

    def test_one_free_slot(self):
        self.would, self.busy = 3, 2
        self.tick()
        self.advance(16 * MIN)
        self.assertTrue(self.idle()["text"].startswith("1 free slot"), self.idle()["text"])

    def test_stale_files_still_count_for_idle(self):
        self.put("alpha", ready_units=120, updated=iso(self.t - 200 * MIN))
        self.tick()
        self.advance(16 * MIN)
        a = self.idle()
        self.assertIsNotNone(a)
        self.assertIn("alpha 120", a["text"])
        self.assertTrue(any("alpha" in s["text"] for s in self.stale().values()))

    def test_explain_and_status_json(self):
        self.tick()
        self.advance(16 * MIN)
        r = self.mm("explain", "IDLE_WITH_WORK")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("level=ACTION", r.stdout)
        self.assertIn("3 free slots while 140 ready units", r.stdout)
        r = self.mm("status", "--json")
        obj = json.loads(r.stdout)
        rw = obj["ready_work"]
        self.assertEqual((rw["free"], rw["ready"]), (3, 140))
        self.assertEqual(mmschema.validate(self.status(), mmschema.load("status")), [])

    def test_raised_in_off_observe_and_dry_run(self):
        for mode in ("off", "observe", "dry", "safe"):
            with self.subTest(mode=mode):
                off = os.path.join(self.data, "off.json")
                for f in ("off.json", "safe.json", "alerts-state.json", "state/controller.json",
                          "state/" + mmready.STATE_NAME):
                    p = os.path.join(self.data, f)
                    if os.path.exists(p):
                        os.unlink(p)
                over = {"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "banner.enabled": False,
                        "mode.observe": mode == "observe"}
                self.write_settings(**over)
                if mode == "off":
                    mmcore.write_atomic(off, json.dumps({"off": True, "since": "x", "reason": "test"}))
                if mode == "safe":
                    import mmrecover
                    mmrecover.enter_safe("test", self.t)
                self.t += 3600
                self.keep_fresh()
                self.start(dry_run=(mode == "dry"))
                self.tick()
                self.advance(16 * MIN)
                self.assertIsNotNone(self.idle(), mode)
                if mode == "safe":
                    self.assertEqual(self.status().get("mode"), "safe")

    def test_no_automatic_action(self):
        slots = os.path.join(self.data, "queue", "slots")
        before = open(slots).read()
        calls = {"kill": [], "pause": [], "resume": [], "deletes": [], "trim": [], "control": []}
        self.start()
        control = self.sup._control

        def rec_control(*a, **k):
            calls["control"].append(a[0])
            return control(*a, **k)
        self.sup._control = rec_control
        self.sup.deletes.kick = lambda *a, **k: calls["deletes"].append(a)
        rec = lambda name: (lambda *a, **k: calls[name].append(a))
        with mock.patch.object(os, "kill", rec("kill")), mock.patch.object(os, "killpg", rec("kill")), \
                mock.patch.object(mmsuper.Pauser, "pause", rec("pause")), \
                mock.patch.object(mmsuper.Pauser, "resume", rec("resume")), \
                mock.patch.object(mmsuper.Trim, "_start", rec("trim")):
            self.tick()
            self.advance(20 * MIN)
        self.assertIsNotNone(self.idle())
        ticks = len(calls.pop("control"))
        self.assertEqual(ticks, 21, "the slot controller runs once a tick, as always")
        self.assertEqual(self.sup.state.get("virtual_slots"), self.would, "would is not raised for ready work")
        self.assertEqual(calls, {k: [] for k in calls}, "no pause, kill, resume, delete or trim")
        self.assertEqual(open(slots).read(), before)
        log = os.path.join(self.data, "state", "decisions.log")
        text = open(log).read() if os.path.exists(log) else ""
        self.assertNotIn("IDLE_WITH_WORK", text)
        self.assertNotIn("ready", text.lower())


# ------------------------------------------------------------------------------------------------ the timer record

class TimerRecord(Base):
    def setUp(self):
        super().setUp()
        self.put("alpha", ready_units=8)
        self.record = os.path.join(self.data, "state", mmready.STATE_NAME)

    def test_the_record_holds_the_start(self):
        self.tick()
        t0 = self.t
        self.assertEqual(mmready.load_since(), (t0, None))
        self.would = self.busy
        self.advance(MIN)
        self.assertEqual(mmready.load_since(), (None, None), "free == 0: no start")

    def test_an_unreadable_record_is_not_no_record(self):
        with open(self.record, "w") as f:
            f.write("{broken")
        since, err = mmready.load_since()
        self.assertIsNone(since)
        self.assertTrue(err)
        self.tick()
        got = self.stale()
        self.assertEqual(list(got), ["READY_STALE:_state"], got)
        self.assertIn("cannot be read", got["READY_STALE:_state"]["text"])
        self.advance(16 * MIN)
        self.assertIsNotNone(self.idle(), "the timer runs in memory from this start")
        with open(self.record) as f:
            self.assertEqual(f.read(), "{broken", "the bad record is kept, not overwritten")
        os.unlink(self.record)
        self.advance(MIN)
        self.assertEqual(self.stale(), {}, "the error clears once the record is gone")

    def test_damaged_after_start_is_kept_and_alerts(self):
        self.tick()
        self.advance(5 * MIN)
        with open(self.record, "w") as f:
            f.write("{broken")
        self.would = self.busy  # since changes (to null): the supervisor wants to write the record
        self.advance(MIN)
        self.would = 5
        self.advance(MIN)
        with open(self.record) as f:
            self.assertEqual(f.read(), "{broken", "the damaged record is kept unchanged")
        self.assertIn("READY_STALE:_state", self.stale())

    def test_a_failed_timer_write_does_not_stop_the_tick(self):
        real = mmcore.write_atomic

        def failing(target, *a, **k):
            if os.path.basename(target) == mmready.STATE_NAME:
                raise OSError(28, "No space left on device")
            return real(target, *a, **k)
        with mock.patch.object(mmcore, "write_atomic", failing):
            self.tick()
            self.advance(16 * MIN)
        self.assertEqual(self.status().get("heartbeat", {}).get("tick"), 17, "every tick ran to its end")
        self.assertIsNotNone(self.idle(), "the timer runs in memory")

    def test_restart_after_a_zero_ready_reset(self):
        self.tick()
        self.advance(10 * MIN)
        self.put("alpha", ready_units=0)
        self.advance(MIN)
        self.assertEqual(mmready.load_since(), (None, None), "ready == 0 resets the saved start")
        self.sup = None
        self.put("alpha", ready_units=8)
        self.t += MIN
        self.tick()
        self.advance(15 * MIN)
        self.assertIsNone(self.idle(), "the timer starts again after the reset, not at the first start")
        self.advance(MIN)
        self.assertIsNotNone(self.idle())

    def test_record_shapes(self):
        for raw in ('{"since": "x"}', '{"since": true}', "[]", '{"since": NaN}', "null"):
            with self.subTest(raw=raw):
                with open(self.record, "w") as f:
                    f.write(raw)
                since, err = mmready.load_since()
                self.assertIsNone(since)
                self.assertTrue(err, raw)
        for raw, want in (('{"since": null}', None), ('{"since": %r}' % NOW, NOW)):
            with open(self.record, "w") as f:
                f.write(raw)
            self.assertEqual(mmready.load_since(), (want, None))
        os.unlink(self.record)
        self.assertEqual(mmready.load_since(), (None, None))

    def test_a_link_as_record_is_an_error(self):
        target = os.path.join(self.root, "elsewhere.json")
        with open(target, "w") as f:
            f.write('{"since": %r}' % NOW)
        os.symlink(target, self.record)
        since, err = mmready.load_since()
        self.assertIsNone(since)
        self.assertTrue(err)


# ------------------------------------------------------------------------------------------------ pure parts

class Pure(unittest.TestCase):
    def test_ready_free(self):
        for would, busy, want in ((5, 2, 3), (5, 5, 0), (3, 5, 0), (0, 0, 0), (None, 0, 0), (1, 0, 1)):
            self.assertEqual(mmdecide.ready_free(would, busy), want, (would, busy))

    def test_ready_since(self):
        self.assertEqual(mmdecide.ready_since(None, 2, 10, NOW), NOW)
        self.assertEqual(mmdecide.ready_since(NOW - 60, 2, 10, NOW), NOW - 60)
        self.assertIsNone(mmdecide.ready_since(NOW - 60, 0, 10, NOW))
        self.assertIsNone(mmdecide.ready_since(NOW - 60, 2, 0, NOW))

    def test_evaluate_boundary_and_text(self):
        s = mmtest.base_settings()
        rw = {"free": 3, "ready": 140, "idle_minutes": 15.0, "not_folder": False, "folder": "/f", "more": 0,
              "state_error": None,
              "owners": [{"file": "beta.json", "stem": "beta", "owner": "beta", "units": 20, "age_min": 1.0,
                          "state": "ok", "why": None, "next": "beta next"},
                         {"file": "alpha.json", "stem": "alpha", "owner": "alpha", "units": 120, "age_min": 1.0,
                          "state": "stale", "why": None, "next": "alpha next"}]}
        import mmalerts
        names = lambda snap: [c for c in mmalerts.evaluate(snap, s, NOW) if c["name"] == "IDLE_WITH_WORK"]
        self.assertEqual(names({"ready_work": rw}), [], "15.0 min is not more than 15")
        got = names({"ready_work": dict(rw, idle_minutes=17.0)})
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["level"], "ACTION")
        self.assertTrue(got[0]["text"].startswith("3 free slots while 140 ready units wait for 17 min: alpha 120, beta 20"),
                        got[0]["text"])
        self.assertRegex(got[0]["text"], r'\(next: "?alpha next"?\)$')
        self.assertEqual(names({"ready_work": dict(rw, idle_minutes=17.0, free=0)}), [])
        self.assertEqual(names({"ready_work": dict(rw, idle_minutes=17.0, ready=0)}), [])


class ReadFile(TempData):
    def write(self, name, raw):
        p = os.path.join(self.root, name)
        with open(p, "w") as f:
            f.write(raw)
        return p

    def test_bad_kinds_give_state_bad_and_zero_units(self):
        up = iso(NOW)
        for raw in ("{", "[]", '{"updated": "%s", "ready_units": true}' % up, '{"updated": "%s", "ready_units": 1.0}' % up,
                    '{"updated": "%s", "ready_units": -2}' % up, '{"updated": "%s", "ready_units": "2"}' % up,
                    '{"updated": "nope", "ready_units": 2}', '{"ready_units": 2}', '{"updated": 5, "ready_units": 2}',
                    '{"updated": "%s", "ready_units": 2}' % iso(NOW + 301),
                    '{"updated": "%s", "ready_units": 2, "next": []}' % up,
                    '{"updated": "%s", "ready_units": 2, "ready_units": 3}' % up):
            with self.subTest(raw=raw):
                p = self.write("alpha.json", raw)
                rec = mmready.read_file(p, "alpha.json", NOW, 90)
                self.assertEqual((rec["state"], rec["units"], rec["owner"]), ("bad", 0, "alpha"), rec)
                self.assertTrue(rec["why"])

    def test_good_and_stale(self):
        p = self.write("beta.json", json.dumps({"owner": "beta", "updated": iso(NOW - 30 * MIN), "ready_units": 4}))
        rec = mmready.read_file(p, "beta.json", NOW, 90)
        self.assertEqual((rec["state"], rec["units"], rec["age_min"], rec["next"]), ("ok", 4, 30.0, ""))
        rec = mmready.read_file(p, "beta.json", NOW, 15)
        self.assertEqual((rec["state"], rec["units"]), ("stale", 4))
        p = self.write("beta.json", json.dumps({"owner": "beta", "updated": iso(NOW + 300), "ready_units": 4}))
        self.assertEqual(mmready.read_file(p, "beta.json", NOW, 90)["state"], "ok", "exactly 5 min ahead is good")

    def test_over_64_kib(self):
        doc = json.dumps({"updated": iso(NOW), "ready_units": 4})
        p = self.write("alpha.json", doc + " " * (65537 - len(doc)))
        rec = mmready.read_file(p, "alpha.json", NOW, 90)
        self.assertEqual((rec["state"], rec["units"]), ("bad", 0))


class ManyFiles(Base):
    def test_more_than_the_read_limit(self):
        for i in range(mmready.FILES_MAX + 2):
            self.put("o%03d" % i, ready_units=1)
        self.tick()
        rw = self.status()["ready_work"]
        self.assertEqual(rw["ready"], mmready.FILES_MAX)
        got = self.stale()
        self.assertIn("READY_STALE:_more", got, "reserved _ prefix: never an owner's stem")
        self.assertEqual(got["READY_STALE:_more"]["level"], "ATTENTION")
        files = {o["file"] for o in rw["owners"]}
        self.assertEqual(len(files), mmready.FILES_MAX)
        for i in (mmready.FILES_MAX, mmready.FILES_MAX + 1):
            self.assertNotIn("o%03d.json" % i, files, "the files past the limit by name are left out")
        self.assertIn("o000.json", files)


class MoreBadFiles(Base):
    def raw(self, name, data):
        with open(os.path.join(self.ready, name), "wb") as f:
            f.write(data)

    def test_more_bad_kinds(self):
        up = iso(self.t)
        kinds = {
            "utf8.json": b'{"owner": "\xff\xfe", "updated": "%s", "ready_units": 3}' % up.encode(),
            "deep.json": ('{"updated": "%s", "ready_units": 3, "x": %s%s}' % (up, "[" * 40, "]" * 40)).encode(),
            "deeper.json": ('{"updated": "%s", "ready_units": 3, "x": %s%s}' % (up, "[" * 30000, "]" * 30000)).encode(),  # valid, under 64 KiB
            "inf.json": ('{"updated": "%s", "ready_units": Infinity}' % up).encode(),
            "nan.json": ('{"updated": "%s", "ready_units": 3, "x": NaN}' % up).encode(),
            "neginf.json": ('{"updated": "%s", "ready_units": 3, "x": -Infinity}' % up).encode(),
            "over.json": ('{"updated": "%s", "ready_units": %d}' % (up, 10 ** 9 + 1)).encode(),
        }
        for n, data in kinds.items():
            self.raw(n, data)
        self.raw("max.json", ('{"updated": "%s", "ready_units": %d}' % (up, 10 ** 9)).encode())
        self.tick()
        rw = self.status()["ready_work"]
        states = {o["file"]: (o["state"], o["units"]) for o in rw["owners"]}
        for n in kinds:
            self.assertEqual(states.get(n), ("bad", 0), (n, states.get(n)))
        self.assertEqual(states["max.json"], ("ok", 10 ** 9), "10**9 units is accepted")
        self.assertEqual(rw["ready"], 10 ** 9)
        self.assertEqual(len(self.stale()), len(kinds), sorted(self.stale()))

    def test_an_unlistable_folder(self):
        if os.geteuid() == 0:
            self.skipTest("root lists a mode-000 folder")
        self.put("alpha", ready_units=5)
        os.chmod(self.ready, 0)
        self.addCleanup(lambda: os.path.lexists(self.ready) and os.chmod(self.ready, 0o700))
        self.tick()
        self.advance(16 * MIN)
        got = self.stale()
        self.assertEqual(len(got), 1, got)
        self.assertEqual(next(iter(got.values()))["level"], "ATTENTION")
        self.assertIsNone(self.idle(), "nothing could be read: no ready work")
        self.assertEqual(self.status()["ready_work"]["ready"], 0)
        os.chmod(self.ready, 0o700)
        self.advance(MIN)
        self.assertEqual(self.stale(), {}, "it clears on the next tick once the folder lists")

    def test_two_files_with_one_owner_keep_separate_alerts(self):
        self.put("alpha", owner="alpha", updated=iso(self.t - 100 * MIN))
        self.put("beta", owner="alpha", ready_units=-1)
        self.tick()
        got = self.stale()
        self.assertEqual(len(got), 2, got)
        self.t += MIN
        self.put("beta", owner="alpha", ready_units=1)
        self.tick()
        got = self.stale()
        self.assertEqual(len(got), 1, "the repaired file's alert clears; the stale one stays")
        self.assertIn("alpha ready-work file is 101 min old", next(iter(got.values()))["text"])


class FleetStatus(Base):
    def test_fleet_validates_a_status_with_ready_work(self):
        import mmfleet
        self.put("alpha", ready_units=7)
        self.put("beta", raw="{")  # a bad-owner entry: units 0, age_min null
        self.tick()
        st = self.status()
        owners = {o["file"]: o for o in st["ready_work"]["owners"]}
        self.assertEqual((owners["beta.json"]["state"], owners["beta.json"]["units"]), ("bad", 0))
        self.assertIsNone(owners["beta.json"]["age_min"])
        cfg = {"id": "test-machine", "stale_after_s": 90, "status_url": "http://127.0.0.1:9/status.json"}
        got = mmfleet.validate_status(st, cfg, NOW + 1)
        self.assertEqual(got["ready_work"]["ready"], 7)
        raw = json.dumps(st).encode()
        self.assertEqual(mmfleet.validate_status(mmfleet._strict_json(raw), cfg, NOW + 1)["ready_work"]["free"], 3)
        bad = json.loads(raw)
        bad["ready_work"]["owners"][0]["units"] = "7"
        with self.assertRaises(mmfleet.FleetError):
            mmfleet.validate_status(bad, cfg, NOW + 1)


class ProfileType(Base):
    def test_not_a_string_is_a_profile_error(self):
        with open(mmtest.PROFILE) as f:
            text = f.read().replace('machine_id = "test-machine"\n', 'machine_id = "test-machine"\nready_work_dir = 5\n', 1)
        p = os.path.join(self.root, "profile-bad.toml")
        with open(p, "w") as f:
            f.write(text)
        with self.assertRaises(mmcore.MMError) as cm:
            mmcore.load_profile(p)
        self.assertEqual(cm.exception.code, "E_PROFILE")


# ------------------------------------------------------------------------------------------------ ready_work_owners
# Contract addendum (2026-11-06): listed owners are expected as <name>.json (by file stem); a missing one is
# READY_STALE:<name>. Coordinator rule: listed owners' files are looked at even past the FILES_MAX cap.

class Owners(Base):
    def owners(self, names):
        self.set_profile(os.path.join(self.root, "ready"), "ready_work_owners = %s\n" % json.dumps(names))

    def test_absent_or_empty_list_is_todays_rule(self):
        for names in (None, []):
            with self.subTest(names=names):
                if names is None:
                    self.set_profile(os.path.join(self.root, "ready"))
                else:
                    self.owners(names)
                self.put("alpha", ready_units=4)
                self.sup = None
                self.tick()
                self.assertEqual(self.stale(), {})
                self.assertEqual(self.status()["ready_work"]["ready"], 4)

    def test_a_missing_listed_file_alerts_and_clears_next_tick(self):
        self.owners(["alpha", "beta"])
        self.put("alpha", ready_units=4)
        calls = []
        self.start()
        self.sup.deletes.kick = lambda *a, **k: calls.append(("deletes", a))
        rec = lambda name: (lambda *a, **k: calls.append((name, a)))
        with mock.patch.object(os, "kill", rec("kill")), mock.patch.object(os, "killpg", rec("kill")), \
                mock.patch.object(mmsuper.Pauser, "pause", rec("pause")), \
                mock.patch.object(mmsuper.Trim, "_start", rec("trim")):
            self.tick()
            got = self.stale()
            self.assertEqual(list(got), ["READY_STALE:beta"], got)
            self.assertEqual(got["READY_STALE:beta"]["level"], "ATTENTION")
            self.assertEqual(got["READY_STALE:beta"]["name"], "READY_WORK_STALE")
            rw = self.status()["ready_work"]
            self.assertEqual(rw["ready"], 4, "a missing file counts 0 units")
            self.advance(20 * MIN)
            self.assertIn("READY_STALE:beta", self.stale())
            self.put("beta", ready_units=3)
            self.advance(MIN)
            self.assertEqual(self.stale(), {}, "it clears on the next tick once the file is present and good")
            self.assertEqual(self.status()["ready_work"]["ready"], 7)
        self.assertEqual(calls, [], "a missing file never pauses, kills, trims or deletes")

    def test_a_listed_owner_with_a_link_bad_or_stale_file_has_the_same_key(self):
        self.owners(["beta"])
        outside = os.path.join(self.root, "outside.json")
        with open(outside, "w") as f:
            f.write(json.dumps({"owner": "beta", "updated": iso(self.t), "ready_units": 9, "next": "n"}))
        cases = {"link": lambda p: os.symlink(outside, p),
                 "bad": lambda p: open(p, "w").write("{"),
                 "stale": lambda p: open(p, "w").write(json.dumps({"updated": iso(self.t - 200 * MIN), "ready_units": 2}))}
        for kind, make in cases.items():
            with self.subTest(kind=kind):
                p = os.path.join(self.ready, "beta.json")
                if os.path.lexists(p):
                    os.unlink(p)
                make(p)
                self.t += MIN
                self.tick()
                got = self.stale()
                self.assertEqual(list(got), ["READY_STALE:beta"], (kind, got))
                self.assertEqual(got["READY_STALE:beta"]["level"], "ATTENTION")
                want = 2 if kind == "stale" else 0
                self.assertEqual(self.status()["ready_work"]["ready"], want, kind)

    def test_a_listed_owner_is_seen_past_the_file_cap(self):
        for i in range(70):
            self.put("o%03d" % i, ready_units=1)
        self.put("zeta", ready_units=5)  # sorts after every o### file: past the cap by name
        self.owners(["zeta", "zmissing"])
        self.tick()
        rw = self.status()["ready_work"]
        files = {o["file"]: o for o in rw["owners"]}
        self.assertIn("zeta.json", files, "a listed owner's file is looked at even past the cap")
        self.assertEqual((files["zeta.json"]["state"], files["zeta.json"]["units"]), ("ok", 5))
        got = self.stale()
        self.assertNotIn("READY_STALE:zeta", got)
        self.assertIn("READY_STALE:zmissing", got)
        self.assertIn("READY_STALE:_more", got)

    def test_matching_is_by_file_stem_not_by_json_owner(self):
        self.owners(["alpha"])
        self.put("beta", owner="alpha", ready_units=6)  # says owner alpha, but its stem is beta
        self.tick()
        self.assertEqual(list(self.stale()), ["READY_STALE:alpha"], "alpha.json is missing")
        self.assertEqual(self.status()["ready_work"]["ready"], 6, "beta.json still counts as an unlisted file")

    def test_unlisted_files_still_count(self):
        self.owners(["alpha"])
        self.put("alpha", ready_units=1)
        self.put("gamma", ready_units=9)
        self.tick()
        self.assertEqual(self.stale(), {})
        self.assertEqual(self.status()["ready_work"]["ready"], 10)


class OwnersProfile(TempData):
    def load(self, value):
        with open(mmtest.PROFILE) as f:
            text = f.read()
        head = 'machine_id = "test-machine"\n'
        text = text.replace(head, head + 'ready_work_dir = "{data}/ready"\nready_work_owners = %s\n' % value, 1)
        p = os.path.join(self.root, "profile-owners.toml")
        with open(p, "w") as f:
            f.write(text)
        return mmcore.load_profile(p)

    def test_good_lists(self):
        for names in ([], ["alpha"], ["builder-a", "b.2", "C_3"], ["n%02d" % i for i in range(64)]):
            with self.subTest(names=names[:3]):
                self.assertEqual(self.load(json.dumps(names)).get("ready_work_owners"), names)

    def test_bad_lists_are_profile_errors(self):
        bad = ['"alpha"', "5", "true", "[1]", '["alpha", 2]', '[["alpha"]]', '[""]', '["-alpha"]', '["_more"]',
               '[".hidden"]', '["a/b"]', '["a b"]', '["alpha.json/../x"]', '["alpha", "alpha"]',
               json.dumps(["n%02d" % i for i in range(65)]), json.dumps(["x" * 65])]
        for value in bad:
            with self.subTest(value=value[:40]):
                with self.assertRaises(mmcore.MMError) as cm:
                    self.load(value)
                self.assertEqual(cm.exception.code, "E_PROFILE")

    def test_profile_schema_takes_the_list(self):
        prof = self.load(json.dumps(["alpha", "beta"]))
        doc = {k: v for k, v in prof.items() if not k.startswith("_")}
        self.assertEqual(mmschema.validate(doc, mmschema.load("profile")), [])


# ------------------------------------------------------------------------------------------------ re-check of 8e8f84d

class FolderLinkForms(Base):
    """Decision: ready_work_dir reached through a link is not a folder, also as "<link>/" and "<link>/."."""

    def setUp(self):
        super().setUp()
        self.target = os.path.join(self.root, "real")
        os.makedirs(self.target)
        with open(os.path.join(self.target, "alpha.json"), "w") as f:
            f.write(json.dumps({"owner": "alpha", "updated": iso(self.t), "ready_units": 99, "next": "n"}))
        os.symlink(self.target, os.path.join(self.root, "lnk"))

    def test_link_with_slash_or_dot_is_not_a_folder(self):
        for form in ("lnk", "lnk/", "lnk/."):
            with self.subTest(form=form):
                for f in ("alerts-state.json", "status.json"):
                    if os.path.exists(os.path.join(self.data, f)):
                        os.unlink(os.path.join(self.data, f))
                self.set_profile(os.path.join(self.root, form))
                self.sup = None
                self.tick()
                got = self.stale()
                self.assertEqual(list(got), ["READY_STALE:_folder"], (form, got))
                self.assertIn("is a link (links are not followed)", got["READY_STALE:_folder"]["text"], form)
                rw = self.status().get("ready_work") or {}
                self.assertEqual(rw.get("owners"), [], form)
                self.assertEqual(rw.get("ready"), 0, "the link's target is never read")

    def test_a_real_folder_with_a_trailing_slash_works(self):
        self.put("alpha", ready_units=4)
        for form in ("/", "/./"):
            with self.subTest(form=form):
                self.set_profile(self.ready + form)
                self.sup = None
                self.tick()
                self.assertEqual(self.stale(), {}, form)
                self.assertEqual(self.status()["ready_work"]["ready"], 4, form)

    def test_a_relative_path_is_not_a_folder(self):
        os.makedirs(os.path.join(self.root, "rel"), exist_ok=True)
        self.set_profile("rel")
        self.tick()
        got = self.stale()
        self.assertEqual(list(got), ["READY_STALE:_folder"], got)
        self.assertIn("is not an absolute path", got["READY_STALE:_folder"]["text"])
        self.assertIsNone(self.idle())


class WriteFailures(Base):
    def test_timer_and_errors_log_writes_fail_and_the_tick_finishes(self):
        self.put("alpha", ready_units=8)
        real_write, real_append = mmcore.write_atomic, mmcore.append_line

        def write(target, *a, **k):
            if os.path.basename(target) == mmready.STATE_NAME:
                raise OSError(28, "No space left on device")
            return real_write(target, *a, **k)

        def append(target, *a, **k):
            if os.path.basename(target) == "errors.log":
                raise OSError(28, "No space left on device")
            return real_append(target, *a, **k)
        with mock.patch.object(mmcore, "write_atomic", write), mock.patch.object(mmcore, "append_line", append):
            self.tick()
            self.advance(16 * MIN)
        self.assertEqual(self.status()["heartbeat"]["tick"], 17, "every tick ran to its end")
        self.assertIsNotNone(self.idle(), "the timer runs in memory")


class ManyEntries(Base):
    def test_listed_owners_found_past_4096_entries(self):
        for i in range(4100):
            with open(os.path.join(self.ready, "n%05d.txt" % i), "w"):
                pass
        self.put("zeta", ready_units=5)
        self.owners_list(["zeta", "gone"])
        self.tick()
        rw = self.status()["ready_work"]
        files = {o["file"]: o for o in rw["owners"]}
        self.assertEqual((files["zeta.json"]["state"], files["zeta.json"]["units"]), ("ok", 5))
        got = self.stale()
        self.assertIn("READY_STALE:_more", got, "the listing stops at 4,096 entries")
        self.assertTrue(got["READY_STALE:_more"]["text"].startswith("the folder listing stopped after 4096 entries"),
                        got["READY_STALE:_more"]["text"])
        self.assertIn("READY_STALE:gone", got)
        self.assertNotIn("READY_STALE:zeta", got)

    def owners_list(self, names):
        self.set_profile(os.path.join(self.root, "ready"), "ready_work_owners = %s\n" % json.dumps(names))


class MissingOwnerText(Base):
    def test_exact_text_and_status_schema(self):
        self.set_profile(os.path.join(self.root, "ready"), 'ready_work_owners = ["beta"]\n')
        self.put("alpha", ready_units=2)
        self.tick()
        a = self.stale()["READY_STALE:beta"]
        self.assertEqual(a["text"], "ready-work file beta.json of listed owner beta is missing; its units count as 0")
        st = self.status()
        owners = {o["file"]: o for o in st["ready_work"]["owners"]}
        self.assertEqual((owners["beta.json"]["state"], owners["beta.json"]["units"]), ("missing", 0))
        self.assertEqual(mmschema.validate(st, mmschema.load("status")), [])
        bad = json.loads(json.dumps(st))
        next(o for o in bad["ready_work"]["owners"] if o["file"] == "beta.json")["state"] = "gone"
        self.assertTrue(mmschema.validate(bad, mmschema.load("status")), "the state enum is closed")


def _checker_has(keyword, schema, value):
    return bool(mmschema.validate(value, schema))


SCHEMA_LIMITS = _checker_has("uniqueItems", {"type": "array", "uniqueItems": True}, ["a", "a"]) and \
    _checker_has("maxItems", {"type": "array", "maxItems": 1}, ["a", "b"])


class OwnersSchema(unittest.TestCase):
    @unittest.skipUnless(SCHEMA_LIMITS, "the repo's schema checker has no uniqueItems/maxItems (mmschema)")
    def test_profile_schema_rejects_duplicates_and_65_names(self):
        prop = mmschema.load("profile")["properties"]["ready_work_owners"]
        self.assertEqual(mmschema.validate(["alpha", "beta"], prop), [])
        self.assertTrue(mmschema.validate(["alpha", "alpha"], prop))
        self.assertTrue(mmschema.validate(["n%02d" % i for i in range(65)], prop))


# ------------------------------------------------------------------------------------------------ Addendum 2
# With listed owners, a set ready_work_dir that is missing or relative is not "feature off": READY_STALE:_folder and
# READY_STALE:<name> "is missing" (0 units) for every listed owner. With no listed owners a missing folder stays off.

class ListedOwnersNeedTheFolder(Base):
    def profile_with(self, path, names):
        self.set_profile(path, "ready_work_owners = %s\n" % json.dumps(names))

    def check(self, want_folder_text):
        got = self.stale()
        self.assertEqual(sorted(got), ["READY_STALE:_folder", "READY_STALE:alpha", "READY_STALE:beta"], got)
        self.assertIn(want_folder_text, got["READY_STALE:_folder"]["text"])
        for n in ("alpha", "beta"):
            self.assertEqual(got["READY_STALE:" + n]["level"], "ATTENTION")
            self.assertIn("is missing", got["READY_STALE:" + n]["text"])
        rw = self.status().get("ready_work")
        self.assertIsNotNone(rw, "the feature is on")
        self.assertEqual(rw["ready"], 0, "missing owners count 0 units")
        self.assertIsNone(self.idle())

    def test_a_missing_folder_with_listed_owners(self):
        missing = os.path.join(self.root, "not-made-yet")
        self.profile_with(missing, ["alpha", "beta"])
        self.tick()
        self.check("does not exist")
        self.advance(20 * MIN)
        self.check("does not exist")
        os.makedirs(missing)
        for n in ("alpha", "beta"):
            with open(os.path.join(missing, n + ".json"), "w") as f:
                f.write(json.dumps({"owner": n, "updated": iso(self.t + MIN), "ready_units": 2, "next": "n"}))
        self.advance(MIN)
        self.assertEqual(self.stale(), {}, "all clear on the next tick once the folder and files are there")
        self.assertEqual(self.status()["ready_work"]["ready"], 4)

    def test_a_relative_folder_with_listed_owners(self):
        os.makedirs(os.path.join(self.root, "rel"), exist_ok=True)
        self.profile_with("rel", ["alpha", "beta"])
        self.tick()
        self.check("is not an absolute path")

    def test_an_unset_folder_with_listed_owners_stays_off(self):
        self.profile_with("", ["alpha", "beta"])
        self.tick()
        self.advance(20 * MIN)
        self.assertEqual((self.idle(), self.stale()), (None, {}))
        self.assertNotIn("ready_work", self.status())

    def test_a_missing_folder_without_listed_owners_stays_off(self):
        missing = os.path.join(self.root, "not-made-yet")
        for names in (None, []):
            with self.subTest(names=names):
                if names is None:
                    self.set_profile(missing)
                else:
                    self.profile_with(missing, names)
                self.sup = None
                self.tick()
                self.advance(20 * MIN)
                self.assertEqual((self.idle(), self.stale()), (None, {}))
                self.assertNotIn("ready_work", self.status())


if __name__ == "__main__":
    unittest.main()
