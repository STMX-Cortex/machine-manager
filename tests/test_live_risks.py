# SPDX-License-Identifier: Apache-2.0
"""Live risks 1-3: wrong-shaped or unreadable input never leads to a delete, a pause, a signal or actions on.

Fix 1: off.json and safe.json. Missing: no guard. An object whose flag is JSON true: the record. Flag JSON false: no
guard. Anything else (unreadable, not valid JSON, not an object, no flag, a flag that is not a JSON bool) sets the
guard: actions stay off, an alert names the file, `mm status` shows the reason, `mm on` still ends it.
Fix 2: own_files names (slot_dir and every `files` name) must be relative and stay inside the data folder; a refused
name gives a KEEP line and is never deleted; the other names of the rule still run.
Fix 3: a broken state/paused.json is never written over, starts no pause, sends no signal, raises an alert, and
counts as "maybe paused" for the watchdog and `mm recover-paused`.

Every file lives in the test's temporary folder; every process here is one this test started; no SIGSTOP or SIGCONT
is sent to anything (a spy replaces mmrecover.signal_process where a pause could start)."""
import json
import os
import signal
import subprocess
import sys
import time
import unittest

import mmtest
from mmtest import TempData, base_settings, mmcore, mmread
import ad_deliver_claude
import mmdelete
import mmrecover
import mmsuper
import mmwatch
from test_deletes import age, make


def sampler_of(**kw):
    def f(now, ticks):
        d = {"t": now, "free_pct": 80, "swap_used_mb": 100, "swap_total_mb": 2048, "comp_mb": 300, "pressure": 1,
             "seg_pct": 1, "load1": 1, "load5": 1, "sys_pct": None, "sys_pct_fixture": 10}
        d.update(kw)
        return d, ticks
    return f


CALM = sampler_of()
RED = sampler_of(free_pct=30)
CRITICAL = sampler_of(free_pct=70, pressure=4)  # a critical RED: the pause starts on it
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

# (name, file text with %s for the flag); every one is BROKEN: the guard must be set
BROKEN_CONTROL = [
    ("list", "[]"),
    ("empty_object", "{}"),
    ("flag_list", '{"%s": []}'),
    ("flag_one", '{"%s": 1}'),
    ("flag_zero", '{"%s": 0}'),
    ("flag_yes", '{"%s": "yes"}'),
    ("flag_false_text", '{"%s": "false"}'),
    ("flag_null", '{"%s": null}'),
    ("flag_object", '{"%s": {}}'),
    ("invalid_json", '{"%s": tru'),
    ("empty_file", ""),
    ("null", "null"),
    ("number", "1"),
    ("string", '"%s"'),
]
# a few broken shapes for the slower tests (a supervisor tick, a subprocess)
SOME_BROKEN = ("list", "empty_object", "flag_list", "invalid_json")


def text_of(name, flag):
    t = dict(BROKEN_CONTROL)[name]
    return t % flag if "%s" in t else t


def write_raw(target, text):
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w") as f:
        f.write(text)


def raw(target):
    with open(target, "rb") as f:
        return f.read()


def unreadable(target, text="{}"):
    """target with content but mode 000 (only for a test that does not run as root)."""
    write_raw(target, text)
    os.chmod(target, 0)


class SignalSpy:
    """Replaces mmrecover.signal_process: records every call and sends nothing."""

    def __init__(self, case):
        self.calls = []
        self.real = mmrecover.signal_process
        mmrecover.signal_process = self.record
        case.addCleanup(self.restore)

    def record(self, pid, expected, sig):
        self.calls.append((pid, sig))
        return None

    def restore(self):
        mmrecover.signal_process = self.real


class SupBase(TempData):
    """A fixture queue (5 slots), a fake gh, an in-process supervisor."""

    def setUp(self):
        super().setUp()
        self.q = self.queue_dir(slots=5)

    def sup(self, sampler=CALM, clock=None, **kw):
        kw.setdefault("check_readings", False)
        return mmsuper.Supervisor(self.profile(), kernel=False, clock=clock or time.time, sampler=sampler, sizes=False,
                                  slow_jobs=False, **kw)

    def ticks(self, sup, n, clock):
        for _ in range(n):
            sup.tick()
            clock["t"] += 10

    def act(self, **over):
        flat = {"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False}
        flat.update(over)
        self.write_settings(**flat)

    def status(self):
        return json.load(open(os.path.join(self.data, "status.json")))

    def active(self):
        st = mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {}) or {}
        return list((st.get("active") or {}).values())

    def alerts_naming(self, word):
        return [a for a in self.active() if word in (a.get("text") or "") or word in (a.get("key") or "")]

    def tick_clear(self, sampler=CALM):
        """Ticks over repeat.clear_after_minutes (an alert clears after that long absent): one supervisor, its own
        clock, three ticks: now, +1 s, + the clear time."""
        clock = {"t": time.time()}
        sup = self.sup(sampler, clock=lambda: clock["t"])
        for step in (1, self.s()["repeat.clear_after_minutes"] * 60 + 5, 0):
            sup.tick()
            clock["t"] += step

    def decisions(self):
        try:
            return open(os.path.join(self.data, "state", "decisions.log")).read()
        except OSError:
            return ""

    def launcher_call(self):
        """A real call of the fixture launcher holding .slot.1, with its sleep; ended at cleanup. Returns its tree."""
        p = subprocess.Popen([sys.executable, "-I", os.path.join(self.q, "launcher.py"), "--", "/bin/sleep", "300"])
        tree = [p.pid]

        def end():
            for pid in reversed(tree):
                try:
                    os.kill(pid, signal.SIGCONT)  # ours; harmless when it was never stopped
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            p.wait(10)
        self.addCleanup(end)
        kids = []
        for _ in range(100):
            kids = [x["pid"] for x in mmread.read_ps() or [] if x["ppid"] == p.pid]
            if kids and mmread.flock_held(os.path.join(self.q, ".slot.1"))[0]:
                break
            time.sleep(0.1)
        tree += kids
        self.assertEqual(len(tree), 2, "the launcher runs its sleep and holds the slot")
        return tree


# ===================================================================================== Fix 1: off.json and safe.json

class F1ControlShapes(TempData):
    """off_state() and safe_state() on every shape of their file."""
    CASES = (("off.json", "off", lambda: mmcore.off_state()), ("safe.json", "safe", lambda: mmcore.safe_state()))

    def test_missing_file_is_no_guard(self):
        for name, flag, fn in self.CASES:
            with self.subTest(file=name):
                self.assertFalse(os.path.lexists(os.path.join(self.data, name)))
                self.assertIsNone(fn())

    def test_flag_true_gives_the_record(self):
        for name, flag, fn in self.CASES:
            with self.subTest(file=name):
                rec = {flag: True, "since": "2026-11-06 20:00", "reason": "test"}
                write_raw(os.path.join(self.data, name), json.dumps(rec))
                self.assertEqual(fn(), rec)

    def test_flag_false_is_no_guard(self):
        for name, flag, fn in self.CASES:
            with self.subTest(file=name):
                write_raw(os.path.join(self.data, name), json.dumps({flag: False, "reason": "x"}))
                self.assertIsNone(fn())

    def test_every_broken_shape_sets_the_guard(self):
        for name, flag, fn in self.CASES:
            for shape, _ in BROKEN_CONTROL:
                with self.subTest(file=name, shape=shape):
                    write_raw(os.path.join(self.data, name), text_of(shape, flag))
                    self.assertTrue(fn(), "%s %s must set the guard" % (name, shape))

    @unittest.skipIf(ROOT, "root reads a mode-000 file")
    def test_unreadable_file_sets_the_guard(self):
        for name, flag, fn in self.CASES:
            with self.subTest(file=name):
                target = os.path.join(self.data, name)
                unreadable(target, json.dumps({flag: False}))  # even a false flag: it cannot be read
                self.assertTrue(fn(), "an unreadable %s must set the guard" % name)

    def test_a_folder_in_its_place_sets_the_guard(self):
        for name, flag, fn in self.CASES:
            with self.subTest(file=name):
                os.makedirs(os.path.join(self.data, name))
                self.assertTrue(fn(), "a folder named %s cannot be read: the guard is set" % name)

    def test_reading_never_changes_the_file(self):
        for name, flag, fn in self.CASES:
            for shape in SOME_BROKEN:
                with self.subTest(file=name, shape=shape):
                    target = os.path.join(self.data, name)
                    write_raw(target, text_of(shape, flag))
                    before = raw(target)
                    fn()
                    self.assertEqual(raw(target), before)


class F1ActMode(SupBase):
    """In act mode a broken off.json or safe.json keeps every action off."""

    def run_red(self, n=3):
        test_slots = os.path.join(self.root, "test-slots")
        mmcore.write_slots(test_slots, 6)
        self.act(**{"mode.slot_writes": "test", "mode.slots_file": test_slots})
        clock = {"t": time.time()}
        self.ticks(self.sup(RED, clock=lambda: clock["t"]), n, clock)
        return test_slots

    def test_control_the_good_case_writes(self):
        """The fixture writes in act mode with no control file (so the broken cases below prove something)."""
        self.assertEqual(open(self.run_red()).read(), "3\n")
        self.assertEqual(self.status()["mode"], "act")

    def test_broken_off_json_no_slot_write(self):
        for shape in SOME_BROKEN:
            with self.subTest(shape=shape):
                target = os.path.join(self.data, "off.json")
                write_raw(target, text_of(shape, "off"))
                before = raw(target)
                self.assertEqual(open(self.run_red()).read(), "6\n", "off.json %s: no slot write" % shape)
                self.assertNotEqual(self.status()["mode"], "act")
                self.assertEqual(raw(target), before, "the supervisor never writes over a broken off.json")

    @unittest.skipIf(ROOT, "root reads a mode-000 file")
    def test_unreadable_off_json_no_slot_write(self):
        unreadable(os.path.join(self.data, "off.json"), json.dumps({"off": False}))
        self.assertEqual(open(self.run_red()).read(), "6\n")
        self.assertNotEqual(self.status()["mode"], "act")

    def test_broken_safe_json_mode_is_not_act_and_file_stays(self):
        for shape in SOME_BROKEN:
            with self.subTest(shape=shape):
                target = os.path.join(self.data, "safe.json")
                write_raw(target, text_of(shape, "safe"))
                before = raw(target)
                f = self.run_red()
                self.assertLessEqual(int(open(f).read()), 6, "a broken safe.json never raises the count")
                self.assertNotEqual(self.status()["mode"], "act", "safe.json %s: actions off" % shape)
                self.assertEqual(raw(target), before, "the supervisor never writes over a broken safe.json")

    @mmtest.needs_proc
    def test_broken_off_json_no_pause_no_signal(self):
        self.launcher_call()
        write_raw(os.path.join(self.data, "off.json"), "{}")
        self.act(**{"pause_newest_call.enabled": True})
        spy = SignalSpy(self)
        clock = {"t": time.time()}
        self.ticks(self.sup(CRITICAL, clock=lambda: clock["t"]), 2, clock)
        self.assertEqual([c for c in spy.calls if c[1] == signal.SIGSTOP], [], "no SIGSTOP with a broken off.json")
        self.assertEqual(mmrecover.read_paused(), {}, "nothing recorded as paused")

    @mmtest.needs_proc
    def test_broken_safe_json_no_pause_no_signal(self):
        self.launcher_call()
        write_raw(os.path.join(self.data, "safe.json"), '{"safe": "yes please"')
        self.act(**{"pause_newest_call.enabled": True})
        spy = SignalSpy(self)
        clock = {"t": time.time()}
        self.ticks(self.sup(CRITICAL, clock=lambda: clock["t"]), 2, clock)
        self.assertEqual([c for c in spy.calls if c[1] == signal.SIGSTOP], [], "no SIGSTOP with a broken safe.json")

    def test_broken_control_file_keeps_the_launch_gate_open(self):
        """The gate is an action: with a broken guard it denies nothing (as with a good off.json / safe.json)."""
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"),
                            json.dumps({"time": now, "state": "RED", "red_since": now - 10, "reasons": ["free 30%"]}))
        s = base_settings(**{"launch_gate.enabled": True})
        cfg, data = {"launch_tools": ["Agent"]}, {"tool_name": "Agent"}
        self.assertTrue(ad_deliver_claude.gate_decision(data, s, now, cfg).startswith("E_GATE_RED"), "control")
        for name, flag in (("off.json", "off"), ("safe.json", "safe")):
            for shape in SOME_BROKEN:
                with self.subTest(file=name, shape=shape):
                    target = os.path.join(self.data, name)
                    write_raw(target, text_of(shape, flag))
                    self.assertIsNone(ad_deliver_claude.gate_decision(data, s, now, cfg))
                    os.remove(target)


class F1AlertAndStatus(SupBase):
    """A broken control file raises an alert that names it, and clears when the file is good again or removed;
    `mm status` (text and --json) shows the reason; `mm on` ends it."""

    def setUp(self):
        super().setUp()
        self.act()  # act mode: a broken guard must change the mode from "act"

    def tick(self, sampler=CALM):
        self.sup(sampler).tick()

    def test_alert_raises_and_clears_on_remove(self):
        for name, flag in (("off.json", "off"), ("safe.json", "safe")):
            with self.subTest(file=name):
                target = os.path.join(self.data, name)
                write_raw(target, text_of("invalid_json", flag))
                self.tick()
                self.assertTrue(self.alerts_naming(name), "an active alert names %s: %s" % (name, self.active()))
                os.remove(target)
                self.tick_clear()
                self.assertEqual(self.alerts_naming(name), [], "cleared when %s is removed" % name)

    def test_alert_clears_when_the_file_is_good_again(self):
        target = os.path.join(self.data, "off.json")
        write_raw(target, '{"off": 1}')
        self.tick()
        self.assertTrue(self.alerts_naming("off.json"), self.active())
        write_raw(target, json.dumps({"off": False}))
        self.tick_clear()
        self.assertEqual(self.alerts_naming("off.json"), [], "a good off.json clears the alert")

    def test_mm_status_shows_the_reason(self):
        for name, flag in (("off.json", "off"), ("safe.json", "safe")):
            with self.subTest(file=name):
                target = os.path.join(self.data, name)
                write_raw(target, "[]")
                self.tick()
                r = self.mm("status")
                self.assertIn(r.returncode, (0, 1), r.stdout + r.stderr)
                self.assertIn(name, r.stdout, "mm status names the broken file")
                self.assertLessEqual(len(r.stdout.splitlines()), 5, "mm status stays at most 5 lines")
                rj = self.mm("status", "--json")
                obj = json.loads(rj.stdout)
                self.assertIn(name, json.dumps(obj), "mm status --json names the broken file")
                self.assertNotEqual(obj.get("mode"), "act")
                if name == "off.json":
                    self.assertIs(obj.get("off"), True, "--json off is true with a broken off.json")
                os.remove(target)

    def test_mm_on_ends_a_broken_off_json_and_safe_json(self):
        for shape in SOME_BROKEN:
            with self.subTest(shape=shape):
                write_raw(os.path.join(self.data, "off.json"), text_of(shape, "off"))
                write_raw(os.path.join(self.data, "safe.json"), text_of(shape, "safe"))
                r = self.mm("on")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertTrue(r.stdout.startswith("actions=on"), r.stdout)
                self.assertFalse(os.path.lexists(os.path.join(self.data, "off.json")))
                self.assertFalse(os.path.lexists(os.path.join(self.data, "safe.json")))
                self.assertIsNone(mmcore.off_state())
                self.assertIsNone(mmcore.safe_state())

    @unittest.skipIf(ROOT, "root reads a mode-000 file")
    def test_mm_on_ends_unreadable_files(self):
        unreadable(os.path.join(self.data, "off.json"))
        unreadable(os.path.join(self.data, "safe.json"))
        r = self.mm("on")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(os.path.lexists(os.path.join(self.data, "off.json")))
        self.assertFalse(os.path.lexists(os.path.join(self.data, "safe.json")))

    def test_clear_safe_ends_a_broken_safe_json(self):
        """mm restart --clear-safe runs mmrecover.clear_safe first (the restart itself needs a service)."""
        write_raw(os.path.join(self.data, "safe.json"), '{"safe": []}')
        mmrecover.clear_safe("test")
        self.assertFalse(os.path.lexists(os.path.join(self.data, "safe.json")))
        self.assertIsNone(mmcore.safe_state())


# ===================================================================================== Fix 2: own_files names

class F2Base(TempData):
    """Helpers: an `outside` folder next to the data folder, a delete Run on own_files rules, the parsed lines."""

    def setUp(self):
        super().setUp()
        # real paths (macOS: the temp folder is under the /var link): an absolute name is then exactly the file's
        # real path, as on Linux, so the old startswith/`in allowed` checks would pass it
        self.outside = os.path.realpath(os.path.join(self.root, "outside"))
        os.makedirs(self.outside)

    def run_rules(self, rules, enabled=True, data=None):
        ctx = mmdelete.Ctx({"rules": list(rules), "cleanup": [], "forbidden_parts": [".records", ".ssh"],
                            "protected_roots": []}, extra={"t": self.outside, "user_tmp": self.outside},
                           data=data or self.data)
        r = mmdelete.Run(base_settings(**{"deletes.lsof_timeout_s": 60}), ctx, enabled=enabled,
                         procs=lambda: [], live_spec={"names": [], "suffixes": [], "path_regexes": []}, mid="m1")
        r.all()
        return r

    def recs(self, run, rule="S1"):
        import mmschema
        out = []
        for line in run.lines:
            rec = mmcore.parse_delete_line(line)
            self.assertIsNotNone(rec, line)
            self.assertEqual(mmschema.validate(rec, mmschema.load("delete-line")), [], line)
            if rec.get("rule") == rule:
                out.append(rec)
        return out

    def old_file(self, path, text="x" * 100):
        write_raw(path, text)
        age(path)
        return path

    def assert_kept_with_keep_line(self, run, kept):
        self.assertTrue(os.path.lexists(kept), "outside the data folder: never deleted: %s" % kept)
        recs = self.recs(run)
        self.assertTrue(recs, "a refused name gives a KEEP line: %s" % run.lines)
        self.assertTrue(all(r["verb"] == "KEEP" for r in recs), run.lines)


class F2OwnFilesNames(F2Base):
    """own_files deletes only inside the data folder. Each test plants an old file OUTSIDE data and checks it stays."""

    def test_control_good_names_delete(self):
        self.old_file(os.path.join(self.data, "metrics.csv.1"))
        make(os.path.join(self.data, "evidence", "01"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["metrics.csv.1"]}])
        self.assertFalse(os.path.lexists(os.path.join(self.data, "metrics.csv.1")))
        self.assertFalse(os.path.lexists(os.path.join(self.data, "evidence", "01")))
        self.assertEqual(sorted(x["verb"] for x in self.recs(r)), ["DELETE", "DELETE"])

    def test_absolute_slot_dir(self):
        victim = make(os.path.join(self.outside, "01"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": self.outside, "files": []}])
        self.assert_kept_with_keep_line(r, victim)
        self.assertTrue(os.path.exists(os.path.join(victim, "a.o")))

    def test_absolute_slot_dir_in_dry_run_claims_nothing(self):
        make(os.path.join(self.outside, "01"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": self.outside, "files": []}], enabled=False)
        self.assertEqual([x for x in self.recs(r) if x["verb"] != "KEEP"], [], "no WOULD-DELETE outside data")

    def test_dotdot_slot_dir(self):
        victim = make(os.path.join(self.outside, "01"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": "../outside", "files": []}])
        self.assert_kept_with_keep_line(r, victim)

    def test_symlinked_slot_dir_inside_data(self):
        victim = make(os.path.join(self.outside, "01"))
        os.symlink(self.outside, os.path.join(self.data, "evidence"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": []}])
        self.assertTrue(os.path.exists(victim))
        self.assertTrue(all(x["verb"] == "KEEP" for x in self.recs(r)), r.lines)

    def test_absolute_file_name_outside(self):
        victim = self.old_file(os.path.join(self.outside, "victim.log"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": [victim]}])
        self.assert_kept_with_keep_line(r, victim)

    def test_absolute_file_name_outside_in_dry_run_claims_nothing(self):
        victim = self.old_file(os.path.join(self.outside, "victim.log"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": [victim]}], enabled=False)
        self.assertEqual([x for x in self.recs(r) if x["verb"] != "KEEP"], [], "no WOULD-DELETE outside data")

    def test_absolute_file_name_inside_data_is_refused_too(self):
        """The rule: every name relative. An absolute name is refused even when it points into the data folder."""
        inside = self.old_file(os.path.join(self.data, "metrics.csv.1"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": [os.path.realpath(inside)]}])
        self.assert_kept_with_keep_line(r, inside)

    def test_dotdot_file_names(self):
        victim = self.old_file(os.path.join(self.outside, "victim.log"))
        os.makedirs(os.path.join(self.data, "a"))
        for name in ("../outside/victim.log", "a/../../outside/victim.log", "state/../../outside/victim.log"):
            with self.subTest(name=name):
                r = self.run_rules([{"id": "S1", "type": "own_files", "files": [name]}])
                self.assert_kept_with_keep_line(r, victim)

    def test_empty_name_never_touches_the_data_folder(self):
        self.old_file(os.path.join(self.data, "metrics.csv.1"))
        age(self.data)
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": [""]}])
        self.assertTrue(os.path.isdir(self.data))
        self.assertTrue(os.path.exists(os.path.join(self.data, "metrics.csv.1")))
        self.assertTrue(all(x["verb"] == "KEEP" for x in self.recs(r)), r.lines)

    def test_dot_name_never_touches_the_data_folder(self):
        self.old_file(os.path.join(self.data, "metrics.csv.1"))
        age(self.data)
        for name in (".", "./", "state/.."):
            with self.subTest(name=name):
                r = self.run_rules([{"id": "S1", "type": "own_files", "files": [name]}])
                self.assertTrue(os.path.exists(os.path.join(self.data, "metrics.csv.1")))
                self.assertTrue(all(x["verb"] == "KEEP" for x in self.recs(r)), r.lines)

    def test_symlinked_parent_folder_inside_data(self):
        victim = self.old_file(os.path.join(self.outside, "old.log"))
        os.symlink(self.outside, os.path.join(self.data, "linkdir"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["linkdir/old.log"]}])
        self.assert_kept_with_keep_line(r, victim)

    def test_symlinked_file_inside_data(self):
        victim = self.old_file(os.path.join(self.outside, "old.log"))
        os.symlink(victim, os.path.join(self.data, "metrics.csv.1"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["metrics.csv.1"]}])
        self.assertTrue(os.path.exists(victim))
        self.assertTrue(all(x["verb"] == "KEEP" for x in self.recs(r)), r.lines)

    def test_a_refused_name_leaves_the_other_names_running(self):
        victim = self.old_file(os.path.join(self.outside, "victim.log"))
        good = self.old_file(os.path.join(self.data, "metrics.csv.1"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": [victim, "../outside/victim.log",
                                                                          "metrics.csv.1"]}])
        self.assertTrue(os.path.exists(victim))
        self.assertFalse(os.path.lexists(good), "the good name of the same rule is still deleted")
        verbs = sorted(x["verb"] for x in self.recs(r))
        self.assertIn("DELETE", verbs)
        self.assertIn("KEEP", verbs)

    def test_a_refused_slot_dir_leaves_the_files_running(self):
        make(os.path.join(self.outside, "01"))
        good = self.old_file(os.path.join(self.data, "metrics.csv.1"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": self.outside, "files": ["metrics.csv.1"]}])
        self.assertTrue(os.path.exists(os.path.join(self.outside, "01")))
        self.assertFalse(os.path.lexists(good))

    def test_relative_subfolder_names_stay_allowed(self):
        """A real profile has "state/decisions.log.1": deleted when old enough, kept when young."""
        old = self.old_file(os.path.join(self.data, "state", "decisions.log.1"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["state/decisions.log.1"]}])
        self.assertFalse(os.path.lexists(old))
        self.assertEqual([x["verb"] for x in self.recs(r)], ["DELETE"])
        write_raw(old, "young")
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["state/decisions.log.1"]}])
        self.assertTrue(os.path.exists(old), "young: kept")

    def test_real_profile_names_unchanged(self):
        names = ["metrics.csv.1", "alerts.jsonl.1", "deletes.log.1", "state/decisions.log.1"]
        for n in names:
            self.old_file(os.path.join(self.data, n))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": names}])
        for n in names:
            self.assertFalse(os.path.lexists(os.path.join(self.data, n)), n)
        self.assertEqual([x["verb"] for x in self.recs(r)], ["DELETE"] * 4)

    def test_relative_slot_dir_inside_data_stays_allowed(self):
        make(os.path.join(self.data, "ev2", "01"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": "ev2", "files": []}])
        self.assertFalse(os.path.lexists(os.path.join(self.data, "ev2", "01")))
        self.assertEqual([x["verb"] for x in self.recs(r)], ["DELETE"])

    def test_a_linked_data_folder_still_works(self):
        """The check uses the real data folder: a data path reached through a link still deletes its own files."""
        good = self.old_file(os.path.join(self.data, "metrics.csv.1"))
        link = os.path.join(self.root, "data-link")
        os.symlink(self.data, link)
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["metrics.csv.1"]}], data=link)
        self.assertFalse(os.path.lexists(good))
        self.assertEqual([x["verb"] for x in self.recs(r)], ["DELETE"])


# ===================================================================================== Fix 3: state/paused.json

BROKEN_PAUSED = [
    ("list", "[]"),
    ("invalid_json", '{"123": "Mon'),
    ("empty_file", ""),
    ("null", "null"),
    ("string", '"123"'),
    ("number", "123"),
]


class F3PausedBase(SupBase):
    def paused(self):
        return os.path.join(self.data, "state", "paused.json")

    def broken(self, shape):
        write_raw(self.paused(), dict(BROKEN_PAUSED)[shape])
        return raw(self.paused())


class F3PausedFile(F3PausedBase):
    def test_missing_and_good_files_read_as_today(self):
        self.assertEqual(mmrecover.read_paused(), {})
        write_raw(self.paused(), json.dumps({"123": "Mon Nov  6 20:00:00 2026"}))
        self.assertEqual(mmrecover.read_paused(), {"123": "Mon Nov  6 20:00:00 2026"})

    def test_add_paused_never_writes_over_a_broken_file(self):
        for shape, _ in BROKEN_PAUSED:
            with self.subTest(shape=shape):
                before = self.broken(shape)
                try:
                    mmrecover.add_paused({"999999": "x"})
                except Exception:  # a refusal may raise; the file is what counts
                    pass
                self.assertEqual(raw(self.paused()), before, "paused.json %s is written over" % shape)

    def test_drop_paused_never_writes_over_a_broken_file(self):
        for shape, _ in BROKEN_PAUSED:
            with self.subTest(shape=shape):
                before = self.broken(shape)
                try:
                    mmrecover.drop_paused(["123"])
                except Exception:
                    pass
                self.assertEqual(raw(self.paused()), before, "paused.json %s is written over" % shape)

    def test_resume_sends_no_signal_and_keeps_the_file(self):
        spy = SignalSpy(self)
        for shape, _ in BROKEN_PAUSED:
            with self.subTest(shape=shape):
                before = self.broken(shape)
                self.assertEqual(mmrecover.resume_paused("test"), [])
                self.assertEqual(raw(self.paused()), before)
        self.assertEqual(spy.calls, [], "no signal from a broken paused.json")

    def test_wrong_entry_shape_resume_does_not_crash_or_signal(self):
        """An entry the resume cannot read (a pid that is not a number) is a broken file too."""
        spy = SignalSpy(self)
        write_raw(self.paused(), json.dumps({"not-a-pid": "Mon Nov  6 20:00:00 2026"}))
        before = raw(self.paused())
        self.assertEqual(mmrecover.resume_paused("test"), [])
        self.assertEqual(raw(self.paused()), before)
        self.assertEqual(spy.calls, [])

    @unittest.skipIf(ROOT, "root reads a mode-000 file")
    def test_unreadable_file_is_never_written_over(self):
        unreadable(self.paused(), "{}")
        spy = SignalSpy(self)
        for call in (lambda: mmrecover.add_paused({"999999": "x"}), lambda: mmrecover.drop_paused(["1"]),
                     lambda: mmrecover.resume_paused("test")):
            try:
                call()
            except Exception:
                pass
        self.assertEqual(os.stat(self.paused()).st_mode & 0o777, 0, "the unreadable file is still there, unchanged")
        os.chmod(self.paused(), 0o600)
        self.assertEqual(raw(self.paused()), b"{}")
        self.assertEqual(spy.calls, [])

    @mmtest.needs_proc
    def test_control_a_pause_starts_without_a_broken_file(self):
        """The fixture pauses (the spy sees the SIGSTOPs and sends nothing), so the broken cases below prove something."""
        tree = self.launcher_call()
        self.act(**{"pause_newest_call.enabled": True})
        spy = SignalSpy(self)
        clock = {"t": time.time()}
        self.ticks(self.sup(CRITICAL, clock=lambda: clock["t"]), 2, clock)
        self.assertEqual(sorted(pid for pid, sig in spy.calls if sig == signal.SIGSTOP), sorted(tree))

    @mmtest.needs_proc
    def test_no_pause_with_a_broken_file(self):
        self.launcher_call()
        self.act(**{"pause_newest_call.enabled": True})
        spy = SignalSpy(self)
        for shape in ("list", "invalid_json", "null"):
            with self.subTest(shape=shape):
                before = self.broken(shape)
                clock = {"t": time.time()}
                self.ticks(self.sup(CRITICAL, clock=lambda: clock["t"]), 2, clock)
                self.assertEqual([c for c in spy.calls if c[1] == signal.SIGSTOP], [], "no pause")
                self.assertEqual(raw(self.paused()), before, "paused.json %s is written over" % shape)
        self.assertEqual(spy.calls, [], "no signal at all")

    def test_supervisor_start_keeps_a_broken_file(self):
        spy = SignalSpy(self)
        for shape in ("list", "invalid_json"):
            with self.subTest(shape=shape):
                before = self.broken(shape)
                self.sup()
                self.assertEqual(raw(self.paused()), before)
        self.assertEqual(spy.calls, [])

    def test_alert_raises_names_the_file_and_clears(self):
        self.act()
        before = self.broken("invalid_json")
        self.sup().tick()
        self.assertTrue(self.alerts_naming("paused.json"), "an active alert names paused.json: %s" % self.active())
        self.assertEqual(raw(self.paused()), before)
        os.remove(self.paused())
        self.tick_clear()
        self.assertEqual(self.alerts_naming("paused.json"), [], "cleared when the file is removed")

    def test_mm_status_shows_it(self):
        self.act()
        self.broken("list")
        self.sup().tick()
        r = self.mm("status")
        self.assertIn("paused", r.stdout.lower(), "mm status shows the broken paused.json: %s" % r.stdout)
        self.assertLessEqual(len(r.stdout.splitlines()), 5)

    def test_recover_paused_does_not_report_nothing_paused(self):
        spy = SignalSpy(self)  # in-process only; the subprocess below has no spy, and the file has no pid
        for shape in ("list", "invalid_json", "null"):
            with self.subTest(shape=shape):
                before = self.broken(shape)
                r = self.mm("recover-paused")
                self.assertEqual(r.returncode, 1, "a broken paused.json is not 'nothing paused': %s" % r.stdout)
                self.assertEqual(r.stdout.strip(), 'resumed="" broken="%s"' % mmrecover.paused_problem(
                    mmrecover.read_paused()))
                self.assertEqual(raw(self.paused()), before)
        self.assertEqual(spy.calls, [])

    def test_watchdog_treats_a_broken_file_as_maybe_paused(self):
        """A stopped supervisor (state/stopped.json): a broken file counts as "maybe paused", so the watchdog's resume
        path runs; it cannot know the pids, so it signals nothing, keeps the file and says so in watchdog.log."""
        spy = SignalSpy(self)
        write_raw(os.path.join(self.data, "state", "stopped.json"), json.dumps({"time": time.time()}))
        before = self.broken("invalid_json")
        mmwatch.check(time.time(), self.s(), self.profile(), restart=False)
        self.assertEqual(raw(self.paused()), before)
        self.assertEqual(spy.calls, [])
        self.assertIn("paused record unusable (state/paused.json: cannot be read (JSONDecodeError)): nothing resumed, "
                      "processes may still be stopped", open(os.path.join(self.data, "state", "watchdog.log")).read())


# ===================================================================================== the coder's API (405277033a07)

class F1Pinned(SupBase):
    """off_state/safe_state records, control_problem/control_broken, CONTROL_FILE_BROKEN, SAFE_MODE text, mm status."""
    CASES = (("off.json", "off", lambda: mmcore.off_state()), ("safe.json", "safe", lambda: mmcore.safe_state()))
    TEXTS = (("list", "%s: not a JSON object"), ("empty_object", "%s: no %s flag"),
             ("flag_one", "%s: %s is not true or false"), ("flag_yes", "%s: %s is not true or false"),
             ("flag_null", "%s: %s is not true or false"), ("flag_false_text", "%s: %s is not true or false"),
             ("null", "%s: not a JSON object"), ("invalid_json", "%s: cannot be read (JSONDecodeError)"),
             ("empty_file", "%s: cannot be read (JSONDecodeError)"))

    def test_broken_record_shape(self):
        for name, flag, fn in self.CASES:
            for shape, _ in BROKEN_CONTROL:
                with self.subTest(file=name, shape=shape):
                    write_raw(os.path.join(self.data, name), text_of(shape, flag))
                    rec = fn()
                    self.assertIs(rec[flag], True)
                    self.assertTrue(rec["broken"].startswith(name + ": "), rec)
                    self.assertEqual(rec["reason"], rec["broken"] + "; automatic actions stay off")
                    want = {flag, "broken", "reason"} | ({"slot_write"} if flag == "safe" else set())
                    self.assertEqual(set(rec), want)
                    if flag == "safe":
                        self.assertEqual(rec["slot_write"], "none (safe.json broken)")
                    self.assertEqual(mmcore.control_problem(name, flag), (None, rec["broken"]))
                    self.assertEqual(mmcore.control_broken(), [rec["broken"]])
                    os.remove(os.path.join(self.data, name))

    def test_problem_texts(self):
        for name, flag, fn in self.CASES:
            for shape, text in self.TEXTS:
                with self.subTest(file=name, shape=shape):
                    write_raw(os.path.join(self.data, name), text_of(shape, flag))
                    self.assertEqual(fn()["broken"], text % ((name, flag) if text.count("%s") == 2 else name))

    def test_dangling_link_sets_the_guard(self):
        for name, flag, fn in self.CASES:
            with self.subTest(file=name):
                os.symlink(os.path.join(self.root, "nowhere.json"), os.path.join(self.data, name))
                self.assertEqual(fn()["broken"], "%s: a dangling link" % name)

    @unittest.skipIf(ROOT, "root reads a mode-000 file")
    def test_unreadable_text(self):
        for name, flag, fn in self.CASES:
            with self.subTest(file=name):
                unreadable(os.path.join(self.data, name))
                self.assertEqual(fn()["broken"], "%s: cannot be read (PermissionError)" % name)

    def test_good_records_have_no_broken(self):
        for name, flag, fn in self.CASES:
            with self.subTest(file=name):
                rec = {flag: True, "since": "x", "reason": "test"}
                write_raw(os.path.join(self.data, name), json.dumps(rec))
                self.assertEqual(fn(), rec)
                self.assertEqual(mmcore.control_problem(name, flag), (rec, None))
                write_raw(os.path.join(self.data, name), json.dumps({flag: False}))
                self.assertEqual(mmcore.control_problem(name, flag), (None, None))
        self.assertEqual(mmcore.control_broken(), [])
        for name, _, _ in self.CASES:
            os.remove(os.path.join(self.data, name))
        self.assertEqual(mmcore.control_broken(), [])

    def test_control_broken_lists_both(self):
        write_raw(os.path.join(self.data, "off.json"), "[]")
        write_raw(os.path.join(self.data, "safe.json"), "{}")
        self.assertEqual(mmcore.control_broken(), ["off.json: not a JSON object", "safe.json: no safe flag"])

    def alert(self, key):
        st = mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {}) or {}
        return (st.get("active") or {}).get(key)

    def test_control_file_broken_alerts_raise_and_clear(self):
        self.act()
        for name, flag in (("off.json", "off"), ("safe.json", "safe")):
            key = "CONTROL_FILE_BROKEN:" + name
            for ending in ("good", "removed"):
                with self.subTest(file=name, ending=ending):
                    target = os.path.join(self.data, name)
                    write_raw(target, "[]")
                    self.sup().tick()
                    a = self.alert(key)
                    self.assertIsNotNone(a, self.active())
                    self.assertEqual((a["name"], a["level"], a["command"]), ("CONTROL_FILE_BROKEN", "ACTION", "mm on"))
                    self.assertEqual(a["text"], "%s: not a JSON object; automatic actions stay off until the file is "
                                     "good again or removed (mm on removes it)" % name)
                    if ending == "good":
                        write_raw(target, json.dumps({flag: False}))
                    else:
                        os.remove(target)
                    self.tick_clear()
                    self.assertIsNone(self.alert(key), "%s cleared when the file is %s" % (key, ending))
                    if os.path.lexists(target):
                        os.remove(target)

    def test_safe_mode_alert_names_the_broken_file(self):
        write_raw(os.path.join(self.data, "safe.json"), '{"safe": 1}')
        self.sup().tick()
        a = self.alert("SAFE_MODE")
        self.assertEqual((a["level"], a["command"]), ("ACTION", "mm on"))
        self.assertEqual(a["text"], "safe mode: safe.json: safe is not true or false; automatic actions stay off")

    def test_good_off_json_raises_no_broken_alert(self):
        write_raw(os.path.join(self.data, "off.json"), json.dumps({"off": True, "since": "x", "reason": "t"}))
        self.sup().tick()
        self.assertIsNotNone(self.alert("OFF"))
        self.assertEqual([a for a in self.active() if a["name"] == "CONTROL_FILE_BROKEN"], [])

    def test_mm_status_broken_line_and_json(self):
        self.act()
        write_raw(os.path.join(self.data, "off.json"), "[]")
        self.sup().tick()
        r = self.mm("status")
        self.assertIn('broken="off.json: not a JSON object"', r.stdout.splitlines(), r.stdout)
        self.assertTrue(r.stdout.splitlines()[0].startswith("state=") and " mode=off " in r.stdout.splitlines()[0])
        obj = json.loads(self.mm("status", "--json").stdout)
        self.assertEqual((obj["broken"], obj["off"], obj["mode"]), (["off.json: not a JSON object"], True, "off"))
        write_raw(os.path.join(self.data, "safe.json"), "{}")
        write_raw(self.paused_file(), "[]")
        self.sup().tick()
        r = self.mm("status")
        self.assertIn('broken="off.json: not a JSON object; safe.json: no safe flag; state/paused.json: not a JSON '
                      'object"', r.stdout.splitlines(), r.stdout)
        self.assertLessEqual(len(r.stdout.splitlines()), 5)
        obj = json.loads(self.mm("status", "--json").stdout)
        self.assertEqual(obj["broken"], ["off.json: not a JSON object", "safe.json: no safe flag",
                                         "state/paused.json: not a JSON object"])

    def test_mm_status_good_files_no_broken(self):
        self.sup().tick()
        r = self.mm("status")
        self.assertFalse([l for l in r.stdout.splitlines() if l.startswith("broken=")], r.stdout)
        self.assertNotIn("broken", json.loads(self.mm("status", "--json").stdout), "the usual output is unchanged")

    def paused_file(self):
        return os.path.join(self.data, "state", "paused.json")

    def calm_act(self, slots):
        test_slots = os.path.join(self.root, "test-slots")
        mmcore.write_slots(test_slots, slots)
        self.act(**{"mode.slot_writes": "test", "mode.slots_file": test_slots})
        clock = {"t": time.time()}
        self.ticks(self.sup(CALM, clock=lambda: clock["t"]), 3, clock)
        return open(test_slots).read()

    def test_control_good_safe_mode_steps_down_once(self):
        """The fixture: a good safe.json (slot_write null) steps 8 slots down to safe_mode.slots (5)."""
        mmrecover.enter_safe("test", time.time())
        self.assertEqual(self.calm_act(8), "5\n")
        self.assertEqual(mmcore.safe_state()["slot_write"], "SET 8 -> 5")

    def test_broken_safe_json_does_not_step_slots_down(self):
        for shape in SOME_BROKEN:
            with self.subTest(shape=shape):
                target = os.path.join(self.data, "safe.json")
                write_raw(target, text_of(shape, "safe"))
                before = raw(target)
                self.assertEqual(self.calm_act(8), "8\n", "no safe-mode step down for a broken safe.json")
                self.assertEqual(raw(target), before)
                self.assertEqual(self.status()["mode"], "safe")

    def test_broken_off_json_decisions_say_would(self):
        write_raw(os.path.join(self.data, "off.json"), "{}")
        test_slots = os.path.join(self.root, "test-slots")
        mmcore.write_slots(test_slots, 6)
        self.act(**{"mode.slot_writes": "test", "mode.slots_file": test_slots})
        clock = {"t": time.time()}
        self.ticks(self.sup(RED, clock=lambda: clock["t"]), 2, clock)
        self.assertIn("WOULD slots", self.decisions())
        self.assertNotIn("SET slots", self.decisions())
        self.assertEqual(self.status()["mode"], "off")

    def test_enter_safe_keeps_a_broken_safe_json(self):
        """The safe-trip path with a broken safe.json: safe mode is already on (the broken record); nothing is
        written over it."""
        target = os.path.join(self.data, "safe.json")
        write_raw(target, '{"safe": "yes"}')
        before = raw(target)
        rec = mmrecover.enter_safe("self-check: test", time.time())
        self.assertEqual(rec["broken"], "safe.json: safe is not true or false")
        self.assertEqual(raw(target), before)
        mmrecover.mark_safe_slot_write("SET 8 -> 5")
        self.assertEqual(raw(target), before, "mark_safe_slot_write never writes over a broken safe.json")
        log = open(os.path.join(self.data, "state", "recovery.log")).read()
        self.assertIn("SAFE MODE trip (self-check: test): safe.json: safe is not true or false is kept as it is; safe "
                      "mode stays on", log)


from test_recovery import Base as _RecoveryBase  # noqa: E402  (its fake launchctl writes a fresh heartbeat)


class F1RestartClearSafe(_RecoveryBase):
    """`mm restart --clear-safe` ends a broken safe.json (a fake launchctl; one restart per test)."""

    def restart_clears(self, shape):
        write_raw(os.path.join(self.data, "safe.json"), text_of(shape, "safe"))
        rc, out, _ = self.run_mm("restart", "--clear-safe", FAKE_HEARTBEAT_PID="4343")
        self.assertEqual((rc, out), (0, ["restart=ok pid=4343 safe=cleared"]))
        self.assertFalse(os.path.lexists(os.path.join(self.data, "safe.json")))
        self.assertIsNone(mmcore.safe_state())

    @mmtest.darwin_only
    def test_restart_clear_safe_ends_a_list_safe_json(self):
        self.restart_clears("list")

    @mmtest.darwin_only
    def test_restart_clear_safe_ends_an_invalid_safe_json(self):
        self.restart_clears("invalid_json")


class F3Pinned(F3PausedBase):
    """PausedBroken, paused_problem, add_paused's result, the log lines, PAUSED_FILE_BROKEN, mm status."""
    ENTRY = "state/paused.json: an entry is not pid -> start time"

    def test_broken_shapes_are_paused_broken(self):
        texts = {"list": "state/paused.json: not a JSON object", "null": "state/paused.json: not a JSON object",
                 "string": "state/paused.json: not a JSON object", "number": "state/paused.json: not a JSON object",
                 "invalid_json": "state/paused.json: cannot be read (JSONDecodeError)",
                 "empty_file": "state/paused.json: cannot be read (JSONDecodeError)"}
        for shape, _ in BROKEN_PAUSED:
            with self.subTest(shape=shape):
                self.broken(shape)
                d = mmrecover.read_paused()
                self.assertIsInstance(d, mmrecover.PausedBroken)
                self.assertTrue(d, "maybe paused: true")
                self.assertEqual(dict(d), {}, "it names no pid")
                self.assertEqual(mmrecover.paused_problem(d), texts[shape])

    def test_wrong_entries_are_paused_broken(self):
        for entry in ({"abc": "x"}, {"0": "x"}, {"-1": "x"}, {"0123": "x"}, {"12345678901": "x"}, {" 12": "x"},
                      {"123": 5}, {"123": ""}, {"123": None}, {"123": ["x"]}, {"123": "x", "abc": "y"}):
            with self.subTest(entry=entry):
                write_raw(self.paused(), json.dumps(entry))
                d = mmrecover.read_paused()
                self.assertIsInstance(d, mmrecover.PausedBroken)
                self.assertEqual(mmrecover.paused_problem(d), self.ENTRY)

    def test_dangling_link(self):
        os.symlink(os.path.join(self.root, "nowhere.json"), self.paused())
        self.assertEqual(mmrecover.paused_problem(mmrecover.read_paused()), "state/paused.json: a dangling link")

    @unittest.skipIf(ROOT, "root reads a mode-000 file")
    def test_unreadable_text(self):
        unreadable(self.paused())
        self.assertEqual(mmrecover.paused_problem(mmrecover.read_paused()),
                         "state/paused.json: cannot be read (PermissionError)")

    def test_good_record_is_a_plain_dict(self):
        for good in ({}, {"123": "Mon Nov  6 20:00:00 2026"}, {"9999999999": "boot:1"}):
            with self.subTest(good=good):
                write_raw(self.paused(), json.dumps(good))
                d = mmrecover.read_paused()
                self.assertNotIsInstance(d, mmrecover.PausedBroken)
                self.assertEqual(d, good)
                self.assertIsNone(mmrecover.paused_problem(d))
        os.remove(self.paused())
        self.assertNotIsInstance(mmrecover.read_paused(), mmrecover.PausedBroken)
        self.assertFalse(mmrecover.read_paused(), "missing: nothing paused")

    def test_add_paused_returns_the_problem_or_none(self):
        before = self.broken("list")
        self.assertEqual(mmrecover.add_paused({"999999": "x"}), "state/paused.json: not a JSON object")
        self.assertEqual(raw(self.paused()), before)
        self.assertIn("PAUSE refused: state/paused.json: not a JSON object; the file is kept, no pid stopped",
                      self.recovery_log())
        os.remove(self.paused())
        self.assertIsNone(mmrecover.add_paused({"999999": "x"}))
        self.assertEqual(mmrecover.read_paused(), {"999999": "x"})

    def recovery_log(self):
        try:
            return open(os.path.join(self.data, "state", "recovery.log")).read()
        except OSError:
            return ""

    def test_resume_logs_the_refusal(self):
        self.broken("invalid_json")
        self.assertEqual(mmrecover.resume_paused("test"), [])
        self.assertIn("RESUME from state/paused.json refused: state/paused.json: cannot be read (JSONDecodeError); no "
                      "pid signalled from it, the file is kept (test)", self.recovery_log())

    @mmtest.needs_proc
    def test_resume_continues_legacy_pids_only_and_keeps_the_file(self):
        """A legacy record (controller.json) still names its pids; the spy sees the SIGCONT and sends nothing."""
        p = subprocess.Popen(["/bin/sleep", "60"])
        self.addCleanup(lambda: (p.kill(), p.wait(5)))
        st = None
        for _ in range(50):
            st = mmrecover.start_time(p.pid)
            if st:
                break
            time.sleep(0.1)
        self.assertTrue(st)
        spy = SignalSpy(self)
        before = self.broken("list")
        self.assertEqual(mmrecover.resume_paused("test", legacy={str(p.pid): st}), [p.pid])
        self.assertEqual(spy.calls, [(p.pid, signal.SIGCONT)])
        self.assertEqual(raw(self.paused()), before)

    def test_supervisor_start_runs_the_resume_path_and_logs(self):
        """mmsuper's start check: a broken file is "maybe paused", so the resume runs (and refuses)."""
        self.broken("list")
        self.sup()
        self.assertIn("RESUME from state/paused.json refused: state/paused.json: not a JSON object; no pid signalled "
                      "from it, the file is kept (start)", self.recovery_log())
        self.assertIn("RESUME pids [] (start)", self.decisions())

    def test_pause_refused_logged_once_per_problem(self):
        self.act(**{"pause_newest_call.enabled": True})
        self.broken("list")
        clock = {"t": time.time()}
        sup = self.sup(CRITICAL, clock=lambda: clock["t"])
        self.ticks(sup, 3, clock)
        line = "PAUSE-REFUSED state/paused.json: not a JSON object; no pause and no resume while it cannot be used"
        self.assertEqual(self.decisions().count(line), 1, self.decisions())
        self.broken("invalid_json")
        self.ticks(sup, 2, clock)
        self.assertEqual(self.decisions().count("PAUSE-REFUSED state/paused.json: cannot be read (JSONDecodeError)"), 1)

    @mmtest.needs_proc
    def test_pauser_refuses_when_the_record_breaks_at_the_last_step(self):
        """Pauser.pause itself: when add_paused finds a broken file, `failed` says so and no pid is stopped."""
        tree = self.launcher_call()
        spy = SignalSpy(self)
        busy = [{"slot": ".slot.1", "pid": tree[0], "since": time.time(), "label": "x"}]
        import mmadapters
        q = mmadapters.queue(self.profile())
        real = mmrecover.read_paused
        calls = {"n": 0}

        def late():  # good at pause()'s first look (self.st), broken when add_paused reads it
            calls["n"] += 1
            return {} if calls["n"] == 1 else mmrecover.PausedBroken("state/paused.json: not a JSON object")
        mmrecover.read_paused = late
        self.addCleanup(setattr, mmrecover, "read_paused", real)
        out = mmsuper.Pauser().pause(busy, q, 30)
        self.assertEqual(out["paused"], [])
        self.assertEqual(out["failed"], "state/paused.json: not a JSON object; no pause while it cannot be used")
        self.assertEqual(spy.calls, [])
        self.assertFalse(os.path.lexists(self.paused()), "nothing written")

    def test_paused_file_broken_alert_raises_and_clears(self):
        self.act()
        self.broken("list")
        self.sup().tick()
        st = mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {})
        a = st["active"].get("PAUSED_FILE_BROKEN")
        self.assertIsNotNone(a, self.active())
        self.assertEqual((a["name"], a["level"], a["command"]),
                         ("PAUSED_FILE_BROKEN", "ACTION", "mm explain PAUSED_FILE_BROKEN"))
        self.assertTrue(a["text"].startswith("state/paused.json: not a JSON object; no new pause, and no pid is "
                                             "continued from it"), a["text"])
        self.assertIn("kill -CONT", a["text"])
        r = self.mm("explain", "PAUSED_FILE_BROKEN")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("state/paused.json: not a JSON object", r.stdout)
        write_raw(self.paused(), "{}")  # good again
        self.tick_clear()
        st = mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {})
        self.assertNotIn("PAUSED_FILE_BROKEN", st["active"], "cleared when the file is good again")

    def test_mm_status_broken_line(self):
        self.broken("list")
        self.sup().tick()
        r = self.mm("status")
        self.assertIn('broken="state/paused.json: not a JSON object"', r.stdout.splitlines(), r.stdout)
        self.assertEqual(json.loads(self.mm("status", "--json").stdout)["broken"],
                         ["state/paused.json: not a JSON object"])



from test_install import SetupBase as _SetupBase  # noqa: E402  (a fake launchctl, a synthetic settings file)


class F3Rollback(_SetupBase):
    @mmtest.darwin_only
    def test_rollback_names_a_broken_paused_json(self):
        self.assertEqual(self.run_mm("install")[0], 0)
        target = os.path.join(self.data, "state", "paused.json")
        write_raw(target, "[]")
        rc, out, _ = self.run_mm("rollback")
        self.assertEqual(rc, 0, out)
        self.assertIn('paused_broken="state/paused.json: not a JSON object" nothing continued from it; inspect it, '
                      'kill -CONT the pids, remove it', out)
        self.assertEqual(raw(target), b"[]")


class F3Watchdog(F3PausedBase):
    """The watchdog's own PAUSED_FILE_BROKEN (key WD:paused-file; coordinator's decision 2026-11-06): raised only when
    the watchdog runs its resume path (supervisor stale, unloaded or stopped), with the supervisor's text and command,
    and the problem in the returned problems. It clears when the file is good or gone, or the supervisor is healthy."""
    KEY = "WD:paused-file"
    TEXT = ("%s; no new pause, and no pid is continued from it: processes it listed may still be stopped; inspect the "
            "file, continue them by hand (kill -CONT PID), then remove it")

    def stopped(self):
        write_raw(os.path.join(self.data, "state", "stopped.json"), json.dumps({"time": time.time()}))

    def healthy(self, now):
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": now, "state": "GREEN"}))

    def check(self, now):
        return mmwatch.check(now, self.s(), self.profile(), restart=False)

    def wd_alert(self):
        st = mmcore.read_json(os.path.join(self.data, "alerts-state.json"), {}) or {}
        return (st.get("active") or {}).get(self.KEY)

    def clear_checks(self, now):
        """Two checks over repeat.clear_after_minutes (a key clears after that long absent)."""
        self.check(now + 1)
        return self.check(now + self.s()["repeat.clear_after_minutes"] * 60 + 5)

    def test_raises_with_a_stopped_supervisor_and_a_broken_file(self):
        spy = SignalSpy(self)
        self.stopped()
        before = self.broken("invalid_json")
        problem = "state/paused.json: cannot be read (JSONDecodeError)"
        probs = self.check(time.time())
        self.assertIn(problem, probs)
        a = self.wd_alert()
        self.assertIsNotNone(a, self.active())
        self.assertEqual((a["name"], a["level"], a["command"]),
                         ("PAUSED_FILE_BROKEN", "ACTION", "mm explain PAUSED_FILE_BROKEN"))
        self.assertEqual(a["text"], self.TEXT % problem)
        self.assertEqual(raw(self.paused()), before)
        self.assertEqual(spy.calls, [])

    def test_raises_with_a_stale_supervisor(self):
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps({"time": now - 3600, "state": "GREEN"}))
        self.broken("list")
        probs = self.check(now)
        self.assertIn("state/paused.json: not a JSON object", probs)
        self.assertIsNotNone(self.wd_alert(), self.active())

    def test_no_watchdog_key_with_a_healthy_supervisor(self):
        now = time.time()
        self.healthy(now)
        self.broken("list")
        probs = self.check(now)
        self.assertIsNone(self.wd_alert(), "no double alert while the supervisor is healthy")
        self.assertFalse([p for p in probs if "paused.json" in p], probs)

    def test_no_watchdog_key_with_a_good_or_missing_file(self):
        self.stopped()
        self.check(time.time())
        self.assertIsNone(self.wd_alert())
        write_raw(self.paused(), "{}")
        self.assertFalse([p for p in self.check(time.time()) if "paused.json" in p])
        self.assertIsNone(self.wd_alert())

    def test_clears_when_the_file_is_good_again(self):
        self.stopped()
        self.broken("list")
        now = time.time()
        self.check(now)
        self.assertIsNotNone(self.wd_alert())
        write_raw(self.paused(), "{}")
        probs = self.clear_checks(now)
        self.assertIsNone(self.wd_alert(), self.active())
        self.assertFalse([p for p in probs if "paused.json" in p], probs)

    def test_clears_when_the_file_is_gone(self):
        self.stopped()
        self.broken("list")
        now = time.time()
        self.check(now)
        self.assertIsNotNone(self.wd_alert())
        os.remove(self.paused())
        self.clear_checks(now)
        self.assertIsNone(self.wd_alert(), self.active())

    def test_clears_when_the_supervisor_is_healthy_again(self):
        self.stopped()
        self.broken("list")
        now = time.time()
        self.check(now)
        self.assertIsNotNone(self.wd_alert())
        os.remove(os.path.join(self.data, "state", "stopped.json"))
        clear_at = now + self.s()["repeat.clear_after_minutes"] * 60 + 5
        self.healthy(now + 1)
        self.check(now + 1)
        self.healthy(clear_at)
        self.check(clear_at)
        self.assertIsNone(self.wd_alert(), "the supervisor's own PAUSED_FILE_BROKEN takes over: %s" % self.active())

    def test_mm_watchdog_lists_the_problem(self):
        self.stopped()
        self.broken("list")
        r = self.mm("watchdog", "--no-restart", env={"MM_NOW": str(time.time())})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('problem="state/paused.json: not a JSON object"', r.stdout)


class F2Pinned(F2Base):
    """Refusals are KEEP lines with guard "refused: ..."; a refused slot_dir gives exactly one line."""

    def refusals(self, run):
        return [x for x in self.recs(run) if x["verb"] == "KEEP" and x["guard"].startswith("refused: ")]

    def test_absolute_slot_dir_one_refusal_line(self):
        make(os.path.join(self.outside, "01"))
        make(os.path.join(self.outside, "02"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": self.outside, "files": []}])
        recs = self.recs(r)
        self.assertEqual(len(recs), 1, r.lines)
        self.assertEqual(len(self.refusals(r)), 1, r.lines)

    def test_dotdot_slot_dir_one_refusal_line(self):
        make(os.path.join(self.outside, "01"))
        make(os.path.join(self.outside, "02"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": "../outside", "files": []}])
        self.assertEqual(len(self.recs(r)), 1, r.lines)
        self.assertEqual(len(self.refusals(r)), 1, r.lines)

    def guards(self, run):
        return [x["guard"] for x in self.recs(run)]

    def test_guard_texts(self):
        victim = self.old_file(os.path.join(self.outside, "victim.log"))
        self.old_file(os.path.join(self.outside, "old.log"))
        os.makedirs(os.path.join(self.data, "a"))
        os.symlink(self.outside, os.path.join(self.data, "linkdir"))
        os.symlink(victim, os.path.join(self.data, "metrics.csv.1"))
        cases = [(victim, "refused: files name is an absolute name"),
                 ("../outside/victim.log", "refused: files name is a name that leaves the data folder"),
                 ("a/../../outside/victim.log", "refused: files name is a name that leaves the data folder"),
                 ("", "refused: files name is an empty name"),
                 (".", "refused: files name is a name that leaves the data folder"),
                 ("state/..", "refused: files name is a name that leaves the data folder"),
                 ("linkdir/old.log", "refused: files name is a link inside the data folder: %s"
                  % os.path.join(os.path.realpath(self.data), "linkdir")),
                 ("metrics.csv.1", "refused: files name is a link inside the data folder: %s"
                  % os.path.join(os.path.realpath(self.data), "metrics.csv.1"))]
        for name, guard in cases:
            with self.subTest(name=name):
                r = self.run_rules([{"id": "S1", "type": "own_files", "files": [name]}])
                self.assertEqual(self.guards(r), [guard], r.lines)
        for slot_dir, guard in ((self.outside, "refused: slot_dir is an absolute name"),
                                ("../outside", "refused: slot_dir is a name that leaves the data folder"),
                                ("", "refused: slot_dir is an empty name")):
            with self.subTest(slot_dir=slot_dir):
                r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": slot_dir, "files": []}])
                self.assertEqual(self.guards(r), [guard], r.lines)
        self.assertTrue(os.path.exists(victim))

    def test_one_keep_line_per_refused_name(self):
        victim = self.old_file(os.path.join(self.outside, "victim.log"))
        good = self.old_file(os.path.join(self.data, "metrics.csv.1"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "slot_dir": "../outside",
                             "files": [victim, "../x", "", "metrics.csv.1"]}])
        verbs = [x["verb"] for x in self.recs(r)]
        self.assertEqual(sorted(verbs), ["DELETE", "KEEP", "KEEP", "KEEP", "KEEP"], r.lines)
        self.assertEqual(len(self.refusals(r)), 4)
        self.assertFalse(os.path.lexists(good))
        self.assertTrue(os.path.exists(victim))

    def test_wrong_type_files_deletes_nothing(self):
        """done2: files = "abc" (a text, not a list) must not mean the names "a", "b", "c"."""
        for files in ("abc", 5, {"a": 1}, None, True):
            with self.subTest(files=files):
                for n in ("a", "b", "c", "abc"):
                    self.old_file(os.path.join(self.data, n))
                r = self.run_rules([{"id": "S1", "type": "own_files", "files": files}])
                for n in ("a", "b", "c", "abc"):
                    self.assertTrue(os.path.exists(os.path.join(self.data, n)), (files, n, r.lines))
                self.assertEqual([x for x in self.recs(r) if x["verb"] != "KEEP"], [], r.lines)
                self.assertIn("refused: files is not a list of names", self.guards(r), r.lines)

    def test_wrong_type_name_inside_files_is_refused(self):
        good = self.old_file(os.path.join(self.data, "metrics.csv.1"))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": [5, None, ["x"], "metrics.csv.1"]}])
        self.assertFalse(os.path.lexists(good), "the good name still runs")
        self.assertEqual(sorted(x["verb"] for x in self.recs(r)), ["DELETE", "KEEP", "KEEP", "KEEP"], r.lines)

    def test_wrong_type_slot_dir_or_pattern_gives_no_slot_candidates(self):
        """done2: slot_dir or slot_pattern of the wrong type: no slot is deleted (the default evidence slots too)."""
        ev = make(os.path.join(self.data, "evidence", "01"))
        for key, value in (("slot_dir", 5), ("slot_dir", ["evidence"]), ("slot_dir", None),
                           ("slot_pattern", 5), ("slot_pattern", ["[0-9][0-9]"]), ("slot_pattern", None)):
            with self.subTest(key=key, value=value):
                r = self.run_rules([{"id": "S1", "type": "own_files", key: value, "files": []}])
                self.assertTrue(os.path.exists(ev), r.lines)
                self.assertEqual([x for x in self.recs(r) if x["verb"] != "KEEP"], [], r.lines)
                self.assertTrue([g for g in self.guards(r) if g.startswith("refused: %s" % key)], r.lines)

    def profile_with(self, rule_toml):
        prof = os.path.join(self.root, "profile.toml")
        with open(mmtest.PROFILE) as f:
            text = f.read()
        with open(prof, "w") as f:
            f.write(text + "\n[[deletes.rules]]\n" + rule_toml)
        self.queue_dir()
        return prof

    def check_lines(self, prof):
        r = self.mm("check", "--profile", prof)
        return r.returncode, [l for l in r.stdout.splitlines() if l.startswith("E_PROFILE deletes rule")]

    def test_mm_check_lists_each_bad_name(self):
        prof = self.profile_with('id = "S1"\ntype = "own_files"\nslot_dir = "/abs"\n'
                                 'files = ["/abs/x", "../y", "", "metrics.csv.1", "state/decisions.log.1"]\n')
        rc, lines = self.check_lines(prof)
        fix = "; fix: use a name relative to the data folder, inside it"
        self.assertEqual(lines, ['E_PROFILE deletes rule S1: slot_dir "/abs" is an absolute name' + fix,
                                 'E_PROFILE deletes rule S1: files "/abs/x" is an absolute name' + fix,
                                 'E_PROFILE deletes rule S1: files "../y" is a name that leaves the data folder' + fix,
                                 'E_PROFILE deletes rule S1: files "" is an empty name' + fix])
        self.assertEqual(rc, 1)

    def test_mm_check_good_names_no_line(self):
        prof = self.profile_with('id = "S1"\ntype = "own_files"\n'
                                 'files = ["metrics.csv.1", "alerts.jsonl.1", "deletes.log.1", "state/decisions.log.1"]\n')
        self.assertEqual(self.check_lines(prof)[1], [])

    def test_mm_check_wrong_types(self):
        """done2: files, slot_dir or slot_pattern of the wrong type is an E_PROFILE line each."""
        for key, value in (("files", '"abc"'), ("slot_dir", "5"), ("slot_pattern", "5")):
            with self.subTest(key=key):
                prof = self.profile_with('id = "S1"\ntype = "own_files"\n%s = %s\n' % (key, value))
                rc, lines = self.check_lines(prof)
                self.assertTrue([l for l in lines if l.startswith("E_PROFILE deletes rule S1: %s" % key)], lines)
                self.assertEqual(rc, 1)

    def test_refused_file_names_have_refused_guards(self):
        victim = self.old_file(os.path.join(self.outside, "victim.log"))
        os.makedirs(os.path.join(self.data, "a"))
        self.old_file(os.path.join(self.outside, "old.log"))
        os.symlink(self.outside, os.path.join(self.data, "linkdir"))
        for name in (victim, "../outside/victim.log", "a/../../outside/victim.log", "", "linkdir/old.log"):
            with self.subTest(name=name):
                r = self.run_rules([{"id": "S1", "type": "own_files", "files": [name]}])
                self.assertEqual(len(self.refusals(r)), 1, r.lines)
                self.assertTrue(os.path.exists(victim))


if __name__ == "__main__":
    unittest.main()
