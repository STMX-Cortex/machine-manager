# SPDX-License-Identifier: Apache-2.0
"""Setup on a temporary HOME with a fake launchctl and a synthetic Claude Code settings file: init, check, install
(twice: idempotent), stop, start, rollback (the settings file returns to its first content). Never the real ones."""
import json
import os
import plistlib
import shutil
import stat
import subprocess
import unittest

import mmtest
from mmtest import TempData

THEIRS = {"permissions": {"allow": ["Bash(ls:*)"]},
          "hooks": {"SessionStart": [{"matcher": "*", "hooks": [{"type": "command", "command": "their-start-hook"}]}],
                    "PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "their-post-hook"}]}]}}


class SetupBase(TempData):
    def setUp(self):
        super().setUp()
        self.queue_dir()
        self.calls = os.path.join(self.root, "launchctl.txt")
        fake = os.path.join(self.root, "launchctl.sh")
        with open(fake, "w") as f:
            f.write('#!/bin/sh\necho "$@" >> %s\nexit 0\n' % self.calls)
        os.chmod(fake, stat.S_IRWXU)
        self.env = {"MM_LAUNCHCTL": fake}
        self.hooks_file = os.path.join(self.data, "claude-settings.json")
        with open(self.hooks_file, "w") as f:
            json.dump(THEIRS, f, indent=2)
        self.agents = os.path.join(self.root, "home", "Library", "LaunchAgents")

    def run_mm(self, *args):
        r = self.mm(*args, env=self.env)
        return r.returncode, r.stdout.strip().splitlines(), r.stderr

    def launchctl(self):
        try:
            return [l.split() for l in open(self.calls).read().splitlines()]
        except OSError:
            return []


class Setup(SetupBase):
    @mmtest.darwin_only
    def test_install_stop_start_rollback(self):
        uid = os.getuid()
        sup, wd = "com.example.machine-manager-test", "com.example.machine-manager-test-watchdog"
        rc, out, err = self.run_mm("install")
        self.assertEqual(rc, 0, out + [err])
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].startswith("installed=yes data="), out)
        self.assertTrue(out[0].endswith("plists=2"))
        for label, keep in ((sup, True), (wd, False)):
            p = plistlib.load(open(os.path.join(self.agents, label + ".plist"), "rb"))
            self.assertEqual(p["Label"], label)
            self.assertEqual(p["ProgramArguments"][-2:] if keep else p["ProgramArguments"][-1:],
                             ["run", "--allow-live-slots"] if keep else ["watchdog"])
            self.assertEqual(p["EnvironmentVariables"]["MM_DATA"], self.data)
            self.assertEqual(p.get("KeepAlive", False), keep)
            self.assertEqual(p.get("StartInterval"), None if keep else 60)
        self.assertEqual(self.launchctl(), [["bootout", "gui/%d/%s" % (uid, sup)], ["bootstrap", "gui/%d" % uid,
                         os.path.join(self.agents, sup + ".plist")], ["bootout", "gui/%d/%s" % (uid, wd)],
                         ["bootstrap", "gui/%d" % uid, os.path.join(self.agents, wd + ".plist")]])
        doc = json.load(open(self.hooks_file))
        self.assertEqual(doc["permissions"], THEIRS["permissions"])
        ours = [h["command"] for ev in doc["hooks"].values() for g in ev for h in g["hooks"] if " hook --event " in h["command"]]
        self.assertEqual(len(ours), 4)
        self.assertTrue(all(h.startswith("MM_PROFILE=") for h in ours))
        self.assertIn("their-start-hook", json.dumps(doc))
        backups = [f for f in os.listdir(self.data) if f.startswith("claude-settings.json.bak-before-machine-manager-")]
        self.assertEqual(len(backups), 1)
        self.assertEqual(json.load(open(os.path.join(self.data, backups[0]))), THEIRS)
        rec = json.load(open(os.path.join(self.root, "base", "install.json")))
        self.assertEqual((rec["data"], rec["hooks_file"]), (self.data, self.hooks_file))

        rc, out, _ = self.run_mm("install")
        self.assertEqual(rc, 0)
        doc2 = json.load(open(self.hooks_file))
        self.assertEqual(doc2, doc, "a second install changes nothing: no doubled hook entries")

        open(self.calls, "w").close()
        rc, out, _ = self.run_mm("stop", "--reason", "test")
        self.assertEqual((rc, out), (0, ["%s=rc0 %s=rc0" % (wd, sup)]), "the watchdog stops first")
        self.assertTrue(os.path.exists(os.path.join(self.data, "state", "stopped.json")))
        self.assertEqual([(r["name"], r["level"], r["command"]) for r in self.pushed()], [("STOPPED", "ATTENTION", "mm start")])
        rc, out, _ = self.run_mm("start")
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(os.path.join(self.data, "state", "stopped.json")))
        self.assertEqual([r["why"] for r in self.pushed()], ["new", "cleared"])

        rc, out, _ = self.run_mm("rollback")
        self.assertEqual(rc, 0)
        self.assertEqual([l.split("=")[0] for l in out], ["removed", "removed", "hooks_removed", "restart_by_hand"])
        self.assertEqual(out[-1], "restart_by_hand=restart the old guard by hand")
        self.assertEqual(json.load(open(self.hooks_file)), THEIRS, "rollback returns the settings file to its first content")
        self.assertEqual([f for f in os.listdir(self.agents) if f.endswith(".plist")], [])
        self.assertFalse(os.path.exists(os.path.join(self.root, "base", "install.json")))
        self.assertTrue(os.path.isdir(self.data), "the data folder stays")

    def test_backups_never_overwrite(self):
        import mminstall
        names = [mminstall.backup(self.hooks_file) for _ in range(3)]
        self.assertEqual(len(set(names)), 3, names)
        self.assertTrue(all(open(n).read() == open(self.hooks_file).read() for n in names))

    @mmtest.darwin_only
    def test_rollback_restores_exact_bytes_and_keeps_later_edits(self):
        odd = '{\n    "permissions" : {"allow": ["Bash(ls:*)"]},\n    "hooks": {}\n}\n'
        with open(self.hooks_file, "w") as f:
            f.write(odd)
        self.assertEqual(self.run_mm("install")[0], 0)
        rc, out, _ = self.run_mm("rollback")
        self.assertEqual(rc, 0)
        self.assertTrue(any("restored=" in l for l in out), out)
        self.assertEqual(open(self.hooks_file).read(), odd, "the same bytes as before the install")
        self.assertEqual(self.run_mm("install")[0], 0)
        doc = json.load(open(self.hooks_file))
        doc["permissions"]["allow"].append("Bash(pwd)")  # an edit by the owner after the install
        with open(self.hooks_file, "w") as f:
            json.dump(doc, f)
        rc, out, _ = self.run_mm("rollback")
        after = json.load(open(self.hooks_file))
        self.assertEqual(after["permissions"]["allow"], ["Bash(ls:*)", "Bash(pwd)"], "the later edit stays")
        self.assertNotIn(" hook --event ", json.dumps(after))

    @mmtest.darwin_only
    def test_install_refuses_without_observe_and_on_a_differing_settings_file(self):
        self.write_settings(**{"mode.observe": False})
        rc, out, _ = self.run_mm("install")
        self.assertEqual(rc, 2)
        self.assertEqual(out, ["E_SETTINGS mode.observe is false; fix: install in observe mode first (mode.observe = true)"])
        self.assertFalse(os.path.exists(self.agents))
        src = os.path.join(self.root, "other.toml")
        with open(src, "w") as f:
            f.write("[slots]\nfloor = 2\n")
        rc, out, _ = self.run_mm("install", "--settings", src)
        self.assertEqual(rc, 2)
        self.assertTrue(out[0].startswith("E_EXISTS "), out)
        self.assertEqual(json.load(open(self.hooks_file)), THEIRS)

    @mmtest.darwin_only
    def test_install_refuses_a_broken_hooks_file(self):
        with open(self.hooks_file, "w") as f:
            f.write("[1, 2]")
        rc, out, _ = self.run_mm("install")
        self.assertEqual(rc, 2)
        self.assertTrue(out[0].startswith("E_HOOKS "), out)
        self.assertEqual(open(self.hooks_file).read(), "[1, 2]")

    def test_init_and_check(self):
        d = os.path.join(self.root, "profiles")
        r = self.mm("init", "--profile", "lab1", "--dir", d, env={"MM_DATA": os.path.join(self.root, "lab-data")})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        lines = r.stdout.strip().splitlines()
        self.assertEqual(lines[0], "profile=%s data=%s" % (os.path.join(d, "lab1.toml"), os.path.join(self.root, "lab-data")))
        self.assertTrue(lines[1].startswith("next="))
        r = self.mm("init", "--profile", "lab1", "--dir", d)
        self.assertEqual((r.returncode, r.stdout.split()[0]), (2, "E_EXISTS"))
        r = self.mm("init", "--profile", "bad name!", "--dir", d)
        self.assertEqual((r.returncode, r.stdout.split()[0]), (2, "E_USAGE"))
        r = self.mm("check", "--profile", os.path.join(d, "lab1.toml"), "--data", os.path.join(self.root, "lab-data"))
        self.assertEqual(mmtest.without_platform(r.stdout.strip().splitlines()), ["check=ok"], r.stdout)
        self.assertEqual(r.returncode, 0)
        r = self.mm("check")
        self.assertEqual((r.returncode, mmtest.without_platform(r.stdout.strip().splitlines())), (0, ["check=ok"]),
                         "the test profile is valid")
        bad = os.path.join(self.root, "bad.toml")
        with open(bad, "w") as f:
            f.write('name = "bad"\n[queue]\nadapter = "nope"\ndir = "/nonexistent-q"\n')
        r = self.mm("check", "--profile", bad)
        self.assertEqual(r.returncode, 1)
        lines = mmtest.without_platform(r.stdout.strip().splitlines())
        self.assertTrue(lines and all(l.startswith("E_") and "; fix: " in l for l in lines), lines)
        self.assertTrue(any("queue.adapter" in l or "nope" in l for l in lines), lines)

    def test_example_profile_checks(self):
        r = self.mm("check", "--profile", os.path.join(mmtest.CODE, "profiles", "example.toml"))
        lines = mmtest.without_platform(r.stdout.strip().splitlines())
        self.assertEqual([l for l in lines if not l.startswith(("E_PROFILE queue.dir not found",
                                                                 "E_COMMAND /opt/example/"))], [],
                         "the example is valid except its made-up queue folder and tools")


CELLAR_PY = "/opt/homebrew/Cellar/python@3.14/3.14.0/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
# Run bin/mm in this interpreter, but with sys.executable set to argv[1] (the path the LaunchAgents would run).
AS_PYTHON = ("import runpy, sys; sys.executable = sys.argv[1]; sys.argv = [sys.argv[2]] + sys.argv[3:]; "
             "runpy.run_path(sys.argv[0], run_name='__main__')")


def old_python():
    """A real Python older than 3.11 on this machine, or None (Apple's Command Line Tools ship 3.9)."""
    for p in ["/Library/Developer/CommandLineTools/usr/bin/python3"] + [shutil.which("python3.%d" % n) or ""
                                                                         for n in (10, 9, 8)]:
        if p and os.access(p, os.X_OK):
            try:
                r = subprocess.run([p, "-I", "-c", "import sys; print(sys.version_info[1])"], capture_output=True,
                                   text=True, timeout=20)
                if r.returncode == 0 and r.stdout.strip().isdigit() and int(r.stdout) < 11:
                    return p
            except (OSError, subprocess.TimeoutExpired):
                pass
    return None


class Interpreter(SetupBase):
    def test_interpreter_problems(self):
        import mminstall
        self.assertEqual(mminstall.interpreter_problems("/opt/homebrew/bin/python3", (3, 12, 1)), [])
        self.assertEqual(mminstall.interpreter_problems("/opt/homebrew/opt/python@3.14/bin/python3.14", (3, 14, 0)), [])
        old = mminstall.interpreter_problems("/usr/bin/python3", (3, 9, 6))
        self.assertEqual(len(old), 1)
        self.assertTrue(old[0].startswith("E_PYTHON python 3.9 at /usr/bin/python3 is older than 3.11; fix: "), old)
        w = mminstall.interpreter_problems(CELLAR_PY, (3, 14, 0))
        self.assertEqual(len(w), 1)
        self.assertTrue(w[0].startswith("W_PYTHON %s goes away at an upgrade; fix: " % CELLAR_PY), w)
        self.assertIn("mm install again", w[0])
        both = mminstall.interpreter_problems("/x/Cellar/python@3.10/3.10.4/bin/python3", (3, 10, 4))
        self.assertEqual([x.split()[0] for x in both], ["E_PYTHON", "W_PYTHON"])
        self.assertTrue(all(len(x) <= 200 for x in old + both), "short paths give lines of at most 200 characters")

    def as_python(self, exe, *args):
        e = dict(os.environ)
        e.update(self.env)
        r = subprocess.run(mmtest.MM[:2] + ["-c", AS_PYTHON, exe, mmtest.MM[-1]] + list(args), capture_output=True,
                           text=True, timeout=60, env=e)
        return r.returncode, r.stdout.strip().splitlines(), r.stderr

    def test_check_and_install_warn_on_a_versioned_interpreter(self):
        rc, out, err = self.as_python(CELLAR_PY, "check")
        self.assertEqual(rc, 0, out + [err])
        out = mmtest.without_platform(out)
        self.assertEqual(len(out), 2, out)
        self.assertTrue(out[0].startswith("W_PYTHON "), out)
        self.assertEqual(out[1], "check=ok")
        if not mmtest.mmplat.DARWIN:  # install is launchd's: it refuses here (tests/test_platform.py)
            return
        rc, out, err = self.as_python(CELLAR_PY, "install")
        self.assertEqual(rc, 0, out + [err])
        self.assertIn("python=%s" % CELLAR_PY, out[0])
        self.assertTrue(out[1].startswith("W_PYTHON "), out)
        p = plistlib.load(open(os.path.join(self.agents, "com.example.machine-manager-test.plist"), "rb"))
        self.assertEqual(p["ProgramArguments"][0], CELLAR_PY, "the warning names the path the jobs run")

    def test_old_python_refused_and_the_hook_stays_silent(self):
        py = old_python()
        if not py:
            self.skipTest("no Python older than 3.11 on this machine")
        e = dict(os.environ)
        e.update(self.env)
        for args in (["status"], ["check"], ["install"]):
            r = subprocess.run([py, "-I", mmtest.MM[-1]] + args, capture_output=True, text=True, timeout=60, env=e)
            self.assertEqual(r.returncode, 2, (args, r.stdout, r.stderr))
            self.assertTrue(r.stdout.startswith("E_PYTHON python 3."), r.stdout)
            self.assertEqual(r.stderr, "")
        r = subprocess.run([py, "-I", mmtest.MM[-1], "hook", "--event", "PreToolUse"], input="{}", capture_output=True,
                           text=True, timeout=60, env=e)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""), "a hook never blocks and never errs")
        self.assertFalse(os.path.exists(self.agents), "nothing installed")


if __name__ == "__main__":
    unittest.main()
