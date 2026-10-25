# SPDX-License-Identifier: Apache-2.0
"""T14: each SAFE-AUTO rule type on a fixture tree, with real lsof and real live processes where the guard depends on
them; T15: forbidden and protected paths survive with deletes on, and the cleanup list only lists.
Every fixture lives in a temporary folder that the test removes."""
import json
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import mmtest
from mmtest import TempData, base_settings, mmcore
import mmdelete
import mmsuper
import ad_queue_fifo

LIVE = {"names": ["go", "test2json"], "suffixes": [".test"], "path_regexes": []}
OLD = time.time() - 30 * 86400


def age(path, when=OLD):
    """Set the times of path and everything under it."""
    for d, dirs, files in os.walk(path):
        for n in dirs + files:
            os.utime(os.path.join(d, n), (when, when), follow_symlinks=False)
    os.utime(path, (when, when), follow_symlinks=False)


def make(path, files=("a.o",), when=OLD):
    os.makedirs(path, exist_ok=True)
    for f in files:
        with open(os.path.join(path, f), "w") as fh:
            fh.write("x" * 4096)
    age(path, when)
    return path


class Base(TempData):
    def setUp(self):
        super().setUp()
        self.tmp = os.path.join(self.root, "t")
        os.makedirs(self.tmp)
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            p.kill()
            p.wait(5)
        super().tearDown()

    def named(self, name, cwd=None):
        """A live process whose program name is `name` (a link to /bin/sleep)."""
        d = tempfile.mkdtemp(prefix="bin-", dir=self.root)
        exe = os.path.join(d, name)
        os.symlink("/bin/sleep", exe)
        p = subprocess.Popen([exe, "60"], cwd=cwd)
        self.procs.append(p)
        time.sleep(0.3)
        return p

    def ctx(self, rules, cleanup=(), forbidden=(".records", ".ssh"), protected=()):
        cfg = {"rules": list(rules), "cleanup": list(cleanup), "forbidden_parts": list(forbidden),
               "protected_roots": list(protected)}
        return mmdelete.Ctx(cfg, extra={"t": self.tmp, "user_tmp": self.tmp}, data=self.data)

    def run_rules(self, rules, enabled=True, procs=None, **kw):
        r = mmdelete.Run(base_settings(**{"deletes.lsof_timeout_s": 60}), self.ctx(rules, **kw), enabled=enabled,
                         procs=procs or (lambda: []), live_spec=LIVE, mid="m1")
        r.all()
        return r

    def verbs(self, run):
        """{basename: (verb, guard)}; every line parses and matches the delete-line schema."""
        import mmschema
        out = {}
        for l in run.lines:
            rec = mmcore.parse_delete_line(l)
            self.assertIsNotNone(rec, l)
            self.assertEqual(mmschema.validate(rec, mmschema.load("delete-line")), [], l)
            out[os.path.basename(rec["path"])] = (rec["verb"], rec["guard"])
        return out


FOLDERS = {"id": "S2", "type": "folders", "roots": ["{t}"], "patterns": ["go-build*"], "dirs_only": True,
           "age_minutes": 360, "no_live_tools": True}


class T14Folders(Base):
    def test_old_go_build_goes_young_and_marked_stay(self):
        make(os.path.join(self.tmp, "go-build111"))
        make(os.path.join(self.tmp, "go-build222"), when=time.time() - 60)
        make(os.path.join(self.tmp, "go-build333"), files=("a.o", ".keep"))
        make(os.path.join(self.tmp, "other-dir"))
        os.symlink(os.path.join(self.tmp, "other-dir"), os.path.join(self.tmp, "go-build-link"))
        with open(os.path.join(self.tmp, "go-build-file"), "w") as f:
            f.write("x")
        age(os.path.join(self.tmp, "go-build-file"))
        r = self.run_rules([FOLDERS])
        v = self.verbs(r)
        self.assertEqual(v["go-build111"][0], "DELETE")
        self.assertIn("lsof=empty live_tools=none", v["go-build111"][1])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "go-build111")))
        self.assertNotIn("go-build222", v, "a young item has no line of its own")
        self.assertEqual(v["t"], ("KEEP", "young: 1 entries changed within 360 min"))
        self.assertEqual(v["go-build333"], ("KEEP", ".keep"))
        self.assertNotIn("go-build-link", v, "dirs_only: a link is not a candidate")
        self.assertNotIn("go-build-file", v)
        for n in ("go-build222", "go-build333", "other-dir", "go-build-link", "go-build-file"):
            self.assertTrue(os.path.lexists(os.path.join(self.tmp, n)), n)
        self.assertGreater(r.freed, 0)
        line = [l for l in r.lines if "go-build111" in l][0]
        self.assertTrue(line.endswith(" machine=m1 v=1"))
        self.assertRegex(line, r" bytes=\d+ ")

    def test_disabled_only_logs_would(self):
        make(os.path.join(self.tmp, "go-build111"))
        r = self.run_rules([FOLDERS], enabled=False)
        self.assertEqual(self.verbs(r)["go-build111"][0], "WOULD-DELETE")
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "go-build111")))
        self.assertGreater(r.would, 0)

    def test_a_process_working_inside_keeps_it(self):
        d = make(os.path.join(self.tmp, "go-build444"))
        p = subprocess.Popen(["/bin/sleep", "60"], cwd=d)
        self.procs.append(p)
        time.sleep(0.3)
        age(d)
        v = self.verbs(self.run_rules([FOLDERS]))
        self.assertEqual(v["go-build444"][0], "KEEP")
        self.assertIn("lsof=pids %d" % p.pid, v["go-build444"][1])
        self.assertTrue(os.path.exists(d))

    def test_a_live_build_tool_keeps_it(self):
        make(os.path.join(self.tmp, "go-build555"))
        self.named("go")
        from mmread import read_ps
        v = self.verbs(self.run_rules([FOLDERS], procs=read_ps))
        self.assertEqual(v["go-build555"][0], "KEEP")
        self.assertIn("live_tools=", v["go-build555"][1])
        self.assertIn(":go", v["go-build555"][1])

    def test_a_held_unix_socket_keeps_it(self):
        short = tempfile.mkdtemp(prefix="mms", dir="/tmp")  # a socket path must stay under 104 bytes
        self.addCleanup(shutil.rmtree, short, True)
        d = os.path.join(short, "go-build666")
        os.makedirs(d)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(os.path.join(d, "s"))
        srv.listen(1)
        self.addCleanup(srv.close)
        age(d)
        rule = dict(FOLDERS, roots=[short])
        v = self.verbs(self.run_rules([rule]))
        self.assertEqual(v["go-build666"][0], "KEEP", v)
        if sys.platform == "darwin":
            self.assertIn("unix socket of pid %d" % os.getpid(), v["go-build666"][1])
        else:  # Linux lsof +D already names the socket's holder: the first lsof step keeps it
            self.assertTrue(re.search(r"unix socket of pid %d\b|lsof=pids (\d+,)*%d\b" % (os.getpid(), os.getpid()),
                                      v["go-build666"][1]), v["go-build666"][1])
        self.assertTrue(os.path.exists(d))

    def test_forbidden_inside_and_protected_survive_with_deletes_on(self):
        """T15."""
        make(os.path.join(self.tmp, "go-build777", ".records", "x"))
        age(os.path.join(self.tmp, "go-build777"))
        prot = os.path.join(self.root, "prot")
        make(os.path.join(prot, "go-build888"))
        make(os.path.join(prot, ".ssh", "go-build999"))
        rules = [FOLDERS, dict(FOLDERS, id="P", roots=[prot]), dict(FOLDERS, id="Q", roots=[os.path.join(prot, ".ssh")])]
        v = self.verbs(self.run_rules(rules, protected=[prot]))
        self.assertEqual(v["go-build777"][0], "KEEP")
        self.assertIn("protected", v["go-build777"][1])
        self.assertEqual(v["go-build888"], ("KEEP", "forbidden path (protected)"))
        self.assertEqual(v["go-build999"], ("KEEP", "forbidden path (protected)"))
        for p in (os.path.join(self.tmp, "go-build777", ".records", "x"), os.path.join(prot, "go-build888"),
                  os.path.join(prot, ".ssh", "go-build999")):
            self.assertTrue(os.path.exists(p), p)


class T14Other(Base):
    def test_own_files(self):
        ev = os.path.join(self.data, "evidence")
        make(os.path.join(ev, "01"))
        make(os.path.join(ev, "02"), when=time.time())
        make(os.path.join(ev, "xx"))
        for n in ("metrics.csv.1", "metrics.csv"):
            with open(os.path.join(self.data, n), "w") as f:
                f.write("x")
            age(os.path.join(self.data, n))
        r = self.run_rules([{"id": "S1", "type": "own_files", "files": ["metrics.csv.1"]}])
        v = self.verbs(r)
        self.assertEqual(v["01"][0], "DELETE")
        self.assertEqual(v["02"][0], "KEEP")
        self.assertEqual(v["metrics.csv.1"][0], "DELETE")
        self.assertNotIn("xx", v)
        self.assertNotIn("metrics.csv", v)
        self.assertTrue(os.path.exists(os.path.join(self.data, "metrics.csv")))
        self.assertTrue(os.path.exists(os.path.join(ev, "xx")))

    def cache(self):
        c = os.path.join(self.tmp, "cache")
        os.makedirs(c)
        with open(os.path.join(c, "README"), "w") as f:
            f.write("This directory holds cached Go build artifacts.\n")
        make(os.path.join(c, "0a"), files=("old-a", "old-b"))
        with open(os.path.join(c, "0a", "young"), "w") as f:
            f.write("y")
        make(os.path.join(c, "zz"), files=("not-an-entry",))
        return c

    def test_cache_entries(self):
        c = self.cache()
        rule = {"id": "S5", "type": "cache_entries", "cache": c, "marker_file": "README", "marker_text": "Go build",
                "age_minutes": 2880, "no_live_tools": True}
        r = self.run_rules([rule])
        self.assertEqual(sorted(os.listdir(os.path.join(c, "0a"))), ["young"])
        self.assertTrue(os.path.exists(os.path.join(c, "zz", "not-an-entry")))
        self.assertIn("entries=2", r.lines[0])
        self.assertTrue(r.lines[0].split(" ")[2] == "DELETE")
        make(os.path.join(c, "0b"), files=("old-c",))
        from mmread import read_ps
        self.named("go")
        r = self.run_rules([rule], procs=read_ps)
        self.assertEqual(r.lines[0].split(" ")[2], "KEEP")
        self.assertIn("live_tools", r.lines[0])
        self.assertTrue(os.path.exists(os.path.join(c, "0b", "old-c")))
        r = self.run_rules([dict(rule, marker_text="something else")])
        self.assertEqual(r.lines, [], "not the expected cache: nothing")

    def test_app_folders(self):
        base = os.path.join(self.tmp, "App")
        make(os.path.join(base, "Derived", "proj-1"))
        make(os.path.join(base, "Derived", "proj-2"), when=time.time())
        make(os.path.join(base, "iOS DeviceSupport", "17.0"), when=time.time() - 100 * 86400)
        rule = {"id": "S6", "type": "app_folders", "app": "AppX", "base": base,
                "while_closed": {"dir": "Derived", "age_minutes": 20160},
                "any_time": {"dir_pattern": "* DeviceSupport", "age_minutes": 129600}, "command": ["/usr/bin/true"]}
        v = self.verbs(self.run_rules([rule], procs=lambda: [{"pid": 9, "ppid": 1, "comm": "/Applications/AppX"}],
                                      enabled=False))
        self.assertEqual(v["Derived"], ("KEEP", "AppX is running: left alone"))
        self.assertEqual(v["17.0"][0], "WOULD-DELETE")
        self.assertTrue(any(" WOULD-RUN rule=S6 " in l for l in self.run_rules([rule], enabled=False).lines))
        r = self.run_rules([rule])
        v = self.verbs(r)
        self.assertEqual((v["proj-1"][0], v["17.0"][0]), ("DELETE", "DELETE"))
        self.assertEqual(v["Derived"], ("KEEP", "young: 1 entries changed within 20160 min"))
        self.assertIn('path="%s"' % os.path.join(base, "iOS DeviceSupport", "17.0"), "\n".join(r.lines), "a path with a space is quoted")
        ran = [l for l in r.lines if " RAN rule=S6 " in l]
        self.assertEqual(len(ran), 1)
        self.assertIn("rc=0", ran[0])

    def test_command_per_dir(self):
        d1 = make(os.path.join(self.tmp, "c1"))
        d2 = make(os.path.join(self.tmp, "c2"))
        tool = os.path.join(self.root, "prune.sh")
        with open(tool, "w") as f:
            f.write('#!/bin/sh\ncase "$2" in *c2) echo "lock held by another process (timeout $LOCK_T s)"; exit 2;; esac\n'
                    'echo "removed 3 entries"\n')
        os.chmod(tool, stat.S_IRWXU)
        rule = {"id": "S7", "type": "command_per_dir", "dirs": [d1, d2, os.path.join(self.tmp, "none")],
                "argv": [tool, "--dir", "{dir}"], "env": {"LOCK_T": "10"}}
        self.assertEqual([l.split(" ")[2] for l in self.run_rules([rule], enabled=False).lines], ["WOULD-RUN", "WOULD-RUN"])
        lines = self.run_rules([rule]).lines
        self.assertIn("RAN rule=S7", lines[0])
        self.assertIn("removed 3 entries", lines[0])
        self.assertIn("KEEP rule=S7", lines[1])
        self.assertIn("skipped, in use or failed (rc=2): lock held by another process (timeout 10 s)", lines[1])

    def test_cleanup_list_lists_and_deletes_nothing(self):
        repo = os.path.join(self.root, "repo")
        os.makedirs(repo)

        def git(*a, cwd=repo):
            subprocess.run(["/usr/bin/git", "-C", cwd] + list(a), check=True, capture_output=True, timeout=60,
                           env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                                    GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com"))
        git("init", "-q", "-b", "main")
        with open(os.path.join(repo, "f"), "w") as f:
            f.write("1")
        git("add", "f")
        git("commit", "-q", "-m", "one")
        wt = os.path.join(self.root, "wts")
        git("worktree", "add", "-q", os.path.join(wt, "done"), "-b", "scratch-1")
        git("worktree", "add", "-q", os.path.join(wt, "dirty"), "-b", "work-2")
        with open(os.path.join(wt, "dirty", "new"), "w") as f:
            f.write("unique")
        make(os.path.join(self.tmp, "old-scratch"))
        make(os.path.join(self.tmp, "new-scratch"), when=time.time())
        cleanup = [{"id": "R1", "type": "git_worktrees", "repo": repo, "roots": [wt], "merged_into": "main"},
                   {"id": "R2", "type": "git_branches", "repo": repo, "patterns": ["scratch-*"]},
                   {"id": "R3", "type": "stale_children", "root": self.tmp, "age_minutes": 4320}]
        ctx = self.ctx([], cleanup=cleanup)
        items = mmdelete.cleanup_list(ctx, time.time())
        got = {(i["rule"], os.path.basename(i["path"])): i["command"] for i in items}
        self.assertEqual(got[("R1", "done")], mmdelete.shell_command(["git", "-C", repo, "worktree", "remove", os.path.join(wt, "done")]))
        self.assertNotIn(("R1", "dirty"), got, "unique uncommitted work is never listed")
        self.assertEqual(got[("R2", "scratch-1")], mmdelete.shell_command(["git", "-C", repo, "branch", "-D", "scratch-1"]))
        self.assertIn(("R3", "old-scratch"), got)
        self.assertNotIn(("R3", "new-scratch"), got)
        for p in (os.path.join(wt, "done"), os.path.join(wt, "dirty", "new"), os.path.join(self.tmp, "old-scratch")):
            self.assertTrue(os.path.exists(p), p)

    def test_printed_commands_keep_each_path_one_word(self):
        """A path or branch with a space, `;` or `$(...)` must give a command that a shell reads as the same words,
        never a second command."""
        odd = "a b;c $(touch PWNED)"
        repo = os.path.join(self.root, "repo " + odd)
        os.makedirs(repo)

        def git(*a, cwd=repo):
            subprocess.run(["/usr/bin/git", "-C", cwd] + list(a), check=True, capture_output=True, timeout=60,
                           env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                                    GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com"))
        git("init", "-q", "-b", "main")
        with open(os.path.join(repo, "f"), "w") as f:
            f.write("1")
        git("add", "f")
        git("commit", "-q", "-m", "one")
        wt = os.path.join(self.root, "wts " + odd)
        done = os.path.join(wt, "done " + odd)
        git("worktree", "add", "-q", done, "-b", "scratch-a;b$(c)")
        os.makedirs(os.path.join(done, "cache dir;x"))
        stale = make(os.path.join(self.tmp, "old " + odd))
        listed = make(os.path.join(self.tmp, "listed " + odd))
        cleanup = [{"id": "R1", "type": "git_worktrees", "repo": repo, "roots": [wt], "merged_into": "main",
                    "inner_caches": ["cache dir;x"]},
                   {"id": "R2", "type": "git_branches", "repo": repo, "patterns": ["scratch-*"]},
                   {"id": "R3", "type": "stale_children", "root": self.tmp, "age_minutes": 4320, "patterns": ["old *"]},
                   {"id": "R4", "type": "paths", "paths": [listed]}]
        items = mmdelete.cleanup_list(self.ctx([], cleanup=cleanup), time.time())
        want = {
            ("R1", done): ["git", "-C", repo, "worktree", "remove", done],
            ("R1", os.path.join(done, "cache dir;x")): ["rm", "-rf", os.path.join(done, "cache dir;x")],
            ("R2", "scratch-a;b$(c)"): ["git", "-C", repo, "branch", "-D", "scratch-a;b$(c)"],
            ("R3", stale): ["rm", "-rf", stale],
            ("R4", listed): ["rm", "-rf", listed],
        }
        got = {(i["rule"], i["path"]): i["command"] for i in items}
        self.assertEqual(sorted(got), sorted(want))
        for k, argv in want.items():
            self.assertEqual(shlex.split(got[k]), argv, got[k])
        # The shell itself reads the same words (echo only: nothing runs and nothing is deleted).
        for k, argv in want.items():
            out = subprocess.run(["/bin/sh", "-c", "printf '%s\\n' " + got[k].split(" ", 1)[1]], capture_output=True,
                                 text=True, timeout=10, cwd=self.tmp)
            self.assertEqual(out.stdout.splitlines(), argv[1:], got[k])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "PWNED")))
        for p in (done, stale, listed):
            self.assertTrue(os.path.exists(p), p)

    def test_shell_command_quotes_each_word(self):
        self.assertEqual(mmdelete.shell_command(["rm", "-rf", "/x/a b;c"]), "rm -rf '/x/a b;c'")
        self.assertEqual(mmdelete.shell_command(["rm", "-rf", "/x/it's"]), "rm -rf '/x/it'\"'\"'s'")
        self.assertEqual(mmdelete.shell_command(["git", "-C", "/plain/path", "branch", "-D", "b-1"]),
                         "git -C /plain/path branch -D b-1")


class T14Trim(Base):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir()
        self.c = T14Other.cache(self)
        self.log = os.path.join(self.data, "deletes.log")

    def trim(self, wait="1"):
        qa = ad_queue_fifo.Queue(self.profile()["queue"])
        argv = qa.exclusive_argv([sys.executable, "-I", os.path.join(mmtest.BIN, "cachetrim.py"), "--cache", self.c,
                                  "--age", "360", "--wait", wait, "--poll", "0.2", "--log", self.log, "--live",
                                  json.dumps(LIVE), "--machine", "m1", "--marker-file", "README", "--marker-text", "Go build"])
        return subprocess.run(argv, capture_output=True, text=True, timeout=60, env=dict(os.environ, **qa.exclusive_env()))

    def test_trim_through_the_queue(self):
        r = self.trim()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stdout.strip(), "trimmed entries=2 bytes=8192")
        self.assertEqual(sorted(os.listdir(os.path.join(self.c, "0a"))), ["young"])
        line = open(self.log).read().splitlines()[-1]
        self.assertIn("DELETE rule=trim path=%s bytes=8192" % self.c, line)
        self.assertIn("entries=2", line)
        self.assertTrue(line.endswith("machine=m1 v=1"))
        hist = open(os.path.join(self.q, "history.log")).read()
        self.assertIn("\tX\t", hist, "the trim ran as an exclusive queue call")

    def test_live_tool_refuses_the_trim(self):
        self.named("test2json")
        r = self.trim()
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertTrue(r.stdout.startswith("refused live_tools="))
        self.assertEqual(sorted(os.listdir(os.path.join(self.c, "0a"))), ["old-a", "old-b", "young"])
        self.assertIn("KEEP rule=trim", open(self.log).read())

    def test_wrong_cache_refused(self):
        os.remove(os.path.join(self.c, "README"))
        r = self.trim()
        self.assertEqual(r.returncode, 2)
        self.assertTrue(r.stdout.startswith("E_NOT_CACHE"))

    def test_supervisor_trim_waits_for_a_drained_queue(self):
        s = base_settings(**{"trim.drained_minutes": 2})
        prof = self.profile()
        state = {}
        tr = mmsuper.Trim(state, ad_queue_fifo.Queue(prof["queue"]), dict(prof["trim"], cache=self.c), LIVE, "m1")
        t = time.time()
        for i in range(10):  # a waiting call: never drained, so no trim however long
            tr.step(t + i * 60, s, True, False, True, [], self.log)
        self.assertNotIn("running", state["trim"])
        self.assertGreaterEqual(tr.step(t + 3700, s, True, False, True, [], self.log).get("needed_min", 0), 60)
        tr.step(t + 3800, s, True, True, False, [], self.log)
        tr.step(t + 3800 + 121, s, True, True, False, [], self.log)
        self.assertNotIn("running", state["trim"], "actions off: no trim")
        self.assertIn("WOULD-TRIM", open(self.log).read())
        tr.step(t + 3800 + 122, s, True, True, True, [], self.log)
        self.assertIn("running", state["trim"])
        ev, phases = [], []
        for _ in range(200):
            run = state["trim"].get("running")
            phases.append(run["phase"] if run else None)
            tr.step(time.time(), s, True, True, True, ev, self.log)
            if "running" not in state["trim"] and "warm_rc" in state["trim"]:
                break
            time.sleep(0.1)
        self.assertEqual(ev, ["trim"])
        self.assertEqual(state["trim"]["event"][0], "TRIM_DONE")
        self.assertIn("warm", phases, "the warm-up ran after the trim")
        self.assertEqual(state["trim"]["warm_rc"], 0)
        hist = open(os.path.join(self.q, "history.log")).read().splitlines()
        self.assertEqual([h.split("\t")[2] for h in hist], ["X", "S"], "the trim exclusive, the warm-up shared")
        self.assertEqual(sorted(os.listdir(os.path.join(self.c, "0a"))), ["young"])


class ObserveDeletesNothing(Base):
    def test_supervisor_in_observe_mode_deletes_nothing(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "deletes.enabled": True,
                               "mode.observe": True})
        res = mmsuper.deletes_job(self.s(), time.time(), False, self.ctx([FOLDERS]), True, LIVE, "m1")
        self.assertEqual((res["enabled"], res["freed_bytes"]), (False, 0))


if __name__ == "__main__":
    unittest.main()
