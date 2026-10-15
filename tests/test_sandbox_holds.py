# SPDX-License-Identifier: Apache-2.0
"""Sandbox holds: the tool runs outside any sandbox, but agents in a sandbox can write their own git worktrees (each
tree's `.git` file too), the queue's slot and ticket files, and their own cache folders. Nothing an agent writes there
may make the tool run a program, signal a process or delete outside the place it was configured for.

Rule 46, the cleanup list: worktrees come from the main repository's `git worktree list --porcelain`; a tree whose `.git`
is not a regular file reading exactly its listed gitdir is reported and skipped; git runs with `--no-optional-locks
-c core.fsmonitor=false -c core.hooksPath=/dev/null`. Settlements: only trees under the profile's roots are candidates,
git's list only confirms them (C-2); a skipped tree gives one KEEP item naming the tree and the reason, and no command
(C-1); the `.git` text is exactly `gitdir: <absolute listed gitdir>`, a relative gitdir is skipped (C-3); every git call
of the cleanup list carries the three settings, the main repository's included (C-4).
Rule 47, the pause: the pid to pause comes from the process that holds the slot file open, never from label text; it is
paused only when its command line is the queue launcher of the configured queue folder. Settlements: every process that
has the slot file open is checked; each that runs the configured launcher is paused with its children, no other process
ever (C-5); any other opener gives an ATTENTION alert PAUSE_REFUSED naming the slot file and each pid not paused (C-6).
Rule 48, deletes and prunes (`cache_entries`, `command_per_dir`, the cleanup list's commands): every component of the
configured folder's absolute path and every component below it to the entry is checked with lstat; a link owned by
root (/tmp, /var) is allowed, any other link refuses (C-7); a refused folder or entry gives a KEEP line with the reason
and an ATTENTION alert LINK_SKIPPED naming the path; in the cleanup list, a KEEP item and no command (C-8).

Every fixture lives in the test's own temporary folder. The only processes signalled are ones the test started: a guard
around os.kill refuses (and records) any SIGSTOP or SIGCONT to another pid."""
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock

import mmtest
from mmtest import TempData, base_settings, mmcore, mmread
import mmdelete
import mmsuper

OLD = time.time() - 30 * 86400
LIVE = {"names": ["go"], "suffixes": [".test"], "path_regexes": []}
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.com"}


def age(path, when=OLD):
    """Set the times of path and everything under it (links themselves, never their targets)."""
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
    """A real-path scratch folder `t` (no link in its own path), and a record of every link the test makes: tearDown
    unlinks each one by its path before the folder is removed."""

    def setUp(self):
        super().setUp()
        self.t = os.path.realpath(os.path.join(self.root, "t"))
        os.makedirs(self.t)
        self.links = []

    def tearDown(self):
        for p in reversed(self.links):
            try:
                if os.path.islink(p):
                    os.unlink(p)
            except OSError:
                pass
        super().tearDown()

    def link(self, target, path):
        """A link at `path` to `target` (both inside this test's folder), recorded for tearDown."""
        self.assertTrue(os.path.realpath(target).startswith(self.t + os.sep), "links point only into the test folder")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(target, path)
        self.links.append(path)
        return path

    def ctx(self, rules=(), cleanup=()):
        cfg = {"rules": list(rules), "cleanup": list(cleanup), "forbidden_parts": [".records", ".ssh"],
               "protected_roots": []}
        return mmdelete.Ctx(cfg, extra={"t": self.t, "user_tmp": self.t}, data=self.data)

    def run_rules(self, rules, enabled=True, procs=None):
        r = mmdelete.Run(base_settings(**{"deletes.lsof_timeout_s": 60}), self.ctx(rules), enabled=enabled,
                         procs=procs or (lambda: []), live_spec=LIVE, mid="m1")
        r.all()
        return r

    def lines_for(self, run, path):
        """(verb, guard) of every delete-log line that names `path`."""
        out = []
        for l in run.lines:
            rec = mmcore.parse_delete_line(l)
            self.assertIsNotNone(rec, l)
            if rec["path"] == path:
                out.append((rec["verb"], rec["guard"]))
        return out


# ------------------------------------------------------------------------------------------------ rule 46 and 48: git

class GitSpy:
    """Records every program the code starts (argv, cwd, env), through subprocess.Popen."""

    def __init__(self):
        self.calls = []
        real = subprocess.Popen
        spy = self

        class Recording(real):
            def __init__(self, args, *a, **kw):
                spy.calls.append((list(args) if not isinstance(args, str) else [args], kw.get("cwd"), kw.get("env")))
                super().__init__(args, *a, **kw)
        self.patch = mock.patch.object(subprocess, "Popen", Recording)

    def __enter__(self):
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.patch.stop()

    def git_calls(self):
        return [c for c in self.calls if c[0] and os.path.basename(str(c[0][0])) == "git"]


def config_set(argv, env, key, value):
    """git sees key=value from the command line: `-c key=value`, or GIT_CONFIG_COUNT/KEY_n/VALUE_n in its environment."""
    want = "%s=%s" % (key, value)
    for i in range(len(argv) - 1):
        if argv[i] == "-c" and argv[i + 1].lower() == want.lower():
            return True
    env = env or {}
    try:
        n = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        n = 0
    return any(env.get("GIT_CONFIG_KEY_%d" % k, "").lower() == key.lower() and env.get("GIT_CONFIG_VALUE_%d" % k) == value
               for k in range(n))


class Repo(Base):
    """A main repository with one commit, and worktrees under `wts/`, made by git itself."""

    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.t, "repo")
        os.makedirs(self.repo)
        self.git("init", "-q", "-b", "main")
        with open(os.path.join(self.repo, "f"), "w") as f:
            f.write("1")
        self.git("add", "f")
        self.git("commit", "-q", "-m", "one")
        self.wts = os.path.join(self.t, "wts")
        self.mark = os.path.join(self.t, "HOOK-RAN")
        self.hook = os.path.join(self.t, "hook.sh")
        with open(self.hook, "w") as f:
            f.write("#!/bin/sh\necho ran >> '%s'\nexit 1\n" % self.mark)
        os.chmod(self.hook, 0o700)

    def git(self, *a, cwd=None):
        return subprocess.run(["/usr/bin/git", "-C", cwd or self.repo] + list(a), check=True, capture_output=True,
                              text=True, timeout=60, env=dict(os.environ, **GIT_ENV)).stdout

    def tree(self, name):
        p = os.path.join(self.wts, name)
        self.git("worktree", "add", "-q", p, "-b", "br-" + name)
        return p

    def gitdir_text(self, tree):
        with open(os.path.join(tree, ".git")) as f:
            return f.read()

    def evil_gitdir(self, name="evil"):
        """An agent-made git folder: a copy of the main repository's, whose config runs the hook as fsmonitor."""
        d = os.path.join(self.t, name)
        shutil.copytree(os.path.join(self.repo, ".git"), d, symlinks=True)
        with open(os.path.join(d, "config"), "a") as f:
            f.write("[core]\n\tfsmonitor = %s\n" % self.hook)
        return d

    def rule(self, **over):
        r = {"id": "R1", "type": "git_worktrees", "repo": self.repo, "roots": [self.wts], "merged_into": "main"}
        r.update(over)
        return r

    def listing(self, *rules):
        with GitSpy() as spy:
            items = mmdelete.cleanup_list(self.ctx(cleanup=rules or [self.rule()]), time.time(), sizes=False)
        return items, spy

    def removes(self, items):
        """Paths that a printed command would remove (`git ... worktree remove P` or `rm -rf P`)."""
        out = set()
        for i in items:
            if not i.get("command"):
                continue
            w = shlex.split(i["command"])
            if w[:2] == ["rm", "-rf"]:
                out.add(w[-1])
            elif "worktree" in w and "remove" in w:
                out.add(w[-1])
        return out

    def assert_keep_item(self, items, path):
        """C-1, C-8: one cleanup-list item for `path` that is a KEEP (a value "KEEP" or a text starting with it), with
        its reason in `why`, and no command."""
        mine = [i for i in items if i.get("path") == path]
        self.assertEqual(len(mine), 1, "one KEEP item for %s: %s" % (path, mine))
        item = mine[0]
        self.assertFalse(item.get("command"), "a skipped path has no command: %s" % item)
        self.assertTrue(any(isinstance(v, str) and v.startswith("KEEP") for v in item.values()), "a KEEP item: %s" % item)
        self.assertTrue(item.get("why"), "the KEEP item names the reason: %s" % item)

    def assert_hook_never_ran(self):
        self.assertFalse(os.path.exists(self.mark), "a git hook or fsmonitor from a planted config ran")

    def assert_git_never_touched(self, spy, *paths):
        for argv, cwd, _env in spy.git_calls():
            for p in paths:
                self.assertFalse(any(p in str(a) for a in argv), "git ran on %s: %s" % (p, argv))
                self.assertFalse(cwd and (cwd == p or str(cwd).startswith(p + os.sep)), "git ran in %s" % p)


class Rule46Worktrees(Repo):
    def test_a_clean_merged_tree_is_listed_and_every_git_call_carries_the_guards(self):
        good = self.tree("good")
        items, spy = self.listing(self.rule(), {"id": "R2", "type": "git_branches", "repo": self.repo,
                                                "patterns": ["br-*"]})
        self.assertIn(good, self.removes(items), "a clean, merged, listed tree is still a candidate")
        calls = spy.git_calls()
        self.assertTrue(calls, "git ran at least once")
        for argv, _cwd, env in calls:
            env = env or {}
            self.assertTrue("--no-optional-locks" in argv or env.get("GIT_OPTIONAL_LOCKS") == "0", argv)
            self.assertTrue(config_set(argv, env, "core.fsmonitor", "false"), "no core.fsmonitor=false: %s" % argv)
            self.assertTrue(config_set(argv, env, "core.hooksPath", "/dev/null"), "no core.hooksPath=/dev/null: %s" % argv)

    def test_an_fsmonitor_in_the_repository_config_never_runs(self):
        good = self.tree("good")
        self.git("config", "core.fsmonitor", self.hook)
        items, _ = self.listing()
        self.assert_hook_never_ran()
        self.assertIn(good, self.removes(items), "the tree itself is valid and stays a candidate")

    def test_an_fsmonitor_in_the_trees_own_worktree_config_never_runs(self):
        good = self.tree("good")
        self.git("config", "extensions.worktreeConfig", "true")
        self.git("config", "--worktree", "core.fsmonitor", self.hook, cwd=good)
        self.listing()
        self.assert_hook_never_ran()

    def test_a_git_file_rewritten_to_an_agent_made_gitdir_is_skipped(self):
        good = self.tree("good")
        evil = self.evil_gitdir()
        with open(os.path.join(good, ".git"), "w") as f:
            f.write("gitdir: %s\n" % evil)
        items, spy = self.listing()
        self.assert_hook_never_ran()
        self.assertNotIn(good, self.removes(items), "a tree with a foreign .git is never a candidate")
        self.assert_keep_item(items, good)
        self.assert_git_never_touched(spy, good, evil)

    def test_a_git_file_naming_another_listed_trees_gitdir_is_skipped(self):
        good, other = self.tree("good"), self.tree("other")
        with open(os.path.join(good, ".git"), "w") as f:
            f.write(self.gitdir_text(other))
        items, spy = self.listing()
        self.assertNotIn(good, self.removes(items), "the .git must read this tree's own listed gitdir")
        self.assertIn(other, self.removes(items))
        self.assert_keep_item(items, good)
        self.assert_git_never_touched(spy, good)

    def test_a_git_file_with_text_after_the_gitdir_is_skipped(self):
        good = self.tree("good")
        text = self.gitdir_text(good)
        with open(os.path.join(good, ".git"), "w") as f:
            f.write(text.rstrip("\n") + "\n[core]\n")
        items, spy = self.listing()
        self.assertNotIn(good, self.removes(items), "exactly the listed gitdir, nothing more")
        self.assert_keep_item(items, good)
        self.assert_git_never_touched(spy, good)

    def test_a_relative_gitdir_is_skipped(self):
        """C-3: the text must be exactly `gitdir: <absolute listed gitdir>`; a relative gitdir that git itself would
        follow to the same place is still skipped."""
        good = self.tree("good")
        admin = self.gitdir_text(good)[len("gitdir: "):].strip()
        with open(os.path.join(good, ".git"), "w") as f:
            f.write("gitdir: %s\n" % os.path.relpath(admin, good))
        items, spy = self.listing()
        self.assertNotIn(good, self.removes(items))
        self.assert_keep_item(items, good)
        self.assert_git_never_touched(spy, good)

    def test_a_git_link_and_a_git_folder_are_skipped(self):
        linked, folder = self.tree("linked"), self.tree("folder")
        copy = os.path.join(self.t, "gitfile-copy")
        with open(copy, "w") as f:
            f.write(self.gitdir_text(linked))  # the exact right text, but behind a link
        os.remove(os.path.join(linked, ".git"))
        self.link(copy, os.path.join(linked, ".git"))
        os.remove(os.path.join(folder, ".git"))
        shutil.copytree(self.evil_gitdir(), os.path.join(folder, ".git"), symlinks=True)
        items, spy = self.listing()
        self.assert_hook_never_ran()
        self.assertNotIn(linked, self.removes(items), ".git is a link, not a regular file")
        self.assertNotIn(folder, self.removes(items), ".git is a folder, not a regular file")
        self.assert_keep_item(items, linked)
        self.assert_keep_item(items, folder)
        self.assert_git_never_touched(spy, linked, folder)

    def test_a_folder_that_git_does_not_list_is_never_entered(self):
        self.tree("good")
        fake = os.path.join(self.wts, "fake")
        os.makedirs(fake)
        with open(os.path.join(fake, "f"), "w") as f:
            f.write("1")
        with open(os.path.join(fake, ".git"), "w") as f:
            f.write("gitdir: %s\n" % self.evil_gitdir())
        items, spy = self.listing()
        self.assert_hook_never_ran()
        self.assertFalse([i for i in items if i.get("command") and (i["path"] == fake or i["path"].startswith(fake + os.sep))],
                         "a folder git does not list is never a candidate (C-2)")
        self.assert_git_never_touched(spy, fake)

    def test_a_listed_tree_outside_the_roots_is_not_a_candidate(self):
        """C-2: only trees under the profile's roots are candidates; git's list only confirms them.
        Passes before the change too."""
        good = self.tree("good")
        away = os.path.join(self.t, "away", "tree")
        self.git("worktree", "add", "-q", away, "-b", "br-away")
        items, _ = self.listing()
        self.assertIn(good, self.removes(items))
        self.assertFalse([i for i in items if i.get("command") and i["path"].startswith(away)])

    def test_a_listed_tree_whose_folder_is_gone_gives_no_item_and_no_crash(self):
        """Passes before the change too: a listed tree that no longer exists (git calls it prunable)."""
        gone = self.tree("gone")
        good = self.tree("good")
        shutil.rmtree(gone)  # made by git above; it holds no link
        items, _ = self.listing()
        self.assertNotIn(gone, self.removes(items))
        self.assertIn(good, self.removes(items))


class Rule48CleanupCommands(Repo):
    def test_an_inner_cache_behind_a_link_is_not_listed(self):
        good = self.tree("good")
        make(os.path.join(self.t, "outside", "go"))
        make(os.path.join(self.t, "outside2", "go"))
        self.link(os.path.join(self.t, "outside"), os.path.join(good, "c"))             # a link above the cache
        os.makedirs(os.path.join(good, "d"))
        self.link(os.path.join(self.t, "outside2", "go"), os.path.join(good, "d", "go"))  # the cache itself a link
        make(os.path.join(good, "e", "go"))
        items, _ = self.listing(self.rule(inner_caches=["c/go", "d/go", "e/go"], inner_id="R5"))
        got = self.removes(items)
        self.assertIn(os.path.join(good, "e", "go"), got, "a real inner cache is still listed")
        self.assertNotIn(os.path.join(good, "c", "go"), got)
        self.assertNotIn(os.path.join(good, "d", "go"), got)
        self.assert_keep_item(items, os.path.join(good, "c", "go"))
        self.assert_keep_item(items, os.path.join(good, "d", "go"))

    def test_stale_children_skip_a_link_child_and_a_linked_root(self):
        scratch = os.path.join(self.t, "scratch")
        old = make(os.path.join(scratch, "old"))
        make(os.path.join(self.t, "outside"))
        lnk = self.link(os.path.join(self.t, "outside"), os.path.join(scratch, "lnk"))
        os.utime(lnk, (OLD, OLD), follow_symlinks=False)
        age(scratch)
        make(os.path.join(self.t, "real-root", "child"))
        root_link = self.link(os.path.join(self.t, "real-root"), os.path.join(self.t, "root-link"))
        items, _ = self.listing({"id": "R3", "type": "stale_children", "root": scratch, "age_minutes": 60},
                                {"id": "R4", "type": "stale_children", "root": root_link, "age_minutes": 60})
        got = self.removes(items)
        self.assertIn(old, got, "a real stale child is still listed")
        self.assertNotIn(lnk, got, "a link child is not listed")
        self.assertFalse([p for p in got if p.startswith(root_link + os.sep)], "nothing under a configured root that is a link")
        self.assert_keep_item(items, lnk)
        self.assert_keep_item(items, root_link)

    def test_a_paths_entry_that_is_a_link_is_not_listed(self):
        real = make(os.path.join(self.t, "real-cache"))
        make(os.path.join(self.t, "outside"))
        lnk = self.link(os.path.join(self.t, "outside"), os.path.join(self.t, "link-cache"))
        make(os.path.join(self.t, "elsewhere", "inner"))
        self.link(os.path.join(self.t, "elsewhere"), os.path.join(self.t, "linked-parent"))
        below = os.path.join(self.t, "linked-parent", "inner")
        items, _ = self.listing({"id": "R5", "type": "paths", "paths": [real, lnk, below]})
        got = self.removes(items)
        self.assertIn(real, got)
        self.assertNotIn(lnk, got, "the listed path is a link")
        self.assertNotIn(below, got, "a component of the listed path is a link not owned by root")
        self.assert_keep_item(items, lnk)
        self.assert_keep_item(items, below)

    def test_a_path_through_a_root_owned_link_is_still_listed(self):
        """C-7: links owned by root (/var here) are allowed in the path. The command is only printed, never run.
        Passes before the change too."""
        self.assertTrue(os.path.islink("/var") and os.lstat("/var").st_uid == 0, "this machine's /var is a root link")
        items, _ = self.listing({"id": "R5", "type": "paths", "paths": ["/var/empty"]})
        self.assertTrue(self.removes(items) & {"/var/empty", "/private/var/empty"}, items)


def alert_records(data):
    """Every alert record the tool keeps: the active ones (alerts-state.json) and the pushed log (alerts.jsonl)."""
    out = []
    try:
        with open(os.path.join(data, "alerts-state.json")) as f:
            st = json.load(f)
        out += [a for a in (st.get("active") or {}).values() if isinstance(a, dict)]
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(data, "alerts.jsonl")) as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return out


# ------------------------------------------------------------------------------------------------ rule 48: deletes

def cache_at(path):
    """A content-addressed cache with its marker, one old entry folder with two old files."""
    os.makedirs(path)
    with open(os.path.join(path, "README"), "w") as f:
        f.write("This directory holds cached Go build artifacts.\n")
    make(os.path.join(path, "0a"), files=("old-a", "old-b"))
    return path


def rule_s5(cache):
    return {"id": "S5", "type": "cache_entries", "cache": cache, "marker_file": "README", "marker_text": "Go build",
            "age_minutes": 60, "no_live_tools": True}


class Rule48Deletes(Base):
    def victim(self, name="victim"):
        v = cache_at(os.path.join(self.t, name))
        return v, [os.path.join(v, "0a", "old-a"), os.path.join(v, "0a", "old-b")]

    def assert_all_exist(self, files):
        for f in files:
            self.assertTrue(os.path.exists(f), "deleted through a link: %s" % f)

    def test_a_real_cache_is_still_trimmed(self):
        """The control: passes before the change too."""
        c, files = self.victim("cache")
        r = self.run_rules([rule_s5(c)])
        self.assertFalse(any(os.path.exists(f) for f in files), r.lines)

    def test_a_cache_folder_that_is_a_link_is_left_alone(self):
        v, files = self.victim()
        c = self.link(v, os.path.join(self.t, "agent-caches", "go-build"))
        r = self.run_rules([rule_s5(c)])
        self.assert_all_exist(files)
        self.assertIn("KEEP", [x[0] for x in self.lines_for(r, c)], r.lines)

    def test_a_cache_folder_below_a_linked_parent_is_left_alone(self):
        """The configured folder's real path is not the configured path: its real path is outside it."""
        v, files = self.victim(os.path.join("elsewhere", "go-build"))
        self.link(os.path.join(self.t, "elsewhere"), os.path.join(self.t, "agent-caches"))
        c = os.path.join(self.t, "agent-caches", "go-build")
        r = self.run_rules([rule_s5(c)])
        self.assert_all_exist(files)
        self.assertIn("KEEP", [x[0] for x in self.lines_for(r, c)], r.lines)

    def swap_after_the_find(self, swap):
        """A process reader that changes the tree on its second call: after the entry find, before the delete."""
        n = {"calls": 0, "swapped": False}

        def procs():
            n["calls"] += 1
            if n["calls"] >= 2 and not n["swapped"]:
                swap()
                n["swapped"] = True
            return []
        return procs, n

    def test_a_cache_swapped_for_a_link_after_the_find_is_left_alone(self):
        c, _ = self.victim("cache")
        v, files = self.victim()

        def swap():
            os.rename(c, c + "-moved")
            self.link(v, c)
        procs, n = self.swap_after_the_find(swap)
        r = self.run_rules([rule_s5(c)], procs=procs)
        self.assertTrue(n["swapped"], "the live-tool check runs after the find")
        self.assert_all_exist(files)
        self.assertNotIn("DELETE", [x[0] for x in self.lines_for(r, c)], r.lines)

    def test_an_entry_swapped_for_a_link_after_the_find_is_left_alone(self):
        c, _ = self.victim("cache")
        v, files = self.victim()

        def swap():
            os.rename(os.path.join(c, "0a"), os.path.join(c, "0a-moved"))
            self.link(os.path.join(v, "0a"), os.path.join(c, "0a"))
        procs, n = self.swap_after_the_find(swap)
        self.run_rules([rule_s5(c)], procs=procs)
        self.assertTrue(n["swapped"], "the live-tool check runs after the find")
        self.assert_all_exist(files)

    def test_an_entry_folder_that_is_a_link_is_skipped(self):
        """Passes before the change too (the entry walk already skips links)."""
        c = cache_at(os.path.join(self.t, "cache"))
        v, files = self.victim()
        self.link(os.path.join(v, "0a"), os.path.join(c, "0b"))
        self.run_rules([rule_s5(c)])
        self.assert_all_exist(files)

    def test_command_per_dir_skips_a_linked_folder_and_a_folder_below_a_link(self):
        real = make(os.path.join(self.t, "uv-real"))
        target = make(os.path.join(self.t, "victim-dir"))
        lnk = self.link(target, os.path.join(self.t, "agent-caches", "uv-cache"))
        make(os.path.join(self.t, "elsewhere", "uv2"))
        self.link(os.path.join(self.t, "elsewhere"), os.path.join(self.t, "linked-parent"))
        below = os.path.join(self.t, "linked-parent", "uv2")
        ran = os.path.join(self.t, "ran.log")
        tool = os.path.join(self.t, "prune.sh")
        with open(tool, "w") as f:
            f.write('#!/bin/sh\nprintf "%%s\\n" "$2" >> \'%s\'\necho "pruned"\n' % ran)
        os.chmod(tool, 0o700)
        rule = {"id": "S7", "type": "command_per_dir", "dirs": [real, lnk, below], "argv": [tool, "--dir", "{dir}"]}
        r = self.run_rules([rule])
        with open(ran) as f:
            self.assertEqual(f.read().splitlines(), [real], "the prune ran only on the real folder")
        self.assertIn("RAN", [x[0] for x in self.lines_for(r, real)])
        for path in (lnk, below):
            keeps = [g for v, g in self.lines_for(r, path) if v == "KEEP"]
            self.assertTrue(keeps and all(keeps), "a KEEP line with its reason for %s: %s" % (path, r.lines))

    def test_command_per_dir_runs_through_a_root_owned_link(self):
        """C-7: /var is a link owned by root, so /var/empty is allowed. The prune here is this test's own script; it
        only records its argument. Passes before the change too."""
        self.assertTrue(os.path.islink("/var") and os.lstat("/var").st_uid == 0, "this machine's /var is a root link")
        ran = os.path.join(self.t, "ran.log")
        tool = os.path.join(self.t, "prune.sh")
        with open(tool, "w") as f:
            f.write('#!/bin/sh\nprintf "%%s\\n" "$2" >> \'%s\'\n' % ran)
        os.chmod(tool, 0o700)
        r = self.run_rules([{"id": "S7", "type": "command_per_dir", "dirs": ["/var/empty"], "argv": [tool, "--dir", "{dir}"]}])
        with open(ran) as f:
            self.assertIn(f.read().splitlines(), (["/var/empty"], ["/private/var/empty"]), r.lines)

    def test_a_refused_link_raises_link_skipped(self):
        """C-8: the supervisor's deletion pass raises an ATTENTION alert LINK_SKIPPED naming the refused path."""
        v, files = self.victim()
        c = self.link(v, os.path.join(self.t, "agent-caches", "go-build"))
        prof = os.path.join(self.root, "profile.toml")
        with open(mmtest.PROFILE) as f:
            text = f.read()
        with open(prof, "w") as f:
            f.write(text + "\n[[deletes.rules]]\n" + "\n".join("%s = %s" % (k, json.dumps(val)) for k, val in rule_s5(c).items()) + "\n")
        os.environ["MM_PROFILE"] = prof  # TempData puts the old value back
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "deletes.enabled": True})
        sup = mmsuper.Supervisor(self.profile(), kernel=False, sampler=sampler_of(), sizes=False, slow_jobs=True,
                                 check_readings=False)
        for _ in range(3):
            sup.tick()
            if sup.deletes.thread is not None:
                sup.deletes.thread.join(60)
        self.assert_all_exist(files)
        got = [a for a in alert_records(self.data) if a.get("name") == "LINK_SKIPPED"]
        self.assertTrue(got, "a LINK_SKIPPED alert")
        self.assertTrue(all(a.get("level") == "ATTENTION" for a in got), got)
        self.assertTrue(any(c in (a.get("text") or "") for a in got), "the alert names %s: %s" % (c, got))


# ------------------------------------------------------------------------------------------------ rule 47: the pause

HOLDER = r'''
import fcntl, os, sys, time
f = open(sys.argv[1], "a+")
fcntl.flock(f, fcntl.LOCK_EX)
f.seek(0); f.truncate(); f.write(sys.argv[2].replace("SELF", str(os.getpid())) + "\n"); f.flush()
time.sleep(300)
'''

OPENER = r'''
import os, sys, time
f = open(sys.argv[1], "r+")
f.seek(0); f.truncate(); f.write(sys.argv[2].replace("SELF", str(os.getpid())) + "\n"); f.flush()
time.sleep(300)
'''


def sampler_of(**kw):
    def f(now, ticks):
        d = {"t": now, "free_pct": 80, "swap_used_mb": 100, "swap_total_mb": 2048, "comp_mb": 300, "pressure": 1,
             "seg_pct": 1, "load1": 1, "load5": 1, "sys_pct": None, "sys_pct_fixture": 10}
        d.update(kw)
        return d, ticks
    return f


CRITICAL = sampler_of(free_pct=70, pressure=4)  # RED with a critical reason: the pause's trigger


def proc_stat(pid):
    return subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True,
                          timeout=5).stdout.strip()


class Rule47Pause(Base):
    def setUp(self):
        super().setUp()
        self.q = self.queue_dir(slots=5)
        self.slot = os.path.join(self.q, ".slot.1")
        self.started = []
        self.refused = []
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, "mode.observe": False,
                               "pause_newest_call.enabled": True})

    def tearDown(self):
        for pid in self.mine():
            try:
                os.kill(pid, signal.SIGCONT)
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        for p in self.started:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                pass
        super().tearDown()

    def start(self, argv):
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.started.append(p)
        return p

    def mine(self):
        """The pids this test started and all their descendants, now."""
        procs = mmread.read_ps() or []
        out = set()
        for p in self.started:
            out.update(mmread.descendants(procs, p.pid))
        return out

    def wait_until(self, cond, what):
        for _ in range(100):
            if cond():
                return
            time.sleep(0.1)
        self.fail("timed out waiting for " + what)

    def label(self):
        with open(self.slot) as f:
            return f.readline().strip()

    def launcher(self):
        """A real queue call: the configured launcher of the configured queue folder runs a sleep."""
        p = self.start([sys.executable, "-I", os.path.join(self.q, "launcher.py"), "--", "/bin/sleep", "300"])
        self.wait_until(lambda: mmread.flock_held(self.slot)[0] and self.label().startswith("S %d " % p.pid),
                        "the launcher to hold its slot")
        self.wait_until(lambda: len(self.mine()) >= 2, "the launcher's child")
        return p

    def victim(self):
        return self.start(["/bin/sleep", "300"])

    def holder(self, label, script_path=None, extra=()):
        """A process that is not the configured launcher, holding the slot with the label it writes."""
        if script_path:
            with open(script_path, "w") as f:
                f.write(HOLDER)
            argv = [sys.executable, "-I", script_path, self.slot, label] + list(extra)
        else:
            argv = [sys.executable, "-I", "-c", HOLDER, self.slot, label] + list(extra)
        p = self.start(argv)
        self.wait_until(lambda: mmread.flock_held(self.slot)[0] and self.label() == label.replace("SELF", str(p.pid)),
                        "the holder to hold the slot")
        return p

    def rewrite_label(self, text):
        with open(self.slot, "r+") as f:
            f.seek(0)
            f.truncate()
            f.write(text + "\n")

    def tick_red(self, n=3):
        """Supervisor ticks at a critical RED in act mode, with os.kill guarded: a SIGSTOP or SIGCONT to a pid this
        test did not start is refused and recorded."""
        real_kill, real_killpg = os.kill, os.killpg
        allowed = self.mine()

        def kill(pid, sig):
            if sig in (signal.SIGSTOP, signal.SIGCONT) and pid not in allowed:
                self.refused.append((pid, sig))
                raise PermissionError("guard: not a process of this test")
            return real_kill(pid, sig)

        def killpg(pgid, sig):
            self.refused.append(("group", pgid, sig))
            raise PermissionError("guard: no group signals in this test")
        clock = {"t": time.time()}
        with mock.patch.object(os, "kill", kill), mock.patch.object(os, "killpg", killpg):
            sup = mmsuper.Supervisor(self.profile(), kernel=False, clock=lambda: clock["t"], sampler=CRITICAL,
                                     sizes=False, slow_jobs=False, check_readings=False)
            for _ in range(n):
                sup.tick()
                clock["t"] += 10
        self.assertEqual(self.refused, [], "a signal to a process this test did not start")
        return sup

    def stopped(self, pid):
        return proc_stat(pid).startswith("T")

    def assert_alerted_about(self, *pids):
        """C-6: an ATTENTION alert PAUSE_REFUSED names the slot file and each pid it did not pause."""
        got = [a for a in alert_records(self.data) if a.get("name") == "PAUSE_REFUSED"]
        self.assertTrue(got, "a PAUSE_REFUSED alert")
        self.assertTrue(all(a.get("level") == "ATTENTION" for a in got), got)
        text = "\n".join(a.get("text") or "" for a in got)
        self.assertIn(".slot.1", text, "the alert names the slot file")
        for pid in pids:
            self.assertIn(str(pid), text, "the alert names pid %d" % pid)

    def assert_no_refusal(self):
        self.assertEqual([a for a in alert_records(self.data) if a.get("name") == "PAUSE_REFUSED"], [],
                         "no other process had the slot file open")

    def assert_nothing_paused(self, *procs):
        import mmrecover
        for p in procs:
            self.assertFalse(self.stopped(p.pid), "pid %d was paused" % p.pid)
        self.assertEqual(mmrecover.read_paused(), {}, "nothing is recorded as paused")

    # -- the real launcher holds the slot

    def test_the_real_launcher_holding_the_slot_is_paused(self):
        """The control: passes before the change too."""
        call = self.launcher()
        self.tick_red()
        kids = [pid for pid in self.mine() if pid != call.pid]
        self.assertTrue(self.stopped(call.pid), "the launcher is paused")
        self.assertTrue(kids and all(self.stopped(k) for k in kids), "its command is paused")
        self.assert_no_refusal()

    def test_a_rewritten_label_never_redirects_the_pause(self):
        call = self.launcher()
        v = self.victim()
        self.rewrite_label("S %d go test ./x" % v.pid)
        self.tick_red()
        self.assertFalse(self.stopped(v.pid), "the pid in the label text is never paused")
        self.assertTrue(self.stopped(call.pid), "the process that holds the slot file is paused")
        self.assert_no_refusal()

    def test_a_label_without_a_pid_still_pauses_the_holder(self):
        call = self.launcher()
        self.rewrite_label("garbage without a pid")
        self.tick_red()
        self.assertTrue(self.stopped(call.pid), "the holder comes from the open file, not from the label")

    # -- a process that is not the configured launcher holds the slot

    def test_a_holder_naming_another_pid_pauses_nothing_and_alerts(self):
        v = self.victim()
        h = self.holder("S %d go test ./x" % v.pid)
        self.tick_red()
        self.assert_nothing_paused(v, h)
        self.assert_alerted_about(h.pid)

    def test_a_launcher_of_the_same_name_in_another_folder_pauses_nothing(self):
        other = os.path.join(self.t, "agent-tree")
        os.makedirs(other)
        h = self.holder("S SELF go test ./x", script_path=os.path.join(other, "launcher.py"))
        self.tick_red()
        self.assert_nothing_paused(h)
        self.assert_alerted_about(h.pid)

    def test_a_holder_that_only_names_the_launcher_as_an_argument_pauses_nothing(self):
        script = os.path.join(self.t, "holder.py")
        h = self.holder("S SELF go test ./x", script_path=script, extra=[os.path.join(self.q, "launcher.py")])
        self.tick_red()
        self.assert_nothing_paused(h)
        self.assert_alerted_about(h.pid)

    def test_an_extra_opener_that_rewrites_the_label_to_itself_is_never_paused(self):
        """C-5: every opener is checked; the launcher is paused, the other opener never, and the alert names it."""
        call = self.launcher()
        o = self.start([sys.executable, "-I", "-c", OPENER, self.slot, "S SELF go test ./x"])
        self.wait_until(lambda: self.label() == "S %d go test ./x" % o.pid, "the opener's label")
        self.tick_red()
        self.assertFalse(self.stopped(o.pid), "a process that only has the slot file open is not the launcher")
        self.assertTrue(self.stopped(call.pid), "the launcher that holds the slot is still paused")
        self.assert_alerted_about(o.pid)


if __name__ == "__main__":
    unittest.main()
