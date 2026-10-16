# SPDX-License-Identifier: Apache-2.0
"""machine-manager deletions: the profile's SAFE-AUTO rules behind their guards, and the owner's cleanup list.

deletes.enabled false (the default): every rule logs WOULD-DELETE, WOULD-RUN or KEEP and deletes nothing.
Each line goes to deletes.log in the data folder:
  `<time> DELETE|WOULD-DELETE|KEEP|RAN|WOULD-RUN|NOTE rule=<id> path=<p> [bytes=<n>] guard=<...> machine=<id> v=1`
The decision for one candidate is the pure mmdecide.delete_guard; this module gathers its facts (age, lsof, live tools).
Cleanup-list items (worktrees, branches, scratch, sessions, caches) are never deleted here: they go to
state/cleanup-list.json with sizes and the exact commands, for the person the profile names.
A path holding a forbidden part (profile deletes.forbidden_parts) is never touched, never entered and never listed.
Links (rule 48): for `cache_entries`, `command_per_dir` and the cleanup list, every component of a configured folder's
path and of each entry below it is checked with lstat (link_refusal). A link owned by root (/tmp, /var) is allowed; any
other link, or a real path outside its folder, refuses that folder or entry: a KEEP line (or a KEEP item in the cleanup
list, with no command) and the path in `link_skipped`, for the LINK_SKIPPED alert.
Git (rule 46): the cleanup list takes worktrees from the main repository's `git worktree list`; it runs git in a tree
only when the tree's `.git` is a regular file reading exactly its listed gitdir, and then with that gitdir given on the
command line (never read from the tree) and the guards of GIT_GUARDS.
Markers and failures: a cache's marker file is read with mmread.read_regular (no link, no wait, a regular file only, at
most mmread.FILE_READ_MAX bytes, invalid UTF-8 replaced). A rule that fails is logged as a KEEP line and kept in
`errors` for the DELETES_FAILED alert; the other rules still run.

Rule types (profile deletes.rules[].type): own_files, folders, cache_entries, app_folders, command_per_dir, trim, note.
Cleanup-list types (profile deletes.cleanup[].type): git_worktrees, git_branches, stale_children, paths.
"""
import errno
import fnmatch
import os
import re
import shlex
import shutil
import stat
import subprocess
import time

import mmcore
import mmdecide
import mmread
import mmtext


def user_tmp():
    rc, out = mmread.run(["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"], timeout=10)
    p = out.strip() if rc == 0 else ""
    return os.path.realpath(p).rstrip("/") if p else "/nonexistent-user-temp"


class Ctx:
    """Everything a pass needs from outside: the profile's deletes section, placeholders, the data folder."""

    def __init__(self, cfg, extra=None, data=None):
        self.cfg = cfg
        self.data = data or mmcore.data_dir()
        self.vals = {"claude_tmp": "/private/tmp/claude-%d" % os.getuid(), "data": self.data}
        self.vals.update(extra or {})
        if "user_tmp" not in self.vals:
            self.vals["user_tmp"] = user_tmp()
        self.forbidden_parts = tuple(cfg.get("forbidden_parts", [".ssh"]))
        self.protected = [os.path.realpath(self.x(p)) for p in cfg.get("protected_roots", [])]

    def x(self, p):
        return mmcore.expand(p, self.vals)


def forbidden(p, ctx):
    real = os.path.realpath(p)
    parts = real.split(os.sep)
    if any(x in parts for x in ctx.forbidden_parts):
        return True
    data = os.path.realpath(ctx.data)
    if real == data or real.startswith(data + os.sep):
        return False
    return any(real == r or real.startswith(r + os.sep) for r in ctx.protected)


def link_refusal(p, root=None):
    """Why `p` must not be deleted, pruned or listed (rule 48), or None. Every component of p's absolute path is checked
    with lstat: a link owned by root (a system link such as /tmp or /var) is allowed, any other link refuses. With
    `root`, p's real path must also stay inside root's real path. A component that does not exist refuses nothing:
    there is nothing behind it, and the caller's own checks skip it."""
    a = p if os.path.isabs(p) else os.path.join(os.getcwd(), p)
    cur = os.sep
    for part in a.split(os.sep):
        if not part:
            continue
        cur = os.path.join(cur, part)  # as given (no normalising): each prefix resolves as the delete would
        try:
            st = os.lstat(cur)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as e:
            return "cannot check %s (%s)" % (cur, e.__class__.__name__)
        if stat.S_ISLNK(st.st_mode) and st.st_uid != 0:
            return "a link: %s" % cur
    if root is not None:
        real, top = os.path.realpath(a), os.path.realpath(root)
        if real != top and not real.startswith(top + os.sep):
            return "real path %s is outside %s" % (real, top)
    return None


def children(root, patterns, dirs_only=False, skip=()):
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return []
    out = []
    for n in names:
        if n in skip or not any(fnmatch.fnmatchcase(n, pat) for pat in patterns):
            continue
        p = os.path.join(root, n)
        if dirs_only and not (os.path.isdir(p) and not os.path.islink(p)):
            continue
        out.append(p)
    return out


class Run:
    """One pass of the rules. `procs` returns the process list (tests inject one); `live_spec` names the live tools."""

    def __init__(self, s, ctx, enabled=None, now=None, procs=mmread.read_ps, live_spec=None, log_file=None, mid=None):
        self.s, self.c = s, ctx
        self.enabled = s["deletes.enabled"] if enabled is None else enabled
        self.now = now or time.time()
        self.procs = procs
        self.live_spec = live_spec or {}
        self.log_file = log_file or mmcore.path("deletes.log")
        self.mid = mid or mmcore.machine_id()
        self.lines = []
        self.freed = 0
        self.would = 0
        self.young = {}  # (rule, folder, minutes) -> count: young items get one summary line, not one line each
        self.link_skipped = []  # paths refused for a link (rule 48): the LINK_SKIPPED alerts
        self._link_seen = set()
        self.errors = []  # [rule id, error] of each rule that failed (the DELETES_FAILED alerts); the others still run

    # ---- log
    def log(self, verb, rule, p, nbytes=None, guard="", extra=""):
        line = "%s %s rule=%s path=%s%s guard=%s%s machine=%s v=%d" % (
            mmcore.now_local(self.now), verb, rule, mmcore.log_path(p), "" if nbytes is None else " bytes=%d" % nbytes, guard, extra,
            self.mid, mmcore.SCHEMA_VERSION)
        self.lines.append(line)
        mmcore.append_line(self.log_file, line)

    def refuse(self, rule, p, why):
        """A configured folder or an entry refused for a link (rule 48): a KEEP line with the reason, and the path for
        the LINK_SKIPPED alert."""
        self.log("KEEP", rule, p, guard=why)
        if p not in self._link_seen:  # a set: many links stay linear (C-21)
            self._link_seen.add(p)
            self.link_skipped.append(p)

    # ---- facts
    def live_tools(self):
        procs = self.procs()
        if procs is None:
            return ["ps failed"]
        return ["%d:%s" % (p["pid"], os.path.basename(p["comm"])) for p in mmread.live_named(procs, self.live_spec)
                if p["pid"] != os.getpid()]

    def untouched(self, p, minutes):
        """(True, bytes, None) when nothing under p changed within `minutes`; a forbidden folder inside, an unreadable
        entry or a symbolic link at the top counts as touched (the item stays)."""
        limit = self.now - minutes * 60
        total = 0
        try:
            st = os.lstat(p)
        except OSError:
            return False, 0, "unreadable"
        if st.st_mtime > limit:
            return False, 0, "changed %.0f min ago" % ((self.now - st.st_mtime) / 60)
        if not stat.S_ISDIR(st.st_mode):
            return True, st.st_size, None
        stack = [p]
        while stack:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for e in it:
                        if e.name in self.c.forbidden_parts:
                            return False, 0, "holds a %s folder (protected)" % e.name
                        try:
                            est = e.stat(follow_symlinks=False)
                        except OSError:
                            return False, 0, "unreadable entry"
                        if est.st_mtime > limit:
                            return False, 0, "an entry changed %.0f min ago" % ((self.now - est.st_mtime) / 60)
                        total += est.st_blocks * 512
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
            except OSError:
                return False, 0, "unreadable folder"
        return True, total, None

    def held(self, p):
        """None when no live process holds a file, a socket or its working folder under p; else the reason.
        A failed or timed-out lsof counts as held."""
        t = self.s["deletes.lsof_timeout_s"]
        try:
            r = subprocess.run(["/usr/sbin/lsof", "-t", "+D", p], capture_output=True, text=True, timeout=t)
        except (OSError, subprocess.TimeoutExpired) as e:
            return "lsof failed: %s" % str(e)[:60]
        pids = r.stdout.split()
        if pids:
            return "lsof=pids %s" % ",".join(pids[:5])
        if r.returncode not in (0, 1):
            return "lsof rc=%d" % r.returncode
        try:
            u = subprocess.run(["/usr/sbin/lsof", "-U", "-F", "pn"], capture_output=True, text=True, timeout=t)
        except (OSError, subprocess.TimeoutExpired) as e:
            return "lsof -U failed: %s" % str(e)[:60]
        pid = None
        prefixes = (os.path.realpath(p) + os.sep, p.rstrip(os.sep) + os.sep)
        for line in mmtext.split_lines(u.stdout):  # socket names are agent text
            if line.startswith("p"):
                pid = line[1:]
            elif line.startswith("n") and line[1:].startswith(prefixes):
                return "unix socket of pid %s" % pid
        return None

    def facts(self, p, minutes, parents, needs_no_live_tools):
        f = {"enabled": self.enabled, "forbidden": forbidden(p, self.c), "age_minutes": minutes,
             "needs_no_live_tools": needs_no_live_tools}
        if f["forbidden"]:
            return f, 0
        parent = os.path.dirname(p.rstrip(os.sep))
        f["parent_ok"] = os.path.realpath(parent) in {os.path.realpath(x) for x in parents if x}
        f["symlink"] = os.path.islink(p)
        f["keep_file"] = os.path.exists(os.path.join(p, ".keep"))
        if not f["parent_ok"] or f["symlink"] or f["keep_file"]:
            return f, 0
        ok, nbytes, why = self.untouched(p, minutes)
        f["untouched"] = [ok, why]
        if not ok:
            return f, 0
        f["held"] = self.held(p)
        if needs_no_live_tools and not f["held"]:
            f["live_tools"] = self.live_tools()
        return f, nbytes

    def remove(self, rule, p, minutes, parents, needs_no_live_tools=False):
        f, nbytes = self.facts(p, minutes, parents, needs_no_live_tools)
        d = mmdecide.delete_guard(f)
        if d["verb"] == "KEEP":
            why = (f.get("untouched") or [True, ""])[1] or ""
            if why.startswith(("changed ", "an entry changed ")):
                k = (rule, os.path.dirname(p.rstrip(os.sep)), minutes)
                self.young[k] = self.young.get(k, 0) + 1
                return False
            self.log("KEEP", rule, p, guard=d["guard"])
            return False
        if d["verb"] == "WOULD-DELETE":
            self.would += nbytes
            self.log("WOULD-DELETE", rule, p, nbytes, d["guard"])
            return True
        f2, nbytes2 = self.facts(p, minutes, parents, needs_no_live_tools)  # the re-check right before the delete
        d2 = mmdecide.delete_guard(f2)
        if d2["verb"] != "DELETE":
            self.log("KEEP", rule, p, guard="re-check: " + d2["guard"])
            return False
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
        except OSError as e:
            self.log("KEEP", rule, p, guard="delete failed: %s" % str(e)[:80])
            return False
        self.freed += nbytes2
        self.log("DELETE", rule, p, nbytes2, d2["guard"])
        return True

    # ---- rule types
    def own_files(self, r):
        """The tool's own evidence slots and rotated logs (in the data folder), older than a setting's days."""
        days = self.s[r.get("age_days_setting", "deletes.evidence_keep_days")]
        data = os.path.realpath(self.c.data)
        slot_dir = os.path.join(data, r.get("slot_dir", "evidence"))
        cands = children(slot_dir, [r.get("slot_pattern", "[0-9][0-9]")], dirs_only=True)
        cands += [os.path.join(data, n) for n in r.get("files", []) if os.path.lexists(os.path.join(data, n))]
        allowed = {os.path.join(data, n) for n in r.get("files", [])}
        for p in cands:
            real = os.path.realpath(p)
            if os.path.islink(p) or not (real.startswith(slot_dir + os.sep) or real in allowed):
                self.log("KEEP", r["id"], p, guard="not an own rotated file or evidence slot")
                continue
            ok, nbytes, why = self.untouched(p, days * 1440)
            if not ok:
                self.log("KEEP", r["id"], p, guard=why)
                continue
            if not self.enabled:
                self.would += nbytes
                self.log("WOULD-DELETE", r["id"], p, nbytes, "pass: own file, age>%gd" % days)
                continue
            try:
                shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
                self.freed += nbytes
                self.log("DELETE", r["id"], p, nbytes, "pass: own file, age>%gd" % days)
            except OSError as e:
                self.log("KEEP", r["id"], p, guard="delete failed: %s" % str(e)[:80])

    def folders(self, r):
        """Top-level entries matching patterns directly inside the roots, untouched age_minutes, not held."""
        parents = [self.c.x(x) for x in r["roots"]]
        for root in parents:
            for p in children(root, r["patterns"], r.get("dirs_only", False), self.c.forbidden_parts):
                self.remove(r["id"], p, r["age_minutes"], parents, r.get("no_live_tools", False))

    def cache_entries(self, r):
        """Entries of a content-addressed cache unused age_minutes; no live tool before and after the find."""
        c = self.c.x(r["cache"])
        bad = link_refusal(c)
        if bad:
            self.refuse(r["id"], c, bad)
            return
        if not has_marker(c, r.get("marker_file"), r.get("marker_text")):
            return
        if forbidden(c, self.c):
            self.log("KEEP", r["id"], c, guard="forbidden path (protected)")
            return
        live = self.live_tools() if r.get("no_live_tools") else []
        if live:
            self.log("KEEP", r["id"], c, guard="live_tools=%s" % ",".join(live[:3]))
            return
        links = []
        files, nbytes = old_cache_entries(c, r["age_minutes"], self.now, r.get("entry_regex", "[0-9a-f]{2}"), links)
        for p in links:
            self.refuse(r["id"], p, "an entry folder that is a link")
        live = self.live_tools() if r.get("no_live_tools") else []
        if live:
            self.log("KEEP", r["id"], c, guard="live_tools after the find=%s" % ",".join(live[:3]))
            return
        if not files:
            return
        if not self.enabled:
            self.would += nbytes
            self.log("WOULD-DELETE", r["id"], c, nbytes, "pass: live_tools=none before and after", " entries=%d" % len(files))
            return
        bad = link_refusal(c)  # the re-check right before the delete: the folder may have become a link
        if bad:
            self.refuse(r["id"], c, "re-check: " + bad)
            return
        links = []
        n, b = delete_entries(files, links)
        for p in links:
            self.refuse(r["id"], p, "re-check: a link (swapped after the find)")
        self.freed += b
        self.log("DELETE", r["id"], c, b, "pass: live_tools=none before and after", " entries=%d" % n)

    def app_folders(self, r):
        """An app's build folders: one set only while the app is closed, one set any time; then the app's own command."""
        base = self.c.x(r["base"])
        if not os.path.isdir(base):
            return
        procs = self.procs() or []
        app_open = any(os.path.basename(p["comm"]) == r["app"] for p in procs)
        wc = r.get("while_closed")
        if wc:
            d = os.path.join(base, wc["dir"])
            if app_open:
                self.log("KEEP", r["id"], d, guard="%s is running: left alone" % r["app"])
            else:
                for p in children(d, ["*"], dirs_only=True):
                    self.remove(r["id"], p, wc["age_minutes"], [d])
        at = r.get("any_time")
        if at:
            for ds in children(base, [at["dir_pattern"]], dirs_only=True):
                for p in children(ds, ["*"], dirs_only=True):
                    self.remove(r["id"], p, at["age_minutes"], [ds])
        if r.get("command"):
            text = shell_command(r["command"])
            if not self.enabled:
                self.log("WOULD-RUN", r["id"], text, guard="the app's own command")
            else:
                rc, _ = mmread.run(r["command"], timeout=300)
                self.log("RAN", r["id"], text, guard="rc=%s" % rc)

    def command_per_dir(self, r):
        """A tool's own prune command for each folder (the tool's lock decides; a lock timeout skips it)."""
        for d in r["dirs"]:
            d = self.c.x(d)
            if not os.path.isdir(d):
                continue
            bad = link_refusal(d)
            if bad:
                self.refuse(r["id"], d, bad)
                continue
            argv = [x.replace("{dir}", d) for x in r["argv"]]
            exe = shutil.which(argv[0]) or argv[0]
            if not self.enabled:
                self.log("WOULD-RUN", r["id"], d, guard="%s (the tool's own lock)" % shell_command(argv))
                continue
            try:
                p = subprocess.run([exe] + argv[1:], capture_output=True, text=True, timeout=r.get("timeout_s", 120),
                                   env=dict(os.environ, **r.get("env", {})))
                rc, tail = p.returncode, (p.stdout + p.stderr).strip().splitlines()[-1:] or [""]
            except (OSError, subprocess.TimeoutExpired) as e:
                rc, tail = None, [str(e)[:80]]
            if rc == 0:
                self.log("RAN", r["id"], d, guard="%s: %s" % (argv[0], tail[0][:120]))
            else:
                self.log("KEEP", r["id"], d, guard="skipped, in use or failed (rc=%s): %s" % (rc, tail[0][:120]))

    def note(self, r):
        self.log("NOTE", r["id"], r.get("path", "-"), guard=r.get("note", ""))

    def trim(self, r):
        pass  # the supervisor's guarded trim (its own exclusive queue call)

    def all(self, ids=None):
        for r in self.c.cfg.get("rules", []):
            if ids is not None and r["id"] not in ids:
                continue
            try:
                getattr(self, r["type"])(r)
            except Exception as e:  # one failing rule never stops the others (DELETES_FAILED names it)
                why = error_text(e)
                self.errors.append([r.get("id", "?"), why])
                self.log("KEEP", r.get("id", "?"), "-", guard="rule failed: " + why)
        for (rule, folder, minutes), n in sorted(self.young.items()):
            self.log("KEEP", rule, folder, guard="young: %d entries changed within %g min" % (n, minutes))
        self.young = {}
        return self.lines


ERROR_TEXT_MAX = 200  # characters of one failed rule's error kept for its log line and its DELETES_FAILED alert


def error_text(e):
    """One failed rule's error as one short line: its class and message."""
    return " ".join(("%s: %s" % (e.__class__.__name__, e)).split())[:ERROR_TEXT_MAX]


# ------------------------------------------------------------------------------------- cache helpers

def has_marker(c, marker_file, marker_text):
    """The cache's marker file holds the marker text. The marker is opened without following a link and without
    waiting, only a regular file counts, at most mmread.FILE_READ_MAX bytes are read and decoded with errors replaced:
    an agent-made marker (a link, a FIFO, a folder, invalid UTF-8, a huge file) is no marker, never a hang or an error."""
    if not marker_file:
        return os.path.isdir(c)
    data = mmread.read_regular(os.path.join(c, marker_file))
    return data is not None and (marker_text or "") in data.decode("utf-8", "replace")


def old_cache_entries(c, minutes, now, entry_regex="[0-9a-f]{2}", links=None):
    """Regular files `c/<entry>/*` unused for `minutes` (the build tool marks use in the mtime). An entry folder that
    is a link is never entered; its path goes to `links` when a list is given."""
    limit = now - minutes * 60
    files, total = [], 0
    for d in sorted(os.listdir(c)):
        if not re.fullmatch(entry_regex, d):
            continue
        dp = os.path.join(c, d)
        if os.path.islink(dp):
            if links is not None:
                links.append(dp)
            continue
        if not os.path.isdir(dp):
            continue
        with os.scandir(dp) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mtime < limit:
                    files.append(e.path)
                    total += st.st_size
    return files, total


def _open_folder(name, dir_fd, links, parent=None):
    """A descriptor of the folder `name` (relative to dir_fd when given), opened without following a link; None when
    it is not a folder. A link goes to `links` (when a list is given) with its path."""
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError as e:
        if links is not None and e.errno in (errno.ELOOP, errno.ENOTDIR):  # macOS gives ENOTDIR for a link
            try:
                if stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode):
                    links.append(os.path.join(parent, name) if parent else name)
            except OSError:
                pass
        return None


def delete_entries(files, links=None):
    """Remove the files `<cache>/<entry>/<name>` that old_cache_entries found, through folder descriptors opened
    without following a link: a cache or entry folder swapped for a link after the find is never entered (its path goes
    to `links` when a list is given), and only regular files go. Returns (count, bytes)."""
    n = b = 0
    groups = {}
    for f in files:
        entry = os.path.dirname(f)
        groups.setdefault(os.path.dirname(entry), {}).setdefault(os.path.basename(entry), []).append(os.path.basename(f))
    for cache, entries in sorted(groups.items()):
        cfd = _open_folder(cache, None, links)
        if cfd is None:
            continue
        try:
            for entry, names in sorted(entries.items()):
                dfd = _open_folder(entry, cfd, links, cache)
                if dfd is None:
                    continue
                try:
                    for name in names:
                        try:
                            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                            if not stat.S_ISREG(st.st_mode):
                                continue
                            os.unlink(name, dir_fd=dfd)
                            n += 1
                            b += st.st_size
                        except OSError:
                            pass
                finally:
                    os.close(dfd)
        finally:
            os.close(cfd)
    return n, b


# ------------------------------------------------------------------------------------- the cleanup list

def du_bytes(p, timeout=300):
    rc, out = mmread.run(["/usr/bin/nice", "-n", "19", "/usr/bin/du", "-sk", p], timeout=timeout)
    try:
        return int(out.split()[0]) * 1024 if rc == 0 else None
    except (IndexError, ValueError):
        return None


# Rule 46: every git call of the cleanup list writes no optional lock and runs no fsmonitor and no hook from any config
# that git reads (a tree's git folder and its configs may be agent-written). attr.tree (git 2.42 or newer) reads the
# attributes from the empty tree, not from the tree's own .gitattributes, so no filter driver from an agent-written
# config (a worktree's config.worktree) ever runs on its files.
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's empty tree (an unknown value also means empty)
GIT_GUARDS = ["--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
              "-c", "attr.tree=" + EMPTY_TREE]
# Bytes read from a `.git` or `gitdir` file: one absolute path (macOS PATH_MAX is 1024) and its `gitdir: ` prefix.
PATH_FILE_MAX = 4096


def git(args, cwd, timeout=60, tree=None):
    """git in `cwd` with GIT_GUARDS. `tree`: (git folder, common folder) of a checked worktree: git takes both from
    here and never reads the tree's `.git` file or the git folder's `commondir` file."""
    argv, env = ["/usr/bin/git"] + GIT_GUARDS, None
    if tree:
        argv += ["--git-dir=" + tree[0], "--work-tree=" + cwd]
        env = dict(os.environ, GIT_COMMON_DIR=tree[1])
    return mmread.run(argv + ["-C", cwd] + args, timeout=timeout, env=env)


def read_path_file(p):
    """The text of a small regular file, opened without following a link and without waiting (a FIFO is refused);
    None when it is not a regular file or cannot be read."""
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, PATH_FILE_MAX + 1).decode("utf-8", "surrogateescape")
    except OSError:
        return None
    finally:
        os.close(fd)


def listed_worktrees(repo):
    """(trees, git folders, common folder) of the main repository (rule 46): the trees of its `git worktree list`, and
    for each tree the git folders under the common folder whose `gitdir` file names that tree's `.git` (an absolute
    path, as git writes it). Empty when git fails."""
    rc, common = git(["rev-parse", "--path-format=absolute", "--git-common-dir"], repo)
    common = common.rstrip("\n") if rc == 0 else ""
    rc, out = git(["worktree", "list", "--porcelain", "-z"], repo) if common else (None, "")
    if rc != 0:
        return set(), {}, None
    trees = {w[len("worktree "):] for w in out.split("\0") if w.startswith("worktree ")}
    gitdirs = {}
    admin = os.path.join(common, "worktrees")
    try:
        names = sorted(os.listdir(admin))
    except OSError:
        names = []
    for n in names:
        text = read_path_file(os.path.join(admin, n, "gitdir"))
        gd = text.rstrip("\n") if text else ""
        if os.path.isabs(gd) and os.path.basename(gd) == ".git" and os.path.dirname(gd) in trees:
            gitdirs.setdefault(os.path.dirname(gd), set()).add(os.path.join(admin, n))
    return trees, gitdirs, common


def gitfile_check(tree, gitdirs):
    """Rule 46: (None, git folder) when the tree's `.git` is a regular file reading exactly `gitdir: <one of its
    listed git folders>` (absolute, as git writes it; one ending newline allowed); else (the reason, None)."""
    g = os.path.join(tree, ".git")
    try:
        mode = os.lstat(g).st_mode
    except OSError:
        return "no .git", None
    if not stat.S_ISREG(mode):
        kind = "a link" if stat.S_ISLNK(mode) else "a folder" if stat.S_ISDIR(mode) else "not a file"
        return ".git is %s, not a regular file" % kind, None
    text = read_path_file(g)
    for d in sorted(gitdirs):
        if text in ("gitdir: %s\n" % d, "gitdir: %s" % d):
            return None, d
    return ".git does not read exactly its listed gitdir", None


def untouched_simple(p, minutes, now, skip=()):
    limit = now - minutes * 60
    try:
        if os.lstat(p).st_mtime > limit:
            return False
        if not os.path.isdir(p) or os.path.islink(p):
            return True
        for d, dirs, files in os.walk(p):
            dirs[:] = [x for x in dirs if x not in skip]
            for n in dirs + files:
                if os.lstat(os.path.join(d, n)).st_mtime > limit:
                    return False
        return True
    except OSError:
        return False


def shell_command(argv):
    """One printed command line: every word quoted for a POSIX shell, so a path with a space, `;` or `$` stays one word."""
    return " ".join(shlex.quote(str(a)) for a in argv)


def cleanup_list(ctx, now, sizes=True):
    """Candidates for the person the profile names, each with its size and exact command, and KEEP items (a skipped
    tree, folder or entry, with its reason and no command). Reads only (git with GIT_GUARDS). Nothing here deletes."""
    items = []

    def add(rid, p, why, cmd, size=True):
        items.append({"rule": rid, "path": p, "why": why, "bytes": du_bytes(p) if sizes and size else None, "command": cmd})

    def keep(rid, p, why, link=False):
        """A skipped tree, folder or entry (C-1, C-8): a KEEP item with its reason and no command; `link` marks a
        refusal for a link (rule 48), which also raises LINK_SKIPPED."""
        item = {"rule": rid, "path": p, "verb": "KEEP", "why": why, "bytes": None, "command": None}
        if link:
            item["link"] = True
        items.append(item)

    for r in ctx.cfg.get("cleanup", []):
        t = r["type"]
        if t == "git_worktrees":
            repo = ctx.x(r["repo"])
            trees, gitdirs, common = listed_worktrees(repo)
            for root in r["roots"]:
                root = ctx.x(root)
                bad = link_refusal(root)
                if bad:
                    keep(r["id"], root, bad, link=True)
                    continue
                for p in children(root, ["*"], True, ctx.forbidden_parts):
                    real = os.path.realpath(p)  # root has no link but root's own, and p is no link
                    if real not in trees:
                        continue  # git does not list it: not a worktree, never entered (C-2)
                    why, gitdir = gitfile_check(p, gitdirs.get(real, ()))
                    if why:
                        keep(r["id"], p, why)
                        continue
                    # no submodule: its git folder would come from its own .git file in the tree
                    rc, st = git(["status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=all"], p,
                                 tree=(gitdir, common))
                    rc2, _ = git(["merge-base", "--is-ancestor", "HEAD", r["merged_into"]], p, tree=(gitdir, common))
                    if rc == 0 and not st.strip() and rc2 == 0:
                        add(r["id"], p, "merged into %s and clean" % r["merged_into"],
                            shell_command(["git", "-C", repo, "worktree", "remove", p]))
                    for sub in r.get("inner_caches", []):
                        cache = os.path.join(p, sub)
                        if not os.path.isdir(cache):
                            continue
                        bad = link_refusal(cache, p)
                        if bad:
                            keep(r.get("inner_id", r["id"]), cache, bad, link=True)
                            continue
                        add(r.get("inner_id", r["id"]), cache, "a worktree's own cache (goes with its worktree)",
                            shell_command(["rm", "-rf", cache]))
        elif t == "git_branches":
            repo = ctx.x(r["repo"])
            pats = list(r["patterns"]) + ["%s/%s" % (r.get("remote", "origin"), x) for x in r["patterns"]]
            rc, out = git(["branch", "-a", "--format=%(refname:short)", "--list"] + pats, repo)
            remote = r.get("remote", "origin") + "/"
            for b in out.split() if rc == 0 else []:
                if b.startswith(remote):
                    items.append({"rule": r["id"], "path": b, "why": "remote branch matching %s" % r["patterns"],
                                  "bytes": None, "command": shell_command(["git", "-C", repo, "push", remote[:-1], "--delete", b[len(remote):]])})
                else:
                    items.append({"rule": r["id"], "path": b, "why": "local branch matching %s" % r["patterns"],
                                  "bytes": None, "command": shell_command(["git", "-C", repo, "branch", "-D", b])})
        elif t == "stale_children":
            root = ctx.x(r["root"])
            bad = link_refusal(root)
            if bad:
                keep(r["id"], root, bad, link=True)
                continue
            depth_pat = r.get("parent_patterns")
            parents = children(root, depth_pat, True, ctx.forbidden_parts) if depth_pat else [root]
            for par in parents:
                try:
                    names = sorted(os.listdir(par))
                except OSError:
                    continue
                for n in names:
                    if n in ctx.forbidden_parts or any(fnmatch.fnmatchcase(n, x) for x in r.get("skip", [])):
                        continue
                    if not any(fnmatch.fnmatchcase(n, x) for x in r.get("patterns", ["*"])):
                        continue
                    p = os.path.join(par, n)
                    if r.get("dirs_only") and not (os.path.isdir(p) and not os.path.islink(p)):
                        continue
                    if untouched_simple(p, r["age_minutes"], now, ctx.forbidden_parts):
                        bad = link_refusal(p, root)
                        if bad:
                            keep(r["id"], p, bad, link=True)
                            continue
                        add(r["id"], p, r.get("why", "untouched %d min" % r["age_minutes"]), shell_command(["rm", "-rf", p]))
        elif t == "paths":
            for p in r["paths"]:
                p = ctx.x(p)
                if not os.path.isdir(p):
                    continue
                bad = link_refusal(p)
                if bad:
                    keep(r["id"], p, bad, link=True)
                    continue
                add(r["id"], p, r.get("why", "listed path"), shell_command(["rm", "-rf", p]))
    return items
