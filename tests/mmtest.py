# SPDX-License-Identifier: Apache-2.0
"""Shared test helpers: a temporary data folder per test (MM_DATA), the test profile, settings, fixtures.
Tests never touch a real install: MM_BASE, MM_DATA and HOME point into the test's own folder."""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.realpath(__file__))
CODE = os.path.dirname(HERE)
BIN = os.path.join(CODE, "bin")
FIX = os.path.join(HERE, "fixtures")
RESULTS = os.path.join(HERE, "results")
sys.path[:0] = [os.path.join(CODE, "core"), os.path.join(CODE, "adapters")]
import mmcore  # noqa: E402
import mmplat  # noqa: E402
import mmread  # noqa: E402
import ad_queue_fifo  # noqa: E402

# A test that needs macOS itself (real sysctl or Mach readings, the macOS commands, launchd) skips elsewhere,
# and under MM_PLATFORM=linux on a Mac (the Linux path's test hook).
darwin_only = unittest.skipUnless(mmplat.DARWIN, "needs macOS (platform %s)" % mmplat.PLATFORM)
# A test that needs the real process layer (the pause reads each opener's argument list: sysctl on macOS,
# /proc/<pid>/cmdline on Linux; the boot time) runs on macOS and on Linux, and skips only under MM_PLATFORM=linux on a
# machine without /proc (a Mac).
needs_proc = unittest.skipUnless(mmplat.DARWIN or os.path.isdir("/proc"),
                                 "needs the process layer (/proc); MM_PLATFORM=linux on a machine without it")


def root_link_folder():
    """(link, folder, real folder) for C-7 tests: a link owned by root and an existing real folder reached through it,
    or None when this machine has none. macOS: /var and /var/empty. Linux (merged /usr): the first of /bin, /sbin,
    /lib, /lib64 that is a root-owned link, and its first real subfolder. Chosen by the real system: a file system fact."""
    import stat
    cands = [("/var", "empty")] if sys.platform == "darwin" else [(p, None) for p in ("/bin", "/sbin", "/lib", "/lib64")]
    for link, sub in cands:
        try:
            st = os.lstat(link)
            if not stat.S_ISLNK(st.st_mode) or st.st_uid != 0:
                continue
            if sub is None:
                sub = next((n for n in sorted(os.listdir(link)) if os.path.isdir(os.path.join(link, n))
                            and not os.path.islink(os.path.join(link, n))), None)
        except OSError:
            continue
        if sub and os.path.isdir(os.path.join(link, sub)):
            folder = os.path.join(link, sub)
            return link, folder, os.path.realpath(folder)
    return None


def without_platform(lines):
    """`mm check` lines without the W_PLATFORM line a platform in its reduced form adds."""
    return [line for line in lines if not line.startswith("W_PLATFORM ")]

PROFILE = os.path.join(FIX, "profile-test.toml")
TMP_BASE = os.environ.get("MM_TEST_TMP") or os.path.join(tempfile.gettempdir(), "mm-tests")
MM = [sys.executable, "-I", os.path.join(BIN, "mm")]


def base_settings(**over):
    """The default settings with fixed machine values (cores 10, floor 3, ceiling 10), as the vectors use."""
    flat = mmcore.defaults()
    flat.update({"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10})
    flat.update(over)
    return flat


def restored_without(*keys):
    """The settings the supervisor runs on when its settings.toml is bad and the last good values were saved by an older
    settings table (without `keys`): mmcore.Settings restores them over the defaults. With the vectors' machine values."""
    with tempfile.TemporaryDirectory() as d, unittest.mock.patch.dict(os.environ, {"MM_DATA": d}):
        os.makedirs(os.path.join(d, "state"))
        with open(os.path.join(d, "state", "settings.lastgood.json"), "w") as f:
            json.dump({k: v for k, v in mmcore.defaults().items() if k not in keys}, f)
        with open(os.path.join(d, "settings.toml"), "w") as f:
            f.write("[slots\n")  # not TOML: the last good values are restored
        st = mmcore.Settings()
        values = st.load(save=False)
    assert st.problem and values is not None, st.problem
    return dict(values, **{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10})


class TempData(unittest.TestCase):
    """Each test gets its own data folder with the test profile; HOME and MM_BASE move there too."""
    settings_over = {}

    def setUp(self):
        os.makedirs(TMP_BASE, exist_ok=True)
        self.root = tempfile.mkdtemp(prefix=self.id().split(".")[-1][:30] + "-", dir=TMP_BASE)
        self.data = os.path.join(self.root, "data")
        os.makedirs(os.path.join(self.data, "state"))
        self._env = {k: os.environ.get(k) for k in ("MM_DATA", "MM_BASE", "MM_PROFILE", "HOME", "MM_LAUNCHCTL")}
        os.environ.update(MM_DATA=self.data, MM_BASE=os.path.join(self.root, "base"), MM_PROFILE=PROFILE,
                          HOME=os.path.join(self.root, "home"))
        os.makedirs(os.environ["HOME"])
        # a fake gh: `--version` works, every other call fails (no test reads GitHub)
        self.fake_gh = os.path.join(self.root, "fake-gh")
        with open(self.fake_gh, "w") as f:
            f.write('#!/bin/sh\n[ "$1" = "--version" ] && { echo "gh version 0.0 (fake)"; exit 0; }\nexit 1\n')
        os.chmod(self.fake_gh, 0o700)
        self._env.setdefault("MM_GH", os.environ.get("MM_GH"))
        os.environ["MM_GH"] = self.fake_gh
        self.write_settings(**dict({"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10}, **self.settings_over))

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        if os.environ.get("MM_KEEP_TMP") != "1":
            shutil.rmtree(self.root, ignore_errors=True)

    def write_settings(self, **over):
        """settings.toml in the data folder with these overrides (flat keys)."""
        secs = {}
        for k, v in over.items():
            sec, key = k.split(".", 1)
            secs.setdefault(sec, {})[key] = v
        lines = []
        for sec, body in secs.items():
            lines.append("[%s]" % sec)
            for k, v in body.items():
                lines.append("%s = %s" % (k, json.dumps(v)))
        p = os.path.join(self.data, "settings.toml")
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n")
        st = os.stat(p)
        os.utime(p, (st.st_atime, st.st_mtime + 1))

    def s(self):
        return mmcore.Settings().load()

    def profile(self):
        return mmcore.load_profile()

    def pushed(self):
        return mmcore.read_pushed(0, os.path.join(self.data, "alerts.jsonl"))

    def queue_dir(self, slots=3):
        q = os.path.join(self.data, "queue")
        os.makedirs(os.path.join(q, "queue"), exist_ok=True)
        shutil.copy(os.path.join(FIX, "launcher.py"), q)
        with open(os.path.join(q, "slots"), "w") as f:
            f.write("%d\n" % slots)
        open(os.path.join(q, "load.log"), "a").close()
        open(os.path.join(q, "history.log"), "a").close()
        return q

    def mm(self, *args, env=None, timeout=60):
        import subprocess
        e = dict(os.environ)
        e.update(env or {})
        return subprocess.run(MM + list(args), capture_output=True, text=True, timeout=timeout, env=e)


def load_fixture(name, year=2026):
    out = []
    with open(os.path.join(FIX, name)) as f:
        for line in f:
            s = ad_queue_fifo.parse_load_line(line, year)
            if s:
                out.append(s)
    return out


def at(text):
    """'2026-10-14 09:11' -> local epoch."""
    return time.mktime(time.strptime(text, "%Y-%m-%d %H:%M"))


def write_result(name, lines):
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, name), "w") as f:
        f.write("\n".join(lines) + "\n")
