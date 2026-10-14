# SPDX-License-Identifier: Apache-2.0
"""Queue adapter "fifo-gates": a slot queue kept as flock'ed files in one folder: `slots` (the count), `.gate.lock` and
`.slot.<k>` (held by running calls, first line "S|W|X <pid> ..."), `queue/<ns>-<pid>` tickets (held while waiting),
a sampler log (one line a minute) and a history log (one tab-separated row per finished call). Its launcher program
(profile queue.launcher) runs a command as a shared call, or with --exclusive as the only call.

Interface (PORTING.md, "Adapters"): read(now) -> {slots, busy[{slot, mode, pid, label, since, kind}],
tickets[{name, mode, age_s, label, kind}]}; slots_path(); sample_log(); history_log(); last_sample(now);
parse_history(line); kind_of(text, mode); exclusive_argv(cmd) and exclusive_env(); shared_argv(cmd).
It reads only: it never writes, unlinks or takes a lock that blocks the queue (a shared flock test, released at once).
"""
import os
import re
import sys
import time

import mmcore
import mmread

_LOAD_RE = re.compile(
    r"^(\d\d)-(\d\d) (\d\d):(\d\d) load ([\d.]+) ([\d.]+) ([\d.]+) free (\d+)% swap ([\d.]+)([KMG]) "
    r"comp ([\d.]+)([KMG]) sys ([\d.]+)% fsev ([\d.]+)([KMG]) slots (\d+)/(\d+) waiting (\d+)\s*$")


def parse_load_line(line, year):
    """One sampler line (gates/load.log) -> sample dict (t = local epoch), or None for a broken line."""
    m = _LOAD_RE.match((line or "").strip())
    if not m:
        return None
    g = m.groups()
    try:
        t = time.mktime((year, int(g[0]), int(g[1]), int(g[2]), int(g[3]), 0, 0, 0, -1))
    except (OverflowError, ValueError):
        return None
    mb = mmread._mb
    return {"t": t, "load1": float(g[4]), "load5": float(g[5]), "load15": float(g[6]), "free_pct": float(g[7]),
            "swap_used_mb": mb(g[8], g[9]), "swap_total_mb": None, "comp_mb": mb(g[10], g[11]), "sys_pct": float(g[12]),
            "fsev_mb": mb(g[13], g[14]), "busy": int(g[15]), "slots": int(g[16]), "waiting": int(g[17]),
            "pressure": None, "seg_pct": None}


def parse_history_line(line):
    """One history row (tab-separated: end, pid, mode, wait=, run=, rc=, mem=, cwd=, words, command) -> dict, or None."""
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 10:
        return None
    try:
        end = time.mktime(time.strptime(parts[0], "%Y-%m-%dT%H:%M:%S"))
        kv = {}
        for p in parts[3:8]:
            k, _, v = p.partition("=")
            kv[k] = v
        return {"end": end, "pid": int(parts[1]), "mode": parts[2], "wait": float(kv["wait"]), "run": float(kv["run"]),
                "rc": kv["rc"], "mem": kv["mem"], "cwd": kv["cwd"].replace("\\t", "\t").replace("\\n", "\n").replace("\\\\", "\\"),
                "words": parts[8], "cmd": "\t".join(parts[9:])}
    except (ValueError, KeyError):
        return None


def read_queue(d, now=None, kind_of=None):
    """Slots, busy holders and live tickets of a queue folder. Never writes or unlinks anything."""
    now = time.time() if now is None else now
    try:
        with open(os.path.join(d, "slots")) as f:
            slots = max(1, min(int(f.read().split()[0]), 16))
    except (OSError, ValueError, IndexError):
        slots = None
    busy = []
    names = [".gate.lock"] + sorted((n for n in os.listdir(d) if re.fullmatch(r"\.slot\.[0-9]+", n)),
                                    key=lambda n: int(n.split(".")[-1]))
    for name in names:
        p = os.path.join(d, name)
        held, line = mmread.flock_held(p)
        if held:
            mode = line[:1] if line and line[:2] in ("S ", "W ", "X ") else "S"
            m = re.match(r"^(?:[SWX] )?(\d+) ", line or "")
            try:
                since = os.stat(p).st_mtime
            except OSError:
                since = None
            busy.append({"slot": name, "mode": mode, "pid": int(m.group(1)) if m else None, "label": line,
                         "since": since, "kind": kind_of(line, mode) if kind_of else None})
    tickets = []
    qdir = os.path.join(d, "queue")
    try:
        entries = sorted(os.listdir(qdir))
    except OSError:
        entries = []
    for name in entries:
        if name.startswith("."):
            continue
        held, line = mmread.flock_held(os.path.join(qdir, name))
        if not held:
            continue  # a dead ticket: the queue removes it; we only skip it
        try:
            born = int(name.split("-", 1)[0]) / 1e9
        except ValueError:
            born = None
        mode = line[:1] if line and line[:2] in ("S ", "W ", "X ") else "O"
        tickets.append({"name": name, "mode": mode, "age_s": None if born is None else now - born, "label": line,
                        "kind": kind_of(line, mode) if kind_of else None})
    return {"slots": slots, "busy": busy, "tickets": tickets}


class Queue:
    def __init__(self, cfg):
        self.cfg = cfg
        self.dir = mmcore.expand(cfg["dir"])
        self.patterns = [(re.compile(p), k) for p, k in cfg.get("kind_patterns", [])]

    def slots_path(self):
        return os.path.join(self.dir, self.cfg.get("slots_file", "slots"))

    def sample_log(self):
        return os.path.join(self.dir, self.cfg.get("sample_log", "load.log"))

    def history_log(self):
        return os.path.join(self.dir, self.cfg.get("history_log", "history.log"))

    def kind_of(self, text, mode=None):
        if mode == "W":
            return self.cfg.get("wide_mode_kind", "wide")
        if mode == "X":
            return self.cfg.get("exclusive_mode_kind", "exclusive")
        for r, k in self.patterns:
            if r.search(text or ""):
                return k
        return "other"

    def read(self, now=None):
        return read_queue(self.dir, now, self.kind_of)

    def last_sample(self, now):
        """The sampler's newest line as a sample, with its age in seconds (None when missing)."""
        ll = mmread.last_line(self.sample_log())
        lp = parse_load_line(ll, time.localtime(now).tm_year) if ll else None
        try:
            age = now - os.path.getmtime(self.sample_log())
        except OSError:
            age = None
        return lp, age

    parse_history = staticmethod(parse_history_line)

    def medians(self, max_bytes=2 << 20):
        """Median run minutes per kind from the newest history rows (rc 0 only)."""
        import statistics
        runs = {}
        f = self.history_log()
        try:
            with open(f, "rb") as fh:
                fh.seek(max(0, os.path.getsize(f) - max_bytes))
                data = fh.read().decode("utf-8", "replace").splitlines()[1:]
        except OSError:
            return {}
        for line in data:
            c = parse_history_line(line)
            if c and c.get("rc") == "0":
                runs.setdefault(self.kind_of(c.get("cmd"), c.get("mode")), []).append(c["run"] / 60.0)
        return {k: statistics.median(v) for k, v in runs.items() if v}

    def launcher(self):
        return [sys.executable, "-I", os.path.join(self.dir, self.cfg["launcher"])]

    def exclusive_argv(self, cmd):
        return self.launcher() + ["--exclusive", "--"] + list(cmd)

    def exclusive_env(self):
        return dict(self.cfg.get("exclusive_env", {}))

    def shared_argv(self, cmd):
        return self.launcher() + ["--"] + list(cmd)
