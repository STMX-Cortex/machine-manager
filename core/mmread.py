# SPDX-License-Identifier: Apache-2.0
"""machine-manager readings (project-free). Fast readings use system calls through ctypes (no fork);
the slower ones run one subprocess each with a time limit. Every parser takes text, so tests feed fake inputs.
Project formats (a queue's sampler log, its history, a session's files) live in the adapters.
"""
import ctypes
import ctypes.util
import fcntl
import json
import os
import re
import struct
import subprocess
import threading
import time

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


_LIVE, _LIVE_LOCK = set(), threading.Lock()


def run(argv, timeout=10, env=None):
    """(returncode, stdout) of a command with a time limit; (None, '') when it cannot run or times out.
    Each running command is known to kill_children(), so a stop can end them (a du of 30 min, a gh call)."""
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env)
    except (OSError, subprocess.SubprocessError):
        return None, ""
    with _LIVE_LOCK:
        _LIVE.add(p)
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out
    except subprocess.SubprocessError:
        p.kill()
        try:
            p.communicate(timeout=5)
        except subprocess.SubprocessError:
            pass
        return None, ""
    finally:
        with _LIVE_LOCK:
            _LIVE.discard(p)


def kill_children():
    """Kill every command run() has running now (any thread). Returns how many."""
    with _LIVE_LOCK:
        live = [p for p in _LIVE if p.poll() is None]
    for p in live:
        try:
            p.kill()
        except OSError:
            pass
    return len(live)


# --------------------------------------------------------------------------------------------- sysctl by ctypes

def sysctl_raw(name):
    size = ctypes.c_size_t(0)
    if _libc.sysctlbyname(name.encode(), None, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if _libc.sysctlbyname(name.encode(), buf, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
        return None
    return buf.raw[:size.value]


def sysctl_int(name):
    raw = sysctl_raw(name)
    if raw is None:
        return None
    if len(raw) == 4:
        return struct.unpack("<i", raw)[0]
    if len(raw) == 8:
        return struct.unpack("<q", raw)[0]
    return None


def swapusage():
    """(total_mb, used_mb) from vm.swapusage (struct xsw_usage: u64 total, avail, used; u32 pagesize; bool encrypted)."""
    raw = sysctl_raw("vm.swapusage")
    if raw is None or len(raw) < 24:
        return None
    total, _avail, used = struct.unpack("<QQQ", raw[:24])
    return total / 2**20, used / 2**20


class _VMStats64(ctypes.Structure):
    _fields_ = [("free_count", ctypes.c_uint32), ("active_count", ctypes.c_uint32), ("inactive_count", ctypes.c_uint32),
                ("wire_count", ctypes.c_uint32), ("zero_fill_count", ctypes.c_uint64), ("reactivations", ctypes.c_uint64),
                ("pageins", ctypes.c_uint64), ("pageouts", ctypes.c_uint64), ("faults", ctypes.c_uint64),
                ("cow_faults", ctypes.c_uint64), ("lookups", ctypes.c_uint64), ("hits", ctypes.c_uint64),
                ("purges", ctypes.c_uint64), ("purgeable_count", ctypes.c_uint32), ("speculative_count", ctypes.c_uint32),
                ("decompressions", ctypes.c_uint64), ("compressions", ctypes.c_uint64), ("swapins", ctypes.c_uint64),
                ("swapouts", ctypes.c_uint64), ("compressor_page_count", ctypes.c_uint32), ("throttled_count", ctypes.c_uint32),
                ("external_page_count", ctypes.c_uint32), ("internal_page_count", ctypes.c_uint32),
                ("total_uncompressed_pages_in_compressor", ctypes.c_uint64)]


_HOST_VM_INFO64, _HOST_CPU_LOAD_INFO = 4, 3
_libc.mach_host_self.restype = ctypes.c_uint32


def vm_stats():
    """The host's vm_statistics64 (as vm_stat prints it), or None."""
    st = _VMStats64()
    count = ctypes.c_uint32(ctypes.sizeof(st) // 4)
    rc = _libc.host_statistics64(_libc.mach_host_self(), _HOST_VM_INFO64, ctypes.byref(st), ctypes.byref(count))
    return st if rc == 0 else None


def cpu_ticks():
    """(user, system, idle, nice) ticks summed over all CPUs, or None."""
    ticks = (ctypes.c_uint32 * 4)()
    count = ctypes.c_uint32(4)
    rc = _libc.host_statistics(_libc.mach_host_self(), _HOST_CPU_LOAD_INFO, ctypes.byref(ticks), ctypes.byref(count))
    return tuple(ticks) if rc == 0 else None


def sys_pct(prev, cur):
    """System CPU % between two cpu_ticks() readings (as top's 'sys')."""
    if not prev or not cur:
        return None
    d = [c - p for c, p in zip(cur, prev)]
    total = sum(d)
    return None if total <= 0 else d[1] * 100.0 / total


PAGE = sysctl_int("vm.pagesize") or 16384
CORES = sysctl_int("hw.ncpu") or 10


def memory_sample(t, prev_ticks=None):
    """One fast sample. Returns (sample, ticks)."""
    s = {"t": t}
    s["free_pct"] = sysctl_int("kern.memorystatus_level")  # the number memory_pressure prints as 'free percentage'
    su = swapusage()
    s["swap_total_mb"], s["swap_used_mb"] = (su if su else (None, None))
    vm = vm_stats()
    s["comp_mb"] = vm.compressor_page_count * PAGE / 2**20 if vm else None
    s["pressure"] = sysctl_int("kern.memorystatus_vm_pressure_level")
    seg, lim = sysctl_int("vm.compressor.segment.total"), sysctl_int("vm.compressor.segment.limit")
    s["seg_pct"] = seg * 100.0 / lim if seg is not None and lim else None
    try:
        s["load1"], s["load5"], _ = os.getloadavg()
    except OSError:
        s["load1"] = s["load5"] = None
    ticks = cpu_ticks()
    s["sys_pct"] = sys_pct(prev_ticks, ticks)
    return s, ticks


def command_readings():
    """The same facts from the macOS commands (memory_pressure, sysctl vm.swapusage, vm_stat, sysctl vm.loadavg).
    Slower (4 subprocesses); used for the cross-check and as the fallback sampler."""
    out = {}
    rc, t = run(["/usr/bin/memory_pressure", "-Q"], timeout=20)
    out["free_pct"] = parse_memory_pressure(t) if rc == 0 else None
    rc, t = run(["/usr/sbin/sysctl", "vm.swapusage"], timeout=10)
    su = parse_swapusage(t) if rc == 0 else None
    out["swap_total_mb"], out["swap_used_mb"] = su if su else (None, None)
    rc, t = run(["/usr/bin/vm_stat"], timeout=10)
    d = parse_vm_stat(t) if rc == 0 else {}
    out["comp_mb"] = (d["Pages occupied by compressor"] * d["page_size"] / 2**20
                      if "Pages occupied by compressor" in d and "page_size" in d else None)
    rc, t = run(["/usr/sbin/sysctl", "vm.loadavg"], timeout=10)
    la = parse_loadavg(t) if rc == 0 else None
    out["load1"], out["load5"] = (la[0], la[1]) if la else (None, None)
    return out


# The largest gap between a fast reading and its command that still counts as the same fact (T13's limits).
CHECK_LIMITS = {"free_pct": lambda c: 1.0, "swap_total_mb": lambda c: 1.0,
                "swap_used_mb": lambda c: max(0.01 * (c.get("swap_total_mb") or 0), 1.0),
                "comp_mb": lambda c: max(0.01 * (c.get("comp_mb") or 0), 4.0), "load5": lambda c: 1.0}


def compare_readings(fast, cmd):
    """Pure: the keys whose fast value differs from the command value beyond CHECK_LIMITS (a missing value counts)."""
    bad = []
    for k, lim in CHECK_LIMITS.items():
        a, b = fast.get(k), cmd.get(k)
        if b is None:
            continue  # the command failed: nothing to compare (the stale-source alert covers it)
        if a is None or abs(a - b) > lim(cmd):
            bad.append("%s fast=%s command=%s" % (k, "none" if a is None else "%.1f" % a, "%.1f" % b))
    return bad


def check_readings(t=None):
    """The macOS change check: one fast sample against the commands. Returns (problems, fast, cmd)."""
    fast, _ = memory_sample(time.time() if t is None else t)
    cmd = command_readings()
    return compare_readings(fast, cmd), fast, cmd


def command_sample(t, prev_ticks=None):
    """The fallback sampler: the commands' values plus the system calls the check did not question."""
    s, ticks = memory_sample(t, prev_ticks)
    s.update({k: v for k, v in command_readings().items() if v is not None})
    return s, ticks


# --------------------------------------------------------------------------------------------- text parsers (T1)

def parse_vm_stat(text):
    """vm_stat output -> {'page_size': n, '<name>': pages}."""
    out = {}
    m = re.search(r"page size of (\d+) bytes", text)
    if m:
        out["page_size"] = int(m.group(1))
    for line in text.splitlines():
        m = re.match(r'^"?([^":]+)"?:\s+(\d+)\.?$', line.strip())
        if m:
            out[m.group(1).strip()] = int(m.group(2))
    return out


def parse_memory_pressure(text):
    m = re.search(r"System-wide memory free percentage:\s*([0-9.]+)%", text)
    return float(m.group(1)) if m else None


def parse_swapusage(text):
    """'total = 2048.00M  used = 499.38M  free = ...' -> (total_mb, used_mb)."""
    units = {"K": 1 / 1024, "M": 1, "G": 1024}
    vals = {}
    for k in ("total", "used"):
        m = re.search(r"\b%s\s*=\s*([0-9.]+)([KMG])" % k, text)
        if not m:
            return None
        vals[k] = float(m.group(1)) * units[m.group(2)]
    return vals["total"], vals["used"]


def parse_loadavg(text):
    nums = re.findall(r"[0-9]+\.[0-9]+", text)
    return tuple(float(x) for x in nums[:3]) if len(nums) >= 3 else None


def parse_df_free_gb(text):
    """`df -k <volume>` -> free GB (10^9 bytes, as disk-watch)."""
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        return None
    parts = lines[-1].split()
    try:
        return int(parts[3]) * 1024 / 1e9
    except (IndexError, ValueError):
        return None


def disk_free_gb(volume="/System/Volumes/Data"):
    try:
        st = os.statvfs(volume)
        return st.f_bavail * st.f_frsize / 1e9
    except OSError:
        return None


def _mb(v, unit):
    return float(v) * {"K": 1 / 1024, "M": 1, "G": 1024}[unit]


def parse_pmset(text):
    """`pmset -g batt` -> True on AC, False on battery, None when unknown."""
    if "AC Power" in text:
        return True
    if "Battery Power" in text:
        return False
    return None


_KERNEL_RE = re.compile(r"memorystatus: (suspending (\S.*?) \[(\d+)\] due to (.*)|triggering no paging space action)")


def parse_kernel_line(line):
    """A `log stream --style ndjson` line (or a plain log line) -> event dict for the two memorystatus events, or None."""
    text = line
    stamp = None
    try:
        d = json.loads(line)
        if isinstance(d, dict):
            text = d.get("eventMessage", "")
            stamp = d.get("timestamp")
    except ValueError:
        m = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)", line)
        stamp = m.group(1) if m else None
    m = _KERNEL_RE.search(text or "")
    if not m:
        return None
    if m.group(2):
        return {"kind": "suspending", "process": m.group(2), "pid": int(m.group(3)), "why": m.group(4).strip(), "time": stamp}
    return {"kind": "no-paging-space", "time": stamp}


def parse_ps(text):
    """`ps -axo pid=,ppid=,rss=,%cpu=,comm=` -> list of dicts."""
    out = []
    for line in text.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        try:
            out.append({"pid": int(parts[0]), "ppid": int(parts[1]), "rss_mb": int(parts[2]) / 1024,
                        "cpu": float(parts[3]), "comm": parts[4]})
        except ValueError:
            continue
    return out



def live_named(procs, spec):
    """Processes that are live tool runs, by process NAME only, never by command text (a shell's text can name a tool it does not run).
    spec: {names: [exact basenames], suffixes: [basename endings], path_regexes: [regexes on the name]}."""
    names = set(spec.get("names", []))
    suffixes = tuple(spec.get("suffixes", []))
    regs = [re.compile(r) for r in spec.get("path_regexes", [])]
    out = []
    for p in procs:
        base = os.path.basename(p["comm"])
        if base in names or (suffixes and base.endswith(suffixes)) or any(r.search(p["comm"]) for r in regs):
            out.append(p)
    return out


def descendants(procs, root_pid):
    kids = {}
    for p in procs:
        kids.setdefault(p["ppid"], []).append(p["pid"])
    out, todo = [], [root_pid]
    while todo:
        pid = todo.pop()
        out.append(pid)
        todo.extend(kids.get(pid, []))
    return out


def read_ps():
    rc, out = run(["/bin/ps", "-axo", "pid=,ppid=,rss=,%cpu=,comm="], timeout=10)
    return parse_ps(out) if rc == 0 else None


# --------------------------------------------------------------------------------------------- the queue (read only)


def flock_held(path_):
    """(held, first line): another process holds an flock on the file."""
    try:
        with open(path_) as f:
            try:
                fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)
                fcntl.flock(f, fcntl.LOCK_UN)
                return False, None
            except BlockingIOError:
                return True, f.readline().rstrip("\r\n")[:240]
    except FileNotFoundError:
        return False, None


class Tail:
    """Reads new complete lines of a growing file from a saved byte offset (restarts at 0 when the file shrinks)."""

    def __init__(self, file, offset=None):
        self.file = file
        self.offset = offset

    def new_lines(self, start_at_end=True, limit=1 << 20):
        try:
            size = os.path.getsize(self.file)
        except OSError:
            return None
        if self.offset is None:
            self.offset = size if start_at_end else 0
        if size < self.offset:
            self.offset = 0
        with open(self.file, "rb") as f:
            f.seek(self.offset)
            data = f.read(limit)
        cut = data.rfind(b"\n")
        if cut < 0:
            return []
        self.offset += cut + 1
        return data[:cut].decode("utf-8", "replace").splitlines()


def last_line(file, nbytes=4096):
    try:
        with open(file, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - nbytes))
            lines = f.read().decode("utf-8", "replace").splitlines()
        return lines[-1] if lines else None
    except OSError:
        return None


# --------------------------------------------------------------------------------------------- other sources

def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


