# SPDX-License-Identifier: Apache-2.0
"""machine-manager readings (project-free). Fast readings use system calls (no fork) through the platform backend
(mmplat: mmplat_darwin by ctypes, mmplat_linux by /proc; `plat` is the chosen one); the slower ones run one subprocess
each with a time limit. Every parser takes text, so tests feed fake inputs. A reading the platform cannot take is None.
Project formats (a queue's sampler log, its history, a session's files) live in the adapters.
"""
import errno
import fcntl
import json
import os
import re
import stat
import subprocess
import selectors
import signal
import sys
import threading
import time

import mmplat
import mmtext

plat = mmplat.backend()  # the platform backend: its readings and command paths


_LIVE, _LIVE_LOCK = set(), threading.Lock()
_LIVE_GROUPS = set()


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


def _kill_owned_group(p):
    """Only a group created by run_bounded's dedicated child session can reach this cleanup path.
    The tiny supervisor child is not reaped before cleanup, so its reserved PID cannot identify a new group.
    """
    with _LIVE_LOCK:
        if p not in _LIVE_GROUPS:
            return False
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        _LIVE_GROUPS.discard(p)
        return True


def kill_children():
    """End owned command groups and other active run() commands on supervisor stop."""
    with _LIVE_LOCK:
        live = [p for p in _LIVE if p in _LIVE_GROUPS or p.poll() is None]
    for p in live:
        try:
            if not _kill_owned_group(p):
                p.kill()
        except OSError:
            pass
    return len(live)


# Keep a known session leader alive until cleanup. It reports the command status through a private descriptor
# (closed in the command), then closes stdout. EOF can precede process exit on macOS, so the leader's status
# after group cleanup cannot be used as the command's status. No group id is reaped/reused before cleanup.
_READER_CHILD = ("import os,signal,subprocess,sys\n"
                 "try: rc=subprocess.call(sys.argv[2:])\n"
                 "except OSError: rc=127\n"
                 "fd=int(sys.argv[1])\n"
                 "os.write(fd,str(rc if 0 <= rc <= 255 else 1).encode('ascii'))\n"
                 "os.close(fd)\n"
                 "os.close(1)\n"
                 "while True: signal.pause()\n")


def run_bounded(argv, timeout=10, max_bytes=65536, cwd=None):
    """Read-only adapter command with bounded stdout/time, no shell/stdin, and cleanup of its owned child group.
    Returns (rc, bytes, error). The private session joins the stop registry; no outside process group is signalled.
    """
    try:
        status_r, status_w = os.pipe()
    except OSError:
        return None, b"", "read command could not start"
    try:
        p = subprocess.Popen([sys.executable, "-I", "-c", _READER_CHILD, str(status_w), *argv],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             cwd=cwd, start_new_session=True, pass_fds=(status_w,))
    except (OSError, subprocess.SubprocessError):
        os.close(status_r)
        return None, b"", "read command could not start"
    finally:
        os.close(status_w)
    with _LIVE_LOCK:
        _LIVE.add(p)
        _LIVE_GROUPS.add(p)
    chunks, size, error = [], 0, None
    deadline = time.monotonic() + timeout
    try:
        os.set_blocking(p.stdout.fileno(), False)
        os.set_blocking(status_r, False)
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    error = "read command timed out"
                    break
                try:
                    part = os.read(p.stdout.fileno(), min(65536, max_bytes + 1 - size))
                except BlockingIOError:
                    continue
                if not part:
                    break
                chunks.append(part)
                size += len(part)
                if size > max_bytes:
                    error = "read command exceeded %d bytes" % max_bytes
                    break
        # The wrapper writes this before closing stdout; never wait on a missing status after an external stop.
        rc = int(os.read(status_r, 16)) if not error else None
        if rc is not None and not 0 <= rc <= 255:
            raise ValueError("invalid command status")
        _kill_owned_group(p)
        p.wait(timeout=1)
        if error:
            return None, b"", error
        return rc, b"".join(chunks), None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None, b"", "read command output unavailable"
    finally:
        _kill_owned_group(p)
        try:
            p.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        p.stdout.close()
        os.close(status_r)
        with _LIVE_LOCK:
            _LIVE.discard(p)


# --------------------------------------------------------------------------------------------- system calls (backend)

# The backend's names, kept here: callers and tests use them as mmread.<name>.
sysctl_raw, sysctl_int, swapusage = plat.sysctl_raw, plat.sysctl_int, plat.swapusage
vm_stats, cpu_ticks, proc_argv, boot_time = plat.vm_stats, plat.cpu_ticks, plat.proc_argv, plat.boot_time
COMMAND_READINGS = plat.COMMAND_READINGS
machine_facts = plat.machine_facts  # static facts (cores, P and E cores, CPU name, memory size): read once at start


def sys_pct(prev, cur):
    """System CPU % between two cpu_ticks() readings (as top's 'sys')."""
    if not prev or not cur:
        return None
    d = [c - p for c, p in zip(cur, prev)]
    total = sum(d)
    return None if total <= 0 else d[1] * 100.0 / total


def cpu_pct(prev, cur):
    """All CPU busy % between two cpu_ticks() readings: 100 minus the idle share (the third value on every backend)."""
    if not prev or not cur:
        return None
    d = [c - p for c, p in zip(cur, prev)]
    total = sum(d)
    return None if total <= 0 else 100.0 - d[2] * 100.0 / total


PAGE = plat.PAGE
CORES = plat.CORES


def memory_sample(t, prev_ticks=None):
    """One fast sample. Returns (sample, ticks). The memory part comes from the backend (plat.memory_readings: free_pct,
    swap, compressor, pressure, segments; None where the platform cannot read it), then the load, system CPU and all CPU."""
    s = {"t": t}
    s.update(plat.memory_readings())
    try:
        s["load1"], s["load5"], _ = os.getloadavg()
    except OSError:
        s["load1"] = s["load5"] = None
    ticks = cpu_ticks()
    s["sys_pct"] = sys_pct(prev_ticks, ticks)
    s["cpu_pct"] = cpu_pct(prev_ticks, ticks)  # shown only (status.json, mm resources); no rule reads it
    return s, ticks


def command_readings():
    """The same facts from the macOS commands (memory_pressure, sysctl vm.swapusage, vm_stat, sysctl vm.loadavg).
    Slower (4 subprocesses); used for the cross-check and as the fallback sampler. {} where the platform has no such
    commands (COMMAND_READINGS false): nothing to compare, so no mismatch, and the fallback adds nothing."""
    out = {}
    if not COMMAND_READINGS:
        return out
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


def disk_free_gb(volume=None):
    """Free GB (10^9 bytes) of the volume (default: the platform's data volume, plat.DATA_VOLUME), or None."""
    try:
        volume = volume or plat.DATA_VOLUME
        st = os.statvfs(volume)
        return st.f_bavail * st.f_frsize / 1e9
    except OSError:
        return None


def disk_total_gb(volume=None):
    """Total GB (10^9 bytes) of the volume (default: plat.DATA_VOLUME), or None."""
    try:
        st = os.statvfs(volume or plat.DATA_VOLUME)
        return st.f_blocks * st.f_frsize / 1e9
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


# The name runs to the LAST " [<pid>] due to " (R5C-3): an executable's name may hold those words; macOS's pid and
# reason come last.
_KERNEL_RE = re.compile(r"memorystatus: (suspending (\S.*) \[(\d+)\] due to (.*)|triggering no paging space action)")


def parse_kernel_line(line):
    """A `log stream --style ndjson` line (or a plain log line) -> event dict for the two memorystatus events, or None.
    The patterns see the message's lines cut (mmtext.search, C-22)."""
    text = line
    stamp = None
    try:
        d = json.loads(line)
        if isinstance(d, dict):
            text = d.get("eventMessage", "")
            stamp = d.get("timestamp")
    except ValueError:
        m = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)", mmtext.cut(line))
        stamp = m.group(1) if m else None
    m = mmtext.search(_KERNEL_RE, text if isinstance(text, str) else "")
    if not m:
        return None
    if m.group(2):
        return {"kind": "suspending", "process": m.group(2), "pid": int(m.group(3)), "why": m.group(4).strip(), "time": stamp}
    return {"kind": "no-paging-space", "time": stamp}


def parse_ps(text):
    """`ps -axo pid=,ppid=,rss=,%cpu=,comm=` -> list of dicts. Records end only at line feeds (C-22): a name an agent
    chose may hold any other line-breaking character."""
    out = []
    for line in mmtext.split_lines(text):
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
        if p.get("name_truncated") and (any(n.startswith(base) for n in names) or suffixes or regs):
            out.append(p)  # Linux comm truncation must not hide a live tool from a delete/trim guard.
            continue
        # a guard's pattern (deletes and trims wait for a live run): a name too long to see whole counts as a match,
        # so the guard fails closed (C-22a)
        live_re = regs and (mmtext.too_long(p["comm"]) or any(mmtext.search(r, p["comm"]) for r in regs))
        alias = p.get("name_alias", "")
        if p.get("alias_truncated") and (suffixes or regs):
            out.append(dict(p, comm=alias))
            continue
        alias_match = alias and (alias in names or (suffixes and alias.endswith(suffixes)) or
                                 (len(alias) >= 15 and any(n.startswith(alias) for n in names)))
        if alias_match:
            out.append(dict(p, comm=alias))  # show the name that actually matched the guard
        elif base in names or (suffixes and base.endswith(suffixes)) or live_re:
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
    """The process list (parse_ps), or None when ps is missing, fails or times out (callers fail closed)."""
    if not plat.PS_ARGV:
        return None
    rc, out = run(plat.PS_ARGV, timeout=10)
    if rc != 0:
        return None
    procs = parse_ps(out)
    if plat.SERVICE == "systemd":
        for p in procs:
            p["start_time"] = plat.proc_start(p["pid"])
            exe = plat.proc_exe(p["pid"])
            if exe:
                p["name_alias"] = os.path.basename(p["comm"])
                p["alias_truncated"] = len(p["name_alias"]) >= 15
                p["comm"] = exe.removesuffix(" (deleted)")
            elif len(os.path.basename(p["comm"])) >= 15:
                p["name_truncated"] = True
            if plat.proc_parent(p["pid"]) != p["ppid"] or plat.proc_start(p["pid"]) != p["start_time"]:
                p["start_time"] = None  # a stale ps row cannot choose a replacement process for a pause
    return procs


def file_writers(path_, timeout):
    """Pids of every process that has the file open with write access (lsof access `u` read-write or `w` write-only,
    on any of its descriptors); a read-only opener is not one. None when lsof is missing, cannot run or times out."""
    if not plat.LSOF:
        return None
    rc, out = run([plat.LSOF, "-F", "pa", "--", path_], timeout=timeout)
    if rc not in (0, 1):  # 1: no process has it open
        return None
    pids, pid = set(), None
    for line in mmtext.split_lines(out):  # file names are agent text: records end only at line feeds
        if line[:1] == "p" and line[1:].isdigit():
            pid = int(line[1:])
        elif line[:1] == "a" and line[1:] in ("u", "w") and pid is not None:
            pids.add(pid)
    return sorted(pids)


def proc_cwd(pid, timeout):
    """A process's working folder (lsof), or None when lsof cannot tell (the process is gone, lsof is missing, fails or
    times out)."""
    if not plat.LSOF:
        return None
    rc, out = run([plat.LSOF, "-a", "-p", str(int(pid)), "-d", "cwd", "-Fn"], timeout=timeout)
    if rc != 0:
        return None
    for line in mmtext.split_lines(out):
        if line[:1] == "n" and os.path.isabs(line[1:]):
            return line[1:]
    return None


# --------------------------------------------------------------------------------------------- the queue (read only)


# Bytes read from a file that agents may write (a queue slot or ticket file, a cache marker): the first line of a
# label, or a marker text, is far shorter.
FILE_READ_MAX = 4096


class NotRegular(Exception):
    """The path holds a link, a FIFO, a folder or another kind of file, not a regular file."""


def open_regular(path_):
    """A read-only descriptor of the regular file at path_, opened without following a link and without waiting (a FIFO
    opens at once). Raises NotRegular for anything else at the path (a socket, which cannot be opened, too), and OSError
    for a regular file that cannot be opened (FileNotFoundError when nothing is there)."""
    try:
        fd = os.open(path_, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError as e:
        if e.errno == errno.ELOOP:  # O_NOFOLLOW on a link
            raise NotRegular(path_) from None
        if e.errno != errno.ENOENT:  # e.g. EOPNOTSUPP for a socket, EACCES for a mode-000 file: which kind is there?
            try:
                regular = stat.S_ISREG(os.lstat(path_).st_mode)
            except OSError:
                regular = True  # the kind is unknown: the open's own error stands
            if not regular:
                raise NotRegular(path_) from None
        raise
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise NotRegular(path_)
    return fd


def read_regular(path_, limit=FILE_READ_MAX):
    """At most `limit` bytes from the start of the regular file at path_ (open_regular), or None when it is missing,
    not a regular file or unreadable."""
    try:
        fd = open_regular(path_)
    except (OSError, NotRegular):
        return None
    try:
        return os.read(fd, limit)
    except OSError:
        return None
    finally:
        os.close(fd)


# flock_held's third value: why the file counts as not held (None: no problem).
NOT_A_FILE = "not_a_file"  # a link, a FIFO, a socket or another kind that is not a regular file (SLOT_NOT_A_FILE)
UNREADABLE = "unreadable"  # a regular file that cannot be opened or read, as a mode-000 file (QUEUE_FILE_UNREADABLE)


def flock_held(path_):
    """(held, first line, problem): another process holds an flock on the regular file at path_. It is opened with
    open_regular and at most FILE_READ_MAX bytes are read. Any error costs only this file: it counts as not held, with
    problem NOT_A_FILE (not a regular file) or UNREADABLE (any other error opening, locking or reading it); a missing
    file is not held, with no problem."""
    try:
        fd = open_regular(path_)
    except FileNotFoundError:
        return False, None, None
    except NotRegular:
        return False, None, NOT_A_FILE
    except OSError:
        return False, None, UNREADABLE
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False, None, None
        except BlockingIOError:
            first = os.read(fd, FILE_READ_MAX).split(b"\n", 1)[0]
            return True, first.decode("utf-8", "replace").rstrip("\r")[:240], None
    except OSError:
        return False, None, UNREADABLE
    finally:
        os.close(fd)


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
        return mmtext.split_lines(data[:cut].decode("utf-8", "replace"))  # agent files: records end at line feeds


def last_line(file, nbytes=4096):
    try:
        with open(file, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - nbytes))
            lines = mmtext.split_lines(f.read().decode("utf-8", "replace"))
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


