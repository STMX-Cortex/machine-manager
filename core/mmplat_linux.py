# SPDX-License-Identifier: Apache-2.0
"""machine-manager platform backend: Linux, reduced form. mmread loads it when mmplat.PLATFORM is not "darwin".

The same names as mmplat_darwin. The memory readings are unknown (None) for now: the Linux memory readings and
rules come in a later stage. Only plain facts are read here, each by a pure parser of the file's text:
the core count (os.cpu_count), CPU ticks and the boot time from /proc/stat, a process's argument list from
/proc/<pid>/cmdline. Commands the tool cannot run here are None, and their callers skip them. It loads no ctypes and
no macOS symbol; nothing here runs at import time but os.path checks. Nothing here runs a subprocess.
"""
import os


def _read(path_, limit=1 << 20):
    try:
        with open(path_, "rb") as f:
            return f.read(limit)
    except OSError:
        return None


def _first_exe(paths):
    """The first path that is an executable file, or None."""
    return next((p for p in paths if os.path.isfile(p) and os.access(p, os.X_OK)), None)


# --------------------------------------------------------------------------------------------- pure parsers

def parse_proc_stat_cpu(text):
    """/proc/stat's `cpu` line (all CPUs) -> (user, system, idle, nice, iowait, irq, softirq, steal) ticks, or None.
    The second value is system time, as in mmplat_darwin.cpu_ticks, so mmread.sys_pct reads both alike; the sum
    of all is the total."""
    for line in (text or "").splitlines():
        parts = line.split()
        if parts[:1] == ["cpu"]:
            try:
                v = [int(x) for x in parts[1:9]]
            except ValueError:
                return None
            if len(v) < 4:
                return None
            v += [0] * (8 - len(v))  # an old kernel shows fewer columns
            user, nice, system, idle, iowait, irq, softirq, steal = v
            return (user, system, idle, nice, iowait, irq, softirq, steal)
    return None


def parse_proc_stat_btime(text):
    """/proc/stat's `btime` line -> the boot time in epoch seconds, or None."""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "btime":
            try:
                return float(int(parts[1]))
            except ValueError:
                return None
    return None


def parse_cmdline(raw):
    """/proc/<pid>/cmdline bytes (NUL-ended words) -> the argument list, or None when empty (a kernel thread, a zombie).
    Words are decoded as mmplat_darwin.proc_argv does (UTF-8, surrogateescape)."""
    if not raw:
        return None
    words = raw[:-1].split(b"\0") if raw.endswith(b"\0") else raw.split(b"\0")
    return [w.decode("utf-8", "surrogateescape") for w in words]


# --------------------------------------------------------------------------------------------- readings

def sysctl_raw(name):
    """No sysctl by name on Linux: always None (unknown)."""
    return None


def sysctl_int(name):
    return None


def swapusage():
    return None  # a later stage: /proc/meminfo


def vm_stats():
    return None  # macOS only (the compressor)


def cpu_ticks():
    """CPU ticks from /proc/stat (parse_proc_stat_cpu), or None."""
    raw = _read("/proc/stat")
    return parse_proc_stat_cpu(raw.decode("ascii", "replace")) if raw is not None else None


def _page():
    try:
        return os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError):
        return None


PAGE = _page() or 4096
CORES = os.cpu_count() or 10


def memory_readings():
    """The memory part of one fast sample: every value unknown (None) until the Linux memory stage."""
    return {"free_pct": None, "swap_total_mb": None, "swap_used_mb": None, "comp_mb": None, "pressure": None,
            "seg_pct": None}


def proc_argv(pid):
    """A process's argument list from /proc/<pid>/cmdline, or None when it cannot be read (gone, another user, empty).
    A later stage checks what a process can do to its own cmdline (it can rewrite it)."""
    return parse_cmdline(_read("/proc/%d/cmdline" % int(pid)))


def boot_time():
    """The boot time from /proc/stat btime, or None."""
    raw = _read("/proc/stat")
    return parse_proc_stat_btime(raw.decode("ascii", "replace")) if raw is not None else None


# --------------------------------------------------------------------------------------------- commands and places

_PS = _first_exe(("/bin/ps", "/usr/bin/ps"))
# POSIX `ps -e -o`. Note for the process stage: Linux `comm` is cut at 15 characters.
PS_ARGV = [_PS, "-eo", "pid=,ppid=,rss=,%cpu=,comm="] if _PS else None
PS_ARGS_ARGV = [_PS, "-ww", "-eo", "args="] if _PS else None  # -ww: no cut at 80 columns into a pipe


def ps_lstart_argv(pid):
    return [_PS, "-o", "lstart=", "-p", str(int(pid))] if _PS else None


LSOF = _first_exe(("/usr/bin/lsof", "/usr/sbin/lsof"))  # Debian: /usr/bin; Red Hat: /usr/sbin; else none
DATA_VOLUME = "/"
COMMAND_READINGS = False  # no macOS commands: no cross-check, no fallback sampler, no READINGS_MISMATCH
KERNEL_LOG = None  # no `log stream`
PMSET = None  # power unknown
PANIC_DIR = None  # no panic report folder
USER_TEMP_ARGV = None  # {user_tmp} is tempfile.gettempdir()
SERVICE = None  # no service yet (the systemd stage comes later): the service verbs refuse with E_PLATFORM
EVIDENCE_ARGVS = []  # the bundle's readings.txt notes that they are skipped


def banner_argv(text):
    """No notification command here: the banner is skipped."""
    return None
