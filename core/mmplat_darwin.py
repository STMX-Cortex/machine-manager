# SPDX-License-Identifier: Apache-2.0
"""machine-manager platform backend: macOS (the full tool). mmread loads it when mmplat.PLATFORM is "darwin".

Fast readings by system calls through ctypes (no fork): sysctl, the Mach host statistics, KERN_PROCARGS2 for a
process's argument list, kern.boottime. The command paths the tool runs differ per platform; this file names the
macOS ones. mmplat_linux carries the same names. Nothing here runs a subprocess; mmread and the callers do.
"""
import ctypes
import ctypes.util
import struct

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


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


PAGE = sysctl_int("vm.pagesize") or 16384
CORES = sysctl_int("hw.ncpu") or 10


def memory_readings():
    """The memory part of one fast sample: free_pct, swap_total_mb, swap_used_mb, comp_mb, pressure, seg_pct."""
    s = {}
    s["free_pct"] = sysctl_int("kern.memorystatus_level")  # the number memory_pressure prints as 'free percentage'
    su = swapusage()
    s["swap_total_mb"], s["swap_used_mb"] = (su if su else (None, None))
    vm = vm_stats()
    s["comp_mb"] = vm.compressor_page_count * PAGE / 2**20 if vm else None
    s["pressure"] = sysctl_int("kern.memorystatus_vm_pressure_level")
    seg, lim = sysctl_int("vm.compressor.segment.total"), sysctl_int("vm.compressor.segment.limit")
    s["seg_pct"] = seg * 100.0 / lim if seg is not None and lim else None
    return s


_CTL_KERN, _KERN_PROCARGS2 = 1, 49  # sys/sysctl.h


def proc_argv(pid):
    """A process's exact argument list (sysctl KERN_PROCARGS2: argc, the executable path, then argc NUL-ended words),
    or None when it cannot be read (the process is gone or belongs to another user)."""
    size = sysctl_int("kern.argmax")
    if not size or size <= 4:
        return None
    mib = (ctypes.c_int * 3)(_CTL_KERN, _KERN_PROCARGS2, int(pid))
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(size)
    if _libc.sysctl(mib, ctypes.c_uint(3), buf, ctypes.byref(n), None, ctypes.c_size_t(0)) != 0 or n.value < 4:
        return None
    raw = buf.raw[:n.value]
    argc = struct.unpack("=i", raw[:4])[0]
    rest = raw[4:]
    end = rest.find(b"\0")  # the end of the executable path; NUL padding follows it
    if argc < 1 or end < 0:
        return None
    words = rest[end:].lstrip(b"\0").split(b"\0")
    if len(words) < argc:
        return None
    return [w.decode("utf-8", "surrogateescape") for w in words[:argc]]


def boot_time():
    """kern.boottime (struct timeval) in epoch seconds, or None."""
    raw = sysctl_raw("kern.boottime")
    if raw is None or len(raw) < 16:
        return None
    sec, usec = struct.unpack("<qq", raw[:16])
    return sec + usec / 1e6


# --------------------------------------------------------------------------------------------- commands and places

PS_ARGV = ["/bin/ps", "-axo", "pid=,ppid=,rss=,%cpu=,comm="]  # mmread.parse_ps
PS_ARGS_ARGV = ["/bin/ps", "-axo", "args="]  # every command line (mmrecover.missing_jobs)


def ps_lstart_argv(pid):
    """One process's start time as ps prints it (mmrecover.start_time)."""
    return ["/bin/ps", "-o", "lstart=", "-p", str(int(pid))]


LSOF = "/usr/sbin/lsof"
DATA_VOLUME = "/System/Volumes/Data"  # free disk (statvfs)
COMMAND_READINGS = True  # memory_pressure, sysctl and vm_stat: the daily cross-check and the fallback sampler
KERNEL_LOG = "/usr/bin/log"  # `log stream`: kernel memorystatus events
PMSET = "/usr/bin/pmset"  # power: AC or battery
PANIC_DIR = "/Library/Logs/DiagnosticReports"  # kernel panic reports (names only)
USER_TEMP_ARGV = ["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"]  # the {user_tmp} placeholder
SERVICE = "launchd"  # mm install, stop, start, rollback, the watchdog's restart
# the evidence bundle's readings.txt
EVIDENCE_ARGVS = [["/usr/bin/vm_stat"], ["/usr/sbin/sysctl", "vm.swapusage", "vm.loadavg", "vm.compressor.segment.total",
                                         "kern.memorystatus_level"], ["/usr/bin/memory_pressure", "-Q"]]


def banner_argv(text):
    """The notification command for an ACTION alert's cleaned text (osascript)."""
    return ["/usr/bin/osascript", "-e", 'display notification "%s" with title "machine-manager"' % text]
