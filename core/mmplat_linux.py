# SPDX-License-Identifier: Apache-2.0
"""machine-manager Linux backend: /proc memory, swap, PSI, CPU and process identities, with cgroup limits.

mmread loads this backend when mmplat.PLATFORM is "linux". Pure parsers accept fixture text. Unsupported macOS
compressor and power readings remain unknown; the decisions use Linux's applicable readings. Process signals use
pidfds and birth identities to avoid signalling recycled PIDs. Per-user service management lives in mmsystemd.
This module runs no subprocess and loads no macOS bindings.
"""
import os
import math
import signal
import re


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


def parse_meminfo_total_mb(text):
    """/proc/meminfo's `MemTotal:  N kB` -> MB (2^20 bytes) as a whole number, or None."""
    for line in (text or "").splitlines():
        parts = line.split()
        if parts[:1] == ["MemTotal:"] and len(parts) >= 2:
            try:
                kb = int(parts[1])
            except ValueError:
                return None
            return kb // 1024 if kb > 0 else None
    return None


def parse_cpuinfo_model(text):
    """/proc/cpuinfo's CPU name: the first `model name` (x86), else `Hardware`, else `Processor` (older ARM kernels);
    None when none has a value. Keys match exactly (`processor`, lower case, is the CPU number)."""
    found = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if sep and value and key in ("model name", "Hardware", "Processor"):
            found.setdefault(key, value)
    return next((found[k] for k in ("model name", "Hardware", "Processor") if k in found), None)


# --------------------------------------------------------------------------------------------- readings

def sysctl_raw(name):
    """No sysctl by name on Linux: always None (unknown)."""
    return None


def sysctl_int(name):
    return None


def swapusage():
    raw = _read("/proc/meminfo")
    m = parse_meminfo(raw.decode("ascii", "replace") if raw else "")
    total, free = m.get("SwapTotal"), m.get("SwapFree")
    return (total / 1024, (total - free) / 1024) if total is not None and free is not None and free <= total else None


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
PSI_SUPPORTED = os.path.exists("/proc/pressure/memory")


def memory_readings():
    """Host available memory and swap; PSI from the kernel. Compressor fields are inapplicable, not zero.
    When the kernel exposes PSI, unreadable data stays unknown and trips safe mode. Kernels without PSI use the
    available-memory and swap rules; no pressure value is fabricated.
    The linux flag tells the pure decisions which memory fields apply."""
    raw, psi = _read("/proc/meminfo"), _read("/proc/pressure/memory")
    sample = parse_memory(raw.decode("ascii", "replace") if raw else "",
                          psi.decode("ascii", "replace") if psi else "", PSI_SUPPORTED)
    # Use the tightest cgroup memory boundary, including parent limits. The remaining cgroup room cannot be
    # increased by reclaiming host memory. Ignoring it would classify an almost-OOM container as GREEN.
    total = parse_meminfo_total_mb(raw.decode("ascii", "replace")) if raw else None
    limit, room = cgroup_memory()
    if limit is not None:
        host_room = sample["free_pct"] * total / 100 if sample["free_pct"] is not None else None
        sample["free_pct"] = min(host_room, room) * 100 / min(total, limit) \
            if total and limit > 0 and host_room is not None and room is not None else None
    return sample


def parse_meminfo(text):
    """Valid nonnegative /proc/meminfo sizes in KiB; malformed entries stay absent."""
    out = {}
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) == 3 and p[0].endswith(":") and p[2] == "kB" and p[1].isdigit():
            out[p[0][:-1]] = int(p[1])
    return out


def parse_psi(text):
    """Memory PSI some/full avg10 shares (0..100); missing/invalid lines remain unknown."""
    out = {}
    for line in (text or "").splitlines():
        p = line.split()
        if not p or p[0] not in ("some", "full"):
            continue
        for item in p[1:]:
            if item.startswith("avg10="):
                try:
                    v = float(item[6:])
                    if math.isfinite(v) and 0 <= v <= 100:
                        out[p[0]] = v
                except ValueError:
                    pass
    return out


def parse_memory(meminfo, psi, psi_supported=True):
    m, p = parse_meminfo(meminfo), parse_psi(psi)
    total, available = m.get("MemTotal"), m.get("MemAvailable")
    swap, swapfree = m.get("SwapTotal"), m.get("SwapFree")
    return {"linux": 1, "psi_supported": int(psi_supported), "free_pct": available * 100.0 / total
            if total and available is not None and available <= total else None,
            "swap_total_mb": swap / 1024 if swap is not None else None,
            "swap_used_mb": (swap - swapfree) / 1024
            if swap is not None and swapfree is not None and swapfree <= swap else None,
            "comp_mb": None, "seg_pct": None, "pressure": None,
            "psi_some_pct": p.get("some"), "psi_full_pct": p.get("full")}


def _mount_word(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)


def cgroup_memory():
    """Effective limit/room in MiB, (None, None) if unlimited, (0, None) if unknown.
    Translate the process cgroup through mountinfo, including delegated/subtree mounts. Both v1 memory and v2
    are supported. A malformed or unreadable bound cannot become unlimited; a zero limit has no available room.
    """
    raw = _read("/proc/self/cgroup", 65536)
    mounts = _read("/proc/self/mountinfo", 1 << 20)
    if raw is None or mounts is None:
        return 0, None
    groups = [line.split(":", 2) for line in raw.decode("utf-8", "replace").splitlines()]
    unified = next((x[2] for x in groups if len(x) == 3 and x[:2] == ["0", ""]), None)
    legacy = next((x[2] for x in groups if len(x) == 3 and "memory" in x[1].split(",")), None)
    entry = unified if unified is not None else legacy
    if entry is None:
        return None, None
    candidates = []
    for line in mounts.decode("utf-8", "replace").splitlines():
        before, sep, after = line.partition(" - ")
        left, right = before.split(), after.split()
        if not sep or len(left) < 5 or len(right) < 3:
            continue
        wanted = right[0] == "cgroup2" if unified is not None else right[0] == "cgroup" and "memory" in right[2].split(",")
        if not wanted:
            continue
        root, mount = _mount_word(left[3]), _mount_word(left[4])
        root, entry_norm = os.path.normpath(root), os.path.normpath(entry)
        if not root.startswith("/") or not mount.startswith("/") or not entry_norm.startswith("/"):
            continue
        if os.path.commonpath((root, entry_norm)) != root:
            continue
        path = os.path.join(mount, os.path.relpath(entry_norm, root))
        candidates.append((len(root), os.path.normpath(mount), os.path.normpath(path)))
    if not candidates:
        return 0, None
    _, root, path = min(candidates)  # the widest view retains ancestor limits hidden by a subtree bind mount
    cap_name, used_name = ("memory.max", "memory.current") if unified is not None else ("memory.limit_in_bytes", "memory.usage_in_bytes")
    limits, rooms, unknown = [], [], False
    while True:
        maximum, current = _read(path + "/" + cap_name, 128), _read(path + "/" + used_name, 128)
        if maximum is None:
            # At the hierarchy root the memory controller may not be enabled. Missing child bounds or a
            # present-but-unreadable root bound cannot establish safety.
            if not os.path.isdir(path) or os.path.lexists(path + "/" + cap_name):
                unknown = True
        elif maximum.strip() == b"max" and unified is not None:
            pass
        elif maximum.strip().isdigit():
            cap_bytes = int(maximum.strip())
            if unified is not None or cap_bytes < 1 << 60:  # v1's PAGE_COUNTER_MAX means unlimited
                cap = cap_bytes / 2**20
                limits.append(cap)
                if current and current.strip().isdigit():
                    rooms.append(max(0, cap - int(current.strip()) / 2**20))
                else:
                    unknown = True
        else:
            unknown = True
        if path == root:
            break
        path = os.path.dirname(path)
    if unknown:
        return (min(limits) if limits else 0), None
    return (min(limits), min(rooms)) if limits else (None, None)


def parse_proc_start(text):
    """/proc/PID/stat start ticks (field 22), using the last ')' because comm can contain spaces and ')'."""
    try:
        tail = text[text.rindex(")") + 2:].split()
        ticks = int(tail[19])
        return str(ticks) if ticks >= 0 else None
    except (ValueError, IndexError, TypeError, AttributeError):
        return None


def proc_start(pid):
    raw = _read("/proc/%d/stat" % int(pid), 16384)
    ticks = parse_proc_start(raw.decode("utf-8", "replace")) if raw else None
    boot = _read("/proc/sys/kernel/random/boot_id", 128)
    return "linux:%s:%s" % (boot.decode("ascii", "replace").strip(), ticks) if ticks and boot else None


def proc_parent(pid):
    raw = _read("/proc/%d/stat" % int(pid), 16384)
    try:
        text = raw.decode("utf-8", "replace")
        return int(text[text.rindex(")") + 2:].split()[1])
    except (AttributeError, ValueError, IndexError):
        return None


def proc_exe(pid):
    try:
        return os.readlink("/proc/%d/exe" % int(pid))
    except OSError:
        return None


def proc_interpreter(pid, expected):
    """Kernel executable identity, not argv text (a process can rewrite its own argument bytes)."""
    try:
        return os.path.samefile("/proc/%d/exe" % int(pid), expected)
    except OSError:
        return False


def signal_process(pid, expected, sig):
    """Pin the process with a pidfd before checking its birth identity; never signal a recycled PID.
    Without pidfds the operation fails closed (readings and slot control still work)."""
    if sig not in (signal.SIGSTOP, signal.SIGCONT):
        raise ValueError("only pause and resume signals are permitted")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise OSError("Linux pause/resume requires pidfd support (Linux 5.3+)")
    fd = os.pidfd_open(int(pid))
    try:
        current = proc_start(pid)
        if current is None:
            raise OSError("process identity unreadable")
        if current != expected:
            raise ProcessLookupError("process identity changed")
        signal.pidfd_send_signal(fd, sig)
    finally:
        os.close(fd)


def machine_facts():
    """The machine's static facts, read once by the supervisor at its start: cores (os.cpu_count), cpu_model
    (/proc/cpuinfo), ram_mb (/proc/meminfo MemTotal); p_cores and e_cores None (no such split here)."""
    info, mem = _read("/proc/cpuinfo"), _read("/proc/meminfo")
    ram = parse_meminfo_total_mb(mem.decode("ascii", "replace")) if mem is not None else None
    limit, _ = cgroup_memory()
    return {"cores": os.cpu_count(), "p_cores": None, "e_cores": None,
            "cpu_model": parse_cpuinfo_model(info.decode("utf-8", "replace")) if info is not None else None,
            "ram_mb": (int(min(ram, limit)) if ram and limit > 0 else None) if limit is not None else ram}


def proc_argv(pid):
    """A process's argument list from /proc/<pid>/cmdline, or None when it cannot be read (gone, another user, empty).
    These words are process-controlled; callers must also validate the executable and process birth identity."""
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
SERVICE = "systemd"  # per-user services; never requires root
EVIDENCE_ARGVS = []  # the bundle's readings.txt notes that they are skipped


def banner_argv(text):
    """No notification command here: the banner is skipped."""
    return None
