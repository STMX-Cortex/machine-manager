# SPDX-License-Identifier: Apache-2.0
"""machine-manager core (project-free): paths, atomic files, locks, settings, the profile, records, masking and the
alert store.

Python 3 standard library only (3.11+ for tomllib). Nothing here names a project or a machine. The code finds its own
folder from this file; project values come from a profile (TOML); live data goes to a data folder outside the code.
The decisions are pure functions in mmdecide.
"""
import fcntl
import json
import re
import os
import socket
import time

import mmdecide

CORE = os.path.dirname(os.path.realpath(__file__))
CODE = os.path.dirname(CORE)
BIN = os.path.join(CODE, "bin")
SCHEMA_VERSION = 1
DEFAULT_LABEL_PREFIX = "com.example.machine-manager"

LEVELS = mmdecide.LEVELS


class MMError(Exception):
    """An error with a stable code, one line: `<code> <what failed>; fix: <the fix>`."""

    def __init__(self, code, what, fix):
        super().__init__("%s %s; fix: %s" % (code, what, fix))
        self.code = code


def base_dir():
    """Where installs live: MM_BASE, else ~/Library/Application Support/machine-manager."""
    return os.path.abspath(os.path.expanduser(os.environ.get("MM_BASE") or "~/Library/Application Support/machine-manager"))


def install_record():
    """base_dir()/install.json, written by `mm install`: {profile, data, ...}; None when not installed."""
    d = read_json(os.path.join(base_dir(), "install.json"), None)
    return d if isinstance(d, dict) else None


def profile_file():
    """The profile's path: MM_PROFILE (a path, or a name in the code's profiles/), else the installed one."""
    p = os.environ.get("MM_PROFILE")
    if p:
        if os.sep in p or p.endswith(".toml"):
            return os.path.abspath(os.path.expanduser(p))
        return os.path.join(CODE, "profiles", p + ".toml")
    rec = install_record()
    if rec and rec.get("profile"):
        return rec["profile"]
    raise MMError("E_NO_PROFILE", "no profile chosen", "mm init --profile <name>, or --profile <file>, or mm install")


def data_dir():
    """The live data folder (alerts, status, metrics, state/, evidence/, deletes.log, settings.toml, off.json):
    MM_DATA, else the installed one, else base_dir()/<profile name>."""
    d = os.environ.get("MM_DATA")
    if d:
        return os.path.abspath(os.path.expanduser(d))
    rec = install_record()
    if rec and rec.get("data") and not os.environ.get("MM_PROFILE"):
        return rec["data"]
    return os.path.join(base_dir(), os.path.splitext(os.path.basename(profile_file()))[0])


root = data_dir  # the data folder; kept as a short name


def path(*parts):
    return os.path.join(data_dir(), *parts)


def expand(p, extra=None):
    """~ and {name} placeholders ({claude_tmp}, {data}, {code}, and the caller's own)."""
    if not isinstance(p, str):
        return p
    vals = {"claude_tmp": "/private/tmp/claude-%d" % os.getuid(), "code": CODE}
    try:
        vals["data"] = data_dir()
    except MMError:
        pass
    vals.update(extra or {})
    for k, v in vals.items():
        p = p.replace("{%s}" % k, str(v))
    return os.path.expanduser(p)


# The profile: only `name` is required. Every other value has this default (a missing section turns its part off:
# no [queue] = no queue readings or slot control; no [ci] = no pool; no [delivery] = alerts only in files and `mm`).
PROFILE_DEFAULTS = {
    "machine_id": "",
    "names": {"owner": "the owner", "recipient": "the recipient", "trim_command": "", "jobs_file": "the job file"},
    "service": {"label_prefix": DEFAULT_LABEL_PREFIX},
    "sizes": {},
    "live_tools": {"names": [], "suffixes": [], "path_regexes": []},
    "memory_guard": {},
    "queue": {},
    "kinds": {"wide": "", "machine_only": {"other": "kind 'other' runs on the machine"}, "pool": {}},
    "ci": {},
    "delivery": {},
    "trim": {},
    "deletes": {"forbidden_parts": [".ssh"], "protected_roots": [], "rules": [], "cleanup": []},
    "recovery": {"expected_jobs": []},
}


def _deep(base, over):
    out = dict(base)
    for k, v in over.items():
        out[k] = _deep(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) and base.get(k) else v
    return out


def load_profile(file=None):
    """The profile (TOML) on top of PROFILE_DEFAULTS. Raises MMError with a code when it is missing or broken."""
    f = file or profile_file()
    try:
        prof = load_toml(f)
    except FileNotFoundError:
        raise MMError("E_PROFILE", "profile not found: %s" % f, "mm init --profile <name>")
    except (OSError, ValueError) as e:
        raise MMError("E_PROFILE", "profile unreadable: %s: %s" % (f, str(e)[:120]), "correct the TOML; mm check")
    if not isinstance(prof.get("name"), str) or not prof["name"]:
        raise MMError("E_PROFILE", "profile has no name: %s" % f, 'add name = "<project>"')
    out = _deep(PROFILE_DEFAULTS, prof)
    out["_file"] = f
    return out


def take_data_arg(argv):
    """Entry points accept --data DIR and --profile P anywhere; they set MM_DATA and MM_PROFILE."""
    out, i = [], 0
    while i < len(argv):
        if argv[i] in ("--data", "--profile") and i + 1 < len(argv):
            os.environ["MM_DATA" if argv[i] == "--data" else "MM_PROFILE"] = argv[i + 1]
            i += 2
            continue
        out.append(argv[i])
        i += 1
    return out


def machine_id(profile=None):
    """The profile's machine_id, else the host name without its domain."""
    mid = (profile or {}).get("machine_id")
    return mid or socket.gethostname().split(".")[0]


def stamp(record, profile=None, mid=None):
    """Every record carries machine_id and schema_version."""
    out = dict(record)
    out.setdefault("machine_id", mid or machine_id(profile))
    out.setdefault("schema_version", SCHEMA_VERSION)
    return out


LOG_MAX_BYTES = 4 << 20


def append_line(path, line, max_bytes=LOG_MAX_BYTES):
    """Append one line to one of the tool's own logs; over max_bytes the log first moves to <path>.1 (one old copy)."""
    try:
        if os.path.getsize(path) > max_bytes:
            os.replace(path, path + ".1")
    except OSError:
        pass
    with open(path, "a") as f:
        f.write(line.rstrip("\n") + "\n")


def log_path(p):
    """A path for a one-line log record: as is, or JSON-quoted when it holds a space, a quote or a control character."""
    p = str(p)
    return json.dumps(p) if re.search(r'[\s"\\]', p) or not p else p


_DL = re.compile(r'^(\S+ \S+) (\S+) rule=(\S+) path=("(?:[^"\\]|\\.)*"|\S+)(?: bytes=(\d+))? guard=(.*) machine=(\S+) v=(\d+)$')


def parse_delete_line(line):
    """One deletes.log line -> the record of schemas/delete-line.schema.json, or None."""
    m = _DL.match(line.rstrip("\n"))
    if not m:
        return None
    t, verb, rule, path, nbytes, guard, mid, v = m.groups()
    return {"time": t, "verb": verb, "rule": rule, "path": json.loads(path) if path.startswith('"') else path,
            "bytes": None if nbytes is None else int(nbytes), "guard": guard, "machine_id": mid, "schema_version": int(v)}


def now_local(t=None):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() if t is None else t))


def write_atomic(target, text):
    """Write text to target by a temporary file in the same folder and a rename."""
    folder = os.path.dirname(target) or "."
    os.makedirs(folder, exist_ok=True)
    tmp = os.path.join(folder, ".%s.%d.tmp" % (os.path.basename(target), os.getpid()))
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, target)


def read_json(target, default=None):
    try:
        with open(target) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


class Locked:
    """An exclusive fcntl lock on a lock file (the supervisor, the watchdog and macman share the alert store)."""

    def __init__(self, target, timeout=5.0):
        self.target, self.timeout, self.f = target, timeout, None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.target), exist_ok=True)
        self.f = open(self.target, "a+")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() > deadline:
                    self.f.close()
                    raise TimeoutError("lock busy: " + self.target)
                time.sleep(0.05)

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.f, fcntl.LOCK_UN)
        finally:
            self.f.close()


# --------------------------------------------------------------------------------------------- settings

# Each checked value: (type, minimum, maximum). Types: "int", "num", "bool", "str", "choice:a|b".
SCHEMA = {
    "mode.slot_writes": ("choice:off|test|live", None, None),
    "mode.slots_file": ("str", None, None), "mode.observe": ("bool", None, None),
    "slots.floor": ("int", 1, 16), "slots.ceiling": ("int", 1, 16),
    "slots.raise_green_minutes": ("num", 1, 240), "slots.raise_requires_waiting": ("int", 0, 100),
    "slots.hold_after_red_minutes": ("num", 0, 600), "slots.hold_after_trim_minutes": ("num", 0, 600),
    "slots.amber_step_interval_s": ("num", 10, 3600),
    "slots.green_free_pct": ("num", 0, 100), "slots.green_load5": ("num", 0, 200), "slots.green_sys_pct": ("num", 0, 100),
    "slots.green_load1_per_core": ("num", 0.1, 4),
    "slots.amber_free_pct": ("num", 0, 100), "slots.amber_swap_growth_mb_30m": ("num", 1, 100000),
    "slots.amber_comp_mb": ("num", 1, 100000), "slots.amber_load5": ("num", 0, 500), "slots.amber_sys_pct": ("num", 0, 100),
    "slots.red_free_pct": ("num", 0, 100), "slots.red_swap_growth_mb_60s": ("num", 1, 100000),
    "slots.red_comp_growth_mb_60s": ("num", 1, 100000), "slots.red_segments_pct": ("num", 1, 100),
    "slots.red_swap_used_of_total_pct": ("num", 1, 100), "slots.red_sys_pct": ("num", 0, 100),
    "slots.red_load1_per_core": ("num", 0.1, 100), "slots.red_disk_gb": ("num", 0, 10000),
    "slots.sustain_samples": ("int", 1, 10), "slots.cores": ("int", 0, 512),
    "launch_gate.enabled": ("bool", None, None), "launch_gate.max_minutes": ("num", 0, 120),
    "pause_newest_call.enabled": ("bool", None, None), "pause_newest_call.resume_after_green_s": ("num", 10, 3600),
    "pause_newest_call.lsof_timeout_s": ("num", 1, 60),
    "banner.enabled": ("bool", None, None),
    "disk.low_gb": ("num", 1, 10000), "disk.recover_gb": ("num", 1, 10000), "disk.trend_hours": ("num", 0.5, 72),
    "disk.cache_attention_gb": ("num", 1, 10000), "disk.cache_action_gb": ("num", 1, 10000),
    "disk.cache_action_disk_gb": ("num", 1, 10000),
    "usage.codex_attention_pct": ("num", 0, 200), "usage.codex_action_pct": ("num", 0, 200),
    "usage.claude_action_pct": ("num", 0, 200), "usage.claude_projection_pct": ("num", 0, 1000),
    "usage.claude_5h_attention_pct": ("num", 0, 200), "usage.watch_state_max_age_s": ("num", 60, 86400),
    "usage.read_clock_allowance_s": ("num", 0, 60),
    "queue.wait_minutes": ("num", 1, 1440), "queue.waits_over_20_per_hour": ("int", 1, 1000),
    "queue.long_call_minutes": ("num", 1, 1440), "queue.head_block_minutes": ("num", 1, 1440),
    "queue.slot_cpu_cores": ("num", 0.5, 64), "queue.placement_max_mac_wait_minutes": ("num", 0, 1440),
    "queue.wide_free_pct": ("num", 0, 100), "queue.idle_room_minutes": ("num", 1, 1440),
    "github.reserve_minutes": ("int", 0, 1000000),
    "other.fseventsd_mb": ("num", 1, 1000000), "other.cache_5m_share_pct": ("num", 0, 100),
    "other.cache_5m_min_tokens_m": ("num", 0, 100000), "other.recipient_tool_wait_minutes": ("num", 1, 1440),
    "other.load_log_max_age_s": ("num", 30, 86400), "other.heartbeat_max_age_s": ("num", 20, 86400),
    "other.resume_gap_s": ("num", 30, 86400),
    "repeat.action_minutes": ("num", 1, 1440), "repeat.clear_after_minutes": ("num", 0, 1440), "repeat.attention_hours": ("num", 0.1, 168),
    "hook.log_input_keys": ("bool", None, None), "hook.remind_waiter_minutes": ("num", 1, 1440),
    "hook.subagent_model_replies": ("int", 1, 1000), "hook.subagent_model_scan_mb": ("num", 1, 1024),
    "deletes.enabled": ("bool", None, None), "deletes.interval_minutes": ("num", 10, 10080),
    "deletes.lsof_timeout_s": ("num", 5, 300), "deletes.evidence_keep_days": ("num", 1, 365),
    "deletes.cleanup_list_hours": ("num", 1, 720),
    "trim.age_minutes": ("num", 60, 100000), "trim.wait_s": ("num", 0, 600), "trim.drained_minutes": ("num", 0.5, 60),
    "trim.needed_after_minutes": ("num", 5, 1440),
    "evidence.slots": ("int", 2, 200), "evidence.window_minutes": ("num", 5, 240),
    "github.included_minutes": ("num", 0, 10000000),
    "github.allowed_gross_usd": ("num", 0, 1000000), "github.near_gross_pct": ("num", 1, 100),
    "github.near_minutes": ("num", 0, 10000000), "github.stop_minutes": ("num", 0, 10000000),
    "github.pace_minutes": ("num", 0, 10000000), "github.stuck_queued_minutes": ("num", 1, 10000),
    "github.stuck_running_minutes": ("num", 1, 10000), "github.read_interval_s": ("num", 60, 86400),
    "github.stale_minutes": ("num", 5, 1440), "github.watch_interval_s": ("num", 30, 3600),
    "github.done_alert_minutes": ("num", 5, 1440), "queue.default_run_minutes": ("num", 1, 600),
    "self.max_rss_mb": ("num", 10, 100000), "self.max_tick_s": ("num", 5, 3600), "self.slow_ticks": ("int", 1, 100),
    "self.bad_reading_ticks": ("int", 1, 1000), "self.min_free_mb": ("num", 1, 1000000),
    "self.max_slot_changes_per_hour": ("int", 1, 1000), "self.crash_loop_starts": ("int", 2, 100),
    "self.crash_loop_minutes": ("num", 1, 1440), "self.watchdog_stale_s": ("num", 90, 86400),
    "self.resume_paused_after_s": ("num", 30, 86400), "self.restart_wait_s": ("num", 5, 600),
    "self.start_grace_s": ("num", 0, 3600), "self.stop_deadline_s": ("num", 1, 15), "disk.sizes_interval_minutes": ("num", 1, 1440),
    "safe_mode.slots": ("int", 1, 16),
    "heartbeat.url": ("str", None, None), "heartbeat.every_min": ("num", 1, 1440), "heartbeat.timeout_s": ("num", 1, 60),
}


def flatten(doc, prefix=""):
    """A TOML document {section: {key: value}} -> {"section.key": value} (one level of sections)."""
    out = {}
    for section, body in doc.items():
        if isinstance(body, dict):
            for key, v in body.items():
                out[section + "." + key] = v
        else:
            out[section] = body
    return out


def load_toml(file):
    import tomllib
    with open(file, "rb") as f:
        return tomllib.load(f)


DEFAULT_SETTINGS = os.path.join(CODE, "settings.default.toml")


def defaults():
    return flatten(load_toml(DEFAULT_SETTINGS))


def merge(over):
    """The default settings with a data folder's overrides on top; an unknown key is a problem."""
    flat = defaults()
    unknown = sorted(k for k in over if k not in SCHEMA)
    flat.update(over)
    return flat, unknown


def resolve(flat):
    """Values that depend on the machine: slots.cores 0 = the core count."""
    out = dict(flat)
    if out.get("slots.cores") == 0:
        out["slots.cores"] = os.cpu_count() or 1
    return out


def validate(flat, real_slots=None):
    """A list of problems; empty when every checked value has its type and range and the pairs agree."""
    bad = []
    for key, (kind, lo, hi) in SCHEMA.items():
        if key not in flat:
            bad.append(key + ": missing")
            continue
        v = flat[key]
        if kind == "bool":
            ok = isinstance(v, bool)
        elif kind == "str":
            ok = isinstance(v, str)
        elif kind.startswith("choice:"):
            ok = v in kind[7:].split("|")
        elif kind == "int":
            ok = isinstance(v, int) and not isinstance(v, bool)
        else:
            ok = isinstance(v, (int, float)) and not isinstance(v, bool)
        if ok and lo is not None and not (lo <= v <= hi):
            ok = False
        if not ok:
            bad.append("%s: %r is not %s%s" % (key, v, kind, "" if lo is None else " in %s..%s" % (lo, hi)))
    if not bad:
        if flat["slots.floor"] > flat["slots.ceiling"]:
            bad.append("slots.floor > slots.ceiling")
        if flat["disk.low_gb"] >= flat["disk.recover_gb"]:
            bad.append("disk.low_gb >= disk.recover_gb")
        if flat["usage.codex_attention_pct"] > flat["usage.codex_action_pct"]:
            bad.append("usage.codex_attention_pct > usage.codex_action_pct")
        if flat["slots.red_free_pct"] > flat["slots.amber_free_pct"]:
            bad.append("slots.red_free_pct > slots.amber_free_pct")
        if flat["github.near_minutes"] > flat["github.stop_minutes"]:
            bad.append("github.near_minutes > github.stop_minutes")
        if flat["heartbeat.url"] and not flat["heartbeat.url"].startswith(("https://", "http://")):
            bad.append("heartbeat.url must be empty or an http(s) URL")
        if flat["mode.slot_writes"] == "test" and real_slots and \
                os.path.realpath(flat["mode.slots_file"] or "/") == os.path.realpath(real_slots):
            bad.append("mode.slot_writes test must not name the real gates/slots")
    return bad


class Settings:
    """The settings: the code's settings.default.toml with the data folder's settings.toml on top (only changed keys).
    Read at each tick when the file changed. A bad file keeps the last good values (and says why in `problem`)."""

    def __init__(self, file=None, real_slots=None):
        self.file = file or path("settings.toml")
        self.real_slots = real_slots
        self.last_good_file = path("state", "settings.lastgood.json")
        self.values = None
        self.problem = None
        self.mtime = None

    def load(self):
        try:
            try:
                st = os.stat(self.file)
                mtime = st.st_mtime
            except FileNotFoundError:
                mtime = "none"
            if self.values is not None and mtime == self.mtime and self.problem is None:
                return self.values
            over = flatten(load_toml(self.file)) if mtime != "none" else {}
            flat, unknown = merge(over)
            bad = ["%s: unknown setting" % k for k in unknown] + validate(flat, self.real_slots)
            if bad:
                raise ValueError("; ".join(bad[:5]))
            self.values, self.problem, self.mtime = resolve(flat), None, mtime
            try:
                write_atomic(self.last_good_file, json.dumps(flat, sort_keys=True))
            except OSError:
                pass
        except (OSError, ValueError) as e:  # tomllib.TOMLDecodeError is a ValueError
            self.problem = str(e)[:400]
            if self.values is None:
                kept = read_json(self.last_good_file)
                if isinstance(kept, dict) and not validate(kept, self.real_slots):
                    self.values = resolve(kept)
        return self.values

    def __getitem__(self, key):
        return self.values[key]


def settings_json_schema():
    """The settings contract as a JSON Schema (schemas/settings.schema.json is this, written by tests/gen_schemas.py)."""
    props = {}
    for key, (kind, lo, hi) in sorted(SCHEMA.items()):
        if kind == "bool":
            p = {"type": "boolean"}
        elif kind == "str":
            p = {"type": "string"}
        elif kind.startswith("choice:"):
            p = {"enum": kind[7:].split("|")}
        else:
            p = {"type": "integer" if kind == "int" else "number"}
            if lo is not None:
                p["minimum"], p["maximum"] = lo, hi
        props[key] = p
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "machine-manager settings (flat keys)",
            "type": "object", "required": sorted(SCHEMA), "properties": props, "additionalProperties": False}


# --------------------------------------------------------------------------------------------- the off switch

def off_state():
    """`mm off` writes off.json in the data folder: every automatic action is off (slot writes, deletes, trim, gate,
    pause); readings and alerts go on. Returns the record or None."""
    d = read_json(path("off.json"), None)
    return d if isinstance(d, dict) and d.get("off") else None


def safe_state():
    """Safe mode (safe.json in the data folder, written by the supervisor): automatic actions off, readings and alerts
    on. Only `mm on` or `mm restart --clear-safe` ends it. Returns the record or None."""
    d = read_json(path("safe.json"), None)
    return d if isinstance(d, dict) and d.get("safe") else None


# --------------------------------------------------------------------------------------------- masking

import re as _re  # noqa: E402

_SECRET_RES = [
    _re.compile(r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|_KEY|CREDENTIALS?|AUTH))(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"),
    _re.compile(r"(?i)(--(?:token|password|passphrase|secret|api-key|key|auth)(?:=|\s+))(\S+)"),
    _re.compile(r"(?i)\b(bearer|basic|token)(\s+)([A-Za-z0-9._~+/=-]{8,})"),
    _re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[abpr]-[A-Za-z0-9-]{10,}"
                r"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,})"),
    _re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", _re.S),
    _re.compile(r"(?<![A-Za-z0-9+_=-])[A-Za-z0-9+_=-]{32,}(?![A-Za-z0-9+_=-])"),
    _re.compile(r"(?i)(://[^/\s:@]+:)([^@\s]+)(@)"),
]


def mask(text):
    """Secret-shaped parts of a text replaced by ***: KEY=value pairs with secret names, --token style flags, bearer
    strings, known token prefixes, private key blocks, passwords in URLs and long random words (32+ chars, letters and
    digits, high entropy). Paths, hex digests and UUIDs are kept."""
    if not isinstance(text, str) or not text:
        return text
    t = _SECRET_RES[4].sub("***PRIVATE KEY***", text)
    t = _SECRET_RES[0].sub(lambda m: m.group(1) + m.group(2) + "***", t)
    t = _SECRET_RES[1].sub(lambda m: m.group(1) + "***", t)
    t = _SECRET_RES[2].sub(lambda m: m.group(1) + m.group(2) + "***", t)
    t = _SECRET_RES[3].sub("***", t)
    t = _SECRET_RES[6].sub(lambda m: m.group(1) + "***" + m.group(3), t)
    t = _SECRET_RES[5].sub(lambda m: "***" if _random(m.group(0)) else m.group(0), t)
    return t


def _random(w):
    """A long word that looks random: letters and digits mixed, high entropy (hex digests and UUIDs stay)."""
    import math
    if not (_re.search(r"[0-9]", w) and _re.search(r"[A-Za-z]", w)) or _re.fullmatch(r"[0-9a-fA-F-]+", w):
        return False
    n = len(w)
    ent = -sum(c / n * math.log2(c / n) for c in (w.count(ch) for ch in set(w)))
    return ent >= 4.2


def mask_obj(o):
    """mask() over every string inside lists and dicts (keys too)."""
    if isinstance(o, str):
        return mask(o)
    if isinstance(o, list):
        return [mask_obj(x) for x in o]
    if isinstance(o, tuple):
        return tuple(mask_obj(x) for x in o)
    if isinstance(o, dict):
        return {mask_obj(k) if isinstance(k, str) else k: mask_obj(v) for k, v in o.items()}
    return o


# --------------------------------------------------------------------------------------------- alerts

class AlertStore:
    """Current alerts (alerts-state.json) and the pushed log (alerts.jsonl), with dedupe, bands, repeat, clear and ack.

    raise_() is called for every active condition at each evaluation; finish() clears keys not raised in that round.
    Pushed lines carry a sequence number; the hook and wait-alert keep a cursor on it.
    """

    def __init__(self, settings_values, clock=time.time, mid=None):
        self.s = settings_values
        self.clock = clock
        self.mid = mid or machine_id()
        self.state_file = path("alerts-state.json")
        self.log_file = path("alerts.jsonl")
        self.lock_file = path("state", "alerts.lock")
        self.seen = set()
        self.pushed = []

    def _load(self):
        st = read_json(self.state_file, None)
        if not isinstance(st, dict) or "active" not in st:
            st = {"seq": 0, "active": {}, "acks": {}}
        st["machine_id"], st["schema_version"] = self.mid, SCHEMA_VERSION
        return st

    def _append(self, st, record):
        st["seq"] += 1
        record = dict(mask_obj(record), seq=st["seq"], time=now_local(self.clock()), machine_id=self.mid,
                      schema_version=SCHEMA_VERSION)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        try:
            if os.path.getsize(self.log_file) > 4 << 20:
                os.replace(self.log_file, self.log_file + ".1")  # S1: rotation of its own log
        except OSError:
            pass
        self.pushed.append(record)
        return record

    def _repeat_s(self, level):
        if level == "ACTION":
            return self.s["repeat.action_minutes"] * 60
        if level == "ATTENTION":
            return self.s["repeat.attention_hours"] * 3600
        return None

    def begin(self):
        self.seen = set()
        self.pushed = []

    def raise_(self, key, name, level, text, value=None, band=None, worse="up", command=None, investigate=None):
        """One active condition. value/band: a number and the step that counts as 'worse by one band'."""
        self.seen.add(key)
        now = self.clock()
        text, command = mask(text), mask(command)
        cond = {"key": key, "name": name, "level": level, "text": text, "value": value, "band": band, "worse": worse,
                "command": command, "investigate": mask_obj(investigate)}
        with Locked(self.lock_file):
            st = self._load()
            r = mmdecide.alert_raise(st["active"].get(key), key in st["acks"], cond, now, self.s)
            if not r["acked"]:
                st["acks"].pop(key, None)
            if r["push"]:
                self._append(st, {"key": key, "name": name, "level": level, "text": text, "value": value,
                                  "command": command, "investigate": investigate, "why": r["why"]})
            st["active"][key] = r["entry"]
            write_atomic(self.state_file, json.dumps(st, sort_keys=True))

    def finish(self, scope_prefixes=None, exclude_prefixes=("SELF_STALE", "SELF_UNLOADED", "WD:")):
        """Clear every active key not raised since begin(): only keys under scope_prefixes (if given), never keys under
        exclude_prefixes (the watchdog's keys; the supervisor must not clear them, the watchdog passes its own scope).
        A pattern ending in ':' is a prefix; any other pattern is one exact key."""
        def under(key, pats):
            return any(key.startswith(p) if p.endswith(":") else key == p for p in pats)
        now = self.clock()
        with Locked(self.lock_file):
            st = self._load()
            for key in list(st["active"]):
                if key in self.seen:
                    continue
                if scope_prefixes is not None and not under(key, scope_prefixes):
                    continue
                if scope_prefixes is None and under(key, exclude_prefixes):
                    continue
                r = mmdecide.alert_absent(st["active"][key], now, self.s)
                if not r["clear"]:
                    st["active"][key] = r["entry"]
                    continue
                cur = st["active"].pop(key)
                st["acks"].pop(key, None)
                if r["push_cleared"]:
                    self._append(st, {"key": key, "name": cur["name"], "level": "INFO", "text": "cleared: " + cur["name"],
                                      "value": None, "command": None, "investigate": None, "why": "cleared"})
            write_atomic(self.state_file, json.dumps(st, sort_keys=True))

    def clear(self, key):
        """Clear one active key now (for example STOPPED at `mm start`); False when it is not active."""
        with Locked(self.lock_file):
            st = self._load()
            cur = st["active"].pop(key, None)
            if cur is None:
                return False
            st["acks"].pop(key, None)
            if mmdecide.LEVELS[cur["level"]] >= 2:
                self._append(st, {"key": key, "name": cur["name"], "level": "INFO", "text": "cleared: " + cur["name"],
                                  "value": None, "command": None, "investigate": None, "why": "cleared"})
            write_atomic(self.state_file, json.dumps(st, sort_keys=True))
            return True

    def ack(self, key):
        with Locked(self.lock_file):
            st = self._load()
            if key not in st["active"]:
                return False
            st["acks"][key] = self.clock()
            write_atomic(self.state_file, json.dumps(st, sort_keys=True))
            return True


LINE_MAX = 200


def display_id(rec):
    """The alert id people and agents see: the rule name, plus the key's ':' part when the key has one
    (MEM with name MEM_RED -> MEM_RED; QWAIT:x -> QWAIT:x). `mm ack` and `mm explain` accept it or the key."""
    key, name = rec.get("key") or "", rec.get("name") or rec.get("key") or "?"
    return name + key[key.index(":"):] if ":" in key else name


def find_alert(active, ident):
    """The active alert entry for a key or display id (None when none or ambiguous)."""
    if ident in active:
        return active[ident]
    hits = [a for a in active.values() if display_id(a) == ident] or [a for a in active.values() if a.get("name") == ident]
    return hits[0] if len(hits) == 1 else None


def alert_line(rec, max_len=LINE_MAX):
    """One alert as one line of at most max_len characters: `LEVEL KEY what/why | do: command`.
    The command is never cut: a command too long for the line becomes `mm explain KEY` (explain prints it whole)."""
    level, key = rec.get("level") or "INFO", display_id(rec)
    if rec.get("why") == "cleared":
        level = "CLEARED"
    count = rec.get("_count", 1)
    head = "%s %s%s " % (level, key, " x%d" % count if count > 1 else "")
    cmd = rec.get("command") if rec.get("why") != "cleared" else None
    tail = ""
    if cmd:
        tail = " | do: " + cmd
        if len(tail) > max_len // 2 or len(head) + len(tail) + 40 > max_len:
            tail = " | do: mm explain " + key
    text = " ".join(str(rec.get("text") or "").split())
    room = max_len - len(head) - len(tail)
    if len(text) > room:
        text = text[:max(room - 3, 0)].rstrip() + "..."
    return (head + text + tail)[:max_len]


def collapse(recs):
    """Repeats of one key collapse into its newest record, with _count; order: level (highest first), then newest."""
    by = {}
    for r in recs:
        k = (r.get("key"), r.get("why") == "cleared")
        prev = by.get(k)
        r = dict(r, _count=(prev.get("_count", 1) + 1) if prev else 1)
        by[k] = r
    return sorted(by.values(), key=lambda r: (-LEVELS.get(r.get("level"), 0) if r.get("why") != "cleared" else 0,
                                             -(r.get("seq") or 0)))


def read_pushed(after_seq, log_file=None, max_bytes=256 << 10):
    """Pushed alert records with seq > after_seq, from the tail of alerts.jsonl."""
    log_file = log_file or path("alerts.jsonl")
    try:
        with open(log_file, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    if size > max_bytes and data:
        data = data[1:]
    out = []
    for line in data:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and isinstance(r.get("seq"), int) and r["seq"] > after_seq:
            out.append(r)
    return out


# --------------------------------------------------------------------------------------------- wrappers

classify = mmdecide.classify


class SlotController:
    """A stateful wrapper of the pure mmdecide.slot_decide (the state dict is kept by the caller)."""

    def __init__(self, s, state=None):
        self.s = s
        self.st = state if isinstance(state, dict) else {}

    def decide(self, now, mac_state, reasons, slots, busy, waiting, wx_waiting, override=None, events=()):
        r = mmdecide.slot_decide(self.st, {"now": now, "mac_state": mac_state, "reasons": list(reasons), "slots": slots,
                                           "busy": busy, "waiting": waiting, "wx_waiting": wx_waiting,
                                           "override": override, "events": list(events)}, self.s)
        self.st.clear()
        self.st.update(r["state"])
        return r["slots"], r["why"]


def write_slots(target, n):
    """Atomic write: slots.new, then a rename."""
    tmp = target + ".new"
    with open(tmp, "w") as f:
        f.write("%d\n" % n)
    os.replace(tmp, target)
