# SPDX-License-Identifier: Apache-2.0
"""Generic pool contract shared by command and static adapters. Start commands are profile data, printed only.

External state can supply capacity, load, state and read_time; it cannot supply a command, reserve or job cost.
Every cache read is validated again. Failed, malformed, future or stale data is UNKNOWN and cannot place a job.
"""
import json
import math
import os
import re
import shlex
import stat
import string
import time

import mmcore
import mmread
import mmschema

FIELDS = {"kind", "shards", "sha", "branch", "crate", "diff_base", "race", "packages", "pool"}


def _finite(value):
    if isinstance(value, float) and not math.isfinite(value):
        return False
    if isinstance(value, dict):
        return all(_finite(x) for x in value.values())
    if isinstance(value, list):
        return all(_finite(x) for x in value)
    return True


def parse_state(raw):
    """Strict bounded JSON is checked for depth, duplicate fields, schema and finite numbers before use."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite number")

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError, UnicodeError):
        raise ValueError("read command returned invalid JSON") from None
    todo = [(result, 0)]
    while todo:
        item, depth = todo.pop()
        if depth > 32:
            raise ValueError("read command JSON nesting exceeds 32")
        if isinstance(item, dict):
            todo.extend((x, depth + 1) for x in item.values())
        elif isinstance(item, list):
            todo.extend((x, depth + 1) for x in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("read command returned a nonfinite number")
    return result


class Pool:
    scoped = True
    supports_watch = False

    def __init__(self, cfg):
        self.cfg = cfg
        self.id = cfg["pool_id"]
        self.prefix = "POOL:%s:" % self.id
        self.unit = cfg["unit"]
        self.reserve = cfg["reserve"]
        self.stale_after = cfg.get("stale_after_s", 300)
        for key in ("unit", "location"):
            if key in cfg and not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", cfg[key]):
                raise mmcore.MMError("E_PROFILE", "pool %s has invalid %s" % (self.id, key), "use a resource word")
        if not _finite(cfg):
            raise mmcore.MMError("E_PROFILE", "pool %s has nonfinite settings" % self.id, "use finite pool numbers")
        if "left" in cfg and cfg["left"] > cfg["total"]:
            raise mmcore.MMError("E_PROFILE", "pool %s left exceeds total" % self.id, "correct the static capacity")
        formatter = string.Formatter()
        if "{" in cfg["start_argv"][0] or "}" in cfg["start_argv"][0]:
            raise mmcore.MMError("E_PROFILE", "pool executable must be literal", "template start_argv arguments only")
        if os.path.basename(cfg["start_argv"][0]) == "ssh":
            raise mmcore.MMError("E_PROFILE", "use ssh_argv for an SSH pool", "keep remote arguments in start_argv")
        if os.path.basename(cfg["start_argv"][0]) in ("sh", "bash", "dash", "zsh", "ksh") and any(
                x.startswith("-") and not x.startswith("--") and "c" in x for x in cfg["start_argv"][1:]):
            raise mmcore.MMError("E_PROFILE", "shell command strings are not pool argv", "use a literal script executable")
        if "ssh_argv" in cfg:
            ssh = cfg["ssh_argv"]
            if not 2 <= len(ssh) <= 64 or os.path.basename(ssh[0]) != "ssh" or any(
                    "{" in x or "}" in x or mmcore.clean(x) != x or mmcore.mask(x) != x for x in ssh):
                raise mmcore.MMError("E_PROFILE", "pool ssh_argv must be fixed trusted SSH arguments",
                                     "use 2..64 SSH transport words without templates or control characters")
        for word in cfg["start_argv"]:
            try:
                for _, field, spec, conversion in formatter.parse(word):
                    if field is not None and (field not in FIELDS or spec or conversion):
                        raise ValueError("unsupported placeholder")
            except ValueError:
                raise mmcore.MMError("E_PROFILE", "pool %s has an invalid start_argv template" % self.id,
                                     "use simple documented request placeholders") from None

    def settings(self, s):
        # The supervisor's existing worker scheduler uses these two keys; all budget decisions use this pool's unit.
        return dict(s, **{"github.read_interval_s": self.cfg.get("read_interval_s", 60),
                          "github.stale_minutes": self.stale_after / 60})

    def cache_file(self):
        return mmcore.path("state", "pools", self.id, "generic.json")

    def watch_file(self):
        return mmcore.path("state", "pools", self.id, "watch.json")

    def load_cache(self):
        """A cache is untrusted input too: regular file only, no link/FIFO wait, finite strict bounded JSON."""
        limit = self.cfg.get("max_bytes", 65536) * 6 + 2048  # JSON escaping plus our small envelope
        try:
            fd = os.open(self.cache_file(), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    return None
                raw = f.read(limit + 1)
            return parse_state(raw) if len(raw) <= limit else None
        except (OSError, ValueError, TypeError, RecursionError):
            return None

    def _validate(self, data, now):
        if not _finite(data):
            raise ValueError("pool state contains a nonfinite number")
        problems = mmschema.validate(data, mmschema.load("pool-read"))
        if problems:
            raise ValueError("pool state does not match pool-read schema")
        if data["capacity"]["unit"] != self.unit:
            raise ValueError("pool capacity unit differs from the profile")
        if data["capacity"]["left"] > data["capacity"]["total"]:
            raise ValueError("pool capacity left exceeds total")
        if data["read_time"] > now + 5:
            raise ValueError("pool read time is in the future")
        return data

    def read(self, s, now, watch=None):
        raise NotImplementedError

    def job(self, s, now):
        started = time.monotonic()
        try:
            data = self.read(s, now)
            completed = now + time.monotonic() - started
            data = self._validate(data, completed)
            result = {"time": completed, "data": data, "error": None}
        except (ValueError, OSError, TypeError, RecursionError, KeyError):
            result = {"time": now, "data": None, "error": "pool read failed or returned invalid state"}
        result = mmcore.clean_obj(mmcore.mask_obj(result))
        mmcore.write_atomic(self.cache_file(), json.dumps(result, allow_nan=False))
        return result

    def snapshot(self, read, now):
        """Return (data, why), never let a corrupt cache poison another pool or a supervisor tick."""
        try:
            if not isinstance(read, dict):
                return None, "no pool read"
            when = read.get("time")
            if isinstance(when, bool) or not isinstance(when, (int, float)) or not math.isfinite(when):
                return None, "pool snapshot time invalid"
            if when > now + 5:
                return None, "pool snapshot time is in the future"
            if read.get("error"):
                return None, "pool read failed"
            data = self._validate(read.get("data"), now)
            if now - when >= self.stale_after or now - data["read_time"] >= self.stale_after:
                return data, "pool read is stale"
            return data, None
        except (ValueError, TypeError, KeyError, RecursionError, AttributeError):
            return None, "pool snapshot invalid"

    def latest(self, now):
        return self.snapshot(self.load_cache(), now)

    def candidate(self, req, s, now):
        data, why = self.latest(now)
        if data and data["state"] in ("RED", "UNKNOWN"):
            why = "pool state is " + data["state"]
        _, command_why = self.guard_args(req)
        why = why or command_why
        cost = self.cfg.get("job_costs", {}).get(req["kind"], self.cfg["job_cost"])
        return {"id": self.id, "generic": True, "unit": self.unit,
                "capacity_left": None if why or not data else data["capacity"]["left"],
                "source": why or "the pool's read", "reserve": self.reserve,
                "job_cost": cost, "plan_cost": self.cfg.get("plan_cost", 0),
                "guard": "skip", "guard_why": why, "stop_active": bool(data and data["state"] == "RED")}

    def conditions(self, read, s, now, mk, owner="the owner"):
        data, why = self.snapshot(read, now)
        if why:
            return [mk(self.prefix + "SOURCE_STALE", "SOURCE_STALE", "ATTENTION", "pool %s: %s" % (self.id, why))]
        if data["state"] == "RED" or data["capacity"]["left"] <= self.reserve:
            return [mk(self.prefix + "GUARD", "GUARD_STOP", "ACTION", "pool %s: capacity reserve reached or pool stopped" % self.id)]
        if data["state"] == "UNKNOWN":
            return [mk(self.prefix + "SOURCE_STALE", "SOURCE_STALE", "ATTENTION", "pool %s: state UNKNOWN" % self.id)]
        if data["state"] == "AMBER":
            return [mk(self.prefix + "GUARD", "GUARD_NEAR", "ATTENTION", "pool %s: state AMBER" % self.id)]
        return []

    def good_keys(self, read):
        # Only actual validation can clear a source failure. Called after job(), so the read's own time is suitable.
        when = read.get("time", 0) if isinstance(read, dict) else 0
        _, why = self.snapshot(read, when)
        return [self.prefix + "SOURCE_STALE"] if not why else []

    def owns(self, key):
        return key in (self.prefix + "SOURCE_STALE", self.prefix + "GUARD")

    def resource(self, read, now):
        data, why = self.snapshot(read, now)
        capacity = {"unit": self.unit, "total": None if data is None else data["capacity"]["total"],
                    "left": None if data is None else data["capacity"]["left"], "reserve": self.reserve}
        state = "UNKNOWN" if why or data is None else data["state"]
        if state != "UNKNOWN" and capacity["left"] <= self.reserve:
            state, why = "RED", "capacity reserve reached"
        return {"resource": "pool", "id": self.id, "location": self.cfg.get("location", "cloud"),
                "read_time": None if data is None else data["read_time"], "stale_after_s": self.stale_after,
                "state": state,
                "why": why or (data.get("why") if data else None), "capacity": capacity,
                "load": data["load"] if data else {"running": None, "queued": None},
                "values": [{"key": "job_cost", "value": self.cfg["job_cost"]},
                           {"key": "plan_cost", "value": self.cfg.get("plan_cost", 0)}]}

    def resources(self, read, s, now):
        return [self.resource(read, now)]

    def status(self, read, s, now, alerts=()):
        row = self.resource(read, now)
        result = mmcore.stamp({"kind": "pool", "time": now, "state": row["state"],
                             "reasons": [row["why"]] if row["why"] else [], "capacity": row["capacity"],
                             "load": row["load"], "alerts": list(alerts), "read_time": row["read_time"]}, mid=self.id)
        return mmcore.clean_obj(mmcore.mask_obj(result))

    def guard_args(self, req):
        values = {k: str(v).lower() if isinstance(v, bool) else str(v) for k, v in req.items() if v is not None}
        values.update(pool=self.id, shards=str(req.get("shards", 1)))
        try:
            argv = [x.format(**values) for x in self.cfg["start_argv"]]
        except KeyError as e:
            return None, "start command needs --" + str(e.args[0]).replace("_", "-")
        if any(mmcore.clean(x) != x or mmcore.mask(x) != x for x in argv):
            return None, "start command withheld: a word needs cleaning or masking"
        return argv, None

    def guard(self, args):
        return 0, "pool capacity checked"

    def commands(self, req, gargs=None, watch_cmd=None):
        argv, why = self.guard_args(req)
        if argv and self.cfg.get("ssh_argv"):
            argv = list(self.cfg["ssh_argv"]) + [shlex.join(argv)]
        return [shlex.join(argv)] if argv and why is None else []
