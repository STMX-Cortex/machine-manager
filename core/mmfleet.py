# SPDX-License-Identifier: Apache-2.0
"""Read-only fleet collection. Only `mm collect` performs network work; consumers read fleet.json.

Every peer keeps its own supervisor and safety decisions. URLs and response errors never choose commands:
placement prints only start_argv from the owner's local profile. Failed reads replace the peer with UNKNOWN.
"""
import json
import math
import os
import re
import shlex
import stat
import sys
import time
import urllib.parse

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mmcore
import mmdecide
import mmschema

MAX_BYTES = 1 << 20
MAX_DEPTH = 32
MAX_PEERS = 32
CACHE_BYTES = MAX_PEERS * (MAX_BYTES + 4096)
MAX_URL = 4096
FUTURE_SKEW_S = 5
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")
FIELDS = frozenset(("kind", "shards", "packages", "branch", "sha", "crate", "diff_base", "race"))


class FleetError(ValueError):
    pass


def _number(value):
    try:
        return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)
    except OverflowError:
        return False


def _url(value):
    if not isinstance(value, str) or not value or len(value) > MAX_URL or mmcore.clean(value) != value:
        raise FleetError("invalid status URL")
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.fragment or parsed.username is not None \
                or parsed.password is not None:
            raise FleetError("status URL must be HTTP(S), without credentials or fragment")
        parsed.port  # validate the port without putting its potentially sensitive text in an error
    except ValueError:
        raise FleetError("invalid status URL") from None
    return value


def configs(profile):
    """Validated profile configs, with bounded defaults. Peer ids also cannot collide with pools or this machine."""
    raw = profile.get("machines", [])
    if not isinstance(raw, list) or len(raw) > MAX_PEERS:
        raise mmcore.MMError("E_PROFILE", "machines must be a list of at most %d peers" % MAX_PEERS, "correct [[machines]]")
    reserved = {mmcore.machine_id(profile).casefold()}
    # Keep adapter loading out of this path: validating profile ids does not start a pool or run a command.
    for cfg in (profile.get("pools") or []):
        if isinstance(cfg, dict) and isinstance(cfg.get("id"), str):
            reserved.add(cfg["id"].casefold())
    ci = profile.get("ci") or {}
    if isinstance(ci, dict) and isinstance(ci.get("pool_id"), str):
        reserved.add(ci["pool_id"].casefold())
    out = []
    schema = mmschema.load("profile")["properties"]["machines"]["items"]
    for row in raw:
        if mmschema.validate(row, schema):
            raise mmcore.MMError("E_PROFILE", "invalid machine profile entry", "correct [[machines]]; mm check")
        cfg = dict({"stale_after_s": 60, "timeout_s": 5, "job_minutes": 40}, **row)
        ident = cfg["id"]
        if not ID.fullmatch(ident) or ident.casefold() in reserved:
            raise mmcore.MMError("E_PROFILE", "machine ids must be unique across machines and pools", "correct [[machines]].id")
        reserved.add(ident.casefold())
        try:
            _url(cfg["status_url"])
        except FleetError:
            raise mmcore.MMError("E_PROFILE", "invalid machine status URL", "use HTTP(S), without URL credentials or fragment") from None
        for key, low, high in (("timeout_s", 0.1, 30), ("stale_after_s", 1, 3600), ("job_minutes", 0.01, 1440)):
            if not _number(cfg[key]) or not low <= cfg[key] <= high:
                raise mmcore.MMError("E_PROFILE", "invalid machine %s" % key, "correct [[machines]]")
        if not cfg["kinds"] or len(cfg["kinds"]) > 128 or any(not isinstance(k, str) or not k or len(k) > 120
                or mmcore.clean(k) != k or type(v) is not int or not 1 <= v <= 1024 for k, v in cfg["kinds"].items()):
            raise mmcore.MMError("E_PROFILE", "invalid machine kinds", "list supported kinds and positive shard limits")
        if not cfg["start_argv"] or len(cfg["start_argv"]) > 64:
            raise mmcore.MMError("E_PROFILE", "machine start_argv is empty or too long", "set the command to print for this machine")
        if not cfg["start_argv"][0] or "{" in cfg["start_argv"][0] or "}" in cfg["start_argv"][0]:
            raise mmcore.MMError("E_PROFILE", "machine executable must be literal", "put request placeholders only in arguments")
        for word in cfg["start_argv"]:
            if len(word) > 4096 or mmcore.clean(word) != word:
                raise mmcore.MMError("E_PROFILE", "invalid machine start_argv word", "use plain argument words")
            placeholders = re.findall(r"\{([^{}]+)\}", word)
            if any(field not in FIELDS for field in placeholders) or re.sub(r"\{[^{}]+\}", "", word).count("{") \
                    or re.sub(r"\{[^{}]+\}", "", word).count("}"):
                raise mmcore.MMError("E_PROFILE", "unknown machine command placeholder", "use the documented placement request fields")
        executable = os.path.basename(cfg["start_argv"][0])
        if executable == "ssh" or (executable in ("sh", "bash", "dash", "zsh", "ksh")
                                   and any(w.startswith("-") and "c" in w[1:] for w in cfg["start_argv"][1:])):
            raise mmcore.MMError("E_PROFILE", "machine command cannot embed an SSH or shell command parser",
                                 "use ssh_argv for SSH transport, or a local argv-preserving launcher")
        transport = cfg.get("ssh_argv")
        if transport is not None and (not 2 <= len(transport) <= 64 or os.path.basename(transport[0]) != "ssh" or
                any(not w or len(w) > 4096 or mmcore.clean(w) != w or "{" in w or "}" in w for w in transport)):
            raise mmcore.MMError("E_PROFILE", "invalid machine ssh_argv", "use fixed SSH arguments ending in the destination")
        out.append(cfg)
    return out


def _structure(value):
    """Bound nesting and reject nonfinite/oversized numeric input before the recursive schema checker."""
    stack = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth >= MAX_DEPTH:
                raise FleetError("status JSON too deep")
            stack.extend((x, depth + 1) for x in (node.values() if isinstance(node, dict) else node))
        elif isinstance(node, (int, float)) and not isinstance(node, bool) and not _number(node):
            raise FleetError("status contains invalid number")


def _strict_json(raw, limit=MAX_BYTES):
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise FleetError("status response too large")
    try:
        def unique(pairs):
            out = {}
            for key, value in pairs:
                if key in out:
                    raise FleetError("status has duplicate JSON keys")
                out[key] = value
            return out
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(FleetError("status contains invalid number")))
        _structure(value)
        return value
    except (UnicodeError, ValueError, RecursionError):
        raise FleetError("invalid status JSON") from None


def validate_status(value, cfg, now):
    _structure(value)
    if not isinstance(value, dict) or mmschema.validate(value, mmschema.load("status")):
        raise FleetError("invalid machine status schema")
    if value.get("kind") != "machine" or type(value.get("schema_version")) is not int or value["schema_version"] != 1 \
            or value.get("machine_id") != cfg["id"]:
        raise FleetError("machine status identity/version mismatch")
    source_time = value.get("time")
    if not _number(source_time) or source_time > now + FUTURE_SKEW_S:
        raise FleetError("invalid machine status timestamp")
    if now - source_time >= cfg["stale_after_s"]:
        raise FleetError("source status stale")
    for key in ("slots", "busy", "waiting"):
        n = value.get(key)
        if type(n) is not int or not 0 <= n <= (1024 if key == "slots" else 1000000):
            raise FleetError("machine status lacks valid queue counts")
    free = (value.get("readings") or {}).get("free_pct")
    if free is not None and (not _number(free) or not 0 <= free <= 100):
        raise FleetError("invalid machine available memory")
    # Keep the cached status bounded even when remote reason strings are much larger than displayed output.
    parsed = urllib.parse.urlsplit(cfg["status_url"])
    secrets = [cfg["status_url"], parsed.query] + [x[1] for x in urllib.parse.parse_qsl(parsed.query) if x[1]] + \
        [part.partition("=")[2] for part in parsed.query.split("&") if part.partition("=")[2]]
    def scrub(node, key=None):
        if isinstance(node, dict):
            return {k: scrub(v, k) for k, v in node.items()}
        if isinstance(node, list):
            return [scrub(v) for v in node]
        if isinstance(node, str) and key not in ("kind", "state", "mode", "machine_id"):
            for secret in secrets:
                if secret:
                    node = node.replace(secret, "[endpoint]")
        return node
    # Machine collection needs no arbitrary capacity/load dictionaries or custom reading names. Dropping those
    # fields also prevents a peer from smuggling endpoint query tokens through object keys into the cache.
    selected = {k: v for k, v in value.items() if k not in ("capacity", "load")}
    selected["readings"] = {k: v for k, v in (value.get("readings") or {}).items() if k in (
        "free_pct", "swap_used_mb", "swap_total_mb", "comp_mb", "pressure", "seg_pct", "load1", "load5",
        "sys_pct", "cpu_pct", "psi_some_pct", "psi_full_pct")}
    if "heartbeat" in selected:
        selected["heartbeat"] = {k: v for k, v in selected["heartbeat"].items() if k in ("pid", "tick", "note")}
    status = mmcore.clean_obj(mmcore.mask_obj(scrub(selected)))
    status["machine_id"] = cfg["id"]
    status["reasons"] = [x[:200] for x in status.get("reasons", [])[:16]]
    return status


def _http(url, timeout):
    """Child-process transport: default CA verification/proxy settings; no redirects, credentials or decompression."""
    _url(url)
    import urllib.request
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(urllib.request.Request(url, headers={"Accept": "application/json", "Accept-Encoding": "identity"}),
                     timeout=timeout) as response:
        if response.status != 200 or response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise FleetError("invalid HTTP response")
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BYTES):
            raise FleetError("status response too large")
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise FleetError("status response too large")
        return raw


def fetch(cfg):
    """One worker process imposes a wall timeout, including DNS, TLS and slow/dripping response bodies.
    The URL is sent over stdin rather than exposed in process arguments or error text."""
    import subprocess
    child = subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__), "--fetch"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        out, _ = child.communicate(json.dumps({"url": cfg["status_url"], "timeout": cfg["timeout_s"]}).encode(),
                                   timeout=cfg["timeout_s"])
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        raise FleetError("status request timed out") from None
    if child.returncode != 0 or len(out) > MAX_BYTES:
        raise FleetError("status request failed")
    return out


def collect(profile, s, now=None, fetcher=None):
    import concurrent.futures
    cfgs, fetcher = configs(profile), fetcher or fetch
    clock = time.time if now is None else lambda: now
    def one(cfg):
        try:
            raw = fetcher(cfg)
            status = validate_status(_strict_json(raw), cfg, clock())
            return {"id": cfg["id"], "collected_at": clock(), "status": status, "error": None}
        except Exception:
            return {"id": cfg["id"], "collected_at": clock(), "status": None, "error": "status unavailable or invalid"}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(4, len(cfgs)))) as executor:
        rows = list(executor.map(one, cfgs))
    rec = mmcore.stamp({"kind": "fleet", "time": clock(), "machines": rows}, profile)
    mmcore.write_atomic(mmcore.path("fleet.json"), json.dumps(rec, allow_nan=False, sort_keys=True, ensure_ascii=False))
    return rec


def _cached(profile, now):
    """Read a bounded cache and validate each status again. A failed read never revives an earlier good snapshot."""
    cfgs = configs(profile)
    if not cfgs:
        return []
    try:
        fd = os.open(mmcore.path("fleet.json"), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise FleetError("fleet cache is not a regular file")
            # A fleet has at most MAX_PEERS statuses, each bounded by MAX_BYTES.
            raw = f.read(CACHE_BYTES + 1)
        if len(raw) > CACHE_BYTES:
            raise FleetError("fleet cache too large")
        doc = _strict_json(raw, CACHE_BYTES)
    except (OSError, ValueError, RecursionError):
        doc = {}
    rows = doc.get("machines", []) if isinstance(doc, dict) and doc.get("kind") == "fleet" \
        and type(doc.get("schema_version")) is int and doc["schema_version"] == 1 else []
    by_id = {row.get("id"): row for row in rows[:MAX_PEERS] if isinstance(row, dict) and isinstance(row.get("id"), str)} \
        if isinstance(rows, list) else {}
    out = []
    for cfg in cfgs:
        row = by_id.get(cfg["id"], {})
        status = None
        why = "no collected status"
        collected = row.get("collected_at")
        try:
            if not _number(collected) or not -FUTURE_SKEW_S <= now - collected < cfg["stale_after_s"]:
                raise FleetError("collection stale or missing")
            status = validate_status(row.get("status"), cfg, now)
            if not -FUTURE_SKEW_S <= now - status["time"] < cfg["stale_after_s"]:
                raise FleetError("source status stale")
            why = None
        except (ValueError, RecursionError) as error:
            status = None
            why = str(error) if isinstance(error, FleetError) else "invalid collected status"
        out.append((cfg, row, status, why))
    return out


def views(profile, now, s):
    out = []
    for cfg, row, status, why in _cached(profile, now):
        status = status or {}
        slots, busy, waiting = status.get("slots"), status.get("busy"), status.get("waiting")
        wait = None
        if slots and busy is not None and waiting is not None:
            wait = 0 if busy < slots and waiting == 0 else (busy + waiting) * cfg["job_minutes"] / slots
        healthy = status.get("state") in ("GREEN", "STEADY") and status.get("mode") == "act" \
            and _number((status.get("readings") or {}).get("free_pct"))
        out.append({"id": cfg["id"], "state": status.get("state", "UNKNOWN"), "reasons": status.get("reasons", [why]),
                    "eligible": bool(status and healthy and slots and wait is not None), "kinds": cfg["kinds"],
                    "wait_minutes": wait})
    return out


def resources(profile, now, s):
    out = []
    for cfg, row, status, why in _cached(profile, now):
        rec = mmdecide.machine_resource(status, cfg["id"], now, s)
        rec.update(id=cfg["id"], location="remote", time=now, read_time=(status or {}).get("time"),
                   stale_after_s=cfg["stale_after_s"])
        if status is None:
            rec.update(state="UNKNOWN", why=why)
        rec["values"].append({"key": "mode", "value": (status or {}).get("mode")})
        out.append(rec)
    return out


def commands(cfg, req):
    values = {key: str(req.get(key) if req.get(key) is not None else "") for key in FIELDS}
    values["race"] = "true" if req.get("race") else "false"
    if any(mmcore.clean(value) != value for value in values.values()):
        return []
    try:
        words = [re.sub(r"\{([^{}]+)\}", lambda m: values[m[1]], word) for word in cfg["start_argv"]]
    except (KeyError, TypeError):
        return []
    if cfg.get("ssh_argv"):
        remote = " ".join(shlex.quote(word) for word in words)
        return [" ".join(shlex.quote(word) for word in cfg["ssh_argv"] + [remote])]
    return [" ".join(shlex.quote(word) for word in words)]


if __name__ == "__main__":
    if sys.argv[1:] != ["--fetch"]:
        sys.exit(2)
    try:
        args = json.loads(sys.stdin.buffer.read(MAX_URL * 2))
        sys.stdout.buffer.write(_http(args["url"], args["timeout"]))
    except Exception:
        sys.exit(1)  # URLs (including query tokens) and transport exceptions never reach logs or output.
