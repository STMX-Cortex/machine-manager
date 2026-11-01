# SPDX-License-Identifier: Apache-2.0
"""The adapter table: profile adapter names -> modules. A second project adds its module here (no plugin system).

Any adapter may define resources(read, s, now) -> [resource record without `time`] (schemas/resource.schema.json,
$defs/record): built only from `read` (the supervisor's last read for that adapter) and the adapter's own small files,
with no command, no network and no waiting. The supervisor asks each one through records() every tick and writes
resources.json; `mm resources` reads that file and loads no adapter."""
import importlib
import json
import re

QUEUE = {"fifo-gates": ("ad_queue_fifo", "Queue")}
POOL = {"github-gh": ("ad_ci_github", "Pool")}
DELIVERY = {"claude-code-hook": ("ad_deliver_claude", "Delivery")}


def _make(table, cfg, part):
    name = (cfg or {}).get("adapter")
    if not name:
        return None
    if name not in table:
        import mmcore
        raise mmcore.MMError("E_PROFILE", "unknown %s adapter %r" % (part, name), "use one of %s" % ", ".join(sorted(table)))
    mod, cls = table[name]
    return getattr(importlib.import_module(mod), cls)(cfg)


def queue(profile):
    return _make(QUEUE, profile.get("queue"), "queue")


def pool_configs(profile):
    """Normalized pool configs. Legacy [ci] keeps its files and keys; [[pools]] uses explicit, unique ids."""
    import mmcore
    import mmschema
    if "pools" not in profile:
        return [profile["ci"]] if (profile.get("ci") or {}).get("adapter") else []
    if profile.get("ci"):
        raise mmcore.MMError("E_PROFILE", "[ci] and [[pools]] cannot be combined", "use [[pools]] for every pool")
    configs = profile["pools"]
    if not isinstance(configs, list):
        raise mmcore.MMError("E_PROFILE", "pools must be a list", "use [[pools]] entries")
    schema = mmschema.load("profile")["properties"]["pools"]["items"]
    out, seen = [], set()
    for cfg in configs:
        problems = mmschema.validate(cfg, schema)
        if problems:
            raise mmcore.MMError("E_PROFILE", "pool: " + problems[0], "correct [[pools]]; mm check")
        ident = cfg["id"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", ident) or ident.casefold() in seen:
            raise mmcore.MMError("E_PROFILE", "pool id is invalid or repeated: %r" % ident,
                                 "use unique ids of 1..80 letters, digits, dots, - or _, starting with a letter or digit")
        for key in ("reserve_minutes", "included_minutes", "job_minutes", "plan_minutes"):
            if key in cfg and not 0 <= cfg[key] <= 10000000:
                raise mmcore.MMError("E_PROFILE", "pool %s has invalid %s" % (ident, key),
                                     "use a finite number from 0 to 10000000")
        seen.add(ident.casefold())
        out.append(dict(cfg, pool_id=ident, _multi_pool=True))
    return out


def pools(profile):
    return [_make(POOL, cfg, "pool") for cfg in pool_configs(profile)]


def pool(profile):
    """The first pool (compatibility for callers that accept one adapter)."""
    found = pools(profile)
    return found[0] if found else None


def delivery(profile):
    return _make(DELIVERY, profile.get("delivery"), "delivery")


def settings(profile):
    """mmcore.Settings as the supervisor builds it (real_slots: the queue's slot file), so `mm check` and
    `mm settings show` refuse what the supervisor refuses; without real_slots when the queue adapter cannot load."""
    import mmcore
    try:
        q = queue(profile)
    except Exception:  # an E_PROFILE line of its own elsewhere; the settings are still read
        q = None
    return mmcore.Settings(real_slots=q.slots_path() if q else None)


def records(ad, read, s, now, part):
    """The resource records of one adapter (part: ci, delivery or queue) for resources.json: [] when ad is None or has
    no resources method; else its list cut to mmdecide.RECORDS_MAX records (each one's values to VALUES_MAX), masked,
    cleaned and checked as strict JSON the way _resources dumps it (sort_keys, allow_nan=False). Any failure (not a
    list, NaN, a set, keys that do not sort, nesting too deep, an exception) gives one UNKNOWN record (resource
    "adapter", id part) and one errors.log line, never a failed tick."""
    import mmcore
    import mmdecide
    if ad is None or not hasattr(ad, "resources"):
        return []
    try:
        got = ad.resources(read, s, now)
        if not isinstance(got, list):
            raise TypeError("not a list: %s" % type(got).__name__)
        out = []
        for r in got[:mmdecide.RECORDS_MAX]:
            if not isinstance(r, dict):
                continue
            r = dict(r)
            if isinstance(r.get("values"), list):
                r["values"] = r["values"][:mmdecide.VALUES_MAX]
            r = mmcore.clean_obj(mmcore.mask_obj(r))
            json.dumps(r, sort_keys=True, allow_nan=False)  # as written: NaN, inf, a set, mixed keys or nesting raise
            out.append(r)
        return out
    except Exception as e:  # RecursionError too
        try:
            mmcore.append_line(mmcore.path("state", "errors.log"),
                               mmcore.mask("%s resources %s %r" % (mmcore.now_local(now), part, e)))
        except Exception:  # the log line is help; the UNKNOWN record still says why
            pass
        return [{"resource": "adapter", "id": part, "location": None, "read_time": None, "stale_after_s": None,
                 "state": "UNKNOWN", "why": mmcore.clean(mmcore.mask("%s.resources failed: %r" % (part, e)))[:200]}]
