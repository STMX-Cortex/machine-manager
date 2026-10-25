# SPDX-License-Identifier: Apache-2.0
"""machine-manager placement: gathers the context, then the pure mmdecide.place decides. Read-only.

It never pushes or dispatches: for POOL it prints the exact commands from the profile for a person or agent to run.
Exit codes: 0 MACHINE or GO, 10 POOL, 20 WAIT.
"""
import shlex
import time

import mmcore
import mmdecide
import mmread


def machine_view(now, s, queue, profile):
    """The machine's state from status.json (fresh), else from one sample (growth rules unchecked)."""
    cur = mmcore.read_json(mmcore.path("status.json"), None)
    if isinstance(cur, dict) and now - float(cur.get("time", 0)) < s["other.status_fresh_s"]:
        return {"state": cur["state"], "reasons": cur.get("reasons", []), "free_pct": (cur.get("readings") or {}).get("free_pct"),
                "source": "supervisor"}
    sample, _ = mmread.memory_sample(now)
    if queue is not None:
        lp, _ = queue.last_sample(now)
        sample["sys_pct"] = lp.get("sys_pct") if lp else None
    st, reasons, _ = mmdecide.classify([sample], s)
    return {"state": st, "reasons": reasons, "free_pct": sample.get("free_pct"),
            "source": "one sample (the supervisor is not running: growth rules unchecked)"}


def place(req, s, profile, queue=None, pool=None, now=None):
    """req: kind, shards, wide, agents, crate, diff_base, race, packages, sha, branch.
    Returns (answer dict, commands list)."""
    now = now or time.time()
    # C-20: the request's words come from the caller (an agent): cleaned for every output; a request that cleaning
    # changes gets no commands (they would name another value), and its kind shows quoted in the reasons
    raw = req
    req = {k: mmcore.clean(v) if isinstance(v, str) else v for k, v in raw.items()}
    changed = req != raw
    mv = machine_view(now, s, queue, profile)
    q = None
    if queue is not None:
        try:
            q = queue.read(now)
        except OSError:
            q = None
    machine = {"id": mmcore.machine_id(profile), "state": mv["state"], "reasons": mv["reasons"], "free_pct": mv["free_pct"],
               "queue": q, "medians": queue.medians() if queue is not None else {}}
    active = {v.get("name") for v in ((mmcore.read_json(mmcore.path("alerts-state.json"), {}) or {}).get("active") or {}).values()}
    pools, gargs = [], None
    if pool is not None:
        left, src = pool.minutes_left(s, now)
        gargs, gwhy = pool.guard_args(req)
        pools.append({"id": pool.id, "minutes_left": left, "minutes_source": src, "plan_minutes": pool.cfg.get("plan_minutes", 2),
                      "job_minutes": pool.cfg.get("job_minutes", 40), "guard": None, "guard_why": gwhy,
                      "stop_active": "GUARD_STOP" in active})
    ctx = {"now": now, "kinds": {"machine_only": profile["kinds"].get("machine_only", {}), "pool": profile["kinds"].get("pool", {})},
           "wide_kind": profile["kinds"].get("wide") or None, "machine": machine, "pools": pools}
    shown = dict(req, kind=mmcore.quoted(req["kind"]))  # a profile's kind is bare and stays as it is
    ans = mmdecide.place(shown, ctx, s)
    if ans["need_guard"]:
        rc, line = pool.guard(gargs)
        pools[0]["guard"] = {"rc": rc, "line": mmcore.clean(mmcore.mask(line))}
        ans = mmdecide.place(shown, ctx, s)
    if mv["source"] != "supervisor":
        ans["reasons"].append("state source: " + mv["source"])
    cmds = []
    if ans["place"] == "POOL" and changed:
        ans["reasons"].append("commands withheld: a request word held a character outputs replace")
    elif ans["place"] == "POOL":
        watch = "mm watch <run-id> --note %s" % shlex.quote(req["kind"])
        cmds = pool.commands(req, gargs or [], watch)
    rec = mmcore.stamp({"kind": "placement", "time": now, "request": req, "place": ans["place"], "candidate": ans["candidate"],
                        "reasons": ans["reasons"], "commands": cmds}, profile)
    return rec
