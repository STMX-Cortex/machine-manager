# SPDX-License-Identifier: Apache-2.0
"""machine-manager evidence bundles for a read-only investigator agent.

A bundle is a folder evidence/<NN>/ in the data folder (a ring of evidence.slots folders, the oldest reused) with the
facts of one alert: alert.json (the question, the hypotheses, the time window), metrics.csv rows of the window, the
queue's sampler and history tails, the queue, ps top lists with the slot trees marked, kernel memorystatus lines of the
window, vm_stat / sysctl / memory_pressure readings, the usage state, the pool summary and sizes.
state/evidence-index.json maps alert seq and key to the folder. Every text is masked (mmcore.mask) before it is written.
"""
import json
import os
import shutil
import time

import mmcore
import mmread


def _slot(n):
    """The ring slot to use: an empty one, else the one written longest ago."""
    ev = mmcore.path("evidence")
    os.makedirs(ev, exist_ok=True)
    best, best_t = None, None
    for i in range(n):
        p = os.path.join(ev, "%02d" % i)
        try:
            t = os.path.getmtime(os.path.join(p, "alert.json"))
        except OSError:
            return "%02d" % i
        if best_t is None or t < best_t:
            best, best_t = "%02d" % i, t
    return best


def _tail_lines(f, n, max_bytes=1 << 20):
    try:
        with open(f, "rb") as fh:
            fh.seek(max(0, os.path.getsize(f) - max_bytes))
            return fh.read().decode("utf-8", "replace").splitlines()[-n:]
    except OSError:
        return []


def bundle(rec, s, now, queue=None, slot=None, extra=None, usage_file=None):
    """Write one bundle for an alert record (from AlertStore.pushed or alerts-state). Returns its folder."""
    win = s["evidence.window_minutes"] * 60
    slot = slot or _slot(s["evidence.slots"])
    d = mmcore.path("evidence", slot)
    tmp = d + ".new"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)

    def put(name, text):
        text = mmcore.mask(text)
        with open(os.path.join(tmp, name), "w") as f:
            f.write(text if text.endswith("\n") or not text else text + "\n")

    inv = rec.get("investigate") or {}
    put("alert.json", json.dumps({
        "alert": {k: rec.get(k) for k in ("seq", "key", "name", "level", "text", "time", "command")},
        "question": inv.get("question"), "hypotheses": inv.get("hypotheses", []),
        "window": [mmcore.now_local(now - win), mmcore.now_local(now)], "made": mmcore.now_local(now),
        "machine_id": mmcore.machine_id((extra or {}).get("profile")), "schema_version": mmcore.SCHEMA_VERSION,
        "files": ["metrics.csv", "load.log", "history.log", "queue.json", "ps.txt", "kernel.jsonl", "readings.txt",
                  "usage.json", "github.json", "sizes.json", "status.json", "decisions.log"]}, indent=1))
    # metrics of the window
    rows = _tail_lines(mmcore.path("metrics.csv"), 400)
    head = rows[:1] if rows and rows[0].startswith("time,") else ["time,..."]
    keep = [r for r in rows if r[:19] >= mmcore.now_local(now - win)[:19]]
    put("metrics.csv", "\n".join(head + keep))
    q = None
    if queue is not None:
        put("load.log", "\n".join(_tail_lines(queue.sample_log(), int(win / 60) + 5)))
        put("history.log", "\n".join(_tail_lines(queue.history_log(), 60)))
        try:
            q = queue.read(now)
        except OSError as e:
            q = {"error": str(e)}
    put("queue.json", json.dumps(q, indent=1, default=str))
    procs = mmread.read_ps() or []
    marks = {}
    for b in (q or {}).get("busy", []) if isinstance(q, dict) else []:
        for pid in mmread.descendants(procs, b.get("pid")) if b.get("pid") else []:
            marks[pid] = b.get("slot")
    lines = ["# top 25 by memory (MB), then top 25 by CPU (%); slot= marks a queue call's process tree"]
    for title, key in (("memory", "rss_mb"), ("cpu", "cpu")):
        lines.append("## by " + title)
        for p in sorted(procs, key=lambda p: -p[key])[:25]:
            lines.append("%7d %7d %9.0f MB %6.1f%% %s%s" % (p["pid"], p["ppid"], p["rss_mb"], p["cpu"], p["comm"],
                                                            "  slot=%s" % marks[p["pid"]] if p["pid"] in marks else ""))
    put("ps.txt", "\n".join(lines))
    kl = [l for l in _tail_lines(mmcore.path("state", "kernel.jsonl"), 200)
          if _seen(l) is not None and now - _seen(l) <= win]
    put("kernel.jsonl", "\n".join(kl))
    rd = []
    for argv in (["/usr/bin/vm_stat"], ["/usr/sbin/sysctl", "vm.swapusage", "vm.loadavg", "vm.compressor.segment.total",
                                        "kern.memorystatus_level"], ["/usr/bin/memory_pressure", "-Q"]):
        rc, out = mmread.run(argv, timeout=20)
        rd.append("$ %s  (rc=%s)\n%s" % (" ".join(argv), rc, out.strip()))
    put("readings.txt", "\n\n".join(rd))
    try:
        with open(usage_file) as f:
            put("usage.json", f.read(200000))
    except (OSError, TypeError):
        put("usage.json", "{}")
    gh = mmcore.read_json(mmcore.path("state", "github.json"), {}) or {}
    put("github.json", json.dumps({k: gh.get(k) for k in ("time", "runs", "billing", "errors", "watched")}, indent=1))
    put("sizes.json", json.dumps((extra or {}).get("sizes") or {}, indent=1))
    put("status.json", json.dumps(mmcore.read_json(mmcore.path("status.json"), {}) or {}, indent=1))
    put("decisions.log", "\n".join(_tail_lines(mmcore.path("state", "decisions.log"), 40)))
    shutil.rmtree(d, ignore_errors=True)
    os.replace(tmp, d)
    with mmcore.Locked(mmcore.path("state", "evidence.lock")):
        idx = mmcore.read_json(mmcore.path("state", "evidence-index.json"), {}) or {}
        idx = {k: v for k, v in idx.items() if v.get("slot") != slot}
        idx[str(rec.get("seq") or rec.get("key"))] = {"slot": slot, "key": rec.get("key"), "time": now}
        mmcore.write_atomic(mmcore.path("state", "evidence-index.json"), json.dumps(idx, sort_keys=True))
    return d


def _seen(line):
    try:
        return float(json.loads(line).get("seen"))
    except (ValueError, TypeError, AttributeError):
        return None


def folder_for(seq=None, key=None):
    idx = mmcore.read_json(mmcore.path("state", "evidence-index.json"), {}) or {}
    for k, v in idx.items():
        if (seq is not None and k == str(seq)) or (key is not None and v.get("key") == key):
            return mmcore.path("evidence", v["slot"])
    return None
