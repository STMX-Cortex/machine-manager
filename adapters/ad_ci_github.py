# SPDX-License-Identifier: Apache-2.0
"""CI pool adapter "github-gh": GitHub Actions read through `gh` (read-only), described as a pool.

Interface (PORTING.md, "Adapters"): Pool(cfg).read(s, now, watch) -> the raw read; status(read, s, now) -> a status
record with kind "pool"; conditions(read, s, now, mk) -> alert conditions; owns(key) -> the key is one conditions()
raises (the pool record lists only those); minutes_left(s, now); guard_args(req);
guard(args) -> (rc, line); commands(req, gargs). Every gh call goes through gh_run, which MM_GH replaces in tests.
Nothing here pushes, dispatches, deletes or changes GitHub (no automatic dispatch).
"""
import calendar
import json
import os
import re
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import mmcore
import mmread
import mmtext
import shlex
import subprocess

RUN_FIELDS = "databaseId,workflowName,headBranch,status,conclusion,createdAt,startedAt,updatedAt,event,url,displayTitle"
QUEUED = ("queued", "waiting", "pending", "requested")
FAILED = ("failure", "timed_out", "startup_failure")
MAX_JOB_READS = 5


def gh_run(argv, timeout=60):
    exe = os.environ.get("MM_GH", "gh")
    return mmread.run([exe] + list(argv), timeout=timeout)


def iso(text):
    return datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp()


# ------------------------------------------------------------------------------------------- billing

class BillingError(ValueError):
    pass


def _num(v, what):
    if isinstance(v, bool) or not isinstance(v, (int, Decimal)):
        raise BillingError("%s is not a number: %r" % (what, str(v)[:40]))
    d = Decimal(v)
    if not d.is_finite() or d < 0:
        raise BillingError("%s is not usable: %s" % (what, str(v)[:40]))
    return d


def parse_billing(text, month, linux_sku="actions linux"):
    """(Actions Linux minutes, Actions gross $, Actions net $) of one month (YYYY-MM).
    Exact decimals: exponent forms such as 4.987e-06 parse (B83); a bool, a string or a negative number is an error."""
    try:
        data = json.loads(text, parse_float=Decimal, parse_int=Decimal)
    except (ValueError, InvalidOperation, RecursionError) as e:
        raise BillingError("billing is not JSON: %s" % e) from e
    items = data.get("usageItems") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise BillingError("billing has no usageItems list")
    minutes = gross = net = Decimal(0)
    for it in items:
        if not isinstance(it, dict) or not isinstance(it.get("date"), str):
            raise BillingError("an item without a date")
        if it["date"][:7] != month or str(it.get("product", "")).lower() != "actions":
            continue
        sku = str(it.get("sku", ""))
        gross += _num(it.get("grossAmount", Decimal(0)), "grossAmount of " + sku)
        net += _num(it.get("netAmount", Decimal(0)), "netAmount of " + sku)
        if sku.lower() == linux_sku:
            minutes += _num(it.get("quantity", Decimal(0)), "quantity of " + sku)
    return minutes, gross, net




# ------------------------------------------------------------------------------------------- runs

def is_noise(r, noise):
    """A run that fails by design (profile ci.noise: workflow or workflow_regex, event, branch_regex)."""
    name = r.get("workflowName") or ""
    for n in noise:
        if "workflow" in n and name != n["workflow"]:
            continue
        if "workflow_regex" in n and not mmtext.search(n["workflow_regex"], name):  # names agents chose (C-22)
            continue
        if n.get("event") and r.get("event") != n["event"]:
            continue
        if n.get("branch_regex") and not mmtext.search(n["branch_regex"], r.get("headBranch") or ""):
            continue
        return True
    return False


def summarize_runs(runs, now, noise=()):
    """Counts and the failed and stuck runs from `gh run list --json RUN_FIELDS`."""
    out = {"in_progress": 0, "queued": 0, "oldest_queued_min": 0, "longest_running_min": 0, "failed_1h": [],
           "running": []}
    for r in runs:
        st = r.get("status")
        if st == "in_progress":
            out["in_progress"] += 1
            out["running"].append(r.get("databaseId"))
            if r.get("startedAt"):
                out["longest_running_min"] = max(out["longest_running_min"], round((now - iso(r["startedAt"])) / 60))
        elif st in QUEUED:
            out["queued"] += 1
            out["oldest_queued_min"] = max(out["oldest_queued_min"], round((now - iso(r["createdAt"])) / 60))
        if r.get("conclusion") in FAILED and not is_noise(r, noise) and r.get("updatedAt") and now - iso(r["updatedAt"]) < 3600:
            out["failed_1h"].append({"id": r.get("databaseId"), "workflow": r.get("workflowName"),
                                     "branch": r.get("headBranch"), "url": r.get("url"),
                                     "title": (r.get("displayTitle") or "")[:120]})
    return out


def read_all(cfg, s, now, watch):
    """One full GitHub read: runs, queued jobs of running runs, billing, watched runs. Returns the state dict.
    A failed part keeps its error text; the other parts still count."""
    repo = cfg["repo"]
    res = {"time": now, "errors": {}, "pool_id": cfg["pool_id"]}
    rc, out = gh_run(["run", "list", "-R", repo, "--limit", "100", "--json", RUN_FIELDS])
    try:
        if rc != 0:
            raise ValueError("gh run list rc=%s" % rc)
        runs = json.loads(out)
        res["runs"] = summarize_runs(runs, now, cfg.get("noise", []))
        oldest_job = 0
        for rid in res["runs"]["running"][:MAX_JOB_READS]:
            rc2, jo = gh_run(["api", "repos/%s/actions/runs/%s/jobs?per_page=100" % (repo, rid)])
            if rc2 != 0:
                continue
            for job in json.loads(jo).get("jobs", []):
                if job.get("status") in QUEUED and job.get("created_at"):
                    oldest_job = max(oldest_job, (now - iso(job["created_at"])) / 60)
        res["runs"]["oldest_queued_job_min"] = round(oldest_job)
    except (ValueError, TypeError, KeyError) as e:
        res["errors"]["runs"] = str(e)[:200]
    rc, out = gh_run(["api", cfg["billing_path"]])
    try:
        if rc != 0:
            raise BillingError("gh api billing rc=%s" % rc)
        m, g, n = parse_billing(out, time.strftime("%Y-%m", time.gmtime(now)), cfg.get("linux_sku", "actions linux"))
        res["billing"] = {"minutes": float(m), "gross": float(g), "net": float(n)}
    except BillingError as e:
        res["errors"]["billing"] = str(e)[:200]
    res["watched"] = poll_watched(watch, now, repo)
    return res


# ------------------------------------------------------------------------------------------- gh-watch

def watch_file():
    return mmcore.path("state", "gh-watch.json")


def watch_add(run_id, note, now):
    if not re.fullmatch(r"[0-9]{1,20}", str(run_id)):
        raise ValueError("a run id is digits only")
    with mmcore.Locked(mmcore.path("state", "gh-watch.lock")):
        w = mmcore.read_json(watch_file(), {}) or {}
        w[str(run_id)] = {"added": now, "note": note[:200], "status": None, "conclusion": None, "done_at": None}
        mmcore.write_atomic(watch_file(), json.dumps(w, sort_keys=True))


def poll_watched(watch, now, repo):
    """Refresh each watched run that is not done; returns the updated dict (the caller saves it)."""
    for rid, w in watch.items():
        if w.get("done_at"):
            continue
        rc, out = gh_run(["run", "view", rid, "-R", repo,
                          "--json", "status,conclusion,url,workflowName,displayTitle,updatedAt"])
        if rc != 0:
            w["error"] = "gh run view rc=%s" % rc
            continue
        try:
            d = json.loads(out)
        except ValueError:
            w["error"] = "unreadable"
            continue
        w.update(status=d.get("status"), conclusion=d.get("conclusion"), url=d.get("url"),
                 title=(d.get("displayTitle") or "")[:120], error=None)
        if d.get("status") == "completed":
            w["done_at"] = now
    return watch


def save_watch(watch):
    with mmcore.Locked(mmcore.path("state", "gh-watch.lock")):
        cur = mmcore.read_json(watch_file(), {}) or {}
        for rid, w in watch.items():
            if rid in cur:  # keep runs added meanwhile; update the ones read
                cur[rid].update(w)
        # forget runs done more than a day ago
        cur = {k: v for k, v in cur.items() if not v.get("done_at") or time.time() - v["done_at"] < 86400}
        mmcore.write_atomic(watch_file(), json.dumps(cur, sort_keys=True))


# ------------------------------------------------------------------------------------------- alerts

def money_stop(gross, s):
    """allowed_gross_usd 0 = no paid use: any gross amount stops; else the stop is at the limit."""
    lim = s["github.allowed_gross_usd"]
    return gross > lim if lim == 0 else gross >= lim


def money_near(gross, s):
    lim = s["github.allowed_gross_usd"]
    return lim > 0 and gross >= lim * s["github.near_gross_pct"] / 100.0


def month_pace(minutes, now):
    t = time.gmtime(now)
    dim = calendar.monthrange(t.tm_year, t.tm_mon)[1]
    day = t.tm_mday - 1 + (t.tm_hour * 3600 + t.tm_min * 60) / 86400.0
    return minutes / max(day, 0.5) * dim


READ_PARTS = ("runs", "billing")


def good_keys(gh):
    """The SOURCE_STALE keys a fresh read proves good: gh itself, and each part read without an error. The caller clears
    them at once (a good read is proof, so the usual clear delay does not apply)."""
    if not gh:
        return []
    errs = gh.get("errors") or {}
    return ["SOURCE_STALE:gh"] + ["SOURCE_STALE:gh-" + p for p in READ_PARTS if p not in errs]


# The alert keys conditions() raises: whole keys, and key prefixes. owns() picks them for the pool record; the memory
# guard's GUARD_KILL and GUARD_DOWN (other keys) stay out. tests/test_consistency.py checks each key conditions() makes.
OWN_KEYS = ("SOURCE_STALE:gh", "GH_STUCK", "GUARD", "GH_PACE")
OWN_PREFIXES = ("SOURCE_STALE:gh-", "GH_FAIL:", "GH_DONE:")


def owns(key):
    """True for an alert key this adapter raises (conditions)."""
    return key in OWN_KEYS or key.startswith(OWN_PREFIXES)


def conditions(gh, s, now, mk, owner="the owner"):
    """GH_FAIL, GH_STUCK, GH_DONE, GUARD_NEAR/STOP, GH_PACE and gh SOURCE_STALE from the last read (`mk` = mmalerts._c)."""
    out = []
    if not gh or now - gh.get("time", 0) > s["github.stale_minutes"] * 60:
        age = "never read" if not gh else "%.0f min old" % ((now - gh["time"]) / 60)
        out.append(mk("SOURCE_STALE:gh", "SOURCE_STALE", "ATTENTION", "source gh is stale: %s" % age))
        if not gh:
            return out
    for part, err in (gh.get("errors") or {}).items():
        out.append(mk("SOURCE_STALE:gh-" + part, "SOURCE_STALE", "ATTENTION", "GitHub %s read failed: %s" % (part, err[:100])))
    r = gh.get("runs")
    if r:
        for f in r.get("failed_1h", []):
            out.append(mk("GH_FAIL:%s" % f["id"], "GH_FAIL", "ATTENTION",
                          "GitHub run failed: %s on %s (%s) %s" % (f["workflow"], f["branch"], f["title"][:50], f["url"]),
                          investigate={"question": "Why did this GitHub run fail?",
                                       "hypotheses": ["a real test failure", "a known Linux-only case", "infrastructure"]}))
        stuck = []
        if r.get("oldest_queued_min", 0) > s["github.stuck_queued_minutes"]:
            stuck.append("a run queued %d min" % r["oldest_queued_min"])
        if r.get("oldest_queued_job_min", 0) > s["github.stuck_queued_minutes"]:
            stuck.append("a job queued %d min" % r["oldest_queued_job_min"])
        if r.get("longest_running_min", 0) > s["github.stuck_running_minutes"]:
            stuck.append("a run running %d min" % r["longest_running_min"])
        if stuck:
            out.append(mk("GH_STUCK", "GH_STUCK", "ATTENTION", "GitHub: " + "; ".join(stuck) + "."))
    b = gh.get("billing")
    if b:
        m, gross = b["minutes"], b["gross"]
        limit = s["github.allowed_gross_usd"]
        if money_stop(gross, s) or m >= s["github.stop_minutes"]:
            out.append(mk("GUARD", "GUARD_STOP", "ACTION",
                          "GitHub: gross $%.2f of $%g, %.0f of %g minutes this month: no dispatch; tell %s."
                          % (gross, limit, m, s["github.included_minutes"], owner), value=m, band=5000))
        elif money_near(gross, s) or m >= s["github.near_minutes"]:
            out.append(mk("GUARD", "GUARD_NEAR", "ATTENTION", "GitHub: gross $%.2f of $%g, %.0f minutes this month."
                          % (gross, limit, m), value=m, band=5000))
        pace = month_pace(m, now)
        if pace > s["github.pace_minutes"]:
            out.append(mk("GH_PACE", "GH_PACE", "ATTENTION", "GitHub month pace %.0f minutes (%.0f used); limit %g."
                          % (pace, m, s["github.pace_minutes"]), value=pace, band=5000))
    for rid, w in (gh.get("watched") or {}).items():
        if w.get("done_at") and now - w["done_at"] < s["github.done_alert_minutes"] * 60:
            out.append(mk("GH_DONE:" + rid, "GH_DONE", "ATTENTION", "Watched GitHub run %s ended: %s (%s). %s %s"
                          % (rid, w.get("conclusion"), w.get("note") or "", w.get("title") or "", w.get("url") or "")))
    return out


# ------------------------------------------------------------------------------------------- the pool record

def pool_state(gh, s, now):
    """GREEN / AMBER / RED for a pool, from its last read (RED: budget stop; AMBER: near, stuck or stale)."""
    if not gh or now - gh.get("time", 0) > s["github.stale_minutes"] * 60:
        return "UNKNOWN", ["no fresh read"]
    b, r = gh.get("billing") or {}, gh.get("runs") or {}
    why = []
    if b and (money_stop(b["gross"], s) or b["minutes"] >= s["github.stop_minutes"]):
        return "RED", ["budget stop: gross $%.2f, %.0f minutes" % (b["gross"], b["minutes"])]
    if b and (money_near(b["gross"], s) or b["minutes"] >= s["github.near_minutes"]):
        why.append("budget near")
    if r.get("oldest_queued_min", 0) > s["github.stuck_queued_minutes"]:
        why.append("runs queue")
    if gh.get("errors"):
        why.append("read errors: " + ", ".join(gh["errors"]))
    return ("AMBER", why) if why else ("GREEN", ["budget and queue fine"])


class Pool:
    def __init__(self, cfg):
        self.cfg = cfg
        self.id = cfg["pool_id"]

    def read(self, s, now, watch):
        return read_all(self.cfg, s, now, watch)

    def conditions(self, gh, s, now, mk, owner):
        return conditions(gh, s, now, mk, owner)

    def good_keys(self, gh):
        return good_keys(gh)

    def owns(self, key):
        return owns(key)

    def job(self, s, now):
        """One full read in a worker thread: the watched runs too; writes state/github.json."""
        watch = mmcore.read_json(watch_file(), {}) or {}
        res = read_all(self.cfg, s, now, watch)
        save_watch(res.get("watched") or {})
        mmcore.write_atomic(mmcore.path("state", "github.json"), json.dumps(res, sort_keys=True))
        return res

    def status(self, gh, s, now, alerts=()):
        st, why = pool_state(gh, s, now)
        b = (gh or {}).get("billing") or {}
        r = (gh or {}).get("runs") or {}
        return mmcore.stamp({"kind": "pool", "time": now, "state": st, "reasons": why,
                             "capacity": {"minutes_left": (s["github.included_minutes"] - b["minutes"]) if b else None,
                                          "reserve_minutes": s["github.reserve_minutes"]},
                             "load": {"running": r.get("in_progress"), "queued": r.get("queued")},
                             "alerts": list(alerts), "read_time": (gh or {}).get("time")}, mid=self.id)

    def minutes_left(self, s, now):
        gh = mmcore.read_json(mmcore.path("state", "github.json"), None)
        if isinstance(gh, dict) and gh.get("billing") and now - gh.get("time", 0) < s["github.stale_minutes"] * 60:
            return s["github.included_minutes"] - gh["billing"]["minutes"], "the supervisor's read"
        rc, out = gh_run(["api", self.cfg["billing_path"]])
        if rc != 0:
            return None, "billing unreadable (gh rc=%s)" % rc
        try:
            m, _, _ = parse_billing(out, time.strftime("%Y-%m", time.gmtime(now)), self.cfg.get("linux_sku", "actions linux"))
        except BillingError as e:
            return None, "billing unreadable: %s" % e
        return s["github.included_minutes"] - float(m), "gh api now"

    def guard_args(self, req):
        """The budget guard's arguments from the profile's ci.guard_args (per kind, else "default");
        (None, reason) when the profile has none or the request lacks a value a placeholder needs."""
        kind = req["kind"]
        tpl = self.cfg.get("guard_args") or {}
        t = tpl.get(kind, tpl.get("default"))
        if t is None:
            return None, "no ci.guard_args for kind %s in the profile" % kind
        fill = dict(self.cfg.get("guard_defaults") or {})
        given = {"kind": kind, "shards": str(req.get("shards", 1)), "race": "true" if req.get("race") else "false",
                 "packages": req.get("packages"), "crate": req.get("crate"), "diff_base": req.get("diff_base")}
        fill.update({k: v for k, v in given.items() if v})
        need = sorted({n for x in t for n in re.findall(r"\{(\w+)\}", x)})
        missing = [n for n in need if not fill.get(n)]
        if missing:
            return None, "%s needs %s for the guard" % (kind, " and ".join("--" + n.replace("_", "-") for n in missing))
        return [x.format(**fill) for x in t], None

    def guard(self, args):
        cmd = os.environ.get("MM_GUARD")
        full = ([cmd] if cmd else list(self.cfg["guard_argv"])) + list(args)
        try:
            p = subprocess.run(full, capture_output=True, text=True, timeout=120, cwd=self.cfg.get("guard_cwd") or None)
            return p.returncode, ((p.stdout + p.stderr).strip().splitlines() or [""])[-1]
        except (OSError, subprocess.TimeoutExpired) as e:
            return 2, str(e)[:200]

    def commands(self, req, gargs, watch_cmd):
        branch = req.get("branch") or ("scratch-%s-%s" % (req["kind"], (req.get("sha") or "<sha>")[:8]))
        fill = {"sha": req.get("sha") or "<sha>", "branch": branch}
        # The push and scratch commands are shell text from the profile: each filled value is quoted as one word.
        quoted = {k: shlex.quote(v) for k, v in fill.items()}
        if req["kind"] in self.cfg.get("dispatch_kinds", []):
            disp = [x.format(**fill) for x in self.cfg["dispatch_argv"]] + list(gargs)
            return [self.cfg["push_command"].format(**quoted), " ".join(shlex.quote(x) for x in disp), watch_cmd]
        return [self.cfg["scratch_command"].format(**quoted), watch_cmd]
