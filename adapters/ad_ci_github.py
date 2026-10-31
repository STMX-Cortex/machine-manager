# SPDX-License-Identifier: Apache-2.0
"""CI pool adapter "github-gh": GitHub Actions read through `gh` (read-only), described as a pool.

Interface (PORTING.md, "Adapters"): Pool(cfg).read(s, now, watch) -> the raw read; status(read, s, now) -> a status
record with kind "pool"; resources(read, s, now) -> resource records (the pool and its self-hosted runners, for
resources.json; mmadapters.records); conditions(read, s, now, mk) -> alert conditions; owns(key) -> the key is one
conditions() raises (the pool record lists only those); minutes_left(s, now); guard_args(req);
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




# ------------------------------------------------------------------------------------------- self-hosted runners

RUNNERS_MAX = 1000  # runners kept from one read; the API page holds at most 100


def parse_runners(text, labels):
    """`gh api repos/<repo>/actions/runners` -> [{name, online, busy, labels}] for each runner that carries every label
    in `labels` (case-insensitive, as runs-on matches). Names and labels are GitHub text: kept cleaned and short.
    Raises ValueError when the text is not that shape."""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as e:
        raise ValueError("runners is not JSON") from e
    runners = data.get("runners") if isinstance(data, dict) else None
    if not isinstance(runners, list):
        raise ValueError("runners has no runners list")
    want = {str(x).lower() for x in labels}
    out = []
    for r in runners[:RUNNERS_MAX]:
        if not isinstance(r, dict) or not isinstance(r.get("name"), str) or not isinstance(r.get("labels"), list):
            continue  # a runner without a name or labels matches nothing
        names = [x.get("name") for x in r["labels"] if isinstance(x, dict) and isinstance(x.get("name"), str)]
        if not want <= {n.lower() for n in names}:
            continue
        out.append({"name": mmtext.clean(r["name"])[:100], "online": r.get("status") == "online",
                    "busy": r.get("busy") is True, "labels": [mmtext.clean(n)[:60] for n in names[:50]]})
    return out


def read_runners(cfg):
    """(runners, None) or ([], why) for the profile's ci.runner_labels. A failure (no admin scope: gh rc 1 on a 403 or
    404; text that does not parse) is only this part's: it never counts as a read error, a stale source or an alert."""
    rc, out = gh_run(["api", "repos/%s/actions/runners?per_page=100" % cfg["repo"]])
    if rc != 0:
        return [], "gh api runners rc=%s (the runner list needs admin access to the repository)" % rc
    try:
        return parse_runners(out, cfg["runner_labels"]), None
    except ValueError as e:
        return [], mmcore.mask(str(e))[:200]


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
    if cfg.get("runner_labels"):  # optional: only when the profile names runner labels
        try:
            res["runners"], res["runners_error"] = read_runners(cfg)
        except Exception as e:  # never the run or billing read's failure
            res["runners"], res["runners_error"] = [], mmcore.mask("runners read failed: %r" % e)[:200]
    res["watched"] = poll_watched(watch, now, repo)
    return res


# ------------------------------------------------------------------------------------------- gh-watch

def watch_file(pool_id=None):
    if pool_id is not None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", pool_id):
            raise ValueError("invalid pool id")
        return mmcore.path("state", "pools", pool_id, "watch.json")
    return mmcore.path("state", "gh-watch.json")


def watch_add(run_id, note, now, pool_id=None):
    if not re.fullmatch(r"[0-9]{1,20}", str(run_id)):
        raise ValueError("a run id is digits only")
    file = watch_file(pool_id)
    with mmcore.Locked(file + ".lock" if pool_id else mmcore.path("state", "gh-watch.lock")):
        w = mmcore.read_json(file, {}) or {}
        w[str(run_id)] = {"added": now, "note": note[:200], "status": None, "conclusion": None, "done_at": None}
        mmcore.write_atomic(file, json.dumps(w, sort_keys=True))


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


def save_watch(watch, pool_id=None):
    file = watch_file(pool_id)
    with mmcore.Locked(file + ".lock" if pool_id else mmcore.path("state", "gh-watch.lock")):
        cur = mmcore.read_json(file, {}) or {}
        for rid, w in watch.items():
            if rid in cur:  # keep runs added meanwhile; update the ones read
                cur[rid].update(w)
        # forget runs done more than a day ago
        cur = {k: v for k, v in cur.items() if not v.get("done_at") or time.time() - v["done_at"] < 86400}
        mmcore.write_atomic(file, json.dumps(cur, sort_keys=True))


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


def _runner_state(online, busy):
    if online is None or (online and busy is None):
        return "UNKNOWN"
    return "RED" if not online else ("STEADY" if busy else "GREEN")


def pool_resources(gh, s, now, pool_id):
    """The pool's resource records from its last read (gh, or None before the first read): the pool (minutes left of
    github.included_minutes, the reserve, the runs, the money), then one per named self-hosted runner (parent: the
    pool; GREEN online and idle, STEADY online and busy, RED offline, UNKNOWN when not known; an entry without a
    non-empty string name is left out), then the runner list's error. Each carries the read's time and
    github.stale_minutes as its read rule. Pure."""
    st, why = pool_state(gh, s, now)
    g = gh or {}
    b, r = g.get("billing") or {}, g.get("runs") or {}
    read = {"read_time": g.get("time"), "stale_after_s": s["github.stale_minutes"] * 60}
    out = [dict({"resource": "pool", "id": pool_id, "location": "cloud"}, **read, state=st,
                why=None if st == "GREEN" else "; ".join(why),
                capacity={"unit": "minutes", "total": s["github.included_minutes"],
                          "left": None if not b else round(s["github.included_minutes"] - b["minutes"], 1),
                          "reserve": s["github.reserve_minutes"]},
                load={"running": r.get("in_progress"), "queued": r.get("queued")},
                values=[{"key": "used_usd", "value": None if not b else round(b["gross"], 2)},
                        {"key": "allowed_usd", "value": s["github.allowed_gross_usd"]}])]
    for x in g.get("runners") if isinstance(g.get("runners"), list) else []:
        if not isinstance(x, dict) or not isinstance(x.get("name"), str) or not x["name"]:
            continue  # no name, no record: a record's id is a non-empty string (resource.schema.json)
        online = x.get("online") if isinstance(x.get("online"), bool) else None
        busy = x.get("busy") if isinstance(x.get("busy"), bool) else None
        out.append(dict({"resource": "runner", "id": x["name"], "parent": pool_id, "location": "self-hosted"}, **read,
                        state=_runner_state(online, busy),
                        why=None, values=[{"key": "online", "value": online}, {"key": "busy", "value": busy}]))
    if isinstance(g.get("runners_error"), str) and g["runners_error"]:
        out.append(dict({"resource": "runner", "id": "runners", "parent": pool_id, "location": "self-hosted"}, **read,
                        state="UNKNOWN", why=g["runners_error"]))
    return out


class Pool:
    def __init__(self, cfg):
        self.cfg = cfg
        self.id = cfg["pool_id"]
        self.scoped = bool(cfg.get("_multi_pool"))
        self.prefix = "POOL:%s:" % self.id if self.scoped else ""

    def settings(self, s):
        """Each pool inherits global thresholds, with its own capacity and reserve when configured."""
        return dict(s, **{"github." + k: self.cfg[k] for k in ("reserve_minutes", "included_minutes") if k in self.cfg})

    def cache_file(self):
        return mmcore.path("state", "pools", self.id, "github.json") if self.scoped else mmcore.path("state", "github.json")

    def watch_file(self):
        return watch_file(self.id if self.scoped else None)

    def read(self, s, now, watch):
        return read_all(self.cfg, self.settings(s), now, watch)

    def conditions(self, gh, s, now, mk, owner):
        found = conditions(gh, self.settings(s), now, mk, owner)
        if self.scoped:
            found = [dict(c, key=self.prefix + c["key"], text="pool %s: %s" % (self.id, c["text"])) for c in found]
        return found

    def good_keys(self, gh):
        return [self.prefix + key for key in good_keys(gh)]

    def owns(self, key):
        return key.startswith(self.prefix) and owns(key[len(self.prefix):])

    def job(self, s, now):
        """One full read in a worker thread: the watched runs too; writes state/github.json."""
        watch = mmcore.read_json(self.watch_file(), {}) or {}
        res = read_all(self.cfg, s, now, watch)
        save_watch(res.get("watched") or {}, self.id if self.scoped else None)
        mmcore.write_atomic(self.cache_file(), json.dumps(res, sort_keys=True))
        return res

    def status(self, gh, s, now, alerts=()):
        s = self.settings(s)
        st, why = pool_state(gh, s, now)
        b = (gh or {}).get("billing") or {}
        r = (gh or {}).get("runs") or {}
        return mmcore.stamp({"kind": "pool", "time": now, "state": st, "reasons": why,
                             "capacity": {"minutes_left": (s["github.included_minutes"] - b["minutes"]) if b else None,
                                          "reserve_minutes": s["github.reserve_minutes"]},
                             "load": {"running": r.get("in_progress"), "queued": r.get("queued")},
                             "alerts": list(alerts), "read_time": (gh or {}).get("time")}, mid=self.id)

    def resources(self, gh, s, now):
        return pool_resources(gh, self.settings(s), now, self.id)

    def minutes_left(self, s, now):
        s = self.settings(s)
        gh = mmcore.read_json(self.cache_file(), None)
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
