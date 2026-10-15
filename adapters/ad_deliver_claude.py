#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Delivery adapter "claude-code-hook": warnings to one Claude Code session (the recipient), plus the session facts
the supervisor reads from Claude Code (usage-watch state, the recipient's open tool calls, its job lines, cache writes).

Interface (PORTING.md, "Adapters"): recipient(); hook(argv, stdin) (the hook process); take_unseen(session, level, now);
format_alerts(records); banner(text, enabled); usage(now, s); open_tool_call(now); jobs(); cache_5m(now).

The hook prints unseen ATTENTION and ACTION alerts as additional context, only in the recipient's main session:
- session_id must equal the id the profile's recipient_regex finds in recipient_file;
- a call from inside a subagent carries agent_id (Claude Code 2.1.299 hook input schema: "Present only when the hook fires
  from within a subagent ... Absent for the main thread"); such calls get no output. Subagent calls carry the parent's
  session_id, so the session check alone would not stop them;
- a subagent's compaction calls SessionStart with no agent_id at all; only its model differs from the recipient's
  (subagent_compaction). Such calls get no output either.
PreToolUse: the launch gate. In observe mode it only logs WOULD-DENY lines (state/gate.log) and denies nothing.
Never blocks: it reads stdin for at most 0.15 s and ends within 0.8 s.
Test overrides: MM_DATA, MM_PROFILE, MM_RECIPIENT_FILE, MM_NOW.
"""
import fcntl
import json
import math
import os
import re
import select
import signal
import sys
import time

import mmcore  # noqa: E402
import mmread  # noqa: E402

EVENTS = ("SessionStart", "UserPromptSubmit", "PostToolUse", "PreToolUse")
LIMIT = 1 << 20


def read_input():
    deadline = time.monotonic() + 0.15
    data = bytearray()
    while len(data) <= LIMIT:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([sys.stdin], [], [], remaining)[0]:
            break
        chunk = os.read(sys.stdin.fileno(), 65536)
        if not chunk:
            break
        data.extend(chunk)
    d = json.loads(bytes(data) or b"{}")
    return d if isinstance(d, dict) else {}


def log_keys(data, event, match, s):
    """Record the hook input's KEYS (never values): proves the subagent field on this Claude Code version."""
    if not s or not s.get("hook.log_input_keys"):
        return
    try:
        rec = {"time": mmcore.now_local(), "event": event, "keys": sorted(data.keys()),
               "has_agent_id": "agent_id" in data, "agent_type": data.get("agent_type") if isinstance(data.get("agent_type"), str) else None,
               "session_is_recipient": match}
        mmcore.append_line(mmcore.path("state", "hook-inputs.log"), json.dumps(rec), max_bytes=1 << 20)
    except OSError:
        pass


def cursor_file(session):
    safe = re.sub(r"[^0-9a-zA-Z-]", "_", session or "unknown")[:80]
    return mmcore.path("state", "cursor-%s.json" % safe)


def take_unseen(session, min_level, now):
    """Unseen pushed alerts for this session; advances the cursor. First use: the active alerts, then the cursor."""
    cf = cursor_file(session)
    os.makedirs(os.path.dirname(cf), exist_ok=True)
    with open(cf, "a+") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return []  # the waiter or another hook call holds it; the next call shows them
        f.seek(0)
        try:
            cur = json.loads(f.read() or "null")
        except ValueError:
            cur = None
        st = mmcore.read_json(mmcore.path("alerts-state.json"), {}) or {}
        out = []
        if not isinstance(cur, dict):
            for a in sorted((st.get("active") or {}).values(), key=lambda a: -mmcore.LEVELS.get(a.get("level"), 0)):
                if mmcore.LEVELS.get(a.get("level"), 0) >= min_level:
                    out.append({"level": a["level"], "name": a.get("name"), "text": a.get("text"), "command": a.get("command"),
                                "key": a.get("key"), "why": "active"})
            seq = st.get("seq", 0)
        else:
            recs = mmcore.read_pushed(cur.get("seq", 0))
            seq = max([cur.get("seq", 0)] + [r["seq"] for r in recs])
            for r in recs:
                if mmcore.LEVELS.get(r.get("level"), 0) >= min_level or (r.get("why") == "cleared" and min_level <= 2):
                    out.append(r)
        f.seek(0)
        f.truncate()
        f.write(json.dumps({"seq": seq, "at": now}))
    return out


def status_age(now):
    """Seconds since the supervisor wrote status.json (None when missing)."""
    st = mmcore.read_json(mmcore.path("status.json"), None)
    try:
        return now - float(st["time"])
    except (TypeError, KeyError, ValueError):
        return None


def stale_line(s, now):
    if os.path.exists(mmcore.path("state", "stopped.json")):
        return None  # stopped on purpose: the stop alert said so
    limit = s["other.heartbeat_max_age_s"] if s else 90
    age = status_age(now)
    if age is None or age > limit:
        return mmcore.alert_line({"level": "ACTION", "key": "SELF_STALE",
                                  "text": "machine-manager status is %s: alerts may be missing; the launch gate is open."
                                  % ("missing" if age is None else "%.0f s old" % age), "command": "mm status"})
    return None


def waiter_live(session):
    try:
        with open(mmcore.path("state", "waiter-%s.pid" % re.sub(r"[^0-9a-zA-Z-]", "_", session))) as f:
            return mmread.pid_alive(int(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return False


def remind_due(session, s, now):
    f = mmcore.path("state", "remind-%s.json" % re.sub(r"[^0-9a-zA-Z-]", "_", session))
    last = (mmcore.read_json(f, {}) or {}).get("at", 0)
    if now - last >= (s["hook.remind_waiter_minutes"] if s else 60) * 60:
        try:
            mmcore.write_atomic(f, json.dumps({"at": now}))
        except OSError:
            pass
        return True
    return False


MAX_LINES = 3


def format_alerts(recs, max_lines=MAX_LINES):
    """At most max_lines alert lines (repeats collapsed, highest level first), then `+N more: mm alerts`.
    An alert with evidence says so in its command: `mm explain KEY` names the evidence folder and the investigator."""
    recs = mmcore.collapse(recs)
    lines = []
    for r in recs[:max_lines]:
        if r.get("investigate") and r.get("why") != "cleared" and not r.get("command"):
            r = dict(r, command="mm explain %s" % r.get("key"))
        lines.append(mmcore.alert_line(r))
    if len(recs) > max_lines:
        lines.append("+%d more: mm alerts" % (len(recs) - max_lines))
    return lines


def gate_decision(data, s, now, cfg):
    """The launch gate: deny an agent launch while the machine is RED, for at most launch_gate.max_minutes.
    Fail-open: no settings, the off switch, safe mode, a stale or missing status.json, or any doubt -> no denial."""
    if not s or not s.get("launch_gate.enabled") or mmcore.off_state() or mmcore.safe_state():
        return None
    cur = mmcore.read_json(mmcore.path("status.json"), None)
    if not isinstance(cur, dict) or cur.get("state") != "RED" or not cur.get("red_since"):
        return None
    if now - float(cur.get("time", 0)) > 60 or now - float(cur["red_since"]) > s["launch_gate.max_minutes"] * 60:
        return None
    tool = data.get("tool_name")
    cmd = ((data.get("tool_input") or {}).get("command") or "") if isinstance(data.get("tool_input"), dict) else ""
    if tool in cfg.get("launch_tools", []) or (tool == "Bash" and re.search(cfg.get("launch_bash_regex", "(?!)"), cmd)):
        return ("E_GATE_RED machine RED (%s); fix: wait until it is not RED (at most %g min from %s), then retry; mm status"
                % ("; ".join(cur.get("reasons", []))[:120], s["launch_gate.max_minutes"], mmcore.now_local(cur["red_since"])[11:]))
    return None


def recipient(cfg):
    """The recipient's session id from its file (profile recipient_file + recipient_regex), or None."""
    f = os.environ.get("MM_RECIPIENT_FILE") or cfg.get("recipient_file")
    try:
        with open(mmcore.expand(f)) as fh:
            head = fh.read(4096)
    except (OSError, TypeError):
        return None
    m = re.search(cfg.get("recipient_regex", "(?!)"), head)
    return m.group(1) if m else None


def model_name(value):
    """'claude-opus-5-5[1m]' and 'claude-opus-5-5-20261001' both name claude-opus-5-5."""
    return re.sub(r"-\d{8}$", "", re.sub(r"\[.*\]$", "", str(value or "").strip().lower()))


def recipient_models(transcript, s):
    """The models of the newest reply records in the session's own transcript (a subagent's replies are in their own
    files). Empty when none is found in the scanned tail."""
    replies = int(s["hook.subagent_model_replies"]) if s else 20
    scan = int((s["hook.subagent_model_scan_mb"] if s else 16) * (1 << 20))
    found, seen = set(), 0
    try:
        with open(transcript, "rb") as fh:
            fh.seek(0, 2)
            pos, carry, read = fh.tell(), b"", 0
            while pos > 0 and read < scan and seen < replies:
                size = min(1 << 20, pos)
                pos -= size
                read += size
                fh.seek(pos)
                lines = (fh.read(size) + carry).split(b"\n")
                carry = lines.pop(0) if pos > 0 else b""
                for line in reversed(lines):
                    if b'"assistant"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    msg = rec.get("message") if isinstance(rec, dict) else None
                    model = msg.get("model") if rec.get("type") == "assistant" and isinstance(msg, dict) else None
                    if isinstance(model, str) and model and model != "<synthetic>":
                        found.add(model_name(model))
                        seen += 1
                        if seen >= replies:
                            break
    except (OSError, TypeError, ValueError):
        return set()
    return found


def subagent_compaction(data, event, s):
    """A subagent's compaction (Claude Code 2.1.299, probes 2026-10-15): SessionStart with source "compact", no
    agent_id, the parent's session_id and transcript_path, and the subagent's own model. Without this check it took
    the recipient's unseen alerts. A compaction whose model is not among the recipient's own reply models is a
    subagent's; with no known recipient model, or no model in the input, it is not (show rather than guess). A
    subagent of the recipient's own model cannot be told apart."""
    if event != "SessionStart" or data.get("source") != "compact":
        return False
    model = model_name(data.get("model"))
    path = data.get("transcript_path")
    if not model or not isinstance(path, str) or not path:
        return False
    own = recipient_models(path, s)
    return bool(own) and model not in own


def main():
    signal.signal(signal.SIGALRM, lambda *_: os._exit(0))
    signal.setitimer(signal.ITIMER_REAL, 0.8)
    event = sys.argv[2] if len(sys.argv) == 3 and sys.argv[1] == "--event" and sys.argv[2] in EVENTS else "PostToolUse"
    try:
        data = read_input()
    except (ValueError, OSError):
        data = {}
    if data.get("hook_event_name") in EVENTS:
        event = data["hook_event_name"]
    now = float(os.environ.get("MM_NOW", time.time()))
    try:
        prof = mmcore.load_profile()
    except mmcore.MMError:
        return  # not installed: nothing to show, nothing to gate
    st = mmcore.Settings()
    s = st.load()
    cfg = prof.get("delivery", {})
    names = prof.get("names", {})
    r1 = recipient(cfg)
    session = data.get("session_id") if isinstance(data.get("session_id"), str) else None
    match = session is not None and session == r1
    log_keys(data, event, match, s)
    if data.get("agent_id") or subagent_compaction(data, event, s):
        return  # a subagent's call: never shown, never gated
    if r1 is not None and not match:
        return
    if event == "PreToolUse":
        reason = gate_decision(data, s, now, cfg)
        if reason and s.get("mode.observe"):
            try:
                mmcore.append_line(mmcore.path("state", "gate.log"), mmcore.mask(
                    "%s WOULD-DENY %s: %s" % (mmcore.now_local(now), data.get("tool_name"), reason[:200])), max_bytes=1 << 20)
            except OSError:
                pass
        elif reason:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                     "permissionDecisionReason": reason}}))
        return
    lines = []
    sl = stale_line(s, now)
    if sl:
        lines.append(sl)
    min_level = 2 if r1 is not None else 3
    lines = [l for l in lines if l]
    if session:
        recs = take_unseen(session, min_level, now)
        lines += format_alerts(recs)
        if r1 is None and recs:
            lines.insert(0, "E_RECIPIENT %s's session id is unreadable in %s; fix: correct the file; ACTION alerts go to "
                         "this session meanwhile" % (names.get("recipient", "the recipient"), cfg.get("recipient_file")))
        if recs and r1 is not None and not waiter_live(session) and remind_due(session, s, now):
            lines.append("INFO WAITER no idle waiter is live | do: mm wait (under Monitor)")
    if lines:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": "\n".join(lines)}}))


def hook_process():
    """The hook's whole life: never an error, never a block (exit 0 always)."""
    try:
        main()
    except BaseException:
        pass
    sys.exit(0)


# ------------------------------------------------------------------------------------------- session facts

def _usage_json(text):
    """Keep unconvertible JSON numbers local to their usage value."""
    def number(text):
        try:
            value = float(text) if any(c in text for c in ".eE") else int(text)
            if math.isfinite(value):
                return value
        except (ValueError, OverflowError):
            pass
        return math.nan

    return json.loads(text, parse_int=number, parse_float=number, parse_constant=number)


def read_usage(file, now, s=None):
    """Current usage levels in percent; unknown rows retain their stale-source reasons."""
    def number(v):
        try:
            return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
        except OverflowError:
            return False

    try:
        s = mmcore.defaults() if s is None else s
        with open(file) as f:
            d = _usage_json(f.read())
        lv = d.get("levels", {})
        checked = float(d.get("checked_at", 0))
        max_age = d.get("max_age_seconds", s["usage.watch_state_max_age_s"])
        if not isinstance(lv, dict) or not number(checked) or not number(max_age) or max_age < 0:
            return None
        out = {"age_s": now - checked, "max_age_s": max_age, "stale_levels": {}}
        for level, key in (("claude_5h", "claude_5h"), ("claude_weekly", "claude_week"),
                           ("codex_weekly", "codex_week"), ("codex_5h", "codex_5h")):
            out[key] = None
            row = lv.get(level)
            if not isinstance(row, dict):
                why = "row missing or invalid"
            elif row.get("status") == "not_offered":
                continue
            elif row.get("status") not in ("ok", "cached"):
                why = "status %s" % row.get("status", "missing")
            elif not number(row.get("used_percent")):
                why = "used_percent missing or invalid"
            elif not number(row.get("read_at")):
                why = "read_at missing or invalid"
            elif row["read_at"] - now > s["usage.read_clock_allowance_s"]:
                why = "read_at %.0f s in future" % (row["read_at"] - now)
            elif now - row["read_at"] > max_age:
                why = "reading %.0f s old" % (now - row["read_at"])
            elif type(row.get("reset_at")) in (int, float) and not number(row["reset_at"]):
                why = "reset_at invalid"
            elif number(row.get("reset_at")) and row["reset_at"] <= now:
                why = "window reset"
            else:
                out[key] = row["used_percent"]
                continue
            out["stale_levels"][level] = why
        proj = d.get("claude_weekly_projection")
        out["proj"] = proj if out["claude_week"] is not None and number(proj) else None
        return out
    except (OSError, ValueError, TypeError, AttributeError, OverflowError):
        return None



def jobs(cfg, base=None):
    """(pid, rc_path) pairs from 'pid=N ... rc=PATH' tokens in the recipient's job file, above its end marker."""
    out = []
    f = os.environ.get("MM_JOBS_FILE") or cfg.get("jobs_file")
    try:
        with open(mmcore.expand(f)) as fh:
            text = fh.read(64 << 10)
    except (OSError, TypeError):
        return out
    marker = cfg.get("jobs_end_marker")
    cut = text.find(marker) if marker else -1
    if cut >= 0:
        text = text[:cut]
    for line in text.splitlines():
        m = re.search(r"\bpid=(\d+)", line)
        r = re.search(r"\brc=([^\s,;)`]+)", line)
        if m and r and r.group(1) not in ("0", "1", "2"):
            p = r.group(1)
            out.append((int(m.group(1)), p if os.path.isabs(p) or not base else os.path.join(base, p)))
    return out


def oldest_open_tool_call(transcript, ignore=("Agent", "Task", "Workflow", "Monitor", "AskUserQuestion"), nbytes=512 << 10,
                          now=None):
    """(tool name, age seconds) of the oldest tool call without a result in the tail of a session transcript, or None."""
    try:
        with open(transcript, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - nbytes))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    calls, done = {}, set()
    for line in lines[1:] if len(lines) > 1 else lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict) or d.get("isSidechain"):
            continue
        msg = d.get("message") or {}
        content = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(content, list):
            continue
        for c in content:
            if not isinstance(c, dict):
                continue
            if c.get("type") == "tool_use" and c.get("name") not in ignore:
                calls[c.get("id")] = (c.get("name"), d.get("timestamp"))
            elif c.get("type") == "tool_result":
                done.add(c.get("tool_use_id"))
    open_ = [(n, ts) for i, (n, ts) in calls.items() if i not in done and ts]
    if not open_:
        return None
    name, ts = min(open_, key=lambda x: x[1])
    try:
        t = _utc_epoch(ts)
    except ValueError:
        return None
    return name, (time.time() if now is None else now) - t


def _utc_epoch(ts):
    import calendar
    return calendar.timegm(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))


def cache_5m(project_dir, now, window=3600):
    """Tokens written to the 5-min and 1-h prompt caches by subagents in the last hour (each message id once)."""
    m5 = h1 = 0
    seen = set()
    try:
        sessions = os.listdir(project_dir)
    except OSError:
        return None
    for sess in sessions:
        sub = os.path.join(project_dir, sess, "subagents")
        try:
            files = os.listdir(sub)
        except OSError:
            continue
        for fn in files:
            fp = os.path.join(sub, fn)
            try:
                if not fn.endswith(".jsonl") or now - os.path.getmtime(fp) > window:
                    continue
                with open(fp, "rb") as f:
                    for raw in f:
                        if b"ephemeral_5m" not in raw:
                            continue
                        try:
                            d = _usage_json(raw)
                            t = _utc_epoch(d.get("timestamp", ""))
                        except (ValueError, TypeError):
                            continue
                        msg = d.get("message") or {}
                        mid = msg.get("id")
                        if now - t > window or mid in seen:
                            continue
                        seen.add(mid)
                        cc = (msg.get("usage") or {}).get("cache_creation") or {}
                        m = cc.get("ephemeral_5m_input_tokens")
                        h = cc.get("ephemeral_1h_input_tokens")
                        if type(m) in (int, float) and math.isfinite(m):
                            m5 += m
                        if type(h) in (int, float) and math.isfinite(h):
                            h1 += h
            except OSError:
                continue
    return {"m5": m5, "h1": h1}




def banner(text, enabled):
    """A macOS notification for an ACTION alert (settings banner.enabled). MM_BANNER_CMD replaces osascript in tests."""
    if not enabled:
        return False
    cmd = os.environ.get("MM_BANNER_CMD")
    safe = mmcore.mask(text).replace("\\", " ").replace('"', "'")[:200]
    argv = [cmd, safe] if cmd else ["/usr/bin/osascript", "-e", 'display notification "%s" with title "machine-manager"' % safe]
    rc, _ = mmread.run(argv, timeout=10)
    return rc == 0


class Delivery:
    """The adapter object the supervisor uses."""

    def __init__(self, cfg):
        self.cfg = cfg

    def recipient(self):
        return recipient(self.cfg)

    def usage(self, now, s=None):
        f = self.cfg.get("usage_state")
        return read_usage(mmcore.expand(f), now, s) if f else None

    def usage_file(self):
        f = self.cfg.get("usage_state")
        return mmcore.expand(f) if f else None

    def open_tool_call(self, now):
        sid = self.recipient()
        d = self.cfg.get("transcripts_dir")
        if not sid or not d:
            return None
        return oldest_open_tool_call(os.path.join(mmcore.expand(d), sid + ".jsonl"),
                                     ignore=tuple(self.cfg.get("ignore_wait_tools", ("Agent", "Task", "Workflow", "Monitor",
                                                                                     "AskUserQuestion"))), now=now)

    def jobs(self):
        return jobs(self.cfg, mmcore.expand(self.cfg.get("jobs_base")) if self.cfg.get("jobs_base") else None)

    def cache_5m(self, now):
        d = self.cfg.get("transcripts_dir")
        return cache_5m(mmcore.expand(d), now) if d else None

    def banner(self, text, enabled):
        return banner(text, enabled)
