# SPDX-License-Identifier: Apache-2.0
"""machine-manager setup: init, check, install, stop, start, rollback.

install writes two LaunchAgents (the supervisor, KeepAlive; the watchdog, every 60 s), adds the hook entries to the
Claude Code settings file the profile names (delivery.settings_file), and records everything in base_dir()/install.json.
Before it changes a file it keeps a copy `<file>.bak-before-machine-manager-<time>`. Rollback undoes all of it.
MM_LAUNCHCTL replaces launchctl and HOME moves ~/Library/LaunchAgents (tests use both; they never touch the real ones).
"""
import json
import os
import plistlib
import re
import shutil
import sys
import time

import mmcore
import mmread

HOOK_EVENTS = (("SessionStart", "*"), ("UserPromptSubmit", "*"), ("PostToolUse", "*"),
               ("PreToolUse", "Agent|Task|Workflow|Bash"))
MINIMAL_PROFILE = '''# machine-manager profile. Only `name` is required; every other value has a documented default
# (README.md, "Profile"). The tool reads this file and never writes it.

name = "{name}"

# [names]                      # words used in alert texts
# owner = "the owner"
# recipient = "the recipient"

# [service]
# label_prefix = "com.example.machine-manager"   # LaunchAgent labels: <prefix> and <prefix>-watchdog

# [queue]                      # a slot queue to watch and control (adapter "fifo-gates")
# adapter = "fifo-gates"
# dir = "/path/to/queue"
# launcher = "run-queued.py"

# [delivery]                   # warnings into one Claude Code session (adapter "claude-code-hook")
# adapter = "claude-code-hook"
# recipient_file = "/path/to/state.md"
# recipient_regex = "Session: ([0-9a-f-]{{36}})"
# settings_file = "/path/to/.claude/settings.local.json"
'''
SETTINGS_HEAD = '''# machine-manager settings overrides for this data folder: only the keys you change.
# Defaults and units: settings.default.toml in the code. `mm check` validates; the tool never writes this file.

# [mode]
# observe = true
'''


def stamp_time():
    return time.strftime("%Y%m%d-%H%M%S")


def launchctl(args):
    exe = os.environ.get("MM_LAUNCHCTL", "/bin/launchctl")
    return mmread.run([exe] + list(args), timeout=30)


def agents_dir():
    return os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents")


def labels(profile):
    p = profile["service"].get("label_prefix") or mmcore.DEFAULT_LABEL_PREFIX
    return p, p + "-watchdog"


MIN_PYTHON = (3, 11)  # tomllib
# A path inside a package manager's versioned folder (Homebrew's Cellar/<formula>/<version>/) goes away at an upgrade.
VERSIONED_DIR = re.compile(r"/Cellar/[^/]+/[0-9][^/]*/")


def interpreter_problems(executable, version):
    """The installed jobs and hooks run `executable` by its full path. E_PYTHON refuses an interpreter older than
    MIN_PYTHON; W_PYTHON warns when the path holds a versioned package folder (it breaks at an upgrade)."""
    out = []
    if tuple(version[:2]) < MIN_PYTHON:
        out.append("E_PYTHON python %d.%d at %s is older than %d.%d; fix: run mm with python3.11 or newer"
                   % (version[0], version[1], executable, MIN_PYTHON[0], MIN_PYTHON[1]))
    if VERSIONED_DIR.search(executable or ""):
        out.append("W_PYTHON %s goes away at an upgrade; fix: run mm with a stable python3 path, then mm install "
                   "again (README.md, Python upgrade)" % executable)
    return out


SYSTEM_PATH = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]


def external_commands(profile):
    """The commands the service runs by name or path from the profile: gh (CI adapter github-gh), ci.guard_argv,
    trim.warm_argv, and the deletes rules' argv and command."""
    names = []
    ci = profile.get("ci") or {}
    if ci.get("adapter") == "github-gh":
        names.append("gh")
    for argv in (ci.get("guard_argv"), (profile.get("trim") or {}).get("warm_argv")):
        if argv:
            names.append(argv[0])
    for r in (profile.get("deletes") or {}).get("rules", []):
        for k in ("argv", "command"):
            if r.get(k):
                names.append(r[k][0])
    return sorted(set(n for n in names if n and "{" not in n))


def resolve_commands(names, search_path):
    """{name: absolute path or None}. MM_GH replaces gh (tests)."""
    out = {}
    for n in names:
        if n == "gh" and os.environ.get("MM_GH"):
            out[n] = os.environ["MM_GH"]
        elif os.path.isabs(n):
            out[n] = n if os.access(n, os.X_OK) else None
        else:
            out[n] = shutil.which(n, path=search_path)
    return out


def service_path(profile, search_path=None):
    """The PATH of the LaunchAgents: the profile's service.path_extra, the folder of each external command as the
    owner's PATH finds it now, then the system folders. Returns (path, {command: absolute path or None})."""
    found = resolve_commands(external_commands(profile), os.environ.get("PATH", "") if search_path is None else search_path)
    dirs = []
    for d in [mmcore.expand(x) for x in profile["service"].get("path_extra", [])] + \
            [os.path.dirname(p) for _, p in sorted(found.items()) if p]:
        if d and d not in dirs and d not in SYSTEM_PATH:
            dirs.append(d)
    return ":".join(dirs + SYSTEM_PATH), found


def command_problems(profile, online=False):
    """E_COMMAND / E_GH lines: each external command must resolve on the service PATH and on the installed plist's
    PATH; gh must run there (--version), and with online=True read GitHub once (gh api rate_limit, read-only)."""
    out = []
    path_, found = service_path(profile)
    env = {"PATH": path_, "HOME": os.path.expanduser("~")}
    for n, p in sorted(found.items()):
        if not p:
            out.append("E_COMMAND %s not found on PATH; fix: install it, or add its folder to service.path_extra" % n)
    gh = found.get("gh")
    if gh:
        rc, _ = mmread.run([gh, "--version"], timeout=20, env=env)
        if rc != 0:
            out.append("E_COMMAND gh does not run in the service environment (rc=%s); fix: reinstall gh" % rc)
        elif online:
            rc, o = mmread.run([gh, "api", "rate_limit", "--jq", ".rate.limit"], timeout=30, env=env)
            if rc != 0 or not o.strip():
                out.append("E_GH gh cannot read GitHub in the service environment (rc=%s); fix: gh auth login" % rc)
    sup = os.path.join(agents_dir(), labels(profile)[0] + ".plist")
    if os.path.exists(sup):
        try:
            with open(sup, "rb") as f:
                ppath = (plistlib.load(f).get("EnvironmentVariables") or {}).get("PATH", "")
        except (OSError, ValueError):
            ppath = ""
        for n, p in sorted(found.items()):
            by_name = not os.path.isabs(n) and not (n == "gh" and os.environ.get("MM_GH"))  # MM_GH: tests only
            got = shutil.which(n, path=ppath) if by_name else p
            if p and (not got or os.path.realpath(got) != os.path.realpath(p)):
                out.append("E_COMMAND %s on the installed service PATH is %s, not %s; fix: mm install again"
                           % (n, got or "missing", p))
    return out


def mm_argv(*args):
    return [sys.executable, "-I", os.path.join(mmcore.BIN, "mm")] + list(args)


def plist(label, args, env, keepalive):
    d = {"Label": label, "ProgramArguments": mm_argv(*args), "EnvironmentVariables": env, "RunAtLoad": True,
         "ProcessType": "Interactive", "StandardOutPath": os.path.join(env["MM_DATA"], "state", label + ".out"),
         "StandardErrorPath": os.path.join(env["MM_DATA"], "state", label + ".out")}
    if keepalive:
        d.update(KeepAlive=True, ThrottleInterval=10)
    else:
        d["StartInterval"] = 60
    return plistlib.dumps(d)


def backup(f):
    """A copy beside f that never overwrites an earlier copy (two in the same second get -2, -3, ...)."""
    if not os.path.exists(f):
        return None
    base = "%s.bak-before-machine-manager-%s" % (f, stamp_time())
    b, n = base, 1
    while os.path.lexists(b):
        n += 1
        b = "%s-%d" % (base, n)
    shutil.copy2(f, b)
    return b


def _same_settings(a, b):
    """Equal JSON, where an empty "hooks" object counts as no "hooks" key."""
    def norm(d):
        return {k: v for k, v in d.items() if not (k == "hooks" and not v)} if isinstance(d, dict) else d
    return norm(a) == norm(b)


def hook_command(event, env):
    return "MM_PROFILE=%s MM_DATA=%s %s hook --event %s" % (
        _q(env["MM_PROFILE"]), _q(env["MM_DATA"]), " ".join(_q(x) for x in mm_argv()), event)


def _q(s):
    import shlex
    return shlex.quote(s)


def is_ours(cmd):
    return isinstance(cmd, str) and os.path.join(mmcore.BIN, "mm") in cmd and " hook --event " in cmd


def add_hooks(doc, env):
    """Our entries added beside the existing ones; idempotent (an entry of ours is replaced, never doubled)."""
    remove_hooks(doc)
    hooks = doc.setdefault("hooks", {})
    for event, matcher in HOOK_EVENTS:
        hooks.setdefault(event, []).append({"matcher": matcher, "hooks": [
            {"type": "command", "command": hook_command(event, env), "timeout": 2}]})
    return doc


def remove_hooks(doc):
    hooks = doc.get("hooks") or {}
    for event in list(hooks):
        kept = []
        for group in hooks[event]:
            hs = [h for h in group.get("hooks", []) if not is_ours(h.get("command"))]
            if hs:
                kept.append(dict(group, hooks=hs))
            elif not group.get("hooks"):
                kept.append(group)
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event)
    if "hooks" in doc and not doc["hooks"]:
        doc.pop("hooks")
    return doc


def init(name, folder=None):
    """A minimal profile <folder or ./>/<name>.toml and an empty settings file in its data folder. Never overwrites."""
    if not name or not all(c.isalnum() or c in "-_" for c in name):
        raise mmcore.MMError("E_USAGE", "bad profile name %r" % name, "use letters, digits, - and _")
    f = os.path.abspath(os.path.join(folder or os.getcwd(), name + ".toml"))
    if os.path.exists(f):
        raise mmcore.MMError("E_EXISTS", "profile exists: %s" % f, "edit it, or choose another name")
    os.makedirs(os.path.dirname(f), exist_ok=True)
    with open(f, "w") as fh:
        fh.write(MINIMAL_PROFILE.format(name=name))
    os.environ["MM_PROFILE"] = f
    data = mmcore.data_dir()
    os.makedirs(os.path.join(data, "state"), exist_ok=True)
    sf = os.path.join(data, "settings.toml")
    if not os.path.exists(sf):
        with open(sf, "w") as fh:
            fh.write(SETTINGS_HEAD)
    return f, data


def check(profile_file=None, online=False):
    """One line per problem in the profile and the settings, plus the macOS readings check. [] = all fine."""
    import mmadapters
    import mmschema
    out = interpreter_problems(sys.executable, sys.version_info)
    try:
        prof = mmcore.load_profile(profile_file)
    except mmcore.MMError as e:
        return [str(e)]
    raw = mmcore.load_toml(prof["_file"])
    for p in mmschema.validate(raw, mmschema.load("profile")):
        out.append("E_PROFILE %s; fix: correct %s" % (p, prof["_file"]))
    for part, fn in (("queue", mmadapters.queue), ("ci", mmadapters.pool), ("delivery", mmadapters.delivery)):
        try:
            fn(prof)
        except mmcore.MMError as e:
            out.append(str(e))
        except (KeyError, TypeError) as e:
            out.append("E_PROFILE [%s] lacks %s; fix: add it (README.md, Profile)" % (part, e))
    out += command_problems(prof, online)
    q = prof.get("queue") or {}
    if q.get("dir") and not os.path.isdir(mmcore.expand(q["dir"])):
        out.append("E_PROFILE queue.dir not found: %s; fix: correct the path" % q["dir"])
    st = mmcore.Settings()
    if st.load() is None or st.problem:
        out.append("E_SETTINGS %s; fix: correct %s" % (st.problem, st.file))
    bad, _, _ = mmread.check_readings()
    for b in bad:
        out.append("E_READINGS %s; fix: the tool uses the command readings; report the macOS version" % b)
    return out


def install(profile, settings_src=None, observe_only=True):
    """Returns the install record (rec["warnings"]: W_ lines). Raises MMError on a refusal."""
    py = interpreter_problems(sys.executable, sys.version_info)
    bad = [x for x in py if x.startswith("E_")]
    if bad:
        raise mmcore.MMError("E_PYTHON", bad[0].split(" ", 1)[1].split("; fix: ")[0], "run mm with python3.11 or newer")
    data = mmcore.data_dir()
    os.makedirs(os.path.join(data, "state"), exist_ok=True)
    rec = {"time": mmcore.now_local(), "profile": profile["_file"], "data": data, "code": mmcore.CODE, "backups": [],
           "plists": [], "hooks_file": None, "python": sys.executable,
           "warnings": [x for x in py if x.startswith("W_")]}
    sf = os.path.join(data, "settings.toml")
    if settings_src:
        if os.path.exists(sf) and open(sf).read() != open(settings_src).read():
            raise mmcore.MMError("E_EXISTS", "%s differs from %s" % (sf, settings_src), "merge by hand or remove it, then retry")
        shutil.copy(settings_src, sf)
    elif not os.path.exists(sf):
        with open(sf, "w") as fh:
            fh.write(SETTINGS_HEAD)
    st = mmcore.Settings()
    s = st.load()
    if s is None or st.problem:
        raise mmcore.MMError("E_SETTINGS", "settings invalid: %s" % st.problem, "mm check")
    if observe_only and not s["mode.observe"]:
        raise mmcore.MMError("E_SETTINGS", "mode.observe is false", "install in observe mode first (mode.observe = true)")
    path_, found = service_path(profile)
    rec["commands"] = found
    rec["warnings"] += ["W_COMMAND %s not found on PATH; fix: install it, or add its folder to service.path_extra" % n
                        for n, p in sorted(found.items()) if not p]
    env = {"MM_PROFILE": profile["_file"], "MM_DATA": data, "PATH": path_}
    os.makedirs(agents_dir(), exist_ok=True)
    sup, wd = labels(profile)
    # The installed supervisor may write the queue's slot file; the settings decide whether it does
    # (mode.observe false and mode.slot_writes "live"). A run by hand without the flag never writes it.
    for label, args, keep in ((sup, ("run", "--allow-live-slots"), True), (wd, ("watchdog",), False)):
        f = os.path.join(agents_dir(), label + ".plist")
        b = backup(f)
        if b:
            rec["backups"].append([f, b])
        with open(f + ".new", "wb") as fh:
            fh.write(plist(label, args, env, keep))
        os.replace(f + ".new", f)
        rec["plists"].append(f)
    hf = mmcore.expand((profile.get("delivery") or {}).get("settings_file") or "")
    if hf:
        doc = mmcore.read_json(hf, None) if os.path.exists(hf) else {}
        if not isinstance(doc, dict):
            raise mmcore.MMError("E_HOOKS", "%s is not a JSON object" % hf, "correct the file, then retry")
        b = backup(hf)
        if b:
            rec["backups"].append([hf, b])
        mmcore.write_atomic(hf, json.dumps(add_hooks(doc, env), indent=2) + "\n")
        rec["hooks_file"] = hf
    try:
        os.remove(os.path.join(data, "state", "stopped.json"))
    except OSError:
        pass
    import mmrecover
    mmrecover.note_loaded(time.time())
    for f, label in zip(rec["plists"], (sup, wd)):
        launchctl(["bootout", "gui/%d/%s" % (os.getuid(), label)])
        rc, out = launchctl(["bootstrap", "gui/%d" % os.getuid(), f])
        rec.setdefault("bootstrap", []).append([label, rc])
    mmcore.write_atomic(os.path.join(mmcore.base_dir(), "install.json"), json.dumps(rec, indent=1))
    return rec


def stop(profile, reason="stopped by hand", alert=True):
    """Watchdog first (so it restarts nothing), then the supervisor; a stopped marker; one alert says so (not for a
    restart). Every process the pause stopped is continued (no supervisor is left to do it)."""
    import mmrecover
    sup, wd = labels(profile)
    os.makedirs(mmcore.path("state"), exist_ok=True)
    mmcore.write_atomic(mmcore.path("state", "stopped.json"), json.dumps({"time": time.time(), "reason": reason}))
    out = []
    for label in (wd, sup):
        rc, _ = launchctl(["bootout", "gui/%d/%s" % (os.getuid(), label)])
        out.append((label, rc))
    mmrecover.resume_paused("stop: " + reason)
    st = mmcore.Settings().load()
    if st and alert:
        a = mmcore.AlertStore(st, mid=mmcore.machine_id(profile))
        a.begin()
        a.raise_("STOPPED", "STOPPED", "ATTENTION", "machine-manager stopped: %s; nothing watches the machine" % reason,
                 command="mm start")
    return out


def start(profile):
    sup, wd = labels(profile)
    try:
        os.remove(mmcore.path("state", "stopped.json"))
    except OSError:
        pass
    import mmrecover
    os.makedirs(mmcore.path("state"), exist_ok=True)
    mmrecover.note_loaded(time.time())
    out = [(label, bootstrap(label)) for label in (sup, wd)]
    st = mmcore.Settings().load()
    if st:
        mmcore.AlertStore(st, mid=mmcore.machine_id(profile)).clear("STOPPED")
    return out


def bootstrap(label, tries=10, wait_s=1.0):
    """Load one LaunchAgent. A bootout ends a service in the background, and a bootstrap right after it fails
    (seen 2026-10-14: `mm restart` left nothing running), so a failed bootstrap is retried; at the end a service that
    is loaded counts as done. Returns the last rc (0 = loaded)."""
    f = os.path.join(agents_dir(), label + ".plist")
    rc = None
    for i in range(tries):
        rc, _ = launchctl(["bootstrap", "gui/%d" % os.getuid(), f])
        if rc == 0:
            return 0
        time.sleep(wait_s)
    prc, _ = launchctl(["print", "gui/%d/%s" % (os.getuid(), label)])
    return 0 if prc == 0 else rc


def rollback(profile):
    """Unload and remove our LaunchAgents, remove our hook entries (a backup first), forget the install record.
    The data folder stays (its alerts and logs are the record). Returns lines for the caller to print."""
    import mmrecover
    lines = []
    sup, wd = labels(profile)
    for label in (wd, sup):
        rc, _ = launchctl(["bootout", "gui/%d/%s" % (os.getuid(), label)])
        f = os.path.join(agents_dir(), label + ".plist")
        if os.path.exists(f):
            b = backup(f)
            os.remove(f)
            lines.append("removed=%s backup=%s bootout_rc=%s" % (f, b, rc))
    resumed = mmrecover.resume_paused("rollback")
    if resumed:
        lines.append("resumed=%s" % ",".join(str(p) for p in resumed))
    hf = mmcore.expand((profile.get("delivery") or {}).get("settings_file") or "")
    rec = os.path.join(mmcore.base_dir(), "install.json")
    if hf and os.path.exists(hf):
        doc = mmcore.read_json(hf, None)
        if isinstance(doc, dict):
            b = backup(hf)
            clean = remove_hooks(doc)
            first = [x[1] for x in ((mmcore.read_json(rec, {}) or {}).get("backups") or []) if x[0] == hf]
            if first and _same_settings(mmcore.read_json(first[0], None), clean):
                shutil.copy2(first[0], hf)  # nothing else changed since install: its exact bytes come back
                lines.append("hooks_removed=%s backup=%s restored=%s" % (hf, b, first[0]))
            else:
                mmcore.write_atomic(hf, json.dumps(clean, indent=2) + "\n")
                lines.append("hooks_removed=%s backup=%s" % (hf, b))
    if os.path.exists(rec):
        os.replace(rec, rec + ".rolled-back-" + stamp_time())
    for note in profile["service"].get("rollback_notes", []):
        lines.append("restart_by_hand=%s" % note)
    return lines
