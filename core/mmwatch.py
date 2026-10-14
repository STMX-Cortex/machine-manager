# SPDX-License-Identifier: Apache-2.0
"""machine-manager watchdog: one shot, every 60 s from launchd (`mm watchdog`).

It checks the supervisor's status.json age, the memory guard's heartbeat and the queue sampler's age. A stale
supervisor gives an ACTION alert SELF_STALE and a restart of the supervisor's LaunchAgent (launchctl kickstart -k;
MM_LAUNCHCTL replaces launchctl in tests). After `mm stop` (state/stopped.json) it restarts nothing and stays quiet.
It writes no slots file and stops no process. When the supervisor is stale over self.resume_paused_after_s (or
stopped), it continues every process the pause stopped (mmrecover.resume_paused). Each run writes state/watchdog.stamp.
"""
import os

import mmadapters
import mmcore
import mmread
import mmrecover


def label(profile, part=""):
    """The LaunchAgent label: the profile's service.label_prefix (default com.example.machine-manager) + part."""
    return (profile["service"].get("label_prefix") or mmcore.DEFAULT_LABEL_PREFIX) + part


def check(now, s, profile, restart=True):
    """Return the list of problems found; raise and clear the watchdog's own alert keys."""
    problems = []
    mmrecover.stamp_watchdog(now)  # the supervisor watches this stamp (WATCHDOG_STALE)
    store = mmcore.AlertStore(s, clock=lambda: now, mid=mmcore.machine_id(profile))
    store.begin()
    stopped = os.path.exists(mmcore.path("state", "stopped.json"))
    st = mmcore.read_json(mmcore.path("status.json"), None)
    try:
        age = now - float(st["time"])
    except (TypeError, KeyError, ValueError):
        age = None
    limit = s["other.heartbeat_max_age_s"]
    # a supervisor that died or hangs while it held a pause: continue every paused process (pid and start time checked)
    if (age is None or age > s["self.resume_paused_after_s"] or stopped) and mmrecover.read_paused():
        got = mmrecover.resume_paused("watchdog: supervisor %s" % ("stopped" if stopped else "stale"), now)
        mmcore.append_line(mmcore.path("state", "watchdog.log"), "%s resumed paused pids %s" % (mmcore.now_local(now), got))
    ref = mmrecover.start_ref(now)
    in_grace = ref is not None and now - ref < s["self.start_grace_s"]
    if not stopped and (age is None or age > limit) and in_grace:
        mmcore.append_line(mmcore.path("state", "watchdog.log"), "%s supervisor starting (%.0f s ago, grace %g s): no "
                           "restart" % (mmcore.now_local(now), now - ref, s["self.start_grace_s"]))
    if not stopped and (age is None or age > limit) and not in_grace:
        why = "no status.json" if age is None else "status.json %.0f s old (limit %g s)" % (age, limit)
        restarted = ""
        if restart:
            argv = [os.environ.get("MM_LAUNCHCTL", "/bin/launchctl"), "kickstart", "-k",
                    "gui/%d/%s" % (os.getuid(), label(profile))]
            rc, _ = mmread.run(argv, timeout=20)
            restarted = "; kickstart rc=%s" % rc
            mmcore.append_line(mmcore.path("state", "watchdog.log"), "%s %s%s" % (mmcore.now_local(now), why, restarted))
        store.raise_("SELF_STALE", "SELF_STALE", "ACTION", "supervisor stale: %s%s; the launch gate is open" % (why, restarted),
                     command="mm status")
        problems.append(why)
    mg = profile.get("memory_guard") or {}
    if mg.get("state_file"):
        sw = mmcore.read_json(mmcore.expand(mg["state_file"]), None)
        sw_age = now - float(sw.get(mg.get("heartbeat_key", "heartbeat_epoch"), 0)) if isinstance(sw, dict) else None
        if sw_age is None or sw_age > mg.get("max_age_s", 60):
            why = "memory guard heartbeat " + ("missing" if sw_age is None else "%.0f s old" % sw_age)
            store.raise_("WD:memory-guard", "GUARD_DOWN", "ACTION", why + ": the memory guard may be down")
            problems.append(why)
    q = mmadapters.queue(profile)
    if q is not None:
        try:
            la = now - os.path.getmtime(q.sample_log())
        except OSError:
            la = None
        if la is None or la > s["other.load_log_max_age_s"]:
            why = "queue sampler " + ("missing" if la is None else "%.0f s old" % la)
            store.raise_("WD:queue-sampler", "SOURCE_STALE", "ATTENTION", why + ": the load sampler may be down")
            problems.append(why)
    store.finish(scope_prefixes=("SELF_STALE", "WD:"))
    return problems
