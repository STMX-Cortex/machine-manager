#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write the vectors (vectors/<function>/<case>.json) from hand-made inputs and the incident fixtures.

The expected values come from this Python core unless a case supplies a hand-written contract expectation;
tests/test_vectors.py pins the meaning of the
important ones by hand (for example: the 09:13 replay is RED at 09:11 with slots at the floor). Rerun this script only
when a behaviour change is intended, and review the diff of vectors/ before keeping it.
"""
import argparse
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import mmtest  # noqa: E402
from vector_functions import FUNCTIONS  # noqa: E402
import ad_ci_github  # noqa: E402
import mmcore  # noqa: E402
import mmdecide  # noqa: E402

VEC = os.path.join(mmtest.CODE, "vectors")
BASE = mmtest.base_settings()
NOW = 1_800_000_000.0


def sample(t, **kw):
    d = {"t": t, "free_pct": 80.0, "swap_used_mb": 500.0, "swap_total_mb": 2048.0, "comp_mb": 300.0, "pressure": 1,
         "seg_pct": 5.0, "load1": 2.0, "load5": 2.0, "sys_pct": 10.0}
    d.update(kw)
    return d


def series(n, **kw):
    return [sample(NOW - (n - 1 - k) * 60, **{a: (b[k] if isinstance(b, list) else b) for a, b in kw.items()}) for k in range(n)]


CASES = {}
EXPECTED = {}


def case(fn, name, inp, over=None, expected=None):
    CASES.setdefault(fn, []).append((name, inp, over or {}))
    if expected is not None:
        EXPECTED[fn, name] = expected


# ---- classify
case("classify", "empty", {"window": []})
case("classify", "green", {"window": series(3), "disk_gb": 100.0})
LINUX_GREEN = dict(sample(NOW), linux=1, psi_supported=1, comp_mb=None, seg_pct=None,
                   psi_some_pct=0, psi_full_pct=0)
case("classify", "linux-green-no-compressor", {"window": [LINUX_GREEN], "disk_gb": 100},
     expected=["GREEN", ["all readings in the green band"], True])
case("classify", "linux-psi-warn", {"window": [dict(LINUX_GREEN, psi_some_pct=12)], "disk_gb": 100},
     expected=["AMBER", ["kernel pressure 2 (warn)"], True])
case("classify", "linux-psi-critical", {"window": [dict(LINUX_GREEN, psi_full_pct=12)], "disk_gb": 100},
     expected=["RED", ["kernel pressure 4 (critical)"], True])
case("classify", "linux-psi-unreadable", {"window": [dict(LINUX_GREEN, psi_full_pct=None)], "disk_gb": 100},
     expected=["STEADY", ["readings incomplete"], False])
case("classify", "linux-without-psi", {"window": [dict(LINUX_GREEN, psi_supported=0, psi_some_pct=None, psi_full_pct=None)],
                                       "disk_gb": 100}, expected=["GREEN", ["all readings in the green band"], True])
case("classify", "steady-free-below-green", {"window": series(3, free_pct=52.0), "disk_gb": 100.0})
case("classify", "amber-free", {"window": series(3, free_pct=45.0), "disk_gb": 100.0})
case("classify", "amber-compressor", {"window": series(3, comp_mb=6000.0), "disk_gb": 100.0})
case("classify", "red-pressure-critical", {"window": series(2, pressure=4), "disk_gb": 100.0})
case("classify", "red-free", {"window": series(2, free_pct=30.0)})
case("classify", "red-swap-growth", {"window": series(2, swap_used_mb=[500.0, 1100.0])})
case("classify", "red-compressor-growth", {"window": series(2, comp_mb=[300.0, 2400.0])})
case("classify", "sys-one-sample-is-not-sustained", {"window": series(2, sys_pct=[10.0, 50.0])})
case("classify", "red-sys-sustained", {"window": series(2, sys_pct=[45.0, 48.0], pressure=[1, 2])})
case("classify", "red-load1-sustained", {"window": series(2, load1=[25.0, 30.0])})
case("classify", "red-kernel-event", {"window": series(1), "kernel_event": True})
case("classify", "red-disk", {"window": series(1), "disk_gb": 15.0})
case("classify", "steady-incomplete", {"window": [{"t": NOW, "free_pct": 80.0}], "disk_gb": 100.0})
case("classify", "amber-swap-30min", {"window": series(31, swap_used_mb=[500.0 + 4 * k for k in range(31)])})
case("classify", "steady-disk-under-recover", {"window": series(3), "disk_gb": 44.0})
case("classify", "pressure-warn-amber", {"window": series(2, pressure=2), "disk_gb": 100.0})

# R-1: expectations are independent of the implementation so these vectors fail before the rule lands.
SYS_RED = "system CPU > 40% in 2 samples"
SYS_AMBER = [SYS_RED + ", no memory sign", "system CPU > 30% in 2 samples"]


def sys_memory_case(name, state, reasons, over=None, **columns):
    settings = {"slots.red_sys_needs_memory_sign": True, "slots.red_sys_comp_growth_mb_60s": 256}
    settings.update(over or {})
    columns.setdefault("sys_pct", [45.0, 48.0])
    case("classify", name, {"window": series(2, **columns)}, settings, expected=[state, reasons, True])


sys_memory_case("amber-sys-no-memory-sign", "AMBER", SYS_AMBER)
sys_memory_case("red-sys-pressure-warn", "RED", [SYS_RED], pressure=[1, 2])
sys_memory_case("amber-sys-past-pressure-warn", "AMBER", SYS_AMBER, pressure=[2, 1])
sys_memory_case("red-sys-swap-small-growth", "RED", [SYS_RED], swap_used_mb=[500.0, 500.01])
sys_memory_case("amber-sys-swap-flat", "AMBER", SYS_AMBER, swap_used_mb=[500.0, 500.0])
sys_memory_case("amber-sys-swap-falling", "AMBER", SYS_AMBER, swap_used_mb=[501.0, 500.0])
sys_memory_case("amber-sys-comp-under-sign-limit", "AMBER", SYS_AMBER, comp_mb=[300.0, 555.99])
sys_memory_case("amber-sys-comp-at-sign-limit", "AMBER", SYS_AMBER, comp_mb=[300.0, 556.0])
sys_memory_case("red-sys-comp-over-sign-limit", "RED", [SYS_RED], comp_mb=[300.0, 556.01])
sys_memory_case("amber-sys-comp-custom-limit", "AMBER", SYS_AMBER,
                over={"slots.red_sys_comp_growth_mb_60s": 700}, comp_mb=[300.0, 557.0])
sys_memory_case("red-sys-comp-custom-limit", "RED", [SYS_RED],
                over={"slots.red_sys_comp_growth_mb_60s": 64}, comp_mb=[300.0, 364.01])
sys_memory_case("red-sys-memory-sign-disabled", "RED", [SYS_RED],
                over={"slots.red_sys_needs_memory_sign": False})
sys_memory_case("sys-memory-sign-one-high-sample", "STEADY", ["system CPU not under 25%"], sys_pct=[10.0, 48.0])
sys_memory_case("red-free-with-sys-no-memory-sign", "RED", ["free 30% < 35%"], free_pct=30.0)

# slots.red_comp_mb (a compressor near its ceiling is a critical RED; default 0 = off) and slots.green_disk_gb
# (the free disk GREEN needs; 0 follows disk.recover_gb). Expectations by hand, from the settings' meaning.
case("classify", "red-compressor-over-ceiling", {"window": series(2, comp_mb=7000.0), "disk_gb": 100.0},
     {"slots.red_comp_mb": 6000}, expected=["RED", ["compressor at 7000 MB (near its ceiling)"], True])
case("classify", "compressor-at-ceiling-is-not-red", {"window": series(2, comp_mb=6000.0), "disk_gb": 100.0},
     {"slots.red_comp_mb": 6000}, expected=["AMBER", ["compressor 6000 MB"], True])
case("classify", "compressor-ceiling-default-off", {"window": series(2, comp_mb=250000.0), "disk_gb": 100.0},
     {"slots.red_comp_mb": 0}, expected=["AMBER", ["compressor 250000 MB"], True])
case("classify", "green-disk-own-value-green", {"window": series(3), "disk_gb": 44.0},
     {"slots.green_disk_gb": 30}, expected=["GREEN", ["all readings in the green band"], True])
case("classify", "steady-green-disk-own-value", {"window": series(3), "disk_gb": 29.9},
     {"slots.green_disk_gb": 30}, expected=["STEADY", ["disk under 30 GB"], True])
case("classify", "steady-green-disk-zero-follows-recover", {"window": series(3), "disk_gb": 44.0},
     {"slots.green_disk_gb": 0}, expected=["STEADY", ["disk under 45 GB"], True])

# ---- slot_decide
st0 = {"last_change": NOW - 3600, "green_since": NOW - 3600}
base_inp = {"now": NOW, "mac_state": "GREEN", "reasons": [], "slots": 5, "busy": 5, "waiting": 2, "wx_waiting": False}
case("slot_decide", "green-raise-one-step", {"state": st0, "inp": base_inp})
case("slot_decide", "green-no-demand", {"state": st0, "inp": dict(base_inp, waiting=0)})
case("slot_decide", "green-too-short", {"state": {"last_change": NOW - 3600, "green_since": NOW - 300}, "inp": base_inp})
case("slot_decide", "green-at-ceiling", {"state": st0, "inp": dict(base_inp, slots=10, busy=10)})
case("slot_decide", "green-wide-waiting", {"state": st0, "inp": dict(base_inp, wx_waiting=True)})
case("slot_decide", "green-held-after-red", {"state": dict(st0, last_red=NOW - 600), "inp": base_inp})
case("slot_decide", "green-held-after-trim", {"state": st0, "inp": dict(base_inp, events=["trim"])})
case("slot_decide", "red-to-floor", {"state": st0, "inp": dict(base_inp, mac_state="RED", reasons=["free 30% < 35%"])})
case("slot_decide", "red-at-floor", {"state": st0, "inp": dict(base_inp, mac_state="RED", slots=3)})
case("slot_decide", "amber-step-down", {"state": st0, "inp": dict(base_inp, mac_state="AMBER", reasons=["load5 15.0 > 14"])})
case("slot_decide", "amber-step-interval", {"state": dict(st0, last_down=NOW - 60), "inp": dict(base_inp, mac_state="AMBER")})
case("slot_decide", "event-timing-failure", {"state": st0, "inp": dict(base_inp, mac_state="STEADY", events=["timing-failure"])})
case("slot_decide", "pin-sets-value", {"state": st0, "inp": dict(base_inp, mac_state="STEADY",
                                                                 override={"slots": 7, "until": NOW + 600, "reason": "test"})})
case("slot_decide", "pin-expired", {"state": st0, "inp": dict(base_inp, mac_state="STEADY",
                                                              override={"slots": 7, "until": NOW - 1, "reason": "old"})})
case("slot_decide", "red-beats-pin", {"state": st0, "inp": dict(base_inp, mac_state="RED", override={"slots": 7, "until": NOW + 600,
                                                                                                    "reason": "x"})})

# ---- alert_raise / alert_absent
cond = {"key": "DISK_LOW", "name": "DISK_LOW", "level": "ACTION", "text": "disk 38 GB", "value": 38.0, "band": 10,
        "worse": "down", "command": None, "investigate": None}
ent = {"key": "DISK_LOW", "name": "DISK_LOW", "level": "ACTION", "first": NOW - 600, "count": 5, "last": NOW - 60,
       "pushed_at": NOW - 600, "pushed_value": 38.0, "pushed_level": "ACTION", "text": "disk 38 GB", "value": 38.0}
case("alert_raise", "new", {"entry": None, "acked": False, "cond": cond, "now": NOW})
case("alert_raise", "same-is-silent", {"entry": ent, "acked": False, "cond": cond, "now": NOW})
case("alert_raise", "worse-by-a-band", {"entry": ent, "acked": True, "cond": dict(cond, value=27.0), "now": NOW})
case("alert_raise", "inside-the-band", {"entry": ent, "acked": False, "cond": dict(cond, value=30.0), "now": NOW})
case("alert_raise", "repeat-after-30-min", {"entry": ent, "acked": False, "cond": cond, "now": NOW + 1800})
case("alert_raise", "acked-no-repeat", {"entry": ent, "acked": True, "cond": cond, "now": NOW + 1800})
case("alert_raise", "level-rose", {"entry": dict(ent, level="ATTENTION", pushed_level="ATTENTION"), "acked": True,
                                    "cond": cond, "now": NOW})
case("alert_raise", "info-never-repeats", {"entry": dict(ent, level="INFO", pushed_level="INFO"), "acked": False,
                                            "cond": dict(cond, level="INFO", band=None), "now": NOW + 86400})
case("alert_absent", "held-under-5-min", {"entry": ent, "now": NOW})
case("alert_absent", "cleared-after-5-min", {"entry": dict(ent, absent_since=NOW - 301), "now": NOW})
case("alert_absent", "info-clears-silently", {"entry": dict(ent, level="INFO", absent_since=NOW - 301), "now": NOW})

# ---- conditions (the alert rules)
C = [
    ("mem-red", {"state": ["RED", ["compressor +2000 MB in 60 s"]], "top_outside": [["AppC", 3100.0]]}),
    ("mem-amber", {"state": ["AMBER", ["free 45% < 50%"]]}),
    ("kernel-suspend", {"kernel_events": [{"kind": "suspending", "process": "AppA", "pid": 1, "why": "swap exhaustion",
                                           "time": "2026-01-01 09:13:09"}]}),
    ("disk-low", {"disk_gb": 35.0}), ("disk-quiet", {"disk_gb": 41.0}), ("disk-trend", {"disk_gb": 50.0, "disk_rate_gb_h": 5.0}),
    ("cache-big-action", {"cache_gb": 50.0, "disk_gb": 100.0}), ("cache-big-attention", {"cache_gb": 35.0, "disk_gb": 100.0}),
    ("codex-98", {"usage": {"codex_week": 98}}), ("codex-95", {"usage": {"codex_week": 95}}),
    ("claude-98", {"usage": {"claude_week": 98, "claude_5h": 10}}), ("usage-quiet", {"usage": {"codex_week": 94, "claude_week": 97,
                                                                                              "claude_5h": 84, "proj": 95.0}}),
    ("qwait", {"queue": {"slots": 5, "busy": [], "tickets": [{"name": "1-2", "mode": "S", "age_s": 1500, "label": "S x"}]}}),
    ("long-call", {"queue": {"slots": 5, "busy": [{"slot": ".slot.2", "mode": "S", "pid": 8, "label": "S 8 go test",
                                                    "since": NOW - 1500}], "tickets": []}}),
    ("slot-cpu", {"slot_cpu": {".slot.3": 9.0}}), ("idle-room", {"idle_minutes": 40}), ("power", {"on_ac": False}),
    ("resumed", {"resumed_gap_s": 2280}), ("recipient-wait", {"recipient_wait": ["Read", 900]}),
    ("guard-down", {"stale_sources": {"memory-guard": "heartbeat 300 s old"}}),
    ("source-stale", {"stale_sources": {"queue-sampler": "last line 400 s old"}}),
    ("jobs-dead", {"jobs_dead": [[4242, "/tmp/x.rc"]]}),
    ("readings-mismatch", {"readings_mismatch": ["free_pct fast=80.0 command=60.0"]}),
    ("off", {"off": {"off": True, "since": "2026-01-01 10:00:00", "reason": "test"}}),
    ("trim-needed", {"trim": {"needed_min": 70}, "trim_needed_ok": True}),
    ("cleanup-list", {"cleanup": {"count": 2, "bytes": 5e9, "top": [{"rule": "R1", "path": "/w/a", "bytes": 4e9}]},
                      "disk_gb": 45.0}),
]
for name, snap in C:
    case("conditions", name, {"snap": snap, "now": NOW})
case("conditions", "disk-hysteresis-held", {"snap": {"disk_gb": 42.0}, "now": NOW, "active": ["DISK_LOW"]})

# ---- delete_guard
ok = {"enabled": True, "forbidden": False, "parent_ok": True, "symlink": False, "keep_file": False,
      "untouched": [True, None], "held": None, "live_tools": [], "needs_no_live_tools": True, "age_minutes": 360}
case("delete_guard", "pass-delete", ok)
case("delete_guard", "pass-would", dict(ok, enabled=False))
case("delete_guard", "forbidden", dict(ok, forbidden=True))
case("delete_guard", "outside-root", dict(ok, parent_ok=False))
case("delete_guard", "symlink", dict(ok, symlink=True))
case("delete_guard", "keep-file", dict(ok, keep_file=True))
case("delete_guard", "young", dict(ok, untouched=[False, "changed 5 min ago"]))
case("delete_guard", "held-by-lsof", dict(ok, held="lsof=pids 4242"))
case("delete_guard", "live-tool", dict(ok, live_tools=["4242:go"]))
case("delete_guard", "live-tool-not-needed", dict(ok, live_tools=["4242:go"], needs_no_live_tools=False))

# ---- place
kinds = {"machine_only": {"merge-wide": "the wide run stays on the machine", "other": "kind 'other' runs on the machine"},
         "pool": {"go-test": 8, "rust-mutants": 64}}
qfull = {"slots": 3, "busy": [{"slot": ".slot.%d" % k, "mode": "S", "kind": "go-test", "since": NOW - 60} for k in range(3)],
         "tickets": [{"name": "t%d" % k, "mode": "S", "kind": "go-test"} for k in range(6)]}
qfree = {"slots": 3, "busy": [], "tickets": []}
mach = {"id": "m1", "state": "GREEN", "reasons": ["all readings in the green band"], "free_pct": 80.0, "queue": qfree,
        "medians": {"go-test": 15.0}}
pool = {"id": "ci:example/project", "minutes_left": 20000, "minutes_source": "read", "plan_minutes": 2, "job_minutes": 40,
        "guard": None, "guard_why": None, "stop_active": False}
ctx = {"now": NOW, "kinds": kinds, "wide_kind": "merge-wide", "machine": mach, "pools": [pool]}
case("place", "machine-free", {"req": {"kind": "go-test", "shards": 1}, "ctx": ctx})
case("place", "busy-needs-guard", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(ctx, machine=dict(mach, queue=qfull))})
case("place", "busy-guard-ok-pool", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(ctx, machine=dict(mach, queue=qfull),
                                     pools=[dict(pool, guard={"rc": 0, "line": "fits: 82 of 20000"})])})
case("place", "busy-guard-refused", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(ctx, machine=dict(mach, queue=qfull),
                                     pools=[dict(pool, guard={"rc": 1, "line": "over the month budget"})])})
case("place", "busy-guard-skip-pool", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(ctx, machine=dict(mach, queue=qfull),
                                       pools=[dict(pool, guard="skip")])})
case("place", "busy-guard-skip-reserve", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(ctx, machine=dict(mach, queue=qfull),
                                          pools=[dict(pool, guard="skip", minutes_left=3050)])}, {"github.reserve_minutes": 3000})
case("place", "red-guard-skip-stop-active", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(
    ctx, machine=dict(mach, state="RED", reasons=["free 30%"], queue=qfull), pools=[dict(pool, guard="skip", stop_active=True)])})
case("place", "busy-reserve", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(ctx, machine=dict(mach, queue=qfull),
                               pools=[dict(pool, minutes_left=3050)])}, {"github.reserve_minutes": 3000})
case("place", "busy-stop-active", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(ctx, machine=dict(mach, queue=qfull),
                                   pools=[dict(pool, stop_active=True)])})
case("place", "machine-only-never-pool", {"req": {"kind": "merge-wide"}, "ctx": dict(ctx, machine=dict(mach, queue=qfull))})
case("place", "unknown-kind-machine", {"req": {"kind": "other"}, "ctx": dict(ctx, machine=dict(mach, queue=qfull))})
case("place", "red-wait", {"req": {"kind": "merge-wide"}, "ctx": dict(ctx, machine=dict(mach, state="RED", reasons=["free 30%"]))})
case("place", "wide-ok", {"req": {"kind": "x", "wide": True}, "ctx": ctx})
case("place", "wide-waits-free", {"req": {"kind": "x", "wide": True}, "ctx": dict(ctx, machine=dict(mach, free_pct=40.0))})
case("place", "wide-waits-other-wide", {"req": {"kind": "x", "wide": True}, "ctx": dict(ctx, machine=dict(
    mach, queue={"slots": 3, "busy": [{"slot": ".gate.lock", "mode": "W", "since": NOW - 60}], "tickets": []}))})
case("place", "agents-red", {"req": {"kind": "other", "agents": 2}, "ctx": dict(ctx, machine=dict(mach, state="RED"))})
case("place", "agents-amber-one", {"req": {"kind": "other", "agents": 2}, "ctx": dict(ctx, machine=dict(mach, state="AMBER"))})
case("place", "agents-go", {"req": {"kind": "other", "agents": 3}, "ctx": ctx})
case("place", "too-many-shards", {"req": {"kind": "go-test", "shards": 9}, "ctx": dict(ctx, machine=dict(mach, queue=qfull))})
case("place", "no-pools", {"req": {"kind": "go-test", "shards": 1}, "ctx": dict(ctx, machine=dict(mach, queue=qfull), pools=[])})
case("place", "pools-independent-reserves", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(
    ctx, machine=dict(mach, queue=qfull), pools=[dict(pool, id="one", guard="skip", reserve_minutes=19950),
                                              dict(pool, id="two", guard="skip", reserve_minutes=50)])}, expected={
    "place": "POOL", "candidate": "two", "need_guard": None,
    "reasons": ["state GREEN: all readings in the green band", "expected wait on m1: 44 min",
                "two: 20000 minutes left (read), worst case 82, reserve 50", "guard: " + mmdecide.GUARD_SKIP]})
case("place", "pools-refused-guard-tries-next", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(
    ctx, machine=dict(mach, queue=qfull), pools=[dict(pool, id="one", guard={"rc": 1, "line": "refused"}),
                                              dict(pool, id="two")])}, expected={
    "place": None, "candidate": None, "need_guard": "two", "reasons": ["state GREEN: all readings in the green band"]})
case("place", "pools-stop-is-local", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(
    ctx, machine=dict(mach, queue=qfull), pools=[dict(pool, id="one", guard="skip", stop_active=True),
                                              dict(pool, id="two", guard="skip")])}, expected={
    "place": "POOL", "candidate": "two", "need_guard": None,
    "reasons": ["state GREEN: all readings in the green band", "expected wait on m1: 44 min",
                "two: 20000 minutes left (read), worst case 82, reserve 300", "guard: " + mmdecide.GUARD_SKIP]})

generic = {"id": "credits", "generic": True, "unit": "credits", "capacity_left": 25, "reserve": 5,
           "job_cost": 3, "plan_cost": 1, "source": "cached", "guard": "skip", "guard_why": None,
           "stop_active": False}
generic_ctx = dict(ctx, machine=dict(mach, queue=qfull), pools=[generic])
case("place", "generic-native-unit-cost", {"req": {"kind": "go-test", "shards": 2}, "ctx": generic_ctx}, expected={
    "place": "POOL", "candidate": "credits", "need_guard": None,
    "reasons": ["state GREEN: all readings in the green band", "expected wait on m1: 44 min",
                "credits: 25 credits left (cached), worst case 7, reserve 5"]})
case("place", "generic-reserve-boundary", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(
    generic_ctx, machine=dict(mach, state="RED", reasons=["critical"], queue=qfull), pools=[dict(generic, capacity_left=12)])},
    expected={"place": "WAIT", "candidate": None, "need_guard": None,
              "reasons": ["state RED: critical", "RED; no pool: credits: credits left 12 - worst case 7 <= reserve 5"]})
case("place", "generic-cross-unit-failover", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(
    generic_ctx, pools=[dict(generic, capacity_left=12), dict(generic, id="slots", unit="slots", capacity_left=3,
                                                           reserve=0, job_cost=1, plan_cost=0)])}, expected={
    "place": "POOL", "candidate": "slots", "need_guard": None,
    "reasons": ["state GREEN: all readings in the green band", "expected wait on m1: 44 min",
                "slots: 3 slots left (cached), worst case 2, reserve 0"]})
case("place", "generic-unknown-fails-over-to-github", {"req": {"kind": "go-test", "shards": 2}, "ctx": dict(
    generic_ctx, pools=[dict(generic, capacity_left=None, source="stale"), dict(pool, guard="skip")])}, expected={
    "place": "POOL", "candidate": "ci:example/project", "need_guard": None,
    "reasons": ["state GREEN: all readings in the green band", "expected wait on m1: 44 min",
                "ci:example/project: 20000 minutes left (read), worst case 82, reserve 300", "guard: " + mmdecide.GUARD_SKIP]})

# ---- expected_wait
case("expected_wait", "free-slot", {"q": qfree, "medians": {}, "default": 10, "now": NOW})
case("expected_wait", "full", {"q": qfull, "medians": {"go-test": 15.0}, "default": 10, "now": NOW})

# ---- drill_stop
d0 = {"elapsed_s": 60, "time_limit_s": 900, "state": "GREEN", "free_pct": 70.0, "swap_used_mb": 500.0, "swap_start_mb": 500.0,
      "step_mb": 512, "total_mb": 16384, "interrupted": False, "held_mb": 0, "free_start_pct": 80.0, "recent": []}
case("drill_stop", "go-on", d0)
case("drill_stop", "amber-seen", dict(d0, state="AMBER"))
case("drill_stop", "red-seen", dict(d0, state="RED"))
case("drill_stop", "floor", dict(d0, free_pct=45.0))
case("drill_stop", "floor-next-step", dict(d0, free_pct=47.0))
case("drill_stop", "swap-growth", dict(d0, swap_used_mb=650.0))
case("drill_stop", "time-limit", dict(d0, elapsed_s=900))
case("drill_stop", "interrupted", dict(d0, interrupted=True))
case("drill_stop", "free-unreadable", dict(d0, free_pct=None))
# free 80 at the start, floor 45: room 35% of 16384 MB = 5734 MB
case("drill_stop", "cap-not-reached", dict(d0, free_start_pct=80.0, held_mb=5632))
case("drill_stop", "cap-unknown", dict(d0, free_start_pct=None))
case("drill_stop", "cap-reached", dict(d0, free_start_pct=80.0, held_mb=6144))
case("drill_stop", "memory-not-used", dict(d0, free_start_pct=80.0, held_mb=1536,
                                           recent=[[0, 76.0], [512, 76.0], [1024, 75.6], [1536, 75.5]]))
case("drill_stop", "memory-used", dict(d0, free_start_pct=80.0, held_mb=1536,
                                       recent=[[0, 76.0], [512, 73.0], [1024, 70.0], [1536, 67.0]]))
# the 2026-10-14 live case: compressed about 7.5 to 1, free fell 1.2 of the 9.4 points the memory should take
case("drill_stop", "memory-compressed-partly", dict(d0, free_start_pct=80.0, held_mb=1536,
                                                    recent=[[0, 76.0], [512, 75.6], [1024, 75.2], [1536, 74.8]]))
case("drill_stop", "two-steps-too-early-to-judge", dict(d0, free_start_pct=80.0, held_mb=1024,
                                                        recent=[[0, 76.0], [512, 76.0], [1024, 76.0]]))

# ---- parsers
case("parse_load_line", "busy-minute", {"line": "10-14 09:14 load 347.39 97.03 38.93 free 69% swap 1001.69M comp 2023M sys "
                                                "24.97% fsev 9M slots 5/5 waiting 7", "year": 2026})
case("parse_load_line", "gigabytes", {"line": "10-10 20:21 load 19.16 11.18 8.54 free 33% swap 17.2G comp 7.8G sys 23.64% "
                                              "fsev 5M slots 4/4 waiting 1", "year": 2026})
case("parse_load_line", "broken", {"line": "10-14 09:14 load broken", "year": 2026})
case("parse_history_line", "row", {"line": "2026-10-14T11:42:01\t4807\tS\twait=7\trun=134\trc=0\tmem=steady\tcwd=/a\\tb\t"
                                           "zsh -c x\tzsh -c python3 worker.py\t--limit 300"})
case("parse_history_line", "short", {"line": "short\tline"})
case("parse_kernel_line", "suspend-plain", {"line": "2026-10-14 09:13:09.826 Df kernel[0:1] memorystatus: suspending AppA "
                                                    "[4242] due to swap exhaustion"})
case("parse_kernel_line", "no-paging-ndjson", {"line": json.dumps({"timestamp": "2026-10-14 09:13:09.826133+0300",
                                                                   "eventMessage": "memorystatus: triggering no paging space action"})})
case("parse_kernel_line", "other", {"line": json.dumps({"eventMessage": "arm_cpu_init(): cpu 9 online"})})
bill = {"usageItems": [
    {"date": "2026-10-01T00:00:00Z", "product": "actions", "sku": "Actions Linux", "quantity": 1200, "grossAmount": 4.8,
     "netAmount": 0},
    {"date": "2026-10-02T00:00:00Z", "product": "actions", "sku": "Actions storage", "quantity": 1.5, "grossAmount": 4.987e-06,
     "netAmount": 0},
    {"date": "2026-09-30T00:00:00Z", "product": "actions", "sku": "Actions Linux", "quantity": 999, "grossAmount": 1,
     "netAmount": 1}]}
case("parse_billing", "exponent-number", {"text": json.dumps(bill), "month": "2026-10"})
case("parse_billing", "string-amount-is-error", {"text": json.dumps({"usageItems": [dict(bill["usageItems"][0], grossAmount="4.8")]}),
                                                 "month": "2026-10"})
case("parse_billing", "bool-is-error", {"text": json.dumps({"usageItems": [dict(bill["usageItems"][0], quantity=True)]}),
                                        "month": "2026-10"})
case("parse_billing", "negative-is-error", {"text": json.dumps({"usageItems": [dict(bill["usageItems"][0], quantity=-1)]}),
                                            "month": "2026-10"})
case("parse_billing", "not-json", {"text": "<html>", "month": "2026-10"})

# ---- mask and alert_line
for name, text in [("env-token", "GH_TOKEN=abcd1234efgh go test ./..."), ("bearer", "curl -H 'Authorization: Bearer abcdefghijklmnop12'"),
                   ("flag", "tool --token s3cr3tvalue --x"), ("url-password", "https://user:pw123@host/x"),
                   ("known-prefix", "key ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 end"),
                   ("random-word", "x aZ9xY8wV7uT6sR5qP4oN3mL2kJ1iH0gFxx y"), ("keeps-paths", "/w/go-build1234567890/b001/exe/main"),
                   ("keeps-hex", "commit 4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e"), ("keeps-uuid", "4f1c2d3e-4f1c-2d3e-4f1c-2d3e4f1c2d3e"),
                   ("private-key", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----")]:
    case("mask", name, {"text": text})
case("alert_line", "plain", {"rec": {"level": "ATTENTION", "key": "DISK_TREND", "name": "DISK_TREND", "text": "disk 50 GB"}})
case("alert_line", "display-id", {"rec": {"level": "ACTION", "key": "MEM", "name": "MEM_RED", "text": "machine RED: free 30%"}})
case("alert_line", "key-suffix", {"rec": {"level": "ATTENTION", "key": "QWAIT:17-4", "name": "QWAIT", "text": "waits 25 min"}})
case("alert_line", "long-text-cut", {"rec": {"level": "ACTION", "key": "MEM", "name": "MEM_RED", "text": "x " * 150,
                                             "command": "mm status"}})
case("alert_line", "long-command-explain", {"rec": {"level": "ACTION", "key": "CACHE_BIG", "name": "CACHE_BIG",
                                                    "text": "build cache 61 GB", "command": "y" * 150}})
case("alert_line", "cleared", {"rec": {"level": "INFO", "key": "MEM", "name": "MEM_RED", "text": "cleared: MEM_RED",
                                       "why": "cleared", "command": "x"}})
case("compare_readings", "same", {"fast": {"free_pct": 80, "swap_total_mb": 2048, "swap_used_mb": 500, "comp_mb": 300, "load5": 2},
                                  "cmd": {"free_pct": 80, "swap_total_mb": 2048, "swap_used_mb": 510, "comp_mb": 302, "load5": 2.5}})
case("compare_readings", "free-differs", {"fast": {"free_pct": 80, "swap_total_mb": 2048, "swap_used_mb": 500, "comp_mb": 300,
                                                   "load5": 2}, "cmd": {"free_pct": 60, "swap_total_mb": 2048, "swap_used_mb": 500,
                                                                        "comp_mb": 300, "load5": 2}})
case("compare_readings", "fast-missing", {"fast": {"free_pct": None}, "cmd": {"free_pct": 70}})

# ---- replays of the three incidents (load.log minutes; the 09:13 kernel event at 09:13:09)
for name, fx, start, kern in (("incident-0913", "load-20261014-0849.log", 5, [mmtest.at("2026-10-14 09:13") + 9]),
                              ("incident-1010", "load-20261010-2000.log", 4, []),
                              ("incident-1013", "load-20261013-1910.log", 6, [])):
    case("replay", name, {"samples": mmtest.load_fixture(fx), "start_slots": start, "kernel_times": kern,
                          "labels": [time.strftime("%H:%M", time.localtime(x["t"])) for x in mmtest.load_fixture(fx)]})


case("parse_delete_line", "delete", {"line": "2026-01-02 03:04:05 DELETE rule=S2 path=/tmp/go-build123 bytes=8192 "
      "guard=pass: age>360min lsof=empty live_tools=none machine=m1 v=1"})
case("parse_delete_line", "quoted-path", {"line": '2026-01-02 03:04:05 KEEP rule=S6 path="/x/iOS DeviceSupport/17.0" '
      'guard=an entry changed 3 min ago machine=m1 v=1'})
case("parse_delete_line", "entries-in-guard", {"line": "2026-01-02 03:04:05 WOULD-DELETE rule=S5 path=/c bytes=10 "
      "guard=pass: live_tools=none before and after entries=2 machine=m1 v=1"})
case("parse_delete_line", "not-a-line", {"line": "garbage"})


# ---- self-recovery
GOOD = {"free_pct": 80, "swap_total_mb": 2048, "swap_used_mb": 500, "comp_mb": 300, "pressure": 1, "load1": 2.0,
        "load5": 2.0, "seg_pct": 5.0}
case("sample_problems", "fine", {"sample": GOOD})
case("sample_problems", "missing-free", {"sample": dict(GOOD, free_pct=None)})
case("sample_problems", "free-above-100", {"sample": dict(GOOD, free_pct=140)})
case("sample_problems", "negative-load", {"sample": dict(GOOD, load5=-1.0)})
case("sample_problems", "swap-used-above-total", {"sample": dict(GOOD, swap_used_mb=4096)})
case("sample_problems", "pressure-3", {"sample": dict(GOOD, pressure=3)})
case("sample_problems", "text-value", {"sample": dict(GOOD, comp_mb="300")})
case("sample_problems", "seg-above-100", {"sample": dict(GOOD, seg_pct=180.0)})
case("sample_problems", "empty", {"sample": {}})
OK_IN = {"now": NOW, "rss_mb": 40.0, "tick_s": 0.4, "tick_errors": 0, "reading_problems": [], "data_writable": True,
         "data_free_mb": 50000.0, "slot_changes": [], "safe": False}
case("self_check", "all-fine", {"state": {}, "inp": OK_IN})
case("self_check", "rss-over", {"state": {}, "inp": dict(OK_IN, rss_mb=250.0)})
case("self_check", "rss-unread", {"state": {}, "inp": dict(OK_IN, rss_mb=None)})
case("self_check", "slow-2-of-3", {"state": {"slow": 1}, "inp": dict(OK_IN, tick_s=31.0)})
case("self_check", "slow-3-restart", {"state": {"slow": 2}, "inp": dict(OK_IN, tick_s=31.0)})
case("self_check", "slow-streak-reset", {"state": {"slow": 2}, "inp": dict(OK_IN, tick_s=1.0)})
case("self_check", "tick-errors-6-restart", {"state": {}, "inp": dict(OK_IN, tick_errors=6)})
case("self_check", "bad-readings-5", {"state": {"bad": 4}, "inp": dict(OK_IN, reading_problems=["free_pct missing"])})
case("self_check", "bad-readings-6-safe", {"state": {"bad": 5}, "inp": dict(OK_IN, reading_problems=["free_pct missing"])})
case("self_check", "data-not-writable-safe", {"state": {}, "inp": dict(OK_IN, data_writable=False)})
case("self_check", "data-disk-low-safe", {"state": {}, "inp": dict(OK_IN, data_free_mb=150.0)})
case("self_check", "slot-changes-12-ok", {"state": {}, "inp": dict(OK_IN, slot_changes=[NOW - 60 * k for k in range(12)])})
case("self_check", "slot-changes-13-safe", {"state": {}, "inp": dict(OK_IN, slot_changes=[NOW - 60 * k for k in range(13)])})
case("self_check", "old-slot-changes-ignored", {"state": {}, "inp": dict(OK_IN, slot_changes=[NOW - 3700 - k for k in range(20)])})
case("self_check", "safe-beats-restart", {"state": {}, "inp": dict(OK_IN, rss_mb=250.0, data_writable=False)})
case("self_check", "in-safe-mode-only-alert", {"state": {"slow": 5}, "inp": dict(OK_IN, rss_mb=250.0, tick_s=40.0, safe=True)})
case("self_check", "in-safe-mode-fine", {"state": {}, "inp": dict(OK_IN, safe=True)})
case("crash_loop", "none", {"starts": [], "now": NOW})
case("crash_loop", "two-in-window", {"starts": [NOW - 300, NOW - 60], "now": NOW})
case("crash_loop", "three-in-window", {"starts": [NOW - 800, NOW - 300, NOW - 60], "now": NOW})
case("crash_loop", "old-dropped", {"starts": [NOW - 1000, NOW - 300, NOW - 60], "now": NOW})
case("crash_loop", "future-dropped", {"starts": [NOW + 50, NOW - 300, NOW - 60], "now": NOW})
case("crash_loop", "longer-window", {"starts": [NOW - 1000, NOW - 300, NOW - 60], "now": NOW}, {"self.crash_loop_minutes": 20})
case("resume_targets", "match", {"paused": {"101": "Tue Oct 14 20:00:01 2026", "102": "Tue Oct 14 20:00:02 2026"},
                                 "current": {"101": "Tue Oct 14 20:00:01 2026", "102": "Tue Oct 14 20:00:02 2026"}})
case("resume_targets", "reused-pid", {"paused": {"101": "Tue Oct 14 20:00:01 2026"}, "current": {"101": "Tue Oct 14 21:30:00 2026"}})
case("resume_targets", "gone", {"paused": {"101": "Tue Oct 14 20:00:01 2026"}, "current": {"101": None}})
case("resume_targets", "unknown-start", {"paused": {"101": None}, "current": {"101": None}})
case("resume_targets", "empty", {"paused": {}, "current": {}})
PREV = {"boot_time": NOW - 86400, "last_tick": NOW - 900, "last_state": "AMBER", "last_slots": 4, "panics": ["panic-old.panic"]}
case("reboot_check", "no-record", {"prev": None, "cur": {"boot_time": NOW - 300, "now": NOW, "panics": [], "missing_jobs": []}})
case("reboot_check", "same-boot", {"prev": PREV, "cur": {"boot_time": NOW - 86400 + 0.5, "now": NOW, "panics": [], "missing_jobs": []}})
case("reboot_check", "reboot-clean", {"prev": PREV, "cur": {"boot_time": NOW - 300, "now": NOW, "panics": ["panic-old.panic"],
                                                             "missing_jobs": []}})
case("reboot_check", "reboot-panic-and-jobs", {"prev": PREV, "cur": {"boot_time": NOW - 300, "now": NOW,
                                                                      "panics": ["panic-old.panic", "panic-full-2026-10-14.panic"],
                                                                      "missing_jobs": ["load sampler", "memory guard"]}})
case("reboot_check", "reboot-panics-unreadable", {"prev": PREV, "cur": {"boot_time": NOW - 300, "now": NOW, "panics": None,
                                                                         "missing_jobs": []}})
case("reboot_check", "reboot-no-last-tick", {"prev": dict(PREV, last_tick=None, last_state=None, last_slots=None),
                                             "cur": {"boot_time": NOW - 300, "now": NOW, "panics": [], "missing_jobs": []}})

# ---- resource records (mm resources): the writers' records, the cap, and one row per record
FACTS_MAC = {"cores": 12, "p_cores": 8, "e_cores": 4, "cpu_model": "Example M1 Pro", "ram_mb": 32768, "disk_gb_total": 994.7}
FACTS_LINUX = {"cores": 16, "p_cores": None, "e_cores": None, "cpu_model": "Example CPU 3.0GHz", "ram_mb": 64000,
               "disk_gb_total": 500.1}
READINGS = {"free_pct": 60, "swap_used_mb": 100.0, "swap_total_mb": 2048.0, "comp_mb": 300.0, "pressure": 1, "load5": 2.5,
            "sys_pct": 8.5, "cpu_pct": 41.27}
MACHINE = {"kind": "machine", "machine_id": "lab1", "schema_version": 1, "time": NOW - 5, "state": "GREEN",
           "reasons": ["all readings in the green band"], "red_since": None, "mode": "observe", "slots": 6,
           "slots_would": 6, "busy": 3, "waiting": 0, "readings": READINGS, "disk_gb": 210.44, "sampler": "fast",
           "alerts": {"ACTION": 0, "ATTENTION": 0, "INFO": 0}, "facts": FACTS_MAC, "calls": 2, "idle_minutes": None,
           "heartbeat": {"pid": 100, "tick": 7, "note": "ok"}}
TICK_ERROR = dict(MACHINE, state="UNKNOWN", reasons=["tick error"], mode="act", slots=None, slots_would=None, busy=0,
                  readings={k: None for k in READINGS}, disk_gb=None, facts=FACTS_LINUX, calls=None,
                  heartbeat={"pid": 100, "tick": 7, "note": "tick error: boom"})
STARTING = {"kind": "machine", "machine_id": "lab1", "schema_version": 1, "time": NOW - 5, "state": "UNKNOWN",
            "reasons": ["starting"], "heartbeat": {"pid": 100, "tick": 0, "note": "starting"}}
RUNNERS = [{"name": "build-1", "online": True, "busy": False, "labels": ["self-hosted", "lab"]},
           {"name": "build-2", "online": True, "busy": True, "labels": ["self-hosted", "lab"]},
           {"name": "build-3", "online": False, "busy": False, "labels": ["self-hosted", "lab"]},
           {"name": "build-4", "online": "yes", "busy": False, "labels": ["self-hosted", "lab"]}]
RUNS = {"in_progress": 2, "queued": 1, "running": [11, 12], "failed_1h": [], "oldest_queued_min": 3,
        "oldest_queued_job_min": 0, "longest_running_min": 20}
GH = {"time": NOW - 120, "errors": {}, "pool_id": "ci:example/repo", "runs": RUNS,
      "billing": {"minutes": 1265.46, "gross": 1.234, "net": 0.0}, "watched": {}}
SPEND = {"github.allowed_gross_usd": 5}  # paid use allowed: a small gross amount is GREEN
USAGE = {"age_s": 300.0, "max_age_s": 1800, "stale_levels": {}, "claude_5h": 41.0, "claude_week": 63.5, "codex_week": 20.04,
         "codex_5h": None, "proj": None}
RESETS = {"claude_5h": {"reset_at": NOW + 3600, "not_offered": False},
          "claude_weekly": {"reset_at": NOW + 86400, "not_offered": False},
          "codex_5h": {"reset_at": None, "not_offered": True},
          "codex_weekly": {"reset_at": NOW + 7200.5, "not_offered": False}}


def machine_case(name, st, over=None):
    case("machine_resource", name, {"st": st, "mid": "lab1", "now": NOW}, over)


machine_case("mac", MACHINE)
machine_case("linux-facts", dict(MACHINE, facts=FACTS_LINUX, readings=dict(READINGS, free_pct=None, cpu_pct=None)))
machine_case("amber", dict(MACHINE, state="AMBER", reasons=["free memory below 50%", 7, "load5 high"]))
machine_case("idle", dict(MACHINE, busy=0, calls=0, idle_minutes=12.4))
machine_case("stale-idle", dict(MACHINE, busy=0, calls=0, idle_minutes=12.4, time=NOW - 120))
machine_case("busy-over-slots", dict(MACHINE, slots=3, busy=5, calls=4, waiting=2))
machine_case("tick-error", TICK_ERROR)
machine_case("starting", STARTING)
machine_case("missing", None)
machine_case("none-values", {k: None for k in MACHINE})
machine_case("wrong-types", dict(MACHINE, state="PURPLE", reasons="busy", slots="6", busy=True, calls=[1],
                                 readings=[1, 2], facts="none", idle_minutes="12", disk_gb={"a": 1}, machine_id=7))


def pool_case(name, gh, over=None):
    case("pool_resources", name, {"gh": gh, "now": NOW, "pool_id": "ci:example/repo"}, over)


pool_case("runners", dict(GH, runners=RUNNERS, runners_error=None), SPEND)
pool_case("runners-unnamed", dict(GH, runners=[7, {"online": True, "busy": False}, {"name": "", "online": True},
                                               RUNNERS[0]], runners_error=None), SPEND)  # no name: no record
pool_case("runners-error", dict(GH, runners=[], runners_error="gh api runners rc=1 (the runner list needs admin access "
                                                              "to the repository)"), SPEND)
pool_case("never-read", None)
pool_case("billing-error", dict({k: v for k, v in GH.items() if k != "billing"},
                                errors={"billing": "gh api billing rc=1"}), SPEND)
pool_case("budget-stop", dict(GH, billing={"minutes": 3010.0, "gross": 6.5, "net": 6.5}), SPEND)
pool_case("no-runner-labels", GH, SPEND)
pool_case("zero-left", dict(GH, billing={"minutes": 3000.0, "gross": 0.0, "net": 0.0}))


def usage_case(name, usage, resets, over=None):
    case("usage_resources", name, {"usage": usage, "resets": resets, "now": NOW}, over)


usage_case("fresh", USAGE, RESETS)
usage_case("not-offered-and-level-error", dict(USAGE, codex_week=None, stale_levels={"codex_weekly": "status error",
                                                                                    "codex_5h": "status error"}), RESETS)
usage_case("state-old", dict(USAGE, age_s=4000.0), RESETS)
usage_case("unreadable", None, {})
usage_case("wrong-types", [], "x")
usage_case("no-max-age", dict(USAGE, max_age_s=None), RESETS, {"usage.watch_state_max_age_s": 900})

case("cap_records", "under", {"recs": [{"resource": "pool", "id": "a"}, 7, {}], "t": NOW})
case("cap_records", "at-cap", {"recs": [{}] * 1000, "t": NOW})
case("cap_records", "over", {"recs": [{}] * 1001, "t": NOW})
case("cap_records", "not-a-list", {"recs": {"resource": "pool"}, "t": NOW})
case("cap_records", "over-no-time", {"recs": [{}] * 1001, "t": None})
case("cap_records", "over-non-dict", {"recs": [{}] * 1000 + [None], "t": NOW})  # the cap counts raw entries


def row_case(name, rec, over=None):
    case("resource_row", name, {"rec": rec, "now": NOW}, over)


def stamped(recs):
    return [dict(r, time=NOW - 5) for r in recs]  # as the supervisor writes them


POOL_RECS = stamped(ad_ci_github.pool_resources(dict(GH, runners=RUNNERS[:1], runners_error=None), dict(BASE, **SPEND),
                                                NOW - 5, "ci:example/repo"))
REC = {"resource": "agent-service", "id": "svc-1", "location": "cloud", "time": NOW - 5, "read_time": NOW - 60,
       "stale_after_s": 900, "state": "GREEN", "why": None}
row_case("pool-full", POOL_RECS[0])
row_case("runner-with-parent", POOL_RECS[1])
row_case("machine-from-status", mmdecide.machine_resource(dict(MACHINE, idle_minutes=12.4), "lab1", NOW, BASE))
row_case("record-at-limit", dict(REC, time=NOW - 60))
row_case("record-limit-raised", dict(REC, time=NOW - 120), {"other.status_fresh_s": 300})
row_case("record-time-future", dict(REC, time=NOW + 30))
row_case("no-record-time", {k: v for k, v in REC.items() if k != "time"})
row_case("read-at-limit", dict(REC, read_time=NOW - 900))
row_case("read-old", dict(REC, read_time=NOW - 901))
row_case("no-read", dict(REC, read_time=None))
row_case("no-read-rule", dict(REC, read_time=None, stale_after_s=None))
row_case("bad-stale-after", dict(REC, stale_after_s="900"))
row_case("negative-stale-after", dict(REC, stale_after_s=-1))
row_case("null-state-fresh", dict(REC, state=None))
row_case("null-state-stale", dict(REC, state=None, read_time=NOW - 1000))
row_case("bad-state-word", dict(REC, state="PURPLE"))
row_case("why-order", dict(REC, time=NOW - 600, read_time=NOW - 1000, state="green", why="writer reason"))
# The freshness checks in order (the first that fails names the reason): the record time before a bad stale_after_s
# and before the read; a bad stale_after_s before a missing read (negative-stale-after: before an old read).
row_case("record-old-bad-stale-after", dict(REC, time=NOW - 600, stale_after_s=-1, read_time=None))
row_case("bad-stale-after-no-read", dict(REC, stale_after_s=-1, read_time=None))
row_case("groups-absent", dict(REC, capacity=None, load="x"))
row_case("groups-partial-and-wrong", dict(REC, capacity={"unit": "Minutes", "total": "x", "left": True},
                                          load={"running": 2.6, "queued": "1"}))
row_case("values-odd", dict(REC, values=[
    7, None, {"key": "credits_left", "value": 12.5}, {"key": "Bad-Key", "value": 1}, {"key": "x" * 41, "value": 1},
    {"key": "state", "value": "RED"}, {"key": "age_s", "value": 1}, {"key": "credits_left", "value": 99},
    {"key": "tags", "value": ["a"]}, {"key": "note", "value": "n" * 300}, {"key": "on", "value": True},
    {"key": "off", "value": None}, {"key": "empty", "value": ""}, {"value": 3}, {"key": 5, "value": 3}] + [
    {"key": k, "value": "spoof"} for k in ("time read_time stale_after_s why values fresh parent capacity load unit "
                                           "total left reserve running queued").split()]))  # FIXED keys not in the row
row_case("values-not-list", dict(REC, values={"key": "credits_left", "value": 1}))
row_case("values-cap", dict(REC, values=[{"key": "v%d" % k, "value": k} if k != 2 else "x" for k in range(70)]))
row_case("bad-words", dict(REC, resource="Pool", location="us east", id=7, parent=[]))
row_case("text-cut", dict(REC, id="i" * 300, read_time=NOW - 1000, why="w" * 500,
                          values=[{"key": "note", "value": "n" * 300}]))
row_case("not-a-record", None)

# ---- timing_warnings: mm check's W_SCHEDULE lines; input: what is in use (the watchdog service, a CI pool)
IN_USE = {"service": True, "pool": True}


def timing_case(name, over, ctx=IN_USE):
    case("timing_warnings", name, ctx, over)


timing_case("defaults", {})  # the defaults give no warning
timing_case("tick-30", {"schedule.tick_s": 30})  # the longest tick fits every other default
timing_case("heartbeat-60", {"other.heartbeat_max_age_s": 60})  # max(10, 30) + 30
timing_case("heartbeat-59", {"other.heartbeat_max_age_s": 59})
timing_case("max-tick-120", {"self.max_tick_s": 120})  # the gap 240: heartbeat and resume
timing_case("max-tick-120-no-service", {"self.max_tick_s": 120}, {"service": False, "pool": True})
timing_case("gap-from-tick", {"schedule.tick_s": 30, "self.max_tick_s": 5, "other.heartbeat_max_age_s": 44})  # 1.5 x 30
timing_case("status-fresh-fraction", {"schedule.tick_s": 12.5, "other.status_fresh_s": 18})  # 18.75
timing_case("status-fresh-at-limit", {"schedule.tick_s": 12.5, "other.status_fresh_s": 18.75})
timing_case("resume-60", {"self.resume_paused_after_s": 60})
timing_case("resume-59", {"self.resume_paused_after_s": 59})  # also under the watchdog's 60 s
timing_case("watchdog-over-resume", {"schedule.watchdog_s": 90, "self.resume_paused_after_s": 89})
# the fix in whole seconds (schedule.watchdog_s is an int): 89
timing_case("watchdog-over-fractional-resume", {"schedule.watchdog_s": 90, "self.resume_paused_after_s": 89.5})
timing_case("watchdog-120", {"schedule.watchdog_s": 120})
timing_case("watchdog-121", {"schedule.watchdog_s": 121, "self.resume_paused_after_s": 600})  # watchdog_stale 180
timing_case("watchdog-no-service", {"schedule.watchdog_s": 600}, {"service": False, "pool": True})
timing_case("github-read-1200", {"github.read_interval_s": 1200})
timing_case("github-read-1201", {"github.read_interval_s": 1201})  # 30.025 min
timing_case("github-no-pool", {"github.read_interval_s": 1201}, {"service": True, "pool": False})
timing_case("github-read-57600", {"github.read_interval_s": 57600})  # 1440 min: github.stale_minutes' maximum still fits
# 2160 min is over github.stale_minutes' maximum (1440): the fix lowers github.read_interval_s instead (30 x 40 s)
timing_case("github-read-86400", {"github.read_interval_s": 86400})
timing_case("intervals-under-tick", {"schedule.tick_s": 15, "schedule.ps_s": 10, "schedule.minute_s": 14,
                                     "schedule.metrics_s": 10})
timing_case("intervals-at-tick", {"schedule.tick_s": 15, "schedule.ps_s": 15, "schedule.minute_s": 15,
                                  "schedule.metrics_s": 15})
timing_case("metrics-over-window", {"schedule.metrics_s": 301, "evidence.window_minutes": 5})
timing_case("metrics-at-window", {"schedule.metrics_s": 300, "evidence.window_minutes": 5})
timing_case("nothing-in-use", {"self.max_tick_s": 120, "schedule.watchdog_s": 600, "github.read_interval_s": 3600}, {})
# every check at once (the gap 60 s at tick 15): the expected list pins the order of the lines, checks 1 to 8
timing_case("every-check", {"schedule.tick_s": 15, "other.heartbeat_max_age_s": 59, "other.status_fresh_s": 15,
                            "self.resume_paused_after_s": 59, "schedule.watchdog_s": 61, "self.watchdog_stale_s": 90,
                            "github.read_interval_s": 1201, "schedule.ps_s": 10, "schedule.metrics_s": 600,
                            "evidence.window_minutes": 5})


# Fleet placement keeps the local gate contract and only consumes validated, cached remote candidates.
FLEET_CTX = {"now": NOW, "wide_kind": "wide", "kinds": {"machine_only": {"other": "machine only"}, "pool": {"go-test": 8}},
             "machine": {"id": "local", "state": "RED", "reasons": ["fixture"], "queue": None}, "pools": []}
FLEET_REMOTE = {"id": "remote-a", "state": "GREEN", "eligible": True, "kinds": {"go-test": 8}, "wait_minutes": 0}
FLEET_ANSWER = {"place": "MACHINE", "candidate": "remote-a", "need_guard": None,
                "reasons": ["remote machine remote-a: state GREEN, estimated wait 0.0 min",
                            "fresh remote status; controls remain on that machine"]}
case("place_fleet", "healthy-remote-relieves-red-local", {"req": {"kind": "go-test", "shards": 1},
     "ctx": dict(FLEET_CTX, machines=[FLEET_REMOTE])}, expected=FLEET_ANSWER)
case("place_fleet", "stale-peer-cannot-take-work", {"req": {"kind": "go-test", "shards": 1},
     "ctx": dict(FLEET_CTX, machines=[dict(FLEET_REMOTE, eligible=False)])},
     expected={"place": "WAIT", "candidate": None, "need_guard": None,
               "reasons": ["state RED: fixture", "RED; no pool: "]})
case("place_fleet", "agent-launch-check-stays-local", {"req": {"kind": "go-test", "agents": 2},
     "ctx": dict(FLEET_CTX, machines=[FLEET_REMOTE])},
     expected={"place": "WAIT", "candidate": None, "need_guard": None,
               "reasons": ["state RED: fixture", "RED: no agent launch now (2 asked)"]})
case("place_fleet", "kind-must-be-explicitly-supported", {"req": {"kind": "go-test", "shards": 1},
     "ctx": dict(FLEET_CTX, machines=[dict(FLEET_REMOTE, kinds={"py-suite": 1})])},
     expected={"place": "WAIT", "candidate": None, "need_guard": None,
               "reasons": ["state RED: fixture", "RED; no pool: "]})
case("place_fleet", "local-wins-an-equal-wait", {"req": {"kind": "go-test", "shards": 1},
     "ctx": dict(FLEET_CTX, machine=dict(FLEET_CTX["machine"], state="GREEN", queue={"slots": 2, "busy": [], "tickets": []}),
                 machines=[FLEET_REMOTE])}, expected={"place": "MACHINE", "candidate": "local", "need_guard": None,
                 "reasons": ["state GREEN: fixture", "expected wait on local: 0 min <= 20"]})


def write_settings():
    """vectors/_settings/base.json from the code's settings table (mmtest.base_settings); test_vectors checks it."""
    os.makedirs(os.path.join(VEC, "_settings"), exist_ok=True)
    with open(os.path.join(VEC, "_settings", "base.json"), "w") as f:
        json.dump(BASE, f, indent=1, sort_keys=True)


def main(function=None):
    # A scoped regeneration leaves separately maintained cases and shared settings intact.
    if function is None and os.path.isdir(VEC):
        for d in os.listdir(VEC):
            if not d.startswith("_"):
                shutil.rmtree(os.path.join(VEC, d))
    if function is None:
        write_settings()
    n = 0
    for fn, cases in CASES.items():
        if function is not None and fn != function:
            continue
        os.makedirs(os.path.join(VEC, fn), exist_ok=True)
        for name, inp, over in cases:
            s = dict(BASE, **over)
            inp = json.loads(json.dumps(inp))
            exp = EXPECTED[fn, name] if (fn, name) in EXPECTED else FUNCTIONS[fn](inp, s)
            exp = json.loads(json.dumps(exp))
            v = {"function": fn, "case": name, "settings": "base", "settings_over": over, "input": inp, "expected": exp}
            with open(os.path.join(VEC, fn, name + ".json"), "w") as f:
                json.dump(v, f, indent=1, sort_keys=True)
                f.write("\n")
            n += 1
    print("vectors=%d functions=%d" % (n, 1 if function is not None else len(CASES)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--function", choices=sorted(CASES), help="update only this function, keeping other cases")
    parser.add_argument("--settings", action="store_true",
                        help="update only vectors/_settings/base.json from the settings table, keeping every case")
    a = parser.parse_args()
    if a.settings:
        if a.function:
            parser.error("--settings takes no --function")
        write_settings()
        print("settings=%d" % len(BASE))
    else:
        main(a.function)
