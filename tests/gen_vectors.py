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
import mmcore  # noqa: E402

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

# ---- resource_row (mm resources): one row per record; freshness, state and arithmetic; never a crash
FACTS_MAC = {"cores": 12, "p_cores": 8, "e_cores": 4, "cpu_model": "Example M1 Pro", "ram_mb": 32768, "disk_gb_total": 994.7}
FACTS_LINUX = {"cores": 16, "p_cores": None, "e_cores": None, "cpu_model": "Example CPU 3.0GHz", "ram_mb": 64000,
               "disk_gb_total": 500.1}
READINGS = {"free_pct": 60, "swap_used_mb": 100.0, "swap_total_mb": 2048.0, "comp_mb": 300.0, "pressure": 1, "load5": 2.5,
            "sys_pct": 8.5, "cpu_pct": 41.27}
MACHINE = {"kind": "machine", "machine_id": "lab1", "schema_version": 1, "time": NOW - 5, "state": "GREEN",
           "reasons": ["all readings in the green band"], "mode": "observe", "slots": 6, "slots_would": 6, "busy": 3,
           "waiting": 0, "calls": 2, "idle_minutes": 12.4, "disk_gb": 210.44, "readings": READINGS, "facts": FACTS_MAC}
TICK_ERROR = {"kind": "machine", "machine_id": "lab1", "schema_version": 1, "time": NOW - 5, "state": "UNKNOWN",
              "reasons": ["tick error"], "red_since": None, "mode": "act", "slots": None, "slots_would": None, "busy": 0,
              "waiting": 0, "readings": {k: None for k in READINGS}, "disk_gb": None, "sampler": "fast",
              "alerts": {"ACTION": 0, "ATTENTION": 0, "INFO": 0}, "facts": FACTS_LINUX, "calls": None,
              "idle_minutes": None, "heartbeat": {"pid": 100, "tick": 7, "note": "tick error: boom"}}
POOL = {"kind": "pool", "machine_id": "ci:example/repo", "schema_version": 1, "time": NOW - 5, "state": "GREEN",
        "reasons": ["budget and queue fine"], "capacity": {"minutes_left": 1234.5, "reserve_minutes": 300, "unit": "minutes"},
        "money": {"used_usd": 0.0, "allowed_usd": 0}, "load": {"running": 2, "queued": 1}, "alerts": [],
        "read_time": NOW - 120}
AT = {"pool": "ci:example/repo", "read_time": NOW - 120, "time": NOW - 5}
USAGE = {"age_s": 300.0, "max_age_s": 1800, "stale_levels": {}, "claude_5h": 41.0, "claude_week": 63.5, "codex_week": None,
         "codex_5h": None, "proj": None}
RESETS = {"claude_5h": {"reset_at": NOW + 3600, "not_offered": False},
          "claude_weekly": {"reset_at": NOW + 86400, "not_offered": False},
          "codex_5h": {"reset_at": None, "not_offered": True},
          "codex_weekly": {"reset_at": NOW + 7200, "not_offered": False}}


def row_case(name, kind, rec, extra=None, over=None):
    case("resource_row", name, {"kind": kind, "rec": rec, "now": NOW, "extra": extra}, over)


row_case("machine-fresh-mac", "machine", MACHINE, {"id": "lab1"})
row_case("machine-linux-facts", "machine", dict(MACHINE, facts=FACTS_LINUX, readings=dict(READINGS, free_pct=None),
                                                idle_minutes=None, state="STEADY"), {"id": "lab1"})
row_case("machine-stale", "machine", dict(MACHINE, time=NOW - 120), {"id": "lab1"})
row_case("machine-fresh-limit-setting", "machine", dict(MACHINE, time=NOW - 120), {"id": "lab1"}, {"other.status_fresh_s": 300})
row_case("machine-missing", "machine", None, {"id": "lab1"})
row_case("machine-empty", "machine", {}, {"id": "lab1"})
row_case("machine-none-values", "machine", {k: None for k in MACHINE}, {"id": "lab1"})
row_case("machine-tick-error", "machine", TICK_ERROR, {"id": "lab1"})
row_case("machine-wrong-types", "machine", dict(MACHINE, state="PURPLE", slots="6", busy=True, calls=[1], readings=[1, 2],
                                                facts="none", idle_minutes="12", disk_gb={"a": 1}, machine_id=7), {"id": "lab1"})
row_case("pool-fresh", "pool", POOL, {"id": "ci_example_repo"})
row_case("pool-old-read-fresh-file", "pool", dict(POOL, read_time=NOW - 3600), {"id": "ci_example_repo"})
row_case("pool-file-stale", "pool", dict(POOL, time=NOW - 600), {"id": "ci_example_repo"})
row_case("pool-no-read-and-wrong-types", "pool", dict(POOL, read_time=None, capacity="x", money=None, load=[]),
         {"id": "ci_example_repo"})
row_case("pool-empty", "pool", {}, {"id": "ci_example_repo"})
row_case("runner-idle", "runner", {"name": "build-1", "online": True, "busy": False, "labels": ["self-hosted", "lab"]}, AT)
row_case("runner-busy", "runner", {"name": "build-2", "online": True, "busy": True, "labels": ["self-hosted", "lab"]}, AT)
row_case("runner-offline", "runner", {"name": "build-3", "online": False, "busy": False, "labels": ["self-hosted"]}, AT)
row_case("runner-stale-read", "runner", {"name": "build-1", "online": True, "busy": False, "labels": []},
         dict(AT, read_time=NOW - 3600))
row_case("runner-error", "runner", {"error": "gh api runners rc=1 (the runner list needs admin access to the repository)"},
         AT)
row_case("runner-wrong-types", "runner", {"name": 5, "online": "yes", "busy": None}, {"pool": None})
row_case("service-claude-fresh", "service", {"usage": USAGE, "levels": RESETS}, {"id": "claude"})
row_case("service-codex-not-offered-and-stale", "service",
         {"usage": dict(USAGE, stale_levels={"codex_weekly": "reading 4000 s old"}), "levels": RESETS}, {"id": "codex"})
row_case("service-state-old", "service", {"usage": dict(USAGE, age_s=4000.0), "levels": RESETS}, {"id": "claude"})
row_case("service-unreadable", "service", {"usage": None, "levels": {}}, {"id": "claude"})
row_case("service-wrong-types", "service", {"usage": [], "levels": "x"}, {"id": "codex"})


def main(function=None):
    # A scoped regeneration leaves separately maintained cases and shared settings intact.
    if function is None and os.path.isdir(VEC):
        for d in os.listdir(VEC):
            if not d.startswith("_"):
                shutil.rmtree(os.path.join(VEC, d))
    if function is None:
        os.makedirs(os.path.join(VEC, "_settings"), exist_ok=True)
        with open(os.path.join(VEC, "_settings", "base.json"), "w") as f:
            json.dump(BASE, f, indent=1, sort_keys=True)
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
    main(parser.parse_args().function)
