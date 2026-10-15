# SPDX-License-Identifier: Apache-2.0
"""Synthetic queue-trial inputs; no process or machine-data access."""
from mmtest import base_settings

NOW = 1_800_000_000.0


def settings(**over):
    # design.md item 1: the only new setting, including on the unfixed reference.
    return base_settings(**dict({"slots.green_load1_per_core": 0.8}, **over))


def sample(t=NOW, **over):
    return dict({"t": t, "free_pct": 80.0, "swap_used_mb": 100.0, "swap_total_mb": 2048.0,
                 "comp_mb": 300.0, "pressure": 1, "seg_pct": 5.0, "load1": 2.0,
                 "load5": 4.0, "sys_pct": 10.0}, **over)


def busy(pid=4100, slots=(".gate.lock", ".slot.2"), mode="W"):
    return [{"slot": slot, "pid": pid, "mode": mode, "label": "%s %d trial" % (mode, pid),
             "since": NOW - 60} for slot in slots]
