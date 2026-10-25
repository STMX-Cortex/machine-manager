# SPDX-License-Identifier: Apache-2.0
"""The table the vector runner uses: function name -> how to call it with a vector's input and settings.
A port implements the same functions; its runner reads the same files (PORTING.md)."""
from decimal import Decimal
import json
import os
import tempfile

import mmtest  # noqa: F401  (paths)
import ad_ci_github
import ad_deliver_claude
import ad_queue_fifo
import mmalerts
import mmcore
import mmdecide
import mmread
import mmreplay


def _drop(d, *keys):
    return None if d is None else {k: v for k, v in d.items() if k not in keys}


def _billing(i, s):
    try:
        m, g, n = ad_ci_github.parse_billing(i["text"], i["month"])
        return {"minutes": format(m.normalize(), "f"), "gross": format(g.normalize(), "f"), "net": format(n.normalize(), "f")}
    except ad_ci_github.BillingError:
        return {"error": True}


def _read_usage(i, s):
    """Exercise the file parser in a disposable fixture folder; compare its public readings only."""
    os.makedirs(mmtest.TMP_BASE, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="usage-vector-", dir=mmtest.TMP_BASE) as root:
        path = os.path.join(root, "usage.json")
        with open(path, "w") as f:
            f.write(i["text"] if "text" in i else json.dumps(i["state"]))
        got = ad_deliver_claude.read_usage(path, i["now"], s)
    if got is None:
        return None
    return {k: got.get(k) for k in ("claude_5h", "claude_week", "codex_week", "proj")}


FUNCTIONS = {
    "read_usage": _read_usage,
    "classify": lambda i, s: mmdecide.classify(i["window"], s, i.get("disk_gb"), i.get("kernel_event", False)),
    "slot_decide": lambda i, s: mmdecide.slot_decide(i["state"], i["inp"], s),
    "alert_raise": lambda i, s: mmdecide.alert_raise(i["entry"], i["acked"], i["cond"], i["now"], s),
    "alert_absent": lambda i, s: mmdecide.alert_absent(i["entry"], i["now"], s),
    "conditions": lambda i, s: sorted([c["name"], c["level"]] for c in mmalerts.evaluate(i["snap"], s, i["now"],
                                                                                         set(i.get("active", [])))),
    "delete_guard": lambda i, s: mmdecide.delete_guard(i),
    "place": lambda i, s: mmdecide.place(i["req"], i["ctx"], s),
    "drill_stop": lambda i, s: mmdecide.drill_stop(i, s),
    "expected_wait": lambda i, s: mmdecide.expected_wait(i["q"], i["medians"], i["default"], i["now"]),
    "replay": lambda i, s: mmreplay.replay(i["samples"], i["start_slots"], s, i.get("kernel_times", [])),
    "parse_load_line": lambda i, s: _drop(ad_queue_fifo.parse_load_line(i["line"], i["year"]), "t"),
    "parse_history_line": lambda i, s: _drop(ad_queue_fifo.parse_history_line(i["line"]), "end"),
    "parse_kernel_line": lambda i, s: mmread.parse_kernel_line(i["line"]),
    "parse_billing": _billing,
    "mask": lambda i, s: mmcore.mask(i["text"]),
    "parse_delete_line": lambda i, s: mmcore.parse_delete_line(i["line"]),
    "alert_line": lambda i, s: mmcore.alert_line(i["rec"]),
    "compare_readings": lambda i, s: mmread.compare_readings(i["fast"], i["cmd"]),
    "sample_problems": lambda i, s: mmdecide.sample_problems(i["sample"]),
    "self_check": lambda i, s: mmdecide.self_check(i["state"], i["inp"], s),
    "crash_loop": lambda i, s: mmdecide.crash_loop(i["starts"], i["now"], s),
    "resume_targets": lambda i, s: mmdecide.resume_targets(i["paused"], i["current"]),
    "reboot_check": lambda i, s: mmdecide.reboot_check(i["prev"], i["cur"]),
    "resource_row": lambda i, s: [[k, v] for k, v in mmdecide.resource_row(i["rec"], i["now"], s).items()],
    "machine_resource": lambda i, s: mmdecide.machine_resource(i["st"], i["mid"], i["now"], s),
    "pool_resources": lambda i, s: ad_ci_github.pool_resources(i["gh"], s, i["now"], i["pool_id"]),
    "usage_resources": lambda i, s: ad_deliver_claude.usage_resources(i["usage"], i["resets"], i["now"], s),
    "cap_records": lambda i, s: mmdecide.cap_records(i["recs"], i["t"]),
    "timing_warnings": lambda i, s: mmdecide.timing_warnings(i, s),
}
