# SPDX-License-Identifier: Apache-2.0
"""A pure replay: one-minute samples through the state machine, the slot controller and the alerts (with dedupe,
bands, repeat and clear in memory). The incident replays are vectors of this function (vectors/replay/)."""
import mmalerts
import mmdecide


def replay(samples, start_slots, s, kernel_times=(), wx_waiting=False):
    """samples: dicts with t (s) and the reading keys, plus busy and waiting. Returns one row per sample:
    {i, state, reasons, slots, pushed: [[name, level, why]]}."""
    ctl = {}
    active, acks = {}, set()
    slots = start_slots
    window, out = [], []
    prev_t = None
    for i, x in enumerate(samples):
        now = x["t"]
        window.append(x)
        window = [w for w in window if now - w["t"] <= 1900]
        kev = [k for k in kernel_times if 0 <= now - k < 120]
        state, reasons, _ = mmdecide.classify(window, s, kernel_event=bool(kev))
        r = mmdecide.slot_decide(ctl, {"now": now, "mac_state": state, "reasons": reasons, "slots": slots,
                                       "busy": min(x.get("busy", 0), slots), "waiting": x.get("waiting", 0),
                                       "wx_waiting": wx_waiting}, s)
        ctl = r["state"]
        if r["slots"] is not None:
            slots = r["slots"]
        snap = {"state": (state, reasons)}
        if kev:
            snap["kernel_events"] = [{"kind": "suspending", "process": "AppA", "pid": 4242, "why": "swap exhaustion",
                                      "time": "replay"}]
        if prev_t is not None and now - prev_t > s["other.resume_gap_s"]:
            snap["resumed_gap_s"] = now - prev_t
        prev_t = now
        pushed, seen = [], set()
        for c in mmalerts.evaluate(snap, s, now, set(active)):
            seen.add(c["key"])
            a = mmdecide.alert_raise(active.get(c["key"]), c["key"] in acks, c, now, s)
            active[c["key"]] = a["entry"]
            if a["push"]:
                pushed.append([c["name"], c["level"], a["why"]])
        for key in [k for k in active if k not in seen]:
            a = mmdecide.alert_absent(active[key], now, s)
            if a["clear"]:
                ent = active.pop(key)
                if a["push_cleared"]:
                    pushed.append([ent["name"], "INFO", "cleared"])
            else:
                active[key] = a["entry"]
        out.append({"i": i, "state": state, "reasons": reasons, "slots": slots, "pushed": pushed})
    return out
