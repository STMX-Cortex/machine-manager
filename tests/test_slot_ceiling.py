# SPDX-License-Identifier: Apache-2.0
"""Slot ceiling: a count above slots.ceiling steps down to the ceiling (written from the contract, not from the code).

The finding: slots.ceiling went back from 13 to 10 after a pinned 13-slot trial, and the controller kept 13 (GREEN, act
mode): GREEN raises only while slots < ceiling, and nothing lowered a count above it. The fix:
  1. with NO active pin, a count that would end the tick above slots.ceiling (GREEN, STEADY, AMBER, or no change at
     all) is set to slots.ceiling at once, in one write; why "above ceiling: <slots> > ceiling <ceiling>"; AMBER at 13
     gives 10, not 12; RED is unchanged (to the floor; the validator keeps floor <= ceiling);
  2. an ACTIVE pin above the ceiling is kept; the tick after the pin ends steps down to the ceiling;
  3. it is a normal step down: last_change and last_down are set, the raise hold applies after it, and it counts as
     one change in the self-check window;
  4. off, observe, dry run and a broken control file write nothing (the supervisor's writes_on rule);
  5. vectors: new slot_decide cases for the rule; the old vectors are unchanged.
Synthetic readings, a fixed clock and temporary data folders only; no live data, no live install."""
import hashlib
import json
import os
import unittest

import mmtest
from mmtest import mmcore, mmread
import mmdecide
import mmrecover
import run_vectors
from slot_trial_helpers import NOW
from test_recovery import Base as RecoveryBase, sampler_of

MIN = 60.0
HOLD = "slots.raise_hold_after_down_minutes"


def why(slots, ceiling=10):
    """The why text of the step down to the ceiling (coder's api commit 3c43924): the count at the start of the tick,
    then the ceiling. It replaces the AMBER, GREEN and event why texts."""
    return "above ceiling: %d > ceiling %d" % (slots, ceiling)


def settings(**over):
    """The defaults with the vectors' machine values (cores 10, floor 3, ceiling 10); GREEN at 50% free and a raise
    after 5 GREEN minutes, so the 15-minute raise hold is the longer rule."""
    return mmtest.base_settings(**dict({"slots.green_free_pct": 50, "slots.raise_green_minutes": 5}, **over))


def inp(now=NOW, mac_state="GREEN", slots=13, free_pct=80.0, **over):
    """Full demand (every slot busy, work waiting), free memory above the raise margin, no pin."""
    d = {"now": now, "mac_state": mac_state, "reasons": [], "slots": slots, "busy": max(slots, 16), "waiting": 3,
         "wx_waiting": False, "override": None, "events": [], "free_pct": free_pct}
    d.update(over)
    return d


def calm_state(now=NOW):
    """GREEN with demand and no change for an hour; no step down ever."""
    return {"last_change": now - 3600, "green_since": now - 3600, "demand_since": now - 3600}


def pin(slots=13, until=NOW + 600, reason="trial"):
    return {"slots": slots, "until": until, "reason": reason}


def decide(state=None, s=None, **over):
    return mmdecide.slot_decide(calm_state() if state is None else state, inp(**over), s or settings())


# ------------------------------------------------------------------------------------------- 1. the step to the ceiling

class GreenAboveCeiling(unittest.TestCase):
    def test_the_finding_13_with_ceiling_10_goes_to_10_at_once(self):
        r = decide()
        self.assertEqual((r["slots"], r["why"]), (10, why(13)))
        self.assertIsNone(r["held"])
        self.assertIsNone(r["problem"])

    def test_without_demand_too(self):
        for over in ({"waiting": 0}, {"busy": 0}, {"wx_waiting": True}):
            with self.subTest(**over):
                self.assertEqual(decide(**over)["slots"], 10)

    def test_a_fresh_green_and_a_fresh_controller_too(self):
        """No GREEN span, no calm time, an empty or missing state: the rule does not wait for a raise's conditions."""
        for st in ({}, None, {"last_change": NOW, "green_since": NOW}):
            with self.subTest(state=st):
                r = mmdecide.slot_decide(st, inp(), settings())
                self.assertEqual((r["slots"], r["why"]), (10, why(13)))

    def test_in_one_step_from_any_count_above(self):
        for slots, ceiling in ((11, 10), (12, 10), (13, 10), (16, 10), (16, 3), (9, 8), (5, 4)):
            with self.subTest(slots=slots, ceiling=ceiling):
                r = decide(slots=slots, s=settings(**{"slots.ceiling": ceiling, "slots.floor": min(3, ceiling)}))
                self.assertEqual((r["slots"], r["why"]), (ceiling, why(slots, ceiling)))

    def test_ceiling_equal_to_the_floor(self):
        s = settings(**{"slots.floor": 4, "slots.ceiling": 4})
        self.assertEqual(decide(slots=7, s=s)["slots"], 4)

    def test_held_rules_do_not_hold_the_step_down(self):
        """The raise's hold rules (after RED, after a trim, after a step down, under the margin) never hold a step down."""
        for st, over in ((dict(calm_state(), last_red=NOW - 60), {}),
                         (dict(calm_state(), last_trim=NOW - 60), {}),
                         (dict(calm_state(), last_down=NOW - 60, last_change=NOW - 60), {}),
                         (calm_state(), {"free_pct": 51.0}),
                         (calm_state(), {"free_pct": None}),
                         (calm_state(), {"events": ["trim"]})):
            with self.subTest(state=st, **over):
                self.assertEqual(decide(state=st, **over)["slots"], 10)

    def test_state_is_not_changed_in_place(self):
        st = calm_state()
        copy = json.loads(json.dumps(st))
        decide(state=st)
        self.assertEqual(st, copy)


class OtherStatesAboveCeiling(unittest.TestCase):
    def test_steady_13_goes_to_10(self):
        r = decide(mac_state="STEADY", reasons=["load5 not under 8"])
        self.assertEqual((r["slots"], r["why"]), (10, why(13)))

    def test_amber_13_goes_to_10_not_12(self):
        r = decide(mac_state="AMBER", reasons=["free 49% < 50%"])
        self.assertEqual((r["slots"], r["why"]), (10, why(13)), "the ceiling's why, not the AMBER why")

    def test_amber_regardless_of_the_step_interval(self):
        cases = (("no step down ever", calm_state(), {}),
                 ("a step down 10 s ago", dict(calm_state(), last_down=NOW - 10, last_change=NOW - 10), {}),
                 ("a step down 119 s ago", dict(calm_state(), last_down=NOW - 119, last_change=NOW - 119), {}),
                 ("interval 3600, step 60 s ago", dict(calm_state(), last_down=NOW - 60, last_change=NOW - 60),
                  {"slots.amber_step_interval_s": 3600}))
        for name, st, s_over in cases:
            with self.subTest(name):
                r = mmdecide.slot_decide(st, inp(mac_state="AMBER", reasons=["x"]), settings(**s_over))
                self.assertEqual((r["slots"], r["why"]), (10, why(13)))

    def test_amber_one_above_the_ceiling(self):
        r = decide(slots=11, mac_state="AMBER", reasons=["x"])
        self.assertEqual((r["slots"], r["why"]), (10, "AMBER: x"), "the step ends AT the ceiling: today's AMBER why")

    def test_timing_failure_and_guard_kill_events_at_13(self):
        for event in ("timing-failure", "guard-kill"):
            for mac_state in ("GREEN", "STEADY"):
                with self.subTest(event=event, mac_state=mac_state):
                    r = decide(mac_state=mac_state, events=[event])
                    self.assertEqual((r["slots"], r["why"]), (10, why(13)))

    def test_every_state_but_red_ends_at_the_ceiling(self):
        """The classify states and any other text (UNKNOWN, as the coder checked): all but RED end at the ceiling."""
        for mac_state in ("GREEN", "STEADY", "AMBER", "UNKNOWN"):
            with self.subTest(mac_state=mac_state):
                r = decide(mac_state=mac_state)
                self.assertEqual((r["slots"], r["why"]), (10, why(13)))


class RedUnchanged(unittest.TestCase):
    def test_red_at_13_goes_to_the_floor(self):
        r = decide(mac_state="RED", reasons=["free 30% < 35%"])
        self.assertEqual((r["slots"], r["why"]), (3, "RED: free 30% < 35%"))

    def test_red_beats_a_pin_above_the_ceiling(self):
        r = decide(mac_state="RED", reasons=["x"], override=pin(13))
        self.assertEqual(r["slots"], 3)

    def test_red_below_the_ceiling_is_todays_rule(self):
        for slots, want in ((10, 3), (5, 3), (3, None)):
            with self.subTest(slots=slots):
                self.assertEqual(decide(slots=slots, mac_state="RED", reasons=["x"])["slots"], want)

    def test_the_validator_keeps_the_floor_at_most_the_ceiling(self):
        flat = dict(mmcore.defaults(), **{"slots.floor": 11, "slots.ceiling": 10})
        self.assertIn("slots.floor > slots.ceiling", mmcore.validate(flat))
        flat = dict(mmcore.defaults(), **{"slots.floor": 10, "slots.ceiling": 10})
        self.assertNotIn("slots.floor > slots.ceiling", mmcore.validate(flat))


# ------------------------------------------------------------------------------------------- 2. the pin

class Pin(unittest.TestCase):
    def test_an_active_pin_above_the_ceiling_is_kept(self):
        for mac_state in ("GREEN", "STEADY"):
            with self.subTest(mac_state=mac_state):
                r = decide(mac_state=mac_state, override=pin(13))
                self.assertEqual((r["slots"], r["why"]), (None, None))

    def test_an_active_pin_still_sets_its_value_above_the_ceiling(self):
        r = decide(slots=10, mac_state="STEADY", override=pin(13))
        self.assertEqual((r["slots"], r["why"]), (13, "pin: trial"))

    def test_a_pin_below_a_count_above_the_ceiling_wins(self):
        r = decide(slots=13, mac_state="STEADY", override=pin(8, reason="cap"))
        self.assertEqual((r["slots"], r["why"]), (8, "pin: cap"))

    def test_amber_under_an_active_pin_is_todays_one_step(self):
        """With an active pin the new rule does not apply: AMBER steps one down, as today."""
        r = decide(mac_state="AMBER", reasons=["x"], override=pin(13))
        self.assertEqual((r["slots"], r["why"]), (12, "AMBER: x"))

    def test_the_tick_after_the_pin_ends_goes_to_the_ceiling(self):
        end = NOW + 120
        st = calm_state()
        r = mmdecide.slot_decide(st, inp(now=NOW, override=pin(13, until=end)), settings())
        self.assertIsNone(r["slots"], "the pin is active")
        st = r["state"]
        r = mmdecide.slot_decide(st, inp(now=NOW + 60, override=pin(13, until=end)), settings())
        self.assertIsNone(r["slots"], "the pin is still active")
        st = r["state"]
        r = mmdecide.slot_decide(st, inp(now=end, override=pin(13, until=end)), settings())
        self.assertEqual((r["slots"], r["why"]), (10, why(13)), "until == now: the pin has ended")

    def test_an_expired_pin_and_no_pin_are_the_same(self):
        for override in (None, pin(13, until=NOW - 1), pin(13, until=0)):
            for mac_state in ("GREEN", "STEADY", "AMBER"):
                with self.subTest(override=override, mac_state=mac_state):
                    self.assertEqual(decide(mac_state=mac_state, override=override)["slots"], 10)

    def test_a_pin_above_16_is_clamped_and_kept(self):
        r = decide(slots=16, mac_state="STEADY", override=pin(20))
        self.assertIsNone(r["slots"], "the pin clamps to 16 and keeps 16")


# ------------------------------------------------------------------------------------------- at and below the ceiling

class AtAndBelowCeiling(unittest.TestCase):
    def test_at_the_ceiling_nothing_changes(self):
        for mac_state in ("GREEN", "STEADY"):
            with self.subTest(mac_state=mac_state):
                r = decide(slots=10, mac_state=mac_state)
                self.assertEqual((r["slots"], r["why"], r["held"]), (None, None, None))
                self.assertEqual(r["state"]["last_change"], NOW - 3600, "no change, no mark")
                self.assertNotIn("last_down", r["state"])

    def test_at_the_ceiling_amber_is_one_step(self):
        r = decide(slots=10, mac_state="AMBER", reasons=["load5 15.0 > 14"])
        self.assertEqual((r["slots"], r["why"]), (9, "AMBER: load5 15.0 > 14"))

    def test_below_the_ceiling_todays_rules(self):
        cases = (("GREEN raise one step", {"slots": 9}, 9 + 1, "GREEN 60 min, 3 waiting, all 9 slots busy"),
                 ("GREEN raise from 5", {"slots": 5}, 6, "GREEN 60 min, 3 waiting, all 5 slots busy"),
                 ("STEADY holds", {"slots": 9, "mac_state": "STEADY"}, None, None),
                 ("AMBER one step", {"slots": 9, "mac_state": "AMBER", "reasons": ["x"]}, 8, "AMBER: x"),
                 ("RED to the floor", {"slots": 9, "mac_state": "RED", "reasons": ["x"]}, 3, "RED: x"),
                 ("GREEN no demand", {"slots": 9, "waiting": 0}, None, None),
                 ("timing failure", {"slots": 9, "mac_state": "STEADY", "events": ["timing-failure"]}, 8,
                  "AMBER: timing-failure"),
                 ("pin", {"slots": 9, "mac_state": "STEADY", "override": pin(7, reason="p")}, 7, "pin: p"))
        for name, over, want, want_why in cases:
            with self.subTest(name):
                r = decide(**over)
                self.assertEqual((r["slots"], r["why"]), (want, want_why))

    def test_a_count_below_the_floor_is_not_raised_without_demand(self):
        """Not in scope (contract): a count below slots.floor is not raised without demand; today's behaviour."""
        for mac_state in ("GREEN", "STEADY"):
            with self.subTest(mac_state=mac_state):
                self.assertIsNone(decide(slots=2, mac_state=mac_state, waiting=0, busy=0)["slots"])


# ------------------------------------------------------------------------------------------- 3. a normal step down

class NormalStepDown(unittest.TestCase):
    def test_last_change_and_last_down_are_set(self):
        r = decide()
        self.assertEqual(r["slots"], 10)
        self.assertEqual((r["state"]["last_change"], r["state"]["last_down"]), (NOW, NOW))

    def test_the_raise_hold_holds_after_the_step(self):
        """13 -> 10 at NOW; the owner then sets 9 by hand; GREEN with full demand: no raise for 15 minutes (the
        hold), although raise_green_minutes (5) has passed; the raise to 10 comes at 15 minutes."""
        s = settings()
        r = decide(s=s)
        self.assertEqual(r["slots"], 10)
        st, out = r["state"], {}
        for m in (1, 5, 6, 10, 14, 14.9, 15):
            got = mmdecide.slot_decide(st, inp(now=NOW + m * MIN, slots=9), s)
            out[m] = got["slots"]
            if m == 6:
                self.assertEqual(got["held"], "raise held: 6 min since the last step down < 15 min")
        self.assertEqual(out, {1: None, 5: None, 6: None, 10: None, 14: None, 14.9: None, 15: 10})

    def test_with_hold_0_the_raise_comes_after_raise_green_minutes(self):
        """Control for the test above: the hold is what waits, not the other raise rules."""
        s = settings(**{HOLD: 0})
        st = decide(s=s)["state"]
        self.assertIsNone(mmdecide.slot_decide(st, inp(now=NOW + 4.9 * MIN, slots=9), s)["slots"])
        self.assertEqual(mmdecide.slot_decide(st, inp(now=NOW + 5 * MIN, slots=9), s)["slots"], 10)

    def test_the_hold_follows_an_amber_step_to_the_ceiling(self):
        s = settings()
        st = decide(mac_state="AMBER", reasons=["x"], s=s)["state"]
        self.assertEqual(st["last_down"], NOW)
        raised = None
        for k in range(1, 21):  # GREEN from NOW + 1 min, the owner's 9 in the file, one tick a minute
            r = mmdecide.slot_decide(st, inp(now=NOW + k * MIN, slots=9), s)
            st = r["state"]
            if r["slots"] is not None:
                raised = (k, r["slots"])
                break
        self.assertEqual(raised, (15, 10), "the hold (15 min), not raise_green_minutes (5)")

    def test_one_change_then_quiet(self):
        """One tick after another at GREEN with demand: one change (13 -> 10), then none for an hour."""
        s, st, slots, changes = settings(), calm_state(), 13, []
        for k in range(60):
            t = NOW + k * MIN
            r = mmdecide.slot_decide(st, inp(now=t, slots=slots), s)
            st = r["state"]
            if r["slots"] is not None and r["slots"] != slots:
                changes.append((k, slots, r["slots"]))
                slots = r["slots"]
        self.assertEqual(changes, [(0, 13, 10)])

    def test_an_invalid_state_never_holds_the_step_down(self):
        for st in ({"last_down": "broken", "last_change": NOW - 3600}, {"last_change": None}, [], False):
            with self.subTest(state=st):
                r = mmdecide.slot_decide(st, inp(), settings())
                self.assertEqual(r["slots"], 10)
                self.assertTrue(r["problem"], "the repair is still reported")


# ------------------------------------------------------------------------------------------- 5. vectors

# sha256 (first 16 hex) of every slot_decide and replay vector at main d2833c7, the base of this change. The change
# adds slot_decide cases and changes none of these; a later change that edits one on purpose updates this list.
OLD_VECTORS = {
    "slot_decide/amber-step-down.json": "4d7693a64bc77fa7",
    "slot_decide/amber-step-interval.json": "1c257012810edb51",
    "slot_decide/amber-step-with-bad-last-down.json": "cbd3c52b94fe42c6",
    "slot_decide/amber-step-with-future-last-down.json": "940135ca798b9834",
    "slot_decide/amber-step-with-null-last-down.json": "f80ba179d0ab300c",
    "slot_decide/event-timing-failure.json": "087d36d177113cf1",
    "slot_decide/green-at-ceiling.json": "083195aa7fd8d5d6",
    "slot_decide/green-bad-last-down-no-raise.json": "b3d132fd6f39de2b",
    "slot_decide/green-down-hold-0-off.json": "6b7ba5735517f498",
    "slot_decide/green-future-last-red-no-raise.json": "2bce28fb2d55258c",
    "slot_decide/green-held-after-down.json": "0df8958b6a417215",
    "slot_decide/green-held-after-red.json": "63a897f6357b756d",
    "slot_decide/green-held-after-repair.json": "faec8a4aa6271b95",
    "slot_decide/green-held-after-trim.json": "0322084a7972ebf1",
    "slot_decide/green-held-free-under-margin.json": "d1f33ad3426692ee",
    "slot_decide/green-held-free-unknown.json": "6f14dd06b64a2793",
    "slot_decide/green-huge-last-change-no-raise.json": "bd36c9f82bd6c082",
    "slot_decide/green-margin-0-no-free-check.json": "f446e29f7df065dc",
    "slot_decide/green-no-demand.json": "8696c49d3dbb889c",
    "slot_decide/green-null-last-change-no-raise.json": "38f88e4504c23ca4",
    "slot_decide/green-null-last-red-no-raise.json": "2a809f46159ebaea",
    "slot_decide/green-null-last-trim-no-raise.json": "d32f4d36c8bd3fea",
    "slot_decide/green-null-spans-are-valid.json": "5c6ad1e9450489f7",
    "slot_decide/green-raise-after-down-hold.json": "56871f2f2f252015",
    "slot_decide/green-raise-after-repair-hold.json": "ba631ee220503e66",
    "slot_decide/green-raise-at-margin.json": "28c789bd277af66e",
    "slot_decide/green-raise-one-step.json": "39a077277074aa91",
    "slot_decide/green-too-short.json": "e8fb88f0ce66b60f",
    "slot_decide/green-wide-waiting.json": "8c9c7ffee428266a",
    "slot_decide/pin-expired.json": "f5b417c6e42fc44e",
    "slot_decide/pin-sets-value.json": "c86c20a0aa1b7013",
    "slot_decide/red-at-floor.json": "52977a91a7db9dab",
    "slot_decide/red-beats-pin.json": "15b55c0e673f6905",
    "slot_decide/red-to-floor.json": "c23de31ce473e9d4",
    "slot_decide/state-false.json": "94fd002473eb56b5",
    "slot_decide/state-not-a-dict.json": "8193b0a59c9059ec",
    "slot_decide/timing-failure-with-null-last-down.json": "33388b64806804bb",
    "replay/incident-0913.json": "db0e23a1128f0b52",
    "replay/incident-1010.json": "0f238cba81bda5e5",
    "replay/incident-1013.json": "dffb98349a8f7904",
    "replay/item1-trial-burst-after-idle-green.json": "d39f1aeb1df0cbf2",
    "replay/item2-free-slot-does-not-count-as-demand.json": "a9ec4c17e53698c8",
    "replay/item2-idle-green-demand-hold.json": "dcec43ba1cbc404d",
    "replay/item2-no-waiter-does-not-count-as-demand.json": "c1c7f93f98b322b8",
}
VEC = os.path.join(mmtest.CODE, "vectors")


def slot_vectors():
    return [(case, v, s) for fn, case, v, s in run_vectors.load_all() if fn == "slot_decide"]


def pin_active(v):
    """An active, valid pin (mmdecide.slot_pin, done2 a37c630): a malformed record is no pin."""
    return mmdecide.slot_pin(v["input"]["inp"].get("override"), v["input"]["inp"]["now"])[0] is not None


class Vectors(unittest.TestCase):
    def test_old_vectors_are_unchanged(self):
        for name, digest in sorted(OLD_VECTORS.items()):
            with self.subTest(name):
                with open(os.path.join(VEC, name), "rb") as f:
                    self.assertEqual(hashlib.sha256(f.read()).hexdigest()[:16], digest)

    def test_every_slot_decide_vector_passes(self):
        for case, v, s in slot_vectors():
            with self.subTest(case):
                got = run_vectors.norm(run_vectors.FUNCTIONS["slot_decide"](v["input"], s))
                self.assertEqual(got, v["expected"])

    def above(self):
        return [(case, v, s) for case, v, s in slot_vectors()
                if v["input"]["inp"]["slots"] > s["slots.ceiling"]]

    def test_new_cases_step_down_to_the_ceiling(self):
        """At least GREEN, STEADY and AMBER above the ceiling without an active pin, each to the ceiling."""
        cases = [(case, v, s) for case, v, s in self.above() if not pin_active(v)
                 and v["input"]["inp"]["mac_state"] != "RED"]
        states = {v["input"]["inp"]["mac_state"] for _, v, _ in cases}
        self.assertLessEqual({"GREEN", "STEADY", "AMBER"}, states, [c for c, _, _ in cases])
        for case, v, s in cases:
            with self.subTest(case):
                e, i = v["expected"], v["input"]["inp"]
                self.assertEqual(e["slots"], s["slots.ceiling"])
                self.assertEqual(e["why"], why(i["slots"], s["slots.ceiling"]))
                self.assertEqual((e["state"]["last_change"], e["state"]["last_down"]), (i["now"], i["now"]))

    def test_new_cases_keep_an_active_pin(self):
        kept = [(case, v, s) for case, v, s in self.above() if pin_active(v) and v["input"]["inp"]["mac_state"] != "RED"
                and v["expected"]["slots"] is None]
        self.assertTrue(kept, "a vector with an active pin above the ceiling that keeps the count")

    def test_a_new_case_after_the_pin_ends(self):
        ended = [case for case, v, s in self.above() if v["input"]["inp"].get("override") and not pin_active(v)
                 and v["expected"]["slots"] == s["slots.ceiling"]]
        self.assertTrue(ended, "a vector with an ended pin above the ceiling that steps down to it")


    def test_new_cases_red_and_a_lower_pin_keep_todays_rules(self):
        """RED above the ceiling goes to the floor with the RED why; an active pin under the count sets the pin."""
        red = [(case, v, s) for case, v, s in self.above() if v["input"]["inp"]["mac_state"] == "RED"]
        lower = [(case, v, s) for case, v, s in self.above() if pin_active(v) and v["input"]["inp"]["mac_state"] != "RED"
                 and v["input"]["inp"]["override"]["slots"] < v["input"]["inp"]["slots"]]
        self.assertTrue(red, "a RED vector above the ceiling")
        self.assertTrue(lower, "a vector with an active pin under a count above the ceiling")
        for case, v, s in red:
            with self.subTest(case):
                self.assertEqual(v["expected"]["slots"], s["slots.floor"])
                self.assertTrue(v["expected"]["why"].startswith("RED: "), v["expected"]["why"])
        for case, v, s in lower:
            with self.subTest(case):
                self.assertEqual(v["expected"]["slots"], v["input"]["inp"]["override"]["slots"])
                self.assertTrue(v["expected"]["why"].startswith("pin: "), v["expected"]["why"])

# ------------------------------------------------------------------------------------------- 4. the supervisor

class Supervisor(RecoveryBase):
    """The supervisor on a fixture queue with full demand and calm GREEN readings; slots 13, ceiling 10."""

    def setUp(self):
        super().setUp()
        real = mmread.disk_free_gb
        mmread.disk_free_gb = lambda *a, **k: 200.0
        self.addCleanup(setattr, mmread, "disk_free_gb", real)

    def build(self, clock, mode="test", slots=13, dry_run=False, free=80, **over):
        """mode "test": act mode on a test slots file; "observe": observe mode with the same test file."""
        f = os.path.join(self.root, "test-slots")
        self.write_settings(**dict({"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10,
                                    "slots.green_free_pct": 50, "slots.raise_green_minutes": 5,
                                    "mode.observe": mode == "observe", "mode.slot_writes": "test",
                                    "mode.slots_file": f}, **over))
        mmcore.write_slots(os.path.join(self.q, "slots"), slots)
        mmcore.write_slots(f, slots)
        sampler = sampler_of(free_pct=free, load1=2, load5=2)
        sup = self.sup(sampler, clock=lambda: clock["t"], dry_run=dry_run)
        read = sup.queue.read
        busy = [{"slot": ".slot.%d" % i, "mode": "S", "pid": None, "label": "S fixture %d" % i, "since": NOW - 60,
                 "kind": None} for i in range(16)]
        tickets = [{"name": "t%d" % i, "mode": "S", "age_s": 60, "label": "S waiting %d" % i, "kind": None}
                   for i in range(3)]
        sup.queue.read = lambda now: dict(read(now), busy=list(busy), tickets=list(tickets))
        return sup, f

    def decisions(self):
        try:
            return open(os.path.join(self.data, "state", "decisions.log")).read()
        except OSError:
            return ""

    def ticks(self, sup, clock, n, step=60):
        for _ in range(n):
            sup.tick()
            clock["t"] += step

    @staticmethod
    def count(path):
        return int(open(path).read().split()[0])

    def test_act_mode_writes_13_to_10_once(self):
        clock = {"t": NOW}
        sup, f = self.build(clock)
        sup.tick()
        self.assertEqual(self.count(f), 10, self.decisions())
        self.assertIn("SET slots 13 -> 10: " + why(13), self.decisions())
        self.assertEqual(self.count(os.path.join(self.q, "slots")), 13, "the queue's slots file is untouched")
        self.assertEqual(json.load(open(os.path.join(self.data, "status.json")))["mode"], "act")
        clock["t"] += 60
        self.ticks(sup, clock, 5)
        self.assertEqual(self.count(f), 10)
        self.assertEqual(sup.state["slot_changes"], [NOW], "one change in the self-check window")
        self.assertEqual(sup.state["controller"]["last_down"], NOW)

    def test_act_mode_amber_writes_10_not_12(self):
        clock = {"t": NOW}
        sup, f = self.build(clock, free=45)  # AMBER: under slots.amber_free_pct 50
        sup.tick()
        self.assertIn("AMBER", json.load(open(os.path.join(self.data, "status.json")))["state"])
        self.assertEqual(self.count(f), 10, self.decisions())

    def test_act_mode_the_raise_hold_after_the_step(self):
        """13 -> 10 at NOW; the owner writes 9 into the file; the raise to 10 waits for the 15-minute hold."""
        clock = {"t": NOW}
        sup, f = self.build(clock)
        sup.tick()
        self.assertEqual(self.count(f), 10, self.decisions())
        mmcore.write_slots(f, 9)
        clock["t"] += 60
        raised = None
        while clock["t"] <= NOW + 20 * MIN and raised is None:
            sup.tick()
            if self.count(f) > 9:
                raised = clock["t"]
            clock["t"] += 60
        self.assertIsNotNone(raised, self.decisions())
        self.assertGreaterEqual(raised, NOW + 15 * MIN, "no raise before the hold ends: %s" % self.decisions())
        self.assertIn("raise held: ", self.decisions())

    def test_act_mode_a_pin_above_the_ceiling_is_kept_until_it_ends(self):
        clock = {"t": NOW}
        sup, f = self.build(clock)
        mmcore.write_atomic(mmcore.path("override.json"), json.dumps(pin(13, until=NOW + 180)))
        self.ticks(sup, clock, 3)  # NOW, +60, +120: the pin is active
        self.assertEqual(self.count(f), 13, self.decisions())
        self.assertNotIn("SET slots 13 -> 10", self.decisions())
        self.ticks(sup, clock, 1)  # NOW + 180: until == now, the pin has ended
        self.assertEqual(self.count(f), 10, self.decisions())
        self.assertIn("SET slots 13 -> 10: " + why(13), self.decisions())

    # ---- 4. no write in off, observe, dry run, or with a broken control file

    def assert_no_write(self, f):
        self.assertEqual(self.count(f), 13, self.decisions())
        self.assertEqual(self.count(os.path.join(self.q, "slots")), 13)
        self.assertNotIn("SET slots", self.decisions())

    def test_observe_writes_nothing(self):
        clock = {"t": NOW}
        sup, f = self.build(clock, mode="observe")
        self.ticks(sup, clock, 3)
        self.assert_no_write(f)

    def test_off_writes_nothing(self):
        mmcore.write_atomic(os.path.join(self.data, "off.json"), json.dumps({"off": True, "since": "x", "reason": "t"}))
        clock = {"t": NOW}
        sup, f = self.build(clock)
        self.ticks(sup, clock, 3)
        self.assert_no_write(f)

    def test_dry_run_writes_nothing(self):
        clock = {"t": NOW}
        sup, f = self.build(clock, dry_run=True)
        self.ticks(sup, clock, 3)
        self.assert_no_write(f)

    def test_a_broken_safe_json_writes_nothing(self):
        with open(os.path.join(self.data, "safe.json"), "w") as fh:
            fh.write("{broken")
        clock = {"t": NOW}
        sup, f = self.build(clock)
        self.ticks(sup, clock, 3)
        self.assert_no_write(f)

    def assert_one_would_line(self, sup, clock, f):
        """The decision is still made and logged as a WOULD line, once."""
        self.ticks(sup, clock, 3)
        lines = [l for l in self.decisions().splitlines() if "WOULD slots 13 -> 10" in l]
        self.assertEqual(len(lines), 1, self.decisions())
        self.assertTrue(lines[0].endswith(": " + why(13)), lines)
        self.assertEqual(self.count(f), 13)

    def test_observe_logs_the_would_line(self):
        clock = {"t": NOW}
        sup, f = self.build(clock, mode="observe")
        self.assert_one_would_line(sup, clock, f)

    def test_off_logs_the_would_line(self):
        mmcore.write_atomic(os.path.join(self.data, "off.json"), json.dumps({"off": True, "since": "x", "reason": "t"}))
        clock = {"t": NOW}
        sup, f = self.build(clock)
        self.assert_one_would_line(sup, clock, f)

    def test_dry_run_logs_the_would_line(self):
        clock = {"t": NOW}
        sup, f = self.build(clock, dry_run=True)
        self.assert_one_would_line(sup, clock, f)

    # ---- safe mode (valid safe.json): slot writes stay on (coordinator, correction of contract item 4): the first
    # tick writes min(cur, safe_mode.slots); after that every step down goes through and only raises are refused

    def test_safe_mode_lowers_to_safe_mode_slots_as_today(self):
        clock = {"t": NOW}
        sup, f = self.build(clock)
        mmrecover.enter_safe("test", NOW)
        self.ticks(sup, clock, 3)
        self.assertEqual(self.count(f), 5, self.decisions())
        self.assertIn("SET slots 13 -> 5: safe mode", self.decisions())

    def test_safe_mode_slots_above_the_ceiling_still_end_at_the_ceiling(self):
        """safe_mode.slots 12 > ceiling 10: the safe-mode write gives at most 12, a step down to 10 follows."""
        clock = {"t": NOW}
        sup, f = self.build(clock, **{"safe_mode.slots": 12})
        mmrecover.enter_safe("test", NOW)
        self.ticks(sup, clock, 1)
        self.assertEqual(self.count(f), 12, self.decisions())
        self.assertIn("SET slots 13 -> 12: safe mode: at most 12 slots", self.decisions())
        self.ticks(sup, clock, 2)
        self.assertEqual(self.count(f), 10, self.decisions())
        self.assertIn("SET slots 12 -> 10: " + why(12), self.decisions())


del RecoveryBase

if __name__ == "__main__":
    unittest.main()
