# SPDX-License-Identifier: Apache-2.0
"""Slot hysteresis at the free-memory border (written from the contract, not from the code).

Free memory that sits at 49-51% around slots.amber_free_pct (50) made the slot count flap: AMBER stepped it down,
GREEN raised it again, and the self-check tripped safe mode on the changes per hour. The fix:
  1. a GREEN raise also needs free_pct >= slots.amber_free_pct + slots.raise_free_margin_pct (default 5; 0 = old);
     free_pct None (unknown) gives no raise;
  2. no raise until slots.raise_hold_after_down_minutes (default 15; 0 = off) after the last step down; the longer
     of this and the existing rules wins;
  3. `mm on` and `mm restart --clear-safe` start a fresh self-check window: only slot changes after the clear count;
  4. the "why" of a refused raise is visible where today's refusals are;
  5. both settings have a default, a range and a schema entry.
Synthetic readings and a fixed clock only; no live data, no live install."""
import json
import os
import random
import time
import unittest
from unittest import mock

import mmtest
from mmtest import TempData, mmcore, mmread
import mmdecide
import mmrecover
import mmsuper
from slot_trial_helpers import NOW, sample
from test_recovery import Base as RecoveryBase, sampler_of, FAKE_LAUNCHCTL, SUP

MARGIN = "slots.raise_free_margin_pct"
HOLD = "slots.raise_hold_after_down_minutes"
MIN = 60.0


def settings(**over):
    """The defaults with the vectors' machine values (cores 10, floor 3, ceiling 10), plus the two border values of
    the finding: GREEN at 51% free (slots.green_free_pct 50) and a raise after 5 GREEN minutes."""
    return mmtest.base_settings(**dict({"slots.green_free_pct": 50, "slots.raise_green_minutes": 5}, **over))


def old(**over):
    """Today's behaviour: margin 0 and hold 0."""
    return settings(**dict({MARGIN: 0, HOLD: 0}, **over))


def inp(now, mac_state="GREEN", free_pct=80.0, slots=5, **over):
    """Full demand: every slot busy and work waiting (the raise rules other than the new ones all pass)."""
    d = {"now": now, "mac_state": mac_state, "reasons": [], "slots": slots, "busy": max(slots, 9), "waiting": 3,
         "wx_waiting": False, "override": None, "events": [], "free_pct": free_pct}
    d.update(over)
    return d


def calm_state(now):
    """A controller that has been GREEN with demand and no change for an hour."""
    return {"last_change": now - 3600, "green_since": now - 3600, "demand_since": now - 3600}


def simulate(free_at, s, minutes=60, tick_s=60, slots=6, start=NOW):
    """60 simulated minutes: one sample per tick, classify on the last 31 minutes, then one slot_decide step.
    Returns (changes [(t, old, new, why)], states [mac_state per tick], final slots)."""
    window, st, changes, states = [], {}, [], []
    for k in range(int(minutes * 60 / tick_s)):
        t = start + k * tick_s
        free = free_at(k, t)
        window.append(sample(t=t, free_pct=free))
        window = [x for x in window if t - x["t"] <= 1860]
        mac_state, reasons, complete = mmdecide.classify(window, s)
        states.append(mac_state)
        r = mmdecide.slot_decide(st, inp(t, mac_state, free, slots, reasons=reasons), s)
        st = r["state"]
        if r["slots"] is not None and r["slots"] != slots:
            changes.append((t - start, slots, r["slots"], r["why"]))
            slots = r["slots"]
    return changes, states, slots


def border_cycle(k, t):
    """A 7-minute cycle: one minute at 49% (AMBER), six at 51% (GREEN)."""
    return 49.0 if k % 7 == 0 else 51.0


def jitter(seed, tick_s=10):
    """Random segments inside 49-51%: 1-2 minutes at 49.0-49.9% (AMBER), then 5-9 minutes at 50.0-51.0% (GREEN),
    with a new random value every tick inside the segment's band."""
    rnd = random.Random(seed)
    bands = []
    while len(bands) * tick_s < 3600:
        amber = rnd.randint(1, 2) * 60 // tick_s
        green = rnd.randint(5, 9) * 60 // tick_s
        bands += [(49.0, 49.9)] * amber + [(50.0, 51.0)] * green
    values = [round(rnd.uniform(lo, hi), 1) for lo, hi in bands]
    return lambda k, t: values[k]


# ------------------------------------------------------------------------------------------- 1. the oscillation

class Oscillation(unittest.TestCase):
    def test_the_fixture_is_the_border_of_the_finding(self):
        _, states, _ = simulate(border_cycle, settings())
        self.assertEqual(set(states), {"AMBER", "GREEN"}, "49% is AMBER and 51% is GREEN with these settings")

    def test_old_behaviour_with_margin_0_and_hold_0_flaps_over_the_limit(self):
        changes, _, _ = simulate(border_cycle, old())
        downs = [c[0] / MIN for c in changes if c[2] < c[1]]
        ups = [c[0] / MIN for c in changes if c[2] > c[1]]
        self.assertEqual(downs, [0, 7, 14, 21, 28, 35, 42, 49, 56], changes)
        self.assertEqual(ups, [6, 13, 20, 27, 34, 41, 48, 55], changes)
        self.assertEqual(len(changes), 17)
        self.assertGreater(len(changes), settings()["self.max_slot_changes_per_hour"], "the finding: over the limit")
        self.assertEqual([c[1:3] for c in changes[:2]], [(6, 5), (5, 6)])

    def test_defaults_give_at_most_3_changes_in_the_hour(self):
        changes, _, final = simulate(border_cycle, settings())
        self.assertLessEqual(len(changes), 3, changes)
        self.assertTrue(all(c[2] < c[1] for c in changes), "no raise below 55%% free: %r" % changes)

    def test_defaults_keep_the_down_steps_of_the_old_behaviour(self):
        new, _, _ = simulate(border_cycle, settings())
        before, _, _ = simulate(border_cycle, old())
        self.assertEqual([c[:3] for c in new], [(0, 6, 5), (7 * MIN, 5, 4), (14 * MIN, 4, 3)])
        self.assertEqual([c[3] for c in new], [c[3] for c in before if c[2] < c[1]][:3], "the same AMBER why text")

    def test_random_free_memory_between_49_and_51_gives_at_most_3_changes(self):
        for seed in range(20):
            with self.subTest(seed=seed):
                changes, states, _ = simulate(jitter(seed), settings(), tick_s=10)
                self.assertIn("AMBER", states)
                self.assertLessEqual(len(changes), 3, changes)
                self.assertTrue(all(c[2] < c[1] for c in changes), changes)

    def test_random_border_with_margin_0_and_hold_0_still_raises(self):
        """Control for the test above: the same readings raise in the old behaviour (the scenario has demand)."""
        counts = []
        for seed in range(20):
            changes, _, _ = simulate(jitter(seed), old(), tick_s=10)
            self.assertTrue(any(c[2] > c[1] for c in changes), seed)
            counts.append(len(changes))
        self.assertGreaterEqual(min(counts), 10, counts)
        self.assertGreater(max(counts), settings()["self.max_slot_changes_per_hour"], counts)

    def test_margin_alone_or_hold_alone(self):
        only_margin, _, _ = simulate(border_cycle, settings(**{HOLD: 0}))
        self.assertTrue(all(c[2] < c[1] for c in only_margin), only_margin)
        self.assertLessEqual(len(only_margin), 3)
        only_hold, _, _ = simulate(border_cycle, settings(**{MARGIN: 0}))
        ups = [c for c in only_hold if c[2] > c[1]]
        downs = [c for c in only_hold if c[2] < c[1]]
        self.assertEqual(ups, [], "a down every 7 minutes keeps the 15-minute hold on: %r" % only_hold)
        self.assertEqual(len(downs), 3)

    def test_a_slower_cycle_with_margin_0_raises_only_after_the_hold(self):
        """One AMBER minute every 20 minutes, 51% between: with margin 0 the hold alone decides the raise time."""
        changes, _, _ = simulate(lambda k, t: 49.0 if k % 20 == 0 else 51.0, settings(**{MARGIN: 0}))
        downs = [c[0] / MIN for c in changes if c[2] < c[1]]
        ups = [c[0] / MIN for c in changes if c[2] > c[1]]
        self.assertEqual(downs, [0, 20, 40])
        self.assertEqual(ups, [15, 35, 55], "15 minutes after each down, not 5")


# ------------------------------------------------------------------------------------------- 1. the raise margin

class RaiseMargin(unittest.TestCase):
    def decide(self, free, s=None, state=None, **over):
        return mmdecide.slot_decide(state or calm_state(NOW), inp(NOW, free_pct=free, **over), s or settings())

    def test_defaults(self):
        d = mmcore.defaults()
        self.assertEqual((d[MARGIN], d[HOLD]), (5, 15))
        self.assertEqual(mmcore.validate(d), [])

    def test_raise_at_55_and_not_under(self):
        for free, want in ((51.0, None), (54.0, None), (54.9, None), (54.99, None), (55.0, 6), (55.1, 6), (80.0, 6)):
            with self.subTest(free=free):
                self.assertEqual(self.decide(free)["slots"], want)

    def test_margin_follows_amber_free_pct(self):
        s = settings(**{"slots.amber_free_pct": 40, "slots.red_free_pct": 30, "slots.green_free_pct": 40})
        self.assertIsNone(self.decide(44.9, s)["slots"])
        self.assertEqual(self.decide(45.0, s)["slots"], 6)

    def test_own_margin_value(self):
        for margin, edge in ((1, 51.0), (10, 60.0), (50, 100.0)):
            with self.subTest(margin=margin):
                s = settings(**{MARGIN: margin})
                self.assertEqual(self.decide(edge, s)["slots"], 6)
                self.assertIsNone(self.decide(edge - 0.1, s)["slots"])

    def test_margin_0_has_no_free_check_of_its_own(self):
        """Margin 0 = today's behaviour: slot_decide does not check free memory (classify alone decides GREEN), so a
        GREEN input raises at any free value, also under slots.amber_free_pct."""
        s = settings(**{MARGIN: 0})
        for free in (49.9, 50.0, 20.0, None):
            with self.subTest(free=free):
                r = self.decide(free, s)
                self.assertEqual((r["slots"], r["held"]), (6, None))

    def test_margin_0_is_the_old_rule(self):
        s = settings(**{MARGIN: 0, HOLD: 0})
        self.assertEqual(self.decide(50.0, s)["slots"], 6)
        self.assertEqual(self.decide(51.0, s)["slots"], 6)

    def test_unknown_free_memory_gives_no_raise(self):
        for margin in (1, 5, 50):
            with self.subTest(margin=margin):
                r = self.decide(None, settings(**{MARGIN: margin}))
                self.assertIsNone(r["slots"])
                self.assertEqual(r["held"], "raise held: free memory unknown")

    def test_margin_0_with_unknown_free_memory_is_todays_raise(self):
        """Contract: margin 0 = today's behaviour; today slot_decide raises on GREEN without a free value."""
        self.assertEqual(self.decide(None, settings(**{MARGIN: 0, HOLD: 0}))["slots"], 6)

    def test_a_missing_free_pct_key_is_unknown_too(self):
        i = inp(NOW)
        del i["free_pct"]
        r = mmdecide.slot_decide(calm_state(NOW), i, settings())
        self.assertEqual((r["slots"], r["held"]), (None, "raise held: free memory unknown"))

    def test_margin_never_stops_a_raise_for_other_reasons_only(self):
        """The margin is on free memory only: high free memory with every old rule met raises at once."""
        self.assertEqual(self.decide(99.0)["slots"], 6)

    def test_the_old_raise_rules_still_apply_above_the_margin(self):
        st = calm_state(NOW)
        self.assertIsNone(self.decide(80.0, waiting=0)["slots"], "no demand")
        self.assertIsNone(self.decide(80.0, wx_waiting=True)["slots"], "a wide job waits")
        self.assertIsNone(self.decide(80.0, slots=10)["slots"], "at the ceiling")
        self.assertIsNone(self.decide(80.0, mac_state="STEADY")["slots"], "STEADY never raises")
        self.assertIsNone(self.decide(80.0, state=dict(st, last_red=NOW - 600))["slots"], "held after RED")
        self.assertIsNone(self.decide(80.0, state=dict(st, last_change=NOW - 60))["slots"], "a change 1 min ago")

    def test_held_text_for_free_memory_under_the_margin(self):
        r = self.decide(52.0)
        self.assertEqual((r["slots"], r["held"]), (None, "raise held: free 52% < 55% (amber 50% + margin 5%)"))
        s = settings(**{MARGIN: 10})
        self.assertEqual(self.decide(51.0, s)["held"], "raise held: free 51% < 60% (amber 50% + margin 10%)")
        self.assertEqual(self.decide(54.6)["held"], "raise held: free 54.6% < 55% (amber 50% + margin 5%)",
                         "%g: a fraction is shown, never rounded up to the border")
        s = settings(**{MARGIN: 2.5, "slots.amber_free_pct": 47.5, "slots.red_free_pct": 30})
        self.assertEqual(self.decide(49.5, s)["held"], "raise held: free 49.5% < 50% (amber 47.5% + margin 2.5%)")

    def test_held_is_none_on_a_raise_and_when_an_old_rule_refuses(self):
        self.assertIsNone(self.decide(80.0)["held"])
        for over in ({"waiting": 0}, {"wx_waiting": True}, {"slots": 10}, {"mac_state": "STEADY"},
                     {"mac_state": "AMBER"}, {"mac_state": "RED"}):
            with self.subTest(**over):
                self.assertIsNone(self.decide(51.0, **over)["held"])
        self.assertIsNone(self.decide(51.0, state=dict(calm_state(NOW), last_red=NOW - 600))["held"])
        self.assertIsNone(self.decide(51.0, state=dict(calm_state(NOW), last_change=NOW - 60))["held"])

    def test_held_key_is_always_present(self):
        for free, state in ((80.0, "GREEN"), (51.0, "GREEN"), (49.0, "AMBER"), (30.0, "RED")):
            self.assertIn("held", mmdecide.slot_decide(calm_state(NOW), inp(NOW, state, free, slots=6), settings()))

    def test_a_hold_does_not_count_as_a_change(self):
        st = calm_state(NOW)
        r = self.decide(52.0, state=st)
        self.assertEqual(r["state"]["last_change"], st["last_change"])
        self.assertNotIn("last_down", r["state"])

    def test_unknown_comes_before_free_and_free_before_down(self):
        st = dict(calm_state(NOW), last_down=NOW - 6 * MIN)
        self.assertEqual(self.decide(None, state=st)["held"], "raise held: free memory unknown")
        self.assertTrue(self.decide(52.0, state=st)["held"].startswith("raise held: free 52% < 55%"))
        self.assertEqual(self.decide(60.0, state=st)["held"], "raise held: 6 min since the last step down < 15 min")

    def test_one_step_at_a_time(self):
        self.assertEqual(self.decide(90.0, slots=7)["slots"], 8)


# ------------------------------------------------------------------------------------------- 2. the hold after a down

class HoldAfterDown(unittest.TestCase):
    def after_down(self, s, down_at=NOW, minutes=(14.9, 15.0), free=60.0):
        """A step down at `down_at`, then GREEN with demand and free memory above the margin."""
        st = {"last_change": down_at, "last_down": down_at, "green_since": down_at, "demand_since": down_at - 3600}
        out = {}
        for m in minutes:
            r = mmdecide.slot_decide(st, inp(down_at + m * MIN, free_pct=free), s)
            out[m] = r["slots"]
        return out

    def test_no_raise_for_15_minutes_after_a_down(self):
        got = self.after_down(settings(), minutes=(5.0, 10.0, 14.0, 14.99, 15.0, 16.0))
        self.assertEqual(got, {5.0: None, 10.0: None, 14.0: None, 14.99: None, 15.0: 6, 16.0: 6})

    def test_held_text_for_the_hold(self):
        st = {"last_change": NOW, "last_down": NOW, "green_since": NOW, "demand_since": NOW - 3600}
        r = mmdecide.slot_decide(st, inp(NOW + 6 * MIN, free_pct=60.0), settings())
        self.assertEqual((r["slots"], r["held"]), (None, "raise held: 6 min since the last step down < 15 min"))

    def test_the_hold_counts_from_the_last_down_through_the_controller(self):
        """AMBER steps down at t=0; GREEN at 60% from t=1 min: the raise comes at t=15 min, not at t=5 min."""
        s = settings()
        st = calm_state(NOW)
        r = mmdecide.slot_decide(st, inp(NOW, "AMBER", 49.0, slots=6), s)
        self.assertEqual(r["slots"], 5)
        st, slots, raised = r["state"], 5, None
        for k in range(1, 31):
            t = NOW + k * MIN
            r = mmdecide.slot_decide(st, inp(t, "GREEN", 60.0, slots=slots), s)
            st = r["state"]
            if r["slots"] is not None:
                raised = (k, r["slots"])
                break
        self.assertEqual(raised, (15, 6))

    def test_own_hold_value(self):
        for hold, edge in ((30, 30.0), (60, 60.0), (240, 240.0)):
            with self.subTest(hold=hold):
                got = self.after_down(settings(**{HOLD: hold}), minutes=(edge - 0.5, edge))
                self.assertEqual(got, {edge - 0.5: None, edge: 6})

    def test_hold_0_leaves_the_old_wait(self):
        got = self.after_down(settings(**{HOLD: 0}), minutes=(4.9, 5.0))
        self.assertEqual(got, {4.9: None, 5.0: 6}, "slots.raise_green_minutes (5) alone")

    def test_the_longer_rule_wins(self):
        got = self.after_down(settings(**{"slots.raise_green_minutes": 20}), minutes=(15.0, 19.9, 20.0))
        self.assertEqual(got, {15.0: None, 19.9: None, 20.0: 6}, "raise_green_minutes 20 > hold 15")
        s = settings(**{"slots.hold_after_red_minutes": 30})
        st = {"last_change": NOW, "last_down": NOW, "last_red": NOW, "green_since": NOW, "demand_since": NOW - 3600}
        self.assertIsNone(mmdecide.slot_decide(st, inp(NOW + 15 * MIN, free_pct=60.0), s)["slots"], "red hold 30")
        self.assertEqual(mmdecide.slot_decide(st, inp(NOW + 30 * MIN, free_pct=60.0), s)["slots"], 6)

    def test_no_down_ever_means_no_hold(self):
        st = calm_state(NOW)
        self.assertNotIn("last_down", st)
        self.assertEqual(mmdecide.slot_decide(st, inp(NOW, free_pct=60.0), settings())["slots"], 6)

    def test_an_old_down_does_not_hold(self):
        st = dict(calm_state(NOW), last_down=NOW - 3600)
        self.assertEqual(mmdecide.slot_decide(st, inp(NOW, free_pct=60.0), settings())["slots"], 6)

    def test_a_later_down_restarts_the_hold(self):
        s = settings()
        st = {"last_change": NOW, "last_down": NOW, "green_since": None, "demand_since": NOW - 3600}
        r = mmdecide.slot_decide(st, inp(NOW + 10 * MIN, "AMBER", 49.0, slots=5), s)
        self.assertEqual(r["slots"], 4)
        st = r["state"]
        for m, want in ((15.0, None), (24.9, None), (25.0, 5)):
            got = mmdecide.slot_decide(st, inp(NOW + m * MIN, free_pct=60.0, slots=4), s)
            self.assertEqual(got["slots"], want, m)

    def test_a_raise_does_not_start_a_hold(self):
        s = settings()
        st = dict(calm_state(NOW))
        r = mmdecide.slot_decide(st, inp(NOW, free_pct=60.0, slots=5), s)
        self.assertEqual(r["slots"], 6)
        r2 = mmdecide.slot_decide(r["state"], inp(NOW + 5 * MIN, free_pct=60.0, slots=6), s)
        self.assertEqual(r2["slots"], 7, "the next raise after raise_green_minutes, no 15-minute hold")


# ------------------------------------------------------------------------------------------- unchanged paths

class Unchanged(unittest.TestCase):
    def test_amber_steps_down_at_once_during_a_hold_and_under_the_margin(self):
        s = settings()
        st = {"last_change": NOW - 3 * MIN, "last_down": NOW - 3 * MIN, "green_since": None}
        for free in (49.0, None):
            r = mmdecide.slot_decide(st, inp(NOW, "AMBER", free, slots=6, reasons=["free 49% < 50%"]), s)
            self.assertEqual(r["slots"], 5, free)
            self.assertTrue(r["why"].startswith("AMBER: "), r["why"])

    def test_amber_step_interval_is_unchanged(self):
        s = settings()
        for gap, want in ((60, None), (119, None), (120, 5)):
            st = {"last_change": NOW - gap, "last_down": NOW - gap}
            self.assertEqual(mmdecide.slot_decide(st, inp(NOW, "AMBER", 49.0, slots=6), s)["slots"], want, gap)

    def test_amber_stops_at_the_floor(self):
        self.assertIsNone(mmdecide.slot_decide({}, inp(NOW, "AMBER", 49.0, slots=3), settings())["slots"])

    def test_timing_failure_still_steps_down(self):
        r = mmdecide.slot_decide(calm_state(NOW), inp(NOW, "STEADY", 60.0, slots=6, events=["timing-failure"]),
                                 settings())
        self.assertEqual(r["slots"], 5)

    def test_red_goes_to_the_floor_during_a_hold_and_with_unknown_free_memory(self):
        s = settings()
        st = {"last_change": NOW - 60, "last_down": NOW - 60}
        for free in (30.0, None, 80.0):
            r = mmdecide.slot_decide(st, inp(NOW, "RED", free, slots=8, reasons=["free 30% < 35%"]), s)
            self.assertEqual((r["slots"], r["why"]), (3, "RED: free 30% < 35%"), free)

    def test_red_same_as_old_settings(self):
        for s in (settings(), old()):
            r = mmdecide.slot_decide(calm_state(NOW), inp(NOW, "RED", 30.0, slots=7, reasons=["x"]), s)
            self.assertEqual(r["slots"], 3)

    def test_pin_raises_during_the_hold_and_under_the_margin(self):
        pin = {"slots": 7, "until": NOW + 600, "reason": "test"}
        st = {"last_change": NOW - 60, "last_down": NOW - 60}
        for free in (51.0, None):
            r = mmdecide.slot_decide(st, inp(NOW, "STEADY", free, slots=4, override=pin), settings())
            self.assertEqual((r["slots"], r["why"]), (7, "pin: test"), free)

    def test_pin_still_caps_and_red_still_beats_the_pin(self):
        pin = {"slots": 5, "until": NOW + 600, "reason": "cap"}
        r = mmdecide.slot_decide(calm_state(NOW), inp(NOW, "GREEN", 80.0, slots=5, override=pin), settings())
        self.assertIsNone(r["slots"], "GREEN at the pin: no raise above it")
        r = mmdecide.slot_decide(calm_state(NOW), inp(NOW, "RED", 80.0, slots=5, override=pin), settings())
        self.assertEqual(r["slots"], 3)

    def test_expired_pin_falls_back_to_the_new_raise_rules(self):
        pin = {"slots": 7, "until": NOW - 1, "reason": "old"}
        r = mmdecide.slot_decide(calm_state(NOW), inp(NOW, "GREEN", 51.0, slots=5, override=pin), settings())
        self.assertIsNone(r["slots"], "51% is under the margin")

    def test_state_is_not_changed_in_place(self):
        st = {"last_change": NOW - 60, "last_down": NOW - 60}
        copy = json.loads(json.dumps(st))
        mmdecide.slot_decide(st, inp(NOW, free_pct=51.0), settings())
        self.assertEqual(st, copy)


# ------------------------------------------------------------------------------------------- 5. settings

class SettingsRanges(unittest.TestCase):
    def problems(self, key, value):
        return [p for p in mmcore.validate(dict(mmcore.defaults(), **{key: value})) if p.startswith(key)]

    def test_margin_range_0_to_50(self):
        for v in (0, 1, 5, 25, 50):
            self.assertEqual(self.problems(MARGIN, v), [], v)
        for v in (-1, -0.1, 50.1, 51, 100, "5", True, None):
            self.assertEqual(len(self.problems(MARGIN, v)), 1, v)

    def test_hold_range_0_to_240(self):
        for v in (0, 1, 15, 240):
            self.assertEqual(self.problems(HOLD, v), [], v)
        for v in (-1, 240.5, 241, 1000, "15", False, None):
            self.assertEqual(len(self.problems(HOLD, v)), 1, v)

    def test_a_missing_key_is_a_problem(self):
        for key in (MARGIN, HOLD):
            flat = mmcore.defaults()
            del flat[key]
            self.assertIn(key + ": missing", mmcore.validate(flat))

    def test_schema_file_has_both_with_range(self):
        here = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        schema = json.load(open(os.path.join(here, "schemas", "settings.schema.json")))
        for key, hi in ((MARGIN, 50), (HOLD, 240)):
            with self.subTest(key=key):
                self.assertIn(key, schema["required"])
                p = schema["properties"][key]
                self.assertEqual((p.get("minimum"), p.get("maximum")), (0, hi))
                self.assertIn(p.get("type"), ("number", "integer"))


class SettingsFile(TempData):
    def test_a_bad_value_in_settings_toml_is_refused(self):
        for key, bad in ((MARGIN, 51), (MARGIN, -1), (HOLD, 241), (HOLD, -1)):
            with self.subTest(key=key, bad=bad):
                self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, key: bad})
                st = mmcore.Settings()
                st.load(save=False)
                self.assertTrue(st.problem and key in st.problem, st.problem)

    def test_good_values_load(self):
        self.write_settings(**{"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10, MARGIN: 0, HOLD: 240})
        st = mmcore.Settings()
        values = st.load(save=False)
        self.assertFalse(st.problem, st.problem)
        self.assertEqual((values[MARGIN], values[HOLD]), (0, 240))

    def test_settings_show_lists_both_with_their_defaults(self):
        r = self.mm("settings", "show", "slots")
        self.assertEqual(r.returncode, 0, r.stderr)
        for key, default in ((MARGIN, "5"), (HOLD, "15")):
            line = [l for l in r.stdout.splitlines() if l.startswith(key + "=")]
            self.assertEqual(line, ["%s=%s default=%s differs=no" % (key, default, default)], r.stdout)


# ------------------------------------------------------------------------------------------- 3. the self-check window

def changes_at(*times):
    return sorted(times)


class SelfCheckWindow(unittest.TestCase):
    def check(self, changes, cleared_at, now=NOW, **over):
        s = settings(**over)
        return mmdecide.self_check({}, {"now": now, "slot_changes": changes, "cleared_at": cleared_at,
                                        "data_writable": True, "data_free_mb": 10000}, s)

    def test_no_clear_counts_the_whole_hour(self):
        self.assertEqual(self.check([NOW - 60 * k for k in range(13)], None)["action"], "safe")
        self.assertEqual(self.check([NOW - 60 * k for k in range(12)], None)["action"], "ok")

    def test_changes_before_the_clear_do_not_count(self):
        old = [NOW - 600 - 60 * k for k in range(20)]
        self.assertEqual(self.check(old, NOW - 300)["action"], "ok")

    def test_changes_after_the_clear_still_count(self):
        old = [NOW - 1800 - 60 * k for k in range(20)]
        after12 = [NOW - 10 * k for k in range(12)]
        after13 = [NOW - 10 * k for k in range(13)]
        self.assertEqual(self.check(old + after12, NOW - 1000)["action"], "ok", "12 after the clear: at the limit")
        r = self.check(old + after13, NOW - 1000)
        self.assertEqual(r["action"], "safe")
        self.assertTrue(any("changed 13 times" in x for x in r["reasons"]), r["reasons"])

    def test_a_change_at_the_clear_time_does_not_count(self):
        cleared = NOW - 1000
        self.assertEqual(self.check([cleared] + [NOW - 10 * k for k in range(12)], cleared)["action"], "ok")
        self.assertEqual(self.check([cleared + 0.001] + [NOW - 10 * k for k in range(12)], cleared)["action"], "safe")

    def test_the_hour_still_applies_after_a_clear(self):
        changes = [NOW - 3600 - k for k in range(5)] + [NOW - 10 * k for k in range(12)]
        self.assertEqual(self.check(changes, NOW - 7200)["action"], "ok", "an old clear widens nothing")

    def test_a_clear_in_the_future_is_not_used(self):
        self.assertEqual(self.check([NOW - 60 * k for k in range(13)], NOW + 600)["action"], "safe")

    def test_own_limit_applies_after_the_clear(self):
        after = [NOW - 10 * k for k in range(5)]
        self.assertEqual(self.check(after, NOW - 1000, **{"self.max_slot_changes_per_hour": 4})["action"], "safe")
        self.assertEqual(self.check(after, NOW - 1000, **{"self.max_slot_changes_per_hour": 5})["action"], "ok")

    def test_in_safe_mode_the_answer_is_alert_not_safe(self):
        r = mmdecide.self_check({}, {"now": NOW, "slot_changes": [NOW - k for k in range(13)], "cleared_at": None,
                                     "safe": True}, settings())
        self.assertEqual(r["action"], "alert")


# ------------------------------------------------------------------------------------------- 3. the clear record

class ClearRecord(RecoveryBase):
    def clear_file(self):
        return os.path.join(self.data, "state", "self-check-clear.json")

    def trip(self, sup, now):
        sup.state["slot_changes"] = [now - 60 * k for k in range(13)]
        self.assertEqual(sup.check_self(0.1, 0)["action"], "safe")
        self.assertIsNotNone(mmcore.safe_state())

    def test_mm_on_after_a_safe_trip_starts_a_fresh_window(self):
        clock = {"t": time.time()}
        sup = self.sup(clock=lambda: clock["t"])
        self.trip(sup, clock["t"])
        clock["t"] += 30
        rc, out, err = self.run_mm("on")
        self.assertEqual((rc, out), (0, ["actions=on safe=cleared"]), err)
        self.assertIsNone(mmcore.safe_state())
        rec = json.load(open(self.clear_file()))
        self.assertEqual((rec["why"], rec["was_safe"]), ("mm on", True))
        self.assertLessEqual(abs(rec["cleared_at"] - time.time()), 120)
        self.assertIn("machine_id", rec)
        clock["t"] = max(clock["t"], rec["cleared_at"]) + 10
        r = sup.check_self(0.1, 0)
        self.assertEqual(r["action"], "ok", r["reasons"])
        self.assertIsNone(mmcore.safe_state(), "no trip again on the old changes")
        self.assertEqual(len(sup.state["slot_changes"]), 13, "the supervisor's own list is not trimmed")

    def test_changes_after_mm_on_still_count(self):
        clock = {"t": time.time()}
        sup = self.sup(clock=lambda: clock["t"])
        self.trip(sup, clock["t"])
        self.assertEqual(self.run_mm("on")[0], 0)
        cleared = json.load(open(self.clear_file()))["cleared_at"]
        base = max(clock["t"], cleared)
        sup.state["slot_changes"] += [base + 1 + k for k in range(12)]
        clock["t"] = base + 20
        self.assertEqual(sup.check_self(0.1, 0)["action"], "ok", "12 new changes: at the limit")
        sup.state["slot_changes"].append(base + 15)
        self.assertEqual(sup.check_self(0.1, 0)["action"], "safe", "13 new changes trip again")
        self.assertIn("changed 13 times", mmcore.safe_state()["reason"])

    def test_mm_on_without_safe_mode_also_writes_the_record(self):
        rc, out, _ = self.run_mm("on")
        self.assertEqual((rc, out), (0, ["actions=on"]))
        rec = json.load(open(self.clear_file()))
        self.assertEqual((rec["why"], rec["was_safe"]), ("mm on", False))

    def test_clear_safe_writes_the_record_with_its_time(self):
        mmrecover.enter_safe("test", NOW)
        cur = mmrecover.clear_safe("unit test", now=NOW + 5)
        self.assertTrue(cur and cur.get("safe"))
        self.assertEqual(mmrecover.read_clear(), (NOW + 5, None))
        rec = json.load(open(self.clear_file()))
        self.assertEqual((rec["why"], rec["was_safe"], rec["cleared_at"]), ("unit test", True, NOW + 5))
        self.assertIsNone(mmcore.safe_state())
        self.assertFalse(os.path.exists(os.path.join(self.data, "state", "starts.json")))

    def test_no_record_is_no_clear(self):
        self.assertFalse(os.path.exists(self.clear_file()))
        self.assertEqual(mmrecover.read_clear(), (None, None))
        sup = self.sup()
        self.trip(sup, time.time())

    def test_an_unreadable_record_counts_every_change_and_says_so(self):
        bad = ["{not json", "[]", "null", '"x"', "{}", '{"cleared_at": "1800000000"}', '{"cleared_at": true}',
               '{"cleared_at": NaN}', '{"cleared_at": Infinity}', '{"cleared_at": null}']
        for text in bad:
            with self.subTest(text=text):
                with open(self.clear_file(), "w") as f:
                    f.write(text)
                cleared, problem = mmrecover.read_clear()
                self.assertIsNone(cleared)
                self.assertTrue(problem, "an unreadable record is not 'no record'")

    def test_an_unreadable_record_trips_on_old_changes_and_logs_once_per_10_minutes(self):
        now = time.time()
        mmcore.write_atomic(self.clear_file(), json.dumps({"cleared_at": now - 600, "why": "mm on"}))
        clock = {"t": now}
        sup = self.sup(clock=lambda: clock["t"])
        sup.state["slot_changes"] = [now - 900 - k for k in range(13)]
        self.assertEqual(sup.check_self(0.1, 0)["action"], "ok", "a good record: the 13 changes are before it")
        with open(self.clear_file(), "w") as f:
            f.write("{broken")
        for _ in range(3):
            clock["t"] += 60
            r = sup.check_self(0.1, 0)
        self.assertIsNotNone(mmcore.safe_state(), "the stricter way: every change of the hour counts")
        line = "SELF-CHECK clear record unreadable"
        decisions = open(os.path.join(self.data, "state", "decisions.log")).read()
        self.assertEqual(decisions.count(line), 1, decisions)
        self.assertIn("every slot change of the hour counts", decisions)
        self.assertEqual(self.recovery_log().count(line), 1, self.recovery_log())
        clock["t"] += 601
        sup.check_self(0.1, 0)
        decisions = open(os.path.join(self.data, "state", "decisions.log")).read()
        self.assertEqual(decisions.count(line), 2, "again after 10 minutes")

    @mmtest.darwin_only
    def test_restart_clear_safe_starts_a_fresh_window(self):
        mmrecover.enter_safe("self-check: the slot count changed 13 times", time.time())
        rc, out, _ = self.run_mm("restart", "--clear-safe", FAKE_HEARTBEAT_PID="4343")
        self.assertEqual((rc, out), (0, ["restart=ok pid=4343 safe=cleared"]))
        rec = json.load(open(self.clear_file()))
        self.assertEqual((rec["why"], rec["was_safe"]), ("mm restart --clear-safe", True))
        clock = {"t": max(time.time(), rec["cleared_at"]) + 5}
        sup = self.sup(clock=lambda: clock["t"])
        sup.state["slot_changes"] = [rec["cleared_at"] - 1 - 60 * k for k in range(13)]
        self.assertEqual(sup.check_self(0.1, 0)["action"], "ok")


# ------------------------------------------------------------------------------------------- the supervisor, 60 minutes

class SupervisorHour(RecoveryBase):
    """The supervisor ticks once a simulated minute on a fixture queue with full demand (10 busy slots without a
    process, 3 waiting tickets) and free memory from the border cycle. Observe mode: WOULD lines, no slot file write."""

    def setUp(self):
        super().setUp()
        real = mmread.disk_free_gb
        mmread.disk_free_gb = lambda *a, **k: 200.0
        self.addCleanup(setattr, mmread, "disk_free_gb", real)

    def run_hour(self, free_at, minutes=60, **over):
        self.write_settings(**dict({"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10,
                                    "slots.green_free_pct": 50, "slots.raise_green_minutes": 5}, **over))
        mmcore.write_slots(os.path.join(self.q, "slots"), 6)
        clock = {"t": NOW, "k": 0}

        def sampler(now, ticks):
            d, _ = sampler_of(free_pct=free_at(clock["k"], now), load1=2, load5=2)(now, ticks)
            return d, ticks

        sup = self.sup(sampler, clock=lambda: clock["t"])
        read = sup.queue.read
        busy = [{"slot": ".slot.%d" % i, "mode": "S", "pid": None, "label": "S fixture %d" % i, "since": NOW - 60,
                 "kind": None} for i in range(10)]
        tickets = [{"name": "t%d" % i, "mode": "S", "age_s": 60, "label": "S waiting %d" % i, "kind": None}
                   for i in range(3)]
        sup.queue.read = lambda now: dict(read(now), busy=list(busy), tickets=list(tickets))
        for k in range(minutes):
            clock["k"] = k
            sup.tick()
            clock["t"] += 60
        return sup

    def decisions(self):
        try:
            return open(os.path.join(self.data, "state", "decisions.log")).read()
        except OSError:
            return ""

    def test_old_settings_flap_through_the_supervisor(self):
        sup = self.run_hour(border_cycle, **{MARGIN: 0, HOLD: 0})
        self.assertEqual(len(sup.state["slot_changes"]), 17, self.decisions())

    def test_defaults_give_at_most_3_changes_and_a_hold_line(self):
        sup = self.run_hour(border_cycle)
        self.assertLessEqual(len(sup.state.get("slot_changes", [])), 3, self.decisions())
        log = self.decisions()
        self.assertNotIn("-> 6: GREEN", log)
        holds = [l for l in log.splitlines() if " HOLD slots " in l]
        self.assertTrue(holds, log)
        self.assertTrue(all(": raise held: " in l for l in holds), holds)
        self.assertLessEqual(len(holds), 12, "at most once per 10 min per kind: %r" % holds)

    def test_the_supervisor_passes_free_memory_and_raises_at_55(self):
        """AMBER for one minute, then 56% free: a raise 15 minutes after the step down."""
        sup = self.run_hour(lambda k, t: 49.0 if k == 0 else 56.0, minutes=20)
        log = [l for l in self.decisions().splitlines() if "WOULD slots" in l]
        self.assertEqual(len(log), 2, log)
        self.assertIn("WOULD slots 6 -> 5: AMBER", log[0])
        self.assertIn("WOULD slots 5 -> 6: GREEN", log[1])
        self.assertEqual(sorted(sup.state["slot_changes"]), [NOW, NOW + 15 * 60])


# ------------------------------------------------------------------------------------------- review round 1
# Exact texts from the coder's "review fixes done" message.
CONTROLLER_UNREADABLE = "SLOT_STATE"  # ATTENTION
CLEAR_WRITE_ERROR = ("E_CLEAR the clear record state/self-check-clear.json was not written (PermissionError); safe mode "
                     "and the unclean starts are kept; fix: make the data folder's state/ writable, then run it again")
HOLD_NOTE = "no raise for one full hold (slots.raise_hold_after_down_minutes)"


class BadLastDown(unittest.TestCase):
    """An invalid last_down in the controller state: no crash, no raise, a step down still works."""
    BAD = ("broken", float("nan"), float("inf"), NOW + 10 ** 9, True, False, [NOW], {"t": NOW}, -float("inf"))

    def test_no_crash_and_no_raise(self):
        for bad in self.BAD:
            with self.subTest(last_down=bad):
                st = dict(calm_state(NOW), last_down=bad)
                r = mmdecide.slot_decide(st, inp(NOW, free_pct=80.0), settings())
                self.assertIsNone(r["slots"], r)

    def test_held_text_and_problem_name_the_key(self):
        for bad in self.BAD:
            with self.subTest(last_down=bad):
                r = mmdecide.slot_decide(dict(calm_state(NOW), last_down=bad), inp(NOW, free_pct=80.0), settings())
                self.assertEqual(r["held"], "raise held: controller state invalid (last_down)")
                self.assertEqual(r["problem"], "slot controller state invalid: last_down; " + HOLD_NOTE)
                self.assertNotIn("last_down", r["state"], "an invalid last_down is dropped")
                self.assertEqual(r["state"]["raise_hold_since"], NOW)

    def test_one_full_hold_after_the_repair(self):
        s = settings()
        r = mmdecide.slot_decide(dict(calm_state(NOW), last_down="broken"), inp(NOW, free_pct=80.0), s)
        st = r["state"]
        for m, want in ((6.0, None), (14.9, None), (15.0, 6)):
            r = mmdecide.slot_decide(st, inp(NOW + m * MIN, free_pct=80.0), s)
            self.assertEqual(r["slots"], want, m)
        r = mmdecide.slot_decide(st, inp(NOW + 6 * MIN, free_pct=80.0), s)
        self.assertEqual(r["held"], "raise held: 6 min since the controller state was repaired < 15 min")

    def test_other_invalid_times_become_now(self):
        for key in ("last_change", "green_since", "last_red", "demand_since"):
            for bad in ("x", float("nan"), True, NOW + 61, 10 ** 400):
                with self.subTest(key=key, bad=bad):
                    r = mmdecide.slot_decide(dict(calm_state(NOW), **{key: bad}), inp(NOW, free_pct=80.0), settings())
                    self.assertIsNone(r["slots"])
                    self.assertIn(key, r["problem"])
                    self.assertEqual(r["state"]["raise_hold_since"], NOW)

    def test_a_time_up_to_60_s_ahead_is_valid(self):
        st = dict(calm_state(NOW), last_down=NOW - 3600, last_red=NOW + 60)
        r = mmdecide.slot_decide(st, inp(NOW, free_pct=80.0), settings(**{"slots.hold_after_red_minutes": 0}))
        self.assertIsNone(r.get("problem"))

    def test_valid_state_has_no_problem(self):
        self.assertIsNone(mmdecide.slot_decide(calm_state(NOW), inp(NOW, free_pct=80.0), settings()).get("problem"))

    def test_step_down_still_works(self):
        for bad in self.BAD:
            with self.subTest(last_down=bad):
                st = dict(calm_state(NOW), last_down=bad)
                r = mmdecide.slot_decide(st, inp(NOW, "AMBER", 49.0, slots=6), settings())
                self.assertEqual(r["slots"], 5, r)
                self.assertEqual(r["state"]["last_down"], NOW, "a valid time replaces the bad value")

    def test_red_still_goes_to_the_floor(self):
        for bad in self.BAD:
            with self.subTest(last_down=bad):
                st = dict(calm_state(NOW), last_down=bad)
                self.assertEqual(mmdecide.slot_decide(st, inp(NOW, "RED", 30.0, slots=7), settings())["slots"], 3)


class ClockBack(unittest.TestCase):
    def test_a_clock_that_goes_back_gives_no_crash_and_no_early_raise(self):
        s = settings()
        r = mmdecide.slot_decide(calm_state(NOW), inp(NOW, "AMBER", 49.0, slots=6), s)
        self.assertEqual(r["slots"], 5)
        st = r["state"]
        back = NOW - 3600  # the clock goes back one hour after the step down
        for k in range(15):
            r = mmdecide.slot_decide(st, inp(back + k * MIN, free_pct=80.0, slots=5), s)
            st = r["state"]
            self.assertIsNone(r["slots"], "minute %d after the clock went back: %r" % (k, r))

    def test_a_step_down_still_works_after_the_clock_goes_back(self):
        s = settings()
        st = dict(calm_state(NOW), last_down=NOW, last_change=NOW)
        r = mmdecide.slot_decide(st, inp(NOW - 3600, "AMBER", 49.0, slots=6), s)
        self.assertEqual(r["slots"], 5, "an AMBER step down is never blocked by a last_down in the future")


class ReadClearLimits(RecoveryBase):
    def clear_file(self):
        return os.path.join(self.data, "state", "self-check-clear.json")

    def test_huge_and_deep_records_are_a_problem_not_an_exception(self):
        texts = ['{"cleared_at": %d}' % 10 ** 400, "[" * 1500 + "]" * 1500,
                 '{"cleared_at": ' + "[" * 1500 + "]" * 1500 + "}", '{"cleared_at": 1e400}']
        for text in texts:
            with self.subTest(text=text[:30]):
                with open(self.clear_file(), "w") as f:
                    f.write(text)
                cleared, problem = mmrecover.read_clear()
                self.assertIsNone(cleared)
                self.assertTrue(problem)
                self.assertEqual(open(self.clear_file()).read(), text, "the file is kept")

    def test_the_supervisor_counts_every_change_with_such_a_record(self):
        with open(self.clear_file(), "w") as f:
            f.write("[" * 1500 + "]" * 1500)
        now = time.time()
        sup = self.sup(clock=lambda: now)
        sup.state["slot_changes"] = [now - 60 * k for k in range(13)]
        self.assertEqual(sup.check_self(0.1, 0)["action"], "safe")


class ClearWriteFails(RecoveryBase):
    def test_clear_safe_reports_the_error_and_keeps_safe_mode(self):
        mmrecover.enter_safe("test", NOW)
        starts = os.path.join(self.data, "state", "starts.json")
        mmcore.write_atomic(starts, json.dumps([NOW - 60]))
        real = mmcore.write_atomic

        def refuse(path, *a, **k):
            if os.path.basename(path).startswith("self-check-clear"):
                raise PermissionError(13, "Permission denied", path)
            return real(path, *a, **k)

        with mock.patch.object(mmcore, "write_atomic", refuse):
            with self.assertRaises(mmcore.MMError) as cm:
                mmrecover.clear_safe("unit test", now=NOW + 5)
        self.assertEqual(cm.exception.code, "E_CLEAR")
        self.assertEqual(str(cm.exception), CLEAR_WRITE_ERROR)
        self.assertIsNotNone(mmcore.safe_state(), "safe mode stays")
        self.assertEqual(json.load(open(starts)), [NOW - 60], "the crash history stays")

    def test_mm_on_reports_the_error_and_keeps_safe_mode(self):
        mmrecover.enter_safe("test", time.time())
        state = os.path.join(self.data, "state")
        starts = os.path.join(state, "starts.json")
        mmcore.write_atomic(starts, json.dumps([time.time() - 60]))
        before = open(starts).read()
        os.chmod(state, 0o500)
        self.addCleanup(os.chmod, state, 0o700)
        rc, out, err = self.run_mm("on")
        os.chmod(state, 0o700)
        self.assertEqual((rc, out), (2, [CLEAR_WRITE_ERROR]), err)
        self.assertIsNotNone(mmcore.safe_state(), "safe mode stays")
        self.assertEqual(open(starts).read(), before, "the crash history stays")
        self.assertFalse(os.path.exists(os.path.join(state, "self-check-clear.json")))


class ClearWriteFailsWithOff(RecoveryBase):
    def test_mm_on_failure_keeps_the_off_switch_too(self):
        mmrecover.enter_safe("test", time.time())
        mmcore.write_atomic(os.path.join(self.data, "off.json"), json.dumps({"off": True, "since": "x", "reason": "t"}))
        state = os.path.join(self.data, "state")
        os.chmod(state, 0o500)
        self.addCleanup(os.chmod, state, 0o700)
        rc, out, err = self.run_mm("on")
        os.chmod(state, 0o700)
        self.assertEqual((rc, out), (2, [CLEAR_WRITE_ERROR]), err)
        self.assertIsNotNone(mmcore.off_state(), "a failed clear changes nothing: off stays")
        self.assertIsNotNone(mmcore.safe_state())


class SupervisorReview(SupervisorHour):
    """The supervisor across a restart, with a bad controller.json, and after a safe-mode reduction."""

    def build(self, free_at, clock, mode="off", slots=6, **over):
        f = os.path.join(self.root, "test-slots")
        extra = {"mode.observe": False, "mode.slot_writes": "test", "mode.slots_file": f} if mode == "test" else {}
        self.write_settings(**dict({"slots.cores": 10, "slots.floor": 3, "slots.ceiling": 10,
                                    "slots.green_free_pct": 50, "slots.raise_green_minutes": 5}, **extra, **over))
        mmcore.write_slots(os.path.join(self.q, "slots"), slots)
        mmcore.write_slots(f, slots)

        def sampler(now, ticks):
            d, _ = sampler_of(free_pct=free_at(now), load1=2, load5=2)(now, ticks)
            return d, ticks

        sup = self.sup(sampler, clock=lambda: clock["t"])
        read = sup.queue.read
        busy = [{"slot": ".slot.%d" % i, "mode": "S", "pid": None, "label": "S fixture %d" % i, "since": NOW - 60,
                 "kind": None} for i in range(10)]
        tickets = [{"name": "t%d" % i, "mode": "S", "age_s": 60, "label": "S waiting %d" % i, "kind": None}
                   for i in range(3)]
        sup.queue.read = lambda now: dict(read(now), busy=list(busy), tickets=list(tickets))
        return sup, f

    def tick_until(self, sup, clock, end, step=60):
        """Ticks every `step` seconds up to `end`; returns the times with a raise in the decisions log."""
        raises = []
        while clock["t"] <= end:
            n = self.decisions().count(": GREEN")
            sup.tick()
            if self.decisions().count(": GREEN") > n:
                raises.append(clock["t"])
            clock["t"] += step
        return raises

    def test_last_down_survives_a_restart_and_the_hold_still_applies(self):
        t0 = NOW
        clock = {"t": t0}
        free = lambda now: 49.0 if now < t0 + 30 else 60.0
        sup, _ = self.build(free, clock)
        sup.tick()  # AMBER: 6 -> 5
        self.assertIn("WOULD slots 6 -> 5: AMBER", self.decisions())
        saved = json.load(open(os.path.join(self.data, "state", "controller.json")))
        self.assertEqual(saved["controller"]["last_down"], t0)
        clock["t"] += 60
        self.tick_until(sup, clock, t0 + 5 * MIN)
        sup2, _ = self.build(free, clock, slots=5)  # a supervisor restart on the same data folder
        self.assertEqual(sup2.state["controller"]["last_down"], t0)
        raises = self.tick_until(sup2, clock, t0 + 20 * MIN)
        self.assertTrue(raises, self.decisions())
        self.assertGreaterEqual(raises[0], t0 + 15 * MIN, "the hold holds after the restart")

    def test_an_unreadable_controller_json_is_kept_alerted_and_holds(self):
        path = os.path.join(self.data, "state", "controller.json")
        with open(path, "w") as f:
            f.write("{broken controller")
        t0 = NOW
        clock = {"t": t0}
        sup, _ = self.build(lambda now: 60.0, clock)
        raises = self.tick_until(sup, clock, t0 + 20 * MIN)
        kept = path + ".unreadable"
        self.assertTrue(os.path.exists(kept))
        self.assertEqual(open(kept).read(), "{broken controller", "the bad file is kept as it was")
        alerts = [r for r in self.pushed() if r.get("name") == CONTROLLER_UNREADABLE]
        self.assertTrue(alerts, [r.get("name") for r in self.pushed()])
        self.assertEqual(alerts[0]["level"], "ATTENTION")
        self.assertEqual(alerts[0]["text"], "state/controller.json unreadable (JSONDecodeError), kept as "
                         "state/controller.json.unreadable; a fresh record starts, " + HOLD_NOTE)
        self.assertTrue(raises, self.decisions())
        self.assertGreaterEqual(raises[0], t0 + 15 * MIN, "one full hold from the detection time")

    def test_the_fresh_record_and_a_non_object_file(self):
        path = os.path.join(self.data, "state", "controller.json")
        for text in ("[1, 2]", '"x"', "null"):
            with self.subTest(text=text):
                for f in (path, path + ".unreadable"):
                    if os.path.exists(f):
                        os.remove(f)
                with open(path, "w") as fh:
                    fh.write(text)
                clock = {"t": NOW}
                sup, _ = self.build(lambda now: 60.0, clock)
                self.assertEqual(sup.state.get("controller", {}).get("raise_hold_since"), NOW)
                self.assertEqual(open(path + ".unreadable").read(), text)

    def test_a_missing_controller_json_is_a_fresh_start_without_hold(self):
        clock = {"t": NOW}
        sup, _ = self.build(lambda now: 60.0, clock)
        self.assertNotIn("raise_hold_since", sup.state.get("controller") or {})
        self.assertFalse(os.path.exists(os.path.join(self.data, "state", "controller.json.unreadable")))

    def test_an_unreadable_controller_json_still_steps_down(self):
        with open(os.path.join(self.data, "state", "controller.json"), "w") as f:
            f.write("not json at all")
        clock = {"t": NOW}
        sup, _ = self.build(lambda now: 49.0, clock)
        sup.tick()
        self.assertIn("WOULD slots 6 -> 5: AMBER", self.decisions())

    def test_an_invalid_stored_time_gives_the_slot_state_alert(self):
        mmcore.write_atomic(os.path.join(self.data, "state", "controller.json"),
                            json.dumps({"controller": {"last_down": "broken", "last_change": NOW - 3600}}))
        clock = {"t": NOW}
        sup, _ = self.build(lambda now: 60.0, clock)
        raises = self.tick_until(sup, clock, NOW + 20 * MIN)
        alerts = [r for r in self.pushed() if r.get("name") == CONTROLLER_UNREADABLE]
        self.assertTrue(alerts, [r.get("name") for r in self.pushed()])
        self.assertEqual((alerts[0]["level"], alerts[0]["text"]),
                         ("ATTENTION", "slot controller state invalid: last_down; " + HOLD_NOTE))
        self.assertTrue(raises and raises[0] >= NOW + 15 * MIN, raises)

    def test_a_safe_mode_reduction_starts_the_hold(self):
        t0 = NOW
        clock = {"t": t0}
        sup, f = self.build(lambda now: 60.0, clock, mode="test", slots=8)
        mmrecover.enter_safe("test", t0)
        sup.tick()
        self.assertEqual(open(f).read().split()[0], "5", "safe mode: at most 5")
        mmrecover.clear_safe("unit test", now=t0 + 30)
        clock["t"] += 60
        raises = self.tick_until(sup, clock, t0 + 25 * MIN)
        self.assertTrue(raises, self.decisions())
        self.assertGreaterEqual(raises[0], t0 + 15 * MIN, "no raise for 15 minutes: %r" % raises)
        self.assertEqual(open(f).read().split()[0], str(5 + len(raises)))
        self.assertIn("SET slots 8 -> 5: safe mode", self.decisions())


del RecoveryBase


if __name__ == "__main__":
    unittest.main()
