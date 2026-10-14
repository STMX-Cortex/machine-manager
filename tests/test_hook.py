# SPDX-License-Identifier: Apache-2.0
"""T9: the hook speaks only to the recipient's main session, never inside a subagent, never blocks, prints at most 3
alert lines then "+N more", and its launch gate denies only while the machine is fresh RED (fail-open otherwise; in
observe mode it only logs WOULD-DENY). Also the waiter (`mm wait`) sharing the hook's cursor."""
import fcntl
import json
import os
import subprocess
import time
import unittest

from mmtest import MM, TempData, mmcore

R1 = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
OTHER = "11111111-2222-3333-4444-555555555555"


class HookBase(TempData):
    def setUp(self):
        super().setUp()
        with open(os.path.join(self.data, "recipient.md"), "w") as f:
            f.write("# agent state\n\nSession: %s\n" % R1)
        self.beat()

    def beat(self, age=0, state="GREEN", red_since=None):
        now = time.time()
        mmcore.write_atomic(os.path.join(self.data, "status.json"), json.dumps(
            {"time": now - age, "state": state, "reasons": ["compressor +2242 MB in 60 s"],
             "red_since": None if red_since is None else now - red_since}))

    def hook(self, data, event="PostToolUse", raw=None, keep_open=False):
        t0 = time.monotonic()
        argv = MM + ["hook", "--event", event]
        if keep_open:
            p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            out = p.stdout.read()
            p.wait(5)
            p.stdin.close()
            rc = p.returncode
        else:
            r = subprocess.run(argv, capture_output=True, timeout=10,
                               input=raw if raw is not None else json.dumps(dict(data, hook_event_name=event)).encode())
            out, rc = r.stdout, r.returncode
        self.assertEqual(rc, 0)
        self.assertLess(time.monotonic() - t0, 2.0, "the hook ends within 2 s")
        if not out.strip():
            return None
        return json.loads(out)["hookSpecificOutput"]

    def alert(self, key, level, text="t", command=None):
        st = mmcore.AlertStore(mmcore.Settings().load())
        st.begin()
        st.raise_(key, key, level, text, command=command)
        return st


class Hook(HookBase):
    def test_recipient_sees_attention_and_action_once(self):
        self.alert("A1", "ACTION", "act now", command="mm status")
        self.alert("I1", "INFO", "just info")
        out = self.hook({"session_id": R1})
        self.assertIn("ACTION A1 act now | do: mm status", out["additionalContext"])
        self.assertNotIn("I1", out["additionalContext"])
        self.assertIsNone(self.hook({"session_id": R1}), "seen alerts are not shown again")
        self.alert("B2", "ATTENTION", "look")
        out = self.hook({"session_id": R1}, event="UserPromptSubmit")
        self.assertIn("ATTENTION B2 look", out["additionalContext"])
        self.assertEqual(out["hookEventName"], "UserPromptSubmit")

    def test_at_most_three_lines_then_more(self):
        self.hook({"session_id": R1})
        for i in range(6):
            self.alert("K%d" % i, "ACTION" if i % 2 else "ATTENTION", "alert %d " % i + "x" * 300)
        lines = self.hook({"session_id": R1})["additionalContext"].splitlines()
        self.assertEqual(len(lines), 5, lines)  # 3 alerts, "+3 more", the waiter reminder
        self.assertEqual(lines[3], "+3 more: mm alerts")
        self.assertTrue(all(l.startswith("ACTION") for l in lines[:3]), "the highest level first")
        self.assertTrue(all(len(l) <= 200 for l in lines))

    def test_subagent_and_other_sessions_get_nothing(self):
        self.alert("A1", "ACTION")
        self.assertIsNone(self.hook({"session_id": R1, "agent_id": "agent-1", "agent_type": "helper"}))
        self.assertIsNone(self.hook({"session_id": OTHER}))
        self.assertIsNone(self.hook({}))
        self.assertIn("A1", self.hook({"session_id": R1})["additionalContext"], "a subagent's call did not move the cursor")

    def test_unreadable_recipient_shows_action_to_main_sessions(self):
        os.remove(os.path.join(self.data, "recipient.md"))
        self.alert("A1", "ACTION")
        self.alert("B1", "ATTENTION")
        out = self.hook({"session_id": OTHER})["additionalContext"]
        self.assertIn("E_RECIPIENT", out)
        self.assertIn("A1", out)
        self.assertNotIn("B1", out)
        self.assertIsNone(self.hook({"session_id": OTHER, "agent_id": "x"}))

    def test_never_blocks(self):
        self.alert("A1", "ACTION")
        self.assertIsNone(self.hook({}, keep_open=True))
        self.assertIsNone(self.hook(None, raw=b"\xff\xfe not json"))
        with mmcore.Locked(os.path.join(self.data, "state", "alerts.lock")):
            self.assertIn("A1", self.hook({"session_id": R1})["additionalContext"])
        with open(os.path.join(self.data, "alerts-state.json"), "w") as f:
            f.write("{broken")
        self.hook({"session_id": R1})
        self.hook({"session_id": R1, "tool_response": "x" * (3 << 20)})

    def test_no_profile_is_silent(self):
        r = subprocess.run(MM + ["hook", "--event", "PostToolUse"], capture_output=True, timeout=10,
                           input=json.dumps({"session_id": R1}).encode(),
                           env=dict(os.environ, MM_PROFILE=os.path.join(self.root, "missing.toml")))
        self.assertEqual((r.returncode, r.stdout), (0, b""))

    def test_cursor_locked_by_waiter_defers(self):
        self.alert("A1", "ACTION")
        cf = os.path.join(self.data, "state", "cursor-%s.json" % R1)
        with open(cf, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            self.assertIsNone(self.hook({"session_id": R1}))
        self.assertIn("A1", self.hook({"session_id": R1})["additionalContext"])

    def test_stale_line_and_stopped(self):
        self.beat(age=200)
        out = self.hook({"session_id": R1})["additionalContext"]
        self.assertIn("ACTION SELF_STALE", out)
        self.assertIn("launch gate is open", out)
        os.remove(os.path.join(self.data, "status.json"))
        self.assertIn("missing", self.hook({"session_id": R1})["additionalContext"])
        mmcore.write_atomic(os.path.join(self.data, "state", "stopped.json"), "{}")
        self.assertIsNone(self.hook({"session_id": R1}), "stopped on purpose: quiet")

    def test_input_keys_logged_without_values(self):
        self.write_settings(**{"hook.log_input_keys": True})
        self.hook({"session_id": R1, "transcript_path": "/secret/path.jsonl", "agent_id": "abc", "tool_input": {"x": "v"}})
        lines = open(os.path.join(self.data, "state", "hook-inputs.log")).read().splitlines()
        rec = json.loads(lines[-1])
        self.assertIn("agent_id", rec["keys"])
        self.assertTrue(rec["session_is_recipient"])
        self.assertNotIn("/secret/path.jsonl", "\n".join(lines))
        self.assertNotIn(R1, "\n".join(lines))

    def test_waiter_reminder_once_per_period(self):
        self.alert("A1", "ACTION")
        self.assertIn("no idle waiter", self.hook({"session_id": R1})["additionalContext"])
        self.alert("A2", "ACTION")
        self.assertNotIn("no idle waiter", self.hook({"session_id": R1})["additionalContext"])


class Waiter(HookBase):
    def test_wait_wakes_and_shares_cursor(self):
        self.hook({"session_id": R1})
        p = subprocess.Popen(MM + ["wait", "--session", R1, "--poll", "0.2", "--max-seconds", "20"], stdout=subprocess.PIPE,
                             text=True)
        time.sleep(0.8)
        self.assertIsNone(p.poll(), "the waiter waits while nothing is new")
        self.alert("W1", "ATTENTION", "wake up")
        out, _ = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 0)
        self.assertIn("ATTENTION W1 wake up", out)
        self.assertIsNone(self.hook({"session_id": R1}), "the hook does not repeat what the waiter showed")

    def test_a_clear_does_not_wake_the_waiter(self):
        self.alert("W3", "ATTENTION", "was bad")
        self.hook({"session_id": R1})  # seen
        p = subprocess.Popen(MM + ["wait", "--session", R1, "--poll", "0.2", "--max-seconds", "20"], stdout=subprocess.PIPE,
                             text=True)
        time.sleep(0.8)
        mmcore.AlertStore(mmcore.Settings().load()).clear("W3")
        self.assertIn("cleared", json.dumps([r.get("why") for r in self.pushed()]), "the clear was pushed")
        time.sleep(1.2)
        self.assertIsNone(p.poll(), "the clear did not wake the waiter")
        self.alert("W4", "ATTENTION", "new problem")
        out, _ = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(out.strip().splitlines(), ["ATTENTION W4 new problem"])

    def test_wait_action_only_timeout_and_stale(self):
        self.hook({"session_id": R1})
        self.alert("W2", "ATTENTION")
        r = self.mm("wait", "--session", R1, "--min-level", "action", "--poll", "0.2", "--max-seconds", "1")
        self.assertEqual((r.returncode, r.stdout.strip()), (1, "alerts=none waited_s=1"))
        self.beat(age=500)
        r = self.mm("wait", "--session", R1, "--max-seconds", "5")
        self.assertEqual(r.returncode, 3)
        self.assertIn("SELF_STALE", r.stdout)


class Gate(HookBase):
    def pre(self, tool, cmd=None, **extra):
        d = {"session_id": R1, "tool_name": tool, "tool_input": {"command": cmd} if cmd else {}}
        d.update(extra)
        return self.hook(d, event="PreToolUse")

    def gate_on(self, observe=False):
        self.write_settings(**{"launch_gate.enabled": True, "mode.observe": observe})

    def test_gate_off_by_default(self):
        self.beat(state="RED", red_since=60)
        self.assertFalse(mmcore.Settings().load()["launch_gate.enabled"])
        self.assertIsNone(self.pre("Agent"))

    def test_gate_denies_launches_only_while_fresh_red(self):
        self.gate_on()
        self.beat(state="RED", red_since=60)
        for tool, cmd in [("Agent", None), ("Workflow", None), ("Bash", "codex exec -m m"), ("Bash", "cd x && claude -p hi"),
                          ("Bash", "printf t | codex -a never exec -"), ("Bash", "agent-launch n")]:
            out = self.pre(tool, cmd)
            self.assertEqual(out["permissionDecision"], "deny", (tool, cmd))
            self.assertTrue(out["permissionDecisionReason"].startswith("E_GATE_RED machine RED"))
            self.assertIn("; fix: ", out["permissionDecisionReason"])
        for tool, cmd in [("Bash", "ls -la"), ("Bash", "grep codex notes.md"), ("Read", None), ("Bash", "cat claude.md")]:
            self.assertIsNone(self.pre(tool, cmd), (tool, cmd))
        self.assertIsNone(self.pre("Agent", agent_id="sub"), "a subagent's calls are never gated")
        self.beat(state="RED", red_since=20 * 60)
        self.assertIsNone(self.pre("Agent"), "at most launch_gate.max_minutes")

    def test_gate_fails_open(self):
        self.gate_on()
        self.beat(age=300, state="RED", red_since=60)
        self.assertIsNone(self.pre("Agent"), "a stale status gates nothing")
        os.remove(os.path.join(self.data, "status.json"))
        self.assertIsNone(self.pre("Agent"), "no status gates nothing")
        self.beat(state="RED", red_since=60)
        mmcore.write_atomic(os.path.join(self.data, "off.json"), json.dumps({"off": True, "since": "x"}))
        self.assertIsNone(self.pre("Agent"), "the off switch opens the gate")
        os.remove(os.path.join(self.data, "off.json"))
        with open(os.path.join(self.data, "settings.toml"), "w") as f:
            f.write("[broken\n")
        os.remove(os.path.join(self.data, "state", "settings.lastgood.json")) if os.path.exists(
            os.path.join(self.data, "state", "settings.lastgood.json")) else None
        self.assertIsNone(self.pre("Agent"), "no valid settings gates nothing")

    def test_observe_mode_logs_would_deny(self):
        self.gate_on(observe=True)
        self.beat(state="RED", red_since=60)
        self.assertIsNone(self.pre("Agent"))
        log = open(os.path.join(self.data, "state", "gate.log")).read()
        self.assertIn("WOULD-DENY Agent: E_GATE_RED", log)


if __name__ == "__main__":
    unittest.main()
