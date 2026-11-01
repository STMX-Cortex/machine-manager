# SPDX-License-Identifier: Apache-2.0
"""Transport boundaries and CLI isolation; no real tailnet or SSH daemon needed."""
import contextlib
import io
import json
from pathlib import Path
import plistlib
import subprocess
from unittest import mock

from mmtest import CODE, TempData
import mmtailscale
from test_resources import load_cli


class Tunnel(TempData):
    def test_default_is_local_read_only_forward_without_shell_or_remote_command(self):
        plan = mmtailscale.tunnel("worker.example.ts.net", "worker")
        argv = plan["argv"]
        self.assertEqual(argv[0], "/usr/bin/ssh")
        self.assertEqual(argv[-6:], ["-L", "127.0.0.1:19877:127.0.0.1:9877", "-l", "worker", "--",
                                    "worker.example.ts.net"])
        for word in ("-N", "-T", "BatchMode=yes", "StrictHostKeyChecking=yes", "ExitOnForwardFailure=yes",
                     "ForwardAgent=no", "PermitLocalCommand=no", "ProxyCommand=none", "ProxyJump=none",
                     "ControlPath=none", "GatewayPorts=no"):
            self.assertIn(word, argv)
        self.assertEqual(argv[1:3], ["-F", "/dev/null"])
        self.assertEqual(plan["status_url"], "http://127.0.0.1:19877/status.json")

    def test_tailnet_addresses_and_distinct_peer_port(self):
        for peer in ("100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::1", "WORKER.Example.ts.net"):
            with self.subTest(peer=peer):
                plan = mmtailscale.tunnel(peer, "_worker-2", 19878)
                self.assertIn("127.0.0.1:19878:127.0.0.1:9877", plan["argv"])
                self.assertEqual(plan["argv"][-1], peer)

    def test_peer_must_be_explicit_tailnet_destination_and_not_an_option(self):
        for peer in (None, "", "worker", "example.com", "worker.ts.net", "127.0.0.1", "100.128.0.1",
                     "100.63.255.255", "::1", "fd7a:115c:a1e1::1", "fd7a:115c:a1e0::1%eth0",
                     "-oProxyCommand=evil", "a\n.b.ts.net",
                     "$(id).example.ts.net", "user@" + "worker.example.ts.net", "a..example.ts.net",
                     "-a.example.ts.net", "a_.example.ts.net", "a." + "b" * 64 + ".ts.net"):
            with self.subTest(peer=peer), self.assertRaises(ValueError):
                mmtailscale.tunnel(peer, "worker")

    def test_user_and_port_injection_and_privileged_ports_rejected(self):
        for user in (None, "", "-root", "a b", "a;id", "a\n", "a" * 65):
            with self.subTest(user=user), self.assertRaises(ValueError):
                mmtailscale.tunnel("worker.example.ts.net", user)
        for port in (0, 22, 1023, 65536, True, 19877.0, "19877"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                mmtailscale.tunnel("worker.example.ts.net", "worker", port)

    def test_exec_replaces_wrapper_and_propagates_fixed_argv(self):
        plan = mmtailscale.tunnel("worker.example.ts.net", "worker")
        with mock.patch("mmtailscale.os.execv", side_effect=SystemExit(23)) as execute:
            with self.assertRaises(SystemExit) as stopped:
                mmtailscale.run(plan)
        self.assertEqual(stopped.exception.code, 23)
        execute.assert_called_once_with("/usr/bin/ssh", plan["argv"])

    def test_cli_dry_run_is_json_and_needs_no_profile_or_runtime_files(self):
        cli = load_cli()
        before = set(Path(self.root).rglob("*"))
        out = io.StringIO()
        with mock.patch.object(cli.mmcore, "load_profile", side_effect=AssertionError("profile read")), \
                mock.patch("mmtailscale.os.execv", side_effect=AssertionError("SSH launched")), \
                contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["tailscale", "--peer", "worker.example.ts.net", "--user", "worker",
                                       "--dry-run", "--json"]), 0)
        self.assertEqual(json.loads(out.getvalue()), mmtailscale.tunnel("worker.example.ts.net", "worker"))
        self.assertEqual(set(Path(self.root).rglob("*")), before)

    def test_cli_rejects_bad_options_before_network(self):
        cli = load_cli()
        for extra in (["--json"], ["--port", "22"], ["--port", "oops"], ["--other"], ["--peer", "bad"]):
            out = io.StringIO()
            with self.subTest(extra=extra), contextlib.redirect_stdout(out), \
                    mock.patch("mmtailscale.run", side_effect=AssertionError("network")):
                try:
                    rc = cli.main(["tailscale", "--peer", "worker.example.ts.net", "--user", "worker"] + extra)
                except cli.mmcore.MMError as exc:
                    self.assertEqual(exc.code, "E_USAGE")
                else:
                    self.assertEqual(rc, 2)

    def test_cli_missing_ssh_is_one_error_line(self):
        out = io.StringIO()
        with mock.patch("mmtailscale.os.execv", side_effect=FileNotFoundError), contextlib.redirect_stdout(out):
            self.assertEqual(load_cli().main(["tailscale", "--peer", "worker.example.ts.net", "--user", "worker"]), 2)
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        self.assertTrue(out.getvalue().startswith("E_TAILSCALE "))

    def test_launchd_template_uses_same_safe_cli_and_independent_label(self):
        doc = plistlib.loads(Path(CODE, "monitoring/tailscale/org.machine-manager.tailscale.PEER.plist").read_bytes())
        self.assertEqual(doc["Label"], "org.machine-manager.tailscale.PEER")
        argv = doc["ProgramArguments"]
        self.assertEqual(argv[3:], ["tailscale", "--peer", "PEER.TAILNET.ts.net", "--user", "SSH_USER",
                                    "--port", "19877"])
        self.assertTrue(doc["KeepAlive"])
        self.assertEqual(doc["ThrottleInterval"], 15)

    def test_foreground_cli_exec_needs_no_profile_or_file_changes(self):
        cli = load_cli()
        before = set(Path(self.root).rglob("*"))
        with mock.patch.object(cli.mmcore, "load_profile", side_effect=AssertionError("profile read")), \
                mock.patch("mmtailscale.os.execv", side_effect=SystemExit(0)) as execute:
            with self.assertRaises(SystemExit):
                cli.main(["tailscale", "--peer", "worker.example.ts.net", "--user", "worker"])
        self.assertEqual(execute.call_args.args[1], mmtailscale.tunnel("worker.example.ts.net", "worker")["argv"])
        self.assertEqual(set(Path(self.root).rglob("*")), before)

    def test_real_openssh_parses_options_without_connecting(self):
        if not Path(mmtailscale.SSH).is_file():
            self.skipTest("/usr/bin/ssh unavailable")
        plan = mmtailscale.tunnel("worker.example.ts.net", "worker")
        result = subprocess.run([plan["argv"][0], "-G"] + plan["argv"][1:], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("hostname worker.example.ts.net", lines)
        self.assertIn("user worker", lines)
        self.assertIn("stricthostkeychecking true", lines)
        self.assertIn("batchmode yes", lines)
        forwards = [line for line in lines if line.startswith("localforward ")]
        self.assertEqual(len(forwards), 1)
        self.assertIn("127.0.0.1", forwards[0])
        self.assertIn("19877", forwards[0])
        self.assertIn("9877", forwards[0])
