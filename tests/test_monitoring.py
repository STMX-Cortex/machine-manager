# SPDX-License-Identifier: Apache-2.0
"""Loopback hosting, read-only HTTP boundaries, real fleet ingestion, shutdown and service examples."""
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import plistlib
import selectors
import signal
import socket
import subprocess
import threading
import time
from unittest import mock

from mmtest import CODE, MM, TempData, base_settings, mmcore
import mmfleet
import mmserve
from test_fleet import machine_config
from test_resources import load_cli, status_rec


class Hosting(TempData):
    def write_status(self, **over):
        doc = status_rec(time.time(), **dict({"machine_id": self.profile()["machine_id"]}, **over))
        Path(self.data, "status.json").write_text(json.dumps(doc))
        return doc

    @contextlib.contextmanager
    def host(self, bind="127.0.0.1"):
        try:
            server = mmserve.Server(self.profile(), bind, 0)
        except PermissionError:
            self.skipTest("loopback sockets unavailable in command sandbox")
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)
            self.assertFalse(thread.is_alive())

    def request(self, server, path="/metrics", method="GET", headers=None):
        conn = http.client.HTTPConnection(server.server_address[0], server.server_port, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            res = conn.getresponse()
            return res.status, dict(res.getheaders()), res.read()
        finally:
            conn.close()

    def test_metrics_content_type_headers_and_head(self):
        self.write_status()
        with self.host() as server:
            code, headers, body = self.request(server)
            self.assertEqual(code, 200)
            self.assertEqual(headers["Content-Type"], mmserve.CONTENT_TYPE)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(headers["Connection"], "close")
            self.assertEqual(int(headers["Content-Length"]), len(body))
            self.assertIn(b"machine_manager_memory_available_ratio", body)
            code, head, body = self.request(server, method="HEAD")
            self.assertEqual(code, 200)
            self.assertGreater(int(head["Content-Length"]), 0)
            self.assertEqual(body, b"")

    def test_staleness_is_recomputed_without_refreshing_source(self):
        original = self.write_status(time=1_800_000_000)
        with self.host() as server:
            with mock.patch("mmserve.time.time", return_value=original["time"]):
                self.assertIn(b"machine_manager_memory_available_ratio", self.request(server)[2])
                self.assertEqual(self.request(server, "/status.json")[0], 200)
            with mock.patch("mmserve.time.time", return_value=original["time"] + 10000):
                code, _, body = self.request(server)
                self.assertEqual(code, 200)  # Prometheus must retain the health/freshness series
                self.assertIn(b'machine_manager_machine_status_fresh{machine_id="test-machine"} 0', body)
                self.assertNotIn(b"machine_manager_memory_available_ratio", body)
                self.assertEqual(self.request(server, "/status.json")[0], 503)
        self.assertEqual(json.loads(Path(self.data, "status.json").read_text()), original)

    def test_status_exposes_only_selected_fields_and_keeps_source_time(self):
        doc = self.write_status(reasons=["private reason"], heartbeat={"pid": 22, "tick": 1, "note": "private note"},
                                capacity={"private": "secret"}, load={"private": "secret"}, mode="act")
        with self.host() as server:
            code, headers, raw = self.request(server, "/status.json")
            self.assertEqual((code, headers["Content-Type"]), (200, "application/json"))
            public = json.loads(raw)
            self.assertEqual(public["time"], doc["time"])
            self.assertEqual(public["facts"]["ram_mb"], doc["facts"]["ram_mb"])
            for key in ("heartbeat", "capacity", "load", "cpu_model"):
                self.assertNotIn(('"%s":' % key).encode(), raw)
            self.assertNotIn(b"private", raw)
            self.assertEqual(public.get("reasons"), [])
            cfg = machine_config(self.profile()["machine_id"], status_url="http://localhost/status.json", stale_after_s=60)
            self.assertEqual(mmfleet.validate_status(public, cfg, time.time())["slots"], doc["slots"])

    def test_invalid_identity_queue_counts_and_files_fail_closed(self):
        with self.host() as server:
            for over in ({"machine_id": "other"}, {"schema_version": 2}, {"slots": None}, {"waiting": -1},
                         {"time": time.time() + 1000}, {"readings": {"free_pct": "bad"}}):
                with self.subTest(over=over):
                    self.write_status(**over)
                    self.assertEqual(self.request(server, "/status.json")[0], 503)
            path = Path(self.data, "status.json")
            path.unlink()
            self.assertEqual(self.request(server, "/status.json")[0], 503)
            path.symlink_to(Path(self.data, "settings.toml"))
            self.assertEqual(self.request(server, "/status.json")[0], 503)

    def test_health_is_independent_of_status_or_settings(self):
        Path(self.data, "settings.toml").write_text("[broken")
        with self.host() as server:
            self.assertEqual(self.request(server, "/-/healthy")[::2], (200, b"ok\n"))
            self.assertEqual(self.request(server)[0], 200)
            self.assertEqual(self.request(server, "/status.json")[0], 503)

    def test_only_exact_paths_are_served(self):
        self.write_status()
        with self.host() as server:
            for path in ("/", "/settings.toml", "/resources.json", "/fleet.json", "/../status.json",
                         "/%73tatus.json", "//metrics", "//status.json", "/metrics?file=settings.toml",
                         "/status.json?token=secret"):
                self.assertEqual(self.request(server, path)[0], 404, path)

    def test_methods_cannot_write_or_control(self):
        self.write_status()
        with self.host() as server:
            for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                code, headers, body = self.request(server, "/metrics", method=method)
                self.assertEqual(code, 405)
                self.assertEqual(headers["Allow"], "GET, HEAD")
                self.assertNotIn(b"Traceback", body)

    def test_host_header_rejects_dns_rebinding_and_duplicates(self):
        with self.host() as server:
            for host in ("public.example", "localhost.evil", "127.0.0.1.evil", "user@localhost", "0.0.0.0"):
                self.assertEqual(self.request(server, "/-/healthy", headers={"Host": host})[0], 403, host)
            for hosts in ([], ["localhost", "localhost"]):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                try:
                    conn.putrequest("GET", "/-/healthy", skip_host=True)
                    for host in hosts:
                        conn.putheader("Host", host)
                    conn.endheaders()
                    res = conn.getresponse()
                    self.assertEqual(res.status, 403)
                    res.read()
                finally:
                    conn.close()

    def test_requests_do_not_collect_sample_spawn_or_write(self):
        self.write_status()
        before = {str(p.relative_to(self.data)): p.read_bytes() for p in Path(self.data).rglob("*") if p.is_file()}
        with mock.patch("mmfleet.collect", side_effect=AssertionError("collection")), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("command")), \
                mock.patch("mmcore.write_atomic", side_effect=AssertionError("write")):
            with self.host() as server:
                for path in ("/metrics", "/status.json", "/-/healthy"):
                    self.assertEqual(self.request(server, path)[0], 200)
        after = {str(p.relative_to(self.data)): p.read_bytes() for p in Path(self.data).rglob("*") if p.is_file()}
        self.assertEqual(after, before)

    def test_actual_http_status_is_accepted_by_fleet_transport(self):
        self.write_status(mode="act")
        with self.host() as server:
            ident = self.profile()["machine_id"]
            profile = dict(self.profile(), machine_id="central", machines=[machine_config(ident,
                           status_url="http://127.0.0.1:%d/status.json" % server.server_port)])
            rec = mmfleet.collect(profile, base_settings())
            self.assertIsNone(rec["machines"][0]["error"])
            self.assertEqual(mmfleet.cached_statuses(profile, time.time())[0][1]["machine_id"], ident)
            # A later failed endpoint replaces the good cached status, never renews it.
            Path(self.data, "status.json").unlink()
            rec = mmfleet.collect(profile, base_settings())
            self.assertIsNone(rec["machines"][0]["status"])

    def test_response_limit_and_errors_do_not_disclose_internal_details(self):
        with self.host() as server:
            with mock.patch("mmprometheus.export", return_value=("x" * (mmserve.RESPONSE_BYTES + 1), True)):
                self.assertEqual(self.request(server)[::2], (503, b"monitoring data unavailable\n"))
            with mock.patch("mmprometheus.export", side_effect=OSError("private/path and token")):
                self.assertEqual(self.request(server)[::2], (503, b"monitoring data unavailable\n"))
            with mock.patch("mmprometheus.export", side_effect=mmcore.MMError("E_PROFILE", "private", "fix")):
                self.assertEqual(self.request(server)[::2], (503, b"monitoring data unavailable\n"))

    def test_slow_dripping_connections_have_a_wall_deadline(self):
        with mock.patch("mmserve.CONNECTION_WALL_S", .3), self.host() as server:
            conn = socket.create_connection(("127.0.0.1", server.server_port), timeout=2)
            stop = threading.Event()
            def drip():
                while not stop.wait(.05):
                    try:
                        conn.sendall(b"x")
                    except OSError:
                        break
            sender = threading.Thread(target=drip)
            try:
                start = time.monotonic()
                conn.sendall(b"GET /metrics HTTP/1.1\r\n")
                sender.start()
                self.assertEqual(conn.recv(1), b"")
                self.assertLess(time.monotonic() - start, 2)
            finally:
                stop.set()
                if sender.ident is not None:
                    sender.join(2)
                conn.close()

    def test_connection_cap_drops_excess_without_starting_more_workers(self):
        with self.host() as server:
            conns = []
            try:
                for _ in range(mmserve.CONNECTIONS):
                    c = socket.create_connection(("127.0.0.1", server.server_port), timeout=2)
                    conns.append(c)
                    c.sendall(b"GET /metrics HTTP/1.1\r\n")
                until = time.monotonic() + 2
                while server.workers._value and time.monotonic() < until:
                    time.sleep(.01)
                self.assertEqual(server.workers._value, 0)
                with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as excess:
                    self.assertEqual(excess.recv(1), b"")
            finally:
                for conn in conns:
                    conn.close()

    def test_ipv6_loopback_when_available(self):
        try:
            with self.host("::1") as server:
                self.assertEqual(self.request(server, "/-/healthy")[0], 200)
        except OSError as error:
            if error.errno in (49, 97, 99):
                self.skipTest("IPv6 loopback unavailable")
            raise

    def test_cli_rejects_invalid_bind_port_json_and_unknown_args_before_starting(self):
        cli = load_cli()
        with mock.patch("mmserve.run", side_effect=AssertionError("started")):
            for args in (["--bind", "0.0.0.0"], ["--bind", "localhost"], ["--port", "0"], ["--port", "65536"],
                         ["--json"], ["--collect"], ["--port", "nan"]):
                with contextlib.redirect_stdout(io.StringIO()):
                    try:
                        self.assertEqual(cli.main(["serve"] + args), 2)
                    except mmcore.MMError as error:
                        self.assertEqual(error.code, "E_USAGE")

    def test_cli_reports_bind_failure_without_paths(self):
        cli = load_cli()
        out = io.StringIO()
        with mock.patch("mmserve.run", side_effect=OSError("private path")), contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["serve"]), 2)
        self.assertTrue(out.getvalue().startswith("E_SERVE "))
        self.assertNotIn("private path", out.getvalue())

    def test_real_foreground_cli_sigterm_shutdown_and_no_state_creation(self):
        # Reserve then release a temporary port, since the public CLI disallows port zero.
        try:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
        except PermissionError:
            self.skipTest("loopback sockets unavailable in command sandbox")
        data = Path(self.root, "never-created")
        process = subprocess.Popen(MM + ["serve", "--port", str(port), "--data", str(data)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(10), "no foreground startup line")
            self.assertEqual(process.stdout.readline().strip(), "serve=ready bind=127.0.0.1 port=%d" % port)
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=15)
            self.assertEqual((process.returncode, out, err), (0, "", ""))
            self.assertFalse(data.exists())
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


class Examples(TempData):
    def test_launchd_examples_parse_with_absolute_argv_and_separate_labels(self):
        labels = set()
        for path in Path(CODE, "monitoring", "launchd").glob("*.plist"):
            doc = plistlib.loads(path.read_bytes())
            self.assertNotIn(doc["Label"], labels)
            labels.add(doc["Label"])
            self.assertTrue(doc["ProgramArguments"][0].startswith("/ABS/"))
            self.assertEqual(doc["Umask"], 0o077)
        self.assertEqual(len(labels), 3)
