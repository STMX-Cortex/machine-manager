# SPDX-License-Identifier: Apache-2.0
"""Fleet storage export: storage.json, `mm storage record`, GET /storage.json, `mm collect` peer caches and the
exporter reader. Collectors and peers are fakes (no real sampling or waits); the HTTP tests start only their own
loopback fixture servers and skip when the command sandbox forbids sockets."""
import contextlib
import copy
import errno
import http.client
import http.server
import io as stdio
import itertools
import json
import math
import os
from pathlib import Path
import plistlib
import stat
import threading
import time
import unittest
from unittest import mock

from mmtest import CODE, TempData, mmcore
import mmfleet
import mmschema
import mmserve
import mmstorage
import mmstorage_collect
import mmstorage_fleet as fleet
import mmstorage_io
import mmstorage_io_collect
from test_fleet import blob, machine_config, status
from test_resources import load_cli
import test_storage as ts
import test_storage_io as tio

NOW = 1_800_000_000.0
LOCAL = "test-machine"


def capacity(mid=LOCAL, t=NOW, filesystems=None, **over):
    return ts.record(filesystems if filesystems is not None else [ts.filesystem()], machine_id=mid, time=t, **over)


def io(mid=LOCAL, t=NOW + 1):
    rec = tio.observed()
    rec.update(machine_id=mid, time=t)
    return rec


def snap(mid=LOCAL, t=NOW, **over):
    return fleet.build(mid, capacity(mid, t, **over), io(mid, t + 1))


def many_filesystems(n=128):
    return [ts.filesystem("fs-%d" % i, mounts=["/data/volume-%03d" % i]) for i in range(n)]


class Validator(unittest.TestCase):
    def test_snapshot_matches_schema_validator_and_time_rule(self):
        doc = snap()
        self.assertTrue(fleet.valid(doc))
        self.assertEqual(mmschema.validate(doc, mmschema.load("storage-snapshot")), [])
        self.assertEqual(set(doc), set(fleet.KEYS))
        self.assertEqual(doc["time"], NOW)
        self.assertEqual(fleet.valid(json.loads(fleet.dumps(doc))), True)
        self.assertTrue(fleet.dumps(doc).isascii() and fleet.dumps(doc).endswith("}\n"))

    def test_schema_embeds_exact_copies_of_both_record_schemas(self):
        schema = mmschema.load("storage-snapshot")
        cap, rate = mmschema.load("storage"), mmschema.load("storage-io")
        for name, value in cap.pop("$defs").items():
            self.assertEqual(schema["$defs"][name], value)
        cap.pop("$schema"), rate.pop("$schema")
        self.assertEqual(schema["$defs"]["storage"], cap)
        self.assertEqual(schema["$defs"]["storage_io"], rate)
        self.assertTrue(mmschema.validate(dict(snap(), extra=1), schema))
        bad = snap()
        bad["capacity"]["state"] = "BROKEN"
        self.assertTrue(mmschema.validate(bad, schema))

    def test_envelope_keys_identity_and_time_are_rejected(self):
        good = snap()
        self.assertFalse(fleet.valid(None))
        self.assertFalse(fleet.valid([good]))
        cases = [dict(good, extra=1), {k: v for k, v in good.items() if k != "io"}, dict(good, kind="storage"),
                 dict(good, schema_version=2), dict(good, schema_version=True), dict(good, machine_id="other"),
                 dict(good, machine_id=None), dict(good, time=NOW + 1), dict(good, time=NOW - 1),
                 dict(good, time=True), dict(good, time=float("nan")), dict(good, time=str(NOW))]
        for doc in cases:
            with self.subTest(doc={k: v for k, v in doc.items() if k not in ("capacity", "io")}):
                self.assertFalse(fleet.valid(doc))

    def test_sub_record_identity_and_validity_are_checked(self):
        good = snap()
        for key, field, value in (("capacity", "machine_id", "other"), ("io", "machine_id", "other"),
                                  ("capacity", "state", "BROKEN"), ("io", "kind", "storage"),
                                  ("capacity", "schema_version", 2), ("io", "devices", "x")):
            doc = copy.deepcopy(good)
            doc[key][field] = value
            with self.subTest(key=key, field=field):
                self.assertFalse(fleet.valid(doc))
        doc = copy.deepcopy(good)
        doc["capacity"]["filesystems"][0]["capacity"]["used_bytes"] = 1
        self.assertFalse(fleet.valid(doc))
        with self.assertRaises(ValueError):
            fleet.build(LOCAL, capacity("other"), io())
        with self.assertRaises(ValueError):
            fleet.build(LOCAL, capacity(), dict(io(), state="BROKEN"))

    def test_bounded_strict_reader(self):
        root = Path(self._tmp())
        good = root / "good.json"
        good.write_text(fleet.dumps(snap()))
        self.assertEqual(fleet.read(str(good), fleet.SNAPSHOT_BYTES), snap())
        self.assertIsNone(fleet.read(str(good), 100), "byte bound")
        for name, raw in (("deep", "[" * 33 + "]" * 33), ("dup", '{"a":1,"a":2}'), ("nan", '{"a":NaN}'),
                          ("inf", '{"a":Infinity}'), ("big", '{"a":1e999}'), ("text", "not json"), ("utf", b"\xff")):
            path = root / name
            path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
            with self.subTest(name=name):
                self.assertIsNone(fleet.read(str(path), fleet.SNAPSHOT_BYTES))
        self.assertEqual(fleet.read(str(root / "shallow"), 10), None, "missing")
        (root / "shallow").write_text("[" * 31 + "]" * 31)
        self.assertIsNotNone(fleet.read(str(root / "shallow"), 1000))
        (root / "link").symlink_to(good)
        self.assertIsNone(fleet.read(str(root / "link"), fleet.SNAPSHOT_BYTES), "no links")
        os.mkfifo(root / "fifo")
        self.assertIsNone(fleet.read(str(root / "fifo"), fleet.SNAPSHOT_BYTES), "no FIFO waits")

    def _tmp(self):
        import tempfile
        path = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, path, True)
        return path

    def test_oversize_fallback_truncates_largest_then_both(self):
        cap, rate = capacity(filesystems=many_filesystems()), io()
        full = fleet.build(LOCAL, cap, rate)
        self.assertEqual(full["capacity"]["state"], "OK")
        size = len(fleet.dumps(full))
        with mock.patch.object(fleet, "SNAPSHOT_BYTES", size):
            self.assertEqual(fleet.build(LOCAL, cap, rate), full, "exactly at the bound is kept")
        with mock.patch.object(fleet, "SNAPSHOT_BYTES", size - 1):
            doc = fleet.build(LOCAL, cap, rate)
        self.assertEqual((doc["capacity"]["state"], doc["capacity"]["reason"]), ("UNKNOWN", "truncated"))
        self.assertEqual((doc["capacity"]["devices"], doc["capacity"]["filesystems"]), ([], []))
        self.assertEqual(doc["capacity"]["time"], NOW, "source time kept, not refreshed")
        self.assertEqual(doc["io"], full["io"])
        self.assertTrue(fleet.valid(doc))
        self.assertFalse(fleet.complete(doc))
        with mock.patch.object(fleet, "SNAPSHOT_BYTES", len(fleet.dumps(doc)) - 1):
            both = fleet.build(LOCAL, cap, rate)
        self.assertEqual([both[k]["reason"] for k in ("capacity", "io")], ["truncated", "truncated"])
        self.assertEqual((both["io"]["devices"], both["io"]["removed_ids"]), ([], []))
        self.assertTrue(fleet.valid(both))
        with mock.patch.object(fleet, "SNAPSHOT_BYTES", 100), self.assertRaises(ValueError):
            fleet.build(LOCAL, cap, rate)

    def test_build_masks_text_like_the_storage_command(self):
        cap = capacity(filesystems=[ts.filesystem(mounts=["/srv/TOKEN=hunter2hunter2hunter2"])])
        doc = fleet.build(LOCAL, cap, io())
        self.assertTrue(fleet.valid(doc))
        self.assertNotIn("hunter2", fleet.dumps(doc))
        self.assertTrue(fleet._clean_text(doc), "a masked snapshot is stable under the peer check")


class Record(TempData):
    def run_cli(self, *args, cap=None, rate=None):
        cli, out = load_cli(), stdio.StringIO()
        cap = capacity(t=time.time()) if cap is None else cap
        rate = io(t=time.time()) if rate is None else rate
        with mock.patch.object(mmstorage_collect, "collect", return_value=cap) as c, \
                mock.patch.object(mmstorage_io_collect, "collect", return_value=rate) as i, \
                contextlib.redirect_stdout(out):
            rc = cli.main(["storage", "record", *args])
        return rc, out.getvalue(), c, i

    def test_complete_record_writes_owner_only_file_and_exits_0(self):
        rc, out, cap, rate = self.run_cli("--include", "/data", "--exclude", "/tmp", "--interval", ".5")
        self.assertEqual(rc, 0, out)
        cap.assert_called_once_with(LOCAL, include=["/data"], exclude=["/tmp"])
        rate.assert_called_once_with(LOCAL, interval_s=.5)
        self.assertEqual(out.splitlines(), ["storage_record=written path=storage.json capacity=OK io=OK "
                                            "filesystems=1 devices=1"])
        path = Path(self.data, "storage.json")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        doc = json.loads(path.read_text())
        self.assertTrue(fleet.valid(doc))
        self.assertEqual(path.read_text(), fleet.dumps(doc))
        self.assertEqual([p.name for p in Path(self.data).iterdir() if p.name.startswith(".")], [], "no temp file left")

    def test_json_prints_the_snapshot_and_default_interval_is_one_second(self):
        rc, out, _, rate = self.run_cli("--json")
        self.assertEqual(rc, 0)
        rate.assert_called_once_with(LOCAL, interval_s=1.0)
        self.assertEqual(json.loads(out), json.loads(Path(self.data, "storage.json").read_text()))

    def test_partial_or_unknown_is_written_with_exit_1(self):
        now = time.time()
        for cap, rate in ((capacity(t=now), mmstorage_io.envelope(LOCAL, now, 1, "timeout")),
                          (capacity(t=now, state="PARTIAL", reason="truncated"), io(t=now)),
                          (capacity(t=now, filesystems=[ts.filesystem(capacity=mmstorage.capacity(),
                                                                      capacity_reason="timeout")]), io(t=now))):
            with self.subTest(cap=cap["state"], rate=rate["state"]):
                rc, out, _, _ = self.run_cli(cap=cap, rate=rate)
                self.assertEqual(rc, 1, out)
                self.assertTrue(out.startswith("storage_record=written "))
                self.assertTrue(fleet.valid(json.loads(Path(self.data, "storage.json").read_text())))
        rate = io(t=now)
        rate["devices"][0].update(rates=dict.fromkeys(mmstorage_io.RATE_KEYS), rate_reason="baseline_missing")
        self.assertEqual(self.run_cli(rate=rate)[0], 1)

    def test_usage_errors_exit_2_before_any_collection_or_write(self):
        for args in (["--interval"], ["--interval", "nan"], ["--interval", "0.01"], ["--interval", "31"],
                     ["--interval", "TOKEN=private"], ["--interval", "1", "--interval", "2"], ["--bogus", "x"],
                     ["--include"], ["io"]):
            with self.subTest(args=args):
                rc, out, cap, rate = self.run_cli(*args)
                self.assertEqual(rc, 2)
                self.assertEqual(len(out.splitlines()), 1)
                self.assertRegex(out, r"^E_[A-Z]+ ")
                self.assertNotIn("private", out)
                cap.assert_not_called()
                rate.assert_not_called()
        self.assertFalse(Path(self.data, "storage.json").exists())

    def test_invalid_selection_and_write_failure_exit_2(self):
        cli, out = load_cli(), stdio.StringIO()
        with mock.patch.object(mmstorage_collect, "collect", side_effect=ValueError("private")), \
                mock.patch.object(mmstorage_io_collect, "collect") as rate, contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["storage", "record", "--include", "relative"]), 2)
        rate.assert_not_called()
        self.assertTrue(out.getvalue().startswith("E_STORAGE "))
        with mock.patch.object(mmcore, "write_atomic", side_effect=OSError("/private/path")):
            rc, out, cap, rate = self.run_cli()
        self.assertEqual(rc, 2)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertTrue(out.startswith("E_WRITE ") and "private" not in out)
        self.assertFalse(Path(self.data, "storage.json").exists())

    def test_existing_storage_commands_write_nothing(self):
        cli = load_cli()
        before = set(Path(self.root).rglob("*"))
        with mock.patch.object(mmstorage_collect, "collect", return_value=capacity()), \
                mock.patch.object(mmstorage_io_collect, "collect", return_value=io()), \
                contextlib.redirect_stdout(stdio.StringIO()):
            self.assertEqual(cli.main(["storage"]), 0)
            self.assertEqual(cli.main(["storage", "io"]), 0)
        self.assertEqual(set(Path(self.root).rglob("*")), before)


class Serve(TempData):
    @contextlib.contextmanager
    def host(self):
        try:
            server = mmserve.Server(self.profile(), "127.0.0.1", 0)
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

    def request(self, server, method="GET", path="/storage.json", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            res = conn.getresponse()
            return res.status, dict(res.getheaders()), res.read()
        finally:
            conn.close()

    def write(self, doc):
        Path(self.data, "storage.json").write_text(doc if isinstance(doc, str) else fleet.dumps(doc))

    def test_fresh_valid_snapshot_is_served_and_head_has_no_body(self):
        doc = snap(t=time.time())
        self.write(json.dumps(doc, ensure_ascii=False, indent=2))  # re-serialized, not raw bytes
        with self.host() as server:
            code, headers, body = self.request(server)
            self.assertEqual(code, 200)
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(body, fleet.dumps(doc).encode())
            self.assertEqual(int(headers["Content-Length"]), len(body))
            code, head, body = self.request(server, "HEAD")
            self.assertEqual((code, body), (200, b""))
            self.assertEqual(head["Content-Length"], headers["Content-Length"])
            self.assertEqual(self.request(server, path="/storage.json?x=1")[0], 404)
            self.assertEqual(self.request(server, "POST")[0], 405)
            self.assertEqual(self.request(server, path="/-/healthy")[0], 200)

    def test_missing_invalid_stale_future_or_foreign_snapshots_are_503(self):
        now = time.time()
        with self.host() as server:
            self.assertEqual(self.request(server)[::2], (503, b"storage snapshot unavailable\n"))
            for doc in (snap(t=now - fleet.STORAGE_FRESH_S - 1), snap(t=now + 60), snap("other", now),
                        dict(snap(t=now), extra=1), "not json", '{"a":1,"a":2}'):
                self.write(doc)
                with self.subTest(doc=str(doc)[:60]):
                    self.assertEqual(self.request(server)[::2], (503, b"storage snapshot unavailable\n"))
                    code, _, body = self.request(server, "HEAD")
                    self.assertEqual((code, body), (503, b""))
            os.unlink(Path(self.data, "storage.json"))
            target = Path(self.root, "elsewhere.json")
            target.write_text(fleet.dumps(snap(t=now)))
            Path(self.data, "storage.json").symlink_to(target)
            self.assertEqual(self.request(server)[0], 503, "links are not followed")

    def test_host_rule_and_no_writes_or_collection(self):
        self.write(snap(t=time.time()))
        before = {p: p.read_bytes() for p in Path(self.data).rglob("*") if p.is_file()}
        with mock.patch.object(mmstorage_collect, "collect", side_effect=AssertionError("collect")), \
                mock.patch.object(mmstorage_io_collect, "collect", side_effect=AssertionError("collect")), \
                mock.patch("mmcore.write_atomic", side_effect=AssertionError("write")), self.host() as server:
            for host in ("public.example", "localhost.evil", "127.0.0.1.evil"):
                self.assertEqual(self.request(server, headers={"Host": host})[0], 403, host)
            self.assertEqual(self.request(server, headers={"Host": "localhost:9877"})[0], 200)
        self.assertEqual({p: p.read_bytes() for p in Path(self.data).rglob("*") if p.is_file()}, before)

    def test_oversized_reserialization_is_503(self):
        self.write(snap(t=time.time()))
        with mock.patch.object(fleet, "SNAPSHOT_BYTES", 100), self.host() as server:
            self.assertEqual(self.request(server)[0], 503)


class Collect(TempData):
    def fleet_profile(self, *configs):
        profile = self.profile()
        profile["machines"] = list(configs) if configs else [
            machine_config("peer-a", storage_url="https://example.invalid/storage.json"), machine_config("peer-b")]
        return profile

    def cache(self, ident="peer-a"):
        return json.loads(Path(self.data, "fleet-storage", ident + ".json").read_text())

    def test_profile_storage_keys_are_optional_and_validated(self):
        cfgs = mmfleet.configs(self.fleet_profile())
        self.assertEqual([c["storage_stale_after_s"] for c in cfgs], [300, 300])
        self.assertNotIn("storage_url", cfgs[1])
        self.assertEqual(mmschema.validate(self.fleet_profile()["machines"],
                                           mmschema.load("profile")["properties"]["machines"]), [])
        for bad in ({"storage_url": "file:///tmp/storage.json"}, {"storage_url": "https://user:password@example.com/storage.json"},
                    {"storage_url": "https://example.invalid/s#frag"}, {"storage_url": ""},
                    {"storage_stale_after_s": 0}, {"storage_stale_after_s": 3601}, {"storage_stale_after_s": True},
                    {"storage_stale_after_s": float("nan")}):
            with self.subTest(bad=bad), self.assertRaises(mmcore.MMError) as caught:
                mmfleet.configs(self.fleet_profile(machine_config("peer-a", **bad)))
            self.assertNotIn("password", str(caught.exception))
        for url in ("https://example.invalid/storage.json?token=abc123", "https://example.invalid/storage.json?"):
            with self.subTest(url=url), self.assertRaises(mmcore.MMError) as caught:
                mmfleet.configs(self.fleet_profile(machine_config("peer-a", storage_url=url)))
            self.assertIn("storage URL must not contain a query string", str(caught.exception))
            self.assertNotIn("abc123", str(caught.exception))

    def test_good_peer_snapshot_is_cached_and_peers_without_url_are_untouched(self):
        other = Path(self.data, "fleet-storage", "peer-b.json")
        other.parent.mkdir()
        other.write_text("owner data")
        doc = snap("peer-a", NOW - 10)
        self.assertEqual(fleet.collect(self.fleet_profile(), now=NOW, fetcher=lambda cfg: fleet.dumps(doc).encode()),
                         [("peer-a", True)])
        rec = self.cache()
        self.assertEqual(rec, {"kind": "fleet_storage", "schema_version": 1, "machine_id": LOCAL, "id": "peer-a",
                               "collected_at": NOW, "snapshot": doc, "error": None})
        self.assertEqual(stat.S_IMODE(Path(self.data, "fleet-storage", "peer-a.json").stat().st_mode), 0o600)
        self.assertEqual(other.read_text(), "owner data")
        self.assertEqual(sorted(p.name for p in other.parent.iterdir()), ["peer-a.json", "peer-b.json"])
        marker = Path(self.data, fleet.ATTEMPT)
        self.assertEqual(json.loads(marker.read_text()), {"kind": "fleet_storage_attempt", "schema_version": 1,
                                                          "machine_id": LOCAL, "time": NOW})
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)

    def test_bad_responses_write_null_and_never_revive_the_old_good_file(self):
        profile, good = self.fleet_profile(), snap("peer-a", NOW)
        masked = copy.deepcopy(good)
        masked["capacity"]["filesystems"][0]["mounts"] = ["/srv/TOKEN=hunter2hunter2hunter2"]
        self.assertTrue(fleet.valid(masked))
        big = fleet.dumps(snap("peer-a", NOW, filesystems=many_filesystems())).encode()

        def fail(cfg):
            raise mmfleet.FleetError("HTTP 404 https://example.invalid/storage.json")
        responses = [("wrong machine", fleet.dumps(snap("peer-b", NOW)).encode()),
                     ("stale", fleet.dumps(snap("peer-a", NOW - 300)).encode()),
                     ("future", fleet.dumps(snap("peer-a", NOW + 6)).encode()),
                     ("invalid", fleet.dumps(dict(good, extra=1)).encode()),
                     ("duplicate", b'{"kind":1,"kind":2}'), ("nan", b'{"time":NaN}'),
                     ("masked text", fleet.dumps(masked).encode()), ("oversize", big), ("404", fail)]
        for name, response in responses:
            fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(good).encode())
            self.assertIsNotNone(self.cache()["snapshot"])
            fetcher = response if callable(response) else (lambda cfg, r=response: r)
            with self.subTest(name=name), mock.patch.object(fleet, "SNAPSHOT_BYTES", len(big) - 1):
                self.assertEqual(fleet.collect(profile, now=NOW, fetcher=fetcher), [("peer-a", False)])
                rec = self.cache()
                self.assertEqual((rec["snapshot"], rec["error"], rec["collected_at"]), (None, fleet.PEER_ERROR, NOW))
                self.assertNotIn("hunter2", json.dumps(rec))
                self.assertEqual(fleet.exported_snapshots(profile, NOW)[0], ("peer-a", None, False))

    def test_attempt_marker_failure_fetches_nothing_and_exits_1(self):
        original = mmcore.write_atomic

        def write(target, text, mode=None):
            if os.path.basename(target) == fleet.ATTEMPT:
                raise OSError("/private/path")
            return original(target, text, mode)
        fetcher = mock.Mock(return_value=fleet.dumps(snap("peer-a", NOW)).encode())
        with mock.patch.object(mmcore, "write_atomic", side_effect=write):
            self.assertEqual(fleet.collect(self.fleet_profile(), now=NOW, fetcher=fetcher), [("peer-a", False)])
            fetcher.assert_not_called()
            rc, out = self.run_collect(self.fleet_profile(), lambda cfg: fleet.dumps(snap("peer-a", time.time())).encode())
        self.assertEqual(rc, 1)
        self.assertIn("storage=UNKNOWN", out)
        self.assertNotIn("private", out)
        self.assertFalse(Path(self.data, "fleet-storage").exists())

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_failed_replace_and_unlink_leave_the_old_entry_not_fresh(self):
        profile, good = self.fleet_profile(), snap("peer-a", NOW)
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(good).encode())
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 1)[0], ("peer-a", good, True))
        folder = Path(self.data, "fleet-storage")
        folder.chmod(0o500)  # neither a new temp file, a rename nor an unlink can succeed
        self.addCleanup(folder.chmod, 0o700)
        self.assertEqual(fleet.collect(profile, now=NOW + 10, fetcher=lambda cfg: fleet.dumps(good).encode()),
                         [("peer-a", False)])
        self.assertEqual(self.cache()["collected_at"], NOW, "the old entry is still there")
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 11)[0], ("peer-a", good, False))

    def test_linked_or_non_directory_cache_is_neither_read_nor_written(self):
        profile, good = self.fleet_profile(), snap("peer-a", NOW)
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(good).encode())
        folder, elsewhere = Path(self.data, "fleet-storage"), Path(self.root, "elsewhere")
        folder.rename(elsewhere)
        folder.symlink_to(elsewhere, target_is_directory=True)
        before = {p.name: p.read_bytes() for p in elsewhere.iterdir()}
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 1)[0], ("peer-a", None, False))
        fetcher = mock.Mock(return_value=fleet.dumps(good).encode())
        self.assertEqual(fleet.collect(profile, now=NOW + 2, fetcher=fetcher), [("peer-a", False)])
        fetcher.assert_not_called()
        self.assertEqual({p.name: p.read_bytes() for p in elsewhere.iterdir()}, before)
        self.assertTrue(folder.is_symlink())
        folder.unlink()
        folder.write_text("not a directory")
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 3)[0], ("peer-a", None, False))
        self.assertEqual(fleet.collect(profile, now=NOW + 3, fetcher=fetcher), [("peer-a", False)])
        self.assertEqual(folder.read_text(), "not a directory")

    @contextlib.contextmanager
    def http_fixture(self, bodies):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = bodies.get(self.path)
                self.send_response(200 if body is not None else 404)
                body = body if body is not None else b"missing"
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        class Quiet(http.server.HTTPServer):
            def handle_error(self, request, client_address):
                pass  # the worker hangs up on purpose when a body exceeds its limit
        try:
            server = Quiet(("127.0.0.1", 0), Handler)
        except PermissionError:
            self.skipTest("loopback sockets unavailable in command sandbox")
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
        thread.start()
        try:
            yield "http://127.0.0.1:%d" % server.server_port
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_worker_validates_and_canonicalizes_while_status_keeps_its_limit(self):
        now = time.time()
        doc = snap("peer-a", now)
        bodies = {"/status": b"x" * ((1 << 20) + 10), "/good": json.dumps(doc, indent=2).encode(),
                  "/stale": fleet.dumps(snap("peer-a", now - 400)).encode()}
        with self.http_fixture(bodies) as base:
            with self.assertRaises(mmfleet.FleetError):
                mmfleet.fetch(machine_config(status_url=base + "/status", timeout_s=10))  # status: 1 MiB, unchanged
            cfg = mmfleet.configs(self.fleet_profile(machine_config("peer-a", storage_url=base + "/good", timeout_s=10)))[0]
            self.assertEqual(fleet.fetch(cfg), fleet.dumps(doc).encode(), "canonical output, not the raw body")
            for path in ("/stale", "/missing"):
                cfg["storage_url"] = base + path
                with self.subTest(path=path), self.assertRaises(mmfleet.FleetError):
                    fleet.fetch(cfg)

    def test_marker_write_failure_after_unlink_leaves_no_peer_fresh(self):
        profile, good = self.fleet_profile(), snap("peer-a", NOW)
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(good).encode())
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 1)[0], ("peer-a", good, True))
        original = mmcore.write_atomic

        def full(target, text, mode=None):
            if os.path.basename(target) == fleet.ATTEMPT:
                raise OSError(errno.ENOSPC, "No space left on device")
            return original(target, text, mode)
        fetcher = mock.Mock(return_value=fleet.dumps(good).encode())
        with mock.patch.object(mmcore, "write_atomic", side_effect=full):
            self.assertEqual(fleet.collect(profile, now=NOW + 10, fetcher=fetcher), [("peer-a", False)])
        fetcher.assert_not_called()
        self.assertFalse(Path(self.data, fleet.ATTEMPT).exists(), "the old marker was removed first")
        self.assertEqual(self.cache()["collected_at"], NOW, "the old entry is still on disk")
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 11)[0], ("peer-a", None, False))

    def test_marker_unlink_failure_fetches_nothing(self):
        profile, good = self.fleet_profile(), snap("peer-a", NOW)
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(good).encode())
        unlink = os.unlink

        def refuse(path, *args, **kwargs):
            if os.path.basename(str(path)) == fleet.ATTEMPT:
                raise PermissionError(errno.EACCES, "denied")
            return unlink(path, *args, **kwargs)
        fetcher = mock.Mock(return_value=fleet.dumps(good).encode())
        with mock.patch("os.unlink", side_effect=refuse):
            self.assertEqual(fleet.collect(profile, now=NOW + 10, fetcher=fetcher), [("peer-a", False)])
        fetcher.assert_not_called()
        os.unlink(Path(self.data, fleet.ATTEMPT))
        self.assertEqual(fleet.collect(profile, now=NOW + 20, fetcher=fetcher), [("peer-a", True)], "a missing marker is fine")

    def test_worker_checks_freshness_with_the_clock_after_the_response(self):
        clock = [NOW]
        doc = snap("peer-a", NOW + 7)  # the peer wrote it while the 7 s request was running

        def slow(url, timeout, limit):
            clock[0] += 7
            return fleet.dumps(doc).encode()
        request = json.dumps({"url": "https://example.invalid/storage.json", "timeout": 10, "id": "peer-a",
                              "stale_after_s": 300}).encode()
        with mock.patch.object(mmfleet, "_http", side_effect=slow), mock.patch.object(fleet.time, "time",
                                                                                      side_effect=lambda: clock[0]):
            self.assertEqual(fleet.worker_main(request), fleet.dumps(doc).encode())
        with self.assertRaises(mmfleet.FleetError):
            fleet.worker_output(fleet.dumps(doc).encode(), {"id": "peer-a", "storage_stale_after_s": 300}, NOW)
        self.assertEqual(fleet.collect(self.fleet_profile(), now=NOW + 7, fetcher=lambda cfg: fleet.dumps(doc).encode()),
                         [("peer-a", True)], "the collector's later check uses its own clock")

    def test_wide_json_is_rejected_in_the_worker_not_parsed_by_the_collector(self):
        wide = b"[" + b"0," * 999999 + b"0]"  # 2 MB, inside the byte bound
        self.assertLess(len(wide), fleet.SNAPSHOT_BYTES)
        with self.http_fixture({"/wide": wide}) as base:
            profile = self.fleet_profile(machine_config("peer-a", storage_url=base + "/wide", timeout_s=10))
            loads, seen = json.loads, []

            def spy(raw, *args, **kwargs):
                seen.append(len(raw))
                return loads(raw, *args, **kwargs)
            with mock.patch.object(mmfleet, "_strict_json", wraps=mmfleet._strict_json) as strict, \
                    mock.patch("json.loads", side_effect=spy):
                self.assertEqual(fleet.collect(profile), [("peer-a", False)])
            strict.assert_not_called()
            self.assertFalse([n for n in seen if n >= len(wide)], "the collector never decodes the raw response")
        self.assertIsNone(self.cache()["snapshot"])

    def run_collect(self, profile, storage_response, *flags):
        cli, out = load_cli(), stdio.StringIO()
        with mock.patch.object(mmfleet, "fetch", side_effect=lambda cfg: blob(status(cfg["id"], time=time.time()))), \
                mock.patch.object(fleet, "fetch", side_effect=lambda cfg: storage_response(cfg)), \
                mock.patch("mmcore.load_profile", return_value=profile), contextlib.redirect_stdout(out):
            rc = cli.main(["collect", *flags])
        return rc, out.getvalue()

    def test_cli_plain_lines_json_output_and_fleet_json_are_unchanged(self):
        profile = self.fleet_profile()
        rc, out = self.run_collect(profile, lambda cfg: fleet.dumps(snap("peer-a", time.time())).encode())
        self.assertEqual(rc, 0, out)
        lines = out.splitlines()
        self.assertEqual(lines[0], "collected=2 unavailable=0")
        self.assertTrue(lines[1].startswith("machine=peer-a state=GREEN ") and lines[1].endswith(" error=none storage=OK"))
        self.assertTrue(lines[2].startswith("machine=peer-b ") and "storage=" not in lines[2])
        fleet_doc = json.loads(Path(self.data, "fleet.json").read_text())
        self.assertEqual(set(fleet_doc), {"kind", "time", "machines", "machine_id", "schema_version"})
        self.assertEqual([set(r) for r in fleet_doc["machines"]], [{"id", "collected_at", "status", "error"}] * 2)
        self.assertEqual(mmschema.validate(fleet_doc, mmschema.load("fleet")), [])
        rc, out = self.run_collect(profile, lambda cfg: b"bad", "--json")
        self.assertEqual(rc, 1, "configured storage unavailable")
        self.assertEqual(json.loads(out), json.loads(Path(self.data, "fleet.json").read_text()))
        self.assertIsNone(self.cache()["snapshot"])
        rc, out = self.run_collect(self.fleet_profile(machine_config("peer-b")), lambda cfg: b"bad")
        self.assertEqual(rc, 0, "no storage_url: no storage fetch, no storage word")
        self.assertNotIn("storage=", out)


class Files(TempData):
    def test_mode_write_ignores_fifo_and_hard_link_at_the_old_temp_name(self):
        target = Path(self.data, "storage.json")
        planted = Path(self.data, ".storage.json.%d.tmp" % os.getpid())
        victim = Path(self.root, "victim")
        victim.write_text("keep")
        for plant in (lambda: os.mkfifo(planted), lambda: os.link(victim, planted)):
            plant()
            done = threading.Thread(target=mmcore.write_atomic, args=(str(target), "new\n"), kwargs={"mode": 0o600},
                                    daemon=True)
            done.start()
            done.join(5)
            self.assertFalse(done.is_alive(), "never blocks on a planted FIFO")
            self.assertEqual(target.read_text(), "new\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertTrue(stat.S_ISFIFO(planted.lstat().st_mode) or planted.read_text() == "keep")
            self.assertEqual(victim.read_text(), "keep")
            self.assertEqual(sorted(p.name for p in Path(self.data).glob(".storage.json*")), [planted.name])
            planted.unlink()
            target.unlink()

    def test_mode_write_removes_its_temp_file_on_failure_and_default_path_is_unchanged(self):
        target = Path(self.data, "storage.json")
        with mock.patch("os.replace", side_effect=OSError("disk")), self.assertRaises(OSError):
            mmcore.write_atomic(str(target), "x", mode=0o600)
        self.assertEqual(list(Path(self.data).glob(".storage.json*")), [])
        self.assertFalse(target.exists())
        mmcore.write_atomic(str(target), "plain")
        self.assertEqual(target.read_text(), "plain")

    def test_service_deadlines_cover_status_and_storage_phases(self):
        def unit(name):
            return dict(line.split("=", 1) for line in Path(CODE, "monitoring", "systemd", name).read_text().splitlines()
                        if "=" in line and not line.startswith("#"))
        rounds = math.ceil(mmfleet.MAX_PEERS / 4)
        self.assertGreater(int(unit("mm-collect.service")["TimeoutStartSec"]), 2 * rounds * 30 + 60)
        storage = unit("mm-storage.service")
        self.assertEqual(storage["SuccessExitStatus"], "1")
        self.assertIn("storage record", storage["ExecStart"])
        self.assertEqual(unit("mm-storage.timer")["OnUnitInactiveSec"], "60")
        plist = plistlib.loads(Path(CODE, "monitoring", "launchd", "org.machine-manager.storage.plist").read_bytes())
        self.assertEqual((plist["StartInterval"], plist["Umask"], plist["ProgramArguments"][3:5]),
                         (60, 0o077, ["storage", "record"]))


class Exported(TempData):
    def setUp(self):
        super().setUp()
        fleet._CHECKED.clear()
        fleet._NEXT[0] = 0

    def profile_with(self, **over):
        profile = self.profile()
        profile["machines"] = [machine_config("peer-a", storage_url="https://example.invalid/storage.json", **over),
                               machine_config("peer-b"),
                               machine_config("peer-c", storage_url="https://example.invalid/c/storage.json")]
        return profile

    def write_local(self, text):
        Path(self.data, "storage.json").write_text(text)

    def test_local_only_when_the_file_exists(self):
        profile = self.profile()
        self.assertEqual(fleet.exported_snapshots(profile, NOW), [])
        doc = snap(t=NOW)
        self.write_local(fleet.dumps(doc))
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 10), [(LOCAL, doc, True)])
        self.assertEqual(fleet.exported_snapshots(profile, NOW + fleet.STORAGE_FRESH_S), [(LOCAL, doc, False)])
        self.assertEqual(fleet.exported_snapshots(profile, NOW - 6), [(LOCAL, doc, False)], "future")
        self.assertEqual(fleet.exported_snapshots(profile, NOW - 5), [(LOCAL, doc, True)])
        for text in ("not json", fleet.dumps(dict(doc, extra=1)), fleet.dumps(snap("other", NOW)), ""):
            self.write_local(text)
            self.assertEqual(fleet.exported_snapshots(profile, NOW), [(LOCAL, None, False)])
        os.unlink(Path(self.data, "storage.json"))
        Path(self.data, "storage.json").symlink_to(Path(self.root, "missing"))
        self.assertEqual(fleet.exported_snapshots(profile, NOW), [(LOCAL, None, False)], "dangling link exists")

    def test_peer_freshness_needs_collection_and_source_age(self):
        profile = self.profile_with(storage_stale_after_s=120)
        doc = snap("peer-a", NOW - 100)
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(doc).encode() if cfg["id"] == "peer-a" else b"")
        self.write_local(fleet.dumps(snap(t=NOW)))
        got = fleet.exported_snapshots(profile, NOW + 10)
        self.assertEqual(got, [(LOCAL, snap(t=NOW), True), ("peer-a", doc, True), ("peer-c", None, False)])
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 25)[1], ("peer-a", doc, False), "source age 125")
        self.assertEqual(fleet.exported_snapshots(profile, NOW - 6)[1], ("peer-a", doc, False), "collected in future")
        # A fresh source does not hide an old collection.
        young = snap("peer-a", NOW + 3)  # source age stays below the limit when collection age reaches it
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(young).encode())
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 119)[1], ("peer-a", young, True))
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 120)[1], ("peer-a", young, False), "collection age")

    def test_missing_invalid_or_foreign_peer_caches_are_none(self):
        profile = self.profile_with()
        self.assertEqual(fleet.exported_snapshots(profile, NOW), [("peer-a", None, False), ("peer-c", None, False)])
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(snap(cfg["id"], NOW)).encode())
        path = Path(self.data, "fleet-storage", "peer-a.json")
        good = json.loads(path.read_text())
        self.assertEqual(fleet.exported_snapshots(profile, NOW)[0][2], True)
        for rec in (dict(good, extra=1), dict(good, id="peer-c"), dict(good, machine_id="central"),
                    dict(good, kind="fleet"), dict(good, collected_at=None), dict(good, snapshot=snap("peer-c", NOW)),
                    dict(good, snapshot=dict(good["snapshot"], time=NOW + 1)), dict(good, error=fleet.PEER_ERROR),
                    dict(good, error="other text"), dict(good, error=""), dict(good, snapshot=None, error=None),
                    {k: v for k, v in good.items() if k != "error"}):
            path.write_text(json.dumps(rec))
            self.assertEqual(fleet.exported_snapshots(profile, NOW)[0], ("peer-a", None, False))
        path.write_text(json.dumps(good) + " " * (fleet.CACHE_BYTES + 1))
        self.assertEqual(fleet.exported_snapshots(profile, NOW)[0], ("peer-a", None, False), "byte bound")

    def test_peers_need_a_valid_attempt_marker_no_older_than_the_entry(self):
        profile = self.profile_with()
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(snap(cfg["id"], NOW)).encode())
        self.assertEqual([x[2] for x in fleet.exported_snapshots(profile, NOW)], [True, True])
        marker = Path(self.data, fleet.ATTEMPT)
        good = json.loads(marker.read_text())
        for doc in (dict(good, machine_id="other"), dict(good, extra=1), dict(good, kind="fleet"),
                    dict(good, schema_version=2), dict(good, time=None)):
            marker.write_text(json.dumps(doc))
            self.assertEqual(fleet.exported_snapshots(profile, NOW), [("peer-a", None, False), ("peer-c", None, False)])
        marker.unlink()
        self.assertEqual(fleet.exported_snapshots(profile, NOW), [("peer-a", None, False), ("peer-c", None, False)])
        marker.write_text(json.dumps(dict(good, time=NOW + 1)))  # a later attempt whose entries were never written
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 2), [("peer-a", snap("peer-a", NOW), False),
                                                                      ("peer-c", snap("peer-c", NOW), False)])

    def test_checked_documents_are_reused_until_the_file_changes(self):
        profile = self.profile_with()
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(snap(cfg["id"], NOW)).encode())
        self.write_local(fleet.dumps(snap(t=NOW)))
        first = fleet.exported_snapshots(profile, NOW)
        self.assertEqual([fresh for _, _, fresh in first], [True, True, True])
        with mock.patch.object(fleet, "valid", side_effect=AssertionError("checked again")):
            self.assertEqual(fleet.exported_snapshots(profile, NOW + 1), first[:1] + [
                (ident, doc, True) for ident, doc, _ in first[1:]])
        later = snap("peer-a", NOW + 2)  # a new collection replaces the file: a new identity is checked again
        fleet.collect(profile, now=NOW + 2, fetcher=lambda cfg: fleet.dumps(
            later if cfg["id"] == "peer-a" else snap(cfg["id"], NOW + 2)).encode())
        calls, real = [], fleet.valid
        with mock.patch.object(fleet, "valid", side_effect=lambda doc: calls.append(1) or real(doc)):
            got = fleet.exported_snapshots(profile, NOW + 3)
        self.assertEqual(len(calls), 2, "only the two replaced peer files")
        self.assertEqual(got[1], ("peer-a", later, True))
        Path(self.data, "fleet-storage", "peer-a.json").write_text("not json")
        self.assertEqual(fleet.exported_snapshots(profile, NOW + 3)[1], ("peer-a", None, False))

    def test_peers_after_the_read_deadline_are_unknown_for_that_scrape(self):
        profile = self.profile_with()
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(snap(cfg["id"], NOW)).encode())
        self.write_local(fleet.dumps(snap(t=NOW)))
        with mock.patch.object(fleet, "READ_DEADLINE_S", -1):
            got = fleet.exported_snapshots(profile, NOW)
        self.assertEqual(got[0][0::2], (LOCAL, True))
        self.assertEqual(got[1:], [("peer-a", None, False), ("peer-c", None, False)])

    def test_a_deadline_never_starves_the_same_peers(self):
        profile = self.profile_with()
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(snap(cfg["id"], NOW)).encode())
        clock = itertools.count(0, 1.5)  # the deadline passes after one peer check in each scrape
        with mock.patch.object(fleet.time, "monotonic", lambda: next(clock)):
            first = fleet.exported_snapshots(profile, NOW)
            second = fleet.exported_snapshots(profile, NOW)
        self.assertEqual([x[2] for x in first], [True, False])  # profile order is kept in the output
        self.assertEqual([x[2] for x in second], [False, True], "the next scrape starts with the peer not reached")
        self.assertEqual([x[2] for x in fleet.exported_snapshots(profile, NOW)], [True, True])

    def test_io_failure_is_not_remembered_and_never_breaks_the_scrape(self):
        profile = self.profile_with()
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(snap(cfg["id"], NOW)).encode())
        self.write_local(fleet.dumps(snap(t=NOW)))
        real = os.fstat
        with mock.patch.object(fleet.os, "fstat", side_effect=OSError("fixture")):
            self.assertEqual([x[1:] for x in fleet.exported_snapshots(profile, NOW)], [(None, False)] * 3)
        self.assertIs(os.fstat, real)
        self.assertEqual([x[2] for x in fleet.exported_snapshots(profile, NOW)], [True, True, True])
        raw = Path(self.data, "storage.json")
        with mock.patch.object(fleet.os, "fdopen", side_effect=OSError("fixture")):
            self.assertEqual(fleet.exported_snapshots(profile, NOW)[0], (LOCAL, None, False))
        self.assertTrue(fleet.exported_snapshots(profile, NOW)[0][2], "read again after the fault cleared")
        self.assertTrue(raw.exists())

    def test_reuse_is_bounded(self):
        with mock.patch.object(fleet, "CHECK_CACHE_ENTRIES", 2):
            for n in range(5):
                fleet._remember(("k", n), (n,), 10, {"n": n})
        self.assertEqual(list(fleet._CHECKED), [("k", 3), ("k", 4)])
        fleet._CHECKED.clear()
        with mock.patch.object(fleet, "CHECK_CACHE_BYTES", 25):
            for n in range(3):
                fleet._remember(("k", n), (n,), 10, None)
            fleet._remember(("big",), (0,), 26, None)
        self.assertEqual(list(fleet._CHECKED), [("k", 1), ("k", 2)])

    def test_reader_is_read_only(self):
        profile = self.profile_with()
        self.write_local(fleet.dumps(snap(t=NOW)))
        before = sorted(str(p) for p in Path(self.root).rglob("*"))
        with mock.patch.object(mmfleet, "fetch", side_effect=AssertionError("network")), \
                mock.patch("mmcore.write_atomic", side_effect=AssertionError("write")), \
                mock.patch.object(mmstorage_collect, "collect", side_effect=AssertionError("collect")):
            self.assertEqual(len(fleet.exported_snapshots(profile, NOW)), 3)
        self.assertEqual(sorted(str(p) for p in Path(self.root).rglob("*")), before)




class Export(TempData):
    """mm metrics end to end: storage.json and peer caches reach the exporter only by opt-in."""
    def profile_with_peer(self):
        profile = self.profile()
        profile["machines"] = [machine_config("peer-a", storage_url="https://example.invalid/storage.json"),
                               machine_config("peer-b")]
        return profile

    def test_export_reads_local_and_peer_storage_and_nothing_without_opt_in(self):
        import mmprometheus
        from mmtest import base_settings
        profile = self.profile_with_peer()
        plain, _ = mmprometheus.export(self.profile(), base_settings(), NOW)
        self.assertNotIn("machine_manager_storage_", plain)
        Path(self.data, "storage.json").write_text(fleet.dumps(snap(t=NOW)))
        fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(snap("peer-a", NOW)).encode())
        text, _ = mmprometheus.export(profile, base_settings(), NOW + 10)
        for ident in (LOCAL, "peer-a"):
            self.assertIn('machine_manager_storage_snapshot_fresh{machine_id="%s"} 1' % ident, text)
            self.assertRegex(text, r'machine_manager_storage_filesystem_size_bytes\{[^}]*machine_id="%s"' % ident)
        self.assertNotRegex(text, r'machine_manager_storage_\w+\{[^}]*machine_id="peer-b"')
        stale, _ = mmprometheus.export(profile, base_settings(), NOW + 10 + fleet.STORAGE_FRESH_S)
        self.assertIn('machine_manager_storage_snapshot_fresh{machine_id="%s"} 0' % LOCAL, stale)
        self.assertNotIn("machine_manager_storage_filesystem_size_bytes", stale)

    def test_unreadable_storage_never_hides_legacy_metrics(self):
        import mmprometheus
        from mmtest import base_settings
        profile = self.profile_with_peer()
        without, _ = mmprometheus.export(self.profile(), base_settings(), NOW)
        with mock.patch.object(fleet, "exported_snapshots", side_effect=OSError("fixture")):
            text, _ = mmprometheus.export(self.profile(), base_settings(), NOW)
        self.assertEqual(text, without)


if __name__ == "__main__":
    unittest.main()
