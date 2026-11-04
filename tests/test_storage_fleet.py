# SPDX-License-Identifier: Apache-2.0
"""Fleet storage export: storage.json, `mm storage record`, GET /storage.json, `mm collect` peer caches and the
exporter reader. Collectors and peers are fakes (no real sampling or waits); the HTTP tests start only their own
loopback fixture servers and skip when the command sandbox forbids sockets."""
import contextlib
import copy
import http.client
import http.server
import io as stdio
import json
import os
from pathlib import Path
import stat
import threading
import time
import unittest
from unittest import mock

from mmtest import TempData, mmcore
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
        self.assertTrue(fleet._clean_text(doc, []), "a masked snapshot is stable under the peer check")


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
            machine_config("peer-a", storage_url="https://example.invalid/storage.json?token=abcdefgh12345678"),
            machine_config("peer-b")]
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

    def test_bad_responses_write_null_and_never_revive_the_old_good_file(self):
        profile, good = self.fleet_profile(), snap("peer-a", NOW)
        secret = copy.deepcopy(good)
        secret["capacity"]["filesystems"][0]["mounts"] = ["/abcdefgh12345678"]
        big = fleet.dumps(snap("peer-a", NOW, filesystems=many_filesystems())).encode()

        def fail(cfg):
            raise mmfleet.FleetError("HTTP 404 https://example.invalid/storage.json?token=abcdefgh12345678")
        responses = [("wrong machine", fleet.dumps(snap("peer-b", NOW)).encode()),
                     ("stale", fleet.dumps(snap("peer-a", NOW - 300)).encode()),
                     ("future", fleet.dumps(snap("peer-a", NOW + 6)).encode()),
                     ("invalid", fleet.dumps(dict(good, extra=1)).encode()),
                     ("duplicate", b'{"kind":1,"kind":2}'), ("nan", b'{"time":NaN}'),
                     ("url secret", fleet.dumps(secret).encode()), ("oversize", big), ("404", fail)]
        for name, response in responses:
            fleet.collect(profile, now=NOW, fetcher=lambda cfg: fleet.dumps(good).encode())
            self.assertIsNotNone(self.cache()["snapshot"])
            fetcher = response if callable(response) else (lambda cfg, r=response: r)
            with self.subTest(name=name), mock.patch.object(fleet, "SNAPSHOT_BYTES", len(big) - 1):
                self.assertEqual(fleet.collect(profile, now=NOW, fetcher=fetcher), [("peer-a", False)])
                rec = self.cache()
                self.assertEqual((rec["snapshot"], rec["error"], rec["collected_at"]), (None, fleet.PEER_ERROR, NOW))
                self.assertNotIn("abcdefgh", json.dumps(rec))
                self.assertEqual(fleet.exported_snapshots(profile, NOW)[0], ("peer-a", None, False))

    def test_fetch_uses_storage_url_and_snapshot_limit_without_raising_status_limit(self):
        seen = []
        with mock.patch.object(mmfleet, "fetch", side_effect=lambda *a: seen.append(a) or b"{}"):
            fleet.collect(self.fleet_profile(), now=NOW)
        self.assertEqual([(a[0]["id"],) + a[1:] for a in seen], [("peer-a", "storage_url", fleet.SNAPSHOT_BYTES)])
        for key, limit in (("start_argv", 10), ("status_url", 0), ("status_url", mmfleet.FETCH_MAX + 1), ("status_url", 1.0)):
            with self.assertRaises(mmfleet.FleetError):
                mmfleet.fetch(machine_config(), key, limit)
        self.assertEqual(fleet.SNAPSHOT_BYTES, mmfleet.FETCH_MAX)

    def test_real_worker_byte_limits_over_loopback_http(self):
        body = b"x" * ((1 << 20) + 10)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
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
            url = "http://127.0.0.1:%d/x" % server.server_port
            cfg = machine_config(status_url=url, storage_url=url, timeout_s=10)
            with self.assertRaises(mmfleet.FleetError):
                mmfleet.fetch(cfg)  # status keeps its 1 MiB limit
            self.assertEqual(mmfleet.fetch(cfg, "storage_url", fleet.SNAPSHOT_BYTES), body)
            with self.assertRaises(mmfleet.FleetError):
                mmfleet.fetch(cfg, "storage_url", len(body) - 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def run_collect(self, profile, storage_response, *flags):
        cli, out = load_cli(), stdio.StringIO()

        def fetch(cfg, key="status_url", limit=mmfleet.MAX_BYTES):
            return blob(status(cfg["id"], time=time.time())) if key == "status_url" else storage_response(cfg)
        with mock.patch.object(mmfleet, "fetch", side_effect=fetch), mock.patch("mmcore.load_profile",
                                                                                 return_value=profile):
            with contextlib.redirect_stdout(out):
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


class Exported(TempData):
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
                    dict(good, snapshot=dict(good["snapshot"], time=NOW + 1))):
            path.write_text(json.dumps(rec))
            self.assertEqual(fleet.exported_snapshots(profile, NOW)[0], ("peer-a", None, False))
        path.write_text(json.dumps(good) + " " * (fleet.CACHE_BYTES + 1))
        self.assertEqual(fleet.exported_snapshots(profile, NOW)[0], ("peer-a", None, False), "byte bound")

    def test_reader_is_read_only(self):
        profile = self.profile_with()
        self.write_local(fleet.dumps(snap(t=NOW)))
        before = sorted(str(p) for p in Path(self.root).rglob("*"))
        with mock.patch.object(mmfleet, "fetch", side_effect=AssertionError("network")), \
                mock.patch("mmcore.write_atomic", side_effect=AssertionError("write")), \
                mock.patch.object(mmstorage_collect, "collect", side_effect=AssertionError("collect")):
            self.assertEqual(len(fleet.exported_snapshots(profile, NOW)), 3)
        self.assertEqual(sorted(str(p) for p in Path(self.root).rglob("*")), before)


if __name__ == "__main__":
    unittest.main()
