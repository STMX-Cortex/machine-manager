# SPDX-License-Identifier: Apache-2.0
"""Prometheus format, unit conversions, unknown/stale data, bounded hostile files and read-only CLI/fleet export."""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from unittest import mock

from mmtest import TempData, base_settings, mmcore, mmread
import mmprometheus as prom
import mmfleet
import mmsuper
from test_fleet import machine_config
from test_resources import load_cli, status_rec, resources_doc, calm

NOW = 1_800_000_000.0
MID = "test-machine"


def machine(**over):
    return status_rec(NOW, **dict({"machine_id": MID}, **over))


def resource(**over):
    return dict({"resource": "pool", "id": "workers", "location": "cloud", "state": "GREEN",
                 "read_time": NOW, "stale_after_s": 60,
                 "capacity": {"unit": "credits", "total": 100, "left": 80, "reserve": 10},
                 "load": {"running": 2, "queued": 3}, "values": [{"key": "busy", "value": True}]}, **over)


def document(*records, **over):
    return resources_doc(NOW, list(records), machine_id=MID, **over)


def samples(text):
    return dict(line.rsplit(" ", 1) for line in text.splitlines() if not line.startswith("#"))


def metric(text, name, **labels):
    key = "machine_manager_" + name + "{" + ",".join('%s="%s"' % item for item in sorted(labels.items())) + "}"
    return float(samples(text)[key])


class Export(TempData):
    def text(self, status=None, resources=None, peers=(), now=NOW):
        return prom.render(MID, machine() if status is None else status, resources, peers, now, base_settings())[0]

    def write(self, name, value):
        Path(self.data, name).write_text(json.dumps(value))

    def test_machine_values_use_ratios_and_byte_units(self):
        text = self.text()
        labels = {"machine_id": MID}
        for name, expected in (("memory_available_ratio", .5), ("cpu_busy_ratio", .4127),
                               ("swap_used_bytes", 100 * 2**20), ("memory_size_bytes", 32768 * 2**20),
                               ("storage_size_bytes", 994.7e9), ("storage_available_bytes", 210.4e9),
                               ("queue_slots", 6), ("queue_running_calls", 2)):
            self.assertAlmostEqual(metric(text, name, **labels), expected)
        self.assertEqual(metric(text, "alerts_active", **labels, level="ACTION"), 0)

    def test_linux_psi_and_optional_mac_segment_metrics(self):
        text = self.text(machine(readings={"psi_some_pct": 2.5, "psi_full_pct": 0, "seg_pct": 10}))
        self.assertEqual(metric(text, "memory_psi_some_ratio", machine_id=MID), .025)
        self.assertEqual(metric(text, "memory_psi_full_ratio", machine_id=MID), 0)
        self.assertEqual(metric(text, "compressor_segments_ratio", machine_id=MID), .1)

    def test_unknown_invalid_and_nonfinite_measurements_are_not_zero(self):
        text = self.text(machine(readings={"free_pct": None, "cpu_pct": True, "comp_mb": float("nan"),
                                          "swap_used_mb": -1, "psi_some_pct": 101, "sys_pct": 10**1000}))
        for name in ("memory_available_ratio", "cpu_busy_ratio", "compressor_bytes", "swap_used_bytes",
                     "memory_psi_some_ratio", "cpu_system_ratio"):
            self.assertNotIn("machine_manager_" + name, text)

    def test_stale_and_far_future_status_export_only_health_and_source_time(self):
        for timestamp in (NOW - 10000, NOW + 6):
            with self.subTest(timestamp=timestamp):
                text = self.text(machine(time=timestamp))
                self.assertEqual(metric(text, "machine_status_fresh", machine_id=MID), 0)
                self.assertEqual(metric(text, "machine_state", machine_id=MID, state="UNKNOWN"), 1)
                self.assertEqual(metric(text, "machine_status_timestamp_seconds", machine_id=MID), timestamp)
                self.assertNotIn("machine_manager_storage_available_bytes", text)
                self.assertNotIn("machine_manager_queue_slots", text)

    def test_valid_state_and_mode_are_one_hot(self):
        text = self.text(machine(state="RED", mode="off"))
        self.assertEqual(metric(text, "machine_state", machine_id=MID, state="RED"), 1)
        self.assertEqual(metric(text, "machine_state", machine_id=MID, state="GREEN"), 0)
        self.assertEqual(metric(text, "machine_mode", machine_id=MID, mode="off"), 1)
        self.assertEqual(metric(text, "machine_mode", machine_id=MID, mode="act"), 0)

    def test_bad_identity_version_kind_or_time_cannot_be_healthy(self):
        for over in ({"machine_id": "someone-else"}, {"schema_version": True}, {"schema_version": 2},
                     {"kind": "pool"}, {"time": True}, {"time": -1}, {"state": "invented"}):
            text = self.text(machine(**over))
            self.assertEqual(metric(text, "machine_status_fresh", machine_id=MID), 0)
            self.assertEqual(metric(text, "snapshot_valid", source="status"), 0)

    def test_resource_capacity_keeps_units_and_boolean_values(self):
        text = self.text(resources=document(resource(), resource(id="slots", capacity={
            "unit": "slots", "total": 8, "left": 4, "reserve": 1})))
        labels = {"machine_id": MID, "resource": "pool", "id": "workers", "location": "cloud", "parent": ""}
        self.assertEqual(metric(text, "resource_capacity_left", **labels, unit="credits"), 80)
        self.assertEqual(metric(text, "resource_running", **labels), 2)
        self.assertEqual(metric(text, "resource_value", **labels, key="busy"), 1)
        self.assertIn('unit="slots"', text)

    def test_stale_resource_file_cannot_refresh_itself_with_record_time(self):
        doc = document(resource(time=NOW), time=NOW - 10000)
        text = self.text(resources=doc)
        self.assertIn('machine_manager_resource_fresh', text)
        self.assertNotIn("machine_manager_resource_capacity_left", text)

    def test_source_read_freshness_and_future_timestamp_are_checked(self):
        for over in ({"read_time": NOW - 61}, {"read_time": NOW + 6}, {"read_time": None},
                     {"state": "UNKNOWN"}):
            text = self.text(resources=document(resource(**over)))
            self.assertNotIn("machine_manager_resource_capacity_left", text)

    def test_missing_resources_do_not_hide_a_healthy_machine(self):
        text, healthy = prom.render(MID, machine(), None, (), NOW, base_settings())
        self.assertTrue(healthy)
        self.assertEqual(metric(text, "snapshot_valid", source="resources"), 0)
        self.assertIn("machine_manager_memory_available_ratio", text)

    def test_unthresholded_resources_export_numeric_values_only(self):
        text = self.text(resources=document(resource(state=None, values=[
            {"key": "used_5h_pct", "value": 60}, {"key": "executable", "value": "/opt/do-not-run"},
            {"key": "token", "value": "secret-text"}])))
        self.assertIn('key="used_5h_pct"', text)
        self.assertNotIn("secret-text", text)
        self.assertNotIn("do-not-run", text)

    def test_labels_are_masked_escaped_and_never_interpreted_as_metric_names(self):
        token = "gh" + "p_" + "a" * 36
        text = self.text(resources=document(resource(id='worker"\\\n' + token, why="sensitive note",
                                                      values=[{"key": token, "value": 1}])))
        self.assertNotIn(token, text)
        self.assertNotIn("sensitive note", text)
        self.assertIn('worker\\"\\\\?', text)
        for line in text.splitlines():
            if not line.startswith("#"):
                self.assertRegex(line, r'^machine_manager_[a-z0-9_]+\{(?:[a-z_]+="(?:[^"\\]|\\[\\"n])*",?)*\} [-+0-9.e]+$')

    def test_duplicate_records_and_cleaned_ids_never_duplicate_series(self):
        text = self.text(resources=document(resource(id="a\nb"), resource(id="a\tb"),
                                             resource(id="same", parent="pool-a"), resource(id="same", parent="pool-b")))
        lines = [line.rsplit(" ", 1)[0] for line in text.splitlines() if not line.startswith("#")]
        self.assertEqual(len(lines), len(set(lines)))
        self.assertIn('parent="pool-a"', text)
        self.assertIn('parent="pool-b"', text)

    def test_unpaired_unicode_surrogates_cannot_break_utf8_exposition(self):
        text = self.text(resources=document(resource(id="worker\ud800")))
        self.assertIn('id="worker?"', text)
        self.assertEqual(text.encode("utf-8").decode("utf-8"), text)

    def test_record_and_value_caps_bound_series_counts(self):
        records = [resource(id="worker-%d" % i) for i in range(1005)]
        records[0]["values"] = [{"key": "v%d" % i, "value": i} for i in range(100)]
        text = self.text(resources=document(*records))
        self.assertNotIn('id="worker-999"', text)
        self.assertNotIn('key="v64"', text)
        self.assertIn('key="v63"', text)
        self.assertLess(len(text), 3 << 20)

    def test_exposition_is_deterministic_and_declares_each_family_once(self):
        text = self.text(resources=document(resource()))
        self.assertEqual(text, self.text(resources=document(resource())))
        names = [line.split()[2] for line in text.splitlines() if line.startswith("# TYPE")]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(text.endswith("\n"))

    def test_snapshot_reader_rejects_malformed_unbounded_or_ambiguous_json(self):
        path = Path(self.data, "snapshot.json")
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'[' * 40 + b'0' + b']' * 40,
                    b'"' + b'x' * 1000 + b'"', b'\xff', b'not json'):
            path.write_bytes(raw)
            self.assertIsNone(prom.read_snapshot(path, 512), raw[:40])
        path.write_text('{"ok":0}')
        self.assertEqual(prom.read_snapshot(path, 512), {"ok": 0})

    def test_snapshot_reader_never_follows_links_or_waits_on_special_files(self):
        target = Path(self.data, "target")
        target.write_text('{"ok":1}')
        link = Path(self.data, "link")
        link.symlink_to(target)
        fifo = Path(self.data, "fifo")
        os.mkfifo(fifo)
        started = time.monotonic()
        for path in (link, fifo, Path(self.data), Path(self.data, "missing")):
            self.assertIsNone(prom.read_snapshot(path, 512))
        self.assertLess(time.monotonic() - started, .5)

    def test_cli_exits_and_usage_errors(self):
        self.write("status.json", machine(time=time.time()))
        result = self.mm("metrics")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("# HELP"))
        self.write("status.json", machine(time=1))
        result = self.mm("metrics")
        self.assertEqual(result.returncode, 3)
        self.assertIn("machine_manager_machine_status_fresh", result.stdout)
        for args in (("--json",), ("--serve",), ("extra",)):
            result = self.mm("metrics", *args)
            self.assertEqual(result.returncode, 2)
            self.assertTrue(result.stdout.startswith("E_USAGE "))

    def test_cli_uses_no_commands_network_or_adapter_and_writes_no_files(self):
        cli = load_cli()
        self.write("status.json", machine(time=time.time()))
        before = {str(p): p.read_bytes() for p in Path(self.root).rglob("*") if p.is_file()}
        with mock.patch.object(mmread, "run", side_effect=AssertionError("command")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("child process")), \
             mock.patch.object(mmfleet, "fetch", side_effect=AssertionError("network")), \
             contextlib.redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(cli.main(["metrics"]), 0)
        self.assertIn("machine_manager_storage_available_bytes", stream.getvalue())
        self.assertEqual(before, {str(p): p.read_bytes() for p in Path(self.root).rglob("*") if p.is_file()})

    def test_missing_status_does_not_create_a_state_directory(self):
        shutil.rmtree(Path(self.data, "state"))
        result = self.mm("metrics")
        self.assertEqual(result.returncode, 3)
        self.assertFalse(Path(self.data, "state").exists())

    def test_collected_peers_export_memory_cpu_and_storage_without_network(self):
        profile = self.profile()
        profile["machines"] = [machine_config(), machine_config("remote-b")]
        remote = machine(machine_id="remote-a", readings={"free_pct": 80, "cpu_pct": 12.5})
        self.write("status.json", machine())
        self.write("fleet.json", mmcore.stamp({"kind": "fleet", "time": NOW, "machines": [
            {"id": "remote-a", "collected_at": NOW, "status": remote, "error": None},
            {"id": "remote-b", "collected_at": NOW, "status": None, "error": "unavailable"}]}))
        with mock.patch.object(mmfleet, "fetch", side_effect=AssertionError("network")):
            text, healthy = prom.export(profile, base_settings(), NOW)
        self.assertTrue(healthy)
        self.assertEqual(metric(text, "cpu_busy_ratio", machine_id="remote-a"), .125)
        self.assertEqual(metric(text, "storage_available_bytes", machine_id="remote-a"), 210.4e9)
        self.assertEqual(metric(text, "machine_status_fresh", machine_id="remote-b"), 0)
        expired, _ = prom.export(profile, base_settings(), NOW + 10000)
        self.assertNotIn('machine_manager_storage_available_bytes{machine_id="remote-a"}', expired)

    def test_supervisor_snapshot_includes_available_segment_reading(self):
        self.queue_dir()
        supervisor = mmsuper.Supervisor(self.profile(), kernel=False, sizes=False, slow_jobs=False,
                                       sampler=calm, check_readings=False)
        supervisor.tick()
        snapshot = json.loads(Path(self.data, "status.json").read_text())
        self.assertEqual(snapshot["readings"]["seg_pct"], 1)
