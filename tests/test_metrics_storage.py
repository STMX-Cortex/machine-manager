# SPDX-License-Identifier: Apache-2.0
"""Fleet storage families: labels and values, unknown/stale omission, opt-in emission, hostile rows, no sums."""
import copy
import importlib.util
import json
import re
from pathlib import Path
import unittest
from unittest import mock

from mmtest import TempData, base_settings
import mmprometheus as prom
import mmprometheus_storage as storage_metrics
import mmstorage
import mmstorage_io
import storage_fixtures as fx
from test_metrics import machine, resource, document, samples, metric, MID, NOW

FS = ("capacity_known", "size_bytes", "free_bytes", "available_bytes", "used_bytes", "read_only")
DEV = ("rates_known", "read_bytes_per_second", "write_bytes_per_second", "read_ops_per_second",
       "write_ops_per_second")
FAMILIES = {"machine_manager_storage_" + name for name in
            ("snapshot_fresh", "snapshot_timestamp_seconds", "inventory_state", "export_complete")
            + tuple("filesystem_" + f for f in FS) + tuple("device_" + d for d in DEV)}
GOLDEN = Path(__file__).resolve().parent / "fixtures" / "metrics-legacy.prom"
LINE = re.compile(r'^machine_manager_[a-z0-9_]+\{(?:[a-z_]+="(?:[^"\\]|\\[\\"n])*",?)*\} [-+0-9.e]+$')


def legacy_fixture(module=prom):
    """Representative legacy exposition; tests/fixtures/metrics-legacy.prom holds main's (7db4be3) output for it."""
    peers = (("remote-a", machine(machine_id="remote-a", readings={"free_pct": 80, "cpu_pct": 12.5})),
             ("remote-b", None), ("remote-c", machine(machine_id="remote-c", time=NOW - 10000)))
    resources = document(resource(), resource(id="slots", parent="pool-a", capacity={
        "unit": "slots", "total": 8, "left": 4, "reserve": 1}), resource(id="old", read_time=NOW - 1000))
    status = machine(state="AMBER", mode="observe", readings={"psi_some_pct": 2.5, "psi_full_pct": 0, "seg_pct": 10})
    return module.render(MID, status, resources, peers, NOW, base_settings())[0]


def storage_bytes(text):
    """Encoded bytes of every storage-contract line (HELP/TYPE headers included), newline-terminated."""
    return sum(len(line.encode("utf-8")) + 1 for line in text.splitlines()
               if re.search(r"machine_manager_\w+", line).group() in FAMILIES)


def relabel(snapshot, ident):
    """The same rows under another machine id (shared row objects keep large fixtures small in memory)."""
    return dict(snapshot, machine_id=ident, capacity=dict(snapshot["capacity"], machine_id=ident),
                io=dict(snapshot["io"], machine_id=ident))


def dense(long=False):
    rows = [fx.filesystem("fs-%03d" % i, ["/" + ("m" * 110 if long else "fs") + "%03d" % i], group=fx.GROUP)
            for i in range(mmstorage.RECORDS_MAX)]
    io = fx.io_record(cases=["actual-interval"] * mmstorage.RECORDS_MAX)
    if long:
        for row in io["devices"]:
            row["name"] = row["name"] + "x" * 110
    return fx.snapshot(capacity=fx.capacity_record(rows=rows), io=io)


def render(*storage, peers=()):
    return prom.render(MID, machine(), None, peers, NOW, base_settings(), storage=storage)[0]


def fs_labels(name, mount, fs_type="ext4", group=""):
    return {"machine_id": MID, "filesystem_id": fx.sid("filesystem", name), "mount": mount, "fs_type": fs_type,
            "capacity_group": group}


def dev_labels(name):
    return {"machine_id": MID, "device_id": fx.device_id(name), "device": name, "scope": "whole_device"}


def storage_samples(text):
    return {k: v for k, v in samples(text).items() if k.startswith("machine_manager_storage_")
            and not k.startswith(("machine_manager_storage_size_bytes{", "machine_manager_storage_available_bytes{"))}


def families(text):
    return set(re.findall(r"^# TYPE (machine_manager_storage_\w+)", text, re.M)) & FAMILIES


class StorageMetrics(unittest.TestCase):
    def test_fixtures_pass_the_storage_validators_and_envelope_rules(self):
        snap = fx.snapshot()
        self.assertTrue(mmstorage.valid(snap["capacity"]))
        self.assertTrue(mmstorage_io.valid(snap["io"]))
        self.assertEqual(set(snap), {"kind", "schema_version", "machine_id", "time", "capacity", "io"})
        self.assertEqual(snap["time"], min(snap["capacity"]["time"], snap["io"]["time"]))
        if importlib.util.find_spec("mmstorage_fleet"):  # Part A's validator, once integrated
            import mmstorage_fleet
            self.assertTrue(mmstorage_fleet.valid(snap))

    def test_fresh_snapshot_exports_every_family_with_exact_labels_and_values(self):
        text = render((MID, fx.snapshot(), True))
        self.assertEqual(families(text), FAMILIES)
        self.assertEqual(metric(text, "storage_snapshot_fresh", machine_id=MID), 1)
        self.assertEqual(metric(text, "storage_snapshot_timestamp_seconds", machine_id=MID), NOW)
        self.assertEqual(metric(text, "storage_export_complete", machine_id=MID), 1)
        for source in ("capacity", "io"):
            for state, value in (("OK", 1), ("PARTIAL", 0), ("UNKNOWN", 0)):
                self.assertEqual(metric(text, "storage_inventory_state", machine_id=MID, source=source,
                                        state=state), value)
        root = fs_labels("root", "/")
        for name, value in (("capacity_known", 1), ("size_bytes", 100), ("free_bytes", 30),
                            ("available_bytes", 20), ("used_bytes", 70), ("read_only", 0)):
            self.assertEqual(metric(text, "storage_filesystem_" + name, **root), value)
        big = fs_labels("large", "/large", "xfs")
        self.assertIn('machine_manager_storage_filesystem_size_bytes{%s} 9223372036854775807'
                      % ",".join('%s="%s"' % i for i in sorted(big.items())), text)
        busy = dev_labels("actual-interval")
        for name, value in (("rates_known", 1), ("read_bytes_per_second", 1000), ("write_bytes_per_second", 2000),
                            ("read_ops_per_second", 10), ("write_ops_per_second", 20)):
            self.assertEqual(metric(text, "storage_device_" + name, **busy), value)
        idle = dev_labels("idle")
        self.assertEqual(metric(text, "storage_device_read_bytes_per_second", **idle), 0)  # a measured zero stays
        for line in text.splitlines():
            if not line.startswith("#"):
                self.assertRegex(line, LINE)

    def test_mount_is_first_sorted_alias_and_null_group_is_empty(self):
        text = render((MID, fx.snapshot(), True))
        data = fs_labels("data", "/Volumes/Data", "apfs", fx.GROUP)
        self.assertEqual(metric(text, "storage_filesystem_size_bytes", **data), 100)
        self.assertNotIn('mount="/data"', text)
        self.assertEqual(metric(text, "storage_filesystem_size_bytes", **fs_labels("root", "/")), 100)

    def test_unknown_capacity_is_omitted_never_zero(self):
        text = render((MID, fx.snapshot(), True))
        remote = fs_labels("remote", "/mnt/remote", "nfs")
        self.assertEqual(metric(text, "storage_filesystem_capacity_known", **remote), 0)
        partial = fs_labels("partial", "/srv")
        self.assertEqual(metric(text, "storage_filesystem_capacity_known", **partial), 0)
        self.assertEqual(metric(text, "storage_filesystem_size_bytes", **partial), 100)
        self.assertEqual(metric(text, "storage_filesystem_available_bytes", **partial), 20)
        series = samples(text)
        for name in ("size_bytes", "free_bytes", "available_bytes", "used_bytes"):
            self.assertFalse([k for k in series if k.startswith("machine_manager_storage_filesystem_" + name)
                              and 'mount="/mnt/remote"' in k], name)
        for name in ("free_bytes", "used_bytes"):
            self.assertFalse([k for k in series if k.startswith("machine_manager_storage_filesystem_" + name)
                              and 'mount="/srv"' in k], name)
        zero = fs_labels("zero", "/boot/efi", "vfat")
        self.assertEqual(metric(text, "storage_filesystem_size_bytes", **zero), 0)  # real zero size is exported

    def test_null_read_only_and_null_rates_are_omitted(self):
        text = render((MID, fx.snapshot(), True))
        self.assertNotRegex(text, r'storage_filesystem_read_only\{[^}]*mount="/Volumes/Data"')
        self.assertEqual(metric(text, "storage_filesystem_read_only",
                                **fs_labels("other", "/Volumes/Other", "apfs", fx.GROUP)), 1)
        for name in ("reset", "invalid-interval", "first-sample"):
            self.assertEqual(metric(text, "storage_device_rates_known", **dev_labels(name)), 0)
            self.assertNotRegex(text, r'_per_second\{[^}]*device="%s"' % name)

    def test_stale_or_missing_snapshot_exports_only_freshness_time_and_unknown_state(self):
        for snapshot, fresh, stamp in ((fx.snapshot(), False, True), (None, False, False), (None, True, False),
                                       (fx.snapshot(machine_id="someone-else"), True, False),
                                       ([], True, False), ("snapshot", True, False)):
            with self.subTest(snapshot=type(snapshot).__name__, fresh=fresh, stamp=stamp):
                text = render((MID, snapshot, fresh))
                self.assertEqual(metric(text, "storage_snapshot_fresh", machine_id=MID), 0)
                for source in ("capacity", "io"):
                    self.assertEqual(metric(text, "storage_inventory_state", machine_id=MID, source=source,
                                            state="UNKNOWN"), 1)
                    self.assertEqual(metric(text, "storage_inventory_state", machine_id=MID, source=source,
                                            state="OK"), 0)
                self.assertEqual("storage_snapshot_timestamp_seconds" in text, stamp)
                self.assertNotIn("storage_export_complete", text)
                self.assertFalse([k for k in samples(text) if k.startswith(("machine_manager_storage_filesystem_",
                                                                            "machine_manager_storage_device_"))])

    def test_partial_and_unknown_inventories_keep_their_state(self):
        snap = fx.snapshot(capacity=fx.capacity_record(state="PARTIAL", reason="timeout"),
                           io=fx.io_record(state="UNKNOWN", reason="truncated"))
        text = render((MID, snap, True))
        self.assertEqual(metric(text, "storage_inventory_state", machine_id=MID, source="capacity", state="PARTIAL"), 1)
        self.assertEqual(metric(text, "storage_inventory_state", machine_id=MID, source="io", state="UNKNOWN"), 1)
        self.assertEqual(metric(text, "storage_filesystem_size_bytes", **fs_labels("root", "/")), 100)
        self.assertNotIn("machine_manager_storage_device_", text)

    def test_only_listed_machines_get_series(self):
        text = render((MID, fx.snapshot(), True), ("peer-b", None, False))
        self.assertIn('storage_snapshot_fresh{machine_id="peer-b"} 0', text)
        self.assertNotIn('machine_id="peer-c"', text)
        for line in storage_samples(text):
            self.assertRegex(line, r'machine_id="(%s|peer-b)"' % MID)
        peers = (("peer-c", machine(machine_id="peer-c")),)
        text = render(peers=peers)
        self.assertFalse(families(text), "no storage tuples means no storage series at all")
        self.assertNotRegex(text, r'storage_snapshot_\w+\{machine_id="peer-c"')

    def test_peer_snapshot_keeps_its_own_identity(self):
        peer = fx.snapshot(machine_id="peer-b")
        text = render((MID, fx.snapshot(), True), ("peer-b", peer, True))
        self.assertEqual(metric(text, "storage_filesystem_size_bytes", **dict(fs_labels("root", "/"),
                                                                              machine_id="peer-b")), 100)
        self.assertEqual(metric(text, "storage_filesystem_size_bytes", **fs_labels("root", "/")), 100)

    def test_legacy_output_is_byte_identical_without_storage(self):
        legacy = prom.render(MID, machine(), None, (), NOW, base_settings())
        self.assertEqual(legacy, prom.render(MID, machine(), None, (), NOW, base_settings(), storage=()))
        self.assertEqual(legacy, prom.render(MID, machine(), None, (), NOW, base_settings(), storage=iter(())))
        self.assertFalse(families(legacy[0]))
        with_storage = prom.render(MID, machine(), None, (), NOW, base_settings(),
                                   storage=[(MID, fx.snapshot(), True)])
        self.assertEqual(with_storage[1], legacy[1], "storage never changes the local health exit")
        old = [line for line in with_storage[0].splitlines() if re.search(r"machine_manager_\w+", line).group()
               not in FAMILIES]
        self.assertEqual(old, legacy[0].splitlines())

    def test_labels_are_masked_cleaned_and_escaped(self):
        token = "gh" + "p_" + "a" * 36
        snap = fx.snapshot()
        root = next(f for f in snap["capacity"]["filesystems"] if f["mounts"] == ["/"])
        root.update(mounts=['/odd"\\\n' + token], fs_type="ext4\t" + token)
        snap["io"]["devices"][0]["name"] = "disk " + token
        text = render((MID, snap, True))
        self.assertNotIn(token, text)
        self.assertIn('mount="/odd\\"\\\\?', text)
        for line in text.splitlines():
            if not line.startswith("#"):
                self.assertRegex(line, LINE)

    def test_duplicate_tuples_rows_and_colliding_labels_never_duplicate_series(self):
        snap = fx.snapshot()
        snap["capacity"]["filesystems"].append(copy.deepcopy(snap["capacity"]["filesystems"][0]))
        snap["io"]["devices"].append(copy.deepcopy(snap["io"]["devices"][0]))
        text = render((MID, snap, True), (MID, snap, True), (MID, None, False))
        lines = [line.rsplit(" ", 1)[0] for line in text.splitlines() if not line.startswith("#")]
        self.assertEqual(len(lines), len(set(lines)))
        names = [line.split()[2] for line in text.splitlines() if line.startswith("# TYPE")]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(metric(text, "storage_snapshot_fresh", machine_id=MID), 1)  # first tuple wins

    def test_malformed_rows_are_skipped_without_inventing_values(self):
        snap = fx.snapshot()
        fs = dict(snap["capacity"]["filesystems"][0], mounts=["/bad-fs"])
        cap = fs["capacity"]
        bad_fs = [None, "row", {}, dict(fs, mounts=[]), dict(fs, mounts="/bad-fs"), dict(fs, mounts=[1]),
                  dict(fs, id=None), dict(fs, fs_type=7), dict(fs, capacity_group=5), dict(fs, capacity=None),
                  dict(fs, capacity=dict(cap, total_bytes=None)),  # null reason claims known, value missing
                  dict(fs, capacity=dict(cap, free_bytes=True)), dict(fs, capacity=dict(cap, used_bytes=-1))]
        dev = dict(next(d for d in snap["io"]["devices"] if d["rate_reason"] is None), name="bad-dev")
        rates = dev["rates"]
        bad_dev = [None, {}, dict(dev, scope="partition"), dict(dev, name=""), dict(dev, id=3), dict(dev, rates=[]),
                   dict(dev, rates=dict(rates, read_ops_per_s=float("nan"))),
                   dict(dev, rates=dict(rates, read_ops_per_s="1")), dict(dev, rates=dict(rates, read_ops_per_s=-1)),
                   dict(dev, rates=dict(rates, read_ops_per_s=None))]
        broken = {"machine_id": MID, "time": NOW, "capacity": {"machine_id": MID, "state": "OK", "filesystems": bad_fs},
                  "io": {"machine_id": MID, "state": "OK", "devices": bad_dev}}
        text = render((MID, broken, True))
        self.assertEqual(metric(text, "storage_snapshot_fresh", machine_id=MID), 1)
        self.assertNotIn("bad-", text)
        self.assertFalse([k for k in samples(text) if "_filesystem_" in k or "_device_" in k])
        for snap, stamp, states in (
                ({"machine_id": MID, "time": NOW, "capacity": "x", "io": {"machine_id": "other", "state": "OK"}},
                 True, ("UNKNOWN", "UNKNOWN")),
                ({"machine_id": MID, "time": float("inf"), "capacity": {"machine_id": MID, "state": "BOGUS"}},
                 False, ("UNKNOWN", "UNKNOWN")),
                ({"machine_id": MID, "time": -1, "capacity": {"machine_id": MID, "state": "OK", "filesystems": "x"},
                  "io": {"machine_id": MID, "state": "PARTIAL", "devices": None}}, False, ("OK", "PARTIAL"))):
            with self.subTest(snap=snap):
                text = render((MID, snap, True))
                self.assertEqual(metric(text, "storage_snapshot_fresh", machine_id=MID), 1)
                self.assertEqual("storage_snapshot_timestamp_seconds" in text, stamp)
                for source, state in zip(("capacity", "io"), states):
                    self.assertEqual(metric(text, "storage_inventory_state", machine_id=MID, source=source,
                                            state=state), 1)
                self.assertFalse([k for k in samples(text) if "_filesystem_" in k or "_device_" in k])

    def test_unknown_inventory_rows_are_ignored_and_rows_are_capped(self):
        snap = fx.snapshot()
        snap["io"]["state"] = "UNKNOWN"  # a defensive reader view: UNKNOWN never exports rows
        text = render((MID, snap, True))
        self.assertNotIn("machine_manager_storage_device_", text)
        rows = [fx.filesystem("fs-%03d" % i, ["/fs-%03d" % i]) for i in range(140)]
        snap = fx.snapshot()
        snap["capacity"]["filesystems"] = rows
        text = render((MID, snap, True))
        self.assertEqual(len([k for k in samples(text) if k.startswith("machine_manager_storage_filesystem_size_bytes")]),
                         mmstorage.RECORDS_MAX)

    def test_maximum_inventory_fits_the_documented_series_budget(self):
        rows = [fx.filesystem("fs-%03d" % i, ["/fs-%03d" % i]) for i in range(mmstorage.RECORDS_MAX)]
        cases = [fx.IO_CASES[i % 2] for i in range(mmstorage.RECORDS_MAX)]
        snap = fx.snapshot(capacity=fx.capacity_record(rows=rows), io=fx.io_record(cases=cases))
        self.assertTrue(mmstorage.valid(snap["capacity"]) and mmstorage_io.valid(snap["io"]))
        series = storage_samples(render((MID, snap, True)))
        self.assertEqual(len(series), 128 * 6 + 128 * 5 + 9)
        self.assertLessEqual(len(series) * 33, 33 * (128 * 7 + 128 * 5))

    def test_never_a_sum_each_filesystem_and_device_is_its_own_series(self):
        text = render((MID, fx.snapshot(), True))
        for key in storage_samples(text):
            name = key.split("{")[0]
            if "_filesystem_" in name:
                self.assertIn("filesystem_id=", key)
            elif "_device_" in name:
                self.assertIn("device_id=", key)
            else:
                self.assertRegex(key, r'^[a-z_]+\{machine_id="[^"]+"(,source="[a-z]+",state="[A-Z]+")?\}$')
        group = [k for k in storage_samples(text) if k.startswith("machine_manager_storage_filesystem_size_bytes")
                 and 'capacity_group="%s"' % fx.GROUP in k]
        self.assertEqual(len(group), 2, "volumes sharing a container stay separate, never a container total")

    def test_renderer_reports_freshness_and_is_deterministic(self):
        out = prom.Metrics()
        self.assertTrue(storage_metrics.add(out, MID, fx.snapshot(), True))
        self.assertFalse(storage_metrics.add(prom.Metrics(), MID, fx.snapshot(), False))
        self.assertEqual(render((MID, fx.snapshot(), True)), render((MID, fx.snapshot(), True)))
        json.dumps(fx.snapshot())  # fixtures stay JSON-serializable for file-based callers


class StorageBudget(unittest.TestCase):
    def machines(self, count, snapshot=None):
        snapshot = fx.snapshot() if snapshot is None else snapshot
        return [("m-%02d" % i, relabel(snapshot, "m-%02d" % i), True) for i in range(count)]

    def one_machine_bytes(self):
        return storage_bytes(render(*self.machines(1)))

    def test_budget_omits_whole_machines_in_order_and_reports_them(self):
        limit = int(self.one_machine_bytes() * 2.5)
        full = len([k for k in samples(render(*self.machines(1))) if "_filesystem_" in k or "_device_" in k])
        with mock.patch.object(storage_metrics, "STORAGE_TEXT_BYTES", limit):
            text = render(*self.machines(4))
        self.assertLessEqual(storage_bytes(text), limit)
        series = samples(text)
        for index, complete in enumerate((1, 1, 0, 0)):
            ident = "m-%02d" % index
            with self.subTest(machine=ident):
                self.assertEqual(metric(text, "storage_export_complete", machine_id=ident), complete)
                self.assertEqual(metric(text, "storage_snapshot_fresh", machine_id=ident), 1)
                self.assertEqual(metric(text, "storage_inventory_state", machine_id=ident, source="io", state="OK"), 1)
                rows = [k for k in series if ('machine_id="%s"' % ident) in k
                        and ("_filesystem_" in k or "_device_" in k)]
                self.assertEqual(len(rows), full if complete else 0)  # never part of a machine

    def test_a_later_smaller_machine_can_still_fit(self):
        small = fx.snapshot(capacity=fx.capacity_record(rows=fx.filesystems()[:1]), io=fx.io_record(cases=["idle"]))
        storage = self.machines(2) + [("small", relabel(small, "small"), True), ("stale", None, False)]
        limit = int(self.one_machine_bytes() * 1.5)
        with mock.patch.object(storage_metrics, "STORAGE_TEXT_BYTES", limit):
            text = render(*storage)
        self.assertLessEqual(storage_bytes(text), limit)
        self.assertEqual(metric(text, "storage_export_complete", machine_id="m-00"), 1)
        self.assertEqual(metric(text, "storage_export_complete", machine_id="m-01"), 0)
        self.assertEqual(metric(text, "storage_export_complete", machine_id="small"), 1)
        self.assertNotRegex(text, r'storage_export_complete\{machine_id="stale"')
        self.assertEqual(metric(text, "storage_snapshot_fresh", machine_id="stale"), 0)

    def test_tiny_budget_still_exports_state_and_completeness(self):
        out = prom.Metrics()
        self.assertFalse(storage_metrics.add(out, MID, fx.snapshot(), True, storage_metrics.Budget(limit=100)))
        text = out.text()
        self.assertEqual(metric(text, "storage_export_complete", machine_id=MID), 0)
        self.assertEqual(metric(text, "storage_inventory_state", machine_id=MID, source="capacity", state="OK"), 1)
        self.assertNotIn("_filesystem_", text)
        empty = fx.snapshot(capacity=fx.capacity_record(rows=[]), io=fx.io_record(cases=[]))
        out = prom.Metrics()
        self.assertTrue(storage_metrics.add(out, MID, empty, True, storage_metrics.Budget(limit=0)))

    def test_dense_fleet_stays_within_the_real_budget(self):
        storage = self.machines(33, dense(long=True))
        text = render(*storage)
        self.assertLessEqual(storage_bytes(text), storage_metrics.STORAGE_TEXT_BYTES)
        complete = [metric(text, "storage_export_complete", machine_id=m) for m, _, _ in storage]
        self.assertEqual(complete[0], 1, "the local machine comes first and is exported")
        self.assertIn(0, complete)
        self.assertEqual(complete, sorted(complete, reverse=True), "equal machines fill the budget in order")
        exported = sum(complete)
        self.assertEqual(len([k for k in samples(text) if k.startswith("machine_manager_storage_filesystem_size_bytes")]),
                         exported * mmstorage.RECORDS_MAX)
        self.assertLess(len(text.encode("utf-8")), 9 << 20)


class StorageExport(TempData):
    def test_legacy_output_matches_main_byte_for_byte(self):
        self.assertEqual(legacy_fixture(), GOLDEN.read_text())
        text = prom.render(MID, machine(), None, (), NOW, base_settings(), storage=())[0]
        self.assertFalse(families(text))


    def test_export_without_storage_inputs_has_no_storage_series(self):
        text, _ = prom.export(self.profile(), base_settings(), NOW)
        self.assertFalse(families(text))
