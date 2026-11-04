# SPDX-License-Identifier: Apache-2.0
"""Linux storage fixtures, isolated workers and opt-in read-only native checks."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

from mmtest import TempData, mmcore
import mmread
import mmschema
import mmstorage as model
import mmstorage_linux as linux
from test_resources import load_cli

BOOT = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
FSUUID = "11111111-1111-1111-1111-111111111111"


def mount(mid=10, path="/", dev="8:1", fs="ext4", ro=False):
    return {"mount_id": mid, "parent_id": 1, "dev": dev, "mount": path, "fs_type": fs,
            "category": linux.category(fs), "read_only": ro}


def disk(dev="8:1", fs_uuid=FSUUID):
    return {"id": model.storage_id("device", "native", "fixture:" + dev), "dev": dev, "name": "/dev/test",
            "kind": "block", "size_bytes": 1000, "fs_uuid": fs_uuid, "diskseq": "1"}


def discovery(rows=None, disks=None, **over):
    return dict({"boot": BOOT, "namespace": "mnt:[10]", "mounts": rows if rows is not None else [mount()],
                 "disks": disks if disks is not None else [disk()], "reason": None}, **over)


def reading(row, cap=None, reason=None):
    return {"mount_id": row["mount_id"], "dev": row["dev"],
            "capacity": model.capacity(1000, 300, 200) if cap is None else cap, "reason": reason}


def collect_fixture(data, replies=None, include=(), exclude=()):
    calls = []
    bypath = {r["mount"]: r for r in data["mounts"]}
    def work(mode, payload, timeout):
        if mode == "--discover":
            return copy.deepcopy(data), None
        calls.append(payload["path"])
        return copy.deepcopy((replies or {}).get(payload["path"], (reading(bypath[payload["path"]]), None)))
    with mock.patch.object(linux.sys, "platform", "linux"), mock.patch.object(linux, "_work", side_effect=work):
        result = linux.collect("test-machine", include, exclude)
    return result, calls


class Parsers(unittest.TestCase):
    def test_mount_escapes_flags_and_sources_are_not_exposed(self):
        text = ("10 1 8:1 / / rw,relatime - ext4 /dev/test rw\n"
                "11 10 8:1 /sub /data\\040disk ro - ext4 /dev/test rw\n"
                "12 10 0:2 / /remote rw - nfs4 PRIVATE_SOURCE rw,password=PRIVATE_OPTION\n"
                "13 10 8:1 /sub /literal\\134040 rw - ext4 /dev/test ro\n")
        parsed = linux.parse_mountinfo(text)
        self.assertIsNone(parsed["reason"])
        self.assertEqual([r["mount"] for r in parsed["mounts"]], ["/", "/data disk", "/remote", "/literal\\040"])
        self.assertTrue(parsed["mounts"][1]["read_only"])
        self.assertTrue(parsed["mounts"][3]["read_only"])
        self.assertNotIn("PRIVATE_", json.dumps(parsed))

    def test_categories_are_conservative(self):
        for fs, expected in (("ext4", "local"), ("xfs", "local"), ("btrfs", "local"), ("zfs", "local"),
                             ("overlay", "overlay"), ("nfs4", "network"), ("cifs", "network"),
                             ("fuse.sshfs", "network"), ("tmpfs", "memory"), ("proc", "pseudo"),
                             ("autofs", "pseudo"), ("fuse.unrecognized", "unknown")):
            self.assertEqual(linux.category(fs), expected)

    def test_bad_rows_are_partial_and_not_silently_repaired(self):
        valid = "10 1 8:1 / / rw - ext4 /dev/test rw\n"
        for bad in ("garbage", "11 1 8:1 / /bad\\012name rw - ext4 x rw", "11 1 8:1 / /a/../b rw - ext4 x rw",
                    "11 1 8:1 / /bad\\777name rw - ext4 x rw", "11 1 8:1 / /a rw,ro - ext4 x rw",
                    "11 11 8:1 / /a rw - ext4 x rw", "11 1 9999999999:0 / /a rw - ext4 x rw"):
            with self.subTest(bad=bad):
                got = linux.parse_mountinfo(valid + bad)
                self.assertEqual(got["reason"], "invalid_data")
                self.assertEqual(len(got["mounts"]), 1)

    def test_duplicate_mount_ids_are_all_removed(self):
        got = linux.parse_mountinfo("10 1 8:1 / / rw - ext4 x rw\n10 1 8:2 / /data rw - xfs y rw\n")
        self.assertEqual(got, {"mounts": [], "reason": "invalid_data"})

    def test_parser_bounds_lines_and_bytes(self):
        with self.assertRaises(linux.Cut):
            linux.parse_mountinfo("x" * (linux.MOUNT_BYTES + 1))
        with mock.patch.object(linux, "MOUNT_LINES", 1):
            r = linux.parse_mountinfo("10 1 8:1 / / rw - ext4 x rw\n11 1 8:2 / /data rw - ext4 y rw\n")
            self.assertEqual((len(r["mounts"]), r["reason"]), (1, "truncated"))
        with mock.patch.object(linux, "LINE_BYTES", 20):
            self.assertEqual(linux.parse_mountinfo("10 1 8:1 / / rw - ext4 x rw")["reason"], "truncated")


class Collector(unittest.TestCase):
    def assertRecord(self, rec):
        self.assertTrue(model.valid(rec), rec)
        self.assertEqual(mmschema.validate(rec, mmschema.load("storage")), [])

    def test_aliases_share_identity_and_first_successful_capacity(self):
        rows = [mount(), mount(11, "/data", ro=True)]
        rec, calls = collect_fixture(discovery(rows), {"/data": (reading(rows[1], model.capacity(1000, 250, 150)), None)})
        self.assertRecord(rec)
        self.assertEqual(calls, ["/", "/data"])
        self.assertEqual(len(rec["filesystems"]), 1)
        fs = rec["filesystems"][0]
        self.assertEqual(fs["mounts"], ["/", "/data"])
        self.assertIsNone(fs["read_only"])
        self.assertEqual(fs["capacity"], model.capacity(1000, 300, 200))
        self.assertEqual(fs["id"], model.storage_id("filesystem", "uuid", FSUUID))
        self.assertIsNone(fs["capacity_group"])

    def test_uuid_survives_mount_rename_and_session_changes(self):
        a, _ = collect_fixture(discovery())
        b, _ = collect_fixture(discovery([mount(99, "/renamed")], boot="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", namespace="mnt:[20]"))
        self.assertEqual(a["filesystems"][0]["id"], b["filesystems"][0]["id"])
        a, _ = collect_fixture(discovery(disks=[]))
        b, _ = collect_fixture(discovery(disks=[], namespace="mnt:[20]"))
        self.assertNotEqual(a["filesystems"][0]["id"], b["filesystems"][0]["id"])
        self.assertIn(":session:", a["filesystems"][0]["id"])

    def test_cloned_filesystem_uuids_do_not_merge(self):
        rec, _ = collect_fixture(discovery([mount(), mount(11, "/data", "8:2")], [disk(), disk("8:2")]))
        self.assertRecord(rec)
        self.assertEqual(len(rec["filesystems"]), 2)
        self.assertTrue(all(":session:" in r["id"] for r in rec["filesystems"]))
        self.assertEqual(len({r["id"] for r in rec["filesystems"]}), 2)

    def test_non_rfc_fat_uuid_uses_a_namespaced_native_identity(self):
        rec, _ = collect_fixture(discovery([mount(fs="vfat")], [disk(fs_uuid="1234-ABCD")]))
        self.assertRecord(rec)
        self.assertEqual(rec["filesystems"][0]["id"], model.storage_id("filesystem", "native", "linux-fs-uuid:1234-abcd"))

    def test_default_filtering_happens_before_probing(self):
        rows = [mount(fs="overlay", dev="0:1"), mount(11, "/remote", "0:2", "nfs4"),
                mount(12, "/tmp", "0:3", "tmpfs"), mount(13, "/proc", "0:4", "proc"),
                mount(14, "/container", "0:5", "overlay"), mount(15, "/unknown", "0:6", "fuse.example")]
        rec, calls = collect_fixture(discovery(rows, []))
        self.assertRecord(rec)
        self.assertEqual(calls, ["/"])
        self.assertEqual(rec["filesystems"][0]["category"], "overlay")

    def test_secret_shaped_paths_and_names_are_omitted_without_rewriting_identity(self):
        rows = [mount(), mount(11, "/mnt/TOKEN=do-not-print", "8:2")]
        d = disk("8:2"); d["name"] = "/dev/mapper/TOKEN=do-not-print"
        rec, calls = collect_fixture(discovery(rows, [disk(), d]))
        self.assertRecord(rec)
        self.assertEqual(calls, ["/"])
        self.assertEqual(rec["reason"], "invalid_data")
        self.assertNotIn("do-not-print", json.dumps(rec))

    def test_exact_include_exclude_and_read_only_capacity(self):
        rows = [mount(ro=True), mount(11, "/remote", "0:2", "nfs4"), mount(12, "/remote/child", "0:3", "nfs4")]
        rec, calls = collect_fixture(discovery(rows), include=["/remote"], exclude=["/"])
        self.assertRecord(rec)
        self.assertEqual(calls, ["/remote"])
        self.assertEqual(rec["filesystems"][0]["mounts"], ["/remote"])
        rec, _ = collect_fixture(discovery([mount(ro=True)]))
        self.assertTrue(rec["filesystems"][0]["read_only"])

    def test_automounts_and_their_children_are_never_opened(self):
        rows = [mount(10, "/auto", "0:2", "autofs"), mount(11, "/auto/remote", "0:3", "nfs4")]
        rec, calls = collect_fixture(discovery(rows, []), include=["/auto", "/auto/remote"])
        self.assertRecord(rec)
        self.assertEqual(calls, [])
        self.assertTrue(all(f["capacity_reason"] == "unsupported" for f in rec["filesystems"]))

    def test_overmount_order_uses_kernel_identity_not_largest_id_or_last_row(self):
        top = mount(12, "/data", "8:2", "xfs")
        hidden = mount(99, "/data", "8:3")
        for rows in ([top, hidden], [hidden, top]):
            rec, _ = collect_fixture(discovery(rows, []), {"/data": (reading(top), None)})
            self.assertRecord(rec)
            self.assertEqual(len(rec["filesystems"]), 1)
            self.assertEqual(rec["filesystems"][0]["fs_type"], "xfs")

    def test_hidden_child_does_not_read_covering_filesystem_capacity(self):
        root, hidden = mount(), mount(11, "/hidden", "8:2")
        rec, _ = collect_fixture(discovery([root, hidden]), {"/hidden": (reading(root), None)})
        self.assertRecord(rec)
        self.assertEqual(rec["filesystems"][0]["mounts"], ["/"])

    def test_probe_device_uses_the_mountinfo_row_and_rejects_a_vanished_mount(self):
        table = "10 1 0:31 / / rw - btrfs /dev/test rw\n"
        info = {"/proc/self/fdinfo/7": "pos:\t0\nflags:\t010000000\nmnt_id:\t10\n", "/proc/self/mountinfo": table}
        stat = os.stat_result((0o40755, 1, os.makedev(0, 33), 1, 0, 0, 0, 0, 0, 0))
        vfs = os.statvfs_result((4096, 4096, 100, 30, 20, 0, 0, 0, 0, 255))
        def read(path, limit=16384):
            return info[path]
        with mock.patch.object(linux.os, "O_PATH", getattr(os, "O_PATH", 0o10000000), create=True), \
                mock.patch.object(linux.os, "open", return_value=7), mock.patch.object(linux.os, "close"), \
                mock.patch.object(linux.os, "fstat", return_value=stat), \
                mock.patch.object(linux.os, "fstatvfs", return_value=vfs), mock.patch.object(linux, "_read", side_effect=read):
            result = linux.probe("/", [10])
            self.assertEqual((result["mount_id"], result["dev"], result["reason"]), (10, "0:31", None))
            self.assertEqual(result["capacity"], model.capacity(409600, 122880, 81920))
            info["/proc/self/mountinfo"] = "11 1 0:31 / / rw - btrfs /dev/test rw\n"
            result = linux.probe("/", [10])
        self.assertEqual((result["mount_id"], result["dev"], result["reason"]), (None, None, "read_failed"))
        self.assertEqual(result["capacity"], model.capacity())

    def test_changed_or_recycled_mount_identity_is_not_accepted(self):
        row = mount()
        for reply in (reading(mount(900)), reading(mount(dev="8:9"))):
            rec, _ = collect_fixture(discovery(), {"/": (reply, None)})
            self.assertRecord(rec)
            self.assertEqual(rec["state"], "PARTIAL")
            self.assertEqual(rec["filesystems"], [])

    def test_capacity_errors_keep_metadata_without_zero_or_stale_values(self):
        row = mount()
        for reason in ("permission_denied", "read_failed", "invalid_data"):
            rec, _ = collect_fixture(discovery(), {"/": (reading(row, model.capacity(), reason), None)})
            self.assertRecord(rec)
            self.assertEqual(rec["filesystems"][0]["capacity"], model.capacity())
            self.assertEqual(rec["filesystems"][0]["capacity_reason"], reason)
        rec, _ = collect_fixture(discovery(), {"/": (None, "timeout")})
        self.assertRecord(rec)
        self.assertEqual((rec["state"], rec["reason"]), ("PARTIAL", "timeout"))
        self.assertEqual(rec["filesystems"][0]["capacity_reason"], "timeout")

    def test_a_later_alias_can_supply_capacity_after_an_unreadable_alias(self):
        rows = [mount(), mount(11, "/data")]
        rec, _ = collect_fixture(discovery(rows), {"/": (reading(rows[0], model.capacity(), "permission_denied"), None)})
        self.assertRecord(rec)
        self.assertIsNone(rec["filesystems"][0]["capacity_reason"])

    def test_limits_and_deadline_preserve_partial_unknown_records(self):
        rows = [mount(i + 10, "/data/" + str(i), "8:" + str(i)) for i in range(129)]
        rec, _ = collect_fixture(discovery(rows, []))
        self.assertRecord(rec)
        self.assertEqual(len(rec["filesystems"]), 128)
        self.assertEqual((rec["state"], rec["reason"]), ("PARTIAL", "truncated"))
        rows = [mount(i + 10, "/data/" + str(i)) for i in range(33)]
        rec, _ = collect_fixture(discovery(rows))
        self.assertRecord(rec)
        self.assertEqual(len(rec["filesystems"][0]["mounts"]), 32)
        self.assertEqual(rec["reason"], "truncated")
        with mock.patch.object(linux, "_work", return_value=(discovery(), None)), \
                mock.patch.object(linux.sys, "platform", "linux"), mock.patch.object(linux.time, "monotonic", side_effect=[0, 10]):
            rec = linux.collect("test-machine")
        self.assertRecord(rec)
        self.assertEqual(rec["filesystems"][0]["capacity_reason"], "timeout")

    def test_bad_arguments_and_unsupported_platform_do_not_spawn(self):
        with mock.patch.object(linux, "_work", side_effect=AssertionError("worker started")):
            for kwargs in ({"include": ["relative"]}, {"exclude": ["/a/../b"]}, {"timeout_s": True},
                           {"timeout_s": 0}, {"timeout_s": float("inf")}, {"timeout_s": float("nan")},
                           {"timeout_s": 31}, {"timeout_s": 10**1000}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    linux.collect("test-machine", **kwargs)
            with mock.patch.object(linux.sys, "platform", "darwin"):
                rec = linux.collect("test-machine")
                self.assertRecord(rec)
                self.assertEqual((rec["state"], rec["reason"]), ("UNKNOWN", "unsupported"))

    def test_discovery_failure_is_not_a_successful_empty_inventory(self):
        with mock.patch.object(linux.sys, "platform", "linux"):
            for reason in model.REASONS:
                with mock.patch.object(linux, "_work", return_value=(None, reason)):
                    rec = linux.collect("test-machine")
                self.assertRecord(rec)
                self.assertEqual((rec["state"], rec["reason"]), ("UNKNOWN", reason))
            for value in ({}, {"mounts": []}, dict(discovery(), boot=None), dict(discovery(), reason="unexpected")):
                with mock.patch.object(linux, "_work", return_value=(value, None)):
                    rec = linux.collect("test-machine")
                self.assertRecord(rec)
                self.assertEqual(rec["state"], "UNKNOWN")


class DiskMetadata(TempData):
    def fixture_disk(self, dev, name, props="", size="20", **attrs):
        root = Path(self.root) / "sys" / dev
        root.mkdir(parents=True)
        (root / "uevent").write_text("DEVNAME=" + name + "\n")
        if size is not None:
            (root / "size").write_text(size)
        for key, value in attrs.items():
            (root / key).write_text(value)
        udev = Path(self.root) / "udev"
        udev.mkdir(exist_ok=True)
        (udev / ("b" + dev)).write_text(props)

    def scan(self):
        return linux._disks(BOOT, "mnt:[10]", str(Path(self.root) / "sys"), str(Path(self.root) / "udev"))

    def test_device_sizes_use_512_byte_sectors_and_stable_wwns(self):
        self.fixture_disk("8:0", "test-a", "E:ID_WWN=0xaaa\n")
        self.fixture_disk("8:1", "test-a1", "E:ID_WWN=0xaaa\nE:ID_PART_ENTRY_UUID=" + FSUUID + "\n", partition="1", start="2048")
        rows, reason = self.scan()
        self.assertIsNone(reason)
        self.assertEqual(rows[0]["size_bytes"], 10240)
        self.assertEqual(rows[0]["id"], model.storage_id("device", "wwn", "0xaaa"))
        self.assertEqual(rows[1]["id"], model.storage_id("device", "uuid", FSUUID))

    def test_wwn_partitions_and_clones_do_not_alias(self):
        self.fixture_disk("8:0", "test-a", "E:ID_WWN=0xaaa\n")
        self.fixture_disk("8:1", "test-b", "E:ID_WWN=0xaaa\n")
        rows, _ = self.scan()
        self.assertEqual(len({r["id"] for r in rows}), 2)
        self.assertTrue(all(":session:" in r["id"] for r in rows))
        for dev, start in (("8:2", "2048"), ("8:3", "4096")):
            self.fixture_disk(dev, "part-" + start, "E:ID_WWN=0xaaa\n", partition="1", start=start)
        rows, _ = self.scan()
        self.assertEqual(len({r["id"] for r in rows}), 4)

    def test_absent_udev_falls_back_to_session_and_missing_size_stays_unknown(self):
        self.fixture_disk("8:0", "test-a", size=None, diskseq="99")
        rows, reason = self.scan()
        self.assertEqual(reason, "read_failed")
        self.assertIsNone(rows[0]["size_bytes"])
        self.assertIn(":session:", rows[0]["id"])
        self.assertEqual(rows[0]["diskseq"], "99")

    def test_scan_limits_and_unsafe_device_names(self):
        self.fixture_disk("8:0", "test-a")
        self.fixture_disk("8:1", "../bad")
        rows, reason = self.scan()
        self.assertEqual((len(rows), reason), (1, "invalid_data"))
        with mock.patch.object(linux, "SYS_ENTRIES", 1):
            rows, reason = self.scan()
            self.assertEqual(reason, "truncated")
        self.assertLessEqual(len(rows), 1)

    def test_metadata_reads_refuse_symlinks_and_oversized_files(self):
        root = Path(self.root)
        (root / "large").write_text("12345")
        with self.assertRaises(linux.Cut):
            linux._read(str(root / "large"), 4)
        (root / "link").symlink_to(root / "large")
        with self.assertRaises(OSError):
            linux._read(str(root / "link"))


class Workers(TempData):
    def test_worker_output_errors_are_bounded_and_never_echoed(self):
        for raw in (b'not-json', b'{"x":NaN}', b'{"x":1,"x":2}', b'[' * 20 + b'0' + b']' * 20):
            with self.subTest(raw=raw), mock.patch.object(mmread, "run_bounded", return_value=(0, raw, None)):
                self.assertEqual(linux._work("--discover", None, 1), (None, "invalid_data"))
        for error, expected in (("read command timed out", "timeout"), ("read command exceeded 10 bytes", "truncated"),
                                ("read command output unavailable", "read_failed")):
            with mock.patch.object(mmread, "run_bounded", return_value=(None, b'PRIVATE_ERROR', error)):
                self.assertEqual(linux._work("--discover", None, 1), (None, expected))

    def test_a_real_stuck_worker_times_out_and_a_healthy_filesystem_still_reads(self):
        rows = [mount(), mount(11, "/slow", "8:2"), mount(12, "/z-healthy", "8:3")]
        data = discovery(rows, [])
        code = ("import json,sys,time\n"
                "if sys.argv[1]=='--discover': print(" + repr(json.dumps(data)) + ")\n"
                "else:\n p=json.loads(sys.argv[2])['path']\n"
                " if p=='/slow': time.sleep(30)\n"
                " else: print(json.dumps(" + repr({r['mount']: reading(r) for r in rows}) + "[p]))\n")
        worker = Path(self.root) / "worker.py"
        worker.write_text(code)
        started = time.monotonic()
        with mock.patch.object(linux, "__file__", str(worker)), mock.patch.object(linux.sys, "platform", "linux"), \
                mock.patch.object(linux, "PROBE_TIMEOUT", .25):
            rec = linux.collect("test-machine", timeout_s=2)
        self.assertLess(time.monotonic() - started, 4)
        self.assertTrue(model.valid(rec))
        bypath = {f['mounts'][0]: f for f in rec['filesystems']}
        self.assertEqual(bypath['/slow']['capacity_reason'], 'timeout')
        self.assertIsNone(bypath['/z-healthy']['capacity_reason'])
        self.assertIsNone(bypath['/']['capacity_reason'])

    def test_discovery_worker_has_an_overall_deadline(self):
        worker = Path(self.root) / "worker.py"
        worker.write_text("import time;time.sleep(30)\n")
        started = time.monotonic()
        with mock.patch.object(linux, "__file__", str(worker)), mock.patch.object(linux.sys, "platform", "linux"):
            rec = linux.collect("test-machine", timeout_s=.2)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual((rec["state"], rec["reason"]), ("UNKNOWN", "timeout"))


class Cli(TempData):
    def test_json_and_plain_output_do_not_write_runtime_files(self):
        rec, _ = collect_fixture(discovery())
        before = set(Path(self.root).rglob("*"))
        cli = load_cli()
        for flags in (["--json"], []):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), mock.patch.object(linux, "collect", return_value=rec) as collect:
                self.assertEqual(cli.main(["storage", "--include", "/data disk", "--exclude", "/remote", *flags]), 0)
            collect.assert_called_once_with(mmcore.machine_id(mmcore.load_profile()), include=["/data disk"], exclude=["/remote"])
            if flags:
                self.assertEqual(json.loads(out.getvalue()), rec)
            else:
                self.assertTrue(out.getvalue().startswith("storage=OK reason=none devices=1 filesystems=1\n"))
        self.assertEqual(set(Path(self.root).rglob("*")), before)

    def test_bad_arguments_are_one_line_and_unknown_is_exit_one(self):
        cli = load_cli()
        for args in (["--other"], ["--include"], ["--include", "relative"]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["storage", *args]), 2)
            self.assertEqual(len(out.getvalue().splitlines()), 1)
            self.assertRegex(out.getvalue(), r'^E_(USAGE|STORAGE) .+; fix: .+')
        rec = linux._envelope("test-machine", 1800000000, "unsupported")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(linux, "collect", return_value=rec):
            self.assertEqual(cli.main(["storage", "--json"]), 1)
        self.assertEqual(json.loads(out.getvalue()), rec)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "O_PATH") and os.path.isdir("/proc/self/fdinfo"),
                     "requires Linux O_PATH and real /proc fdinfo")
class Native(unittest.TestCase):
    def root_id(self):
        fd = os.open("/", os.O_PATH | os.O_CLOEXEC)
        try:
            return linux._mount_id(fd)
        finally:
            os.close(fd)

    def test_real_root_capacity_matches_native_statvfs(self):
        mid = self.root_id()
        result = linux.probe("/", [mid])
        self.assertIsNone(result["reason"])
        self.assertEqual(result["mount_id"], mid)
        native = os.statvfs("/")
        self.assertEqual(result["capacity"]["total_bytes"], native.f_blocks * native.f_frsize)
        self.assertGreaterEqual(result["capacity"]["free_bytes"], result["capacity"]["available_bytes"])

    def test_device_comes_from_mountinfo_not_a_btrfs_style_subvolume_st_dev(self):
        mid = self.root_id()
        expected = linux._mount_dev(mid)
        self.assertRegex(expected, r"^[0-9]+:[0-9]+$")
        real = os.fstat
        def subvolume(fd):  # btrfs reports a per-subvolume anon st_dev, not the superblock's mountinfo device
            st = list(real(fd))
            st[2] = os.makedev(0, 999999)
            return os.stat_result(st)
        with mock.patch.object(linux.os, "fstat", side_effect=subvolume):
            result = linux.probe("/", [mid])
        self.assertEqual((result["mount_id"], result["dev"], result["reason"]), (mid, expected, None))

    def test_unselected_mount_is_identified_without_a_capacity_syscall(self):
        with mock.patch.object(linux.os, "fstatvfs", side_effect=AssertionError("unselected mount sampled")):
            result = linux.probe("/", [])
        self.assertEqual(result["reason"], "unsupported")
        self.assertEqual(result["capacity"], model.capacity())

    def test_mount_change_during_probe_discards_capacity(self):
        mid = self.root_id()
        with mock.patch.object(linux, "_mount_id", side_effect=[mid, mid + 1]):
            result = linux.probe("/", [mid])
        self.assertIsNone(result["mount_id"])
        self.assertEqual(result["capacity"], model.capacity())

    def test_real_collector_returns_a_valid_fresh_observation(self):
        started = time.time()
        rec = linux.collect("test-machine")
        self.assertTrue(model.valid(rec))
        self.assertGreaterEqual(rec["time"], started)
        self.assertIn(rec["state"], ("OK", "PARTIAL"))
        self.assertTrue(any("/" in fs["mounts"] for fs in rec["filesystems"]))
