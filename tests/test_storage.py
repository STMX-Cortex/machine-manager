# SPDX-License-Identifier: Apache-2.0
"""Storage contract acceptance fixtures; no OS discovery or live services."""
import copy
import json
import unittest

import mmtest  # noqa: F401 (paths)
import mmschema
import mmstorage as storage


def sid(kind, value, basis="native"):
    return storage.storage_id(kind, basis, value)


def filesystem(value="root", mounts=None, **over):
    return dict({"id": sid("filesystem", value), "fs_type": "ext4", "category": "local",
                 "mounts": mounts or ["/"], "read_only": False, "device_ids": [], "capacity_group": None,
                 "capacity": storage.capacity(100, 30, 20), "capacity_reason": None}, **over)


def record(filesystems=None, devices=None, **over):
    return dict({"schema_version": 1, "machine_id": "test-machine", "time": 1800000000,
                 "state": "OK", "reason": None, "devices": sorted(devices or [], key=lambda d: d["id"]),
                 "filesystems": sorted(filesystems or [], key=lambda f: f["id"])}, **over)


class Storage(unittest.TestCase):
    def assertValid(self, value):
        self.assertEqual(mmschema.validate(value, mmschema.load("storage")), [])
        self.assertTrue(storage.valid(value), value)
        self.assertTrue(storage.valid(json.loads(json.dumps(value, allow_nan=False))))

    def test_uuid_identity_survives_case_and_spelling(self):
        a = storage.storage_id("filesystem", "uuid", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        b = storage.storage_id("filesystem", "uuid", "{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}")
        self.assertEqual(a, b)
        self.assertNotEqual(a, storage.storage_id("device", "uuid", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
        self.assertNotIn("aaaaaaaa", a)

    def test_native_and_session_identities_do_not_alias(self):
        self.assertNotEqual(sid("device", "disk", "native"), sid("device", "disk", "session"))
        self.assertNotEqual(sid("device", "boot-a:ns-a:8:0", "session"),
                            sid("device", "boot-b:ns-a:8:0", "session"))
        self.assertNotEqual(sid("device", "boot-a:ns-a:8:0", "session"),
                            sid("device", "boot-a:ns-b:8:0", "session"))

    def test_identity_inputs_are_bounded_and_do_not_get_rewritten(self):
        for args in (("mount", "native", "x"), ("device", "label", "x"),
                     ("device", "uuid", "not-a-uuid"), ("device", "native", ""),
                     ("device", "native", "a\n"), ("device", "native", "x" * 1025),
                     ("device", "native", "a\u202e"), ("device", "native", "a\ud800")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                storage.storage_id(*args)

    def test_reserved_free_bytes_are_not_counted_as_used(self):
        cap = storage.capacity(100, 30, 20)
        self.assertEqual(cap, {"total_bytes": 100, "free_bytes": 30, "available_bytes": 20, "used_bytes": 70})
        self.assertEqual(storage.capacity(100, None, 20)["used_bytes"], None)
        self.assertEqual(storage.capacity(), dict.fromkeys(cap))
        self.assertEqual(storage.capacity(0, 0, 0), dict.fromkeys(cap, 0))
        self.assertEqual(storage.capacity(2**63 - 1, 1, 0)["used_bytes"], 2**63 - 2)

    def test_invalid_capacity_never_turns_into_zero_or_a_percentage(self):
        for args in ((100, 101, 0), (100, 20, 30), (None, 20, 30), (100, None, 101),
                     (-1, 0, 0), (True, 0, 0), (100.0, 30, 20), ("100", 30, 20),
                     (float("nan"), 0, 0), (float("inf"), 0, 0), (2**63, 0, 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                storage.capacity(*args)

    def test_mount_aliases_do_not_duplicate_a_filesystem(self):
        fs = filesystem(mounts=["/", "/srv/data"])
        self.assertValid(record([fs]))
        self.assertEqual(storage.select_mounts("local", ["/srv/data", "/", "/srv/data"]), ["/", "/srv/data"])
        self.assertFalse(storage.valid(record([fs, filesystem("bind", ["/srv/data"])])))
        self.assertFalse(storage.valid(record([fs, fs])))

    def test_default_selection_excludes_nonlocal_mounts_and_keeps_container_root(self):
        for category in ("network", "memory", "pseudo", "unknown"):
            self.assertEqual(storage.select_mounts(category, ["/", "/mnt/test"]), [])
        self.assertEqual(storage.select_mounts("overlay", ["/", "/srv/container"]), ["/"])
        self.assertEqual(storage.select_mounts("local", ["/mnt/read-only"]), ["/mnt/read-only"])

    def test_explicit_selection_is_exact_and_excludes_win(self):
        self.assertEqual(storage.select_mounts("network", ["/mnt/a", "/mnt/a/child", "/mnt/b"],
                                              include=["/mnt/a", "/mnt/b"], exclude=["/mnt/b"]), ["/mnt/a"])
        self.assertEqual(storage.select_mounts("local", ["/", "/srv"], exclude=["/"]), ["/srv"])

    def test_selection_rejects_ambiguous_or_oversized_paths(self):
        for path in ("", "relative", "//srv", "/a/", "/a//b", "/a/../b", "/./a", "/a\n", "/a|b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                storage.select_mounts("local", [path])
        for kwargs in ({"mounts": ["/"] * 33}, {"mounts": ["/"], "include": ["/"] * 257},
                       {"mounts": ["/"], "exclude": ["/"] * 257}, {"mounts": "/"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                storage.select_mounts("local", **kwargs)

    def test_apfs_volumes_share_a_capacity_domain_without_merging_volumes(self):
        group = sid("capacity", "apfs-container")
        rows = [filesystem("apfs-system", ["/"], fs_type="apfs", read_only=True, capacity_group=group),
                filesystem("apfs-data", ["/System/Volumes/Data"], fs_type="apfs", capacity_group=group)]
        rec = record(rows)
        self.assertValid(rec)
        self.assertEqual(len({f["id"] for f in rec["filesystems"]}), 2)
        self.assertEqual(len({f["capacity_group"] for f in rec["filesystems"]}), 1)
        self.assertValid(record([filesystem(capacity_group=None)]))  # unknown domain is not independence

    def test_devices_and_filesystems_have_many_to_many_links(self):
        devices = [{"id": sid("device", n), "name": n, "kind": "block", "size_bytes": 100}
                   for n in ("disk-a", "disk-b")]
        refs = sorted(d["id"] for d in devices)
        self.assertValid(record([filesystem(device_ids=refs), filesystem("other", ["/data"], device_ids=refs)], devices))
        self.assertFalse(storage.valid(record([filesystem(device_ids=refs)], devices[:1])))
        self.assertFalse(storage.valid(record(devices=devices + devices[:1])))

    def test_unknown_inventory_is_distinct_from_successfully_empty_inventory(self):
        self.assertValid(record())
        for reason in storage.REASONS:
            self.assertValid(record(state="UNKNOWN", reason=reason))
            self.assertValid(record([filesystem()], state="PARTIAL", reason=reason))
        self.assertFalse(storage.valid(record([filesystem()], state="UNKNOWN", reason="read_failed")))
        self.assertFalse(storage.valid(record(state="UNKNOWN")))
        self.assertFalse(storage.valid(record(reason="read_failed")))

    def test_capacity_failure_keeps_discovered_metadata_and_reason(self):
        for cap in (storage.capacity(), storage.capacity(100, None, 20)):
            rec = record([filesystem(capacity=cap, capacity_reason="permission_denied")])
            self.assertValid(rec)  # enumeration succeeded; capacity did not
            rec["filesystems"][0]["capacity_reason"] = None
            self.assertFalse(storage.valid(rec))
        self.assertFalse(storage.valid(record([filesystem(capacity_reason="read_failed")])))

    def test_semantic_validation_rejects_bad_counters_and_metadata(self):
        for field, value in (("used_bytes", 99), ("used_bytes", True), ("available_bytes", -1),
                             ("total_bytes", float("nan")), ("free_bytes", 101)):
            rec = record([filesystem()]); rec["filesystems"][0]["capacity"][field] = value
            self.assertFalse(storage.valid(rec), (field, value))
        for field, value in (("read_only", 1), ("mounts", ["/", "/"]), ("mounts", ["/b", "/a"]),
                             ("device_ids", ["missing"]), ("category", "bad"),
                             ("capacity_group", sid("device", "wrong-kind")), ("fs_type", "a\n")):
            rec = record([filesystem()]); rec["filesystems"][0][field] = value
            self.assertFalse(storage.valid(rec), (field, value))

    def test_record_limits_versions_timestamps_and_unknown_fields(self):
        rows = [filesystem(str(i), ["/data/" + str(i)]) for i in range(129)]
        self.assertValid(record(rows[:128]))
        self.assertFalse(storage.valid(record(rows)))
        devices = [{"id": sid("device", str(i)), "name": "disk-" + str(i), "kind": "virtual", "size_bytes": None}
                   for i in range(129)]
        self.assertValid(record(devices=devices[:128]))
        self.assertFalse(storage.valid(record(devices=devices)))
        aliases = sorted("/data/" + str(i) for i in range(33))
        self.assertValid(record([filesystem(mounts=aliases[:32], read_only=None)]))
        self.assertFalse(storage.valid(record([filesystem(mounts=aliases)])))
        for field, value in (("time", float("inf")), ("time", float("nan")), ("time", True),
                             ("time", -1), ("time", 10**1000), ("schema_version", 2),
                             ("schema_version", True), ("machine_id", "a" * 121), ("machine_id", "a\n")):
            rec = record(); rec[field] = value
            self.assertFalse(storage.valid(rec), field)
        self.assertFalse(storage.valid(dict(record(), unexpected=True)))
        for value in (None, [], {}, dict(record(), devices=[None]), dict(record(), filesystems=[None])):
            self.assertFalse(storage.valid(value))

    def test_validation_does_not_mutate_input(self):
        rec = record([filesystem()]); before = copy.deepcopy(rec)
        self.assertValid(rec)
        self.assertEqual(rec, before)
