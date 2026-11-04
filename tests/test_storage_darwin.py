# SPDX-License-Identifier: Apache-2.0
"""Portable macOS storage fixtures and read-only native Mac acceptance checks."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import time
import unittest
from unittest import mock
from types import SimpleNamespace

from mmtest import TempData, mmcore
import mmread
import mmstorage as model
import mmstorage_collect as collect
import mmstorage_darwin as mac
import mmstorage_linux as linux
from test_resources import load_cli

BOOT = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
VOL = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"
POOL = "33333333-3333-3333-3333-333333333333"


def mount(path="/", fsid=1, dev="disk3s1", fs="apfs", ro=False):
    return {"mount": path, "fs_type": fs, "category": mac.category(fs), "fsid": [fsid, 0], "dev": dev, "read_only": ro}


def disk(dev="disk3s1", vol=VOL):
    return {"dev": dev, "uuid": None, "volume_uuid": vol, "size_bytes": 1000}


def volume(vol=VOL, ref="disk3", pool=POOL):
    return {"volume_uuid": vol, "container": ref, "container_uuid": pool}


def fixture(rows=None, disks=None, volumes=None, replies=None, info=None, metadata_failures=None, **options):
    rows = rows if rows is not None else [mount()]
    disks = disks if disks is not None else [disk()]
    volumes = volumes if volumes is not None else {"disk3s1": volume()}
    calls = []
    bypath = {r["mount"]: r for r in rows}
    def work(mode, payload, timeout):
        calls.append((mode, copy.deepcopy(payload)))
        if mode in (metadata_failures or {}):
            return None, metadata_failures[mode]
        if mode == "--mounts":
            return {"boot": BOOT, "mounts": copy.deepcopy(rows), "reason": None}, None
        if mode == "--disks":
            return {"disks": copy.deepcopy(disks), "reason": None}, None
        if mode == "--apfs":
            return {"volumes": copy.deepcopy(volumes), "reason": None}, None
        if mode == "--info":
            return copy.deepcopy((info or {}).get(payload, ({"volume_uuid": None, "snapshot_uuid": None,
                                                           "snapshot": False, "container": None}, None)))
        return copy.deepcopy((replies or {}).get(payload["path"], ({"row": bypath[payload["path"]],
                                 "capacity": model.capacity(1000, 300, 200), "reason": None}, None)))
    with mock.patch.object(mac.sys, "platform", "darwin"), mock.patch.object(mac, "_work", side_effect=work):
        result = mac.collect("test-machine", **options)
    assert model.valid(result), result
    return result, calls


class Metadata(unittest.TestCase):
    def test_disk_inventory_is_bounded_sorted_and_strips_labels(self):
        raw = {"AllDisksAndPartitions": [{"DeviceIdentifier": "disk10", "Size": 1000, "MediaName": "PRIVATE",
               "Partitions": [{"DeviceIdentifier": "disk10s1", "Size": 900, "VolumeUUID": VOL}]},
               {"DeviceIdentifier": "disk2", "Size": 500}]}
        result = mac.parse_disks(raw)
        self.assertIsNone(result['reason'])
        self.assertEqual([d['dev'] for d in result['disks']], ['disk2', 'disk10', 'disk10s1'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        with mock.patch.object(model, 'RECORDS_MAX', 1):
            result = mac.parse_disks(raw)
        self.assertEqual((len(result['disks']), result['reason']), (1, 'truncated'))

    def test_bad_or_duplicate_devices_are_not_invented(self):
        result = mac.parse_disks({'AllDisksAndPartitions': [{'DeviceIdentifier': 'disk1', 'Size': True},
                  {'DeviceIdentifier': '../secret'}, {'DeviceIdentifier': 'disk2'}, {'DeviceIdentifier': 'disk2'}]})
        self.assertEqual(result['reason'], 'invalid_data')
        self.assertEqual([d['dev'] for d in result['disks']], ['disk1'])
        self.assertIsNone(result['disks'][0]['size_bytes'])

    def test_apfs_membership_never_converts_container_totals_to_volume_capacity(self):
        doc = {'Containers': [{'ContainerReference': 'disk3', 'APFSContainerUUID': POOL,
                              'CapacityCeiling': 2000, 'CapacityFree': 500, 'Volumes': [
                                  {'DeviceIdentifier': 'disk3s1', 'APFSVolumeUUID': VOL, 'Name': 'PRIVATE'},
                                  {'DeviceIdentifier': 'disk3s2', 'APFSVolumeUUID': OTHER}]}]}
        result = mac.parse_apfs(doc)
        self.assertEqual(result, {'volumes': {'disk3s1': volume(), 'disk3s2': volume(OTHER)}, 'reason': None})
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_duplicate_container_or_volume_is_rejected(self):
        row = {'ContainerReference': 'disk3', 'APFSContainerUUID': POOL, 'Volumes': []}
        with self.assertRaises(ValueError):
            mac.parse_apfs({'Containers': [row, row]})
        row['Volumes'] = [{'DeviceIdentifier': 'disk3s1'}, {'DeviceIdentifier': 'disk3s1'}]
        with self.assertRaises(ValueError):
            mac.parse_apfs({'Containers': [row]})

    def test_plist_byte_depth_entity_and_node_bounds_before_decoding(self):
        doc = {'Containers': []}
        self.assertEqual(mac._plist(plistlib.dumps(doc)), doc)
        for raw in (b'<?xml version="1.0"?><!ENTITY x "secret"><plist/>',
                    b'bplist00garbage', b'<?xml?>' + b'<array>' * 20 + b'</array>' * 20):
            with self.assertRaises(ValueError):
                mac._plist(raw)
        with mock.patch.object(mac, 'PLIST_BYTES', 3), self.assertRaises(mac.common.Cut):
            mac._plist(plistlib.dumps(doc))
        with mock.patch.object(mac, 'NODES_MAX', 1), self.assertRaises(mac.common.Cut):
            mac.parse_disks({'AllDisksAndPartitions': [{'DeviceIdentifier': 'disk1'}]})

    def test_categories_are_conservative(self):
        for fs, expected in [('apfs', 'local'), ('hfs', 'local'), ('exfat', 'local'), ('smbfs', 'network'),
                             ('afpfs', 'network'), ('nfs', 'network'), ('autofs', 'pseudo'), ('devfs', 'pseudo'),
                             ('tmpfs', 'memory'), ('osxfuse', 'unknown')]:
            self.assertEqual(mac.category(fs), expected)


class Collector(unittest.TestCase):
    def test_apfs_volumes_keep_individual_capacity_and_share_only_a_group(self):
        rows = [mount(), mount('/System/Volumes/Data', 2, 'disk3s2')]
        rec, _ = fixture(rows, [disk(), disk('disk3s2', OTHER)], {'disk3s1': volume(), 'disk3s2': volume(OTHER)},
                         {'/System/Volumes/Data': ({'row': rows[1], 'capacity': model.capacity(900, 250, 100), 'reason': None}, None)})
        self.assertEqual(rec['state'], 'OK')
        files = rec['filesystems']
        self.assertEqual(len(files), 2)
        self.assertEqual(len({f['capacity_group'] for f in files}), 1)
        self.assertEqual(files[0]['capacity_group'], model.storage_id('capacity', 'uuid', POOL))
        self.assertEqual({f['capacity']['total_bytes'] for f in files}, {900, 1000})
        self.assertNotIn('total_bytes', rec)  # no misleading host/container sum

    def test_aliases_are_one_record_with_first_capacity_and_mixed_ro(self):
        rows = [mount(), mount('/alias', ro=True)]
        rec, _ = fixture(rows, replies={'/alias': ({'row': rows[1], 'capacity': model.capacity(1000, 200, 100), 'reason': None}, None)})
        self.assertEqual(len(rec['filesystems']), 1)
        fs = rec['filesystems'][0]
        self.assertEqual(fs['mounts'], ['/', '/alias'])
        self.assertIsNone(fs['read_only'])
        self.assertEqual(fs['capacity'], model.capacity(1000, 300, 200))

    def test_uuid_identity_survives_rename_and_snapshot_does_not_merge_with_live_volume(self):
        first, _ = fixture()
        renamed, _ = fixture([mount('/new')])
        self.assertEqual(first['filesystems'][0]['id'], renamed['filesystems'][0]['id'])
        rows = [mount(dev='disk3s1s1'), mount('/live', 2)]
        snap = {'volume_uuid': VOL, 'snapshot_uuid': OTHER, 'snapshot': True, 'container': 'disk3'}
        rec, _ = fixture(rows, info={'disk3s1s1': (snap, None)})
        self.assertEqual(len(rec['filesystems']), 2)
        self.assertEqual(len({f['id'] for f in rec['filesystems']}), 2)
        self.assertEqual(len({f['capacity_group'] for f in rec['filesystems']}), 1)

    def test_cloned_volume_and_container_uuids_do_not_merge_native_objects(self):
        rows = [mount(), mount('/clone', 2, 'disk4s1')]
        rec, _ = fixture(rows, [disk(), disk('disk4s1')], {'disk3s1': volume(), 'disk4s1': volume(ref='disk4')})
        self.assertEqual(len(rec['filesystems']), 2)
        self.assertTrue(all(':session:' in f['id'] for f in rec['filesystems']))
        self.assertEqual(len({f['capacity_group'] for f in rec['filesystems']}), 2)

    def test_duplicate_device_uuid_falls_back_and_missing_topology_remains_unknown(self):
        a, b = disk(), disk('disk4s1', OTHER)
        a['uuid'] = b['uuid'] = POOL
        rec, _ = fixture([mount(), mount('/other', 2, 'disk4s1', 'hfs')], [a, b], {})
        self.assertEqual(len(rec['devices']), 2)
        self.assertTrue(all(':session:' in d['id'] for d in rec['devices']))
        self.assertTrue(all(f['capacity_group'] is None for f in rec['filesystems']))

    def test_session_fallback_changes_between_observations_instead_of_claiming_stability(self):
        a, _ = fixture(disks=[], volumes={})
        b, _ = fixture(disks=[], volumes={})
        self.assertNotEqual(a['filesystems'][0]['id'], b['filesystems'][0]['id'])
        self.assertIn(':session:', a['filesystems'][0]['id'])
        self.assertEqual(a['filesystems'][0]['device_ids'], [])

    def test_default_filtering_and_exact_include_exclude_precede_path_access(self):
        rows = [mount(), mount('/remote', 2, None, 'smbfs'), mount('/dev', 3, None, 'devfs'),
                mount('/unknown', 4, None, 'osxfuse')]
        rec, calls = fixture(rows)
        self.assertEqual([v['path'] for m, v in calls if m == '--probe'], ['/'])
        rec, calls = fixture(rows, include=['/remote'], exclude=['/'])
        self.assertEqual([v['path'] for m, v in calls if m == '--probe'], ['/remote'])
        self.assertEqual(rec['filesystems'][0]['category'], 'network')

    def test_autofs_and_children_remain_metadata_only(self):
        rows = [mount('/auto', 2, None, 'autofs'), mount('/auto/remote', 3, None, 'nfs')]
        rec, calls = fixture(rows, [], {}, include=['/auto', '/auto/remote'])
        self.assertFalse(any(m == '--probe' for m, _ in calls))
        self.assertTrue(all(f['capacity_reason'] == 'unsupported' for f in rec['filesystems']))

    def test_secret_shaped_paths_are_omitted_not_rewritten(self):
        rec, calls = fixture([mount(), mount('/TOKEN=secret-data', 2, 'disk4s1')])
        self.assertEqual(rec['reason'], 'invalid_data')
        self.assertNotIn('secret-data', json.dumps(rec))
        self.assertFalse(any(v.get('path') == '/TOKEN=secret-data' for m, v in calls if m == '--probe'))

    def test_changed_mount_is_not_attributed_to_discovered_filesystem(self):
        for reply in ({'row': mount(fsid=99), 'capacity': model.capacity(1000, 300, 200), 'reason': None},
                      {'row': None, 'capacity': model.capacity(), 'reason': 'read_failed'}):
            rec, _ = fixture(replies={'/': (reply, None)})
            self.assertEqual(rec['state'], 'PARTIAL')
            self.assertEqual(rec['filesystems'], [])

    def test_capacity_failure_keeps_metadata_with_null_bytes(self):
        for reason in ('timeout', 'permission_denied', 'invalid_data'):
            rec, _ = fixture(replies={'/': (None, reason)})
            self.assertEqual(rec['filesystems'][0]['capacity'], model.capacity())
            self.assertEqual(rec['filesystems'][0]['capacity_reason'], reason)

    def test_a_later_healthy_alias_supplies_capacity(self):
        rec, _ = fixture([mount(), mount('/alias')], replies={'/': (None, 'permission_denied')})
        self.assertIsNone(rec['filesystems'][0]['capacity_reason'])
        self.assertEqual(rec['filesystems'][0]['capacity'], model.capacity(1000, 300, 200))

    def test_record_and_alias_limits_are_partial(self):
        rows = [mount('/v%d' % n, n + 1, 'disk%ds1' % n) for n in range(4)]
        with mock.patch.object(model, 'RECORDS_MAX', 2):
            rec, _ = fixture(rows, [], {})
        self.assertEqual((len(rec['filesystems']), rec['reason']), (2, 'truncated'))
        rows = [mount('/v%d' % n) for n in range(4)]
        with mock.patch.object(model, 'MOUNTS_MAX', 2):
            rec, _ = fixture(rows)
        self.assertEqual((len(rec['filesystems'][0]['mounts']), rec['reason']), (2, 'truncated'))

    def test_missing_diskutil_preserves_capacity_with_explicit_partial_inventory(self):
        rec, _ = fixture(metadata_failures={'--disks': 'read_failed', '--apfs': 'timeout'})
        self.assertEqual(rec['state'], 'PARTIAL')
        self.assertEqual(rec['devices'], [])
        self.assertEqual(rec['filesystems'][0]['capacity'], model.capacity(1000, 300, 200))
        self.assertIsNone(rec['filesystems'][0]['capacity_group'])

    def test_duplicate_snapshot_uuid_across_fsids_is_disambiguated(self):
        rows = [mount(dev='disk3s1s1'), mount('/clone', 2, 'disk4s1s1')]
        extra = {'volume_uuid': VOL, 'snapshot_uuid': OTHER, 'snapshot': True, 'container': None}
        rec, _ = fixture(rows, [], {}, info={'disk3s1s1': (extra, None), 'disk4s1s1': (extra, None)})
        self.assertEqual(rec['state'], 'PARTIAL')
        self.assertEqual(len({f['id'] for f in rec['filesystems']}), 2)
        self.assertTrue(all(':session:' in f['id'] for f in rec['filesystems']))

    def test_bad_arguments_and_wrong_platform_do_not_start_workers(self):
        with mock.patch.object(mac, '_work') as work:
            for timeout in (True, 0, 31, float('inf'), float('nan'), 10**1000):
                with self.assertRaises(ValueError):
                    mac.collect('test-machine', timeout_s=timeout)
            with self.assertRaises(ValueError):
                mac.collect('test-machine', include=['relative'])
            with mock.patch.object(mac.sys, 'platform', 'linux'):
                rec = mac.collect('test-machine')
            self.assertTrue(model.valid(rec))
            self.assertEqual(rec['reason'], 'unsupported')
            work.assert_not_called()


class Probe(unittest.TestCase):
    def run_probe(self, changed=False, hidden=False, invalid=False):
        samples = iter([1 if not hidden else 9, 9 if changed else 1])
        def statfs(fd, st):
            st.__dict__.update(bsize=10, blocks=100, bfree=30, bavail=40 if invalid else 20,
                               mount=b'/', fstype=b'apfs', source=b'/dev/disk3s1',
                               fsid=[next(samples), 0], flags=0)
            return 0
        native = (SimpleNamespace(byref=lambda v: v), SimpleNamespace(fstatfs64=statfs), SimpleNamespace)
        with mock.patch.object(mac, '_native', return_value=native), \
                mock.patch.object(mac.os, 'open', side_effect=[10, 11]), mock.patch.object(mac.os, 'close') as close:
            result = mac.probe('/', [mount()])
        return result, close.call_args_list

    def test_descriptor_capacity_and_both_descriptors_closed(self):
        result, closed = self.run_probe()
        self.assertEqual(result['capacity'], model.capacity(1000, 300, 200))
        self.assertIsNone(result['reason'])
        self.assertEqual(closed, [mock.call(11), mock.call(10)])

    def test_hidden_or_changed_mount_does_not_supply_capacity(self):
        for options in ({'changed': True}, {'hidden': True}):
            result, closed = self.run_probe(**options)
            self.assertIsNone(result['row'])
            self.assertEqual(result['capacity'], model.capacity())
            self.assertIn(mock.call(10), closed)

    def test_inconsistent_capacity_is_rejected(self):
        with self.assertRaises(ValueError):
            self.run_probe(invalid=True)


class Workers(TempData):
    def test_fixed_diskutil_commands_and_sanitized_info(self):
        doc = {'DeviceIdentifier': 'disk3s1', 'VolumeUUID': VOL, 'VolumeName': 'PRIVATE',
               'APFSContainerReference': 'disk3', 'APFSSnapshotUUID': OTHER, 'APFSSnapshot': True}
        with mock.patch.object(mmread, 'run_bounded', return_value=(0, plistlib.dumps(doc), None)) as run:
            info, error = mac._work('--info', 'disk3s1', .5)
        self.assertIsNone(error)
        self.assertEqual(run.call_args.args[0], ['/usr/sbin/diskutil', 'info', '-plist', 'disk3s1'])
        self.assertNotIn('PRIVATE', json.dumps(info))

    def test_worker_failure_does_not_echo_stderr_or_accept_nonfinite_json(self):
        for raw in (b'{"x":NaN}', b'{"x":1,"x":2}', b'not-json'):
            with mock.patch.object(mmread, 'run_bounded', return_value=(0, raw, None)):
                self.assertEqual(mac._work('--mounts', None, 1), (None, 'invalid_data'))
        with mock.patch.object(mmread, 'run_bounded', return_value=(0, b'<?xml?>bad', None)):
            self.assertEqual(mac._work('--disks', None, 1), (None, 'invalid_data'))
        with mock.patch.object(mmread, 'run_bounded', return_value=(None, b'PRIVATE', 'read command timed out')):
            self.assertEqual(mac._work('--mounts', None, 1), (None, 'timeout'))

    def test_real_worker_timeout_leaves_budget_for_healthy_mount(self):
        data = {'boot': BOOT, 'mounts': [mount(dev=None), mount('/slow', 2, None), mount('/z-good', 3, None)], 'reason': None}
        worker = Path(self.root) / 'worker.py'
        worker.write_text('import sys,json,time\n'
                          'if sys.argv[1]=="--mounts": print(' + repr(json.dumps(data)) + ')\n'
                          'else:\n p=json.loads(sys.argv[2])["path"]\n'
                          ' if p=="/slow": time.sleep(30)\n'
                          ' else: print(json.dumps({"row":' + repr({r['mount']: r for r in data['mounts']}) +
                          '[p],"capacity":{"total_bytes":1000,"free_bytes":300,"available_bytes":200,"used_bytes":700},"reason":None}))\n')
        original = mac._work
        def work(mode, payload, timeout):
            if mode == '--disks':
                return {'disks': [], 'reason': None}, None
            if mode == '--apfs':
                return {'volumes': {}, 'reason': None}, None
            return original(mode, payload, timeout)
        started = time.monotonic()
        with mock.patch.object(mac, '__file__', str(worker)), mock.patch.object(mac, '_work', side_effect=work), \
                mock.patch.object(mac.sys, 'platform', 'darwin'), mock.patch.object(mac, 'PROBE_TIMEOUT', .25):
            rec = mac.collect('test-machine', timeout_s=2)
        self.assertLess(time.monotonic() - started, 4)
        self.assertTrue(model.valid(rec))
        bypath = {f['mounts'][0]: f for f in rec['filesystems']}
        self.assertEqual(bypath['/slow']['capacity_reason'], 'timeout')
        self.assertIsNone(bypath['/z-good']['capacity_reason'])

    def test_discovery_deadline_and_metadata_failure_are_explicit(self):
        with mock.patch.object(mac.sys, 'platform', 'darwin'), mock.patch.object(mac, '_work', return_value=(None, 'timeout')):
            rec = mac.collect('test-machine', timeout_s=.1)
        self.assertTrue(model.valid(rec))
        self.assertEqual((rec['state'], rec['reason']), ('UNKNOWN', 'timeout'))


class Cli(TempData):
    def test_actual_platform_dispatch_preserves_linux_and_mac_apis(self):
        for platform, backend in [('darwin', mac), ('linux', linux), ('unsupported', linux)]:
            rec = linux._envelope('test-machine', 1800000000, 'unsupported')
            with mock.patch.object(collect.sys, 'platform', platform), mock.patch.object(backend, 'collect', return_value=rec) as read:
                self.assertEqual(collect.collect('test-machine', ['/remote'], ['/']), rec)
            read.assert_called_once_with('test-machine', include=['/remote'], exclude=['/'], timeout_s=5.0)

    def test_mac_json_plain_and_exit_codes_without_runtime_writes(self):
        rec, _ = fixture()
        before = set(Path(self.root).rglob('*'))
        cli = load_cli()
        for flags in (['--json'], []):
            out = io.StringIO()
            with mock.patch.object(collect.sys, 'platform', 'darwin'), mock.patch.object(mac, 'collect', return_value=rec), \
                    contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(['storage', *flags]), 0)
            if flags:
                self.assertEqual(json.loads(out.getvalue()), rec)
            else:
                self.assertIn('storage=OK', out.getvalue())
        self.assertEqual(set(Path(self.root).rglob('*')), before)

    def test_import_on_linux_does_not_load_native_ctypes(self):
        code = 'import sys;sys.path.insert(0,' + repr(str(Path(__file__).resolve().parents[1] / 'core')) + ');import mmstorage_darwin,mmstorage_collect;assert "ctypes" not in sys.modules'
        result = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(sys.platform == 'darwin', 'requires native macOS mount and diskutil APIs')
class Native(unittest.TestCase):
    def test_real_mount_abi_and_root_capacity_matches_statvfs(self):
        data = mac.mounts()
        root = next(r for r in data['mounts'] if r['mount'] == '/')
        result = mac.probe('/', [root])
        self.assertIsNone(result['reason'])
        self.assertEqual(result['row'], root)
        v = os.statvfs('/')
        self.assertEqual(result['capacity']['total_bytes'], v.f_blocks * v.f_frsize)

    def test_real_diskutil_and_apfs_container_membership(self):
        disks, reason = mac._work('--disks', None, 5)
        self.assertIsNone(reason)
        self.assertTrue(disks['disks'])
        data = mac.mounts()
        if any(r['fs_type'] == 'apfs' for r in data['mounts']):
            apfs, reason = mac._work('--apfs', None, 5)
            self.assertIsNone(reason)
            self.assertTrue(apfs['volumes'])
            self.assertTrue(any(v['container_uuid'] for v in apfs['volumes'].values()))

    def test_real_collection_is_valid_fresh_and_includes_root(self):
        started = time.time()
        rec = collect.collect('test-machine')
        self.assertTrue(model.valid(rec))
        self.assertGreaterEqual(rec['time'], started)
        self.assertIn(rec['state'], ('OK', 'PARTIAL'))
        self.assertTrue(any('/' in f['mounts'] for f in rec['filesystems']), rec)
        apfs = [f for f in rec['filesystems'] if f['fs_type'] == 'apfs']
        self.assertTrue(any(f['capacity_group'] for f in apfs), rec)
