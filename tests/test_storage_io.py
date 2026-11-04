# SPDX-License-Identifier: Apache-2.0
"""Device I/O arithmetic, pinned metadata fixtures, owned-worker deadlines and native read-only checks."""
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

from mmtest import TempData
import mmread
import mmschema
import mmstorage_io as model
import mmstorage_io_collect as collector
import mmstorage_io_linux as linux
import mmstorage_io_darwin as mac
from test_resources import load_cli

BOOT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'


def row(key='8:0', generation='1', name='/dev/sda', tick=1_000_000_000, count=None, **over):
    return dict({'key': key, 'generation': generation, 'name': name, 'scope': 'whole_device', 'time': 1000 + tick / 1e9,
                 'monotonic_ns': tick, 'counters': count if count is not None else model.counters(1000, 2000, 10, 20), 'reason': None}, **over)


def snapshot(rows=None, **over):
    return dict({'boot': BOOT, 'domain': 'fixture-v1', 'time': 1100, 'monotonic_ns': 100_000_000_000,
                 'state': 'OK', 'reason': None, 'devices': rows if rows is not None else [row()]}, **over)


def observed(before=None, after=None):
    return model.observation('test-machine', before if before is not None else snapshot(),
                             after if after is not None else snapshot([row(tick=3_000_000_000, count=model.counters(3000, 6000, 30, 60))]), 1)


def driver(entry=100, name='disk0', stats=None):
    return {'IORegistryEntryID': entry, 'IOObjectClass': 'IOBlockStorageDriver',
            'Statistics': stats if stats is not None else dict(zip(mac.STAT_KEYS, (1000, 2000, 10, 20))),
            'Serial Number': 'PRIVATE_SECRET', 'IORegistryEntryChildren': [
                {'IORegistryEntryID': entry + 1, 'IOObjectClass': 'IOMedia', 'Whole': True, 'BSD Name': name, 'VolumeName': 'PRIVATE_LABEL',
                 'IORegistryEntryChildren': [{'Whole': False, 'BSD Name': name + 's1'}]}]}


class Arithmetic(unittest.TestCase):
    def test_exact_uint64_counters_reject_coercion_and_overflow(self):
        self.assertEqual(model.counters(0, model.MAX_COUNTER, 0, None)['write_bytes'], model.MAX_COUNTER)
        for value in (-1, True, 1.0, model.MAX_COUNTER + 1, '1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                model.counters(read_bytes=value)

    def test_rates_use_actual_elapsed_time_and_idle_zero_is_known(self):
        a = model.counters(1000, 2000, 10, 20)
        b = model.counters(3000, 6000, 30, 60)
        self.assertEqual(model.rates(a, b, 2), {'rates': dict(zip(model.RATE_KEYS, (1000., 2000., 10., 20.))), 'reason': None})
        self.assertEqual(list(model.rates(a, a, 1)['rates'].values()), [0, 0, 0, 0])

    def test_any_counter_reset_makes_all_rates_unknown(self):
        a, b = model.counters(1000, 2000, 10, 20), model.counters(3000, 1999, 30, 60)
        result = model.rates(a, b, 1)
        self.assertEqual(result['reason'], 'counter_reset')
        self.assertTrue(all(v is None for v in result['rates'].values()))

    def test_missing_and_bad_intervals_do_not_create_zero_or_infinite_rates(self):
        a = model.counters(1000, 2000, 10, 20)
        self.assertEqual(model.rates(None, a, 1)['reason'], 'baseline_missing')
        self.assertEqual(model.rates(model.counters(), a, 1)['reason'], 'read_failed')
        for elapsed in (None, True, 0, -1, .0001, 61, float('inf'), float('nan'), 10**1000):
            self.assertEqual(model.rates(a, a, elapsed)['reason'], 'interval_invalid')

    def test_large_counter_delta_stays_exact_before_division(self):
        before = model.counters(model.MAX_COUNTER - 3, 0, 0, 0)
        after = model.counters(model.MAX_COUNTER, 0, 0, 0)
        self.assertEqual(model.rates(before, after, 1)['rates']['read_bytes_per_s'], 3)

    def test_full_uint64_delta_at_minimum_interval_stays_within_the_validated_bound(self):
        zero, full = model.counters(0, 0, 0, 0), model.counters(*(model.MAX_COUNTER,) * 4)
        result = model.rates(zero, full, .001)  # float division rounds above MAX_COUNTER * 1000
        self.assertEqual(result, {'rates': dict.fromkeys(model.RATE_KEYS), 'reason': 'invalid_data'})
        rec = observed(snapshot([row(count=zero)]), snapshot([row(tick=1_001_000_000, count=full)]))
        self.assertTrue(model.valid(rec))
        self.assertEqual(rec['devices'][0]['rate_reason'], 'invalid_data')


class Records(unittest.TestCase):
    def test_independent_versioned_schema_and_source_timestamps(self):
        rec = observed()
        self.assertTrue(model.valid(rec))
        self.assertEqual(mmschema.validate(rec, mmschema.load('storage-io')), [])
        self.assertEqual(rec['requested_interval_s'], 1)
        d = rec['devices'][0]
        self.assertEqual(d['interval_s'], 2)  # not the requested sleep interval
        self.assertEqual(d['rates']['read_bytes_per_s'], 1000)
        self.assertEqual(d['time'], 1003)
        self.assertNotIn('filesystems', rec)

    def test_replacement_same_name_and_reboot_never_reuse_a_baseline(self):
        for before, after in ((snapshot(), snapshot([row(generation='2', tick=2_000_000_000)])),
                              (snapshot(), snapshot([row(tick=2_000_000_000)], boot='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'))):
            rec = observed(before, after)
            self.assertTrue(model.valid(rec))
            self.assertEqual(rec['devices'][0]['rate_reason'], 'identity_changed')
            self.assertEqual(len(rec['removed_ids']), 1)

    def test_rename_with_proven_same_generation_keeps_identity_and_rates(self):
        rec = observed(snapshot(), snapshot([row(name='/dev/renamed', tick=2_000_000_000)]))
        self.assertIsNone(rec['devices'][0]['rate_reason'])
        self.assertEqual(rec['removed_ids'], [])

    def test_new_and_removed_devices_are_not_zero_activity(self):
        rec = observed(snapshot([row()]), snapshot([row('8:16', '2', '/dev/sdb')]))
        self.assertEqual(rec['devices'][0]['rate_reason'], 'baseline_missing')
        self.assertEqual(len(rec['removed_ids']), 1)
        rec = observed(snapshot(), snapshot([]))
        self.assertEqual(rec['devices'], [])
        self.assertEqual(len(rec['removed_ids']), 1)

    def test_missing_generation_does_not_claim_an_old_id_disappeared(self):
        rec = observed(snapshot(), snapshot([row(generation=None, tick=2_000_000_000)]))
        self.assertEqual(rec['removed_ids'], [])
        self.assertEqual(rec['devices'][0]['rate_reason'], 'unsupported')

    def test_incomplete_scan_does_not_claim_disappearance(self):
        rec = observed(snapshot(), snapshot([], state='PARTIAL', reason='truncated'))
        self.assertEqual(rec['removed_ids'], [])
        self.assertEqual((rec['state'], rec['reason']), ('PARTIAL', 'truncated'))

    def test_missing_generation_and_counters_are_explicit(self):
        rec = observed(snapshot([row(generation=None)]), snapshot([row(generation=None, tick=2_000_000_000)]))
        self.assertEqual(rec['devices'][0]['rate_reason'], 'unsupported')
        rec = observed(snapshot(), snapshot([row(tick=2_000_000_000, count=model.counters(), reason='permission_denied')]))
        self.assertEqual(rec['devices'][0]['counter_reason'], 'permission_denied')
        self.assertEqual(rec['devices'][0]['rate_reason'], 'permission_denied')
        self.assertTrue(model.valid(rec))

    def test_bad_baseline_is_not_relabelled_as_current_data(self):
        rec = model.observation('test-machine', None, snapshot(), 1, 'timeout')
        self.assertEqual((rec['state'], rec['reason']), ('PARTIAL', 'timeout'))
        self.assertEqual(rec['devices'][0]['rate_reason'], 'baseline_missing')
        rec = observed(snapshot([row(count=model.counters(), reason='read_failed')]), snapshot())
        self.assertEqual(rec['devices'][0]['rate_reason'], 'baseline_missing')

    def test_shared_devices_are_not_repeated_per_filesystem_or_summed(self):
        rec = observed(snapshot([row(), row('253:0', '2', '/dev/dm-0')]),
                       snapshot([row(tick=2_000_000_000), row('253:0', '2', '/dev/dm-0', tick=2_000_000_000)]))
        self.assertEqual(len(rec['devices']), 2)
        self.assertNotIn('total', rec)
        self.assertNotIn('filesystem_id', rec['devices'][0])

    def test_semantic_validation_rejects_extra_keys_unknown_versions_bad_relations_and_sorting(self):
        good = observed()
        variants = []
        for key, value in [('schema_version', 2), ('time', float('nan')), ('requested_interval_s', True), ('extra', 1)]:
            d = copy.deepcopy(good); d[key] = value; variants.append(d)
        d = copy.deepcopy(good); d['devices'].append(copy.deepcopy(d['devices'][0])); variants.append(d)
        d = copy.deepcopy(good); d['removed_ids'] = [d['devices'][0]['id']]; variants.append(d)
        d = copy.deepcopy(good); d['devices'][0]['rates']['read_bytes_per_s'] = None; variants.append(d)
        d = copy.deepcopy(good); d['devices'][0]['interval_s'] = None; variants.append(d)
        d = copy.deepcopy(good); d['devices'][0]['counters']['read_bytes'] = True; variants.append(d)
        for variant in variants:
            self.assertFalse(model.valid(variant), variant)

    def test_snapshot_validation_rejects_duplicate_native_identity_and_untrusted_text(self):
        bad = snapshot([row(), row()])
        self.assertFalse(model.snapshot_valid(bad))
        for r in (row(name='/dev/TOKEN=do-not-print'), row(generation=True), row(count={'read_bytes': 0}), row(tick=True)):
            self.assertFalse(model.snapshot_valid(snapshot([r])))
        with self.assertRaises(ValueError):
            observed(snapshot(), bad)


class Linux(TempData):
    def make_device(self, dev='8:0', name='sda', seq='1', part=False, stat='10 0 2 0 20 0 4 0 0 0 0'):
        d = Path(self.root) / dev
        d.mkdir()
        (d / 'uevent').write_text('DEVTYPE=%s\nDEVNAME=%s\n' % ('partition' if part else 'disk', name))
        (d / 'dev').write_text(dev)
        (d / 'stat').write_text(stat)
        if seq is not None:
            (d / 'diskseq').write_text(seq)
        return d

    def test_stat_parser_fixed_sector_units_and_completed_operations(self):
        self.assertEqual(linux.parse_stat('10 99 2 8 20 99 4 8 0 100 100'), model.counters(1024, 2048, 10, 20))
        self.assertEqual(linux.parse_stat('0 ' * 17), model.counters(0, 0, 0, 0))

    def test_invalid_short_negative_boolean_and_overflow_stats_are_rejected(self):
        for text in ('1 2', '-1 ' + '0 ' * 10, 'True ' + '0 ' * 10, '0 0 ' + str(model.MAX_COUNTER) + ' ' + '0 ' * 8,
                     'x' * 4097):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                linux.parse_stat(text)

    def test_pinned_stat_reads_and_partition_exclusion(self):
        self.make_device()
        self.make_device('8:1', 'sda1', part=True)
        result = linux._row(self.root, '8:0')
        self.assertEqual(result['counters'], model.counters(1024, 2048, 10, 20))
        self.assertEqual((result['name'], result['generation']), ('/dev/sda', '1'))
        self.assertIsNone(linux._row(self.root, '8:1'))

    def test_generation_change_during_read_rejects_counters(self):
        self.make_device()
        with mock.patch.object(linux, '_sequence', side_effect=['1', '2']), self.assertRaises(ValueError):
            linux._row(self.root, '8:0')

    def test_replaced_directory_after_sampling_is_rejected(self):
        d = self.make_device()
        original = linux._read
        def read(fd, name, limit=4096):
            value = original(fd, name, limit)
            if name == 'stat':
                d.rename(Path(self.root) / 'old')
                self.make_device(seq='2')
            return value
        with mock.patch.object(linux, '_read', side_effect=read), self.assertRaises(ValueError):
            linux._row(self.root, '8:0')

    def test_missing_sequence_exposes_counters_without_continuity_claim(self):
        self.make_device(seq=None)
        r = linux._row(self.root, '8:0')
        self.assertIsNone(r['generation'])
        self.assertIsNone(r['reason'])

    def test_bad_stat_retains_device_with_null_counters(self):
        self.make_device(stat='broken')
        r = linux._row(self.root, '8:0')
        self.assertEqual(r['counters'], model.counters())
        self.assertEqual(r['reason'], 'invalid_data')

    def test_symlinked_stat_and_secret_name_are_not_followed_or_echoed(self):
        d = self.make_device()
        (d / 'stat').unlink(); (d / 'stat').symlink_to('/etc/passwd')
        r = linux._row(self.root, '8:0')
        self.assertEqual(r['counters'], model.counters())
        d = self.make_device('8:16', 'TOKEN=do-not-print')
        with self.assertRaises(ValueError):
            linux._row(self.root, '8:16')

    def test_enumeration_is_bounded_and_sorted(self):
        self.make_device('8:16', 'sdb'); self.make_device()
        with mock.patch.object(linux.os, 'readlink', return_value='mnt:[10]'), \
                mock.patch.object(linux.linux, '_read', return_value=BOOT), mock.patch.object(model.storage, 'RECORDS_MAX', 1):
            result = linux.sample(self.root)
        self.assertEqual(result['reason'], 'truncated')
        self.assertEqual(result['devices'][0]['key'], '8:0')
        self.assertTrue(model.snapshot_valid(result))


class Mac(unittest.TestCase):
    def test_driver_counters_map_once_to_whole_media_not_apfs_partitions(self):
        result = mac.parse_ioreg([driver()])
        self.assertEqual(len(result['devices']), 1)
        r = result['devices'][0]
        self.assertEqual(r['name'], '/dev/disk0')
        self.assertEqual(r['scope'], 'whole_device')
        self.assertEqual(r['counters'], model.counters(1000, 2000, 10, 20))
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('disk0s1', json.dumps(result))

    def test_ambiguous_media_preserves_driver_scope_without_guessing_disk(self):
        d = driver()
        d['IORegistryEntryChildren'].append({'IORegistryEntryID': 999, 'Whole': True, 'BSD Name': 'disk2'})
        r = mac.parse_ioreg([d])['devices'][0]
        self.assertEqual((r['name'], r['scope']), ('IOBlockStorageDriver', 'driver'))

    def test_media_replacement_on_same_driver_changes_counter_identity(self):
        a, b = driver(), driver()
        b['IORegistryEntryChildren'][0]['IORegistryEntryID'] += 100
        first = mac.parse_ioreg([a])['devices'][0]
        second = mac.parse_ioreg([b])['devices'][0]
        self.assertNotEqual(first['generation'], second['generation'])
        self.assertEqual(first['name'], second['name'])

    def test_missing_and_invalid_counters_are_unknown_not_zero(self):
        for stats, reason in (({}, 'unsupported'), ({mac.STAT_KEYS[0]: -1}, 'invalid_data'),
                              ({mac.STAT_KEYS[0]: True}, 'invalid_data')):
            r = mac.parse_ioreg([driver(stats=stats)])['devices'][0]
            self.assertEqual(r['reason'], reason)
            self.assertTrue(all(v is None for v in r['counters'].values()))

    def test_duplicate_registry_identity_is_omitted_entirely(self):
        result = mac.parse_ioreg([driver(), driver()])
        self.assertEqual(result, {'devices': [], 'reason': 'invalid_data'})

    def test_record_tree_and_registry_limits(self):
        with mock.patch.object(model.storage, 'RECORDS_MAX', 1):
            result = mac.parse_ioreg([driver(), driver(200, 'disk1')])
        self.assertEqual((len(result['devices']), result['reason']), (1, 'truncated'))
        with mock.patch.object(mac.mac, 'NODES_MAX', 1), self.assertRaises(ValueError):
            mac.parse_ioreg([driver()])

    def test_registry_metadata_has_its_own_bounded_depth_without_changing_capacity_default(self):
        deep = 1
        for _ in range(15):
            deep = {'nested': deep}
        data = [driver()]
        data[0]['extra_driver_properties'] = deep
        raw = plistlib.dumps(data)
        with self.assertRaises(ValueError):
            mac.mac._plist(raw)  # capacity metadata retains its original depth limit
        self.assertEqual(mac.mac._plist(raw, depth_max=mac.REGISTRY_DEPTH), data)
        self.assertEqual(mac.parse_ioreg(data)['devices'][0]['name'], '/dev/disk0')
        for _ in range(33):
            deep = {'nested': deep}
        data[0]['extra_driver_properties'] = deep
        with self.assertRaises(ValueError):
            mac.mac._plist(plistlib.dumps(data), depth_max=mac.REGISTRY_DEPTH)
        with self.assertRaises(ValueError):
            mac.parse_ioreg(data)

    def test_fixed_query_bounds_children_to_driver_and_media_levels(self):
        self.assertEqual(mac.IOREG, ['/usr/sbin/ioreg', '-a', '-l', '-r', '-c', 'IOBlockStorageDriver', '-d', '2'])

    def test_registry_child_inherits_owned_process_group_and_has_byte_bound(self):
        p = mock.Mock()
        p.stdout.read.return_value = plistlib.dumps([driver()])
        p.wait.return_value = 0; p.poll.return_value = 0
        with mock.patch.object(mac.subprocess, 'Popen', return_value=p) as popen:
            self.assertEqual(mac._registry(), [driver()])
        self.assertEqual(popen.call_args.args[0], mac.IOREG)
        self.assertNotIn('start_new_session', popen.call_args.kwargs)
        p.stdout.read.assert_called_once_with(mac.mac.PLIST_BYTES + 1)
        p.stdout.close.assert_called_once()


class Collection(TempData):
    def test_two_samples_wait_requested_interval_but_use_measured_elapsed(self):
        with mock.patch.object(collector, 'snapshot', side_effect=[(snapshot(), None),
                         (snapshot([row(tick=3_000_000_000)]), None)]), mock.patch.object(collector.time, 'sleep') as sleep:
            result = collector.collect('test-machine', .5)
        sleep.assert_called_once_with(.5)
        self.assertEqual(result['devices'][0]['interval_s'], 2)

    def test_first_failure_can_recover_but_second_failure_is_unknown_without_old_data(self):
        with mock.patch.object(collector, 'snapshot', side_effect=[(None, 'timeout'), (snapshot(), None)]), \
                mock.patch.object(collector.time, 'sleep'):
            result = collector.collect('test-machine')
        self.assertEqual(result['state'], 'PARTIAL')
        with mock.patch.object(collector, 'snapshot', side_effect=[(snapshot(), None), (None, 'timeout')]), \
                mock.patch.object(collector.time, 'sleep'):
            result = collector.collect('test-machine')
        self.assertEqual(result['state'], 'UNKNOWN')
        self.assertEqual(result['devices'], [])
        self.assertEqual(result['removed_ids'], [])
        self.assertTrue(model.valid(result))

    def test_argument_and_actual_platform_checks_happen_before_work_or_sleep(self):
        with mock.patch.object(collector, 'snapshot') as read, mock.patch.object(collector.time, 'sleep') as sleep:
            for interval in (True, -1, 0, .01, 31, float('nan'), float('inf'), 10**1000):
                with self.assertRaises(ValueError):
                    collector.collect('test-machine', interval)
            with mock.patch.object(collector.sys, 'platform', 'other'):
                result = collector.collect('test-machine')
            self.assertEqual(result['reason'], 'unsupported')
            read.assert_not_called(); sleep.assert_not_called()

    def test_worker_invalid_json_schema_and_failures_never_echo_raw_output(self):
        for raw in (b'not-json', b'{"x":NaN}', b'{"x":1,"x":2}', b'{"schema_version":2}', b'[' * 20 + b'0' + b']' * 20):
            with mock.patch.object(mmread, 'run_bounded', return_value=(0, raw, None)):
                self.assertEqual(collector.snapshot(), (None, 'invalid_data'))
        for error, reason in [('read command timed out', 'timeout'), ('read command exceeded 2 bytes', 'truncated')]:
            with mock.patch.object(mmread, 'run_bounded', return_value=(None, b'PRIVATE_SECRET', error)):
                self.assertEqual(collector.snapshot(), (None, reason))

    def test_real_stuck_worker_times_out_and_next_sample_can_recover(self):
        worker = Path(self.root) / 'worker.py'
        worker.write_text('import time;time.sleep(30)\n')
        started = time.monotonic()
        with mock.patch.object(collector, '__file__', str(worker)):
            self.assertEqual(collector.snapshot(.1), (None, 'timeout'))
        self.assertLess(time.monotonic() - started, 3)
        worker.write_text('print(' + repr(json.dumps(snapshot())) + ')\n')
        with mock.patch.object(collector, '__file__', str(worker)):
            doc, error = collector.snapshot(1)
        self.assertIsNone(error)
        self.assertTrue(model.snapshot_valid(doc))

    def test_cli_json_plain_no_runtime_writes_and_unavailable_exit(self):
        cli, rec = load_cli(), observed()
        before = set(Path(self.root).rglob('*'))
        for flags in ([], ['--json']):
            out = io.StringIO()
            with mock.patch.object(collector, 'collect', return_value=rec) as read, contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(['storage', 'io', '--interval', '.5', *flags]), 0)
            read.assert_called_once_with('test-machine', interval_s=.5)
            self.assertEqual(json.loads(out.getvalue()), rec) if flags else self.assertIn('storage_io=OK', out.getvalue())
        self.assertEqual(set(Path(self.root).rglob('*')), before)
        rec = model.envelope('test-machine', 1100, 1, 'timeout')
        with mock.patch.object(collector, 'collect', return_value=rec), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['storage', 'io', '--json']), 1)

    def test_cli_invalid_options_are_one_generic_error_line_without_input_echo(self):
        cli = load_cli()
        for args in (['--include', '/private'], ['--interval'], ['--interval', 'TOKEN=private'],
                     ['--interval', 'nan'], ['--interval', '-1'], ['--interval', '1', '--interval', '2']):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(['storage', 'io', *args]), 2)
            self.assertEqual(len(out.getvalue().splitlines()), 1)
            self.assertNotIn('private', out.getvalue())

    def test_importing_collectors_does_not_load_ctypes_or_run_commands(self):
        core = str(Path(__file__).resolve().parents[1] / 'core')
        code = 'import sys;sys.path.insert(0,' + repr(core) + ');import mmstorage_io,mmstorage_io_linux,mmstorage_io_darwin,mmstorage_io_collect;assert "ctypes" not in sys.modules'
        result = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(sys.platform == 'linux' and os.path.isdir('/sys/dev/block'), 'requires native Linux sysfs block counters')
class NativeLinux(unittest.TestCase):
    def test_real_sysfs_counters_and_generation_are_valid(self):
        doc = linux.sample()
        self.assertTrue(model.snapshot_valid(doc))
        self.assertTrue(doc['devices'])
        self.assertTrue(any(d['generation'] is not None and d['reason'] is None for d in doc['devices']))
        for d in doc['devices']:
            self.assertEqual(d['scope'], 'whole_device')

    def test_real_two_sample_device_rates_are_finite_and_nonnegative(self):
        rec = collector.collect('test-machine', .1)
        self.assertTrue(model.valid(rec))
        self.assertTrue(any(d['rate_reason'] is None for d in rec['devices']), rec)
        self.assertTrue(all(v >= 0 for d in rec['devices'] for v in d['rates'].values() if v is not None))


@unittest.skipUnless(sys.platform == 'darwin', 'requires native macOS IOKit counters')
class NativeMac(unittest.TestCase):
    def test_real_registry_counters_and_identity_are_valid(self):
        doc = mac.sample()
        self.assertTrue(model.snapshot_valid(doc))
        self.assertTrue(doc['devices'], 'no IOBlockStorageDriver entries')
        self.assertTrue(any(d['reason'] is None for d in doc['devices']), doc)
        # Every Mac boots from a whole disk behind a storage driver; the fixed query must prove that mapping.
        self.assertTrue(any(d['scope'] == 'whole_device' and d['name'].startswith('/dev/disk') for d in doc['devices']), doc)

    def test_real_two_sample_driver_rates_are_finite_and_nonnegative(self):
        rec = collector.collect('test-machine', .1)
        self.assertTrue(model.valid(rec))
        self.assertTrue(any(d['rate_reason'] is None for d in rec['devices']), rec)
        self.assertTrue(all(v >= 0 for d in rec['devices'] for v in d['rates'].values() if v is not None))
