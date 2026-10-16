# SPDX-License-Identifier: Apache-2.0
"""Fresh review finding: an upgrade must retain the last good owner settings.

R-1 adds two defaults, but does not retire the README Settings guarantee that a
bad owner file keeps the last good values. A 6af93dc cache lacks these new keys.
"""
import json
import os

from mmtest import TempData, base_settings, mmcore


class RedSysUpgradeReview(TempData):
    def test_bad_owner_file_after_upgrade_keeps_pre_upgrade_lastgood(self):
        # All other settings and defaults are unchanged from 6af93dc. This is
        # the flat cache that its Settings.load() wrote before the upgrade.
        legacy = base_settings(**{"slots.floor": 7, "slots.ceiling": 10})
        del legacy["slots.red_sys_needs_memory_sign"]
        del legacy["slots.red_sys_comp_growth_mb_60s"]
        mmcore.write_atomic(os.path.join(self.data, "state", "settings.lastgood.json"), json.dumps(legacy))

        # An ordinary TOML boolean typo on the first start of the new version.
        self.write_settings(**{"slots.red_sys_needs_memory_sign": "false"})
        settings = mmcore.Settings()
        loaded = settings.load()
        self.assertTrue(settings.problem, "the bad owner value must still be reported")
        self.assertIsNotNone(loaded, "the upgrade discarded a valid pre-upgrade last-good cache")
        self.assertEqual(loaded["slots.floor"], 7, "retain owner values, rather than replacing them with defaults")
        self.assertIs(loaded["slots.red_sys_needs_memory_sign"], True)
        self.assertEqual(loaded["slots.red_sys_comp_growth_mb_60s"], 256)
