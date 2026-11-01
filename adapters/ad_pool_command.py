# SPDX-License-Identifier: Apache-2.0
"""A bounded, schema-validated command supplies read-only pool state. Profile start_argv is never executed."""
import ad_pool_generic
import mmcore
import mmread


class Pool(ad_pool_generic.Pool):
    def read(self, s, now, watch=None):
        argv = [mmcore.expand(x) for x in self.cfg["read_argv"]]
        cwd = mmcore.expand(self.cfg["read_cwd"]) if self.cfg.get("read_cwd") else None
        rc, raw, error = mmread.run_bounded(argv, self.cfg.get("timeout_s", 10), self.cfg.get("max_bytes", 65536), cwd)
        if error or rc != 0:
            raise ValueError(error or "read command failed")
        return ad_pool_generic.parse_state(raw)
