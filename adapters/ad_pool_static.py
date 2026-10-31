# SPDX-License-Identifier: Apache-2.0
"""Owner-maintained fixed capacity in any unit; no command, dispatch or automatic capacity consumption."""
import ad_pool_generic


class Pool(ad_pool_generic.Pool):
    def read(self, s, now, watch=None):
        return {"schema_version": 1, "read_time": now, "state": "GREEN",
                "capacity": {"unit": self.unit, "total": self.cfg["total"], "left": self.cfg.get("left", self.cfg["total"])},
                "load": {"running": self.cfg.get("running", 0), "queued": self.cfg.get("queued", 0)}}

    def latest(self, now):
        return self.read({}, now), None

    def snapshot(self, read, now):
        # A static value is the owner's current declared capacity, not a sampled external state that expires.
        return self.read({}, now), None
