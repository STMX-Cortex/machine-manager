# SPDX-License-Identifier: Apache-2.0
"""The adapter table: profile adapter names -> modules. A second project adds its module here (no plugin system)."""
import importlib

QUEUE = {"fifo-gates": ("ad_queue_fifo", "Queue")}
POOL = {"github-gh": ("ad_ci_github", "Pool")}
DELIVERY = {"claude-code-hook": ("ad_deliver_claude", "Delivery")}


def _make(table, cfg, part):
    name = (cfg or {}).get("adapter")
    if not name:
        return None
    if name not in table:
        import mmcore
        raise mmcore.MMError("E_PROFILE", "unknown %s adapter %r" % (part, name), "use one of %s" % ", ".join(sorted(table)))
    mod, cls = table[name]
    return getattr(importlib.import_module(mod), cls)(cfg)


def queue(profile):
    return _make(QUEUE, profile.get("queue"), "queue")


def pool(profile):
    return _make(POOL, profile.get("ci"), "ci")


def delivery(profile):
    return _make(DELIVERY, profile.get("delivery"), "delivery")
