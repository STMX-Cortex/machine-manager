# SPDX-License-Identifier: Apache-2.0
"""Prometheus text exposition from cached snapshots only; no readers, network, commands or writes.

Unknown and stale measurements are absent, not zero. Freshness/state series remain available for monitoring.
Metric names and label keys are fixed; outside text is masked, cleaned, bounded and escaped as label values only.
"""
import json
import math
import os
import stat

import mmcore
import mmdecide
import mmfleet
import mmprometheus_storage

STATUS_BYTES = 1 << 20
RESOURCE_BYTES = 8 << 20
DEPTH_MAX = 32
MODES = ("act", "observe", "off", "safe", "dry")


def number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def read_snapshot(path, limit):
    """Strict bounded JSON from a regular file, without following links or waiting on a FIFO."""
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out

    def constant(_):
        raise ValueError("nonfinite JSON number")

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                return None
            raw = file.read(limit + 1)
        if len(raw) > limit:
            return None
        doc = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
        stack = [(iter((doc,)), 0)]
        while stack:
            values, depth = stack[-1]
            try:
                value = next(values)
            except StopIteration:
                stack.pop()
                continue
            if isinstance(value, (dict, list)):
                if depth >= DEPTH_MAX:
                    return None
                stack.append((iter(value.values() if isinstance(value, dict) else value), depth + 1))
            elif type(value) in (int, float) and not number(value):
                return None
        return doc
    except (OSError, ValueError, RecursionError, UnicodeError):
        return None


def label(value):
    # Mask before truncating, so cutting a token cannot hide its original secret shape.
    text = mmcore.clean(mmcore.mask(value))[:120] if isinstance(value, str) else ""
    text = text.encode("utf-8", errors="replace").decode("utf-8")  # JSON may contain lone surrogates
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Metrics:
    def __init__(self):
        self.families = {}
        self.seen = set()

    @staticmethod
    def sample(name, labels, value):
        """(series key, exposition line) after masking/cleaning/escaping, or None for an unusable value."""
        if not number(value):
            return None
        name = "machine_manager_" + name
        labels = tuple(sorted((key, label(value)) for key, value in labels.items()))
        fields = ",".join('%s="%s"' % pair for pair in labels)
        return (name, labels), "%s{%s} %s" % (name, fields, str(value))

    @staticmethod
    def header(name, help_text):
        return "# HELP %s %s\n# TYPE %s gauge\n" % (name, help_text, name)

    def put(self, help_text, sample):
        key, line = sample
        if key in self.seen:
            return False  # duplicate records or identities that collide after masking/cleaning never duplicate a series
        self.seen.add(key)
        self.families.setdefault(key[0], (help_text, []))[1].append(line)
        return True

    def add(self, name, help_text, labels, value):
        sample = self.sample(name, labels, value)
        if sample is not None:
            self.put(help_text, sample)

    def text(self):
        out = []
        for name, (help_text, samples) in sorted(self.families.items()):
            out += self.header(name, help_text).splitlines() + samples
        return "\n".join(out) + "\n"


def valid_status(doc, ident):
    return isinstance(doc, dict) and doc.get("kind") == "machine" \
        and type(doc.get("schema_version")) is int and doc["schema_version"] == 1 \
        and doc.get("machine_id") == ident and doc.get("state") in mmdecide.STATES \
        and number(doc.get("time")) and doc["time"] >= 0


def fresh(timestamp, now, limit):
    return number(timestamp) and -mmfleet.FUTURE_SKEW_S <= now - timestamp < limit


def mapping(value):
    return value if isinstance(value, dict) else {}


def machine_metrics(out, ident, doc, now, limit):
    labels = {"machine_id": ident}
    valid = valid_status(doc, ident)
    is_fresh = valid and fresh(doc["time"], now, limit)
    out.add("machine_status_fresh", "Whether the machine snapshot is valid and fresh.", labels, int(is_fresh))
    if valid:
        out.add("machine_status_timestamp_seconds", "Machine snapshot source time in Unix seconds.", labels, doc["time"])
    state = doc["state"] if is_fresh else "UNKNOWN"
    for name in mmdecide.STATES:
        out.add("machine_state", "Current machine state (one hot); stale snapshots are UNKNOWN.",
                dict(labels, state=name), int(state == name))
    if not is_fresh:
        return False
    mode = doc.get("mode")
    if mode in MODES:
        for name in MODES:
            out.add("machine_mode", "Current supervisor mode (one hot).", dict(labels, mode=name), int(mode == name))

    def gauge(name, help_text, value, scale=1, percent=False):
        if number(value) and value >= 0 and (not percent or value <= 100):
            out.add(name, help_text, labels, value * scale)

    readings, facts = mapping(doc.get("readings")), mapping(doc.get("facts"))
    for key, name, help_text in (
        ("free_pct", "memory_available_ratio", "Available memory as a fraction of the effective memory limit."),
        ("cpu_pct", "cpu_busy_ratio", "CPU busy fraction over the sampler interval."),
        ("sys_pct", "cpu_system_ratio", "CPU system fraction over the sampler interval."),
        ("psi_some_pct", "memory_psi_some_ratio", "Memory PSI some avg10 fraction (Linux)."),
        ("psi_full_pct", "memory_psi_full_ratio", "Memory PSI full avg10 fraction (Linux)."),
        ("seg_pct", "compressor_segments_ratio", "Compressor segments used as a fraction of the limit (macOS)."),
    ):
        gauge(name, help_text, readings.get(key), 0.01, percent=True)
    for key, name in (("swap_used_mb", "swap_used_bytes"), ("swap_total_mb", "swap_size_bytes"),
                      ("comp_mb", "compressor_bytes")):
        gauge(name, "Memory size in bytes.", readings.get(key), 2**20)
    gauge("memory_pressure_level", "Platform memory pressure level.", readings.get("pressure"))
    gauge("load5", "Five minute system load average.", readings.get("load5"))
    gauge("memory_size_bytes", "Effective machine memory size in bytes.", facts.get("ram_mb"), 2**20)
    gauge("cpu_cores", "Machine logical CPU cores.", facts.get("cores"))
    gauge("storage_size_bytes", "Main filesystem total size in bytes.", facts.get("disk_gb_total"), 1e9)
    gauge("storage_available_bytes", "Main filesystem space available to the supervisor in bytes.", doc.get("disk_gb"), 1e9)
    for key, name, help_text in (
        ("slots", "queue_slots", "Actual queue slot count."),
        ("slots_would", "queue_slots_desired", "Controller desired slot count, including observe/dry mode."),
        ("busy", "queue_busy_slots", "Queue slots held by running work."),
        ("calls", "queue_running_calls", "Distinct queue calls holding slots."),
        ("waiting", "queue_waiting_jobs", "Jobs waiting in the queue."),
    ):
        gauge(name, help_text, doc.get(key))
    for level in ("ACTION", "ATTENTION", "INFO"):
        count = mapping(doc.get("alerts")).get(level)
        if type(count) is int and count >= 0:
            out.add("alerts_active", "Active alerts by level.", dict(labels, level=level), count)
    return True


def render(ident, status, resources, peers, now, settings, *, storage=()):
    """Pure snapshot rendering. Peer tuples are (configured id, validated cached status or None).

    Storage tuples are (machine id, validated storage snapshot or None, fresh); none means no storage series.
    """
    out = Metrics()
    out.add("snapshot_valid", "Whether the cached document has valid identity and envelope fields.",
            {"source": "status"}, int(valid_status(status, ident)))
    local_fresh = machine_metrics(out, ident, status, now, settings["other.status_fresh_s"])
    for peer, snapshot in peers:
        machine_metrics(out, peer, snapshot, now, settings["other.status_fresh_s"])
    doc = mapping(resources)
    valid = doc.get("kind") == "resources" and type(doc.get("schema_version")) is int \
        and doc["schema_version"] == 1 and doc.get("machine_id") == ident \
        and number(doc.get("time")) and doc["time"] >= 0 and isinstance(doc.get("resources"), list)
    out.add("snapshot_valid", "Whether the cached document has valid identity and envelope fields.",
            {"source": "resources"}, int(valid))
    for rec in mmdecide.cap_records(doc["resources"], doc["time"]) if valid else ():
        row = mmdecide.resource_row(dict(rec, time=doc["time"]), now, settings)
        if not row["resource"] or not row["id"]:
            continue
        # Mask full ids before resource_row truncates text, including the parent scope for duplicate runner names.
        labels = {"machine_id": ident, "resource": row["resource"], "id": rec.get("id"),
                  "parent": rec.get("parent", ""), "location": row.get("location") or ""}
        read = rec.get("read_time")
        is_fresh = row["fresh"] and fresh(doc["time"], now, settings["other.status_fresh_s"]) \
            and (read is None or (number(read) and read <= now + mmfleet.FUTURE_SKEW_S))
        out.add("resource_fresh", "Whether a resource record and its source read are fresh.", labels, int(is_fresh))
        state = row["state"] if is_fresh else "UNKNOWN"
        if state in mmdecide.STATES:
            for name in mmdecide.STATES:
                out.add("resource_state", "Resource state (one hot); stale records are UNKNOWN.",
                        dict(labels, state=name), int(state == name))
        if not is_fresh or state == "UNKNOWN":
            continue
        if row.get("unit"):
            for field in ("total", "left", "reserve"):
                out.add("resource_capacity_" + field, "Resource capacity in its native unit.",
                        dict(labels, unit=row["unit"]), row.get(field))
        for field in ("running", "queued"):
            out.add("resource_" + field, "Resource load count.", labels, row.get(field))
        for key, value in row.items():
            if key not in mmdecide.FIXED and mmdecide.VALUE_KEY.fullmatch(key):
                out.add("resource_value", "Numeric resource value in the key's documented native unit.",
                        dict(labels, key=key), int(value) if type(value) is bool else value)
    storage = list(storage)
    if storage:  # storage gets what legacy text leaves under the response target, never more than its own budget
        legacy = len(out.text().encode("utf-8"))
        if mmprometheus_storage.fits(legacy, len(storage)):  # else no storage line at all: legacy output stays whole
            mmprometheus_storage.add_all(out, storage, mmprometheus_storage.budget_for(legacy))
    return out.text(), local_fresh


def export(profile, settings, now):
    status = read_snapshot(mmcore.path("status.json"), STATUS_BYTES)
    resources = read_snapshot(mmcore.path("resources.json"), RESOURCE_BYTES)
    peers = mmfleet.cached_statuses(profile, now)
    import mmstorage_fleet  # opt-in storage export: local storage.json and peer caches, read-only
    try:
        storage = mmstorage_fleet.exported_snapshots(profile, now)
    except (OSError, ValueError, RecursionError):
        storage = ()  # an unreadable storage cache never hides the machine and resource metrics
    return render(mmcore.machine_id(profile), status, resources, peers, now, settings, storage=storage)
