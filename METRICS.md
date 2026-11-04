# Prometheus metrics export

`mm metrics` renders cached readings as Prometheus text exposition (version 0.0.4) on stdout:

```sh
python3 -I bin/mm metrics --profile profiles/example.toml --data /path/to/data
```

Use the profile and data folder for the machine to monitor. The command reads `status.json`, `resources.json`,
`storage.json` when present and, for configured peers, `fleet.json` and their `fleet-storage/` caches. It runs no
system sampler, adapter command or network request, writes no files, and starts no server or background service.
Collect peers separately with `mm collect` and let each local supervisor refresh its own status. For the separate
`mm serve` HTTP endpoint, scheduled collection, Prometheus configuration and Linux/macOS hosting templates, see
[MONITORING.md](MONITORING.md). This export does not start or install those programs. Grafana dashboards and
Prometheus alert rules are provided in [GRAFANA.md](GRAFANA.md).

Exit 0 means the local machine status is valid and fresh. Exit 3 means it is missing, invalid or stale; stdout still
contains valid health metrics and any other usable cached records. Exit 2 reports a usage/profile error.
`--json` and other command arguments are rejected; global `--profile` and `--data` remain supported.
Existing commands keep their usual output format.

## Metric contract

Every family starts with `machine_manager_`, has HELP and TYPE declarations, and is a **gauge**. Values such as
queue counts, alert counts and resource load are current snapshots, not cumulative counters. Samples have no
explicit Prometheus timestamps; source time has its own gauge. Metric names and label keys are fixed.

| Suffix | Labels besides `machine_id` | Meaning/unit |
| --- | --- | --- |
| `snapshot_valid` | `source` only (no `machine_id`) | Local status/resources document envelope and identity are valid (1/0) |
| `machine_status_fresh` | — | Valid and fresh machine snapshot (1/0), including configured peers |
| `machine_status_timestamp_seconds` | — | Source snapshot time, Unix seconds, even when stale |
| `machine_state` | `state` | One hot GREEN/STEADY/AMBER/RED/UNKNOWN; stale/missing is UNKNOWN |
| `machine_mode` | `mode` | One hot act/observe/off/safe/dry, only with a fresh known mode |
| `memory_available_ratio` | — | Available memory divided by the effective memory limit, 0..1 |
| `memory_size_bytes` | — | Effective RAM size (including detected cgroup limits) |
| `swap_used_bytes`, `swap_size_bytes`, `compressor_bytes` | — | Byte sizes; source MiB multiplied by 2^20 |
| `memory_pressure_level` | — | Platform memory pressure level; absent where unsupported |
| `memory_psi_some_ratio`, `memory_psi_full_ratio` | — | Linux memory PSI avg10, 0..1 |
| `compressor_segments_ratio` | — | macOS compressor segment use, 0..1, when exposed by the kernel |
| `cpu_busy_ratio`, `cpu_system_ratio` | — | CPU fractions over the sampler interval, 0..1 |
| `cpu_cores` | — | Logical CPU count |
| `load5` | — | Five minute system load average |
| `storage_size_bytes`, `storage_available_bytes` | — | Main filesystem capacity/available bytes; source decimal GB multiplied by 10^9 |
| `queue_slots`, `queue_slots_desired` | — | Actual slots vs controller desired slots (which may differ in observe/dry mode) |
| `queue_busy_slots`, `queue_running_calls`, `queue_waiting_jobs` | — | Held slots, distinct running calls, and waiting jobs |
| `alerts_active` | `level` | Active ACTION/ATTENTION/INFO alert count |
| `resource_fresh`, `resource_state` | Resource labels; `state` for the latter | Resource freshness and one-hot state |
| `resource_capacity_total`, `resource_capacity_left`, `resource_capacity_reserve` | Resource labels plus `unit` | Capacity in each resource's native unit (credits, minutes, slots, ...) |
| `resource_running`, `resource_queued` | Resource labels | Current resource load counts |
| `resource_value` | Resource labels plus `key` | Numeric/boolean adapter values in the key's documented native unit; booleans are 1/0 |

Resource labels are `machine_id` (the producer), `resource`, `id`, `parent` and `location`. `parent` distinguishes,
for example, equal runner names in different pools. Empty optional labels stay empty. String adapter values,
commands, reasons, paths, endpoint URLs, process ids and CPU-model text are not exported. Avoid summing capacity
across different units; these are separate resources, not interchangeable capacity.

Machine measurements for configured peers come from validated, collected status snapshots. Adapter resource
records come from the local `resources.json`; the exporter does not collect remote adapter records. The legacy
`storage_size_bytes`/`storage_available_bytes` pair still covers one main filesystem per host (`/` on Linux, the
data volume on macOS) and is unchanged; per-mount capacity and device I/O use the separate families below.

## Fleet storage families

Storage series are **opt-in**: they exist only for machines with a storage snapshot to export, that is the local
machine when `storage.json` exists (written by `mm storage record`) and each peer with `storage_url` (cached by
`mm collect` in `fleet-storage/`). Machines without either have no storage series at all, not zeros.

| Suffix | Labels | Meaning/unit |
| --- | --- | --- |
| `storage_snapshot_fresh` | `machine_id` | Valid and fresh storage snapshot (1/0) |
| `storage_snapshot_timestamp_seconds` | `machine_id` | Snapshot source time (the older of capacity and I/O), Unix seconds, even when stale |
| `storage_inventory_state` | `machine_id`, `source` (`capacity`/`io`), `state` | One hot OK/PARTIAL/UNKNOWN; stale/missing is UNKNOWN |
| `storage_export_complete` | `machine_id` | Fresh snapshots only: 1 when all its filesystem/device series fit the byte budget, 0 when all were omitted |
| `storage_filesystem_capacity_known` | Filesystem labels | 1 when all capacity values are known, else 0 |
| `storage_filesystem_size_bytes`, `_free_bytes`, `_available_bytes`, `_used_bytes` | Filesystem labels | Exact byte counts (STORAGE.md); each only when known |
| `storage_filesystem_read_only` | Filesystem labels | 1/0; absent when unknown or mixed |
| `storage_device_rates_known` | Device labels | 1 when the device rates are known, else 0 |
| `storage_device_read_bytes_per_second`, `_write_bytes_per_second`, `_read_ops_per_second`, `_write_ops_per_second` | Device labels | Rates over the collector's sample interval; each only when known |

Filesystem labels are `machine_id`, `filesystem_id` (the record id), `mount` (first sorted alias), `fs_type` and
`capacity_group` (empty when unknown). Device labels are `machine_id`, `device_id`, `device` (display name) and
`scope` (`whole_device`/`driver`). Ids are machine-local: always use them with `machine_id`. Reasons, other mount
aliases, device sizes, raw counters, categories and removed ids are not exported.

A stale, invalid or missing snapshot exports freshness 0, its source time when known and UNKNOWN inventory state,
with every filesystem and device series omitted; a failed read never revives an older snapshot. Unknown capacity
values, null read-only flags and unknown rates (first sample, reset, replaced device, bad interval) are absent; a
measured zero (idle device, zero-size filesystem) stays zero. Freshness is decided by the snapshot reader
(local: 300 s; peers: their `storage_stale_after_s`), with five seconds of future skew.

The exporter **never sums**: there is no host, capacity-group, container or device total. Volumes in one capacity
group share space, so adding their sizes double counts it; partition and disk I/O can overlap in the same way.
Each snapshot has at most 128 filesystems and 128 devices, so at most 6 x 128 + 5 x 128 + 9 = 1417 storage series
per machine; 33 machines stay below 50 000. Labels are masked, cleaned, capped at 120 characters and escaped like
the others.

**Read cost.** Each scrape reads `storage.json` and the peer caches again. A long-running `mm serve` reuses a checked
document while its file identity (device, inode, size, times) is unchanged; writers replace files atomically, so a
collection is normally checked once (concurrent scrapes can repeat it). Reuse is bounded to 64 documents and 64 MiB of
file bytes; an I/O failure is never remembered. The 2 s read limit (`READ_DEADLINE_S`) is soft: no new peer check
starts after it, but one already running finishes. Peers not reached are unavailable for that scrape (freshness 0),
never stale data, and the next scrape starts with the first of them, so every peer is reached and then reused.

**Byte budget.** Dense inventories with long labels can reach about 18-21 MiB for 33 machines, more than the 16 MiB
`mm serve` response cap and Prometheus `body_size_limit`; an oversized body would fail the whole scrape (`up=0`) and
hide every alert from that endpoint. The guarantee is: **storage never pushes the response past 15 MiB**
(`RESPONSE_TEXT_BYTES`, 1 MiB headroom under both 16 MiB caps). After the legacy families are rendered, storage gets
min(8 MiB, 15 MiB - legacy bytes), never less than zero (`STORAGE_TEXT_BYTES` is the 8 MiB ceiling). Freshness,
source time, inventory state and `storage_export_complete` are reserved first and exported for every listed machine
(at most 8 KiB each, `STATE_RESERVE_BYTES`). If even those lines would pass 15 MiB, no storage line is exported at
all and the legacy output stays whole. Filesystem and device series are then added machine by
machine in snapshot order (local first, then peers in profile order). A machine whose series would exceed the
remaining budget exports **none** of them, never part of a machine, and reports `storage_export_complete` 0; a
later, smaller machine can still fit. Rows of a machine are not ranked or truncated, so no filesystem silently
disappears from a machine that looks complete. With typical labels a full 33-machine inventory is about 12 MiB, so
expect the last machines to be omitted at that size; exclude mounts on the source or scrape those hosts directly.
`MachineManagerStorageExportIncomplete` reports it. Legacy output alone is bounded only by its existing limits:
1000 resource records with 64 values and labels near the 120-character cap are about 25 MiB, which already fails
the scrape without any storage; keep resource records and values well below those caps.

## Freshness, unknowns and limits

Unknown, unsupported, boolean-as-number, negative physical measurements, out-of-range percentages, and nonfinite
numbers are omitted. **A missing measurement is never fabricated as zero.** Real measured zeroes remain zero.
Stale machines export freshness 0, UNKNOWN state and source time when known, with their measurements omitted.
Stale/UNKNOWN resource records also omit capacity, load and numeric values. Unthresholded resources (null state)
may still export valid numeric values. Missing resources do not hide a fresh machine, and a missing local status
does not hide healthy peers. A freshness value of 1 does not imply that a machine is healthy or in action mode;
inspect state and mode as well.

Local status and resource document times use `other.status_fresh_s`. Resource source reads also obey their own
`stale_after_s`. Peers additionally obey the configured collection and source age limits. Future clock skew of at
most five seconds is tolerated. Exporting metrics never refreshes a source timestamp or collects new data.

Snapshot inputs must be regular files, with no leaf symlink or FIFO/device wait. Status is bounded to 1 MiB and
resources to 8 MiB, with at most 32 JSON container levels. Duplicate keys, malformed JSON, and nonfinite numbers
invalidate that document. Fleet caches retain the existing fleet reader bounds and validation. The resource reader
caps the list at 1000 records and values at 64 entries per record. Labels are masked before truncation, cleaned,
capped to 120 characters and escaped for Prometheus. Duplicate label sets after cleaning/masking are emitted once.
Unbounded job names, alert text and command strings do not create series. Resource identities can still change
over time; configure stable identities and retention appropriate for your fleet.

The exporter is an additional read-only view. Control decisions, service managers, guards, slot files, and the
existing CSV metrics log keep their existing behavior. Do not expose metric files publicly without deciding who
may read machine/resource identities and capacity. Real hosting and pool integration remain acceptance checks.
