# Prometheus metrics export

`mm metrics` renders cached readings as Prometheus text exposition (version 0.0.4) on stdout:

```sh
python3 -I bin/mm metrics --profile profiles/example.toml --data /path/to/data
```

Use the profile and data folder for the machine to monitor. The command reads `status.json`, `resources.json`
and, for configured peers, `fleet.json`. It runs no system sampler, adapter command or network request, writes no
files, and starts no server or background service. Collect peers separately with `mm collect` and let each local
supervisor refresh its own status. Prometheus collection/hosting configuration and Grafana dashboards are the next
steps; this export does not install either. A plain output file can be consumed by a textfile collector later.

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
records come from the local `resources.json`; the exporter does not collect remote adapter records. Storage
currently covers one filesystem per host (`/` on Linux, the data volume on macOS). Per-mount discovery and device
I/O are separate roadmap work.

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
