# Shared storage contract

Scope 1 supplies `core/mmstorage.py`, `schemas/storage.schema.json`, acceptance fixtures and portable decision
vectors. The module is pure: it does not discover storage, run commands, read mounts, write runtime files, or add
metrics. Existing main-filesystem readings, safety thresholds, placement and supervisor behavior stay in place.
Scope 2 adds the opt-in Linux collector described below. The Mac collector, fleet collection/export and dashboards
remain separate scopes. The shared model itself stays pure.

## Devices, filesystems and allocation domains

A **device** is an OS-visible block or virtual device, not necessarily a physical drive. A VM may expose only a
virtual disk. Its `size_bytes` describes that device; a partition and its parent disk must never be added together.
`name` is display metadata, not an identity or an instruction to open a device.

A **filesystem** has one identity and one or more mounted aliases. Bind mounts of the same filesystem belong in
its sorted `mounts` list, not in duplicate capacity records. A filesystem can reference several devices, and one
device can back several filesystems. Unknown backing devices use an empty `device_ids` list; never invent a disk.
`fs_type` is a bounded platform name (for example `ext4` or `apfs`); use `unknown` when unavailable.
`read_only` is true, false or null. Use null when selected aliases have mixed or unknown write restrictions;
never infer write permission from this field. A read-only mount is still eligible for capacity monitoring.

A **capacity group** identifies a shared allocation domain, such as an APFS container or storage pool. It is an
opaque identity referenced by `capacity_group`, not a device, a third capacity sample, or an additive metric.
Different APFS volumes retain their own filesystem identities even when their group matches. Volume quotas,
reservations and snapshots can give them different capacity readings. Do not sum or arbitrarily select volume
capacities as a container total. `capacity_group: null` means the relationship is unknown, not independent storage.
There is deliberately no aggregate-capacity function. Later collectors need actual pool-level facts before any
pool or host total can be introduced. Neither disk sizes nor filesystem totals are safe to add by default.

## Identities

`storage_id(kind, basis, value)` returns `KIND:BASIS:SHA256`, using the full lowercase SHA-256 hex digest of the
ASCII bytes of compact JSON `[kind,basis,value]` (ensure_ascii=true, separators comma/colon, no whitespace).
Kinds are `device`, `filesystem` and `capacity`. The basis is part of the identity:

| Basis | Adapter input and lifetime |
| --- | --- |
| `uuid` | OS-reported device, filesystem or pool UUID, normalized to lowercase hyphenated UUID before hashing |
| `wwn` | Canonical OS-reported device WWN, with adapter-defined spelling; survives renaming when genuinely stable |
| `native` | A proven persistent platform identifier, including namespace where needed; exact canonical spelling |
| `session` | Boot identity **and** mount/device namespace **and** native identifier, with unambiguous adapter encoding |

Prefer the strongest available persistent identifier. Linux `/dev/sda`, major/minor numbers, mount IDs and Mac
`diskN` names alone are not persistent identities. Use `session` when stable identity cannot be established;
the helper cannot verify boot/namespace content, so adapters must supply it and document their encoding. UUID
inputs accept UUID spelling/case variants; other bases are not trimmed, case-folded or guessed by the helper.
The same identity basis/value survives a mount rename; a format or device replacement needs a new identity.
If stronger identity becomes available later, it may create a new series; there is no hidden migration registry.

Identities are machine-local. Consumers must use `(machine_id, id)`, never `id` alone, across machines.
Cloned UUIDs can also collide on one host: a collector must detect distinct native objects claiming one identity
and disambiguate with a documented native/session basis, or omit the ambiguous objects and mark inventory PARTIAL.
Do not silently merge clones. Duplicate identities are rejected by the validator. Hashing bounds identifiers and
avoids raw serials in IDs; it does not provide anonymity, authentication, clone detection or authorization.
Do not include credentials, raw network sources, user labels or secret-bearing mount options in identity inputs.

## Capacity and unavailable readings

`capacity(total_bytes, free_bytes, available_bytes)` returns these fields plus `used_bytes`:

| Field | Meaning |
| --- | --- |
| `total_bytes` | Filesystem-visible capacity, subject to its platform/quota semantics |
| `free_bytes` | All unallocated filesystem bytes, including reserved space |
| `available_bytes` | Bytes available to the collecting account, after platform reservations/restrictions |
| `used_bytes` | `total_bytes - free_bytes`, when both operands are known |

Counts are exact integers in bytes, between 0 and `2**63 - 1`; unknown is JSON null. Floats, booleans, negative
counters, overflow and inconsistent known values (`available > free`, `free > total`, `available > total`) are
rejected, never coerced or clamped to zero. Partial readings remain partial; the used count is never inferred
from available space. Zero capacity is valid and supplies no meaningful percentage denominator.
Adapters must report invalid/unsupported capacity as null fields with a reason, not crash discovery or reuse old
capacity under a fresh timestamp. All-null readings are distinct from real zero-byte readings.

Every filesystem has `capacity_reason`: null exactly when all capacity fields are known; otherwise one of
`unsupported`, `permission_denied`, `timeout`, `read_failed`, `invalid_data`, `truncated`.
Missing capacity preserves known filesystem metadata. Explanations are fixed codes, not raw command stderr,
mount options or network sources. Future adapters must bound commands, stdout, duration and any mount probing;
this model does not make network or unresponsive mounts safe to probe.

## Record and limits

`schemas/storage.schema.json` specifies a standalone version-1 observation. The Linux command prints it without
writing a runtime cache; no automatic supervisor writer or fleet exporter is enabled yet.
Its required envelope fields are `schema_version`, `machine_id`, `time`, `state`, `reason`, `devices`, `filesystems`.
`time` is the source observation's nonnegative finite Unix timestamp (at most `2**53 - 1`), not fleet fetch time.
Future collectors must sample each batch without refreshing timestamps on retained old readings; per-reading
cache timestamps would require an explicit contract extension before introducing such reuse.

| Inventory state | Meaning |
| --- | --- |
| `OK` | Enumeration and selection completed, possibly yielding no selected storage; envelope reason is null |
| `PARTIAL` | Enumeration is incomplete, invalid objects were omitted, or record limits were reached; fixed reason required |
| `UNKNOWN` | Inventory unavailable; fixed reason required and both arrays empty |

Envelope reasons use the same fixed codes as capacity reasons. Successful enumeration with unreadable capacity
can be `OK`, with failure represented on that filesystem. Filtering a known excluded mount is not a read failure.
Disappearance after a successful scan removes the object from that new scan; a failed scan must not masquerade
as successful disappearance or a new zero-capacity sample. Consumers must check source freshness separately;
`valid()` validates structure and relations, not current time, host authenticity or measurement accuracy.

Limits: 128 devices and 128 filesystems independently; 32 aliases per filesystem; 128 device references per
filesystem; 1024 characters per path, display name or identity input; 64 per filesystem type; 120 per machine ID.
Paths are canonical absolute POSIX strings: root `/` or slash-separated nonempty components without `.`/`..`
or a trailing slash. Spaces and ordinary Unicode names are permitted; control/format/separator/surrogate
characters and `|` are rejected in text. Do not normalize names by opening paths or following symlinks, and do
not silently rewrite rejected names into a different mount. Omit unrepresentable objects with PARTIAL/invalid_data.

Arrays of devices/filesystems sort by ID; mount and device-reference lists are sorted and unique. A selected
mount path can belong to only one filesystem record: collectors must resolve overmounted entries in the visible
namespace. All device references must resolve inside the same record. Unknown fields and newer versions are
rejected by this version's validator. Future optional fields need coordinated schema/validator updates.

Collectors must enforce discovery and input limits **before** materializing huge lists. Choose retained objects
deterministically; keep only resolvable references to retained devices, mark PARTIAL/truncated when cutting data,
and never report a complete inventory after a cut. `valid()` rejects over-limit records rather than silently
cutting them. Before decoding external JSON, readers must enforce byte/depth limits; this is not a JSON reader.
The JSON Schema describes shape; `mmstorage.valid(record)` additionally enforces finite numbers, text/path
rules, bounds, sort order, identities/references, state/reason consistency and exact capacity relationships.
The repository's small schema checker supports a subset of JSON Schema, so it alone is insufficient validation.

## Mount selection

Adapters classify filesystem mounts before probing capacity. `select_mounts(category, mounts, include, exclude)`
returns sorted unique selected aliases, using exact canonical paths. Both policy lists default to empty, each
with at most 256 entries. They are additive includes and overriding excludes, not globs, recursive roots or an
include-only mode. The Linux command exposes these helper arguments as repeated CLI options; no persistent
profile/settings keys are added.

| Category | Default selection |
| --- | --- |
| `local` | All supplied mounted aliases, including read-only volumes |
| `overlay` | Only `/`, to retain a container's visible root capacity |
| `network`, `memory`, `pseudo`, `unknown` | Excluded unless an exact path is included |

An exact exclude always wins, including `/`. An excluded alias does not exclude other aliases of the same
filesystem. Return only selected aliases in the record; combine them into one filesystem record before applying
the record cap. Selection does not grant permission to mount, unmount, change storage, open raw devices, wake
automounts, or run cleanup. Explicit network includes still require bounded collection and failure handling.
Adapters must document filesystem-type/category mappings and test virtual, temporary and disconnected mounts.

## Linux collector (scope 2)

`core/mmstorage_linux.py` implements one explicit foreground observation. Use an existing profile for machine
identity, or the test profile in an isolated checkout; the command does not require a running supervisor:

```sh
python3 -I bin/mm --profile tests/fixtures/profile-test.toml storage --json
mm storage
mm storage --include /mnt/archive --exclude /mnt/scratch --json
```

`--include PATH` and `--exclude PATH` can each repeat up to 256 times. They use the exact-path rules above;
includes add to the defaults. JSON output is the full standalone observation. Plain output starts with inventory
state/reason and device/filesystem counts, followed by one line per filesystem with byte counts and reasons.
Exit 0 means inventory OK and all selected filesystem capacities known. Exit 1 means partial/unknown inventory
or unavailable capacity. Invalid options/paths/identity return one error line and exit 2. On actual non-Linux hosts
the command returns UNKNOWN/unsupported without spawning workers, including when MM_PLATFORM forces Linux.
Detailed device records are in JSON; this is a fresh local read, unlike the cached-only `mm resources` command.
Text that would need secret masking is omitted with PARTIAL/invalid_data rather than rewriting a mount or
device name into a different identity. The active profile's text-line bounds also apply to output eligibility.

No persistent service, cache, profile/settings change, new status/fleet field or metrics is installed by this
command. It does not run in supervisor ticks, scan files for usage, mount/unmount anything, open block devices
for data, invoke `lsblk`/`blkid`/`df`, dispatch jobs, or change storage/safety decisions. It uses Python's standard
library and Linux metadata; util-linux, root privileges and a udev daemon are not required.

### Discovery and identities

- Read bounded `/proc/self/mountinfo` in the collector's mount namespace. Decode the kernel's four pathname
  escapes; keep mount IDs, device major/minor, type and read-only flags. Discard raw mount sources, options and
  stderr, so network credentials/addresses and options do not reach the observation.
- Read `/sys/dev/block` metadata for visible disks, partitions and virtual devices. Device size is the kernel's
  sector count times **512 bytes**, not the hardware's logical sector size. Partitions and their parent disks
  remain separate device records with no implicit sum. This version exposes no parent/RAID/LVM topology.
  Sysfs may expose host devices inside a container; a record does not establish that the container can use them.
- Optional `/run/udev/data/bMAJOR:MINOR` properties supply filesystem UUIDs, partition UUIDs and WWNs. No raw
  device is probed to find missing UUIDs. Missing/denied udev metadata falls back to session identities.
- A whole-device WWN gives a `wwn` device identity. A partition uses PARTUUID when available, otherwise its
  parent's reported WWN plus partition start offset (`native`). Without those facts use `session` with compact
  JSON `[boot_uuid,mount_namespace,major_minor,diskseq_or_null]`. Disk sequence counters, where available,
  distinguish replacement devices within a boot. Duplicate WWNs/PARTUUIDs fall back to distinct session IDs.
- A unique filesystem UUID gives a persistent filesystem identity. RFC UUIDs use `uuid`; FAT-style hexadecimal
  identifiers use `native` with `linux-fs-uuid:` followed by lowercase UUID text. Repeated UUIDs across discovered
  devices are ambiguous: keep separate session identities, never merge clones or guess at multi-device topology.
- Filesystem fallback `session` input is compact JSON
  `[boot_uuid,mount_namespace,major_minor,fs_type,smallest_mount_id,diskseq_or_null]`. Major/minor and type group
  mounted aliases; persistent IDs survive mount renames. Session IDs can change on remount, namespace changes,
  removing the earliest alias or device replacement; they are not a promise of persistent hardware identity.
- Missing backing-device metadata yields `device_ids: []`. This includes many container overlays and can include
  multi-device filesystems such as Btrfs. Shared allocation/pool topology remains unknown (`capacity_group: null`);
  no filesystem/device/host totals are inferred from it.

### Capacity, selection and races

Known local types include ext2/3/4, XFS, Btrfs, F2FS, FAT/exFAT, NTFS, HFS, UFS, JFS, ReiserFS, NILFS2,
SquashFS, ISO9660, UDF, Bcachefs and ZFS. Known network types include NFS, CIFS/SMB, 9p, Ceph, AFS, Coda,
GlusterFS, Lustre and their explicitly recognized FUSE variants. Tmpfs/ramfs/hugetlbfs are memory filesystems;
proc, sysfs, cgroups and other kernel interfaces are pseudo filesystems. Unrecognized types/FUSE variants are
`unknown` and require an explicit include. Overlay mounts default to `/` only, even when another bind alias is
available. Read-only local volumes remain eligible.

For each selected path a worker opens an **O_PATH** descriptor, reads its kernel `mnt_id` from fdinfo, and checks
that ID against the selected mountinfo candidates before taking capacity. An unselected overmount supplies no
capacity sample. The parent resolves candidates using the actual mount ID and device, independent of row order
or mount-ID magnitude. Hidden child paths cannot supply a covering filesystem's capacity. Unknown/replaced
mounts are omitted with PARTIAL/read_failed rather than attributed to the old filesystem.

Capacity uses `fstatvfs` on the pinned descriptor: block counts times `f_frsize`. The worker reopens the path and
checks the mount ID again before accepting that sample. These checks detect mount changes during collection;
the observation is a bounded set of source readings, not an atomic lock over the machine's entire mount table.
Bind aliases become one filesystem record. The first successful verified alias supplies its capacity; subsequent
aliases do not add or average it. Free space can legitimately change between alias probes. Mixed mount restrictions
yield `read_only: null`. Read-only is descriptive metadata, never permission to write.

Autofs mount points **and paths beneath a known autofs mount** are metadata-only even when explicitly included;
the collector does not open them to wake an automount. Their capacity stays unsupported. Selected network mounts
can still hang in a filesystem syscall; they get the same bounded-worker handling as local mounts.

### Bounds and failures

The default collection budget is **5 seconds**, including a discovery budget of at most **1.5 seconds** and
individual capacity probe budgets of at most **0.35 seconds**, limited by remaining time. Each worker runs in
the existing bounded-command runner's owned process group, with no shell/stdin, bounded stdout, suppressed
stderr and cleanup on success/failure/timeout. Timeouts send signals only to owned reader processes. Kernel
uninterruptible I/O can delay a worker's actual termination; the caller does not wait indefinitely for that I/O.
Ordinary process creation/cleanup adds small scheduling overhead to the budgets.

Discovery reads at most 1 MiB of mountinfo, 4096 rows, 32 KiB per row and 1024 sysfs directory entries, retaining
at most 128 devices. Metadata files have fixed small byte limits. Parent/worker JSON has fixed byte/depth limits.
Devices are retained in numeric major/minor order; selected paths are considered `/` first, then lexical order.
Keep at most 128 filesystem groups and 32 aliases per group, then serialize in the shared contract's ID order.
Limits produce PARTIAL/truncated; malformed omitted rows produce PARTIAL/invalid_data. An oversized/unreadable
mount table or absent boot/namespace/root identity produces UNKNOWN, never a successfully empty inventory.
Sysfs unavailability leaves mount collection partial with no invented devices. Optional UUID/WWN absence alone
does not make discovery incomplete.

Unreadable capacity retains available metadata with null byte fields and a fixed reason. A slow filesystem
does not prevent subsequent healthy paths from being sampled while budget remains. After the overall deadline,
remaining unambiguous mount metadata is retained with timeout capacity; unresolved overmount stacks are omitted.
No cached older capacity is reused. An alias failing to open or verify can make inventory PARTIAL even if another
alias supplies known capacity. These errors do not alter the machine's existing memory/disk safety state.

Fixture tests cover parsing/escaping, cloned identities, bind aliases, filters, overmounts, missing metadata,
limits and real disposable stuck-worker cleanup. Linux-native tests compare root capacity with `statvfs`, check
mount-ID changes and prove unselected mounts receive no capacity syscall. Native tests skip on Mac; the Mac
collector remains scope 3. Real hotplug/remounts, nontrivial RAID/LVM/Btrfs/ZFS layouts, disconnected network mounts,
containers with restricted proc/sys/udev, and worst-case latency still need target-machine acceptance.

## Next scopes and acceptance

1. **Scope 2 implemented:** opt-in Linux inventory/capacity command; owner target-host acceptance remains.
2. **Scope 3 next:** Mac collector with bounded discovery, APFS volume/container relationships, capacity, aliases and errors.
3. Device I/O: separately timestamped counters/rates, resets and disappearing devices; never attach whole-device
   throughput to each filesystem as if it were separate traffic.
4. Fleet/status/export: explicit compatibility, freshness, payload/label limits and metrics; preserve legacy guards.
5. Grafana views and then alerts from proven readings; optional hardware health later.

The Mac collector can use the same contract independently. Real UUID stability,
APFS accounting, containers/namespaces, disconnected mounts and sampling latency need target-machine validation
when those collectors exist. Scope-1 fixtures prove contract behavior only, not production storage discovery.

```sh
python3 -I tests/run_tests.py storage_linux storage vectors
python3 -I tests/run_vectors.py
```
