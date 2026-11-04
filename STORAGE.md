# Shared storage contract

Scope 1 supplies `core/mmstorage.py`, `schemas/storage.schema.json`, acceptance fixtures and portable decision
vectors. The module is pure: it does not discover storage, run commands, read mounts, write runtime files, or add
metrics. Existing main-filesystem readings, safety thresholds, placement and supervisor behavior stay in place.
Scopes 2 and 3 add the opt-in Linux and Mac collectors described below. Fleet storage export (`mm storage record`,
`/storage.json`, `mm collect`) is below; dashboards and alerts are a separate scope. The shared model stays pure.

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

`schemas/storage.schema.json` specifies a standalone version-1 observation. `mm storage` prints it without writing a
runtime cache. The supervisor never writes or reads storage; only `mm storage record` writes `storage.json` (below).
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
include-only mode. The storage command exposes these helper arguments as repeated CLI options; no persistent
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
or unavailable capacity. Invalid options/paths/identity return one error line and exit 2. Actual macOS hosts use
the Mac collector below; other non-Linux platforms return UNKNOWN/unsupported. Dispatch ignores MM_PLATFORM.
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
capacity sample. The worker takes that mount's device from a fresh mountinfo row, not from `fstat`: Btrfs
reports a per-subvolume `st_dev` that differs from the mountinfo major:minor. The parent resolves candidates
using the actual mount ID and device, independent of row order or mount-ID magnitude. Hidden child paths cannot supply a covering filesystem's capacity. Unknown/replaced
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
collector is described below. Real hotplug/remounts, nontrivial RAID/LVM/Btrfs/ZFS layouts, disconnected network mounts,
containers with restricted proc/sys/udev, and worst-case latency still need target-machine acceptance.

## macOS collector (scope 3)

The same `mm storage [--include PATH] [--exclude PATH] [--json]` command now selects
`core/mmstorage_darwin.py` on actual macOS. Linux continues to use its existing collector;
no Darwin ABI or ctypes is loaded when these storage modules are imported on Linux.
Neither collector runs in supervisor ticks or writes runtime files. The shared schema,
selection policy, exit codes and exact byte arithmetic are unchanged. Plain filesystem lines
include `capacity_group`; JSON includes device records and all relationships.

### Native discovery and capacity

- A disposable worker calls Darwin's 64-bit `getfsstat64` with **MNT_NOWAIT**, copying mount
  metadata without asking all network filesystems to refresh. The fixed 2168-byte xnu
  `statfs64` layout is checked on 64-bit Python. A bounded `kern.bootsessionuuid` read supplies
  boot identity. Keep fsid, mount path, filesystem type, read-only state and a strict local
  `diskN[sN[sN]]` device identifier only. Raw mount sources, labels and options are discarded.
- Bounded read-only `/usr/sbin/diskutil list -plist` enumerates visible whole disks,
  partitions and synthetic APFS devices/volumes, including unmounted devices. These are
  separate device records with no implied sum or parent hierarchy. Device kind is `unknown`
  because this observation does not prove physical versus virtual hardware. Mounted selected
  filesystems have filesystem records; unmounted volumes have no invented mount/capacity.
- `/usr/sbin/diskutil apfs list -plist` supplies actual container/volume UUID membership
  when APFS is mounted. Optional `diskutil info -plist diskN...` queries supply missing
  mounted volume/snapshot facts. They also run for mounted APFS devices outside `apfs list`
  membership: macOS 26+ lists the sealed root snapshot with a VolumeUUID but no container,
  so a known UUID alone does not prove live-volume identity or container membership.
  Only validated device identifiers enter fixed argument
  arrays, never shell text or user labels. No raw device is opened for data.
- Each selected path gets its own worker, opening an **O_EVTONLY**, no-follow descriptor.
  `fstatfs64` supplies fsid, mount path, filesystem type, local device identity and counters.
  All identity fields must match a discovered candidate at that exact path. Reopen and
  recheck identity/read-only state before accepting capacity. Hidden/replaced paths are
  omitted with PARTIAL/read_failed rather than borrowing a covering filesystem's sample.
  Darwin's identity query itself obtains filesystem statistics; it is bounded even when
  a new overmount is discovered. It is not Linux's O_PATH identity-only precheck.
- Capacity is blocks times `f_bsize`, with total/free/account-available semantics from
  Darwin. Reject inconsistent, negative-equivalent or overflowing counters instead of
  inventing zeros. Quotas, snapshots and reservations can affect each volume differently.
  Mount aliases with the same fsid/type/device become one record; keep the first successful
  capacity, never add or average aliases. Mixed read-only flags become null.

Local types: APFS, HFS, FAT, exFAT, NTFS, CD9660, UDF, ZFS and UFS. Network types: NFS,
SMBFS/CIFS, AFPFS and WebDAV. Autofs/devfs/fdesc/volfs are pseudo; tmpfs/ramfs are memory;
unrecognized types (including unrecognized FUSE variants) are unknown. Network, pseudo,
memory and unknown mounts require explicit exact includes. Known autofs mounts and their
children remain metadata-only even when included, without opening paths or waking automounts.

### APFS and identities: no double counting

A unique OS-reported volume UUID identifies a live filesystem. A snapshot uses its own
reported snapshot UUID; it must never reuse its live volume UUID as filesystem identity.
Different volumes and snapshots remain distinct records. A proven APFS container UUID
provides their shared `capacity_group`. This includes the sealed root snapshot when its
native info reports the container. Missing membership stays null, never inferred from diskN
spelling. The group is a relationship only: this command emits **no container or host total**.
Do not sum volume capacities, free space, disk sizes, or rows with null groups. Volume quotas
and shared allocation prevent those sums from describing independent usable capacity.

Device identities prefer a unique disk/partition UUID when diskutil supplies it. Filesystem,
device and container UUID clones attached as distinct native objects are disambiguated, not
merged. Any duplicate persistent filesystem identity discovered across native fsids falls
back and marks inventory partial. Missing stable IDs use `session` with compact JSON
`[boot_uuid,"darwin-global",observation_nonce,...native_identity]`. For devices the suffix
is disk identifier; for filesystems it is `[fsid_pair,fs_type,device_or_null]` as three suffix
values; for capacity groups it is container reference. The per-observation nonce means
fallback IDs intentionally change between observations: recycled disk names or fsids cannot
claim persistent continuity. This trades series continuity for correctness when stable
metadata is unavailable. Known volume UUIDs survive mount renames. Backing device references
only resolve to a retained matching volume device; unknown physical-store topology stays unknown.

### Bounds, failures and acceptance

Default total budget: **5 seconds**, mount discovery at most **1.5 seconds**, disk/APFS
metadata commands at most **0.8 seconds each**, each capacity or optional info command at
most **0.35 seconds**, all limited by remaining time. Root is probed first, then paths in
lexical order. Capacity probes precede optional per-device info so missing UUID lookups
cannot starve root capacity. Owned process groups, stdout suppression/limits and timeout
cleanup use the existing bounded runner. Kernel uninterruptible I/O can delay worker exit;
the caller does not wait indefinitely. Scheduling and cleanup add overhead to these budgets.

Native enumeration retains at most 4096 mounts, detecting an extra row. Command stdout
is at most 2 MiB; XML plist entities/binary plists are rejected; XML container depth is
checked before decoding, with at most 16384 decoded tree nodes and depth 12. Internal
worker JSON has the existing byte/depth bounds. Retain at most 128 devices/filesystems
and 32 aliases per filesystem. Size/identity/path constraints remain those of the shared
validator. Limits yield PARTIAL/truncated. Unrepresentable or secret-shaped paths are
omitted with PARTIAL/invalid_data without rewriting their identity.

A failed mount scan gives UNKNOWN. Missing/failed diskutil metadata preserves usable mount
readings with PARTIAL and session IDs/null relationships where needed. Failed capacity
keeps discovered metadata with null bytes and a fixed reason. No cached sample gets a fresh
timestamp. Real native Mac CI checks mount ABI/root capacity, disk/APFS metadata and a fresh
observation; portable fixtures cover snapshots, clones, shared capacity, aliases, bounds,
filters and owned-worker timeout/recovery. Linux-native tests continue independently.

Target acceptance still needs actual APFS quotas/reservations/snapshots, multiple containers,
encrypted/locked volumes, disk images, removable media, UUID stability, hotplug/remount races,
permission failures and disconnected network filesystems. Check latency and worker cleanup
on the intended kernel. Read-only hosted checks do not prove these layouts or production
service integrations. Do not mount/unmount/resize/create volumes or install services merely
to run this command.

## Device I/O counters and rates (PR #9)

```sh
mm storage io --json
mm storage io --interval 1 --json
python3 -I bin/mm --profile tests/fixtures/profile-test.toml storage io --interval 0.5 --json
```

This is an explicit foreground two-sample command on Linux and Mac. `--interval` is a
finite number from **0.1 through 30 seconds**, default 1. It is the requested wait **between**
reads, not the measured denominator. Each device's rate uses its actual monotonic sample
interval, including command/sampling overhead. The supervisor never calls this command;
there is no background sampler, persistent cache, service or profile/settings change.
The capacity-only `mm storage` command and version-1 capacity schema remain unchanged.

### Separate I/O contract

`schemas/storage-io.schema.json` and `mmstorage_io.valid` define a standalone version-1
record with `kind: storage_io`, machine/source identity, observation time, inventory
state/reason, requested interval, `devices` and `removed_ids`. Use both schema and semantic
validation; the small schema checker alone does not check all bounds/relations.

Each device record has:

| Field | Meaning |
| --- | --- |
| `id`, `name` | Opaque machine-local counter identity and safe display name |
| `scope` | `whole_device` (one proven whole-device mapping) or `driver` (Mac driver without a unique media mapping) |
| `time` | Current source counter sample time; never an old sample with a new timestamp |
| `counters` | Exact unsigned cumulative `read_bytes`, `write_bytes`, `read_ops`, `write_ops`, each integer 0..2**64-1 or null |
| `counter_reason` | Null for all-known counters, otherwise a fixed unavailable reason |
| `interval_s` | Measured elapsed time between matched samples; null when unavailable/invalid |
| `rates` | `read_bytes_per_s`, `write_bytes_per_s`, `read_ops_per_s`, `write_ops_per_s`, finite nonnegative numbers or all null |
| `rate_reason` | Null exactly when all rates are known; otherwise a fixed reason below |

Rate arithmetic subtracts exact integers **before** dividing by actual elapsed seconds.
No fabricated block-size conversions, negative rates, wrap correction or zero-filled gaps.
A real idle device has known zero rates. If any counter decreases, all rates for that device
are null with `counter_reset`; current counters remain available. Any missing counter
prevents a complete rate set. The valid interval range is 0.001..60 seconds; backward,
zero, nonfinite or excessively long intervals give `interval_invalid`, not a misleading rate.
Rates describe the sampled interval; they are not instantaneous peak throughput or latency.

Other rate reasons: `baseline_missing` for new devices/failed baseline; `identity_changed`
when the same display name has a different counter identity; `unsupported` when generation
continuity cannot be proven; plus `permission_denied`, `timeout`, `read_failed`,
`invalid_data` and `truncated`. Counter reasons use the six existing storage reason codes.

Inventory `OK` means enumeration completed, even when individual rates are unavailable;
`PARTIAL` means an incomplete/invalid/limited scan or failed baseline; `UNKNOWN` means the
current scan is unavailable and both output arrays are empty. Exit **0** requires OK
inventory and all displayed rates known; **1** reports unknown/partial/unavailable results;
**2** is invalid usage/identity/interval. An all-known empty inventory is valid but does
not establish that the host exposes storage counters. JSON contains counters and rates;
plain output prints one header plus one device/rate line per row.

A successful complete current scan may report formerly seen known-generation IDs under
`removed_ids`. This means those counter identities are absent, not proof that physical
hardware was unplugged. Replaced generations can therefore remove an old ID and introduce
one at the same name. An incomplete/unreadable scan never claims disappearance. Missing
generation information also does not prove an old ID disappeared. No previous-only device
counters are retained or refreshed under the current timestamp.

### Linux source and continuity

The bounded worker scans `/sys/dev/block` and opens each sysfs **directory**, following the
kernel's device link. Metadata files are read relative to that pinned descriptor with
no-follow/nonblocking flags and small byte bounds. `uevent` and `dev` establish the native
identity/name. **Partitions are excluded**, avoiding the same traffic appearing once for
a whole disk and again for each partition. Whole devices can still be stacked (for example
LVM/device-mapper, RAID and their members); no sum across those layers is offered.

The `stat` file supplies completed reads/writes and sectors read/written. Linux sector
counters use **512 bytes per sector**, regardless of hardware logical/physical block size.
Discard, flush, merged-operation, busy-time, queue-depth and latency fields are not exported
as read/write activity. Unsupported/invalid statistics preserve device metadata with null
counters. No raw `/dev` file, mount, filesystem capacity probe or external utility is needed.

Read `diskseq` before and after counters, verify metadata, then reopen the directory and
compare inode/sequence before accepting the sample. A sequence change/replaced directory
is omitted with PARTIAL instead of borrowing its counters. Session identity hashes compact
JSON `[boot_uuid,"linux-sysfs-v1:"+mount_namespace,scope,major_minor,diskseq,null]`.
On kernels without diskseq, counters remain useful but rates are `unsupported`; a per-sample
monotonic suffix replaces the final null, so no false continuity is claimed. Session IDs
are counter-source identities, not the capacity collector's UUID/WWN hardware identities.

### Mac source and APFS scope

A bounded worker reads `kern.bootsessionuuid` and invokes fixed read-only argv
`/usr/sbin/ioreg -a -l -r -c IOBlockStorageDriver -d 2`; `-l` is needed for the child IOMedia's
`BSD Name`/`Whole` properties. Only `Bytes (Read)`, `Bytes (Write)`,
`Operations (Read)` and `Operations (Write)` from `Statistics` are used. Byte counts are
already bytes. Other registry properties, serials and user labels are discarded.

One driver is one counter source. A unique whole IOMedia with a valid registry entry ID
and `BSD Name` supplies the `/dev/diskN` display name and `whole_device` scope. Partition
and APFS-volume child nodes do **not** get copies of the parent's traffic. If a unique
mapping cannot be proven, retain `driver` scope with the name `IOBlockStorageDriver`.
Session identity hashes compact JSON `[boot_uuid,"darwin-iokit-v1",scope,driver_entry_id,
"[driver_entry_id,whole_media_entry_id_or_null]",null]`. Both driver and media entry IDs
participate, so media replacement on a surviving driver also prevents a baseline match.
These are registry counter identities within a boot, not persistent disk UUIDs or serials.
Duplicate registry identities are omitted with PARTIAL/invalid_data.

Underlying physical/virtual driver activity can include all volumes, snapshots and other
users of its device. It is not per-volume, per-process, per-job or per-filesystem I/O.
This scope does not join I/O IDs to capacity IDs or infer storage topology. It emits no
APFS/container, pool or host I/O sum. Network filesystem traffic is not attributed to local
block devices. Caching, compression, encryption and layered devices prevent simple equality
between application bytes, volume bytes and physical-device bytes.

### Timing, bounds and target acceptance

Linux timestamps each counter read at its monotonic/Unix midpoint. Mac uses the midpoint
of its bounded registry query/decode window for the driver batch. Queries/readings are
not globally atomic, and the OS may publish asynchronous statistics. Monotonic clocks are
shared across worker processes on supported Python versions; wall-clock changes cannot
become the rate denominator. Per-device timestamps/intervals remain separate from capacity.

Each sample worker has a **2-second deadline**, 2 MiB stdout limit and owned process-group
cleanup, using the existing bounded runner. The Mac `ioreg` child inherits that same group;
no nested independent command session can survive the outer cleanup. Default total time
is at most two sample budgets plus the requested wait (about 5 seconds default), with
process scheduling/cleanup overhead. Kernel uninterruptible I/O can delay actual worker
termination; the caller does not wait indefinitely. The wait is only in this explicit CLI.

Scan at most 1024 sysfs entries, retain at most 128 device records. The Mac query limits
registry children to driver/media levels. Registry XML/tree keep 2 MiB and 16384-node
bounds, with a separate depth-32 limit for nested driver properties; capacity metadata
retains its original depth-12 default. Entities and binary plists are rejected. Sysfs stat/uevent reads are at most 4096 bytes, identity files smaller.
Internal JSON is byte/depth bounded and semantically validated before pairing. Limits give
PARTIAL/truncated; fixed error codes replace raw exceptions/stderr. Arrays sort by ID and
removed IDs are unique/disjoint from current records. Imports perform no collection or
Darwin ctypes loading on Linux.

Native tests read real counters/rates without generating a benchmark workload. Target
acceptance remains for controlled known I/O, reset/wrap, hotplug/removable media, encrypted
and virtual disks, RAID/LVM/storage layers, registry permissions, older kernels without
diskseq, suspend/resume and worst-case sampling latency/cleanup. Hosted fixtures and native
API reads do not prove production integrations or exact hardware throughput. No mounts,
services, queues, safety settings or production jobs are changed for these tests.

## Fleet storage export

```sh
mm storage record [--include PATH]... [--exclude PATH]... [--interval SEC] [--json]
```

`record` takes one capacity observation (same collector, selection rules and limits as `mm storage`), then one I/O
observation (same as `mm storage io`; interval 0.1..30, default 1), and atomically writes **`storage.json`** in the
data directory, mode 0600. It is the only storage writer; schedule it on every host that exports storage (central
and peers) with [mm-storage.timer](monitoring/systemd/mm-storage.timer) or
[org.machine-manager.storage.plist](monitoring/launchd/org.machine-manager.storage.plist): every 60 s, no overlap.

```json
{"kind": "storage_snapshot", "schema_version": 1, "machine_id": "ID", "time": T, "capacity": {...}, "io": {...}}
```

`capacity` is a version-1 storage record and `io` a version-1 `storage_io` record, each passing its own validator,
with the same `machine_id` as the envelope. `time` = min(capacity.time, io.time): the older source observation, never
the write time. No other keys. `schemas/storage-snapshot.schema.json` embeds exact copies of both record schemas
(tests keep them equal); `mmstorage_fleet.valid(doc)` adds the semantic checks. Text is masked/cleaned as in
`mm storage`; a sub-record that masking would make invalid is written as UNKNOWN/`invalid_data`.

| Exit | Meaning |
| --- | --- |
| 0 | written; both inventories OK, every capacity and every rate known |
| 1 | written; some part PARTIAL, UNKNOWN or unavailable (exported as such) |
| 2 | usage error, invalid identity/selection/interval (nothing collected or written), or `E_WRITE` |

Plain output is one line: `storage_record=written path=storage.json capacity=STATE io=STATE filesystems=N devices=N`
(`devices` counts I/O devices). `--json` prints the snapshot.

**Serve.** `mm serve` answers `GET`/`HEAD /storage.json` with 200 `application/json`: the local snapshot,
re-serialized (compact ASCII JSON), when it is valid, of this profile's machine id and fresh. Otherwise 503
`storage snapshot unavailable`. Same loopback/Host/connection/limit rules as the other endpoints; serving never
collects, samples or writes. Peer caches are never served.

**Collect.** A `[[machines]]` entry may add `storage_url` (same rules as `status_url`, and **no query string**: access
control is the private transport, never a URL token) and `storage_stale_after_s` (1..3600, default 300). `mm collect`
first collects statuses and writes `fleet.json` exactly as before. Then, for peers with `storage_url` only:

1. It removes the old attempt marker `fleet-storage-attempt.json` in the data directory (an unlink needs no free
   space), then atomically writes the new one (mode 0600):
   `{"kind": "fleet_storage_attempt", "schema_version": 1, "machine_id": "CENTRAL", "time": T}`. If the unlink fails
   (other than a missing file) or the write fails, nothing is fetched and every storage peer is unavailable; without
   a marker every cached peer reads as not available. If the whole data directory becomes unwritable, so that even
   the unlink fails, earlier readings expire by their age limits, the same as `fleet.json`.
2. It creates `fleet-storage/` (0700) when missing and opens it without following links. A link or non-directory
   there is never read or written; every storage peer is then unavailable.
3. Each fetch runs in the peer worker process (`core/mmstorage_fleet.py --fetch`): HTTP read (no redirects, 8 MiB
   limit), strict JSON parse and full validation all inside the wall timeout `timeout_s`, so a huge or wide response
   costs only the worker. The worker checks source age with its clock read after the response arrives, and prints
   only the canonical validated snapshot; the collector strict-parses and validates that bounded output again with
   its own clock. Status reads keep their own 1 MiB worker, unchanged.
4. It writes `fleet-storage/<id>.json` (new random temp file, mode 0600, fsync, rename, all relative to the open
   directory):

```json
{"kind": "fleet_storage", "schema_version": 1, "machine_id": "CENTRAL", "id": "PEER", "collected_at": T,
 "snapshot": {...} or null, "error": null or "storage unavailable or invalid"}
```

A snapshot is accepted only when valid, its `machine_id` is the peer id, its source time is at most 5 s in the future
and younger than `storage_stale_after_s`, and no text would change under masking (rejected, not rewritten, so ordering
relations stay intact). Any failure writes `snapshot: null`; if even that write fails, the old entry is removed. If
removal also fails, the old entry is older than the attempt marker and so never fresh. Plain machine lines gain
`storage=OK|UNKNOWN` for peers with `storage_url`; exit 1 when any status or configured storage is unavailable.
`--json` output and `fleet.json` are unchanged. Peers without `storage_url` are not fetched, so peers on older versions
keep working.

**Freshness.** Local: fresh while -5 <= now - time < 300 s (`STORAGE_FRESH_S`). Peer: the attempt marker is valid,
`collected_at` >= its time, and collection age **and** source age are both in [-5, `storage_stale_after_s`).
`mmstorage_fleet.exported_snapshots(profile, now)` gives the exporter `(machine_id, snapshot or None, fresh)`: the
local machine first, only when `storage.json` exists (invalid or foreign: None), then each peer with `storage_url` in
profile order. A missing/invalid cache entry (including `error` not null exactly when a snapshot is present), a missing
or invalid marker, or a linked/non-directory `fleet-storage` gives None. Valid but stale snapshots are returned with
fresh false; consumers export no measurements for them. It reads files only.

**Limits.** One serialized snapshot is at most 8 MiB (`SNAPSHOT_BYTES`). If a record would exceed it, the larger
sub-record (then the other) becomes the UNKNOWN/`truncated` envelope with its source time and empty arrays. Readers
bound bytes (peer cache: 8 MiB + 4096; marker: 4096), depth 32, and reject duplicate keys, nonfinite numbers, links
and non-regular files. Serving re-checks the 8 MiB bound. One collection takes at most about 2 x 8 x `timeout_s`
(status then storage, 32 peers, 4 at a time); the collect unit allows 600 s.

**Unchanged.** The supervisor, `status.json`, `fleet.json`, `/status.json`, existing metrics (including legacy
main-filesystem `storage_size_bytes`/`storage_available_bytes`), guards, placement, settings and profile defaults.
`mm storage` and `mm storage io` still write nothing. Capacities and I/O are never summed across filesystems,
groups, devices or hosts.

## Next scopes and acceptance

1. **Scopes 2 and 3 implemented:** opt-in Linux/Mac inventory/capacity; target-host acceptance remains.
2. **Device I/O implemented:** explicit Linux/Mac counters/rates, resets and disappearing identities; target acceptance remains.
   No whole-device traffic is repeated for each filesystem.
3. **Fleet storage export implemented:** `mm storage record`, `/storage.json`, `mm collect` peer caches, freshness and
   limits (above); legacy guards unchanged. Target-host timers/agents and private-network acceptance remain.
4. Grafana views and then alerts from proven readings; optional hardware health later.

```sh
python3 -I tests/run_tests.py storage_fleet storage_io storage_darwin storage_linux storage vectors
python3 -I tests/run_vectors.py
```
