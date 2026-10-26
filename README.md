# machine-manager

## What

machine-manager watches one build machine (macOS; Linux in a reduced form, see Platforms) and keeps it safe and busy:

1. It reads memory, swap, compressor, load and CPU each tick, every `schedule.tick_s` (10 s), by system calls (sysctl
   and Mach), with no fork. Free disk comes every `schedule.disk_s` (5 min, statvfs), `ps` and the queue every
   `schedule.ps_s` (30 s), and power with the minute tasks every `schedule.minute_s` (1 min; `pmset`, a child process).
   Kernel memory events come from one long-running `log stream` child. The readings are checked against the macOS
   commands at start and every `schedule.readings_check_hours` (24 h); after a `READINGS_MISMATCH`, the fallback
   sampler runs the macOS commands each tick. Each interval is a setting (Settings, Schedules).
2. It classifies the machine as `GREEN`, `STEADY`, `AMBER` or `RED`, and lowers or raises the slot count of a job queue.
3. It answers "where should this job run?" (`mm place`): this machine, a CI pool (GitHub Actions), or wait.
4. It raises one-line alerts and delivers them into one Claude Code session through hooks.
5. It deletes only safe, space-only files behind guards (off by default), and lists everything else with exact commands.

It is plain Python 3 (standard library only). The core knows no project: a **profile** (TOML) names the paths, and
three **adapters** connect a job queue, a CI pool and an alert delivery. Every decision is a pure function with
language-neutral test vectors, so the tool can be ported (PORTING.md).

Safety first: a new install runs in **observe mode**. It reads, alerts and writes `WOULD` lines; it changes nothing.

## Install

```sh
git clone <this repository> ~/machine-manager && cd ~/machine-manager
bin/mm init --profile lab1 --dir ~/mm-profiles        # a minimal profile; edit it (see profiles/example.toml)
bin/mm check --profile ~/mm-profiles/lab1.toml          # one line per problem; "check=ok" when clean
bin/mm selftest                                         # the quick test suite
bin/mm install --profile ~/mm-profiles/lab1.toml [--settings my-settings.toml]
```

`mm install` resolves each outside command the profile names (gh, the CI guard, the warm-up, the delete commands)
on your PATH, records it in `install.json`, and gives the LaunchAgents a PATH of those folders plus the system folders.
`mm check` proves each one resolves there (`E_COMMAND`); `mm check --online` also reads GitHub once with gh (`E_GH`).
`mm install` writes two LaunchAgents (`<label_prefix>`: the supervisor, kept alive; `<label_prefix>-watchdog`: every
`schedule.watchdog_s`, 60 s; a change takes effect at the next `mm install`), adds hook entries to the Claude Code settings file named in the profile (a backup first), and records the
install in `~/Library/Application Support/machine-manager/install.json`. It refuses unless `mode.observe = true`.
After its own line it prints `mm check`'s `W_SCHEDULE` timing lines (Settings, Schedules); they never stop it.

### Python upgrade

The LaunchAgents and the hooks run the Python that ran `mm install`, by its full path (`mm install` prints it as
`python=`). It must be Python 3.11 or newer; `mm check` and `mm install` refuse an older one (`E_PYTHON`). A path inside a
versioned package folder (Homebrew's `Cellar/<formula>/<version>/`) goes away at an upgrade; `mm check` warns
(`W_PYTHON`). After a Python upgrade, or when that path no longer exists:

1. `mm stop`
2. `/path/to/new/python3 -I bin/mm check --profile <profile>`
3. `/path/to/new/python3 -I bin/mm install --profile <profile>` (it rewrites the LaunchAgents and the hook entries)
4. `mm status`

An old Python fails safe: `mm` prints one `E_PYTHON` line, and the hooks exit 0 and print nothing.

Code and live data are apart. The code folder is this repository. The live data folder is
`~/Library/Application Support/machine-manager/<profile>/` (or `--data DIR`, or `MM_DATA`): `status.json`,
`resources.json`, `alerts.jsonl`, `alerts-state.json`, `metrics.csv`, `deletes.log`, `settings.toml`, `off.json`,
`state/`, `evidence/`, `pools/`, `drills/`.

## Platforms

`mm` runs on macOS in full. On Linux it loads and runs in a reduced form:

1. The memory readings (free, swap, compressor, kernel pressure, segments) are unknown. Load, CPU ticks
   (`/proc/stat`), the core count, the boot time and free disk are read. The static facts `mm resources` shows come
   from `/proc/cpuinfo` (`model name`, else `Hardware` or `Processor`) and `/proc/meminfo` (`MemTotal`); there is no
   P and E core split (none). After `self.bad_reading_ticks` ticks with
   missing readings the self-check turns safe mode on, so no automatic action runs.
2. The macOS-only parts are skipped: the kernel `log stream`, `pmset` (power unknown), the readings check
   (`schedule.readings_check_hours`) and the fallback sampler (no `READINGS_MISMATCH`), the evidence bundle's macOS
   commands (its `readings.txt` says so), the banner, the panic report names. `{user_tmp}` is the system temp folder.
3. `mm install`, `mm rollback`, `mm stop`, `mm start`, `mm restart` and `mm drill` refuse with one `E_PLATFORM` line.
   Run `mm run` in the foreground. The watchdog restarts nothing. `mm check` prints `W_PLATFORM` and skips the
   LaunchAgent checks.
4. The data folder is `$XDG_DATA_HOME/machine-manager/<profile>/`, else `~/.local/share/machine-manager/<profile>/`.
   `MM_BASE`, `MM_DATA` and `--data` still choose another.
5. Without `ps` or `lsof`, nothing is deleted, trimmed or paused.

The Linux memory readings and rules, the Linux process layer and a systemd service come in later stages.
`MM_PLATFORM=linux` (or `darwin`) replaces the detected platform. It is a test hook, like `MM_LAUNCHCTL`: the Linux path
runs on a Mac (`tests/test_platform.py`).

## Status

```sh
mm status        # at most 5 lines: state, mode, slots; readings; alert counts; why; staleness
mm alerts        # one line per active alert: LEVEL ID text | do: command (agent values cleaned and quoted)
mm explain ID    # one alert in full, with its evidence folder
mm place --kind go-test --shards 4      # place=MACHINE|POOL|WAIT, why= lines, do= lines (never run by the tool)
mm resources     # one line per resource: the machine, the pool, its runners, the usage services
```

Output is plain `key=value` lines; `--json` gives one JSON object. Errors are one line: `E_CODE what; fix: how`.

`mm resources` reads files only: the machine from status.json, every other resource from `resources.json` (the
supervisor writes it each tick from every adapter's records), plus the profile and the settings. No reading, no child
process, no network and no adapter, so a launch hook can call it before each agent launch. `--json` gives
`{"resources": [row, ...]}`. Each record follows one contract (`schemas/resource.schema.json`) and gives one row
(`mmdecide.resource_row`, with vectors), whatever the resource; a new kind of resource needs no change here.

Each row's keys, in this order: `resource id [parent] location state [unit total left reserve] [running queued]`, then
the record's own values in the writer's order, then `age_s fresh [why]`. `unit total left reserve` is the capacity in
the resource's own unit and `running queued` the load; each group shows only when the record has it. `age_s` is the age
of the resource's last read (none when never read).

`fresh=yes` when the record's `time` is younger than `other.status_fresh_s` and its last read is no older than the
writer's own limit (`stale_after_s`; none: no read rule). Otherwise `fresh=no`, `state=UNKNOWN`, and `why` starts with
the first reason: `no record time`, `record N s old` (the supervisor is gone), `bad stale_after_s`, `no read` or
`read N s old`. A state word the tool does not know shows `UNKNOWN` (`state word not known`); `state=none` means the
resource has no thresholds. Then comes the writer's own `why`. The values still show on a row that is not fresh, so read
`fresh` and `state` first; only the machine's `idle` and `idle_min` are none unless its status is fresh.

1. `resource=machine` (status.json, mapped when read): `state`, and its reasons as `why` when it is not `GREEN`;
   `unit=slots total` (the queue's slots) `left` (slots not held; below 0 when more are held) `running` (queue calls
   holding slots) `queued` (waiting calls); `cores`, `p_cores`, `e_cores`, `cpu_model`, `ram_mb` (the static facts, read
   once at the supervisor's start), `ram_avail_mb` (free % of `ram_mb`; none without the free reading), `disk_gb_total`,
   `disk_free_gb`, `cpu_pct` (all CPU busy), `idle` (the `IDLE_ROOM` rule: yes, with `idle_min`).
2. `resource=pool` (the `ci` adapter): `unit=minutes`, `total` (`github.included_minutes`), `left`, `reserve`, the
   runs `running` and `queued`, `used_usd`, `allowed_usd`; its read rule is `github.stale_minutes`.
3. `resource=runner` (`parent=` the pool), with the profile's `ci.runner_labels`: `GREEN` online and idle, `STEADY`
   online and busy, `RED` offline, else `UNKNOWN`; `online`, `busy`. When the runner list cannot be read, one row
   `id=runners state=UNKNOWN why="..."`; that never changes the pool's state or its alerts.
4. `resource=service` (`claude`, `codex`; the `delivery` adapter, when the profile names `delivery.usage_state`):
   `used_5h_pct`, `reset_5h`, `used_week_pct`, `reset_week` (epoch seconds); its read rule is the state file's own
   `max_age_seconds`, else `usage.watch_state_max_age_s`. A value the usage rules reject is none, and `why` names the
   reason. `state` is `UNKNOWN` when no value is known, else none. A window the plan does not offer is left out.

A `resources.json` whose `schema_version` is not 1 gives one `resource=file` row (`UNKNOWN`); more than 1000 records
give the first 999 and one `resource=file` row that counts the rest. Plain floats show exactly (`used_usd=0.04`).
`mm resources` ignores a status.json or resources.json with more than 128 object or array levels, including the root.
Outside text (runner names and the like) shows cleaned and quoted as in "Agent-written files", item 6. Exit 0 when the
machine status is fresh, 3 when status.json is missing or not fresh (the rows are still printed), 2 on a usage error. A
supervisor that runs code older than `resources.json` writes none: until it restarts, only the machine row shows.

## Stop

```sh
mm off --reason "maintenance"   # every automatic action off (slot writes, deletes, gate, pause); readings and alerts go on
mm on
mm stop                          # unloads the watchdog, then the supervisor; one STOPPED alert says so
mm start
mm restart [--clear-safe]        # stop, start, wait for a fresh heartbeat: restart=ok pid=N, or one E_RESTART line
```

## Self-recovery

The tool restarts itself, guards against a restart loop, and never leaves a process stopped. Every limit is a
setting (`[self]`, `[safe_mode]`, `[heartbeat]`); every decision is a pure function with vectors (PORTING.md).

1. **Self-check, each tick** (`self_check`). A fault of the tool itself gives a restart: its own memory over
   `self.max_rss_mb`, `self.slow_ticks` ticks over `self.max_tick_s`, or `self.bad_reading_ticks` failed ticks. It logs
   one line, holds a `SELF_RESTART` alert and exits with code 75; launchd starts it again. A fault a restart cannot fix
   gives safe mode: wrong readings for `self.bad_reading_ticks` ticks, a data folder that is not writable or has less
   than `self.min_free_mb` free, or more than `self.max_slot_changes_per_hour` slot changes in an hour.
2. **Crash-loop guard** (`crash_loop`). A start after a run that did not end by itself (a crash, a kill, a self
   restart) is unclean. At `self.crash_loop_starts` unclean starts in `self.crash_loop_minutes`, safe mode.
3. **Safe mode** (`safe.json`). Automatic actions are off: no slot raise, no delete, no trim, no pause, the launch gate
   open. The slot count is lowered once to at most `safe_mode.slots` (a WOULD line in observe mode); it may still go
   down after that. Readings, alerts and hooks go on. An ACTION alert `SAFE_MODE` names the reason. In safe mode the
   self-check never exits (it raises `SELF_CHECK`). Only `mm on` or `mm restart --clear-safe` ends it.
4. **Paused processes** (`resume_targets`). The pause writes each pid and its start time to `state/paused.json`
   before its SIGSTOP. Every start, safe mode, turning `pause_newest_call.enabled` off, `mm stop`, `mm rollback` and
   the watchdog (when the supervisor is stale over `self.resume_paused_after_s`) send SIGCONT to each recorded pid
   whose start time still matches. A paused call also continues after a long calm (GREEN or STEADY), and after
   `pause_newest_call.max_minutes` paused (default 0 = no limit). From that time it needs `slots.sustain_samples`
   clear ticks in a row: every memory reading present (free, swap used and total, compressor, kernel pressure,
   compressor segments) in this tick and every sample of the last 60 s used for growth, and no critical reason,
   kernel memorystatus event, growing swap near its total or compressor segments over their limit. The calm span
   needs the same complete memory window. Any other tick starts the relevant count or span again; ticks before
   the cap time, including after a cap change, drop the cap count. A failed start-time read keeps the process record
   for retry and sends no signal to that pid. It writes a `RESUME` line with the reason, and each capped pause raises
   its own `PAUSE_MAX` naming the call (or saying the call was gone). If a call continued but its updated record could
   not be written, the alert says both.
5. **The watchdog is watched.** Each watchdog run writes `state/watchdog.stamp`; at `self.watchdog_stale_s` the
   supervisor raises `WATCHDOG_STALE` and restarts the watchdog (installed runs only, once per 10 min).
6. **Mac reboot** (`reboot_check`). At start, a changed `kern.boottime` gives `MAC_REBOOTED`: the uptime, how long the
   tool was down, the state and slots before, new kernel panic report names (names only), and the profile's
   `recovery.expected_jobs` that are not running. Details: `state/reboot-<time>.json`.
7. **Dead-man ping** (off by default). With `heartbeat.url` set, a GET every `heartbeat.every_min` minutes; the log
   names only the host. No network unless the owner sets it.

The tool never reboots the Mac, never deletes in safe mode, and never signals a process except the pause's own
SIGSTOP and SIGCONT.

## Roll back

```sh
mm rollback      # unloads and removes both LaunchAgents and the hook entries (backups first); prints by-hand steps
```

The data folder stays: its alerts and logs are the record. To return to the state before install, restore the
`.bak-before-machine-manager-<time>` copies it names.

## Profile

A TOML file the tool reads and never writes. Only `name` is required; a section left out turns its part off.
`profiles/example.toml` shows every section with made-up paths. Sections: `names` (words in alert texts;
`disk_command`, default none, is the command `DISK_LOW` and `CLEANUP_LIST` name; without it `CLEANUP_LIST` names
`mm cleanup`), `service` (`label_prefix`, default
`com.example.machine-manager`; `rollback_notes`; `path_extra`, folders for the service PATH), `sizes`, `live_tools` (process names of a live build), `memory_guard`
(an external guard's heartbeat), `queue` (adapter `fifo-gates`), `kinds` (machine-only and pool job kinds), `ci`
(adapter `github-gh`, read-only; `runner_labels`, optional: `mm resources` lists the self-hosted runners that carry
every one of these labels, as `runs-on` matches; the list needs admin access to the repository, and a failed read
shows only as the `UNKNOWN` runner record `id=runners`, never a read error or an alert), `delivery` (adapter `claude-code-hook`), `trim` (the guarded cache trim), `deletes`
(`rules`, `cleanup`, `forbidden_parts`, `protected_roots`), `recovery` (`expected_jobs`: `{name, match}` regular
expressions over process command lines, checked after a Mac reboot), `text_line_max` (default 4096, from 256 to
1048576: the longest line any pattern sees, "Agent-written files", item 7). Placeholders: `{data}`, `{user_tmp}`,
`{claude_tmp}`, `~`. The schema is `schemas/profile.schema.json`.

Clean-up list rule types (`deletes.cleanup`) are `git_worktrees`, `git_branches`, `stale_children` and `paths`.
A `git_worktrees` rule may set `keep = ["journal-*"]`: case-sensitive `fnmatch` patterns on each tree folder's
base name. The first matching pattern gives a KEEP item with reason `kept by the profile (keep: <pattern>)`,
no command and no inner cache candidates. An empty list, or no `keep`, preserves the usual merged-and-clean rule.

## Settings

Thresholds and switches live in `settings.default.toml` (every key with its unit). A data folder's `settings.toml`
overrides only the keys it names; an unknown key or a bad value is a problem (`SETTINGS_BAD`), and the last good
values stay in force. The public defaults are safe: `mode.observe = true`, `mode.slot_writes = "off"`,
`deletes.enabled = false`, `launch_gate.enabled = false`, `pause_newest_call.enabled = false`, `banner.enabled = false`.

`mm settings show [KEY|SECTION]` prints the settings in force, one line per key in `settings.default.toml`'s order:
`key=value default=value differs=yes|no`. A bool shows as `true` or `false`; a text setting (`mode.slots_file`,
`heartbeat.url`) is always JSON-quoted, masked and cleaned, and `heartbeat.url` shows only as `<scheme>://<host>/...`;
a choice (`mode.slot_writes`) shows as its bare word; values are as written (`slots.cores=0`, not the core count). A section name shows its keys. It only reads: no file is written and no supervisor is needed. When
`settings.toml` is bad, the first line is its `SETTINGS_BAD` alert line, the values shown are the ones in force (the
last good values, else the defaults), and the exit code is 1. `--json` gives one object, its keys sorted:
`{"in_force": "current"|"last_good"|"none", "problem", "settings": {key: {"value", "default", "differs"}}}`. An
unknown key or section is one `E_USAGE` line (exit 2).

`deletes.cleanup_list_hours` controls how often the clean-up list is refreshed (default 24 h).
`deletes.cleanup_attention_gb` makes `CLEANUP_LIST` ATTENTION when candidate bytes reach that many GB
(10^9 bytes; default 10, range 0-10000, 0 = off; authority: the owner). Unknown sizes count as zero.
The low-disk warning below `disk.cache_action_disk_gb` still applies independently. When only list size triggers
the warning, its text ends with `; list over <N> GB`.

System CPU above `slots.red_sys_pct` for `slots.sustain_samples` (defaults 40% and 2 samples) needs a current memory
sign for RED: kernel pressure at least 2, any swap growth in the last 60 s, or compressor growth in the last 60 s
above `slots.red_sys_comp_growth_mb_60s` (default 256 MB). Without a sign, this rule gives AMBER with a
`no memory sign` reason. The owner can set `slots.red_sys_needs_memory_sign = false` in the data folder's
`settings.toml` to restore system CPU alone giving RED. Other RED rules still apply independently.
A compressor over `slots.red_comp_mb` (default 0 = off; range 0-100000 MB) is RED `compressor at N MB (near its
ceiling)`, a critical reason (it pauses the newest call).

status.json older than `other.heartbeat_max_age_s` (default 90 s) is stale: `mm status` says `E_STALE` (it uses 90 s
when it cannot read the settings), the hook says `SELF_STALE`. `mm place` and the launch gate use status.json's state
only while it is younger than `other.status_fresh_s` (default 60 s, range 15-3600); else `mm place` takes one sample
and the gate stays open. `mm drill` keeps its own stricter 30 s, and refuses while `schedule.tick_s` is over 20 s.

GREEN needs load1 strictly below `slots.green_load1_per_core` times the core count (default 0.8, range 0.1-4), as well
as the load5 band. A slot raise needs `slots.raise_green_minutes` of GREEN while enough calls wait and all slots stay
busy. GREEN also needs free disk of at least `slots.green_disk_gb` (default 0 = follow `disk.recover_gb`; else at
least `slots.red_disk_gb`). `queue.slot_cpu_cores` is the CPU cap per held slot: each call's process tree is counted
once, with one alert per call after two readings over its cap.

### Schedules

Every timing in the tool. The supervisor runs one tick every `schedule.tick_s`; each other job runs on the first tick
at or after its interval, so an interval rounds up to whole ticks (at `tick_s` 7, `ps_s` 30 runs every 35 s). Every
span checked once per tick rounds up the same way (`slots.amber_step_interval_s`,
`pause_newest_call.resume_after_green_s`, `slots.raise_green_minutes`, the alert repeats). A changed `settings.toml`
counts from the next tick, the tick's own length from the next wait; no restart is needed, except for
`schedule.watchdog_s`, which takes effect at `mm install`.

| What runs | Setting | Default | Notes |
| --- | --- | --- | --- |
| The tick: memory, swap, compressor, load and CPU readings, the state, the slot controller, the alerts, the pause, the trim's step, the usage state, `status.json`, `resources.json`, the pool's status file, the self-check | `schedule.tick_s` | 10 s | Range 5-30 s (at least 3 samples in the 60 s growth window). Read before each wait. `mm run --tick-seconds N` overrides it (tests; the LaunchAgent does not pass it). |
| Free disk (statvfs) and its trend | `schedule.disk_s` | 300 s | Range 60-600 s. `DISK_LOW` and the RED disk reason wait for it. |
| `ps` and the queue read | `schedule.ps_s` | 30 s | Range 10-60 s. Feeds the slot controller, the pause's newest call, `IDLE_ROOM`, `SLOT_CPU` (two reads over the cap: 2 x `ps_s`) and the trim's drained test (`trim.drained_minutes` rests on these reads). |
| The minute tasks: the queue's history, the memory guard's kills, `mm event` events, power (`pmset`), source ages (`SOURCE_STALE`), the recipient's open tool call, the listed jobs | `schedule.minute_s` | 60 s | Range 10-300 s. |
| A `metrics.csv` row, and `state/counts.json` saved with it | `schedule.metrics_s` | 60 s | Range 10-600 s. An evidence bundle copies the rows of its `evidence.window_minutes`. |
| The readings check: the fast readings against the macOS commands (`READINGS_MISMATCH`) | `schedule.readings_check_hours` | 24 h | Range 1-168 h. Also at each start. macOS only. |
| The watchdog (`mm watchdog`: `SELF_STALE`, the supervisor's restart, the resume of paused calls) | `schedule.watchdog_s` | 60 s | Range 10-600 s, whole seconds: the LaunchAgent's `StartInterval`, written by `mm install`. `mm check` warns when the installed one differs. |
| Folder sizes (`du` of the profile's `[sizes]`) and the `CACHE_5M` share | `disk.sizes_interval_minutes` | 30 min | In a worker thread. |
| The pool read (gh) | `github.read_interval_s` | 600 s | In a worker thread. Its read rule is `github.stale_minutes` (30 min). |
| The watched runs (`mm watch`) | `github.watch_interval_s` | 120 s | Only while a watch is pending. |
| The deletes pass (`WOULD-DELETE` unless deletes are on) | `deletes.interval_minutes` | 180 min | In a worker thread. |
| The cleanup list | `deletes.cleanup_list_hours` | 24 h | With a deletes pass; at most hourly while free disk is under `disk.cache_action_disk_gb`. |
| The dead-man ping | `heartbeat.every_min` | 5 min | Only with `heartbeat.url`. |
| The hook's `INFO WAITER` line (no waiter is live) | `hook.remind_waiter_minutes` | 60 min | Per session. |
| An active alert repeats | `repeat.action_minutes`, `repeat.attention_hours` | 30 min, 3 h | It clears after `repeat.clear_after_minutes` (5 min) absent. |
| The hook | fixed | each event | On each Claude Code event it is entered for (`SessionStart`, `UserPromptSubmit`, `PostToolUse`, `PreToolUse`); 2 s limit. |
| The kernel `log stream` restart | fixed | 60 s | At most once per 60 s (macOS). Kernel events count 30 min for the alert, 2 min for RED. |
| The supervisor's restart of a stale watchdog | fixed | 10 min | At most once per 10 min (installed runs only). |
| `WOULD-PAUSE` and unreadable-slots decision lines; `WOULD-TRIM` | fixed | 10 min; 1 h | At most once per span. |
| The growth windows | fixed | 60 s; 30 min; 6 h | Swap and compressor growth, the memory sign and the pause's readings: 60 s. The swap base: 30 min (samples kept 1900 s). The disk trend: 6 h, from readings at least 30 min apart. |
| The queue sampler's system CPU | fixed | 150 s | Used while its last line is under 150 s old. |
| launchd | fixed | 10 s; 20 s | `ThrottleInterval` (the supervisor's restart) and `ExitTimeOut` (from SIGTERM to the kill). |
| `mm drill memory` | fixed | 30 s; 25 s; 60 s | It trusts status.json up to 30 s old (and refuses while `schedule.tick_s` is over 20 s); 25 s per step; 60 s after its stop. |
| `mm wait`, `mm restart` | fixed | 5 s; 0.25 s | `mm wait --poll` (5 s); `mm restart` polls every 0.25 s within `self.restart_wait_s`. |
| Staleness without settings | fixed | 90 s | `mm status` and the hook use 90 s when they cannot read `other.heartbeat_max_age_s`. |

Counts of ticks, not seconds, so their time scales with `schedule.tick_s`: `self.slow_ticks`, `self.bad_reading_ticks`
(6 ticks: 1 min at 10 s, 3 min at 30 s), the pause cap's `slots.sustain_samples` clear ticks, `SUPERVISOR_ERROR` after
3 failed ticks in a row, and the ticks per state in `state/counts.json`.

`mm check` prints one `W_SCHEDULE <what>; fix: <how>` line for each timing that does not fit
(`mmdecide.timing_warnings`, with vectors). It is a warning like `W_PYTHON`: it never fails the check (with no
problem, `check=ok` follows and the exit code is 0), it is never `SETTINGS_BAD`, and it never stops the last good
values. The defaults give none. It reads the settings, not a `--tick-seconds` override. G is the longest status.json
gap of a working supervisor: max(`schedule.tick_s`, `self.max_tick_s`) + `self.max_tick_s`, and at least 1.5 x
`schedule.tick_s` (60 s at the defaults; a tick writes status.json with the time of its start, and the next one starts
after the wait or after a long tick). The checks, in order:

1. `other.heartbeat_max_age_s` under G: a working supervisor reads as stale (`E_STALE`, `SELF_STALE`, a restart).
2. `other.status_fresh_s` under 1.5 x `schedule.tick_s`: `mm place` and the launch gate find status.json old between
   two ticks. Only 1.5 x the tick on purpose: both fail open.
3. With the services (macOS): `self.resume_paused_after_s` under G: the watchdog continues calls a working
   supervisor paused.
4. With the services: `schedule.watchdog_s` over `self.resume_paused_after_s`: a paused call can stay stopped up to
   their sum after the supervisor's last status. The fix names whole seconds (`schedule.watchdog_s` is an int).
5. With the services: `self.watchdog_stale_s` under 1.5 x `schedule.watchdog_s`: `WATCHDOG_STALE` for a watchdog that
   runs on time.
6. With a CI pool: `github.stale_minutes` under 1.5 x `github.read_interval_s`: the pool reads as stale between reads.
   Over 57600 s no `github.stale_minutes` fits (its maximum is 1440), so the fix lowers `github.read_interval_s`.
7. `schedule.ps_s`, `schedule.minute_s` or `schedule.metrics_s` under `schedule.tick_s`: it runs once per tick only.
8. `schedule.metrics_s` over `evidence.window_minutes`: an evidence bundle can hold no metrics row.

On macOS it also says when the installed watchdog's `StartInterval` is not `schedule.watchdog_s` (`mm install` again,
with `mode.observe = true`).

## Agent-written files

Agents may write their own git worktrees (each tree's `.git` file too), the queue's slot and ticket files, and their own
cache folders. Nothing they write there makes the tool run a program, signal a process or delete outside the place the
profile names:

1. **Git.** The cleanup list takes worktrees from the main repository's `git worktree list` (only trees under the
   profile's roots are candidates). It runs git in a tree only when the tree's `.git` is a regular file reading exactly
   `gitdir: <its listed git folder>` (absolute), and then names that folder on git's command line, so git never reads it
   from the tree. Every git call carries `--no-optional-locks -c core.fsmonitor=false -c core.hooksPath=/dev/null`
   and `-c attr.tree=<the empty tree>` (git 2.42 or newer; no filter driver runs on the tree's files), and the status
   skips submodules. Any other tree is a KEEP item with its reason and no command.
2. **The pause.** The slot path must be a regular file (lstat) before lsof runs on it. The pids come from the processes
   that have the newest call's slot file open with write access (lsof, with the time limit
   `pause_newest_call.lsof_timeout_s`), never from its label text; a read-only opener (a waiter's scan) is never paused
   and never named. Each one whose argument list runs the queue's launcher (profile `queue.launcher`, named by its
   absolute path, or by a path relative to that process's working folder; real paths compared) is paused with its
   process tree, as the process list shows it just before the signals (read afresh, never an older reading). Any other
   process is never paused: `PAUSE_REFUSED` names the slot file and its pid. A held slot with no write opener (a
   read-only lock, whose holder lsof cannot show) pauses nothing: `PAUSE_REFUSED` names the slot. A waiter that tries
   a slot has it open read-write for a moment (an accepted limit).
3. **Slot and ticket files.** The queue read and the evidence bundle open each slot and ticket file without following a
   link and without waiting, require a regular file and read at most 4096 bytes. An error costs only that file. A link,
   a FIFO, a socket or any other kind there counts as not held, is never paused through, and raises `SLOT_NOT_A_FILE`
   naming the path. A regular file that cannot be opened or read (mode 000) counts as not held and raises one
   `QUEUE_FILE_UNREADABLE` alert, however many there are: the count and the first 5 paths. Waiting calls raise one
   `QWAIT` alert (the count and the oldest call), never one per ticket.
4. **Links.** Deletes and prunes (`cache_entries`, `command_per_dir`, the cleanup list's commands) check every
   component of the configured folder's path, and of each entry below it, with lstat. A link owned by root (`/tmp`,
   `/var`) is allowed; any other link, or a real path outside the folder, refuses: a KEEP line in `deletes.log` (a KEEP
   item with no command in the cleanup list) and `LINK_SKIPPED` naming the path. Cache entries are deleted through
   folder descriptors opened without following a link, so a folder swapped for a link after the find is never entered.
5. **Markers and failures.** A cache's marker file is opened the same way (no link, no wait, a regular file only, at most
   4096 bytes, invalid UTF-8 replaced): a link, a FIFO or a folder there is no marker. One delete rule that fails never
   stops the others or the cleanup list: its KEEP line in `deletes.log` (`rule=<id>`) and `DELETES_FAILED` name the
   rule and the error. A cleanup list that fails stops no rule: its KEEP line in `deletes.log` (`rule=cleanup_list`)
   and `DELETES_FAILED` name it. A failure of the whole pass (`deletes_job`) means no rule or list result that time:
   `DELETES_FAILED` names `deletes_job` and the error. The cleanup list's alerts (`CLEANUP_LIST`, its `LINK_SKIPPED`
   paths, `DELETES_FAILED` for `cleanup_list`) keep their state until the list runs again
   (`deletes.cleanup_list_hours`), not only until the next deletes pass.
6. **Outputs.** File, folder and ticket names, call labels, paths below agent folders and text read from such files
   reach alert keys and texts, `mm cleanup` and `mm place`. In every output (alert lines, the hook, `mm wait`,
   `mm alerts`, `mm status`, `mm explain`, `mm ack`, `mm cleanup`, `mm place`, `mm resources`, each `--json` form) such
   a value shows cleaned: each control, format or line-separator character (Unicode Cc, Cf, Zl, Zp) and each `|`
   shows as `?` (`core/mmtext.py`). A plain `key=value` value, an alert id in a line, and such a value inside an alert's text are
   JSON-quoted unless every character is a letter, a digit or one of `._/:@+,~-`. ` | do: ` comes only with the
   alert's own command. A command that would name a value cleaning changes, or that holds a control character, is
   withheld: a line shows `mm explain KEY` (the id shell-quoted when it needs it), `mm explain` shows
   `command=withheld`, `mm cleanup` shows `do=withheld`, and `mm place` gives no commands. Such a value is masked
   before it is quoted, and a text is masked part by part, so a mask never takes a closing quote; a command the mask
   changes is withheld too. The same cleaning holds in every file the tool writes that a person or a tool reads: its
   own logs (`decisions.log`, `errors.log`, `deletes.log`, `events.jsonl`, `alerts.jsonl` and the others: one record
   per line), the evidence bundle (each copied log cleaned line by line, a tab kept only in the tab-separated
   `history.log` and `load.log`; every JSON file with cleaned strings; process names quoted in `ps.txt`) and the
   banner. State files only the tool reads (`alerts-state.json`, `controller.json`, cursor files) may keep raw values;
   every value shown from them is cleaned.
7. **Patterns.** Every regular expression the tool runs over text an agent can make (the mask, the log, ps and
   kernel-line parsers, the profile's patterns over labels, commands, process names and branch names) sees that text
   split at its line feeds, each line cut to the profile's `text_line_max` characters, its end marked `[...cut]`. A URL
   password may hold `/` and `:`; it ends at its `@`, never past the next `://`. A record ends only at a line feed: a
   LINE SEPARATOR, NEL or CR inside a name stays inside its record. A cut never opens a gate: where a pattern decides
   a refusal or a guard, a line too long to see whole counts as a match (the launch gate's `launch_bash_regex`: a
   launch while the machine is RED; `live_tools.path_regexes`: a live run, so a delete or trim waits). Patterns that
   only show, sort or mask text use the cut line. In a kernel suspend line the process name runs to the last
   ` [<pid>] due to `.

## Glossary

States: `GREEN` fine; `STEADY` busy but stable (no raise); `AMBER` slots down one step; `RED` slots to the floor;
`UNKNOWN` no fresh status. Levels: `INFO` (not pushed), `ATTENTION`, `ACTION`. An alert id is its name, plus `:part`
when one name has several alerts. Modes: `act`, `observe` (WOULD lines only), `off` (the off switch), `safe` (safe
mode), `dry` (a test run).

Alerts:
`MEM_RED`, `MEM_AMBER` memory state; `KERNEL_SUSPEND` the kernel suspended a process; `GUARD_KILL` the memory guard
ended a process; `GUARD_DOWN` the memory guard is not alive; `DISK_LOW`, `DISK_TREND` free disk; `CACHE_BIG` the build
cache is large; `TRIM_NEEDED` a trim waits for a drained queue; `TRIM_DONE`, `TRIM_REFUSED` the trim's end;
`CLEANUP_LIST` candidates for a person; `CODEX95`, `CODEX98`, `CLAUDE98`, `CLAUDE_PROJ`, `FIVE_H` plan usage;
`CACHE_5M` short prompt-cache writes; `QWAIT` queue calls wait long (one alert: the count and the oldest);
`HEAD_BLOCK` an exclusive call blocks the queue; `PAUSE_REFUSED` the newest call's slot file is held by a process
that is not the queue's launcher, or by a read-only lock; `PAUSE_MAX` a paused call continued (or was gone) after
`pause_newest_call.max_minutes`, one alert for each capped pause;
`SLOT_NOT_A_FILE` a queue slot or ticket path is not a regular file; `LINK_SKIPPED` a delete or prune path goes through
a link; `DELETES_FAILED` a delete rule, the cleanup list or the whole deletes pass failed; `QUEUE_FILE_UNREADABLE`
queue slot or ticket files cannot be opened or read;
`LONG_CALL` a call runs long; `REFUSED` the queue refused a call; `SLOT_CPU` a slot uses much CPU; `IDLE_ROOM` the
queue is idle; `FSEV` the file-event daemon is large; `POWER` on battery; `RESUMED` the machine slept;
`RECIPIENT_WAIT` the recipient waits on one tool call; `JOB_DEAD` a listed job died without a result;
`SOURCE_STALE` a reading source is old; `READINGS_MISMATCH` fast readings disagree with the macOS commands;
`OFF` the off switch is on; `SETTINGS_BAD` the settings file is invalid; `SUPERVISOR_ERROR` ticks fail;
`SELF_STALE` the supervisor is not writing; `SELF_RESTART` the tool restarted itself; `SAFE_MODE` safe mode is on;
`SELF_CHECK` a self-check fault in safe mode; `WATCHDOG_STALE` the watchdog does not run; `MAC_REBOOTED` the Mac
restarted; `STOPPED` stopped by hand; `GH_FAIL`, `GH_STUCK`, `GH_DONE`, `GH_PACE`
the CI pool; `GUARD_NEAR`, `GUARD_STOP` the CI budget.

Exit codes: 0 ok; 1 nothing found or problems listed; 2 error (one `E_` line); 3 stale; 10 `POOL`; 20 `WAIT`;
75 the supervisor restarts itself (`mm run` only).
Error codes: `E_PYTHON`, `E_RESTART`, `E_USAGE`, `E_RANGE`, `E_EXISTS`, `E_PROFILE`, `E_NO_PROFILE`, `E_SETTINGS`, `E_HOOKS`, `E_READINGS`,
`E_RECIPIENT`, `E_STALE`, `E_NO_STATUS`, `E_GATE_RED`, `E_DRILL`, `E_NOT_CACHE`, `E_PLATFORM`.

## Roadmap

Today the tool watches one machine and one CI pool (GitHub Actions). Four parts come next. The rule for each part:
you add any resource with a profile entry, and a new kind of resource needs one adapter file at most.

1. **A list of pools.** The profile takes `[[pools]]` entries (each with an `id` and an `adapter`) in place of the
   one `[ci]` section. The supervisor reads each pool apart. Each pool has its own status file, alert keys and
   reserve. `mm place` already takes a list of candidates. Until then the supervisor asks only the `ci`, `delivery` and
   `queue` adapters for resource records. Estimate: 1.5 to 2 hours.
2. **Any kind of pool.** One pool contract for every resource: the capacity left in its own unit (minutes, credits,
   tasks or slots), a reserve, the cost of a job, the queued and running work, and the start command. Two general
   adapters: `command` (a script prints the pool's state as JSON, checked against a schema, so a new resource needs
   only the script and a profile entry) and `static` (a fixed capacity). Examples: a second CI system, a cloud
   machine, a cloud agent service. The record contract exists (`schemas/resource.schema.json`: capacity in its own
   unit, reserve, load, values, freshness), and `mm resources` shows any record that keeps it. Still to come: the cost
   of a job, the start command, and the `command` and `static` adapters. Estimate: 1.5 to 2 hours.
3. **Many machines.** Each machine runs its own `mm` and writes its `status.json`. A collector reads them over the
   network, and placement chooses across machines and pools. Safety actions stay local on each machine and never
   depend on the network. Estimate: 1 to 2 days.
4. **At large scale, a monitor watches and `mm` controls.** When scale comes, connect `mm` to Prometheus and Grafana,
   and grow only its control part, because large-scale monitoring is already solved for free, and control for AI-agent
   fleets is not. `mm` exports its readings as Prometheus metrics. Prometheus stores them, and Grafana draws the graphs
   and sends the alerts; each runs as its own program. `mm` keeps the decisions: the slots, the placement, the guards
   and the usage meters, across the whole fleet. Estimate: none yet; this part starts only when scale comes.

## Tests

```sh
python3 -I tests/run_tests.py            # every group; one result file per group in tests/results/
python3 -I tests/run_vectors.py          # the language-neutral vectors only
```

## Licence

Apache-2.0 (LICENSE).
