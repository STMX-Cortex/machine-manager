# machine-manager

## What

machine-manager watches one build machine (macOS) and keeps it safe and busy:

1. It reads memory, swap, compressor, load, disk, power and kernel memory events every 10 s, with no fork.
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
60 s), adds hook entries to the Claude Code settings file named in the profile (a backup first), and records the
install in `~/Library/Application Support/machine-manager/install.json`. It refuses unless `mode.observe = true`.

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
`alerts.jsonl`, `alerts-state.json`, `metrics.csv`, `deletes.log`, `settings.toml`, `off.json`, `state/`, `evidence/`,
`pools/`, `drills/`.

## Status

```sh
mm status        # at most 5 lines: state, mode, slots; readings; alert counts; why; staleness
mm alerts        # one line per active alert: LEVEL NAME text | do: command
mm explain ID    # one alert in full, with its evidence folder
mm place --kind go-test --shards 4      # place=MACHINE|POOL|WAIT, why= lines, do= lines (never run by the tool)
```

Output is plain `key=value` lines; `--json` gives one JSON object. Errors are one line: `E_CODE what; fix: how`.

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
   before its SIGSTOP. Every start, safe mode, `mm stop`, `mm rollback` and the watchdog (when the supervisor is stale
   over `self.resume_paused_after_s`) send SIGCONT to each recorded pid whose start time still matches.
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
`profiles/example.toml` shows every section with made-up paths. Sections: `names`, `service` (`label_prefix`, default
`com.example.machine-manager`; `rollback_notes`; `path_extra`, folders for the service PATH), `sizes`, `live_tools` (process names of a live build), `memory_guard`
(an external guard's heartbeat), `queue` (adapter `fifo-gates`), `kinds` (machine-only and pool job kinds), `ci`
(adapter `github-gh`, read-only), `delivery` (adapter `claude-code-hook`), `trim` (the guarded cache trim), `deletes`
(`rules`, `cleanup`, `forbidden_parts`, `protected_roots`), `recovery` (`expected_jobs`: `{name, match}` regular
expressions over process command lines, checked after a Mac reboot). Placeholders: `{data}`, `{user_tmp}`, `{claude_tmp}`,
`~`. The schema is `schemas/profile.schema.json`.

## Settings

Thresholds and switches live in `settings.default.toml` (every key with its unit). A data folder's `settings.toml`
overrides only the keys it names; an unknown key or a bad value is a problem (`SETTINGS_BAD`), and the last good
values stay in force. The public defaults are safe: `mode.observe = true`, `mode.slot_writes = "off"`,
`deletes.enabled = false`, `launch_gate.enabled = false`, `pause_newest_call.enabled = false`, `banner.enabled = false`.

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
`CACHE_5M` short prompt-cache writes; `QWAIT` a queue call waits long; `HEAD_BLOCK` an exclusive call blocks the queue;
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
`E_RECIPIENT`, `E_STALE`, `E_NO_STATUS`, `E_GATE_RED`, `E_DRILL`, `E_NOT_CACHE`.

## Roadmap

Today the tool watches one machine and one CI pool (GitHub Actions). Three parts come next. The rule for each part:
you add any resource with a profile entry, and a new kind of resource needs one adapter file at most.

1. **A list of pools.** The profile takes `[[pools]]` entries (each with an `id` and an `adapter`) in place of the
   one `[ci]` section. The supervisor reads each pool apart. Each pool has its own status file, alert keys and
   reserve. `mm place` already takes a list of candidates. Estimate: 1.5 to 2 hours.
2. **Any kind of pool.** One pool contract for every resource: the capacity left in its own unit (minutes, credits,
   tasks or slots), a reserve, the cost of a job, the queued and running work, and the start command. Two general
   adapters: `command` (a script prints the pool's state as JSON, checked against a schema, so a new resource needs
   only the script and a profile entry) and `static` (a fixed capacity). Examples: a second CI system, a cloud
   machine, a cloud agent service. Estimate: 1.5 to 2 hours.
3. **Many machines.** Each machine runs its own `mm` and writes its `status.json`. A collector reads them over the
   network, and placement chooses across machines and pools. Safety actions stay local on each machine and never
   depend on the network. Estimate: 1 to 2 days.

## Tests

```sh
python3 -I tests/run_tests.py            # every group; one result file per group in tests/results/
python3 -I tests/run_vectors.py          # the language-neutral vectors only
```

## Licence

Apache-2.0 (LICENSE).
