# machine-manager for agents

`mm` watches this machine and its job queue. Ask it before heavy work; read its alerts; never fight it.

## Commands

| Command | Use |
| --- | --- |
| `mm status` | state, slots, readings, alert counts (at most 5 lines) |
| `mm alerts` | active alerts, one line each |
| `mm explain ID` | one alert in full: text, command, evidence folder |
| `mm ack ID` | silence an alert you handled, until it gets worse |
| `mm place --kind K [--shards N] [--wide] [--agents N]` | where a job runs: MACHINE, POOL or WAIT |
| `mm resources` | one line per resource (machine, pools, runners, services); files only, fast |
| `mm wait [--min-level action]` | block until an unseen alert (run it under a monitor) |
| `mm event timing-failure --note TEXT` | report a test that failed by time (slots go down one step) |
| `mm watch RUN_ID --note TEXT` | an alert when that CI run ends |
| `mm help` | every verb |

Add `--json` for one JSON object.

## Output format

- Plain `key=value` words, one record per line. No colour, no progress lines.
- An alert line: `LEVEL NAME text | do: command` (at most 200 characters; `do: mm explain ID` when the command is long).
- An error: one line `E_CODE what; fix: how`.
- Hooks show at most 3 alert lines, then `+N more: mm alerts`.

## Exit codes

0 ok; 1 nothing found or problems listed; 2 error; 3 the supervisor is stale (wait, then retry);
10 place=POOL (run the printed `do=` commands yourself, if allowed); 20 place=WAIT.

## Words

States: GREEN, STEADY, AMBER (slots down one step), RED (slots at the floor), UNKNOWN (no fresh status).
Levels: INFO, ATTENTION, ACTION. Alert names: README.md, Glossary.

## Never

1. Never edit the profile, `settings.toml`, `off.json`, `override.json` or the queue's slot file by hand
   unless the owner asks; use `mm off`, `mm slots pin`, `mm on`.
2. Never delete what `mm cleanup` lists; it is a list for the owner, with exact commands.
3. Never start a heavy job when `mm place` says WAIT, or many agents at RED.
4. Never kill, stop or resume a process the tool paused; tell the owner.
5. Never run `mm drill`, `mm install`, `mm rollback`, `mm stop`, `mm restart` or `mm on` without the owner's word.
   `SAFE_MODE` means automatic actions are off until the owner ends it.
6. Never put secrets in `--note` or `--reason` text (they are masked, but still).
