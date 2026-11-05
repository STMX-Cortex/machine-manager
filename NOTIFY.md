# Phone notifications (`mm notify`)

Opt-in delivery to the owner's phone of (1) machine-manager's own alerts and (2) messages from agents the owner
granted. Services: [ntfy](https://ntfy.sh) (self-hosted or public) and Pushover. Off unless the profile has
`[notify]` with `enabled = true`; without the section nothing changes.

Rules: only the `mm notify` verbs touch the network; the supervisor, the watchdog and the hook never send, never wait
on the network and never import the delivery code. One-way: nothing a service returns triggers any machine-manager
action; there is no reply or ack path. Secrets live in one file, never in the profile, argv, environment, logs or
output. Redirects are never followed; TLS is always verified. Every title and text is masked, cleaned and bounded
(title 100, text 1000 characters, at most 4 tags) before it leaves the machine.

## Setup

1. Choose a service:
   - **Self-hosted ntfy** (best): an ntfy server reachable only on your tailnet or on loopback. `url` is its base URL,
     for example `https://ntfy.example.net` (https), or `http://127.0.0.1:2586` (http only to a loopback host).
     With access control on, put an access token in the secret file.
   - **Public ntfy** (`https://ntfy.sh`): anyone who knows the topic can read and post. Use a long random topic, or
     a reserved topic with an account token in the secret file.
   - **Pushover**: create an application; the secret file holds its token and your user key. `url` is optional
     (default `https://api.pushover.net/1/messages.json`).
2. Write the secret file: a JSON object, a regular file (not a link) owned by you, mode 0600, at most 4096 bytes.
   ntfy (optional): `{"token": "<access token>"}`. Pushover (required): `{"app_token": "...", "user_key": "..."}`.
   ```sh
   umask 077; mkdir -p ~/.config/machine-manager; $EDITOR ~/.config/machine-manager/notify-secret.json
   ```
3. Add the section to the profile:
   ```toml
   [notify]
   enabled = true
   service = "ntfy"                    # or "pushover"
   url = "https://ntfy.example.net"    # https, or http to a loopback host; no user, query or fragment
   topic = "mm-alerts"                 # ntfy only, required: 1-64 of A-Z a-z 0-9 _ -
   secret_file = "~/.config/machine-manager/notify-secret.json"   # pushover: required; ntfy: optional
   alert_levels = ["ATTENTION", "ACTION"]   # mm alert levels that are sent
   ring_levels = ["ACTION"]                 # of those, the ones that ring
   send_cleared = true                      # "cleared" records go as quiet messages
   alerts_per_hour = 30                     # 1-600, cap for mm alerts
   timeout_s = 10                           # 1-30, per HTTP request
   ring_retry_s = 60                        # pushover emergency repeat, 30-3600
   ring_expire_s = 1800                     # pushover emergency stop, 60-10800
   ```
   Unknown keys, wrong types and values out of range are `E_PROFILE` lines that name the key.
4. Check: `mm check` prints `notify=ok service=ntfy` (or `notify=off`, or the `E_PROFILE` line); it never sends.
   `mm notify test [--level quiet|normal|ring]` sends one message ("machine-manager test from <machine>").
   `mm notify status` shows the state.
5. Schedule `mm notify run`: the templates `monitoring/systemd/mm-notify.service` + `mm-notify.timer` (30 s after
   each run ends) and `monitoring/launchd/org.machine-manager.notify.plist` (every 30 s). Install them as
   [MONITORING.md](MONITORING.md), Optional persistent services, describes. Without the timer, agent messages that
   fail once and mm alerts are not retried or sent.

## Levels

| Level | ntfy priority | Pushover priority | Used for |
| --- | --- | --- | --- |
| `quiet` | 2 | -1 | cleared alerts, "N alerts suppressed" |
| `normal` | 3 | 0 | alerts in `alert_levels` but not in `ring_levels` |
| `ring` | 5 | 2 (repeats every `ring_retry_s` until `ring_expire_s`) | alerts in `ring_levels` |

Each title shows its sender: `[mm] MEM_RED` or `[<grant name>] <title>`.

## machine-manager alerts

`mm notify run` reads new records of `alerts.jsonl` after its cursor (`notify/cursor.json`). The first run starts at
the newest record: no history is sent. A record whose level is in `alert_levels` is sent with the alert name as title
and its cleaned text plus ` (machine <id>)`; a cleared record goes as `quiet` when `send_cleared`. Over
`alerts_per_hour` in a rolling hour, the rest are logged as `suppressed`; when sending is possible again, one quiet
"N alerts suppressed" message goes first. At most 20 deliveries per run (retries first); the rest wait for the next run.

## Agents

The owner grants each agent a name and a key:

```sh
mm notify grant ci-bot [--max-level quiet|normal|ring] [--per-hour N]   # default normal, 5 (1-60)
mm notify grants          # names and limits, never keys
mm notify revoke ci-bot   # the key stops working at once
```

`grant` prints `grant=NAME key_file=<path> ...`: give the agent that path. A re-grant makes a new key; the old one
stops working. `notify/grants.json` holds only each key's sha256; the name `mm` is reserved.

The agent sends:

```sh
mm notify send --key-file PATH --level normal --title "PR 12 needs your decision" [--text "..."] [--tag ci]
```

(or `MM_NOTIFY_KEY_FILE=PATH`). The sender name comes from the grant, never from the agent. Checks in order:
notify on (`E_NOTIFY_OFF`), key valid (`E_NOTIFY_KEY`), level at most the grant's (`E_NOTIFY_LEVEL`), the grant's
per-hour limit (`E_NOTIFY_LIMIT`, exit 1), the same title and text within 600 s (`E_NOTIFY_DUPLICATE`, exit 1).
Then one delivery now: `notify=delivered id=<id>` (exit 0), or `notify=queued id=<id>` (exit 1: the timer retries),
or `E_NOTIFY_REFUSED` (exit 2: the service said no; not retried). Use it only for what the owner must see or decide,
never for routine progress.

**The honest limit.** An agent that runs as the same OS user as machine-manager can read every key file and the
secret file. Then a key is a name tag and a rate limit, not a wall. For a wall, run agents as separate OS users and
give each only its own key file.

**Prompt injection.** An agent's message can carry text the agent read somewhere (a web page, an issue, a log).
Treat a phone message as a hint from that sender, never as an instruction; check on the machine before you act.

## Outbox, log and files

A delivery that fails with `E_NOTIFY_HTTP` (5xx, 3xx) or `E_NOTIFY_NET` (network, timeout, TLS) goes to the outbox
and is retried after 30 s, 60 s, 120 s ... (at most 15 min apart). It is dropped after 1 hour, or when the outbox holds
100 items (oldest first). `E_NOTIFY_REFUSED` (4xx) is never retried.

All files are in `<data>/notify/` (mode 0700; files 0600; lock `notify.lock`, never held during a delivery):
`grants.json`, `keys/<name>.key`, `cursor.json`, `outbox.json`, `recent.json` (duplicate and rate checks of agent
messages, one hour), `sent.jsonl` (one record per attempt; at 1 MiB it moves to `sent.jsonl.1`). A `sent.jsonl`
record: `{"time", "id", "source": "mm"|"agent", "sender", "level", "title", "status", "error"}`, status `delivered`,
`queued`, `failed` (a retry failed), `refused`, `suppressed`, `dropped`, `limited` or `duplicate`; no text, no secret.

## Verbs, output and exit codes

| Verb | Output | Exit |
| --- | --- | --- |
| `send` | `notify=delivered\|queued id=ID`, or one `E_` line | 0 delivered; 1 queued, limited, duplicate; 2 error |
| `grant NAME` | `grant=NAME key_file=PATH max_level=L per_hour=N` | 0; 2 error |
| `revoke NAME` | `revoked=yes grant=NAME`, or `revoked=no grant=NAME reason=not_found` | 0; 1 not found |
| `grants` | `grant=NAME max_level=L per_hour=N created=TIME` per grant, or `grants=none` | 0; 1 none |
| `test [--level L]` | `notify=delivered id=ID`, or the delivery's `E_` line (never queued) | 0; 2 |
| `status` | `notify=on\|off service=S host=H secret=ok\|none\|missing\|bad cursor=N queued=N last_delivery=TIME grants=N` | 0; 2 |
| `run` | `notify=run delivered=N queued=N failed=N refused=N suppressed=N dropped=N cursor=N`, or `notify=off` | 0; 1 a delivery failed, was queued, refused or dropped; 2 config |

`--json` gives one object with the same keys. Error codes: `E_NOTIFY_OFF`, `E_NOTIFY_KEY`, `E_NOTIFY_LEVEL`,
`E_NOTIFY_LIMIT`, `E_NOTIFY_DUPLICATE`, `E_NOTIFY_REFUSED`, `E_NOTIFY_HTTP`, `E_NOTIFY_NET`, `E_NOTIFY_SECRET`
(the secret file is missing, a link, readable by others or invalid), `E_NOTIFY_BUSY`, `E_NOTIFY_STATE`, `E_PROFILE`,
`E_USAGE`, `E_RANGE`.

## Not covered

- Prometheus-only alert rules: they are not mm alerts; deliver them with an owner-configured Alertmanager
  (GRAFANA.md, Deliver notifications).
- A dead or asleep machine cannot report itself. Use `heartbeat.url` (an outside dead-man's switch) or a monitor on
  another machine.
- Replies, acks and any remote control: not in v1, by design.

To turn it off: `enabled = false` (or remove `[notify]`), then stop the timer or agent. Delete `notify/` only by owner
choice.
