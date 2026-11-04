# Prometheus collection and hosting

Run one local machine-manager supervisor per machine, plus a separate `mm serve` process to publish its cached
status. On a central machine, schedule `mm collect`, run `mm serve` against that central profile/data folder, and
run Prometheus to scrape it and store history. The central machine can be Linux or macOS. Prometheus is a separate
program; machine-manager still uses only the Python 3.11+ standard library.

```text
Remote supervisors -> remote mm serve /status.json -> private tunnel/HTTPS -> central mm collect
                                                                              |
                                                                        fleet.json
                                                                              |
Central supervisor -> status.json/resources.json -> central mm serve /metrics -> Prometheus history
```

This stage provides the endpoint, scrape configuration and service templates. It does not install or start them,
change an existing supervisor. Grafana dashboards and Prometheus alert rules are in [GRAFANA.md](GRAFANA.md).
Test an isolated candidate before updating a live
installation. Fixture collection is not proof that production queues or pool dispatch work.

## Start the endpoint in the foreground

From the candidate checkout, use the machine's own profile and data directory:

```sh
python3 -I bin/mm serve --profile /path/to/profile.toml --data /path/to/data
```

The startup line is `serve=ready bind=127.0.0.1 port=9877`. Ctrl-C or SIGTERM stops the foreground process.
`--bind ::1` selects IPv6 loopback; `--port N` accepts 1..65535. Other addresses, `--json` and unknown options are
rejected. A bind failure is `E_SERVE` with exit 2. A normal stop exits 0. It does not daemonize, install services,
create data/state directories, collect peers, take readings, or execute commands. Profile changes require restarting
this separate endpoint; settings are read on each request without saving a last-good file.

| Endpoint | Response |
| --- | --- |
| `GET /metrics` | Prometheus text, including health/freshness series. HTTP 200 even if the supervisor is stale; inspect freshness/state. |
| `GET /status.json` | Bounded, schema-validated local status for `mm collect`, with the original source time. HTTP 503 for missing, invalid, stale or unusable queue counts. |
| `GET /storage.json` | The local `storage.json` snapshot written by `mm storage record`, re-serialized, for `mm collect`. HTTP 503 for missing, invalid, foreign or stale (300 s) snapshots. See [STORAGE.md](STORAGE.md), Fleet storage export. |
| `GET /-/healthy` | HTTP 200 `ok` while the HTTP process can respond, independent of supervisor health. |

HEAD has the same status and headers, with no body. Other paths (including query strings) are 404. Write methods
are rejected. Responses have `Cache-Control: no-store`; there is no directory listing, arbitrary file serving,
control endpoint, access log or CORS header. `/status.json` uses a fixed allowlist: machine identity/version/time,
state/mode, queue counts, selected numeric readings/facts and alert counts. It omits reason text, heartbeat notes,
CPU-model strings, capacity/load dictionaries, resource records and arbitrary keys. Metric rules are in
[METRICS.md](METRICS.md). Unknown measurements remain unknown; stale measurements are not revived by a scrape.

The listener accepts only loopback connections and a single loopback Host header (`localhost`, `127.0.0.1` or
`[::1]`, optionally with a port). Binding uses the numeric address directly, with no reverse DNS lookup.
Host validation also rejects browser DNS rebinding. At most four connections run at once;
excess connections close immediately. Each has a three-second socket timeout and ten-second wall deadline, no
keep-alive, and a 16 MiB response cap. Keep Prometheus and untrusted browser pages on separate origins.

## Machines in different locations

**Prefer Tailscale with ordinary OpenSSH tunnels.** [TAILSCALE.md](TAILSCALE.md) provides the default `mm tailscale`
command, per-peer Linux/macOS service templates, a tailnet policy fragment and setup/acceptance steps for Linux,
Mac and cloud VMs. Tailscale login and policy remain owner-managed; no public bind or Funnel is enabled.

Run `mm serve` on each peer. Use an existing private network with an authenticated HTTPS reverse proxy, or an SSH
tunnel. The built-in endpoint deliberately has no public bind, TLS or authentication; the private transport supplies
access control. A reverse proxy must overwrite Host with `127.0.0.1:9877`, preserve source responses/status codes,
disable caching, verify upstream certificates where applicable, and allow only the intended read paths and clients.
Do not proxy a whole runtime data directory.

Example: from the central machine, forward a local port to a Linux worker's loopback listener:

```sh
ssh -N -T -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -L 127.0.0.1:19877:127.0.0.1:9877 worker.example.internal
```

Use a different local port for each peer. Verify SSH host keys and use your existing credentials. Keep tunnels
running separately; these templates do not manage them. In the central profile's existing `[[machines]]` entry,
set `status_url = "http://127.0.0.1:19877/status.json"` and set `id` to the peer's exact `machine_id`. Keep the
existing explicit kinds, queue launcher and SSH placement configuration (README.md, Machines). Then run:

```sh
python3 -I bin/mm collect --profile /path/to/central.toml --data /path/to/central-data
```

For storage export, run `mm storage record` on the peer (below) and add `storage_url =
"http://127.0.0.1:19877/storage.json"` (optional `storage_stale_after_s`, default 300) to the same entry. A
`storage_url` with a query string is refused: the tunnel or proxy supplies access control, not a URL token. Without
`storage_url` no storage is fetched, so peers on older versions need no change.

Collection writes only `fleet.json`, then `fleet-storage-attempt.json` and one `fleet-storage/<id>.json` per peer with
`storage_url`, plus the existing state directory creation; it does not dispatch work or alter slots/settings. Exit 1
means one or more peer statuses or configured storage snapshots are unavailable; their new cache entries become
UNKNOWN (storage: `snapshot: null`). Schedule
only one collector per profile/data directory. A slow collection must complete before the next starts. Match
`stale_after_s` to the supervisor tick, collection duration and scrape interval; each peer request has a wall timeout
and at most four run concurrently. Status and then storage each take up to 8 rounds of `timeout_s` for 32 peers,
so `mm-collect.service` allows 600 s. Disconnections eventually produce freshness 0, never a healthy cached machine
forever. A central outage does not stop local safety decisions.

## Start Prometheus and verify collection

Install an official Prometheus 3.x release for the central machine's OS/architecture, following
[Prometheus installation](https://prometheus.io/docs/prometheus/latest/installation/). Check its published checksum.
`prometheus` and `promtool` are external binaries; they are not Python dependencies. These examples are validated
with Prometheus 3.15.1. Put a copy of [monitoring/prometheus.yml](monitoring/prometheus.yml) in an owner-only
monitoring directory; keep its TSDB outside the checkout and the supervisor data directory.

```sh
promtool check config /path/to/monitoring/prometheus.yml
prometheus --config.file=/path/to/monitoring/prometheus.yml \
  --storage.tsdb.path=/path/to/monitoring/tsdb \
  --storage.tsdb.retention.time=15d --storage.tsdb.retention.size=2GB \
  --web.listen-address=127.0.0.1:9090
```

The configuration scrapes `127.0.0.1:9877/metrics` every 15 seconds, with a five-second scrape timeout and explicit
sample/body/label limits. A scrape exceeding limits fails as a whole (`up=0`); reduce resource/value counts or
adjust the limits after measuring. Retention limits reduce history growth, but temporary/WAL files can exceed the
retention size; monitor free disk space. Both processes run as the owning user, with no root requirement.

Open `http://127.0.0.1:9090` on the central machine and check targets, then query:

```promql
up{job="machine-manager"}
machine_manager_machine_status_fresh
machine_manager_memory_available_ratio
machine_manager_storage_available_bytes
```

`up=1` proves a successful scrape, not a healthy supervisor. A machine also needs freshness 1; its state and mode
describe its health and action eligibility. Values for unknown readings are absent, not zero. Remote machines
appear only after `mm collect` succeeds. Peer adapter resources are not collected by the current fleet contract.

Choose one topology: the supplied central target already exports local and configured peer machines. Do not also
scrape those peers' `/metrics` into the same fleet queries without excluding duplicate machine series. If you want
per-host pool resources, scrape each host directly through private tunnels and use profiles without peer entries
for those exporters. Keep `job`/`instance` labels when comparing producer snapshots; never sum duplicate producers.

To view Prometheus remotely, tunnel its loopback port to your viewing machine:

```sh
ssh -N -T -o ExitOnForwardFailure=yes -L 127.0.0.1:19090:127.0.0.1:9090 central.example.internal
```

Open `http://127.0.0.1:19090`. Do not enable the Prometheus admin/lifecycle API or expose its web UI publicly.
For Grafana dashboards, Prometheus alert evaluation and owner-configured notification delivery, see [GRAFANA.md](GRAFANA.md).

## Optional persistent services: owner installation

The examples under [monitoring/systemd](monitoring/systemd) and [monitoring/launchd](monitoring/launchd) are separate
from the existing supervisor/watchdog installation. They are templates, not an installer. Review copies outside
the checkout and replace **every** `/ABS/...` placeholder with an absolute path:

| Placeholder | Value |
| --- | --- |
| `/ABS/PYTHON3` | Intended Python 3.11+ executable (Mac: use the actual interpreter path, not a shell alias) |
| `/ABS/MACHINE_MANAGER` | Candidate checkout/install directory |
| `/ABS/PROFILE.toml`, `/ABS/MM_DATA` | This machine's profile and runtime data directory |
| `/ABS/PROMETHEUS` | Installed official Prometheus executable |
| `/ABS/MONITORING` | Owner-only directory containing prometheus.yml, TSDB and optional logs |

For systemd, quote each full argv word containing spaces, escape literal `%` as `%%`, and escape literal `$` as `$$`.
For launchd, each XML string is one argv word; XML-escape `&`/`<`. Neither expands `~`, shell variables or shell commands. Create the
monitoring/log directory with mode 0700 before starting. Logs and history need their own retention plan; launchd
stdout/stderr files do not rotate automatically.

Linux: copy reviewed units to `~/.config/systemd/user/`. Run `systemd-analyze --user verify` on the service and timer
copies and `promtool check config` on the copied YAML. After owner approval, use `systemctl --user daemon-reload`
and enable/start `mm-monitoring.service`, `mm-collect.timer` and `mm-prometheus.service` on the central machine.
Peers need only `mm-monitoring.service`. Every host that exports storage (central and peers) also enables
`mm-storage.timer`: it runs `mm storage record` 60 seconds after the previous run finished (no overlap; exit 1, partial
storage, still counts as success). The collect timer waits 15 seconds after each collection finishes, so runs cannot
overlap. Collection exit 1 is accepted by the service because unavailable peers are recorded in the cache. Check
`systemctl --user status` and the user journal for those exact units. User services depend on the user manager;
login-independent operation requires an owner/admin decision about lingering. These instructions do not enable it.

macOS: copy reviewed plists to `~/Library/LaunchAgents/`, validate each with `plutil -lint`, then, after owner
approval, bootstrap the monitoring/collect/Prometheus agents into `gui/$(id -u)` using `launchctl bootstrap`.
Peers need only the monitoring agent, plus `org.machine-manager.storage` (every 60 seconds) on each host that exports
storage. `StartInterval` triggers collection every 15 seconds and launchd does not
start another copy while that job is running; missed intervals are not a backlog. Check `launchctl print` for the
exact `org.machine-manager.*` labels you bootstrapped and their logs. GUI LaunchAgents depend on the logged-in session.
These labels do not replace or restart the installed supervisor or watchdog.

Stop/remove only the new units/agents when rolling back monitoring: Linux disable/stop `mm-collect.timer`,
`mm-storage.timer`, `mm-monitoring.service` and `mm-prometheus.service`; Mac boot out the exact new agents. Delete
`storage.json`, `fleet-storage/` and `fleet-storage-attempt.json` only by owner choice; nothing else reads them. Remove their reviewed
copies and reload the user manager as applicable. Close only your monitoring tunnels. Keep the existing profile,
settings, queue, supervisor, watchdog and data files in place. Retain or remove the separate TSDB only by owner choice.

## Validation before deployment

```sh
python3 -u -I tests/run_tests.py
python3 -I tests/run_vectors.py
promtool check config monitoring/prometheus.yml
python3 -I tests/check_prometheus.py --prometheus /path/to/prometheus --promtool /path/to/promtool
```

The optional last command runs real Prometheus against disposable fixture servers, with an isolated TSDB and no
service installation. It verifies scraping, peer collection (including a real `mm storage record` and peer storage),
queries, staleness and endpoint failure, then stops its own processes. The normal Python suite covers HTTP
paths/methods/Host, bounds, file isolation, status projection, fleet compatibility, IPv6 when available, and SIGTERM
shutdown. Socket-restricted environments report those skips.

Still required on the owner's machines: full suite/vectors at the exact candidate commit, real private-network
hosting/tunnel access, actual systemd and launchd startup/restart/stop across login/reboot as intended, target-host
Prometheus ingestion/retention and outage behavior. Existing supervisor/watchdog recovery, production action-mode
queues and external pool credentials/guards/dispatch remain separate acceptance checks. Optional `MM_LIVE_QUEUE`
and `MM_PUBLIC_DENY` checks still need their inputs. Never infer production integration success from these fixtures.
