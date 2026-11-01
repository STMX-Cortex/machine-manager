# Grafana dashboards and Prometheus alerts

Run Grafana on the central monitoring machine, beside Prometheus. Grafana reads Prometheus history; Prometheus
evaluates the supplied alert rules. Each is a separate program. Neither can change machine-manager settings,
slots, placement, safe mode or services. These files do not install or start anything.

The two dashboards work for Linux and macOS with the metrics in [METRICS.md](METRICS.md):

| Dashboard | Contents |
| --- | --- |
| Fleet (`mm-fleet`) | Endpoint reachability, source freshness/state/mode, memory, CPU, main-filesystem capacity, queues, source alerts, snapshot age, optional PSI/compressor/swap, firing Prometheus alerts |
| Resources (`mm-resources`) | Local resource freshness/state, capacity/total/reserve in native units, running/queued counts, numeric adapter values, resources document validity |

Select a **Producer** (scrape endpoint) and **Machine**. Resource panels also filter by kind, id and capacity unit.
Parent and location remain in labels and legends, distinguishing equal runner/pool ids. The job is the supplied
`machine-manager` scrape job; if you rename it, change the dashboard constant and rule selectors together.
The datasource selector defaults to the provisioned `mm-prometheus` UID, but can select another Prometheus source.
Stable dashboard UIDs support links between Fleet and Resources. Provisioned copies are read-only; change source
JSON and review/deploy it rather than editing a live dashboard.

Unknown/unsupported readings are gaps or `Unknown`, never invented zeros. An empty table means no matching series,
not a healthy machine. Last-value legends are historical; use freshness, state and mode tables for current status.
Ratios use percent display, byte sizes use bytes, snapshot age uses seconds, and queue counts are gauges. Optional
Linux PSI and macOS compressor panels can be empty on other platforms. Storage covers the main filesystem only;
per-mount capacity and device I/O are still roadmap work. Resource units remain separate; the dashboard never sums
credits, minutes or slots, and it never applies `rate()` to snapshot gauges.

Use one collection topology as described in [MONITORING.md](MONITORING.md). Central collection exports peer machine
readings, not peer adapter records. To monitor each host's pools, use direct per-host scrapes with peer-free profiles
and private transport. Do not scrape both a peer directly and its central copy into fleet totals. These dashboards
keep `instance` as producer identity; alert instances also retain producer labels.

## Provision Grafana on Linux or macOS

Install an official Grafana OSS release for the OS/architecture and verify its published checksum/signature.
The disposable provisioning check uses Grafana 13.3.0. Grafana and Prometheus are external dependencies, not Python
packages or components of the supervisor. For a native install, use Grafana's release instructions and the matching
`--homepath` containing its public assets/defaults. Container loopback addresses refer to the container: the native
same-host configuration below assumes both programs share a network namespace.

1. In the existing owner-only monitoring directory, copy `monitoring/grafana/` to `grafana/`. Create separate
   `grafana/data`, `grafana/logs` and `grafana/plugins` directories writable by the intended Grafana user. Keep
   this directory outside the checkout, supervisor data and Prometheus TSDB. Treat its database and backups as
   sensitive. Do not overwrite an existing Grafana installation or its provisioning.
2. Replace every `/ABS/MONITORING` placeholder in `grafana.ini` and
   `provisioning/dashboards/machine-manager.yml` with that monitoring directory's absolute path. The `.yml`
   provisioning files use JSON syntax, which Grafana's YAML reader accepts. Preserve valid JSON escaping when
   inserting paths, especially paths with quotes or backslashes. Confirm the dashboard provider points at your
   copied `dashboards` folder. The datasource URL defaults to `http://127.0.0.1:9090`; change only the copy when needed.
3. Create a private file containing a new initial Grafana administrator password outside the checkout. Restrict
   its permissions to the intended user. Supply its path through `GF_SECURITY_ADMIN_PASSWORD__FILE`; do not put
   the password in the source, shell history or command arguments. This bootstrap setting only applies to a new
   Grafana database; it does not reset an existing administrator. Use a dedicated read-only Viewer account for viewing.
4. Run in the foreground with your actual paths (the launcher is `bin/grafana server` in current distributions):

   ```sh
   GF_SECURITY_ADMIN_PASSWORD__FILE=/path/to/private/grafana-admin-password \
     /path/to/grafana/bin/grafana server --homepath /path/to/grafana \
     --config /path/to/monitoring/grafana/grafana.ini
   ```

5. Log in at `http://127.0.0.1:3000`. Check the Machine Manager folder and datasource health. Confirm both dashboards
   show the expected producers/machines and units; compare them with Prometheus queries and `mm status` on the source.
   Test a controlled stale fixture, endpoint failure and recovery. Check optional-platform gaps remain gaps.

The template binds IPv4 loopback, disables anonymous access/sign-up, external snapshots, telemetry and update
checks, and leaves Grafana's duplicate alert evaluator disabled. Keep authentication enabled. To view from a Mac
when Grafana is on another machine, use an existing authorized SSH connection:

```sh
ssh -N -T -o ExitOnForwardFailure=yes -L 127.0.0.1:13000:127.0.0.1:3000 central.example.internal
```

Open `http://127.0.0.1:13000`. For shared access use an existing authenticated HTTPS proxy, configure Grafana's
external root URL, secure cookies and access controls, and test login/session behavior. Do not simply expose port
3000 publicly. No Grafana persistent-service installer is supplied. Use the platform's service manager only after
reviewing the actual executable, user, paths and login/reboot requirements; this never replaces the supervisor.

## Evaluate alerts

Copy **both** `monitoring/prometheus.yml` and `monitoring/machine-manager.rules.yml` into the same monitoring
directory. The config now loads the rule file relative to itself. Existing copies of the old config must add
`rule_files: [machine-manager.rules.yml]`. Validate the copy before starting/restarting the separate Prometheus
process through the owner's deployment procedure; no admin/lifecycle web endpoint is needed.

```sh
promtool check config /path/to/monitoring/prometheus.yml
promtool test rules monitoring/tests/alerts.test.yml
```

| Alert | Condition sustained for | Severity |
| --- | --- | --- |
| TargetMissing | No `up` series for job `machine-manager`, 2 minutes | critical |
| EndpointDown | Scrape `up=0`, 2 minutes | critical |
| MachineStale | Machine freshness 0 with a working endpoint, 2 minutes | warning |
| MachineRed | Fresh machine in RED, 2 minutes | critical |
| MemoryLow | Available/effective RAM below 5%, 5 minutes | warning |
| StorageLow | Main-filesystem available/total below 10%, 10 minutes; total must be positive | warning |
| ActionAlerts | Fresh source has at least one ACTION alert, 2 minutes | warning |
| ResourceStale | Resource freshness 0 with a valid document, 5 minutes | warning |
| ResourcesInvalid | Missing/invalid local resources document, 5 minutes | warning |
| ResourceReserve | Resource capacity left at or below its own reserve, 5 minutes | warning |

Every name has the prefix `MachineManager`. These are monitoring defaults, independent of controller thresholds;
review them against the owner's workload. Machine measurement/state alerts require a fresh source and successful
scrape. Resource reserve joins preserve resource, parent, location and native unit. Sustained conditions have a
pending period before firing and resolve when the expression stops matching. Missing numerical measurements do
not become low-capacity alarms. Endpoint failures suppress source/workload alerts rather than reviving old readings.
The firing-alert table includes all machines on the selected producers so endpoint problems remain visible.
`TargetMissing` lacks an instance label and is visible with Producer = All.

These rules do not inventory removed machines/resources: if configuration removes an entity, its series eventually
disappears. `TargetMissing` detects an entirely missing job, not each removed target. Prometheus cannot alert while
Prometheus/the central host itself is down. Use an independent external uptime check and an owner-maintained
inventory if you need those guarantees. State RED and ACTION counts also apply in observe/off/safe/dry mode;
inspect the mode before acting. Static pool capacity is owner-maintained, not measured consumption.

## Deliver notifications (owner configuration)

Rules are evaluated by Prometheus and visible in its `/alerts` page even without notification delivery. Grafana's
dashboards display firing `ALERTS` series; Grafana contact points are not used for these Prometheus-managed rules.
For email, chat or paging, run an owner-configured Alertmanager and add its reachable private address to the copied
Prometheus configuration, for example when it is on the same native host:

```yaml
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['127.0.0.1:9093']
```

Configure the intended receiver, group labels (include job/instance/machine_id/alertname), repeat intervals, resolved
notifications and secrets in Alertmanager's private configuration. Validate using the matching `amtool check-config`.
Credentials and actual receivers are deliberately not supplied. No message is sent by these examples or tests.
Prove a controlled notification reaches its intended recipient and resolves, including network-outage behavior,
before calling alert delivery ready. Never wire a notification receiver to machine-manager control commands.

## Validation and rollback

```sh
python3 -u -I tests/run_tests.py
python3 -I tests/run_vectors.py
promtool check config monitoring/prometheus.yml
promtool test rules monitoring/tests/alerts.test.yml
python3 -I tests/check_prometheus.py --prometheus /path/to/prometheus --promtool /path/to/promtool
```

The rule fixtures test thresholds, pending/firing/recovery, stale and unavailable sources, missing targets, zero
filesystem size and separate resource parents/units. The Prometheus fixture executes every dashboard query and
loads/evaluates real rules, in isolated temporary data. These prove query/rule behavior, not production integrations.
The separate optional Grafana check described in `tests/check_grafana.py --help` provisions a disposable container
and verifies the API-visible dashboards/datasource; Docker is not required for normal Python tests or native use.
For that optional check, use the same pinned official image as CI:

```sh
docker pull grafana/grafana:13.3.0@sha256:488984b716c0862639f91a698adbe2862677a5a07bad42da5f03f3030883b205
python3 -I tests/check_grafana.py \
  --docker-image grafana/grafana:13.3.0@sha256:488984b716c0862639f91a698adbe2862677a5a07bad42da5f03f3030883b205
```

Still required on the owner's Mac/Linux: native Grafana startup/login, actual dashboard rendering with live private
peer collection, expected unit/timezone/filter behavior, persistent-service recovery if installed, datasource access
control, and real Alertmanager delivery/resolution. The full suite's platform and optional-input skips still apply.
Existing action-mode queues, supervisor/watchdog recovery and pool dispatch/credentials remain separate acceptance.

To roll back, stop only the newly introduced Grafana process/service and remove its reviewed provisioning copies;
keep its separate database until the owner decides otherwise. Remove `rule_files` from the copied Prometheus
config (or restore its reviewed previous version), validate and restart only Prometheus. Close only your monitoring
tunnel. Do not edit supervisor settings, queue files, safe mode or the installed supervisor/watchdog.
