#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Optional real Prometheus fixture: isolated HTTP processes/TSDB; no live queues, credentials or installs."""
import argparse
import json
import os
import re
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

CODE = Path(__file__).resolve().parent.parent
MM = [sys.executable, "-I", str(CODE / "bin" / "mm")]


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def snapshot(ident):
    return {"kind": "machine", "schema_version": 1, "machine_id": ident, "time": time.time(),
            "state": "GREEN", "mode": "act", "slots": 4, "busy": 0, "waiting": 0,
            "readings": {"free_pct": 75}, "disk_gb": 20, "facts": {"ram_mb": 1024, "disk_gb_total": 100}}


def wait(check, description):
    until = time.monotonic() + 30
    while time.monotonic() < until:
        try:
            if check():
                print("PASS " + description, flush=True)
                return
        except (OSError, ValueError):
            pass
        time.sleep(.2)
    raise RuntimeError("timeout: " + description)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prometheus", required=True)
    parser.add_argument("--promtool", required=True)
    options = parser.parse_args()
    for executable in (options.prometheus, options.promtool):
        subprocess.run([executable, "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=10)
    subprocess.run([options.promtool, "check", "config", str(CODE / "monitoring" / "prometheus.yml")],
                   check=True, timeout=15)
    processes, logs = [], []
    with tempfile.TemporaryDirectory(prefix="mm-prometheus-") as temporary:
        root = Path(temporary)
        env = dict(os.environ, HOME=str(root), MM_BASE=str(root / "base"))
        remote_port, central_port, prom_port = port(), port(), port()

        def host(ident, host_port, peers=""):
            data = root / ident
            data.mkdir(mode=0o700)
            profile = data / "profile.toml"
            profile.write_text('name = "%s"\nmachine_id = "%s"\n%s' % (ident, ident, peers))
            source = snapshot(ident)
            (data / "status.json").write_text(json.dumps(source))
            process = subprocess.Popen(MM + ["serve", "--port", str(host_port), "--profile", str(profile),
                                             "--data", str(data)], env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes.append(process)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(10) or not process.stdout.readline().startswith("serve=ready "):
                    raise RuntimeError("fixture endpoint failed to start")
            return profile, data, source

        def collect(profile, data, expected):
            result = subprocess.run(MM + ["collect", "--profile", str(profile), "--data", str(data)], env=env,
                                    capture_output=True, text=True, timeout=15)
            if result.returncode != expected:
                raise RuntimeError("fixture collection exit %d, expected %d" % (result.returncode, expected))

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # fixture loopback only

        def query(expr):
            url = "http://127.0.0.1:%d/api/v1/query?%s" % (prom_port, urllib.parse.urlencode({"query": expr}))
            with opener.open(url, timeout=2) as response:
                doc = json.load(response)
            if doc["status"] != "success":
                raise ValueError("query failed")
            return doc["data"]["result"]

        def value(expr, expected):
            rows = query(expr)
            return len(rows) == 1 and float(rows[0]["value"][1]) == expected

        try:
            host("fixture-peer", remote_port)
            peers = ('[[machines]]\nid = "fixture-peer"\nstatus_url = "http://127.0.0.1:%d/status.json"\n'
                     'timeout_s = 2\nstale_after_s = 60\nstart_argv = ["/usr/bin/false"]\n'
                     '[machines.kinds]\nother = 1\n') % remote_port
            profile, data, local = host("fixture-central", central_port, peers)
            resource = {"resource": "pool", "id": "fixture-pool", "parent": "team", "location": "cloud",
                        "state": "GREEN", "read_time": time.time(), "stale_after_s": 300,
                        "capacity": {"unit": "credits", "total": 100, "left": 10, "reserve": 10},
                        "load": {"running": 1, "queued": 2}, "values": []}
            (data / "resources.json").write_text(json.dumps({"kind": "resources", "schema_version": 1,
                "machine_id": "fixture-central", "time": time.time(), "resources": [resource]}))
            collect(profile, data, 0)
            config = root / "prometheus.yml"
            (root / "machine-manager.rules.yml").write_text(
                (CODE / "monitoring" / "machine-manager.rules.yml").read_text().replace("interval: 15s", "interval: 1s"))
            config.write_text((CODE / "monitoring" / "prometheus.yml").read_text().replace("15s", "1s")
                              .replace("5s", "1s").replace("127.0.0.1:9877", "127.0.0.1:%d" % central_port))
            subprocess.run([options.promtool, "check", "config", str(config)], check=True, timeout=15)
            log = (root / "prometheus.log").open("w+")
            logs.append(log)
            processes.append(subprocess.Popen([options.prometheus, "--config.file=" + str(config),
                                               "--storage.tsdb.path=" + str(root / "tsdb"),
                                               "--storage.tsdb.retention.time=1h", "--storage.tsdb.retention.size=64MB",
                                               "--web.listen-address=127.0.0.1:%d" % prom_port], env=env,
                                              stdout=log, stderr=subprocess.STDOUT))
            wait(lambda: value('up{job="machine-manager"}', 1), "actual Prometheus scrape succeeds")
            wait(lambda: value('machine_manager_machine_status_fresh{machine_id="fixture-peer"}', 1),
                 "collected peer is fresh")
            wait(lambda: value('machine_manager_memory_available_ratio{machine_id="fixture-peer"}', .75),
                 "peer memory reading is queryable")
            wait(lambda: value('machine_manager_storage_available_bytes{machine_id="fixture-peer"}', 20e9),
                 "peer filesystem reading is queryable")
            wait(lambda: value('machine_manager_resource_capacity_left{id="fixture-pool"}', 10),
                 "local pool capacity is queryable")
            wait(lambda: bool(query('(machine_manager_resource_capacity_left{job="machine-manager"} <= '
                 'machine_manager_resource_capacity_reserve{job="machine-manager"}) and on(job, instance, '
                 'machine_id, resource, id, parent, location) '
                 '(machine_manager_resource_fresh{job="machine-manager"} == 1)')), "reserve condition matches")
            try:
                wait(lambda: value('ALERTS{alertname="MachineManagerResourceReserve",alertstate="pending"}', 1),
                     "real Prometheus evaluates resource reserve rule")
            except RuntimeError:
                with opener.open("http://127.0.0.1:%d/api/v1/rules" % prom_port, timeout=2) as response:
                    rules = json.load(response)
                for group in rules.get("data", {}).get("groups", []):
                    print("Rule group: " + group["name"], file=sys.stderr)
                    for rule in group.get("rules", []):
                        print(json.dumps({k: rule.get(k) for k in ("name", "state", "health", "lastError", "query")}),
                              file=sys.stderr)
                raise
            for dashboard in sorted((CODE / "monitoring" / "grafana" / "dashboards").glob("*.json")):
                count = 0
                for panel in json.loads(dashboard.read_text())["panels"]:
                    for target in panel.get("targets", []):
                        expression = target["expr"].replace("$job", "machine-manager")
                        for variable in ("instance", "machine", "resource", "id", "unit"):
                            expression = expression.replace("${%s}" % variable, ".*")
                        query(expression)  # Parse and execute every shipped panel against real Prometheus.
                        # Also exercise selected label values, including punctuation in the producer address.
                        # Grafana's Prometheus datasource must provide the corresponding PromQL string escaping.
                        selected = target["expr"].replace("$job", "machine-manager")
                        for variable, value_ in {"instance": "127.0.0.1:%d" % central_port,
                                                  "machine": "fixture-central", "resource": "pool",
                                                  "id": "fixture-pool", "unit": "credits"}.items():
                            escaped = json.dumps(re.escape(value_))[1:-1]
                            selected = selected.replace("${%s}" % variable, escaped)
                        query(selected)
                        count += 1
                print("PASS %s: %d dashboard queries execute" % (dashboard.name, count), flush=True)
            remote_status = root / "fixture-peer" / "status.json"
            stale = json.loads(remote_status.read_text())
            stale["time"] -= 10000
            remote_status.write_text(json.dumps(stale))
            collect(profile, data, 1)
            wait(lambda: value('machine_manager_machine_status_fresh{machine_id="fixture-peer"}', 0),
                 "stale peer becomes unavailable")
            wait(lambda: not query('machine_manager_memory_available_ratio{machine_id="fixture-peer"}'),
                 "stale peer measurement disappears")
            local["time"] -= 10000
            (data / "status.json").write_text(json.dumps(local))
            wait(lambda: value('machine_manager_machine_status_fresh{machine_id="fixture-central"}', 0)
                 and value('up{job="machine-manager"}', 1), "stale supervisor remains a successful health scrape")
            processes[1].terminate()
            processes[1].wait(timeout=15)
            wait(lambda: value('up{job="machine-manager"}', 0), "endpoint outage produces up=0")
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                try:
                    process.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
            for log in logs:
                log.close()
    print("PASS cleanup: stopped fixture processes; removed temporary TSDB and data")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("FAIL " + str(error), file=sys.stderr)
        sys.exit(1)
