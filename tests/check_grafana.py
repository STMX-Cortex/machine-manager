#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Optional disposable Grafana provisioning check (requires Docker and a pre-pulled official image).

Example: python3 -I tests/check_grafana.py --docker-image grafana/grafana:13.3.0
Uses a random admin password, temporary read-only provisioning, a temporary in-memory database and a random
host-loopback port. No real datasource requests, notifications, services or supervisor changes. Cleans up its
own container/files even on failure. --docker-host can select the managed local socket explicitly.
"""
import argparse
import base64
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

CODE = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-image", required=True, help="pre-pulled official Grafana image (CI pins its digest)")
    parser.add_argument("--docker-host", help="optional Docker endpoint; Cloud uses unix:///var/run/docker.sock")
    options = parser.parse_args()
    docker = ["docker"] + (["--host=" + options.docker_host] if options.docker_host else [])

    def run(*args):
        return subprocess.run(docker + list(args), check=True, capture_output=True, text=True, timeout=90).stdout

    name = "mm-grafana-test-" + secrets.token_hex(8)
    created = False
    with tempfile.TemporaryDirectory(prefix="mm-grafana-") as temporary:
        root = Path(temporary)
        root.chmod(0o755)  # Container uid 472 must traverse the fixture; it contains no real credentials.
        shutil.copytree(CODE / "monitoring/grafana/provisioning", root / "provisioning")
        shutil.copytree(CODE / "monitoring/grafana/dashboards", root / "dashboards")
        provider = root / "provisioning/dashboards/machine-manager.yml"
        provider.write_text(provider.read_text().replace("/ABS/MONITORING/grafana/dashboards", "/etc/mm-dashboards"))
        (root / "grafana.ini").write_text((CODE / "monitoring/grafana/grafana.ini").read_text()
                                         .replace("/ABS/MONITORING", "/tmp/mm-monitoring"))
        password = secrets.token_urlsafe(32)
        secret_file = root / "password"
        secret_file.write_text(password)
        secret_file.chmod(0o444)  # Disposable credential, read-only bind inside this container only.
        for path in root.rglob("*"):
            if path != secret_file:
                path.chmod(0o755 if path.is_dir() else 0o644)
        # Explicitly disable client proxy defaults for loopback requests from this validation process.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        auth = "Basic " + base64.b64encode(("admin:" + password).encode()).decode()
        try:
            run("create", "--pull=never", "--name", name, "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--memory=512m", "--cpus=1",
                "--tmpfs", "/tmp:rw,size=256m,mode=1777", "--publish", "127.0.0.1::3000",
                "--mount", "type=bind,src=%s,dst=/etc/grafana/provisioning,readonly" % (root / "provisioning"),
                "--mount", "type=bind,src=%s,dst=/etc/mm-dashboards,readonly" % (root / "dashboards"),
                "--mount", "type=bind,src=%s,dst=/etc/grafana/grafana.ini,readonly" % (root / "grafana.ini"),
                "--mount", "type=bind,src=%s,dst=/run/mm-test-password,readonly" % secret_file,
                "--env", "GF_SECURITY_ADMIN_PASSWORD__FILE=/run/mm-test-password",
                "--env", "GF_PATHS_DATA=/tmp/mm-grafana-data", "--env", "GF_PATHS_LOGS=/tmp/mm-grafana-logs",
                "--env", "GF_PATHS_PLUGINS=/tmp/mm-grafana-plugins",
                "--env", "GF_PATHS_PROVISIONING=/etc/grafana/provisioning",
                "--env", "GF_PLUGINS_PREINSTALL_DISABLED=true",
                # Only the container listens on all of its interfaces; the host port is loopback-only.
                "--env", "GF_SERVER_HTTP_ADDR=0.0.0.0", options.docker_image)
            created = True
            run("start", name)
            inspected = json.loads(run("inspect", "--format", "{{json .NetworkSettings.Ports}}", name))
            binding, = inspected["3000/tcp"]
            if binding["HostIp"] != "127.0.0.1":
                raise RuntimeError("fixture must publish only on host loopback")
            url = "http://127.0.0.1:" + binding["HostPort"]

            def get(path, authenticated=True):
                request = urllib.request.Request(url + path, headers={"Authorization": auth} if authenticated else {})
                with opener.open(request, timeout=5) as response:
                    return json.load(response)

            until = time.monotonic() + 60
            while True:
                try:
                    health = get("/api/health", False)
                    if health.get("database") == "ok":
                        break
                except (OSError, ValueError):
                    pass
                if time.monotonic() >= until:
                    print("Grafana container state: " + run("inspect", "--format",
                          "status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}", name).strip(),
                          file=sys.stderr)
                    errors = [line for line in run("logs", name).splitlines() if "level=error" in line or "Error:" in line]
                    for line in errors[-5:]:
                        print(line.replace(password, "[fixture-password]"), file=sys.stderr)
                    raise RuntimeError("Grafana did not become healthy within 60 seconds")
                time.sleep(.5)
            print("PASS real Grafana %s is healthy" % health["version"], flush=True)
            try:
                get("/api/search", False)
            except urllib.error.HTTPError as error:
                if error.code != 401:
                    raise RuntimeError("unexpected anonymous API response") from None
            else:
                raise RuntimeError("anonymous access was not rejected")
            print("PASS anonymous dashboard API access rejected", flush=True)
            datasource = get("/api/datasources/uid/mm-prometheus")
            if datasource.get("type") != "prometheus" or datasource.get("url") != "http://127.0.0.1:9090" \
                    or datasource.get("access") != "proxy" or datasource.get("readOnly") is not True:
                raise RuntimeError("datasource provisioning differs from expected contract")
            print("PASS fixed-UID read-only Prometheus datasource provisioned", flush=True)
            for path in sorted((CODE / "monitoring/grafana/dashboards").glob("*.json")):
                expected = json.loads(path.read_text())
                actual = get("/api/dashboards/uid/" + expected["uid"])
                if actual["meta"].get("provisioned") is not True:
                    raise RuntimeError("dashboard is not provisioned")
                panels = actual["dashboard"]["panels"]
                if [(p["id"], p["targets"]) for p in panels] != [(p["id"], p["targets"]) for p in expected["panels"]]:
                    raise RuntimeError("provisioned dashboard queries differ from source")
                if actual["dashboard"]["templating"]["list"] != expected["templating"]["list"]:
                    raise RuntimeError("provisioned dashboard filters differ from source")
                print("PASS %s: %d panels and filters provisioned" % (expected["uid"], len(panels)), flush=True)
        finally:
            if created:
                run("rm", "--force", "--volumes", name)
    print("PASS cleanup: removed fixture container, in-memory database and provisioning copies")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        # Container output is deliberately not dumped: logs may include generated session credentials.
        print("FAIL " + str(error), file=sys.stderr)
        sys.exit(1)
