# Tailscale setup for machine-manager

**Tailscale is the preferred private transport** between Linux hosts, Macs and cloud VMs in different locations.
The default setup uses ordinary OpenSSH over Tailscale, forwarding the peer's loopback monitoring endpoint to a
loopback port on the central machine. Prometheus and Grafana stay on loopback too. Existing authenticated private
networks remain supported; existing installations are not migrated automatically.

```text
Peer supervisor -> peer mm serve (127.0.0.1:9877)
                             ^
                  OpenSSH over Tailscale (TCP 22)
                             |
Central 127.0.0.1:19877 -> mm collect -> fleet.json -> mm serve -> Prometheus -> Grafana
```

This setup adds monitoring transport only. Each supervisor keeps its own safety decisions. It does not enable
remote execution or change placement, queue actions, settings, guards, pools, or installed supervisor services.
You still need one installation/profile/supervisor on each watched machine; see [README.md](README.md) and
[MONITORING.md](MONITORING.md). The central machine can itself be a Linux cloud VM.

## 1. Connect the hosts to your tailnet

Install Tailscale using the [official OS-specific instructions](https://tailscale.com/download) on the central
machine and every peer. Sign in to the intended tailnet, approve devices and enable MagicDNS as required by your
organization. Verify both devices in the Tailscale admin console, then verify connectivity using the Tailscale
client's status/ping commands. Use the peer's full MagicDNS name (for example `worker.example.ts.net`) or its
Tailscale IPv4/IPv6 address. Short hostnames are deliberately not accepted by the tunnel helper.

Tailscale installation/login, device approval, tags, grants, key expiry and unattended startup remain owner/admin
operations. Machine-manager never installs Tailscale, joins a tailnet, embeds auth keys, or changes its settings.
Do not commit Tailscale credentials or put auth keys on command lines. Confirm that the chosen macOS Tailscale
distribution and Linux daemon start in the login/reboot conditions you need. This is separate from LaunchAgents.

Review tailnet access before adding peers. [grants.example.json](monitoring/tailscale/grants.example.json) is a
minimal **policy fragment** allowing `tag:mm-monitor` to reach `tag:mm-worker` on TCP 22. Merge and validate it in
your actual policy; do not overwrite an existing tailnet policy. Assign tags only through your approved workflow.
Tailscale allows are additive: this fragment does not revoke a pre-existing broad allow rule. Review those rules
too, and retain only the access you intend. Neither grants nor tags configure SSH authentication or the host firewall.

## 2. Prepare the peer

Run the peer's supervisor and `mm serve` as described in MONITORING.md. Keep `mm serve` at its default
`127.0.0.1:9877`. Confirm `http://127.0.0.1:9877/-/healthy` locally on the peer, and check `/status.json` is fresh.
Use the peer's exact `machine_id`; do not copy a profile from another host.

The peer needs an owner-approved **ordinary OpenSSH server**, a dedicated or existing permitted SSH user and
public-key authentication. Allow local TCP forwarding to `127.0.0.1:9877`; restrict the monitoring key/account to
that destination where possible. A tailnet grant to port 22 can also permit other SSH capabilities, so review the
SSH account/key restrictions separately. Keep public cloud firewall TCP 22 closed if you intend tailnet-only SSH;
allow the connection on the Tailscale interface according to your host firewall policy.

The default does not enable Tailscale SSH, Tailscale Serve, Funnel, subnet routes or exit nodes. Tailscale SSH
policies/check-mode prompts are a different authentication setup and are not assumed to work with this unattended
OpenSSH helper. Review existing SSH configuration before changing it.

From the central machine, verify the peer's SSH host-key fingerprint through a trusted independent channel and
enroll it in that central user's `~/.ssh/known_hosts`. Never use `StrictHostKeyChecking=no` or trust unverified
`ssh-keyscan` output. Ensure public-key authentication works without a prompt using the default identity files
or the central user's existing SSH agent. Do not copy private keys into the repository or service templates.

## 3. Open a tunnel on the central machine

First inspect the plan; this command does not connect or write any files and needs no machine profile:

```sh
python3 -I bin/mm tailscale --peer worker.example.ts.net --user worker --dry-run --json
```

Then run it in the foreground:

```sh
python3 -I bin/mm tailscale --peer worker.example.ts.net --user worker
```

The default is `127.0.0.1:19877` on the central machine to `127.0.0.1:9877` on the peer, using `/usr/bin/ssh` on
TCP 22. Choose `--port 19878` for a second peer (valid local ports: 1024..65535). A full `*.ts.net` MagicDNS name,
`100.64.0.0/10` IPv4 address or `fd7a:115c:a1e0::/48` IPv6 address is required. These address checks do not prove
the device is connected to your tailnet; routing, Tailscale policy and the verified SSH host key establish access.

The helper deliberately ignores SSH config files (`-F /dev/null`), proxies, connection sharing and local commands.
It disables agent/X11 forwarding, remote commands and terminals. It requires an already trusted host key, uses
batch authentication, fails on a local bind error, and checks the SSH connection every 15 seconds (three missed
replies end it). It does not run `tailscale up`, collect a status, edit profiles, install services or dispatch jobs.
An interactive/unlocked key may work in your shell but fail in a LaunchAgent or systemd user service; test that
service environment explicitly. No passwords, custom SSH config, jump hosts or alternate SSH ports are supplied
by this default. For other network requirements, use a separately reviewed transport as in MONITORING.md.

Without `--dry-run`, the process becomes SSH: it stays in the foreground without a machine-manager startup line,
Ctrl-C/SIGTERM closes it, SSH diagnostics go to stderr, and the exit code is SSH's (commonly 255 on connection
failure), rather than the normal mm exit-code contract. There is no internal retry loop. `--json` requires
`--dry-run`. A missing executable or invalid helper arguments gives a normal one-line mm error and exit 2.

In another terminal, verify the local forwarded endpoint:

```sh
curl --fail --max-time 5 http://127.0.0.1:19877/-/healthy
curl --fail --max-time 5 http://127.0.0.1:19877/status.json
```

SSH can start a local listener even when the remote endpoint is down. These HTTP checks, followed by source
freshness checks, are required before calling a tunnel ready. The forwarded URL retains the loopback Host header
required by `mm serve`; do not use the tailnet hostname as the HTTP Host header.

In the central profile's **existing** entry for this machine, use:

```toml
[[machines]]
id = "linux-worker"  # must equal the peer's machine_id
status_url = "http://127.0.0.1:19877/status.json"
# Retain the existing explicit kinds, launcher, timeouts and placement limits.
```

This snippet shows the transport fields only; it is not a full placement configuration. Do not add a duplicate
entry or invent a launcher for a monitoring-only peer. The current machine contract also requires explicit kinds
and `start_argv` (see README.md); remote resource-only inventory is not introduced here. Editing a live profile
still requires the owner's instruction. After reviewing the complete entry, run `mm collect` on the central
machine, verify fresh peer metrics, and schedule the existing collector as in MONITORING.md. The helper does not
change `ssh_argv` or authorize remote job dispatch.

## 4. Optional persistent tunnel

Copy one reviewed template **per peer** outside the checkout:

- Linux: [mm-tailscale-PEER.service](monitoring/tailscale/mm-tailscale-PEER.service), installed into
  `~/.config/systemd/user/` under a unique `mm-tailscale-worker.service` name.
- Mac: [org.machine-manager.tailscale.PEER.plist](monitoring/tailscale/org.machine-manager.tailscale.PEER.plist),
  installed into `~/Library/LaunchAgents/` with a matching unique filename and Label.

Replace **all** `/ABS/...`, `PEER`, `TAILNET`, and `SSH_USER` placeholders. Assign a distinct local port and log
paths per peer. Use a durable install path and the intended Python 3.11+ executable. Follow the systemd argv
escaping and XML escaping rules in MONITORING.md. Create the private log directory first. Validate copied units
with `systemd-analyze --user verify` or copied plists with `plutil -lint`. Then, with owner installation authority,
enable/start only these new user units or bootstrap only these new agents. Tunnels retry every 15 seconds after
failure. There is no dependency on a system-wide tailscaled unit, because the Mac and Linux clients differ;
temporary Tailscale unavailability is handled by SSH failure and service retries.

Confirm the service account sees the same verified host keys and usable key/agent as your shell. These services
do not create an agent, unlock keys or bypass authentication. Per-user systemd services may depend on login or
owner-configured lingering; GUI LaunchAgents depend on login. After reboot/login, verify the intended behavior.
To roll back, stop/disable or boot out the exact new tunnel service, remove its reviewed copy, and close its local
port. Leave Tailscale, unrelated tunnels, supervisor/watchdog, settings, queues and monitoring history in place.
Revert a profile URL only if you changed it and have owner authorization. Logs need a retention plan.

## Central dashboard access and acceptance

Prometheus and Grafana remain at `127.0.0.1:9090` and `127.0.0.1:3000` on the central machine. From a viewer
already authorized for SSH to that machine over Tailscale, forward Grafana separately:

```sh
ssh -N -T -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes \
  -L 127.0.0.1:13000:127.0.0.1:3000 -l viewer central.example.ts.net
```

Open `http://127.0.0.1:13000` and sign in with the configured Grafana account. The worker grant fragment does not
grant viewer-to-central access; that requires your own reviewed policy. Keep Grafana authentication enabled.
Do not expose monitoring ports publicly or enable Funnel as part of this setup.

Run `python3 -I tests/run_tests.py tailscale monitoring fleet` plus the full suite and vectors before release.
Fixture tests cover argument boundaries, loopback forwarding, dry-run isolation and native SSH option parsing;
they do not prove Tailscale connectivity. On real Linux/Mac/cloud hosts, verify Tailscale access policy permits
only intended peers, host-key mismatch/missing keys fail closed, HTTP health and source identity/freshness, distinct
ports for multiple peers, actual Prometheus/Grafana readings, tunnel outage/reconnection, service stop/restart,
login/reboot, and expired/revoked device/key behavior. Unavailable peers must become UNKNOWN and then recover.
Confirm forbidden clients cannot reach SSH or monitoring ports and no listener binds publicly. Production queue
actions, external pools and alert delivery remain separate acceptance checks.
