# SPDX-License-Identifier: Apache-2.0
"""Explicit foreground OpenSSH transport over an owner-managed tailnet."""
import ipaddress
import os
import re

PORT = 19877
SSH = "/usr/bin/ssh"


def tunnel(peer, user, port=PORT):
    """Return fixed argv and the local URL; no shell, network, credentials or file writes."""
    if not isinstance(peer, str) or len(peer) > 253 or "%" in peer:
        raise ValueError("invalid peer")
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        labels = peer.lower().split(".")
        if len(labels) < 4 or labels[-2:] != ["ts", "net"] or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError("use a full MagicDNS name or Tailscale IP")
    else:
        network = "100.64.0.0/10" if address.version == 4 else "fd7a:115c:a1e0::/48"
        if address not in ipaddress.ip_network(network):
            raise ValueError("use a Tailscale address")
    if not isinstance(user, str) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]{0,63}", user):
        raise ValueError("invalid SSH user")
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("local port must be 1024..65535")
    argv = [SSH, "-F", "/dev/null", "-N", "-T"]
    for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", "ExitOnForwardFailure=yes",
                   "ConnectTimeout=10", "ServerAliveInterval=15", "ServerAliveCountMax=3",
                   "ForwardAgent=no", "ForwardX11=no", "PermitLocalCommand=no", "ProxyCommand=none",
                   "ProxyJump=none", "ControlMaster=no", "ControlPath=none", "GatewayPorts=no"):
        argv += ["-o", option]
    argv += ["-L", "127.0.0.1:%d:127.0.0.1:9877" % port, "-l", user, "--", peer]
    return {"argv": argv, "status_url": "http://127.0.0.1:%d/status.json" % port}


def run(plan):
    # Replace this process: signals and exit status belong to SSH; no orphan tunnel wrapper.
    os.execv(SSH, plan["argv"])
