# SPDX-License-Identifier: Apache-2.0
"""Per-user systemd units and bounded control commands. No service is touched at import time.
MM_SYSTEMCTL is the fixture command; real installs use systemctl --user and never sudo.
"""
import os
import re

import mmcore
import mmread


def directory():
    config = os.environ.get("XDG_CONFIG_HOME", "")
    return os.path.join(config if os.path.isabs(config) else os.path.expanduser("~/.config"), "systemd", "user")


def valid_label(label):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,179}", label):
        raise mmcore.MMError("E_PROFILE", "invalid systemd service label", "use letters, digits, dots, - and _")
    return label


def control(*args):
    return mmread.run([os.environ.get("MM_SYSTEMCTL", "systemctl"), "--user", *args], timeout=30)


def quoted(value, exec_word=False):
    value = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    value = value.replace("%", "%%")
    if exec_word:
        value = value.replace("$", "$$")
    return '"' + value + '"'


def command(argv):
    return " ".join(quoted(a, True) for a in argv)


def units(sup, wd, argv, env, interval, timeout):
    """Three unit files. The timer is independent of the supervisor, so it can recover a hung main process."""
    valid_label(sup)
    valid_label(wd)
    environment = "\n".join("Environment=" + quoted(k + "=" + v) for k, v in env.items())
    common = environment + "\nTimeoutStopSec=%ds\n" % timeout
    supervisor = ("[Unit]\nDescription=machine-manager supervisor\nStartLimitIntervalSec=0\n[Service]\nType=simple\n" + common +
                  "ExecStart=" + command(argv + ["run", "--allow-live-slots"]) + "\n" +
                  "ExecStopPost=" + command(argv + ["recover-paused"]) + "\n" +
                  "Restart=always\nRestartSec=10s\nKillMode=control-group\n[Install]\nWantedBy=default.target\n")
    watchdog = ("[Unit]\nDescription=machine-manager watchdog\n[Service]\nType=oneshot\n" + common +
                "ExecStart=" + command(argv + ["watchdog"]) + "\nSuccessExitStatus=1\n")
    timer = ("[Unit]\nDescription=machine-manager watchdog timer\n[Timer]\nOnActiveSec=1s\nOnUnitActiveSec=%ds\n"
             "AccuracySec=1s\nUnit=%s.service\n[Install]\nWantedBy=timers.target\n" % (interval, wd))
    return {sup + ".service": supervisor, wd + ".service": watchdog, wd + ".timer": timer}


def unit(label):
    valid_label(label)
    return label + (".timer" if os.path.isfile(os.path.join(directory(), label + ".timer")) else ".service")


def loaded(label):
    return control("is-active", "--quiet", unit(label))[0] == 0


def start(label):
    return control("enable", "--now", unit(label))[0]


def stop(label):
    target = unit(label)
    rc, _ = control("disable", "--now", target)
    if target.endswith(".timer"):
        other, _ = control("stop", label + ".service")
        return rc if rc else other
    return rc


def restart(label):
    # A watchdog service is oneshot; keep its timer running and trigger a check now.
    target = label + ".service"
    rc, _ = control("restart", target)
    return rc
