# SPDX-License-Identifier: Apache-2.0
"""machine-manager platform choice (project-free).

PLATFORM is "darwin" (macOS with launchd) or "linux" (Linux with /proc readings and per-user systemd services).
Unsupported platform-specific readings remain unknown. Any other system loads as "linux".
MM_PLATFORM ("darwin" or "linux") replaces the choice: a test hook, like MM_LAUNCHCTL, so the Linux path can
run on a Mac. The backends mmplat_darwin and mmplat_linux carry the same names (readings and command paths); mmread
loads the chosen one (mmread.plat). This module needs nothing but the standard library and loads no backend itself.
"""
import importlib
import os
import sys

NAMES = ("darwin", "linux")


def choose(env=None, system=None):
    """Pure: the platform for an MM_PLATFORM value (a value outside NAMES is ignored) and a sys.platform value."""
    v = os.environ.get("MM_PLATFORM", "") if env is None else env
    if v in NAMES:
        return v
    return "darwin" if (sys.platform if system is None else system) == "darwin" else "linux"


PLATFORM = choose()
DARWIN = PLATFORM == "darwin"


def backend():
    """The backend module of PLATFORM (mmplat_darwin or mmplat_linux)."""
    return importlib.import_module("mmplat_" + PLATFORM)


def default_base(env=None):
    """Where installs live when MM_BASE is not set: macOS ~/Library/Application Support/machine-manager; Linux
    $XDG_DATA_HOME/machine-manager (an absolute XDG_DATA_HOME only), else ~/.local/share/machine-manager."""
    if DARWIN:
        return "~/Library/Application Support/machine-manager"
    xdg = (os.environ if env is None else env).get("XDG_DATA_HOME") or ""
    return os.path.join(xdg if os.path.isabs(xdg) else "~/.local/share", "machine-manager")


def refusal(verb):
    """Compatibility API: both backends implement every verb; runtime prerequisites are checked by each command."""
    return None
