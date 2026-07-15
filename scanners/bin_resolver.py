# SPDX-License-Identifier: GPL-2.0-only
"""bin_resolver.py — locate external scanner binaries across platforms + elevation check.

Mark2 shells out to nmap/nuclei/trivy/clamscan/lynis by bare name, relying on $PATH.
That relied-on-PATH assumption breaks the "plug-and-play" story on Windows, where a
bundled install won't necessarily be on PATH. resolve() gives every parser one
overridable way to find its binary:

    1. explicit env-var override  (NMAP_BINARY, NUCLEI_BINARY, TRIVY_BINARY, ...)
    2. a bundled binaries dir (MARK2_BIN_DIR, else ./bin at the repo root), where a
       packaged Windows build drops nmap.exe / nuclei.exe / trivy.exe / etc.
    3. the tool name as-is → subprocess falls back to a PATH lookup (unchanged behavior)

is_elevated() reports whether we run with the privileges several scans need — raw-socket
nmap and Administrator-gated PowerShell audit checks on Windows, root on Unix. It is
best-effort and never raises.
"""
from __future__ import annotations

import os
import shutil
import sys


def _env_var_for(tool: str) -> str:
    """nmap -> NMAP_BINARY, http-x -> HTTP_X_BINARY."""
    return f"{tool.upper().replace('-', '_')}_BINARY"


def _bundled_dir() -> str:
    override = os.environ.get("MARK2_BIN_DIR")
    if override:
        return override
    # bin_resolver.py lives in scanners/; the bundled bin/ dir is next to the repo
    # root (one level up), not next to this file, so this stays the same physical
    # location (repo_root/bin) regardless of which package the resolver sits in.
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")


def resolve(tool: str) -> str:
    """Return the command to invoke `tool`. Precedence: env override → bundled dir → PATH.

    Always returns a string; on total miss it returns the bare tool name so the caller's
    existing FileNotFoundError handling still fires exactly as before.
    """
    override = os.environ.get(_env_var_for(tool))
    if override:
        return override

    exe = f"{tool}.exe" if sys.platform.startswith("win") else tool
    candidate = os.path.join(_bundled_dir(), exe)
    if os.path.isfile(candidate):
        return candidate

    return shutil.which(exe) or shutil.which(tool) or tool


def is_elevated() -> bool:
    """True if the process has admin/root privileges. Best-effort; never raises."""
    if sys.platform.startswith("win"):
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
