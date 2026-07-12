# SPDX-License-Identifier: GPL-2.0-only
"""
Tool registry for the mark2 security agent (LangChain edition).

Each tool is decorated with @tool so LangGraph can bind it directly to the LLM.
The docstring becomes the tool description sent to the model.

Each tool delegates to its own compiled LangGraph subgraph so the full
multi-stage pipeline is graph-managed end-to-end.

TOOLS — list passed to create_react_agent / llm.bind_tools()
"""
import json
import os
import platform
import re
import time
from typing import Any

from langchain_core.tools import tool

_DB_PATH = os.environ.get("DB_PATH", "vulnerability_cache.db")
_CLAMAV_MANIFEST_DB = os.environ.get("CLAMAV_MANIFEST_DB", "clamav_manifest.db")


def _is_windows() -> bool:
    return platform.system() == "Windows"


def sync_nmap_db() -> None:
    """Run the nmap subgraph's DB init + NVD sync once.

    Not an @tool — this is called explicitly by agent.py's worker spine, once,
    before scan_network/scan_iot_defaults/discover_hosts run, so those calls can
    pass skip_sync=True instead of each re-syncing the NVD cache. Raises
    RuntimeError if the DB is unavailable/sync fails; callers should treat that
    the same as an "unavailable" nmap tool result.
    """
    from nmap_subgraph import run_db_sync
    run_db_sync(db_path=_DB_PATH)


@tool
def scan_network(target: str) -> str:
    """Scan a target IP address or hostname for open network ports and running
    services, then look up known CVE vulnerabilities for each service in the
    local database. Use this first to get a picture of what is exposed on the network."""
    if not re.match(r"^[\w.\-/]+$", target):
        raise ValueError(f"Invalid target format: {target!r}")
    from nmap_subgraph import run_pipeline as nmap_run_pipeline
    try:
        payload = nmap_run_pipeline(target, db_path=_DB_PATH)
    except RuntimeError as exc:
        return json.dumps({
            "status": "unavailable",
            "reason": str(exc),
        })
    return json.dumps(payload)


def _scan_network_no_sync(target: str) -> str:
    """Fast-path used by agent.py's spine: assumes sync_nmap_db() already ran."""
    if not re.match(r"^[\w.\-/]+$", target):
        raise ValueError(f"Invalid target format: {target!r}")
    from nmap_subgraph import run_pipeline as nmap_run_pipeline
    try:
        payload = nmap_run_pipeline(target, db_path=_DB_PATH, skip_sync=True)
    except RuntimeError as exc:
        return json.dumps({
            "status": "unavailable",
            "reason": str(exc),
        })
    return json.dumps(payload)


@tool
def discover_hosts(target: str) -> str:
    """Discover devices on the local network (host discovery / 'who's on my Wi-Fi').
    Takes an IP or CIDR range (e.g. '192.168.1.0/24') and returns a list of hosts that
    are up, keyed by MAC address, with vendor and hostname where available. Does not
    scan ports. Use this to inventory devices on the network before deeper scanning."""
    if not re.match(r"^[\w.\-/]+$", target):
        raise ValueError(f"Invalid target format: {target!r}")
    from nmap_subgraph import run_pipeline as nmap_run_pipeline
    try:
        payload = nmap_run_pipeline(target, scan_type="host_discovery", db_path=_DB_PATH)
    except RuntimeError as exc:
        return json.dumps({
            "status": "unavailable",
            "reason": str(exc),
        })
    return json.dumps(payload)


@tool
def scan_iot_defaults(target: str) -> str:
    """Check a target IP or hostname for default/factory credentials and open UPnP or
    SNMP exposure — the most common real-world weakness on home routers, cameras, and
    other IoT devices. Runs Nmap's http-default-accounts, upnp-info, and snmp-info
    scripts. Use this on devices that look like routers/IoT gear from discover_hosts
    or scan_network."""
    if not re.match(r"^[\w.\-/]+$", target):
        raise ValueError(f"Invalid target format: {target!r}")
    from nmap_subgraph import run_pipeline as nmap_run_pipeline
    try:
        payload = nmap_run_pipeline(target, scan_type="iot_default_creds", db_path=_DB_PATH)
    except RuntimeError as exc:
        return json.dumps({
            "status": "unavailable",
            "reason": str(exc),
        })
    return json.dumps(payload)


def _scan_iot_defaults_no_sync(target: str) -> str:
    """Fast-path used by agent.py's spine: assumes sync_nmap_db() already ran."""
    if not re.match(r"^[\w.\-/]+$", target):
        raise ValueError(f"Invalid target format: {target!r}")
    from nmap_subgraph import run_pipeline as nmap_run_pipeline
    try:
        payload = nmap_run_pipeline(target, scan_type="iot_default_creds", db_path=_DB_PATH, skip_sync=True)
    except RuntimeError as exc:
        return json.dumps({
            "status": "unavailable",
            "reason": str(exc),
        })
    return json.dumps(payload)


@tool
def scan_filesystem() -> str:
    """Run a Trivy vulnerability scan on the local machine's filesystem.
    Finds known vulnerabilities in installed OS packages and software libraries.
    Use this to detect outdated or insecure software on the host."""
    # Trivy's fs mode reads Linux package DBs (dpkg/rpm/apk), which don't exist on
    # Windows — there it would only match language-manifest deps after crawling all of
    # C:\ (slow, near-empty for non-developers). OS-patch state on Windows is covered by
    # the Windows-Update check in windows_audit instead, so we skip Trivy entirely.
    if _is_windows():
        return json.dumps({
            "status": "skipped",
            "reason": "trivy not applicable on Windows (no OS package DB); "
                      "OS patch state is covered by the host audit's Windows Update check",
        })
    from trivy_subgraph import run_pipeline as trivy_run_pipeline
    try:
        payload = trivy_run_pipeline()
    except RuntimeError:
        return json.dumps({
            "status": "unavailable",
            "reason": "trivy not installed or returned no data",
        })
    if not payload:
        return json.dumps({
            "status": "unavailable",
            "reason": "trivy not installed or returned no data",
        })
    return json.dumps(payload)


@tool
def lookup_cves(cpe: str) -> str:
    """Look up detailed CVE vulnerability records for a specific product using its
    CPE identifier. Use this to investigate a specific service found during a network
    scan when it shows a high risk score or critical vulnerabilities."""
    from nmap_parser import fetch_cves_from_local_cache
    return json.dumps(fetch_cves_from_local_cache(cpe, db_path=_DB_PATH))


@tool
def scan_web(target: str) -> str:
    """Run a Nuclei web and network vulnerability scan against a target IP or hostname.
    Uses a large library of security templates to detect misconfigurations, exposed
    admin panels, default credentials, outdated software, and known CVEs on web services.
    Use this to check what vulnerabilities are exposed on the target's web-facing services."""
    if not re.match(r"^[\w.\-/:]+$", target):
        raise ValueError(f"Invalid target format: {target!r}")
    from nuclei_subgraph import run_pipeline as nuclei_run_pipeline
    try:
        payload = nuclei_run_pipeline(target=target)
    except RuntimeError:
        return json.dumps({
            "status": "unavailable",
            "reason": "nuclei not installed or returned no findings",
        })
    return json.dumps(payload)


@tool
def audit_host() -> str:
    """Run a Lynis security audit on the local machine. Checks system hardening settings,
    authentication configuration, SSH settings, kernel parameters, installed software,
    file permissions, and other host-based security controls. Returns a hardening index
    score and a list of warnings and improvement suggestions.
    Use this to assess the security configuration of the host itself."""
    # Lynis has no Windows port; on Windows the equivalent host-hardening audit runs via
    # PowerShell (windows_audit_subgraph), emitting the same host_audit payload contract.
    if _is_windows():
        from windows_audit_subgraph import run_pipeline as _run_pipeline
        tool_name = "windows audit (PowerShell)"
    else:
        from lynis_subgraph import run_pipeline as _run_pipeline
        tool_name = "lynis"
    try:
        payload = _run_pipeline()
    except RuntimeError:
        return json.dumps({
            "status": "unavailable",
            "reason": f"{tool_name} not available or audit returned no data",
        })
    if not payload:
        return json.dumps({
            "status": "unavailable",
            "reason": f"{tool_name} not available or audit returned no data",
        })
    return json.dumps(payload)


@tool
def scan_malware() -> str:
    """Run a ClamAV antivirus scan across the local machine's high-risk directories
    (home, tmp, opt, srv, root, var/www). Detects known malware, trojans, and other
    infected files by signature. Uses an incremental manifest so repeat runs only
    rescan changed files, with a full rescan forced monthly. Use this to answer
    'am I infected?' — the one question none of the other scanners cover."""
    # On Windows we read Defender's own threat history instead of running ClamAV — every
    # Windows host already has Defender, and the query is instant (see windows_defender_parser).
    if _is_windows():
        from windows_defender_parser import query_defender_malware
        payload = query_defender_malware()
        if payload is None:
            return json.dumps({
                "status": "unavailable",
                "reason": "Windows Defender threat history not available on this host",
            })
        return json.dumps(payload)
    from clamav_subgraph import run_pipeline as clamav_run_pipeline
    try:
        payload = clamav_run_pipeline()
    except RuntimeError as exc:
        return json.dumps({
            "status": "unavailable",
            "reason": str(exc),
        })
    if not payload:
        return json.dumps({
            "status": "unavailable",
            "reason": "clamscan not installed or scan returned no data",
        })
    return json.dumps(payload)


def get_last_malware_result() -> Any:
    """Reads the most recently completed ClamAV scan out of the shared result
    store instead of running a scan. This is what agent.py's deterministic spine
    calls for the 'malware' stage — a full scan can take 1-4+ hours, so the
    spine must never block on a live clamscan invocation. The actual scan runs
    out-of-band (cron/systemd timer/manual `python3 clamav_subgraph.py` run);
    every completed run updates the store via clamav_parser.save_last_result.

    Not decorated with @tool: unlike scan_malware, this isn't a choice the LLM
    should get to make (live scan vs. cached read) — the spine always reads
    the cache, full stop.

    Windows exception: there is no hours-long scan to decouple from — Defender's
    threat history is queried live and instantly, so the spine reads it directly
    (the ClamAV producer/consumer split exists only to avoid blocking on clamscan).
    """
    if _is_windows():
        from windows_defender_parser import query_defender_malware
        payload = query_defender_malware()
        if payload is None:
            return {
                "status": "pending",
                "reason": "Windows Defender threat history not available on this host",
            }
        payload["scanned_at"] = time.time()
        payload["scan_age_hours"] = 0.0
        return payload

    from clamav_parser import load_last_result
    result = load_last_result(_CLAMAV_MANIFEST_DB)
    if result is None:
        return {
            "status": "pending",
            "reason": "no ClamAV scan has completed yet — the first scan can take "
                      "1-4+ hours; run `python3 clamav_subgraph.py` (or schedule it "
                      "via cron/systemd) to populate results",
        }
    payload = dict(result["payload"])
    age_seconds = time.time() - result["completed_at"]
    payload["scanned_at"] = result["completed_at"]
    payload["scan_age_hours"] = round(age_seconds / 3600, 1)
    return payload


TOOLS = [
    discover_hosts,
    scan_network,
    scan_iot_defaults,
    scan_filesystem,
    lookup_cves,
    scan_web,
    audit_host,
    scan_malware,
]
