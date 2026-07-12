# SPDX-License-Identifier: GPL-2.0-only
import glob
import subprocess
import json
import os
import sys
import time
import re
from typing import List, Dict, Any, Optional

from bin_resolver import resolve as _resolve_bin

#STAGE 1: AUTOMATED EXECUTION ENGINE

# Default hard timeout (seconds) for the trivy subprocess. A hung scan was a latent
# production hang with no prior bound — every worker must fail bounded, not hang.
DEFAULT_TRIVY_TIMEOUT = 300

# Pseudo-filesystems and noisy mount points that contain no real packages/lockfiles —
# walking them wastes most of a scan's time without ever surfacing a finding.
_SKIP_DIRS = [
    "/proc", "/sys", "/dev", "/run", "/snap",
    "/mnt", "/media", "/lost+found",
    "/var/lib/docker", "/var/lib/containerd",
]

# Directory name patterns that are enormous but never contain OS packages or
# lockfiles worth re-parsing (dependency trees already reported via their
# top-level lockfile). Trivy's --skip-dirs accepts glob patterns.
_SKIP_DIR_PATTERNS = [
    "**/.cache", "**/.git", "**/node_modules", "**/__pycache__",
    "**/.venv", "**/venv", "**/.tox", "**/.mypy_cache", "**/.pytest_cache",
]

# How old (hours) Trivy's local vulnerability DB can be before we bother
# triggering a re-download — mirrors clamav_parser.py's freshclam skip so a
# scan doesn't pay a network fetch on every single invocation.
_TRIVY_DB_MAX_AGE_HOURS = 24


def _trivy_cache_dir() -> str:
    return os.environ.get("TRIVY_CACHE_DIR") or os.path.expanduser("~/.cache/trivy")


def _trivy_db_is_fresh(max_age_hours: int = _TRIVY_DB_MAX_AGE_HOURS) -> bool:
    db_files = glob.glob(os.path.join(_trivy_cache_dir(), "db", "*"))
    if not db_files:
        return False
    newest_mtime = max(os.path.getmtime(p) for p in db_files)
    return (time.time() - newest_mtime) / 3600 < max_age_hours


def run_local_trivy_scan(
    timeout: int = DEFAULT_TRIVY_TIMEOUT,
    scan_target: str = "/",
    skip_dirs: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Kicks off a local open-source Trivy vulnerability audit (like a checklist) via the terminal
    and streams the results directly into system memory as JSON payload.

    Scoped like clamav_parser.py's clamscan invocation: noisy/irrelevant
    directories are excluded via --skip-dirs, the scan is restricted to the
    vuln scanner only (skipping secret/misconfig/license passes that don't
    matter for this pipeline), and a fresh local DB skips the network
    re-download — all in service of finishing inside `timeout` instead of a
    full unscoped "/" walk blowing past it.
    """
    print(f"[*] Launching localized open-source Trivy vulnerability scanner...")

    exclude_flags: List[str] = []
    for d in _SKIP_DIRS:
        exclude_flags += ["--skip-dirs", d]
    for pattern in (skip_dirs or _SKIP_DIR_PATTERNS):
        exclude_flags += ["--skip-dirs", pattern]

    command = (
        [_resolve_bin("trivy"), "fs", scan_target,
         "--format", "json", "--quiet",
         "--scanners", "vuln",
         # Trivy's own internal timeout — leaves a few seconds of margin so
         # trivy can flush partial JSON before the subprocess-level timeout
         # below would otherwise SIGKILL it mid-write.
         "--timeout", f"{max(timeout - 10, 10)}s"]
        + exclude_flags
    )
    if _trivy_db_is_fresh():
        print("[*] Trivy vulnerability DB is up-to-date — skipping DB update.", file=sys.stderr)
        command.append("--skip-db-update")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        )

        parsed_json = json.loads(result.stdout)
        return parsed_json.get("Results", [])

    except FileNotFoundError:
        print("[!] Error: The 'trivy' binary is not installed on this host node.", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"[!] Trivy scan exceeded the {timeout}s timeout and was killed.", file=sys.stderr)
        return []
    except subprocess.CalledProcessError as e:
        print(f"[!] Scanner failed during execution. Error details: {e.stderr}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Unexpected system crash: {e}", file=sys.stderr)
        return []
    
#STAGE 2: CLEAN TEXT TRUNCATION ENGINE
def clean_truncate_description(text_block: str, max_chars: int = 400) -> str:
    """
    Safely cuts long security text blocks down so they never end in 
    the middle of a word, keeping data clean for the LLM prompt
    """

    if not text_block or len(text_block) <= max_chars:
        return text_block

    raw_cut  = text_block[:max_chars]
    clean_cut = raw_cut.rsplit(' ', 1)[0]
    return f"{clean_cut}"

#STAGE 3: THE LLM CONDENSING AND ENRICHMENT LAYER

def build_llm_payload_from_trivy(trivy_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Takes raw Trivy outputs, calculates summary statistics, ranks threats,
    and isolates the top 10 worst bugs to protect LLM context windows.
    """
    priority_findings = []
    
    # Initialize metrics for overall risk scoring
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for target in trivy_results:
        vulnerabilities = target.get("Vulnerabilities", [])
        for v in vulnerabilities:
            severity = v.get("Severity", "UNKNOWN")
            
            # Aggregate total counts for our enriched metrics block
            if severity == "CRITICAL": critical_count += 1
            elif severity == "HIGH": high_count += 1
            elif severity == "MEDIUM": medium_count += 1
            elif severity == "LOW": low_count += 1

            # Noise Filter: Drop low and unknown vulnerabilities to save token space
            if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
                entry = {
                    "cve_id": v.get("VulnerabilityID", "UNKNOWN-CVE"),
                    "package": v.get("PkgName", "Unknown Package"),
                    "installed_version": v.get("InstalledVersion", "N/A"),
                    "fixed_version": v.get("FixedVersion", "No Patch Available"),
                    "severity": severity,
                    "title": v.get("Title", "No title metadata available."),
                    # Apply our optimized text truncation method here
                    "description": clean_truncate_description(v.get("Description", ""))
                }
                priority_findings.append(entry)

    # Sort all findings mathematically so CRITICAL and HIGH issues float to the top
    severity_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
    priority_findings.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)

    # Compile the final optimized structure
    return {
        "host_node": "production_target_host",
        "risk_summary": {
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "total_actionable": len(priority_findings)
        },
        # Slice the array down to protect token limitations
        "priority_findings": priority_findings[:10]
    }

def main():
    # 1. Run the local open-source scanner engine
    raw_scan_data = run_local_trivy_scan()

    if not raw_scan_data:
        print("[!] Pipeline aborted. No scan data captured.", file=sys.stderr)
        sys.exit(1)

    # 2. Package and condense the dataset for your LLM context window
    llm_ready_payload = build_llm_payload_from_trivy(raw_scan_data)

    # 3. Output clean, production-grade JSON
    print(json.dumps(llm_ready_payload, indent=2))


if __name__ == "__main__":
    main()