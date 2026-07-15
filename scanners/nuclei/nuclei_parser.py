# SPDX-License-Identifier: GPL-2.0-only
import subprocess
import json
import os
import sys
from typing import List, Dict, Any, Optional

from ..bin_resolver import resolve as _resolve_bin

# STAGE 1: AUTOMATED EXECUTION ENGINE

# Default hard timeout (seconds) for the nuclei subprocess. A hung scan was a latent
# production hang with no prior bound — every worker must fail bounded, not hang.
DEFAULT_NUCLEI_TIMEOUT = 300

def run_nuclei_scan(target: str, templates: Optional[str] = None, timeout: int = DEFAULT_NUCLEI_TIMEOUT) -> List[Dict[str, Any]]:
    """
    Launches a Nuclei scan against the target and streams JSONL results into memory.
    Nuclei outputs one JSON object per matched finding on stdout with -json.
    """
    print(f"[*] Launching Nuclei vulnerability scanner against {target}...")

    command = [_resolve_bin("nuclei"), "-u", target, "-jsonl", "-silent"]
    if templates:
        command += ["-t", templates]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,  # nuclei exits non-zero when findings exist; don't raise
            timeout=timeout,
        )

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip malformed lines (e.g. progress output)

        return findings

    except FileNotFoundError:
        print("[!] Error: The 'nuclei' binary is not installed on this host node.", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"[!] Nuclei scan of {target!r} exceeded the {timeout}s timeout and was killed.", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Unexpected system crash: {e}", file=sys.stderr)
        return []


# STAGE 2: CLEAN TEXT TRUNCATION ENGINE

def clean_truncate_description(text_block: str, max_chars: int = 400) -> str:
    """
    Safely cuts long security text blocks down so they never end in
    the middle of a word, keeping data clean for the LLM prompt.
    """
    if not text_block or len(text_block) <= max_chars:
        return text_block

    raw_cut   = text_block[:max_chars]
    clean_cut = raw_cut.rsplit(' ', 1)[0]
    return clean_cut


# STAGE 3: THE LLM CONDENSING AND ENRICHMENT LAYER

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def build_llm_payload_from_nuclei(
    raw_findings: List[Dict[str, Any]],
    target: str = "unknown"
) -> Dict[str, Any]:
    """
    Takes raw Nuclei JSONL findings, calculates summary statistics, ranks threats,
    and isolates the top 10 worst issues to protect LLM context windows.
    """
    critical_count = 0
    high_count     = 0
    medium_count   = 0
    low_count      = 0
    info_count     = 0

    priority_findings = []

    for finding in raw_findings:
        info     = finding.get("info", {})
        severity = info.get("severity", "unknown").upper()

        if severity == "CRITICAL":   critical_count += 1
        elif severity == "HIGH":     high_count     += 1
        elif severity == "MEDIUM":   medium_count   += 1
        elif severity == "LOW":      low_count      += 1
        elif severity == "INFO":     info_count     += 1

        # Noise filter: drop INFO-level findings to save token space
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            continue

        classification = info.get("classification", {})
        cve_id    = classification.get("cve-id") or None
        cvss_score = classification.get("cvss-score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
            except (TypeError, ValueError):
                cvss_score = None

        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]

        entry = {
            "template_id":  finding.get("template-id", "unknown"),
            "name":         info.get("name", "Unknown Finding"),
            "severity":     severity,
            "host":         finding.get("host", target),
            "matched_at":   finding.get("matched-at", ""),
            "cve_id":       cve_id,
            "cvss_score":   cvss_score,
            "description":  clean_truncate_description(info.get("description", "")),
            "references":   references[:3]  # cap to limit LLM token cost
        }
        priority_findings.append(entry)

    # Sort so CRITICAL floats to the top, then by CVSS score within each band
    priority_findings.sort(
        key=lambda x: (_SEVERITY_ORDER.get(x["severity"], 0), x["cvss_score"] or 0.0),
        reverse=True
    )

    return {
        "scan_target": target,
        "risk_summary": {
            "critical_count":  critical_count,
            "high_count":      high_count,
            "medium_count":    medium_count,
            "low_count":       low_count,
            "info_count":      info_count,
            "total_actionable": len(priority_findings)
        },
        "priority_findings": priority_findings[:10]
    }


def main():
    target    = os.environ.get("TARGET", "127.0.0.1")
    templates = os.environ.get("NUCLEI_TEMPLATES")  # optional path override

    raw_findings = run_nuclei_scan(target=target, templates=templates)

    if not raw_findings:
        print("[!] Pipeline aborted. No scan data captured.", file=sys.stderr)
        sys.exit(1)

    llm_ready_payload = build_llm_payload_from_nuclei(raw_findings=raw_findings, target=target)
    print(json.dumps(llm_ready_payload, indent=2))


if __name__ == "__main__":
    main()
