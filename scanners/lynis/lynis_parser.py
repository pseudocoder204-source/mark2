# SPDX-License-Identifier: GPL-2.0-only
import subprocess
import json
import os
import sys
from typing import List, Dict, Any, Optional

_DEFAULT_REPORT_FILE = "/tmp/lynis-report.dat"

# STAGE 1: AUTOMATED EXECUTION ENGINE

# Default hard timeout (seconds) for the lynis subprocess. A hung audit was a latent
# production hang with no prior bound — every worker must fail bounded, not hang.
DEFAULT_LYNIS_TIMEOUT = 300

def run_lynis_audit(report_file: str = _DEFAULT_REPORT_FILE, timeout: int = DEFAULT_LYNIS_TIMEOUT) -> str:
    """
    Kicks off a Lynis system security audit via the terminal and captures the
    machine-readable report file as a raw string for downstream parsing.
    """
    print("[*] Launching Lynis system security audit...")

    command = [
        "lynis", "audit", "system",
        "--quick",          # suppress interactive prompts
        "--no-colors",      # strip ANSI codes from log output
        "--report-file", report_file,
    ]

    try:
        subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,   # lynis exits non-zero when warnings are present; don't raise
            timeout=timeout,
        )

        with open(report_file, "r") as fh:
            return fh.read()

    except FileNotFoundError:
        print("[!] Error: The 'lynis' binary is not installed on this host node.", file=sys.stderr)
        return ""
    except subprocess.TimeoutExpired:
        print(f"[!] Lynis audit exceeded the {timeout}s timeout and was killed.", file=sys.stderr)
        return ""
    except OSError as e:
        print(f"[!] Could not read Lynis report file '{report_file}': {e}", file=sys.stderr)
        return ""
    except Exception as e:
        print(f"[!] Unexpected system crash: {e}", file=sys.stderr)
        return ""


# STAGE 2: REPORT FILE PARSER

def _parse_pipe_fields(raw: str) -> Dict[str, str]:
    """
    Splits a pipe-delimited Lynis entry into its four named fields.
    Format: TEST_ID|description|details|solution|
    Trailing empty segments after the last pipe are ignored.
    """
    parts = [p.strip() for p in raw.split("|")]
    return {
        "test_id":     parts[0] if len(parts) > 0 else "UNKNOWN",
        "description": parts[1] if len(parts) > 1 else "",
        "details":     parts[2] if len(parts) > 2 else "",
        "solution":    parts[3] if len(parts) > 3 else "",
    }


def parse_lynis_report(report_content: str) -> Dict[str, Any]:
    """
    Parses the Lynis key=value report file into structured Python dicts.
    Collects warning[] and suggestion[] arrays and extracts key metadata fields.
    """
    warnings    = []
    suggestions = []
    metadata    = {}

    _META_KEYS = {
        "hardening_index", "lynis_version",
        "os", "os_name", "os_version", "hostname",
    }

    for line in report_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key   = key.strip()
        value = value.strip()

        if key == "warning[]":
            warnings.append(_parse_pipe_fields(value))
        elif key == "suggestion[]":
            suggestions.append(_parse_pipe_fields(value))
        elif key in _META_KEYS:
            metadata[key] = value

    return {
        "metadata":    metadata,
        "warnings":    warnings,
        "suggestions": suggestions,
    }


# STAGE 3: CLEAN TEXT TRUNCATION ENGINE

def clean_truncate_description(text_block: str, max_chars: int = 400) -> str:
    """
    Safely cuts long security text blocks down so they never end in
    the middle of a word, keeping data clean for the LLM prompt.
    """
    if not text_block or len(text_block) <= max_chars:
        return text_block

    raw_cut   = text_block[:max_chars]
    clean_cut = raw_cut.rsplit(" ", 1)[0]
    return clean_cut


# STAGE 4: THE LLM CONDENSING AND ENRICHMENT LAYER

_SEVERITY_ORDER = {"HIGH": 2, "MEDIUM": 1}


def build_llm_payload_from_lynis(parsed_report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Takes a parsed Lynis report, calculates summary statistics, ranks findings
    by severity, and isolates the top 10 worst issues to protect LLM context windows.

    Severity mapping:
      warning[]    → HIGH   (Lynis detected an active security problem)
      suggestion[] → MEDIUM (Lynis recommends a hardening improvement)
    """
    warnings    = parsed_report.get("warnings", [])
    suggestions = parsed_report.get("suggestions", [])
    metadata    = parsed_report.get("metadata", {})

    high_count   = len(warnings)
    medium_count = len(suggestions)

    priority_findings: List[Dict[str, Any]] = []

    for w in warnings:
        priority_findings.append({
            "test_id":     w["test_id"],
            "severity":    "HIGH",
            "description": clean_truncate_description(w["description"]),
            "details":     clean_truncate_description(w["details"]),
            "solution":    clean_truncate_description(w["solution"]),
        })

    for s in suggestions:
        priority_findings.append({
            "test_id":     s["test_id"],
            "severity":    "MEDIUM",
            "description": clean_truncate_description(s["description"]),
            "details":     clean_truncate_description(s["details"]),
            "solution":    clean_truncate_description(s["solution"]),
        })

    priority_findings.sort(
        key=lambda x: _SEVERITY_ORDER.get(x["severity"], 0),
        reverse=True,
    )

    hardening_index: Optional[int] = None
    try:
        hardening_index = int(metadata.get("hardening_index", ""))
    except (ValueError, TypeError):
        pass

    os_label = metadata.get("os_name") or metadata.get("os", "unknown")

    return {
        "scan_target":     metadata.get("hostname", "localhost"),
        "lynis_version":   metadata.get("lynis_version", "unknown"),
        "os":              os_label,
        # hardening_index is 0-100; higher = more hardened
        "hardening_index": hardening_index,
        "risk_summary": {
            "critical_count":   0,           # Lynis has no CRITICAL tier
            "high_count":       high_count,
            "medium_count":     medium_count,
            "low_count":        0,           # Lynis has no LOW tier
            "total_actionable": high_count + medium_count,
        },
        # Slice to protect token budget — top 10 by severity
        "priority_findings": priority_findings[:10],
    }


def main():
    report_file  = os.environ.get("LYNIS_REPORT_FILE", _DEFAULT_REPORT_FILE)
    report_content = run_lynis_audit(report_file=report_file)

    if not report_content:
        print("[!] Pipeline aborted. No scan data captured.", file=sys.stderr)
        sys.exit(1)

    parsed_report     = parse_lynis_report(report_content)
    llm_ready_payload = build_llm_payload_from_lynis(parsed_report)
    print(json.dumps(llm_ready_payload, indent=2))


if __name__ == "__main__":
    main()