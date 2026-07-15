# SPDX-License-Identifier: GPL-2.0-only
"""windows_defender_parser.py — malware source for Windows, in place of ClamAV.

On Windows the malware stage does not ship/run ClamAV: every Windows box already runs
Microsoft Defender, so a second full-disk signature scan is redundant, slow, and risks
Defender quarantining ClamAV's own signature DB. Instead this module reads Defender's own
threat-detection history (Get-MpThreatDetection joined to Get-MpThreat for names and
severity) and maps it onto the *same* malware payload contract build_findings_table
consumes (agent.py malware branch): priority_findings of {file_path, signature, severity}.

Because the Defender query is effectively instant (unlike a multi-hour clamscan), the
ClamAV producer/consumer decoupling does NOT apply here — this runs live on the spine.

An empty detection history is genuine good news (Defender ran, found nothing) and yields
an empty priority_findings list — distinct from Defender being unavailable, which the
subgraph/tools layer surfaces as a status instead.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, Dict, List, Optional

from ..bin_resolver import resolve as _resolve_bin

# Default hard timeout (seconds) for the Defender query subprocess.
DEFAULT_DEFENDER_TIMEOUT = 60

# Defender SeverityID → our HIGH/MEDIUM/LOW buckets. 5=Severe, 4=High, 2=Moderate, 1=Low.
_SEVERITY_ID_MAP = {5: "HIGH", 4: "HIGH", 2: "MEDIUM", 1: "LOW"}
_SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ── STAGE 1: query Defender's threat history ───────────────────────────────────

_DEFENDER_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$threats = @{}
Get-MpThreat | ForEach-Object { $threats[$_.ThreatID.ToString()] = @{ name = $_.ThreatName; sev = [int]$_.SeverityID } }
$out = @()
foreach ($d in Get-MpThreatDetection) {
    $tid  = $d.ThreatID.ToString()
    $meta = $threats[$tid]
    $name = if ($meta) { $meta.name } else { "ThreatID $tid" }
    $sev  = if ($meta) { $meta.sev } else { 0 }
    $res  = $d.Resources
    if (-not $res) { $res = @('unknown') }
    foreach ($r in $res) {
        $out += [ordered]@{
            file_path   = ($r -replace '^file:_','')
            signature   = $name
            severity_id = [int]$sev
        }
    }
}
$status = Get-MpComputerStatus
[ordered]@{
    detections       = $out
    engine_available = [bool]$status
    realtime         = if ($status) { [bool]$status.RealTimeProtectionEnabled } else { $null }
} | ConvertTo-Json -Depth 4 -Compress
"""


def run_defender_query(timeout: int = DEFAULT_DEFENDER_TIMEOUT) -> str:
    """Query Defender's threat history via PowerShell; return raw JSON ('' on failure)."""
    print("[*] Querying Windows Defender threat history...")
    command = [
        _resolve_bin("powershell"),
        "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", _DEFENDER_PS_SCRIPT,
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=timeout,
        )
        return result.stdout.strip()
    except FileNotFoundError:
        print("[!] 'powershell' not found — Defender query only runs on Windows.", file=sys.stderr)
        return ""
    except subprocess.TimeoutExpired:
        print(f"[!] Defender query exceeded the {timeout}s timeout and was killed.", file=sys.stderr)
        return ""
    except Exception as e:
        print(f"[!] Unexpected crash during Defender query: {e}", file=sys.stderr)
        return ""


# ── STAGE 2: parse ─────────────────────────────────────────────────────────────

def parse_defender_output(raw_json: str) -> Dict[str, Any]:
    """Parse the Defender JSON. Normalizes the single-detection PowerShell array quirk."""
    if not raw_json:
        return {}
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    dets = data.get("detections")
    if isinstance(dets, dict):        # ConvertTo-Json collapses a 1-element array to an object
        data["detections"] = [dets]
    elif dets is None:
        data["detections"] = []
    return data


# ── STAGE 3: build the malware payload (matches ClamAV's contract) ─────────────

def build_llm_payload_from_defender(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Map Defender detections onto the malware priority_findings contract."""
    detections: List[Dict[str, Any]] = parsed.get("detections", []) or []

    priority_findings: List[Dict[str, str]] = []
    for d in detections:
        severity = _SEVERITY_ID_MAP.get(int(d.get("severity_id", 0) or 0), "MEDIUM")
        priority_findings.append({
            "file_path": d.get("file_path", "unknown"),
            "signature": d.get("signature", "unknown"),
            "severity":  severity,
        })

    priority_findings.sort(key=lambda x: _SEVERITY_ORDER.get(x["severity"], 0), reverse=True)

    high_count   = sum(1 for f in priority_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in priority_findings if f["severity"] == "MEDIUM")
    low_count    = sum(1 for f in priority_findings if f["severity"] == "LOW")

    return {
        "scan_target": "local host (Windows Defender threat history)",
        "engine":      "Windows Defender",
        "scan_mode":   "history",
        "risk_summary": {
            "critical_count":   0,
            "high_count":       high_count,
            "medium_count":     medium_count,
            "low_count":        low_count,
            "total_actionable": len(priority_findings),
            "infected_files":   len(priority_findings),
        },
        "priority_findings": priority_findings[:10],
    }


def query_defender_malware(timeout: int = DEFAULT_DEFENDER_TIMEOUT) -> Optional[Dict[str, Any]]:
    """Full run→parse→build. Returns the payload, or None if Defender is unavailable
    (not Windows / cmdlets missing) so callers can surface a status instead of a scan."""
    raw = run_defender_query(timeout=timeout)
    parsed = parse_defender_output(raw)
    if not parsed or not parsed.get("engine_available"):
        return None
    return build_llm_payload_from_defender(parsed)


def main():
    payload = query_defender_malware()
    if payload is None:
        print(json.dumps({"status": "unavailable",
                          "reason": "Windows Defender not available on this host"}, indent=2))
        return
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
