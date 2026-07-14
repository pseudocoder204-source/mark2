# SPDX-License-Identifier: GPL-2.0-only
"""windows_audit_parser.py — Windows host-hardening audit, Lynis's Windows counterpart.

Lynis has no Windows port (it audits the Unix kernel/service config), so on Windows the
`host_audit` stage of agent.py's spine uses this module instead. It produces the *exact
same* payload contract build_findings_table consumes (agent.py host_audit branch):

    {
      "scan_target": <hostname>, "os": <caption>, "hardening_index": <0-100|None>,
      "risk_summary": {critical/high/medium/low/total_actionable counts},
      "priority_findings": [ {test_id, severity ("HIGH"|"MEDIUM"), description, solution}, ... ]
    }

Design mirrors lynis_parser.py: a run→parse→build flow. Two Windows-specific choices:

  * ONE batched PowerShell invocation returns every check as a JSON object (not one
    subprocess per check — PowerShell startup is ~300ms). CIM cmdlets are used, not
    deprecated WMI.
  * Several checks (Defender status, SMBv1 server config, BitLocker) require an elevated
    token. When a check can't be read, it is surfaced as an explicit *undetermined*
    finding — never silently treated as secure, which would poison the training set and
    give the user a false all-clear.

Only insecure and undetermined checks become findings; a check that reads back secure
contributes nothing (same as Lynis emitting only warnings/suggestions).
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, Dict, List, Optional

from bin_resolver import is_elevated, resolve as _resolve_bin

# Default hard timeout (seconds) for the PowerShell audit subprocess. Every worker must
# fail bounded, not hang — same rationale as the other parsers' timeouts.
DEFAULT_AUDIT_TIMEOUT = 120

# ── Windows audit catalog ──────────────────────────────────────────────────────
# test_id → {category, description, solution}. Same role as LYNIS_TEST_CATALOG: the
# machine-readable check facts carry no human text, so the build stage fills it in here.

WINDOWS_AUDIT_CATALOG: Dict[str, Dict[str, str]] = {
    "DEFENDER-RTP": {
        "category":    "Malware Protection",
        "description": "Microsoft Defender real-time protection is turned off",
        "solution":    "Turn real-time protection back on: Windows Security > Virus & threat "
                       "protection > Manage settings > Real-time protection = On.",
    },
    "FIREWALL-DOMAIN": {
        "category":    "Firewall",
        "description": "Windows Firewall is disabled for the Domain network profile",
        "solution":    "Enable it: Windows Security > Firewall & network protection > Domain "
                       "network > turn the firewall On (or 'Set-NetFirewallProfile -Name Domain -Enabled True').",
    },
    "FIREWALL-PRIVATE": {
        "category":    "Firewall",
        "description": "Windows Firewall is disabled for the Private network profile",
        "solution":    "Enable it: Windows Security > Firewall & network protection > Private "
                       "network > turn the firewall On (or 'Set-NetFirewallProfile -Name Private -Enabled True').",
    },
    "FIREWALL-PUBLIC": {
        "category":    "Firewall",
        "description": "Windows Firewall is disabled for the Public network profile",
        "solution":    "Enable it: Windows Security > Firewall & network protection > Public "
                       "network > turn the firewall On (or 'Set-NetFirewallProfile -Name Public -Enabled True').",
    },
    "SMB1-ENABLED": {
        "category":    "Legacy Protocols",
        "description": "The legacy SMBv1 file-sharing protocol is enabled (EternalBlue/WannaCry-class exposure)",
        "solution":    "Disable SMBv1: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' "
                       "or 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'; reboot.",
    },
    "RDP-ENABLED": {
        "category":    "Remote Access",
        "description": "Remote Desktop (RDP) is enabled and accepting connections",
        "solution":    "If you don't use Remote Desktop, disable it: Settings > System > Remote "
                       "Desktop = Off. If you do, restrict it to a VPN and enable Network Level Authentication.",
    },
    "RDP-NLA": {
        "category":    "Remote Access",
        "description": "Remote Desktop is enabled without Network Level Authentication (NLA)",
        "solution":    "Require NLA: System Properties > Remote > 'Allow connections only from computers "
                       "running Remote Desktop with Network Level Authentication'.",
    },
    "UAC-DISABLED": {
        "category":    "Privilege Control",
        "description": "User Account Control (UAC) is disabled — programs can gain admin rights without a prompt",
        "solution":    "Re-enable UAC: set registry EnableLUA=1 under "
                       "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System, then reboot.",
    },
    "BITLOCKER-OFF": {
        "category":    "Disk Encryption",
        "description": "The system drive is not protected by BitLocker/device encryption",
        "solution":    "Turn on device encryption or BitLocker: Settings > Privacy & security > "
                       "Device encryption, or Control Panel > BitLocker Drive Encryption.",
    },
    "WU-AUTOUPDATE": {
        "category":    "Patch Management",
        "description": "Windows Update automatic updates are turned off",
        "solution":    "Re-enable automatic updates: Settings > Windows Update > Advanced options, "
                       "and ensure the Windows Update service is set to run automatically.",
    },
    "WU-STALE": {
        "category":    "Patch Management",
        "description": "No Windows update has been installed recently — the system may be missing security patches",
        "solution":    "Open Settings > Windows Update and install all pending updates now.",
    },
    "GUEST-ENABLED": {
        "category":    "Accounts",
        "description": "The built-in Guest account is enabled",
        "solution":    "Disable the Guest account: 'Disable-LocalUser -Name Guest'.",
    },
    "PS-EXECPOLICY": {
        "category":    "Scripting",
        "description": "PowerShell execution policy is unrestricted — scripts run without any signing check",
        "solution":    "Tighten it: 'Set-ExecutionPolicy RemoteSigned -Scope LocalMachine'.",
    },
}

# Checks whose facts require an elevated token to read; used only to tailor the
# undetermined-finding message ('re-run as Administrator').
_ELEVATION_GATED = {"DEFENDER-RTP", "SMB1-ENABLED", "BITLOCKER-OFF"}


# ── STAGE 1: batched PowerShell probe ──────────────────────────────────────────

# One script, one process. $ErrorActionPreference='SilentlyContinue' means an
# unavailable/denied cmdlet yields $null rather than aborting the whole script, so a
# blocked check comes back as null and the build stage renders it 'undetermined'.
_AUDIT_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = [ordered]@{}
$r.hostname = $env:COMPUTERNAME
$r.os = (Get-CimInstance Win32_OperatingSystem).Caption
$mp = Get-MpComputerStatus
$r.defender_realtime = if ($mp) { [bool]$mp.RealTimeProtectionEnabled } else { $null }
$r.firewall_domain  = (Get-NetFirewallProfile -Name Domain).Enabled
$r.firewall_private = (Get-NetFirewallProfile -Name Private).Enabled
$r.firewall_public  = (Get-NetFirewallProfile -Name Public).Enabled
$smb = Get-SmbServerConfiguration
$r.smb1 = if ($smb) { [bool]$smb.EnableSMB1Protocol } else { $null }
$r.rdp_deny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$r.rdp_nla  = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication
$r.uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA
$bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
$r.bitlocker = if ($bl) { $bl.ProtectionStatus.ToString() } else { $null }
$r.au_option = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name AUOptions).AUOptions
$lu = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
$r.days_since_update = if ($lu) { [int]((Get-Date) - $lu).TotalDays } else { $null }
$r.guest_enabled = (Get-LocalUser -Name 'Guest').Enabled
# Skip Process scope here: this script was itself launched with -ExecutionPolicy Bypass
# (so the outer PowerShell.exe call always succeeds), which would make plain
# Get-ExecutionPolicy report 'Bypass' on every machine regardless of the user's real
# policy. Read the effective policy from the scopes that actually reflect user/machine
# config instead.
$policyMap = @{}
foreach ($p in (Get-ExecutionPolicy -List)) { $policyMap[$p.Scope.ToString()] = $p.ExecutionPolicy.ToString() }
$effective = 'Undefined'
foreach ($scope in @('MachinePolicy', 'UserPolicy', 'CurrentUser', 'LocalMachine')) {
    if ($policyMap.ContainsKey($scope) -and $policyMap[$scope] -ne 'Undefined') {
        $effective = $policyMap[$scope]
        break
    }
}
if ($effective -eq 'Undefined') { $effective = 'Restricted' }
$r.exec_policy = $effective
$r | ConvertTo-Json -Compress
"""


def run_windows_audit(timeout: int = DEFAULT_AUDIT_TIMEOUT) -> str:
    """Run the batched PowerShell audit and return its raw JSON string (or '' on failure)."""
    print("[*] Launching Windows host-hardening audit (PowerShell)...")
    command = [
        _resolve_bin("powershell"),
        "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", _AUDIT_PS_SCRIPT,
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,   # individual checks handle their own errors inside the script
            timeout=timeout,
        )
        return result.stdout.strip()
    except FileNotFoundError:
        print("[!] Error: 'powershell' was not found — this audit only runs on Windows.", file=sys.stderr)
        return ""
    except subprocess.TimeoutExpired:
        print(f"[!] Windows audit exceeded the {timeout}s timeout and was killed.", file=sys.stderr)
        return ""
    except Exception as e:
        print(f"[!] Unexpected system crash during Windows audit: {e}", file=sys.stderr)
        return ""


# ── STAGE 2: parse the JSON facts ──────────────────────────────────────────────

def parse_windows_audit(raw_json: str) -> Dict[str, Any]:
    """Parse the PowerShell JSON object into a plain dict. Returns {} if unparseable."""
    if not raw_json:
        return {}
    try:
        facts = json.loads(raw_json)
        return facts if isinstance(facts, dict) else {}
    except json.JSONDecodeError:
        return {}


# ── STAGE 3: evaluate facts → findings ─────────────────────────────────────────

def _finding(test_id: str, severity: str, extra: str = "") -> Dict[str, str]:
    meta = WINDOWS_AUDIT_CATALOG.get(test_id, {})
    desc = meta.get("description", test_id)
    if extra:
        desc = f"{desc} — {extra}"
    return {
        "test_id":     test_id,
        "severity":    severity,
        "description": desc,
        "solution":    meta.get("solution", ""),
    }


def _undetermined(test_id: str, elevated: bool) -> Dict[str, str]:
    hint = ("could not be determined" if elevated
            else "could not be determined — re-run the audit as Administrator")
    return _finding(test_id, "MEDIUM", extra=hint)


def _evaluate_findings(facts: Dict[str, Any], elevated: bool) -> List[Dict[str, str]]:
    """Turn raw check facts into HIGH/MEDIUM findings. A null gated fact → undetermined.
    Secure checks produce nothing. Pure function of (facts, elevated) — unit-testable."""
    out: List[Dict[str, str]] = []

    # Defender real-time protection (elevation-gated)
    rtp = facts.get("defender_realtime")
    if rtp is None:
        out.append(_undetermined("DEFENDER-RTP", elevated))
    elif rtp is False:
        out.append(_finding("DEFENDER-RTP", "HIGH"))

    for profile, tid in (("firewall_domain", "FIREWALL-DOMAIN"),
                         ("firewall_private", "FIREWALL-PRIVATE"),
                         ("firewall_public", "FIREWALL-PUBLIC")):
        val = facts.get(profile)
        if val is None:
            out.append(_undetermined(tid, elevated))
        elif val is False:
            out.append(_finding(tid, "HIGH"))

    # SMBv1 (elevation-gated)
    smb1 = facts.get("smb1")
    if smb1 is None:
        out.append(_undetermined("SMB1-ENABLED", elevated))
    elif smb1 is True:
        out.append(_finding("SMB1-ENABLED", "HIGH"))

    # RDP: enabled when fDenyTSConnections == 0
    rdp_deny = facts.get("rdp_deny")
    if rdp_deny == 0:
        out.append(_finding("RDP-ENABLED", "MEDIUM"))
        # NLA only meaningful when RDP is on: UserAuthentication == 1 means NLA required
        if facts.get("rdp_nla") != 1:
            out.append(_finding("RDP-NLA", "HIGH"))

    # UAC: EnableLUA == 0 means disabled
    if facts.get("uac") == 0:
        out.append(_finding("UAC-DISABLED", "HIGH"))

    # BitLocker (elevation-gated): ProtectionStatus 'On' is secure
    bl = facts.get("bitlocker")
    if bl is None:
        out.append(_undetermined("BITLOCKER-OFF", elevated))
    elif str(bl).lower() != "on":
        out.append(_finding("BITLOCKER-OFF", "MEDIUM"))

    # Windows Update auto-update: AUOptions 1 (never check) / disabled is insecure
    au = facts.get("au_option")
    if au is not None and au in (0, 1):
        out.append(_finding("WU-AUTOUPDATE", "HIGH"))

    days = facts.get("days_since_update")
    if isinstance(days, int) and days > 30:
        out.append(_finding("WU-STALE", "MEDIUM", extra=f"last update {days} days ago"))

    if facts.get("guest_enabled") is True:
        out.append(_finding("GUEST-ENABLED", "MEDIUM"))

    policy = str(facts.get("exec_policy", "")).lower()
    if policy in ("unrestricted", "bypass"):
        out.append(_finding("PS-EXECPOLICY", "MEDIUM", extra=f"currently '{facts.get('exec_policy')}'"))

    return out


# ── STAGE 4: build the LLM/table payload (host_audit contract) ─────────────────

_SEVERITY_ORDER = {"HIGH": 2, "MEDIUM": 1}


def build_llm_payload_from_windows_audit(
    facts: Dict[str, Any], elevated: Optional[bool] = None,
) -> Dict[str, Any]:
    """Condense evaluated findings into the host_audit payload contract."""
    if elevated is None:
        elevated = is_elevated()

    findings = _evaluate_findings(facts, elevated)
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 0), reverse=True)

    high_count   = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")

    # Rough hardening index (report text only, mirrors Lynis's 0-100 field).
    hardening_index = max(0, 100 - high_count * 15 - medium_count * 5)

    return {
        "scan_target":     facts.get("hostname", "localhost"),
        "os":              facts.get("os", "Windows"),
        "hardening_index": hardening_index,
        "risk_summary": {
            "critical_count":   0,
            "high_count":       high_count,
            "medium_count":     medium_count,
            "low_count":        0,
            "total_actionable": high_count + medium_count,
        },
        "priority_findings": findings[:10],
    }


def main():
    raw = run_windows_audit()
    if not raw:
        print("[!] Pipeline aborted. No audit data captured.", file=sys.stderr)
        sys.exit(1)
    facts   = parse_windows_audit(raw)
    payload = build_llm_payload_from_windows_audit(facts)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
