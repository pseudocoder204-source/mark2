# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic training-data generator for the report LoRA (see FinetuneGuide.txt PHASE 1B/1C).

Replaces SecGen: instead of launching vulnerable VMs, this hand-assembles a worker-output
`results` dict per PHASE 1C's field contract, then runs it through the REAL
`build_findings_table` from agent.py + `priority.rank` — so every generated training
input is byte-identical in shape to what the live pipeline emits. No model, no scan, no VM.

Six environment profiles model "different user environments" as sampling configs over the
six finding sources (network, iot_defaults, filesystem, host_audit, malware, web). Real
vocabulary is sampled from vulnerability_cache.db (CVEs) and LYNIS_TEST_CATALOG (Lynis
test IDs) rather than invented, so labels drafted later stay grounded in real facts.

Usage:
    python3 finetune/synth_findings.py --db trainset.db --per-profile 45
    python3 finetune/synth_findings.py --db trainset.db --profile clean_healthy --per-profile 10
"""

import argparse
import json
import random
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import build_findings_table
from scanners.lynis.lynis_subgraph import LYNIS_TEST_CATALOG
from core.priority import ordered_refs, rank

_VULN_DB_PATH = "vulnerability_cache.db"
_TRAINSET_SCHEMA = """
CREATE TABLE IF NOT EXISTS examples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT,                   -- 'synth' | 'real'
    profile       TEXT,                   -- profile name, or NULL for real anchors
    ordered_facts TEXT NOT NULL,           -- json.dumps(ordered_facts) — the model input
    label         TEXT,                   -- json.dumps(report) — NULL until labeled
    status        TEXT DEFAULT 'pending'   -- pending -> labeled -> validated | rejected
)
"""

# Small hand-curated real vocab for sources with no local DB/catalog to sample from.
_CLAMAV_SIGNATURES = [
    ("Unix.Trojan.Generic-1234", "high"),
    ("Unix.Malware.Agent-9981", "high"),
    ("PUA.Script.Coinminer-4521", "medium"),
    ("Win.Trojan.Downloader-771", "high"),
    ("Unix.Exploit.CVE-2016-3714-1", "high"),
]
_NUCLEI_TEMPLATES = [
    ("Exposed .git directory", "medium", None, None),
    ("Default admin login page", "medium", None, None),
    ("WordPress outdated core version", "high", "CVE-2022-21661", 7.5),
    ("Apache Struts RCE", "critical", "CVE-2017-5638", 10.0),
    ("Open Redis instance (no auth)", "critical", None, 9.8),
    ("Jenkins default credentials", "high", None, 8.1),
]
_IOT_SCRIPT_FINDINGS = [
    [{"id": "http-default-accounts", "output": "Found default credentials admin:admin at path /login"}],
    [{"id": "upnp-info", "output": "Server: Linux/3.10 UPnP/1.0 MiniUPnPd/1.9 — external port mapping open"}],
    [{"id": "snmp-info", "output": "SNMP community string 'public' accepted (read access)"}],
]
_SERVICES = [
    (22, "ssh", "OpenSSH", "7.4", "cpe:2.3:a:openbsd:openssh:7.4"),
    (80, "http", "Apache httpd", "2.4.29", "cpe:2.3:a:apache:http_server:2.4.29"),
    (443, "https", "nginx", "1.14.0", "cpe:2.3:a:nginx:nginx:1.14.0"),
    (445, "smb", "Samba", "4.3.11", "cpe:2.3:a:samba:samba:4.3.11"),
    (8080, "http-proxy", "Jetty", "9.4.8", "cpe:2.3:a:eclipse:jetty:9.4.8"),
    (3306, "mysql", "MySQL", "5.7.21", "cpe:2.3:a:mysql:mysql:5.7.21"),
    (23, "telnet", "BusyBox telnetd", "1.24.0", "cpe:2.3:a:busybox:busybox:1.24.0"),
    (1900, "upnp", "MiniUPnPd", "1.9", "cpe:2.3:a:miniupnp_project:miniupnpd:1.9"),
]
_OS_CPES = [
    ("cpe:2.3:o:linux:linux_kernel:4.15", "Linux (kernel 4.15)"),
    ("cpe:2.3:o:microsoft:windows_10:-", "Windows 10"),
    ("cpe:2.3:o:vxworks:vxworks:6.9", "VxWorks 6.9 (embedded/router firmware)"),
]
_TRIVY_PACKAGES = [
    ("openssl", "1.1.1f-1ubuntu2", "1.1.1f-1ubuntu2.16", "CVE-2022-0778", "critical"),
    ("curl", "7.68.0-1ubuntu2", "7.68.0-1ubuntu2.14", "CVE-2023-38545", "high"),
    ("libxml2", "2.9.10-1", "2.9.10-2ubuntu0.3", "CVE-2022-40304", "medium"),
    ("zlib1g", "1:1.2.11.dfsg-2", "1:1.2.11.dfsg-2ubuntu1.5", "CVE-2018-25032", "high"),
    ("python3.8", "3.8.10-0ubuntu1", "3.8.10-0ubuntu1.13", "CVE-2022-45061", "medium"),
]


def _cve_rows_for_cpe_prefix(conn: sqlite3.Connection, prefix: str, limit: int) -> List[Dict[str, Any]]:
    """Real CVE rows from vulnerability_cache.db, matching PHASE 1C's nmap CVE-dict shape."""
    cur = conn.cursor()
    cur.execute(
        """SELECT cve_id, cvss_score, severity, description, patch_links
           FROM local_cves WHERE cpe_base LIKE ? AND cvss_score > 0 ORDER BY RANDOM() LIMIT ?""",
        (prefix + "%", limit),
    )
    out = []
    for cve_id, cvss, severity, desc, links_s in cur.fetchall():
        links = [l.strip() for l in (links_s or "").split(",") if l.strip()]
        out.append({
            "cve_id": cve_id,
            "cvss_score": float(cvss) if cvss else 0.0,
            "severity": severity or "UNKNOWN",
            "description": desc or "No description provided.",
            "links": links[:2],
        })
    return out


def _service_record(conn: sqlite3.Connection, with_cves: bool, script_findings: Optional[list] = None) -> Dict[str, Any]:
    port, service, product, version, cpe = random.choice(_SERVICES)
    cves = _cve_rows_for_cpe_prefix(conn, cpe.rsplit(":", 1)[0], random.randint(1, 3)) if with_cves else []
    max_cvss = max((c["cvss_score"] for c in cves), default=0.0)
    critical = sum(1 for c in cves if c["severity"] == "CRITICAL")
    high = sum(1 for c in cves if c["severity"] == "HIGH")
    return {
        "port": port,
        "service": service,
        "product": product,
        "version": version,
        "cpe": cpe,
        "risk_metrics": {
            "max_cvss_score": max_cvss,
            "total_critical_cves_found": critical,
            "total_high_cves_found": high,
        },
        "priority_vulnerabilities": cves[:5],
        "verified_patch_urls": [l for c in cves for l in c["links"]][:4],
        "script_findings": script_findings or [],
    }


def _host_os_record(conn: sqlite3.Connection) -> Dict[str, Any]:
    cpe, os_name = random.choice(_OS_CPES)
    cves = _cve_rows_for_cpe_prefix(conn, cpe.rsplit(":", 1)[0], random.randint(0, 2))
    max_cvss = max((c["cvss_score"] for c in cves), default=0.0)
    critical = sum(1 for c in cves if c["severity"] == "CRITICAL")
    high = sum(1 for c in cves if c["severity"] == "HIGH")
    return {
        "finding_type": "host_os",
        "cpe": cpe,
        "os_name": os_name,
        "risk_metrics": {
            "max_cvss_score": max_cvss,
            "total_critical_cves_found": critical,
            "total_high_cves_found": high,
        },
        "priority_vulnerabilities": cves[:5],
        "verified_patch_urls": [l for c in cves for l in c["links"]][:4],
    }


def _filesystem_payload(n: int) -> Dict[str, Any]:
    picks = random.sample(_TRIVY_PACKAGES, min(n, len(_TRIVY_PACKAGES)))
    findings = [
        {
            "cve_id": cve_id,
            "package": pkg,
            "installed_version": inst,
            "fixed_version": fixed,
            "severity": sev.upper(),
            "title": f"{pkg} vulnerability",
            "description": f"{pkg} {inst} is affected by {cve_id}, fixed in {fixed}.",
        }
        for pkg, inst, fixed, cve_id, sev in picks
    ]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"].lower()] = counts.get(f["severity"].lower(), 0) + 1
    return {
        "host_node": "production_target_host",
        "risk_summary": {
            "critical_count": counts["critical"], "high_count": counts["high"],
            "medium_count": counts["medium"], "low_count": counts["low"],
            "total_actionable": len(findings),
        },
        "priority_findings": findings[:10],
    }


def _host_audit_payload(n: int) -> Dict[str, Any]:
    test_ids = random.sample(list(LYNIS_TEST_CATALOG), min(n, len(LYNIS_TEST_CATALOG)))
    findings = []
    for tid in test_ids:
        meta = LYNIS_TEST_CATALOG[tid]
        severity = random.choice(["HIGH", "MEDIUM"])
        findings.append({
            "test_id": tid,
            "severity": severity,
            "description": meta["description"],
            "details": "",
            "solution": meta["solution"],
        })
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = len(findings) - high
    return {
        "scan_target": "localhost",
        "lynis_version": "3.0.9",
        "os": "Linux",
        "hardening_index": random.randint(50, 85),
        "risk_summary": {
            "critical_count": 0, "high_count": high, "medium_count": medium,
            "low_count": 0, "total_actionable": len(findings),
        },
        "priority_findings": findings[:10],
    }


def _malware_payload(n: int) -> Dict[str, Any]:
    picks = random.sample(_CLAMAV_SIGNATURES, min(n, len(_CLAMAV_SIGNATURES)))
    findings = [
        {"file_path": f"/home/user/downloads/file_{i}.bin", "signature": sig, "severity": sev.upper()}
        for i, (sig, sev) in enumerate(picks)
    ]
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = len(findings) - high
    return {
        "scan_target": ["/home", "/tmp", "/var/tmp", "/opt", "/srv", "/root", "/var/www"],
        "engine": "ClamAV",
        "scan_mode": "incremental",
        "risk_summary": {
            "critical_count": 0, "high_count": high, "medium_count": medium, "low_count": 0,
            "total_actionable": len(findings), "scanned_files": 5000, "infected_files": len(findings),
        },
        "priority_findings": findings[:10],
    }


def _pending_malware_payload() -> Dict[str, Any]:
    return {"status": "pending"}


def _web_payload(n: int) -> Dict[str, Any]:
    picks = random.sample(_NUCLEI_TEMPLATES, min(n, len(_NUCLEI_TEMPLATES)))
    findings = []
    for name, sev, cve_id, cvss in picks:
        findings.append({
            "template_id": name.lower().replace(" ", "-"),
            "name": name,
            "severity": sev.upper(),
            "host": "192.168.1.50",
            "matched_at": f"http://192.168.1.50/{name.lower().replace(' ', '-')}",
            "cve_id": cve_id,
            "cvss_score": cvss,
            "description": f"{name} was detected during a template-based web scan.",
            "references": [],
        })
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"].lower()] = counts.get(f["severity"].lower(), 0) + 1
    return {
        "scan_target": "192.168.1.50",
        "risk_summary": {**counts, "info_count": 0, "total_actionable": len(findings)},
        "priority_findings": findings[:10],
    }


# --- Profiles -----------------------------------------------------------------
# Each profile returns a `results` dict shaped exactly like agent.py's worker spine
# output (the dict build_findings_table consumes).

def _profile_elderly_minimal(conn: sqlite3.Connection) -> Dict[str, Any]:
    network = [_service_record(conn, with_cves=False)]
    iot = [_service_record(conn, with_cves=False, script_findings=random.choice(_IOT_SCRIPT_FINDINGS))]
    return {
        "network": network, "iot_defaults": iot,
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_family_smarthome(conn: sqlite3.Connection) -> Dict[str, Any]:
    network = [_service_record(conn, with_cves=True) for _ in range(random.randint(2, 4))]
    iot = [_service_record(conn, with_cves=random.random() < 0.5, script_findings=random.choice(_IOT_SCRIPT_FINDINGS))
           for _ in range(random.randint(1, 2))]
    return {
        "network": network, "iot_defaults": iot,
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_freelancer_laptop(conn: sqlite3.Connection) -> Dict[str, Any]:
    return {
        "network": [_service_record(conn, with_cves=False)],
        "iot_defaults": [],
        "filesystem": _filesystem_payload(random.randint(3, 5)),
        "host_audit": _host_audit_payload(random.randint(4, 8)),
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_compromised_machine(conn: sqlite3.Connection) -> Dict[str, Any]:
    return {
        "network": [_service_record(conn, with_cves=True)],
        "iot_defaults": [],
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _malware_payload(1),
        "web": {"priority_findings": []},
    }


def _profile_small_office(conn: sqlite3.Connection) -> Dict[str, Any]:
    network = [_service_record(conn, with_cves=True) for _ in range(random.randint(3, 5))]
    network.append(_host_os_record(conn))
    return {
        "network": network, "iot_defaults": [],
        "filesystem": _filesystem_payload(random.randint(0, 2)),
        "host_audit": _host_audit_payload(random.randint(0, 3)),
        "malware": _pending_malware_payload(),
        "web": _web_payload(random.randint(2, 4)),
    }


def _profile_clean_healthy(conn: sqlite3.Connection) -> Dict[str, Any]:
    return {
        "network": [_service_record(conn, with_cves=False) for _ in range(random.randint(1, 3))],
        "iot_defaults": [],
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


_PROFILES = {
    "elderly_minimal": _profile_elderly_minimal,
    "family_smarthome": _profile_family_smarthome,
    "freelancer_laptop": _profile_freelancer_laptop,
    "compromised_machine": _profile_compromised_machine,
    "small_office": _profile_small_office,
    "clean_healthy": _profile_clean_healthy,
}


def generate_ordered_facts(profile: str, conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Assemble a synthetic `results` dict for `profile`, run it through the real
    build_findings_table + priority.rank, and return ordered_facts — identical in
    shape to what run_report's _log_training_input logs in production."""
    results = _PROFILES[profile](conn)
    table = build_findings_table(results)
    order = ordered_refs(rank(table))
    by_ref = {f["ref"]: f for f in table}
    return [by_ref[r] for r in order if r in by_ref]


def _init_trainset_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(_TRAINSET_SCHEMA)
    conn.commit()
    return conn


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default="trainset.db", help="path to the trainset working store")
    ap.add_argument("--vuln-db", default=_VULN_DB_PATH, help="path to vulnerability_cache.db")
    ap.add_argument("--profile", choices=list(_PROFILES), help="generate only this profile (default: all)")
    ap.add_argument("--per-profile", type=int, default=45, help="rows to generate per profile")
    ap.add_argument("--seed", type=int, default=None, help="random seed for reproducibility")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    vuln_conn = sqlite3.connect(args.vuln_db)
    trainset_conn = _init_trainset_db(args.db)

    profiles = [args.profile] if args.profile else list(_PROFILES)
    inserted = 0
    for profile in profiles:
        for _ in range(args.per_profile):
            ordered_facts = generate_ordered_facts(profile, vuln_conn)
            trainset_conn.execute(
                "INSERT INTO examples (source, profile, ordered_facts, status) VALUES (?, ?, ?, 'pending')",
                ("synth", profile, json.dumps(ordered_facts)),
            )
            inserted += 1
        trainset_conn.commit()
        print(f"[synth_findings] {profile}: {args.per_profile} rows")

    print(f"[synth_findings] inserted {inserted} pending rows into {args.db}")
    vuln_conn.close()
    trainset_conn.close()


if __name__ == "__main__":
    main()
