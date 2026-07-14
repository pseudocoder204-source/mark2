# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic training-data generator for the triage LoRA (see notes/FinetuneGuideTriage.txt
PHASE 1, Step 3). Sibling of synth_findings.py, NOT a modification of it — that generator is
tuned for report tier-SHAPE diversity (empty/all-good/mixed/critical) and its profiles rarely
produce >=2 CVE-bearing findings tied on cvss within one tier, which is the only shape a triage
model can learn anything from (see the module docstring rationale in FinetuneGuideTriage.txt).

Every generated row still runs through the REAL build_findings_table (agent.py) — only the
`results` dict fed into it is synthetic. Unlike synth_findings.py, rows are stored in REF order
(not passed through _fallback_order): Step 4a of the labeling guide shuffles/presents the table
itself, so the corpus should hold the undecided table, not a pre-sorted one.

Contest shapes (Step 3a-3d):
  - contested_critical / contested_high / contested_mixed: 2-4 network/iot service findings
    share an EXACT cvss score within one tier (mixed: two tiers at once), each carrying a real,
    distinct CVE pulled from vulnerability_cache.db so the tie is genuinely decidable via
    lookup_cves detail — never a coin flip.
  - no_contest_single / no_contest_low: control rows with no intra-tier ambiguity, teaching the
    model when NOT to spend an escalation.

Usage:
    python3 finetune/synth_findings_triage.py --db trainset.db --shape contested_critical --count 40
    python3 finetune/synth_findings_triage.py --db trainset.db   # generates the full default mix
"""

import argparse
import json
import random
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import build_findings_table

_VULN_DB_PATH = "vulnerability_cache.db"

# Matches the live schema (trainset.db already carries these columns); kept as
# CREATE TABLE IF NOT EXISTS so this script can also bootstrap a fresh trainset.db from scratch.
_TRAINSET_SCHEMA = """
CREATE TABLE IF NOT EXISTS examples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT,                   -- 'synth' | 'real' | 'synth_triage'
    profile       TEXT,                   -- profile / contest-shape name
    ordered_facts TEXT NOT NULL,           -- json.dumps(table) — the model input
    label         TEXT,                   -- json.dumps(report) — report-channel only
    status        TEXT DEFAULT 'pending',  -- report-channel status
    platform      TEXT,
    triage_label  TEXT,                   -- json trace — NULL until labeled
    triage_status TEXT DEFAULT NULL        -- pending -> labeled -> validated | rejected
)
"""

# cvss scores with enough distinct-vendor CVE inventory in vulnerability_cache.db to draw
# multiple genuinely different products from.
_CRITICAL_SCORES = [9.8, 9.6, 9.9, 10.0]
_HIGH_SCORES = [7.5, 7.8, 8.1, 8.8]
_MEDIUM_SCORES = [5.3, 5.9, 6.1, 6.5]

_IOT_SCRIPT_FINDINGS = [
    [{"id": "http-default-accounts", "output": "Found default credentials admin:admin at path /login"}],
    [{"id": "upnp-info", "output": "Server: Linux/3.10 UPnP/1.0 MiniUPnPd/1.9 — external port mapping open"}],
    [{"id": "snmp-info", "output": "SNMP community string 'public' accepted (read access)"}],
]

# Filler services with no CVE — pad tables with realistic non-contested findings, same vocab
# synth_findings.py uses, so a contested tier doesn't stand alone as the whole table.
_FILLER_SERVICES = [
    (22, "ssh", "OpenSSH", "9.6", "cpe:2.3:a:openbsd:openssh:9.6"),
    (80, "http", "Apache httpd", "2.4.58", "cpe:2.3:a:apache:http_server:2.4.58"),
    (443, "https", "nginx", "1.25.3", "cpe:2.3:a:nginx:nginx:1.25.3"),
    (445, "smb", "Samba", "4.19.4", "cpe:2.3:a:samba:samba:4.19.4"),
]


def _unique_ports(n: int, exclude: Optional[set] = None) -> List[int]:
    exclude = exclude or set()
    pool = [p for p in range(1024, 60000) if p not in exclude]
    return random.sample(pool, n)


def _cve_rows_at_score(conn: sqlite3.Connection, score: float, k: int) -> List[Dict[str, Any]]:
    """k CVE records tied at exactly `score`, each from a DISTINCT application cpe_base with
    real version-range data, so lookup_cves(cpe) at label time returns a real, matchable hit
    and every contested finding carries a genuinely different CVE (real tie-break material,
    not a repeated one — mirrors the `distinct_cve_sets` check from the Step 2 audit)."""
    cur = conn.cursor()
    cur.execute(
        """SELECT cpe_base, cve_id, vulnerable_version, version_start_including,
                  version_end_including, severity, description, patch_links
           FROM local_cves
           WHERE cvss_score = ?
             AND substr(cpe_base, 9, 1) = 'a'
             AND (
                   (vulnerable_version IS NOT NULL AND vulnerable_version NOT IN ('', '*'))
                OR (version_start_including IS NOT NULL AND version_start_including != '')
                OR (version_end_including IS NOT NULL AND version_end_including != '')
             )
           ORDER BY RANDOM() LIMIT 500""",
        (score,),
    )
    seen_cpe_bases: set = set()
    out: List[Dict[str, Any]] = []
    for cpe_base, cve_id, exact_v, start_v, end_v, severity, desc, links_s in cur.fetchall():
        if cpe_base in seen_cpe_bases:
            continue
        version = next(v for v in (exact_v, start_v, end_v) if v and v != "*")
        seen_cpe_bases.add(cpe_base)
        links = [l.strip() for l in (links_s or "").split(",") if l.strip()]
        out.append({
            "cpe_base": cpe_base,
            "version": version,
            "cve_id": cve_id,
            "cvss_score": score,
            "severity": severity or "UNKNOWN",
            "description": desc or "No description provided.",
            "links": links[:2],
        })
        if len(out) == k:
            break
    return out


def _contested_service_record(port: int, cve_row: Dict[str, Any], with_script: bool) -> Dict[str, Any]:
    cpe_base, version = cve_row["cpe_base"], cve_row["version"]
    parts = cpe_base.split(":")
    vendor, product = (parts[3], parts[4]) if len(parts) > 4 else ("unknown", "unknown")
    severity = cve_row["severity"]
    return {
        "port": port,
        "service": product,
        "product": f"{vendor} {product}".replace("_", " "),
        "version": version,
        "cpe": f"{cpe_base}:{version}",
        "risk_metrics": {
            "max_cvss_score": cve_row["cvss_score"],
            "total_critical_cves_found": 1 if severity == "CRITICAL" else 0,
            "total_high_cves_found": 1 if severity == "HIGH" else 0,
        },
        "priority_vulnerabilities": [{
            "cve_id": cve_row["cve_id"],
            "cvss_score": cve_row["cvss_score"],
            "severity": severity,
            "description": cve_row["description"],
            "links": cve_row["links"],
        }],
        "verified_patch_urls": cve_row["links"][:4],
        "script_findings": random.choice(_IOT_SCRIPT_FINDINGS) if with_script else [],
    }


def _filler_record(port: int) -> Dict[str, Any]:
    _, service, product, version, cpe = random.choice(_FILLER_SERVICES)
    return {
        "port": port, "service": service, "product": product, "version": version, "cpe": cpe,
        "risk_metrics": {"max_cvss_score": 0.0, "total_critical_cves_found": 0, "total_high_cves_found": 0},
        "priority_vulnerabilities": [], "verified_patch_urls": [], "script_findings": [],
    }


def _assemble(network: List[Dict[str, Any]], iot: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "network": network, "iot_defaults": iot,
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": {"status": "pending"},
        "web": {"priority_findings": []},
    }


# --- Contest shapes --------------------------------------------------------

def _shape_contested(conn: sqlite3.Connection, scores: List[float]) -> Dict[str, Any]:
    """2-4 tied, distinct-CVE findings in one tier (Step 3a/3b) plus a couple of uncontested
    filler ports so the tier isn't the entire table."""
    k = random.randint(2, 4)
    score = random.choice(scores)
    rows = _cve_rows_at_score(conn, score, k)
    ports = _unique_ports(len(rows) + 2)
    records = [_contested_service_record(ports[i], row, with_script=False) for i, row in enumerate(rows)]
    iot = []
    if random.random() < 0.3 and records:
        # occasionally move one contested finding to iot_defaults with a script finding —
        # exercises the network+iot_defaults dedup/merge path in build_findings_table.
        idx = random.randrange(len(records))
        records[idx] = _contested_service_record(ports[idx], rows[idx], with_script=True)
        iot = [records.pop(idx)]
    network = records + [_filler_record(p) for p in ports[len(rows):]]
    return _assemble(network, iot)


def _shape_contested_mixed(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Two DIFFERENT tiers each independently contested — tests that reordering stays
    correctly scoped within each tier and doesn't bleed across the tier boundary."""
    tier_a_scores, tier_b_scores = random.sample(
        [_CRITICAL_SCORES, _HIGH_SCORES, _MEDIUM_SCORES], 2
    )
    k_a, k_b = random.randint(2, 3), random.randint(2, 3)
    rows = _cve_rows_at_score(conn, random.choice(tier_a_scores), k_a) + \
        _cve_rows_at_score(conn, random.choice(tier_b_scores), k_b)
    ports = _unique_ports(len(rows))
    network = [_contested_service_record(ports[i], row, with_script=False) for i, row in enumerate(rows)]
    return _assemble(network, [])


def _shape_no_contest_single(conn: sqlite3.Connection) -> Dict[str, Any]:
    """One CVE-bearing finding per tier, distinct cvss throughout — nothing to reorder, the
    correct move is zero escalations and straight fallback order (Step 3d)."""
    chosen_scores = [random.choice(_CRITICAL_SCORES), random.choice(_HIGH_SCORES), random.choice(_MEDIUM_SCORES)]
    random.shuffle(chosen_scores)
    n = random.randint(1, 3)
    rows = [_cve_rows_at_score(conn, s, 1)[0] for s in chosen_scores[:n]]
    ports = _unique_ports(len(rows))
    network = [_contested_service_record(ports[i], row, with_script=False) for i, row in enumerate(rows)]
    return _assemble(network, [])


def _shape_no_contest_low(conn: sqlite3.Connection) -> Dict[str, Any]:
    """All-low / no-CVE table — the other half of "when not to escalate" (nothing to escalate
    on at all)."""
    ports = _unique_ports(random.randint(1, 3))
    network = [_filler_record(p) for p in ports]
    iot = [dict(_filler_record(_unique_ports(1, set(ports))[0]),
                script_findings=random.choice(_IOT_SCRIPT_FINDINGS))] if random.random() < 0.4 else []
    return _assemble(network, iot)


_SHAPES = {
    "contested_critical": lambda conn: _shape_contested(conn, _CRITICAL_SCORES),
    "contested_high": lambda conn: _shape_contested(conn, _HIGH_SCORES),
    "contested_mixed": _shape_contested_mixed,
    "no_contest_single": _shape_no_contest_single,
    "no_contest_low": _shape_no_contest_low,
}

# Default mix: ~40%+ escalation-worthy (contested_*), rest zero-tool-call (no_contest_*).
_DEFAULT_COUNTS = {
    "contested_critical": 40,
    "contested_high": 40,
    "contested_mixed": 30,
    "no_contest_single": 90,
    "no_contest_low": 60,
}


def generate_ordered_facts(shape: str, conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Assemble a synthetic `results` dict for `shape`, run it through the REAL
    build_findings_table, and return the table in ref order (undecided — Step 4a shuffles
    and strips script_findings at label time, not here)."""
    results = _SHAPES[shape](conn)
    return build_findings_table(results)


def _init_trainset_conn(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(_TRAINSET_SCHEMA)
    conn.commit()
    return conn


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default="trainset.db", help="path to the trainset working store")
    ap.add_argument("--vuln-db", default=_VULN_DB_PATH, help="path to vulnerability_cache.db")
    ap.add_argument("--shape", choices=list(_SHAPES), help="generate only this shape (default: full default mix)")
    ap.add_argument("--count", type=int, default=None, help="rows to generate (with --shape); ignored for the default mix")
    ap.add_argument("--seed", type=int, default=None, help="random seed for reproducibility")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    vuln_conn = sqlite3.connect(args.vuln_db)
    trainset_conn = _init_trainset_conn(args.db)

    plan = {args.shape: args.count or _DEFAULT_COUNTS[args.shape]} if args.shape else _DEFAULT_COUNTS
    inserted = 0
    for shape, count in plan.items():
        for _ in range(count):
            table = generate_ordered_facts(shape, vuln_conn)
            trainset_conn.execute(
                "INSERT INTO examples (source, profile, ordered_facts, triage_status) "
                "VALUES ('synth_triage', ?, ?, 'pending')",
                (shape, json.dumps(table)),
            )
            inserted += 1
        trainset_conn.commit()
        print(f"[synth_findings_triage] {shape}: {count} rows")

    print(f"[synth_findings_triage] inserted {inserted} pending triage rows into {args.db}")
    vuln_conn.close()
    trainset_conn.close()


if __name__ == "__main__":
    main()
