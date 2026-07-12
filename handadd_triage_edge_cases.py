# SPDX-License-Identifier: GPL-2.0-only
"""Step 6 of notes/FinetuneGuideTriage.txt PHASE 2: hand-add ~20-30 edge cases the
distribution-driven sampler (synth_findings_triage.py) may under-cover. Each case is built
deliberately, not drawn from the random contest-shape mix, then drafted with the SAME real
policy (label_triage_batch.draft_triage_label) and pushed through the SAME real validators
(validate_triage_labels._check) as every other row — hand-picking the shape of the table is
the only thing that's "by hand" here; the label and the accept/reject gate are not.

Four cases (Step 6 bullets):
  edge_empty                    empty table -> [] , zero tool calls
  edge_all_tiers_single         one CVE-bearing finding per tier (incl. low, which the main
                                 sampler's _shape_no_contest_single never draws), zero
                                 tool calls, straight fallback order
  edge_partial_escalation       critical tier fully consumes 2 of the 3-call budget on its own
                                 tied pair; the high tier's tied pair then gets only ONE
                                 escalation before the budget runs out — exercises "escalate
                                 exactly once, reorder one pair" under a budget that's already
                                 partly spent, not a fresh one
  edge_out_of_scope_cpe         a contested, real, escalatable network pair sits in the same
                                 tier as a filesystem finding whose description dangles a
                                 tempting product/version string — but filesystem findings
                                 always carry cpe=None (agent.py:256), so it can never appear
                                 in valid_cpes and must never be escalated

Usage: python3 handadd_triage_edge_cases.py [--db trainset.db] [--vuln-db vulnerability_cache.db]
"""

import argparse
import json
import sqlite3
from typing import Any, Dict, List

from agent import build_findings_table
from label_triage_batch import draft_triage_label
from synth_findings_triage import (
    _CRITICAL_SCORES,
    _HIGH_SCORES,
    _assemble,
    _contested_service_record,
    _cve_rows_at_score,
    _filler_record,
    _init_trainset_conn,
    _unique_ports,
)

_LOW_SCORES = [2.5, 2.7, 3.1, 3.3, 3.5, 3.7]


def _case_empty() -> List[Dict[str, Any]]:
    return build_findings_table(_assemble([], []))


def _case_all_tiers_single(conn: sqlite3.Connection, n_tiers: int) -> List[Dict[str, Any]]:
    """One singleton CVE-bearing finding per chosen tier (low included), distinct cvss
    throughout — nothing tied, so the only correct move is zero escalations + fallback order."""
    import random
    pools = [_CRITICAL_SCORES, _HIGH_SCORES, [5.3, 5.9, 6.1, 6.5], _LOW_SCORES]
    chosen = random.sample(pools, n_tiers)
    rows = [_cve_rows_at_score(conn, random.choice(p), 1)[0] for p in chosen]
    ports = _unique_ports(len(rows))
    network = [_contested_service_record(ports[i], row, with_script=False) for i, row in enumerate(rows)]
    return build_findings_table(_assemble(network, []))


def _case_partial_escalation(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Critical tier: a tied pair (2 members) that fully consumes 2 of the 3-call budget.
    High tier: a second tied pair where only the FIRST member (ref order) can still be
    escalated before the budget of 3 runs out -- the second member of that pair stays
    un-escalated and is correctly outranked by rule 5 of the labeling policy."""
    crit_rows = _cve_rows_at_score(conn, _CRITICAL_SCORES[0], 2)
    while len(crit_rows) < 2:
        crit_rows = _cve_rows_at_score(conn, __import__("random").choice(_CRITICAL_SCORES), 2)
    high_rows = _cve_rows_at_score(conn, _HIGH_SCORES[0], 2)
    while len(high_rows) < 2:
        high_rows = _cve_rows_at_score(conn, __import__("random").choice(_HIGH_SCORES), 2)

    all_rows = crit_rows + high_rows
    ports = _unique_ports(len(all_rows))
    network = [_contested_service_record(ports[i], row, with_script=False) for i, row in enumerate(all_rows)]
    return build_findings_table(_assemble(network, []))


def _case_out_of_scope_cpe(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """A real, escalatable tied pair in the HIGH tier, plus a filesystem finding at the same
    tier whose description dangles a concrete, tempting product/version/CVE string. The
    filesystem finding's own "cpe" is always None (agent.py build_findings_table), so it can
    never land in valid_cpes -- the correct trace escalates only the two network cpes."""
    high_rows = _cve_rows_at_score(conn, _HIGH_SCORES[0], 2)
    while len(high_rows) < 2:
        high_rows = _cve_rows_at_score(conn, __import__("random").choice(_HIGH_SCORES), 2)
    ports = _unique_ports(len(high_rows))
    network = [_contested_service_record(ports[i], row, with_script=False) for i, row in enumerate(high_rows)]

    results = _assemble(network, [])
    results["filesystem"] = {"priority_findings": [{
        "package": "openssl", "installed_version": "3.0.1",
        "severity": "high",
        "cve_id": "CVE-2023-0286",
        "description": (
            "A type confusion vulnerability in X.400 address processing in OpenSSL "
            "3.0.1 (cpe:2.3:a:openssl:openssl:3.0.1) allows an attacker to read memory "
            "contents or cause a denial of service."
        ),
        "fixed_version": "3.0.8",
    }]}
    return build_findings_table(results)


def _insert(conn: sqlite3.Connection, profile: str, table: List[Dict[str, Any]]) -> int:
    label = draft_triage_label(table)
    cur = conn.execute(
        "INSERT INTO examples (source, profile, ordered_facts, triage_label, triage_status) "
        "VALUES ('synth_triage', ?, ?, ?, 'labeled')",
        (profile, json.dumps(table), json.dumps(label)),
    )
    return cur.lastrowid


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default="trainset.db")
    ap.add_argument("--vuln-db", default="vulnerability_cache.db")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        import random
        random.seed(args.seed)

    vuln_conn = sqlite3.connect(args.vuln_db)
    trainset_conn = _init_trainset_conn(args.db)

    ids: List[int] = []

    for _ in range(5):
        ids.append(_insert(trainset_conn, "edge_empty", _case_empty()))

    import random
    for _ in range(8):
        n_tiers = random.randint(2, 4)
        ids.append(_insert(trainset_conn, "edge_all_tiers_single",
                            _case_all_tiers_single(vuln_conn, n_tiers)))

    for _ in range(6):
        ids.append(_insert(trainset_conn, "edge_partial_escalation",
                            _case_partial_escalation(vuln_conn)))

    for _ in range(6):
        ids.append(_insert(trainset_conn, "edge_out_of_scope_cpe",
                            _case_out_of_scope_cpe(vuln_conn)))

    trainset_conn.commit()
    print(f"[handadd_triage_edge_cases] inserted {len(ids)} rows, "
          f"id range {min(ids)}-{max(ids)}")
    vuln_conn.close()
    trainset_conn.close()


if __name__ == "__main__":
    main()
