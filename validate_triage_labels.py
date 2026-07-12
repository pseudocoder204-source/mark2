# SPDX-License-Identifier: GPL-2.0-only
"""Step 5 of notes/FinetuneGuideTriage.txt PHASE 2: auto-filter every 'labeled' triage trace
through the REAL validators and promote to triage_status='validated' or 'rejected'. This is
the free reward signal — no human judgment involved, just re-running the same checks
run_triage itself applies at inference (agent.py) against the gold trace drafted by
label_triage_batch.py.

A row is promoted to 'validated' only if ALL hold:
  - _validate_triage_order(final_text, table) is not None
      (no CVE/CPE literal, valid JSON shape, refs a subset of the table, tier-monotonic)
  - escalations_used <= _MAX_ESCALATIONS
  - every escalated cpe is in valid_cpes for that table (the cpes actually present on the
    row's findings) — guards against an escalation drifting onto an out-of-scope cpe.
Anything that fails any check is marked 'rejected' with the reason printed to stderr so a
labeling bug can be traced back to label_triage_batch.py rather than silently dropped.

Usage: python3 validate_triage_labels.py <lo> <hi>
"""

import json
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Tuple

from agent import _MAX_ESCALATIONS, _validate_triage_order


def _check(table: List[Dict[str, Any]], label: Dict[str, Any]) -> Optional[str]:
    """Returns None if the row passes, else a short rejection reason."""
    final_text = label.get("final_text")
    if final_text is None:
        return "missing final_text"

    if _validate_triage_order(final_text, table) is None:
        return "failed _validate_triage_order"

    escalations_used = label.get("escalations_used", 0)
    if escalations_used > _MAX_ESCALATIONS:
        return f"escalations_used {escalations_used} > _MAX_ESCALATIONS {_MAX_ESCALATIONS}"

    valid_cpes = {f["cpe"] for f in table if f.get("cpe")}
    for cpe in label.get("escalated_cpes", []):
        if cpe not in valid_cpes:
            return f"escalated cpe {cpe!r} not in valid_cpes for this table"

    return None


def main() -> None:
    lo, hi = int(sys.argv[1]), int(sys.argv[2])
    conn = sqlite3.connect("trainset.db")
    rows = conn.execute(
        "SELECT id, ordered_facts, triage_label FROM examples "
        "WHERE id BETWEEN ? AND ? AND triage_status = 'labeled' ORDER BY id",
        (lo, hi),
    ).fetchall()

    validated = rejected = 0
    for _id, ordered_facts_json, triage_label_json in rows:
        table = json.loads(ordered_facts_json)
        label = json.loads(triage_label_json)

        reason = _check(table, label)
        if reason is None:
            conn.execute(
                "UPDATE examples SET triage_status = 'validated' WHERE id = ?", (_id,)
            )
            validated += 1
        else:
            print(f"[id={_id}] REJECTED: {reason}", file=sys.stderr)
            conn.execute(
                "UPDATE examples SET triage_status = 'rejected' WHERE id = ?", (_id,)
            )
            rejected += 1

    conn.commit()
    print(f"\nbatch [{lo}-{hi}]: validated={validated} rejected={rejected} "
          f"(of {len(rows)} labeled rows checked)")


if __name__ == "__main__":
    main()
