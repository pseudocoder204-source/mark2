# SPDX-License-Identifier: GPL-2.0-only
"""One-off batch-labeling helper for trainset.db's triage channel (see
notes/FinetuneGuideTriage.txt PHASE 2, Step 4). Mirrors label_batch.py's role for the report
channel: not part of the shipped pipeline, a scratch script used interactively through Claude
Code to draft gold triage traces, then run through the real validators (Step 5) before
promoting status.

WHY ESCALATION IS STILL MEANINGFUL even though run_triage's `compact` input (agent.py:397)
only strips "script_findings" and otherwise keeps each finding's stored "description": every
finding in this trainset was built from exactly ONE synthetic CVE record (see
synth_findings_triage.py::_contested_service_record), but a cpe's REAL row set in
vulnerability_cache.db is usually much larger — the same cpe/version can match several CVEs
the synthetic finding never carried. `tools.lookup_cves.func(cpe)` surfaces that fuller,
real picture; deciding intra-tier order from it (rather than from the single pre-baked
description already visible) is the genuine, decidable signal Step 3's contest shapes were
built around. Confirmed empirically during Step 3: escalating a synthetic contested finding's
cpe reliably returns MORE cve rows than the one embedded in the table.

GOLD-LABEL POLICY (the deterministic stand-in for "Opus decides", scaled the same way
label_batch.py's template/classifier tables stand in for per-row LLM drafting):
  1. Walk tiers critical -> high -> medium -> low. Within each tier, group CVE-bearing
     findings (cve_ids + cpe present) by their exact cvss value — a group of >=2 is a tie
     _fallback_order alone can't break.
  2. Spend the shared 3-call budget on tied groups in tier-severity order (protect the
     escalations that matter most first); within a group, escalate members in ref order
     until the group is resolved or the budget runs out.
  3. For each escalated finding, call the REAL lookup_cves(cpe) and rank it by
     (max cvss_score among ALL returned CVEs, vulnerability-class severity of the CVE that
     hit that max) — the class ranking reuses label_batch.py's _VULN_CLASS_KEYWORDS ladder
     (rce > downgrade > bypass > privesc > infoleak > crash > other) rather than inventing a
     second one, so "worse" means the same thing here as it does in the report labels.
  4. Un-escalated members of a tied group get NO extra signal and stay in their original
     relative (ref-ascending) order — this is deliberately "keep _fallback_order" (Step 4c):
     teaching a preference between two findings the labeler never actually differentiated
     would be noise, not signal.
  5. Escalated members always outrank un-escalated members of the same tie (we confirmed one
     is worse via real data; the other is simply unknown, not equal).

Usage: python3 label_triage_batch.py <lo> <hi> [--relabel]
  --relabel  re-draft rows already labeled in this range (default: pending only)
"""

import json
import sqlite3
import sys
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from agent import _MAX_ESCALATIONS, _TIER_RANK, _validate_triage_order
from label_batch import _VULN_CLASS_KEYWORDS, _classify_vuln
from tools import lookup_cves

_CLASS_RANK = {cls: i for i, (cls, _) in enumerate(_VULN_CLASS_KEYWORDS)}
_WORST_CLASS_RANK = len(_VULN_CLASS_KEYWORDS)  # "other" bucket, ranks below every named class


def _lookup_impact(raw_json: str) -> Tuple[float, int]:
    """(max cvss among ALL real CVEs for this cpe, severity-class bonus of the worst one) —
    bigger is worse on both axes, so this sorts correctly with reverse=True."""
    try:
        records = json.loads(raw_json)
    except (json.JSONDecodeError, TypeError):
        return (0.0, 0)
    if not isinstance(records, list) or not records:
        return (0.0, 0)
    best = max(records, key=lambda r: r.get("cvss_score") or 0.0)
    max_cvss = best.get("cvss_score") or 0.0
    cls_rank = _CLASS_RANK.get(_classify_vuln(best.get("description") or ""), _WORST_CLASS_RANK)
    return (max_cvss, _WORST_CLASS_RANK - cls_rank)  # invert so lower class-rank -> bigger bonus


def draft_triage_label(table: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a gold multi-turn trace for one row's findings table. Returns
    {"trace": [...], "final_text": <json str>, "escalated_cpes": [...], "escalations_used": n}."""
    if not table:
        final_text = json.dumps({"priority_order": []})
        return {"trace": [{"role": "assistant", "content": final_text}],
                "final_text": final_text, "escalated_cpes": [], "escalations_used": 0}

    # Step 4a: present findings in ref-ascending ("original ref") order, never the gold order.
    presentation = sorted(table, key=lambda f: f["ref"])

    tiers_present = sorted({f["severity"] for f in presentation},
                            key=lambda s: -_TIER_RANK.get(s, 0))

    trace: List[Dict[str, Any]] = []
    escalated_cpes: List[str] = []
    impact: Dict[int, Tuple[float, int]] = {}
    escalations_used = 0

    for tier in tiers_present:
        by_cvss: Dict[float, List[Dict[str, Any]]] = defaultdict(list)
        for f in presentation:
            if f["severity"] == tier and f.get("cve_ids") and f.get("cpe"):
                by_cvss[f["cvss"]].append(f)
        for group in by_cvss.values():
            if len(group) < 2:
                continue
            for f in group:
                if escalations_used >= _MAX_ESCALATIONS:
                    break
                cpe = f["cpe"]
                result = lookup_cves.func(cpe)
                call_id = f"call_{escalations_used}"
                trace.append({"role": "assistant", "tool_calls": [
                    {"id": call_id, "name": "lookup_cves", "args": {"cpe": cpe}}
                ]})
                trace.append({"role": "tool", "tool_call_id": call_id, "content": result})
                impact[f["ref"]] = _lookup_impact(result)
                escalated_cpes.append(cpe)
                escalations_used += 1

    def sort_key(f: Dict[str, Any]):
        cvss_from_lookup, class_bonus = impact.get(f["ref"], (0.0, 0))
        escalated_flag = 1 if f["ref"] in impact else 0
        return (_TIER_RANK.get(f["severity"], 0), f["cvss"], escalated_flag, cvss_from_lookup, class_bonus)

    ordered = sorted(presentation, key=sort_key, reverse=True)
    order = [f["ref"] for f in ordered]
    final_text = json.dumps({"priority_order": order})
    trace.append({"role": "assistant", "content": final_text})

    return {"trace": trace, "final_text": final_text,
            "escalated_cpes": escalated_cpes, "escalations_used": escalations_used}


def main() -> None:
    lo, hi = int(sys.argv[1]), int(sys.argv[2])
    relabel = "--relabel" in sys.argv[3:]
    conn = sqlite3.connect("trainset.db")
    status_clause = "" if relabel else "AND triage_status = 'pending'"
    rows = conn.execute(
        f"SELECT id, ordered_facts FROM examples WHERE id BETWEEN ? AND ? "
        f"AND triage_status IS NOT NULL {status_clause} ORDER BY id",
        (lo, hi),
    ).fetchall()

    labeled = escalation_rows = zero_call_rows = warned = 0
    for _id, ordered_facts_json in rows:
        table = json.loads(ordered_facts_json)
        result = draft_triage_label(table)

        check = _validate_triage_order(result["final_text"], table)
        if check is None:
            print(f"[id={_id}] WARNING: self-check failed on freshly-drafted trace", file=sys.stderr)
            warned += 1

        conn.execute(
            "UPDATE examples SET triage_label = ?, triage_status = 'labeled' WHERE id = ?",
            (json.dumps(result), _id),
        )
        labeled += 1
        if result["escalations_used"] > 0:
            escalation_rows += 1
        else:
            zero_call_rows += 1

    conn.commit()
    print(f"\nbatch [{lo}-{hi}]: labeled={labeled} "
          f"escalation_rows={escalation_rows} zero_call_rows={zero_call_rows} warnings={warned}")


if __name__ == "__main__":
    main()
