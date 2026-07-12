# SPDX-License-Identifier: GPL-2.0-only
"""Steps 11-14 (notes/FinetuneGuideTriage.txt PHASE 5) — score
finetune/eval_triage_outputs.json (finetune/eval_triage_modal.py's tuned +
stock generations over the held-out eval set) against the bar that matters:

  Step 11: first-pass _validate_triage_order rejection rate (tuned vs stock).
  Step 12: intra-tier ordering agreement vs Opus gold, Kendall-tau computed
           WITHIN each severity tier only (cross-tier order is fixed by
           monotonicity, so it carries no signal about what the LLM added).
  Step 13: escalation precision/recall vs gold's escalated cpes.
  Step 14: A/B floor — tuned must beat BOTH stock and the free
           _fallback_order baseline on Step 12, or triage tuning isn't worth
           shipping (agent.py keeps using _fallback_order either way, so a
           tie is a loss for the tuning effort, not a wash).

Usage:
    python3 score_triage_eval.py
"""

import json
import pathlib
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import agent  # noqa: E402

_OUT_PATH = pathlib.Path(__file__).resolve().parent / "finetune" / "eval_triage_7b_outputs.json"
_SCORES_PATH = pathlib.Path(__file__).resolve().parent / "finetune" / "eval_triage_7b_scores.json"


def _tier_of(table: List[Dict[str, Any]]) -> Dict[int, str]:
    return {f["ref"]: f["severity"] for f in table}


def _kendall_tau(seq_gold: List[int], seq_pred: List[int]) -> Optional[float]:
    """Pairwise concordance Kendall-tau restricted to refs present in both
    sequences. None if fewer than 2 comparable items (no signal)."""
    pos_pred = {ref: i for i, ref in enumerate(seq_pred)}
    items = [r for r in seq_gold if r in pos_pred]
    n = len(items)
    if n < 2:
        return None
    concordant = discordant = 0
    for i in range(n):
        for j in range(i + 1, n):
            pi, pj = pos_pred[items[i]], pos_pred[items[j]]
            if pi < pj:
                concordant += 1
            elif pi > pj:
                discordant += 1
    total = concordant + discordant
    return None if total == 0 else (concordant - discordant) / total


def _intra_tier_taus(table, gold_order: List[int], pred_order: List[int]) -> Dict[str, Optional[float]]:
    tier_by_ref = _tier_of(table)
    by_tier: Dict[str, List[int]] = {}
    for ref in gold_order:
        by_tier.setdefault(tier_by_ref.get(ref, "?"), []).append(ref)

    taus = {}
    for tier, refs in by_tier.items():
        if len(refs) < 2:
            continue
        pred_refs_in_tier = [r for r in pred_order if tier_by_ref.get(r) == tier]
        taus[tier] = _kendall_tau(refs, pred_refs_in_tier)
    return taus


def _score_variant(table, gold_order: List[int], raw_final_text: str):
    order = agent._validate_triage_order(raw_final_text, table)
    passed = order is not None
    if not passed:
        order = agent._fallback_order(table)  # same recovery run_triage applies
    taus = _intra_tier_taus(table, gold_order, order)
    return {"passed": passed, "order": order, "intra_tier_tau": taus}


def _escalation_prf(gold_cpes: List[str], pred_cpes: List[str]):
    gold_set, pred_set = set(gold_cpes), set(pred_cpes)
    tp = len(gold_set & pred_set)
    return {"tp": tp, "pred_total": len(pred_set), "gold_total": len(gold_set)}


def main() -> None:
    rows = json.loads(_OUT_PATH.read_text())

    per_row = []
    for row in rows:
        table = json.loads(row["ordered_facts_json"])
        gold_order = agent._validate_triage_order(row["gold"]["final_text"], table)
        if gold_order is None:
            print(f"[{row['index']}] WARNING: gold trace failed _validate_triage_order "
                  "(should be impossible — export only includes validated rows)", file=sys.stderr)
            gold_order = agent._fallback_order(table)

        fallback_order = agent._fallback_order(table)
        tuned = _score_variant(table, gold_order, row["tuned"]["final_text"])
        stock = _score_variant(table, gold_order, row["stock"]["final_text"])
        fallback_taus = _intra_tier_taus(table, gold_order, fallback_order)

        per_row.append({
            "index": row["index"],
            "tuned_passed": tuned["passed"],
            "stock_passed": stock["passed"],
            "tuned_tau": tuned["intra_tier_tau"],
            "stock_tau": stock["intra_tier_tau"],
            "fallback_tau": fallback_taus,
            "escalation": {
                "tuned": _escalation_prf(row["gold"]["escalated_cpes"], row["tuned"]["escalated_cpes"]),
                "stock": _escalation_prf(row["gold"]["escalated_cpes"], row["stock"]["escalated_cpes"]),
            },
        })

    n = len(per_row)

    def _rejection_rate(key):
        n_pass = sum(r[key] for r in per_row)
        return n_pass, n - n_pass

    def _mean_tau(key):
        vals = [t for r in per_row for t in r[key].values() if t is not None]
        return (sum(vals) / len(vals), len(vals)) if vals else (None, 0)

    def _micro_prf(variant):
        tp = sum(r["escalation"][variant]["tp"] for r in per_row)
        pred_total = sum(r["escalation"][variant]["pred_total"] for r in per_row)
        gold_total = sum(r["escalation"][variant]["gold_total"] for r in per_row)
        precision = tp / pred_total if pred_total else None
        recall = tp / gold_total if gold_total else None
        return precision, recall, tp, pred_total, gold_total

    print(f"Eval set size: {n}\n")

    print("== Step 11: first-pass validator rejection rate ==")
    for label, key in (("tuned", "tuned_passed"), ("stock", "stock_passed")):
        n_pass, n_rej = _rejection_rate(key)
        print(f"  {label:<6} PASS {n_pass}/{n} ({100*n_pass/n:.1f}%)  "
              f"REJECT {n_rej}/{n} ({100*n_rej/n:.1f}%)")

    print("\n== Step 12: intra-tier Kendall-tau vs Opus gold ==")
    for label, key in (("tuned", "tuned_tau"), ("stock", "stock_tau"), ("fallback", "fallback_tau")):
        mean, count = _mean_tau(key)
        shown = f"{mean:.3f}" if mean is not None else "n/a"
        print(f"  {label:<8} mean tau = {shown}  (over {count} contested tier-instances)")

    print("\n== Step 13: escalation precision/recall vs gold ==")
    for variant in ("tuned", "stock"):
        precision, recall, tp, pred_total, gold_total = _micro_prf(variant)
        p_shown = f"{precision:.3f}" if precision is not None else "n/a"
        r_shown = f"{recall:.3f}" if recall is not None else "n/a"
        print(f"  {variant:<6} precision={p_shown} recall={r_shown}  "
              f"(tp={tp}, pred_total={pred_total}, gold_total={gold_total})")

    print("\n== Step 14: A/B floor ==")
    tuned_mean, _ = _mean_tau("tuned_tau")
    stock_mean, _ = _mean_tau("stock_tau")
    fallback_mean, _ = _mean_tau("fallback_tau")
    if tuned_mean is None:
        print("  tuned produced no comparable contested tiers — cannot judge.")
    else:
        beats_fallback = fallback_mean is None or tuned_mean > fallback_mean
        beats_stock = stock_mean is None or tuned_mean > stock_mean
        print(f"  tuned={tuned_mean:.3f}  stock={stock_mean if stock_mean is None else f'{stock_mean:.3f}'}  "
              f"fallback={fallback_mean if fallback_mean is None else f'{fallback_mean:.3f}'}")
        print(f"  beats fallback: {beats_fallback}   beats stock: {beats_stock}")
        if beats_fallback and beats_stock:
            print("  VERDICT: ship the tuned triage model.")
        else:
            print("  VERDICT: tuned model does NOT clear the bar — "
                  "keep _fallback_order, do not deploy (see PHASE 5 fallback note).")

    _SCORES_PATH.write_text(json.dumps(per_row, indent=2))
    print(f"\nWrote per-row scores to {_SCORES_PATH}")


if __name__ == "__main__":
    main()
