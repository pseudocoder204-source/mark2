# SPDX-License-Identifier: GPL-2.0-only
"""FinetuneGuideTriage.txt PHASE 5 fallback — score
finetune/eval_triage_singleshot_outputs.json (the single-shot tuned adapter's
and stock model's generations, table -> final JSON only, no tool calls)
against the same bar as score_triage_eval.py:

  Step 11: first-pass _validate_triage_order rejection rate (tuned vs stock).
  Step 12: intra-tier Kendall-tau vs Opus gold.
  Step 14: A/B floor — tuned must beat both stock and _fallback_order.

No Step 13 here — this variant never calls lookup_cves by construction, so
there's no escalation precision/recall to measure.

Usage:
    python3 score_triage_singleshot_eval.py
"""

import json
import pathlib
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import agent  # noqa: E402

_OUT_PATH = pathlib.Path(__file__).resolve().parent / "finetune" / "eval_triage_singleshot_outputs.json"
_SCORES_PATH = pathlib.Path(__file__).resolve().parent / "finetune" / "eval_triage_singleshot_scores.json"


def _tier_of(table: List[Dict[str, Any]]) -> Dict[int, str]:
    return {f["ref"]: f["severity"] for f in table}


def _kendall_tau(seq_gold: List[int], seq_pred: List[int]) -> Optional[float]:
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
        order = agent._fallback_order(table)
    taus = _intra_tier_taus(table, gold_order, order)
    return {"passed": passed, "order": order, "intra_tier_tau": taus}


def main() -> None:
    rows = json.loads(_OUT_PATH.read_text())

    per_row = []
    for row in rows:
        table = json.loads(row["ordered_facts_json"])
        gold_order = agent._validate_triage_order(row["gold_final_text"], table)
        if gold_order is None:
            print(f"[{row['index']}] WARNING: gold trace failed _validate_triage_order", file=sys.stderr)
            gold_order = agent._fallback_order(table)

        fallback_order = agent._fallback_order(table)
        tuned = _score_variant(table, gold_order, row["tuned_final_text"])
        stock = _score_variant(table, gold_order, row["stock_final_text"])
        fallback_taus = _intra_tier_taus(table, gold_order, fallback_order)

        per_row.append({
            "index": row["index"],
            "tuned_passed": tuned["passed"],
            "stock_passed": stock["passed"],
            "tuned_tau": tuned["intra_tier_tau"],
            "stock_tau": stock["intra_tier_tau"],
            "fallback_tau": fallback_taus,
        })

    n = len(per_row)

    def _rejection_rate(key):
        n_pass = sum(r[key] for r in per_row)
        return n_pass, n - n_pass

    def _mean_tau(key):
        vals = [t for r in per_row for t in r[key].values() if t is not None]
        return (sum(vals) / len(vals), len(vals)) if vals else (None, 0)

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
            print("  VERDICT: ship the single-shot tuned triage model.")
        else:
            print("  VERDICT: single-shot model does NOT clear the bar either — "
                  "keep _fallback_order, do not deploy any triage LoRA.")

    _SCORES_PATH.write_text(json.dumps(per_row, indent=2))
    print(f"\nWrote per-row scores to {_SCORES_PATH}")


if __name__ == "__main__":
    main()
