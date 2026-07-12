"""FinetuneGuideTriage.txt PHASE 5 fallback (invoked after Step 14 showed the
multi-turn tuned model doesn't beat _fallback_order — see finetune/
eval_triage_outputs.json / eval_triage_scores.json, 2026-07-12 run: tuned
intra-tier tau 0.824 vs fallback 0.882).

"re-export without the tool-call turns (input table -> final JSON only),
retrain, and let escalation stay a stock-model/non-tuned behavior" (guide,
PHASE 5). This isolates whether the reordering judgment itself (the FINAL
gold priority_order, which for escalated rows was informed by lookup_cves
detail at labeling time) is learnable directly from the table alone, without
also asking the 3B to learn the tool-calling protocol in the same pass.

Fork of export_triage_trainset.py: same source table
(triage_status='validated'), same _compact_user_content presentation
(ref-ascending, script_findings stripped), same split stratification — the
only difference is _build_messages, which drops every tool_call/tool turn
and keeps just [system, user, final assistant JSON]. No "tools" key is
written (this variant never calls lookup_cves, matching run_triage's
fallback if this doesn't clear the bar either: keep _fallback_order).

Usage:
    python3 export_triage_trainset_singleshot.py [--db trainset.db]
        [--out-dir finetune] [--eval-frac 0.1] [--seed 0]
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

from agent import _MAX_ESCALATIONS, _TRIAGE_SYSTEM_PROMPT

from export_triage_trainset import _compact_user_content, _escalation_shape, _load_validated, _stratify_split


def _build_messages_singleshot(table, triage_label):
    final_text = triage_label["trace"][-1]["content"]
    return [
        {"role": "system", "content": _TRIAGE_SYSTEM_PROMPT.format(budget=_MAX_ESCALATIONS)},
        {"role": "user", "content": _compact_user_content(table)},
        {"role": "assistant", "content": final_text},
    ]


def _write_jsonl(rows, path: Path):
    with path.open("w") as f:
        for _id, _source, _profile, ordered_facts, triage_label_json in rows:
            table = json.loads(ordered_facts)
            triage_label = json.loads(triage_label_json)
            record = {"messages": _build_messages_singleshot(table, triage_label)}
            f.write(json.dumps(record) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="trainset.db")
    parser.add_argument("--out-dir", default="finetune")
    parser.add_argument("--eval-frac", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    rows = _load_validated(args.db)
    if not rows:
        raise SystemExit(f"No triage_status='validated' rows found in {args.db}")

    train, eval_ = _stratify_split(rows, args.eval_frac, args.seed)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    train_path = out_dir / "train_triage_singleshot.jsonl"
    eval_path = out_dir / "eval_triage_singleshot.jsonl"
    _write_jsonl(train, train_path)
    _write_jsonl(eval_, eval_path)

    by_group = defaultdict(lambda: [0, 0])
    for _id, source, profile, _f, triage_label in train:
        by_group[(profile or source, _escalation_shape(triage_label))][0] += 1
    for _id, source, profile, _f, triage_label in eval_:
        by_group[(profile or source, _escalation_shape(triage_label))][1] += 1

    print(f"validated rows: {len(rows)}")
    print(f"train: {len(train)} -> {train_path}")
    print(f"eval:  {len(eval_)} -> {eval_path}")
    print(f"{'group':<24}{'shape':<12}{'train':>8}{'eval':>8}")
    for group, shape in sorted(by_group):
        t, e = by_group[(group, shape)]
        print(f"{group:<24}{shape:<12}{t:>8}{e:>8}")


if __name__ == "__main__":
    main()
