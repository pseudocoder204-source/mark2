"""Step 8 (FinetuneGuide.txt PHASE 3) — export chat-format JSONL from trainset.db.

Pulls status='validated' rows and writes a 90/10 train/eval split as chat-format
JSONL, one three-turn record per example, matching inference exactly:

    {"messages": [
        {"role": "system", "content": <_REPORT_SYSTEM_PROMPT verbatim>},
        {"role": "user", "content": <ordered_facts column, verbatim>},
        {"role": "assistant", "content": <label column, verbatim>}
    ]}

The system prompt is imported directly from agent.py (not copy-pasted) so the
export can never drift from what run_report actually sends at inference.

Split is stratified by (profile-or-source, tier-shape), where tier-shape is
derived from each row's gold label: "empty" (no findings, no good_news),
"all_good" (no findings, only good_news), "critical" (>=1 critical finding),
or "mixed" (findings present, none critical). Profile alone under-represents
shape diversity — e.g. compromised_machine and family_smarthome each contain
both "critical" and "mixed" rows — so stratifying on the pair guarantees every
tier-shape a profile can produce, and every real anchor, appears in eval too
(Step 3a/Step 9).

Usage:
    python3 export_trainset.py [--db trainset.db] [--out-dir .] [--eval-frac 0.1] [--seed 0]
"""

import argparse
import json
import random
import sqlite3
from collections import defaultdict
from pathlib import Path

from agent import _REPORT_SYSTEM_PROMPT


def _load_validated(db_path: str):
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, source, profile, ordered_facts, label "
            "FROM examples WHERE status = 'validated'"
        ).fetchall()
    finally:
        conn.close()
    return rows


def _tier_shape(label: str) -> str:
    report = json.loads(label)
    findings = report.get("findings", [])
    good_news = report.get("good_news", [])
    if not findings and not good_news:
        return "empty"
    if not findings:
        return "all_good"
    if any(f.get("severity") == "critical" for f in findings):
        return "critical"
    return "mixed"


def _stratify_split(rows, eval_frac: float, seed: int):
    groups = defaultdict(list)
    for row in rows:
        _id, source, profile, _facts, label = row
        key = (profile or source, _tier_shape(label))
        groups[key].append(row)

    rng = random.Random(seed)
    train, eval_ = [], []
    for key in sorted(groups):
        group_rows = groups[key][:]
        # Some synth rows are byte-identical (limited seed vocabulary produces
        # exact duplicates, e.g. plain low-severity findings with no CVEs).
        # Keep every row sharing the same ordered_facts on the same side of
        # the split so an eval example is never a verbatim copy of a train one.
        by_facts = defaultdict(list)
        for row in group_rows:
            by_facts[row[3]].append(row)
        content_units = list(by_facts.values())
        rng.shuffle(content_units)

        n_eval_target = max(1, round(len(group_rows) * eval_frac)) if group_rows else 0
        group_eval, group_train = [], []
        eval_count = 0
        for unit in content_units:
            if eval_count < n_eval_target:
                group_eval.extend(unit)
                eval_count += len(unit)
            else:
                group_train.extend(unit)
        eval_.extend(group_eval)
        train.extend(group_train)
    return train, eval_


def _write_jsonl(rows, path: Path):
    with path.open("w") as f:
        for _id, _source, _profile, ordered_facts, label in rows:
            record = {
                "messages": [
                    {"role": "system", "content": _REPORT_SYSTEM_PROMPT},
                    {"role": "user", "content": ordered_facts},
                    {"role": "assistant", "content": label},
                ]
            }
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
        raise SystemExit(f"No status='validated' rows found in {args.db}")

    train, eval_ = _stratify_split(rows, args.eval_frac, args.seed)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    train_path = out_dir / "train.jsonl"
    eval_path = out_dir / "eval.jsonl"
    _write_jsonl(train, train_path)
    _write_jsonl(eval_, eval_path)

    by_group = defaultdict(lambda: [0, 0])
    for _id, source, profile, _f, label in train:
        by_group[(profile or source, _tier_shape(label))][0] += 1
    for _id, source, profile, _f, label in eval_:
        by_group[(profile or source, _tier_shape(label))][1] += 1

    print(f"validated rows: {len(rows)}")
    print(f"train: {len(train)} -> {train_path}")
    print(f"eval:  {len(eval_)} -> {eval_path}")
    print(f"{'group':<24}{'shape':<10}{'train':>8}{'eval':>8}")
    for group, shape in sorted(by_group):
        t, e = by_group[(group, shape)]
        print(f"{group:<24}{shape:<10}{t:>8}{e:>8}")


if __name__ == "__main__":
    main()
