"""Step 7-8 (notes/FinetuneGuideTriage.txt PHASE 3) — export multi-turn chat JSONL
from trainset.db's triage channel.

Pulls triage_status='validated' rows and writes a 90/10 train/eval split as
chat-format JSONL, one multi-turn record per example, matching run_triage
(agent.py) exactly:

    {"messages": [
        {"role": "system", "content": <_TRIAGE_SYSTEM_PROMPT.format(budget=3), verbatim>},
        {"role": "user", "content": <compact table, script_findings stripped,
                                      presented in ref-ascending order>},
        ... zero or more (assistant tool_call -> tool result) pairs ...,
        {"role": "assistant", "content": "{\\"priority_order\\": [...]}"}
    ], "tools": [<lookup_cves JSON schema>]}

The system prompt and escalation budget are imported directly from agent.py
(not copy-pasted), same discipline as export_trainset.py:35, so the export
can't drift from what run_triage actually sends at inference. The tool
schema is derived the same way LangChain's llm.bind_tools([lookup_cves])
derives it, via convert_to_openai_tool — this is the exact "tools" block
Ollama's Qwen2.5 template injects into the system turn at inference
(confirmed against `ollama show qwen2.5:7b --template`: assistant tool_calls
render as <tool_call>{"name":...,"arguments":...}</tool_call>, tool results
render as a user turn wrapped in <tool_response>...</tool_response> — the
same structure this script encodes).

The user-turn presentation order (ref-ascending, never the gold order) must
match label_triage_batch.draft_triage_label's Step 4a convention exactly,
since that's the input the gold trace in triage_label was actually drafted
against.

Split is stratified by (profile-or-source, escalation-vs-no-escalation) so
eval covers both tool-call and direct (zero-escalation) traces (Step 8).

Usage:
    python3 finetune/export_triage_trainset.py [--db trainset.db] [--out-dir finetune]
                                       [--eval-frac 0.1] [--seed 0]
"""

import argparse
import json
import random
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langchain_core.utils.function_calling import convert_to_openai_tool

import agent
from agent import _MAX_ESCALATIONS, _TRIAGE_SYSTEM_PROMPT
from tools import lookup_cves

_TOOL_SCHEMA = convert_to_openai_tool(lookup_cves)


def _load_validated(db_path: str):
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, source, profile, ordered_facts, triage_label "
            "FROM examples WHERE triage_status = 'validated'"
        ).fetchall()
    finally:
        conn.close()
    return rows


def _compact_user_content(table):
    # Ref-ascending presentation order, script_findings stripped — must match
    # label_triage_batch.draft_triage_label's `presentation` exactly, since
    # triage_label's gold trace was drafted against this exact ordering.
    presentation = sorted(table, key=lambda f: f["ref"])
    compact = [{k: v for k, v in f.items() if k != "script_findings"} for f in presentation]
    return json.dumps(compact)


_MAX_TOOL_RECORDS = 25


def _shrink_tool_content(content: str, max_records: int = _MAX_TOOL_RECORDS) -> str:
    """fetch_cves_from_local_cache (nmap_parser.py:477) has no cap on rows
    returned per cpe_base — a handful of contested cpes in this corpus pull
    back 400-1800+ CVE rows (many byte-identical duplicates), ballooning a
    single tool turn to 500K+ tokens and making MAX_SEQ_LENGTH unworkable.
    Dedupe exact-duplicate records, then, if still over the cap, keep the
    highest-cvss ones. This can't change what any gold label in this corpus
    was actually based on: label_triage_batch._lookup_impact only ever reads
    the single max-cvss record from a lookup_cves call, so that record always
    survives the cap. Stays valid JSON — never a truncated string."""
    try:
        records = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return content
    if not isinstance(records, list):
        return content

    seen = set()
    deduped = []
    for record in records:
        key = json.dumps(record, sort_keys=True)
        if key not in seen:
            seen.add(key)
            deduped.append(record)

    if len(deduped) > max_records:
        deduped.sort(key=lambda r: r.get("cvss_score") or 0.0, reverse=True)
        deduped = deduped[:max_records]

    return json.dumps(deduped)


def _trace_to_messages(trace):
    """Convert label_triage_batch's LangChain-shaped trace dicts into the HF
    chat-template shape Qwen2.5 (and Ollama's Go template for it) expects."""
    messages = []
    for turn in trace:
        role = turn["role"]
        if role == "assistant" and "tool_calls" in turn:
            messages.append({
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"name": tc["name"], "arguments": tc["args"]}}
                    for tc in turn["tool_calls"]
                ],
            })
        elif role == "tool":
            messages.append({"role": "tool", "content": _shrink_tool_content(turn["content"])})
        else:
            messages.append({"role": "assistant", "content": turn["content"]})
    return messages


def _build_messages(table, triage_label):
    # run_triage short-circuits to [] before sending anything to the LLM when
    # table is empty, but the empty shape should still be trained on ("so the
    # shape is seen") — include the user turn with what WOULD be sent ("[]")
    # so the record still looks like a real turn.
    messages = [
        {"role": "system", "content": _TRIAGE_SYSTEM_PROMPT.format(budget=_MAX_ESCALATIONS)},
        {"role": "user", "content": _compact_user_content(table)},
    ]
    messages.extend(_trace_to_messages(triage_label["trace"]))
    return messages


def _escalation_shape(triage_label: str) -> str:
    label = json.loads(triage_label)
    return "escalated" if label.get("escalations_used", 0) > 0 else "direct"


def _gold_differs_from_fallback(ordered_facts: str, triage_label: str) -> bool:
    """Whether Opus's gold order is the genuinely-hard case (differs from the
    free deterministic _fallback_order) or the easy case (agrees with it).
    Stratifying on this too (in addition to escalation-shape) matters because
    without it a 90/10 split can, by chance, dump most of the hard cases into
    train and leave eval unrepresentatively easy for _fallback_order — which
    is exactly what happened on the first triage eval split (2026-07-12):
    eval-only fallback-vs-gold tau was 0.882 vs 0.693 across the full
    corpus, making the tuned models look worse relative to fallback than
    they really are."""
    table = json.loads(ordered_facts)
    label = json.loads(triage_label)
    gold_order = agent._validate_triage_order(label["trace"][-1]["content"], table)
    if gold_order is None:
        return False
    return gold_order != agent._fallback_order(table)


def _stratify_split(rows, eval_frac: float, seed: int):
    groups = defaultdict(list)
    for row in rows:
        _id, source, profile, facts, triage_label = row
        key = (
            profile or source,
            _escalation_shape(triage_label),
            _gold_differs_from_fallback(facts, triage_label),
        )
        groups[key].append(row)

    rng = random.Random(seed)
    train, eval_ = [], []
    for key in sorted(groups):
        group_rows = groups[key][:]
        # Keep byte-identical ordered_facts together on one side of the split,
        # same reasoning as export_trainset.py's stratified split.
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
        for _id, _source, _profile, ordered_facts, triage_label_json in rows:
            table = json.loads(ordered_facts)
            triage_label = json.loads(triage_label_json)
            record = {
                "messages": _build_messages(table, triage_label),
                "tools": [_TOOL_SCHEMA],
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
        raise SystemExit(f"No triage_status='validated' rows found in {args.db}")

    train, eval_ = _stratify_split(rows, args.eval_frac, args.seed)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    train_path = out_dir / "train_triage.jsonl"
    eval_path = out_dir / "eval_triage.jsonl"
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
