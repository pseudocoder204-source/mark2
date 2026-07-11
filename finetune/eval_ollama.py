"""Step 17/18 (FinetuneGuide.txt) — run the deployed Ollama model (OLLAMA_MODEL,
e.g. mark2-report) over every row in eval.jsonl through the REAL agent.run_report
path (same retry-on-rejection + deterministic-template fallback prod uses), then
score against the same validators finetune/score_eval.py uses.

Unlike finetune/eval_modal.py (which generates once against the raw LoRA adapter
on Modal and is scored separately), this exercises the exact code path agent.py
runs in production: run_report's 2-attempt retry loop and its fallback to
_deterministic_report on repeated validation failure.

Usage:
    OLLAMA_MODEL=mark2-report python3 finetune/eval_ollama.py
    OLLAMA_MODEL=llama3.1:8b   python3 finetune/eval_ollama.py   # stock baseline
"""

import json
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import agent  # noqa: E402

_EVAL_PATH = pathlib.Path(__file__).resolve().parent / "eval.jsonl"


def _load_rows():
    rows = []
    with open(_EVAL_PATH) as f:
        for line in f:
            rows.append(json.loads(line))
    return rows


def main() -> None:
    model_name = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
    llm = agent._get_report_llm()

    rows = _load_rows()
    results = []
    n_pass = n_fallback = 0

    for i, rec in enumerate(rows):
        user_msg = rec["messages"][1]
        table = json.loads(user_msg["content"])
        order = [f["ref"] for f in table]

        t0 = time.time()
        report = agent.run_report(llm, table, order)
        elapsed = time.time() - t0

        # run_report already ran the real validators internally; re-derive
        # pass/fail by checking whether the result matches _deterministic_report
        # (its fallback signature: a single generic summary sentence) so we can
        # tell "model passed validation" from "fell back to the template".
        is_fallback = report.get("summary", "").startswith("The scan found")
        severities_ok = agent._validate_report_severities(report, table)
        passed = (not is_fallback) and severities_ok

        if passed:
            n_pass += 1
        if is_fallback:
            n_fallback += 1

        results.append({
            "index": i,
            "elapsed_s": round(elapsed, 2),
            "passed_first_pass": passed,
            "fell_back_to_template": is_fallback,
            "severities_ok": severities_ok,
            "report": report,
        })
        print(f"[{i + 1}/{len(rows)}] {'PASS' if passed else 'FALLBACK' if is_fallback else 'REJECT'} "
              f"({elapsed:.1f}s)", file=sys.stderr)

    n = len(results)
    mean_latency = sum(r["elapsed_s"] for r in results) / n if n else 0.0

    print(f"\nModel: {model_name}")
    print(f"Eval set size: {n}")
    print(f"Model-authored PASS (no fallback, severities intact): {n_pass}/{n} ({100 * n_pass / n:.1f}%)")
    print(f"Fell back to deterministic template: {n_fallback}/{n} ({100 * n_fallback / n:.1f}%)")
    print(f"Mean latency per report: {mean_latency:.2f}s")

    out_path = pathlib.Path(__file__).resolve().parent / f"eval_ollama_{model_name.replace(':', '_')}.json"
    out_path.write_text(json.dumps({
        "model": model_name,
        "n": n,
        "n_pass": n_pass,
        "n_fallback": n_fallback,
        "mean_latency_s": mean_latency,
        "rows": results,
    }, indent=2))
    print(f"Wrote detailed results to {out_path}")


if __name__ == "__main__":
    main()
