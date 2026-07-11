"""Step 13 (FinetuneGuide.txt PHASE 5) — score finetune/eval_outputs.json
(the tuned adapter's generations over the held-out eval set) against the REAL
validators from agent.py:

    _validate_report_text(text) and _parse_report(text) and
    _validate_report_severities(report, table)

"table" for each row is just json.loads(ordered_facts_json) — ordered_facts
entries are the exact table rows (see agent.py:562-563, run_report), so they
already carry "affected"/"severity" and satisfy _validate_report_severities's
lookup without needing to rebuild build_findings_table.

Usage:
    python3 finetune/score_eval.py
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import agent  # noqa: E402

_OUT_PATH = pathlib.Path(__file__).resolve().parent / "eval_outputs.json"


def score_row(row: dict) -> dict:
    table = json.loads(row["ordered_facts_json"])
    raw_output = row["raw_output"]

    parse_error = None
    report = None
    try:
        report = agent._parse_report(raw_output)
    except ValueError as e:
        parse_error = str(e).split("\n")[0]

    text_ok = report is not None and agent._validate_report_text(report)

    severities_ok = False
    if report is not None:
        severities_ok = agent._validate_report_severities(report, table)

    passed = text_ok and report is not None and severities_ok
    return {
        "index": row["index"],
        "passed": passed,
        "text_ok": text_ok,
        "parsed_ok": report is not None,
        "parse_error": parse_error,
        "severities_ok": severities_ok,
    }


def main() -> None:
    rows = json.loads(_OUT_PATH.read_text())
    results = [score_row(r) for r in rows]

    n = len(results)
    n_pass = sum(r["passed"] for r in results)
    n_parse_fail = sum(not r["parsed_ok"] for r in results)
    n_text_fail = sum(r["parsed_ok"] and not r["text_ok"] for r in results)
    n_sev_fail = sum(r["parsed_ok"] and r["text_ok"] and not r["severities_ok"] for r in results)

    print(f"Eval set size: {n}")
    print(f"First-pass validation PASS: {n_pass}/{n} ({100 * n_pass / n:.1f}%)")
    print(f"First-pass validation REJECT: {n - n_pass}/{n} ({100 * (n - n_pass) / n:.1f}%)")
    print(f"  - failed JSON parse: {n_parse_fail}")
    print(f"  - failed literal check (raw CVE/CPE string): {n_text_fail}")
    print(f"  - failed severity/affected fidelity: {n_sev_fail}")

    failures = [r for r in results if not r["passed"]]
    if failures:
        print("\nFailed rows:")
        for r in failures:
            reason = (
                f"JSON parse error: {r['parse_error']}" if not r["parsed_ok"]
                else "literal CVE/CPE leak" if not r["text_ok"]
                else "severity/affected mismatch"
            )
            print(f"  [{r['index']}] {reason}")

    out_path = pathlib.Path(__file__).resolve().parent / "eval_scores.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nWrote per-row scores to {out_path}")


if __name__ == "__main__":
    main()
