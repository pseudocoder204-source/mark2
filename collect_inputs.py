#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
collect_inputs.py — Step-3 training-input collector for the report LoRA.

Per FinetuneGuide.txt Step 3 ("Gather 150-400 real input rows"), this drives the
*deterministic* half of agent.py's DAG against a target and appends the resulting
`ordered_facts` row — the byte-for-byte input the report model sees at inference —
to a JSONL file. Gold outputs (Step 4) are drafted offline against these inputs.

Why a separate harness instead of just running agent.py:
  - The `ordered_facts` row is fully determined by run_scan_phase -> build_findings_table
    -> _fallback_order. None of that needs an LLM. But agent.py only *logs* the row
    inside run_report(), which sits AFTER the triage+report LLM calls — so using
    agent.py as-is would force an Ollama backend in every collection box just to reach
    the log line. This harness skips triage/report entirely.
  - `_fallback_order` is exactly the deterministic ordering triage itself falls back
    to, so the row produced here is faithful to the real pipeline's deterministic path.
  - The spine's malware stage reads a *cached* ClamAV result (get_last_malware_result);
    that's right for the product (a live scan can take hours) but wrong for data
    collection, where we want the live host findings (e.g. an EICAR test file). This
    harness runs a live ClamAV scan by default so the malware source actually appears.

Everything else — scope validation, per-worker error isolation, the findings table —
is imported from agent.py and tools.py, not reimplemented.

Usage (typically run *inside* each vulnerable VM so all six scanners hit that box):
    python3 collect_inputs.py --target 127.0.0.1 --label secgen-iot-01
    python3 collect_inputs.py --target 192.168.56.10 --malware skip --label web-box
"""
import argparse
import hashlib
import json
import os
import platform
import socket
import sys
import time
from typing import Any, Dict, List

import agent
import tools


# ── Live scan phase (mirrors agent.run_scan_phase, malware made configurable) ──

def _call_malware_live(_target: str) -> Any:
    """Live ClamAV scan via the existing tool — populates real malware findings
    (and updates the shared result store as a side effect). Slower than the spine's
    cache read, which is exactly why the spine doesn't do this, but for data
    collection we want the live findings, not a 'pending' placeholder."""
    return json.loads(tools.scan_malware.func())


def _call_malware_skip(_target: str) -> Any:
    return {"status": "skipped", "reason": "malware collection disabled via --malware skip"}


def _build_workers(malware_mode: str):
    """Same fixed spine as agent._WORKERS, with the malware stage swapped per mode."""
    malware_fn = {
        "live": _call_malware_live,
        "cache": lambda _t: tools.get_last_malware_result(),
        "skip": _call_malware_skip,
    }[malware_mode]
    return [
        ("network",      True,  agent._call_network),
        ("iot_defaults", True,  agent._call_iot_defaults),
        ("filesystem",   False, agent._call_filesystem),
        ("host_audit",   False, agent._call_host_audit),
        ("malware",      False, malware_fn),
        ("web",          True,  agent._call_web),
    ]


def run_scan_phase(target: str, scope_token: str, malware_mode: str) -> Dict[str, Any]:
    """Per-worker error isolation copied from agent.run_scan_phase — one scanner
    failing degrades to {"status": "error"} for that source instead of aborting."""
    results: Dict[str, Any] = {}
    for name, needs_target, fn in _build_workers(malware_mode):
        try:
            if needs_target and not agent.verify_scope_token(target, scope_token):
                raise agent.ScopeError("scope token invalid or expired before worker ran")
            print(f"[collect] running {name}...", file=sys.stderr)
            t0 = time.time()
            results[name] = fn(target)
            print(f"[collect]   {name} done in {time.time() - t0:.1f}s", file=sys.stderr)
        except Exception as exc:
            print(f"[collect]   {name} failed: {exc}", file=sys.stderr)
            results[name] = {"status": "error", "reason": str(exc)}
    return results


# ── Diversity bookkeeping (so you can eyeball whether the dataset is any good) ──

def _classify_shape(table: List[Dict[str, Any]]) -> str:
    if not table:
        return "empty"
    non_low = [f for f in table if f.get("severity") != "low"]
    if not non_low:
        return "all_good"
    if len(non_low) == 1:
        return "single_issue"
    return "mixed"


def _tier_histogram(table: List[Dict[str, Any]]) -> Dict[str, int]:
    hist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in table:
        hist[f.get("severity", "low")] = hist.get(f.get("severity", "low"), 0) + 1
    return hist


def _facts_hash(ordered_facts: List[Dict[str, Any]]) -> str:
    """Stable content hash of a row, for dedup ('not many copies of one')."""
    return hashlib.sha256(
        json.dumps(ordered_facts, sort_keys=True, default=str).encode()
    ).hexdigest()


def _existing_hashes(out_path: str) -> set:
    hashes: set = set()
    if not os.path.exists(out_path):
        return hashes
    with open(out_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            of = rec.get("ordered_facts")
            if isinstance(of, list):
                hashes.add(_facts_hash(of))
    return hashes


# ── Main ──────────────────────────────────────────────────────────────────────

def collect(target: str, label: str, out_path: str, malware_mode: str,
            allow_dupes: bool) -> Dict[str, Any]:
    try:
        scope_token = agent.resolve_scope(target)
    except agent.ScopeError as exc:
        raise SystemExit(f"[collect] invalid target: {exc}")

    started = time.time()
    results = run_scan_phase(target, scope_token, malware_mode)
    table = agent.build_findings_table(results)
    order = agent._fallback_order(table)

    # The full findings dicts in deterministic order.
    by_ref = {f["ref"]: f for f in table}
    ordered_facts = [by_ref[r] for r in order if r in by_ref]

    fhash = _facts_hash(ordered_facts)
    if not allow_dupes and fhash in _existing_hashes(out_path):
        print(f"[collect] duplicate row (hash {fhash[:12]}) already in {out_path} — "
              f"skipping. Use --allow-dupes to keep it.", file=sys.stderr)
        return {"written": False, "ordered_facts": ordered_facts, "table": table,
                "shape": _classify_shape(table), "hash": fhash}

    record = {
        "ordered_facts": ordered_facts,
        "raw_output": None,          # gold output is drafted offline, separately
        "passed_validation": None,
        "logged_at": time.time(),
        "_meta": {
            "label": label,
            "target": target,
            "collector_host": socket.gethostname(),
            "platform": platform.platform(),
            "platform_system": platform.system().lower(),
            "malware_mode": malware_mode,
            "shape": _classify_shape(table),
            "tier_histogram": _tier_histogram(table),
            "num_findings": len(table),
            "source_status": {
                k: (v.get("status") if isinstance(v, dict) else f"{len(v)} recs")
                for k, v in results.items()
            },
            "scan_seconds": round(time.time() - started, 1),
            "facts_hash": fhash,
        },
    }
    with open(out_path, "a") as f:
        f.write(json.dumps(record) + "\n")

    return {"written": True, "ordered_facts": ordered_facts, "table": table,
            "shape": record["_meta"]["shape"], "hash": fhash,
            "tier_histogram": record["_meta"]["tier_histogram"]}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect one report-LoRA training input (ordered_facts) from a scan target.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Run inside each vulnerable VM with --target 127.0.0.1 so all six scanners\n"
            "hit that box. Appends one JSONL row per run to --out (default:\n"
            "report_training_log.jsonl), the same file agent.py logs to."
        ),
    )
    parser.add_argument("--target", default=os.environ.get("TARGET", "127.0.0.1"),
                        help="IP/hostname to scan (default: 127.0.0.1 or $TARGET)")
    parser.add_argument("--label", default="unlabeled",
                        help="Provenance tag for this row, e.g. 'secgen-iot-01'")
    parser.add_argument("--out", default=os.environ.get("REPORT_TRAINING_LOG", "report_training_log.jsonl"),
                        help="Output JSONL path (default: report_training_log.jsonl)")
    parser.add_argument("--malware", choices=["live", "cache", "skip"], default="live",
                        help="live: run ClamAV now (default); cache: read last result; skip: omit")
    parser.add_argument("--allow-dupes", action="store_true",
                        help="Keep the row even if an identical ordered_facts is already in --out")
    parser.add_argument("--json", action="store_true", dest="output_json",
                        help="Print the produced ordered_facts JSON to stdout")
    args = parser.parse_args()

    print(f"[collect] target={args.target} label={args.label} malware={args.malware}",
          file=sys.stderr)
    result = collect(args.target, args.label, args.out, args.malware, args.allow_dupes)

    hist = result.get("tier_histogram")
    print(
        f"[collect] shape={result['shape']} "
        + (f"tiers={hist} " if hist else "")
        + f"findings={len(result['table'])} "
        + ("written" if result["written"] else "skipped(dupe)")
        + f" -> {args.out}",
        file=sys.stderr,
    )
    if args.output_json:
        print(json.dumps(result["ordered_facts"], indent=2))


if __name__ == "__main__":
    main()
