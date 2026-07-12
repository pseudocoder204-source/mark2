# SPDX-License-Identifier: GPL-2.0-only
"""
clamav_subgraph.py — LangGraph subgraph edition of the ClamAV malware-scan pipeline.

Three stages, each modelled as a LangGraph node:

    [scan_node] → [parse_node] → [build_node] → END
          ↓              ↓               ↓
         END            END             END   (on error)

Mirrors clamav_parser.py's three-stage design (STAGE 1 execution engine, STAGE 2
report parser, STAGE 4 LLM condensing layer) as graph nodes instead of a linear
main(). No enrich node is needed — unlike Lynis, ClamAV's FOUND-line signature
already carries everything (file path, signature name, inferred severity) needed
for the payload; there's no external catalog to cross-reference.

Usage — standalone:
    python3 clamav_subgraph.py

Usage — as a subgraph node inside a parent graph:
    from clamav_subgraph import build_clamav_subgraph
    parent.add_node("clamav", build_clamav_subgraph())

    No target input required — ClamAV always scans the local host's high-risk
    directories (see clamav_parser._DEFAULT_SCAN_PATHS).
    On completion the subgraph writes back: raw_output, parsed_report, payload, error.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

from typing_extensions import TypedDict

from langgraph.graph import END, StateGraph
# from display_graph import display_graph  # testing-only visualization, not needed for the pipeline

from clamav_parser import (
    DEFAULT_SCAN_TIMEOUT,
    build_llm_payload_from_clamav,
    parse_clamav_output,
    run_clamav_scan,
    save_last_result,
)

# ── State ─────────────────────────────────────────────────────────────────────

class ClamAVSubgraphState(TypedDict):
    # Optional inputs — override via env vars or pass directly
    scan_paths:       Optional[List[str]]
    scan_timeout:     int
    manifest_db_path: str
    force_full_scan:  bool

    # Stage outputs — populated as the pipeline progresses
    raw_output:    str              # Stage 1: raw clamscan stdout
    parsed_report: Dict[str, Any]   # Stage 2: structured infected/summary/mode
    payload:       Dict[str, Any]   # Stage 4: condensed LLM-ready payload

    # Set by any node on failure; causes the graph to route to END early
    error: Optional[str]

# ── Nodes ─────────────────────────────────────────────────────────────────────

def _scan_node(state: ClamAVSubgraphState) -> Dict[str, Any]:
    """Stage 1 — Run the ClamAV scan (full or incremental, per the manifest) and
    capture clamscan's raw stdout."""
    print("[clamav/scan]  launching scan...", file=sys.stderr)
    try:
        raw_output = run_clamav_scan(
            scan_paths=state.get("scan_paths"),
            scan_timeout=state.get("scan_timeout", DEFAULT_SCAN_TIMEOUT),
            manifest_db_path=state.get("manifest_db_path", "clamav_manifest.db"),
            force_full_scan=state.get("force_full_scan", False),
        )
        if not raw_output:
            return {"error": "ClamAV scan produced no output — is clamscan installed and are the scan paths present?"}
        lines = raw_output.count("\n")
        print(f"[clamav/scan]  captured {lines} output line(s).", file=sys.stderr)
        return {"raw_output": raw_output}
    except Exception as exc:
        return {"error": str(exc)}


def _parse_node(state: ClamAVSubgraphState) -> Dict[str, Any]:
    """Stage 2 — Parse clamscan's stdout into structured infected/summary/mode fields."""
    print("[clamav/parse] parsing scan output...", file=sys.stderr)
    try:
        parsed = parse_clamav_output(state["raw_output"])
        infected = len(parsed.get("infected", []))
        mode = parsed.get("scan_mode", "full")
        print(f"[clamav/parse] {infected} infected file(s) found (mode={mode}).", file=sys.stderr)
        return {"parsed_report": parsed}
    except Exception as exc:
        return {"error": str(exc)}


def _build_node(state: ClamAVSubgraphState) -> Dict[str, Any]:
    """Stage 4 — Condense the parsed report into a ranked, LLM-ready payload."""
    print("[clamav/build] condensing findings for LLM context...", file=sys.stderr)
    try:
        payload = build_llm_payload_from_clamav(
            state["parsed_report"], scan_paths=state.get("scan_paths")
        )
        total = payload.get("risk_summary", {}).get("total_actionable", 0)
        print(f"[clamav/build] enrichment complete — {total} actionable finding(s).", file=sys.stderr)
        return {"payload": payload}
    except Exception as exc:
        return {"error": str(exc)}

# ── Routing ───────────────────────────────────────────────────────────────────

def _route(state: ClamAVSubgraphState) -> str:
    """Continue to the next node unless a previous node set an error."""
    return "error" if state.get("error") else "ok"

# ── Graph factory ─────────────────────────────────────────────────────────────

def build_clamav_subgraph():
    """Build and compile the ClamAV parser subgraph.

    Returns a compiled CompiledStateGraph that can be:
      • Invoked directly:  app.invoke({...})  / app.stream({...})
      • Embedded as a node in a parent graph via parent.add_node("clamav", build_clamav_subgraph())

    No target input is required — ClamAV always scans the local host's
    high-risk directories.
    On completion the subgraph populates:
        raw_output, parsed_report, payload, error
    """
    graph = StateGraph(ClamAVSubgraphState)

    graph.add_node("scan",  _scan_node)
    graph.add_node("parse", _parse_node)
    graph.add_node("build", _build_node)

    graph.set_entry_point("scan")

    graph.add_conditional_edges("scan",  _route, {"ok": "parse", "error": END})
    graph.add_conditional_edges("parse", _route, {"ok": "build", "error": END})
    graph.add_conditional_edges("build", _route, {"ok": END,     "error": END})

    return graph.compile()

# ── Convenience wrapper ───────────────────────────────────────────────────────

def run_pipeline(
    scan_paths: Optional[List[str]] = None,
    scan_timeout: int = DEFAULT_SCAN_TIMEOUT,
    manifest_db_path: str = "clamav_manifest.db",
    force_full_scan: bool = False,
) -> Dict[str, Any]:
    """Run the full scan → parse → build pipeline.

    Mirrors the original clamav_parser.py interface so this module can be swapped
    in wherever build_llm_payload_from_clamav output is expected.

    On success, also persists the payload via save_last_result so a later,
    unrelated process (e.g. agent.py's deterministic spine) can read it back
    instantly instead of re-running the scan. This is what makes it safe to
    invoke this module from cron/a systemd timer as a background scanner: every
    completed run — scheduled or manual — updates the same shared result store.

    Raises RuntimeError if any stage fails.
    """
    app = build_clamav_subgraph()
    # display_graph(app)
    final_state = app.invoke({
        "scan_paths":       scan_paths,
        "scan_timeout":     scan_timeout,
        "manifest_db_path": manifest_db_path,
        "force_full_scan":  force_full_scan,
        "raw_output":       "",
        "parsed_report":    {},
        "payload":          {},
        "error":            None,
    })
    if final_state.get("error"):
        raise RuntimeError(f"ClamAV pipeline failed: {final_state['error']}")
    payload = final_state["payload"]
    save_last_result(manifest_db_path, payload)
    return payload

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    env_paths = os.environ.get("CLAMAV_SCAN_PATHS")
    scan_paths = env_paths.split(",") if env_paths else None

    timeout_env = os.environ.get("CLAMAV_SCAN_TIMEOUT")
    scan_timeout = int(timeout_env) if timeout_env else DEFAULT_SCAN_TIMEOUT

    manifest_db_path = os.environ.get("CLAMAV_MANIFEST_DB", "clamav_manifest.db")
    force_full_scan = os.environ.get("CLAMAV_FORCE_FULL_SCAN", "").lower() in ("1", "true", "yes")

    print("[clamav_subgraph] scanning local host...", file=sys.stderr)
    try:
        payload = run_pipeline(
            scan_paths=scan_paths,
            scan_timeout=scan_timeout,
            manifest_db_path=manifest_db_path,
            force_full_scan=force_full_scan,
        )
        print(json.dumps(payload, indent=2))
    except RuntimeError as exc:
        print(f"[clamav_subgraph] {exc}", file=sys.stderr)
        sys.exit(1)
