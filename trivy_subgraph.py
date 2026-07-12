# SPDX-License-Identifier: GPL-2.0-only
"""
trivy_subgraph.py — LangGraph subgraph edition of the Trivy filesystem pipeline.

Both stages from trivy_parser.py are each modelled as a LangGraph node:

    [scan_node] → [build_node] → END
          ↓              ↓
         END            END   (on error)

Usage — standalone:
    python3 trivy_subgraph.py

Usage — as a subgraph node inside a parent graph:
    from trivy_subgraph import build_trivy_subgraph
    parent.add_node("trivy", build_trivy_subgraph())

    The parent state needs no special inputs for Trivy (it always scans the local fs).
    On completion the subgraph writes back: raw_results, payload, error.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from typing_extensions import TypedDict

from langgraph.graph import END, StateGraph
# from display_graph import display_graph  # testing-only visualization, not needed for the pipeline

from trivy_parser import (
    build_llm_payload_from_trivy,
    run_local_trivy_scan,
)

# ── State ─────────────────────────────────────────────────────────────────────

class TrivySubgraphState(TypedDict):
    # Stage outputs — populated as the pipeline progresses
    raw_results: List[Dict[str, Any]]  # Stage 1: raw Trivy Results array
    payload:     Dict[str, Any]        # Stage 2: condensed LLM-ready payload

    # Set by any node on failure; causes the graph to route to END early
    error: Optional[str]

# ── Nodes ─────────────────────────────────────────────────────────────────────

def _scan_node(state: TrivySubgraphState) -> Dict[str, Any]:
    """Stage 1 — Run Trivy against the local filesystem and capture raw JSON results."""
    print("[trivy/scan]  launching Trivy filesystem scan...", file=sys.stderr)
    try:
        raw_results = run_local_trivy_scan()
        print(f"[trivy/scan]  {len(raw_results)} result target(s) returned.", file=sys.stderr)
        return {"raw_results": raw_results}
    except Exception as exc:
        return {"error": str(exc)}


def _build_node(state: TrivySubgraphState) -> Dict[str, Any]:
    """Stage 2 — Condense raw Trivy output into a ranked, LLM-ready payload."""
    print("[trivy/build] condensing findings for LLM context...", file=sys.stderr)
    try:
        payload = build_llm_payload_from_trivy(state["raw_results"])
        total   = payload.get("risk_summary", {}).get("total_actionable", 0)
        print(f"[trivy/build] enrichment complete — {total} actionable finding(s).", file=sys.stderr)
        return {"payload": payload}
    except Exception as exc:
        return {"error": str(exc)}

# ── Routing ───────────────────────────────────────────────────────────────────

def _route(state: TrivySubgraphState) -> str:
    """Continue to the next node unless a previous node set an error."""
    return "error" if state.get("error") else "ok"

# ── Graph factory ─────────────────────────────────────────────────────────────

def build_trivy_subgraph():
    """Build and compile the Trivy parser subgraph.

    Returns a compiled CompiledStateGraph that can be:
      • Invoked directly:  app.invoke({...})  / app.stream({...})
      • Embedded as a node in a parent graph via parent.add_node("trivy", build_trivy_subgraph())

    On completion the subgraph populates:
        raw_results, payload, error
    """
    graph = StateGraph(TrivySubgraphState)

    graph.add_node("scan",  _scan_node)
    graph.add_node("build", _build_node)

    graph.set_entry_point("scan")

    graph.add_conditional_edges("scan",  _route, {"ok": "build", "error": END})
    graph.add_conditional_edges("build", _route, {"ok": END,     "error": END})

    return graph.compile()

# ── Convenience wrapper ───────────────────────────────────────────────────────

def run_pipeline() -> Dict[str, Any]:
    """Run the full scan → build pipeline.

    Mirrors the original trivy_parser.py interface so this module can be swapped
    in wherever build_llm_payload_from_trivy output is expected.

    Raises RuntimeError if any stage fails.
    """
    app = build_trivy_subgraph()
    # display_graph(app)
    final_state = app.invoke({
        "raw_results": [],
        "payload":     {},
        "error":       None,
    })
    if final_state.get("error"):
        raise RuntimeError(f"Trivy pipeline failed: {final_state['error']}")
    return final_state["payload"]

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[trivy_subgraph] scanning local filesystem...", file=sys.stderr)
    try:
        payload = run_pipeline()
        print(json.dumps(payload, indent=2))
    except RuntimeError as exc:
        print(f"[trivy_subgraph] {exc}", file=sys.stderr)
        sys.exit(1)
