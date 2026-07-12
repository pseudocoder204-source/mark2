# SPDX-License-Identifier: GPL-2.0-only
"""
nuclei_subgraph.py — LangGraph subgraph edition of the Nuclei web scanner pipeline.

Both stages from nuclei_parser.py are each modelled as a LangGraph node:

    [scan_node] → [build_node] → END
          ↓              ↓
         END            END   (on error)

Usage — standalone:
    python3 nuclei_subgraph.py [target]

Usage — as a subgraph node inside a parent graph:
    from nuclei_subgraph import build_nuclei_subgraph
    parent.add_node("nuclei", build_nuclei_subgraph())

    The parent state must expose at least: target.
    On completion the subgraph writes back: raw_findings, payload, error.

Design note:
    Nuclei's httpx probe defaults to port 443 before 80. When the target does not
    serve HTTPS, httpx marks the host as permanently unresponsive and skips all
    templates — resulting in zero findings even for a live HTTP service. To avoid
    this, scan_node constructs an explicit http:// URL and passes it via -u instead
    of relying on httpx auto-discovery from a bare IP.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

from typing_extensions import TypedDict

from langgraph.graph import END, StateGraph
# from display_graph import display_graph  # testing-only visualization, not needed for the pipeline

from nuclei_parser import (
    build_llm_payload_from_nuclei,
    run_nuclei_scan,
)

# ── State ─────────────────────────────────────────────────────────────────────

class NucleiSubgraphState(TypedDict):
    # Inputs
    target:    str            # IP address or hostname to scan
    templates: Optional[str]  # optional path to a specific template or directory

    # Stage outputs — populated as the pipeline progresses
    raw_findings: List[Dict[str, Any]]  # Stage 1: raw Nuclei JSONL records
    payload:      Dict[str, Any]        # Stage 2: condensed LLM-ready payload

    # Set by any node on failure; causes the graph to route to END early
    error: Optional[str]

# ── Nodes ─────────────────────────────────────────────────────────────────────

def _scan_node(state: NucleiSubgraphState) -> Dict[str, Any]:
    """Stage 1 — Run Nuclei against the target and capture raw JSONL findings.

    Passes an explicit http:// URL via -u rather than a bare IP so that nuclei's
    built-in httpx probe does not attempt HTTPS first and mark the host as
    permanently unresponsive when port 443 is closed or filtered.
    """
    target    = state["target"]
    templates = state.get("templates")

    # Prepend scheme if the caller passed a bare IP or hostname so httpx doesn't
    # probe 443 before 80 and silently drop the target from the scan.
    url_target = target if target.startswith(("http://", "https://")) else f"http://{target}"

    print(f"[nuclei/scan]  target={url_target!r}", file=sys.stderr)
    try:
        raw_findings = run_nuclei_scan(target=url_target, templates=templates)
        print(f"[nuclei/scan]  {len(raw_findings)} raw finding(s) returned.", file=sys.stderr)
        return {"raw_findings": raw_findings}
    except Exception as exc:
        return {"error": str(exc)}


def _build_node(state: NucleiSubgraphState) -> Dict[str, Any]:
    """Stage 2 — Condense raw Nuclei JSONL output into a ranked, LLM-ready payload."""
    print("[nuclei/build] condensing findings for LLM context...", file=sys.stderr)
    try:
        payload = build_llm_payload_from_nuclei(
            raw_findings=state["raw_findings"],
            target=state["target"],
        )
        total = payload.get("risk_summary", {}).get("total_actionable", 0)
        print(f"[nuclei/build] enrichment complete — {total} actionable finding(s).", file=sys.stderr)
        return {"payload": payload}
    except Exception as exc:
        return {"error": str(exc)}

# ── Routing ───────────────────────────────────────────────────────────────────

def _route(state: NucleiSubgraphState) -> str:
    """Continue to the next node unless a previous node set an error."""
    return "error" if state.get("error") else "ok"

# ── Graph factory ─────────────────────────────────────────────────────────────

def build_nuclei_subgraph():
    """Build and compile the Nuclei scanner subgraph.

    Returns a compiled CompiledStateGraph that can be:
      • Invoked directly:  app.invoke({...})  / app.stream({...})
      • Embedded as a node in a parent graph via parent.add_node("nuclei", build_nuclei_subgraph())

    The parent state must include:
        target      — IP or hostname to scan
        templates   — (optional) template path override
    and will receive back:
        raw_findings, payload, error
    """
    graph = StateGraph(NucleiSubgraphState)

    graph.add_node("scan",  _scan_node)
    graph.add_node("build", _build_node)

    graph.set_entry_point("scan")

    graph.add_conditional_edges("scan",  _route, {"ok": "build", "error": END})
    graph.add_conditional_edges("build", _route, {"ok": END,     "error": END})

    return graph.compile()

# ── Convenience wrapper ───────────────────────────────────────────────────────

def run_pipeline(
    target:    str,
    templates: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the full scan → build pipeline.

    Mirrors the original nuclei_parser.py interface so this module can be swapped
    in wherever build_llm_payload_from_nuclei output is expected.

    Raises RuntimeError if any stage fails.
    """
    app = build_nuclei_subgraph()
    # display_graph(app)
    final_state = app.invoke({
        "target":       target,
        "templates":    templates,
        "raw_findings": [],
        "payload":      {},
        "error":        None,
    })
    if final_state.get("error"):
        raise RuntimeError(f"Nuclei pipeline failed: {final_state['error']}")
    return final_state["payload"]

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    target    = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TARGET", "127.0.0.1")
    templates = os.environ.get("NUCLEI_TEMPLATES")
    print(f"[nuclei_subgraph] scanning {target}...", file=sys.stderr)
    try:
        payload = run_pipeline(target=target, templates=templates)
        print(json.dumps(payload, indent=2))
    except RuntimeError as exc:
        print(f"[nuclei_subgraph] {exc}", file=sys.stderr)
        sys.exit(1)
