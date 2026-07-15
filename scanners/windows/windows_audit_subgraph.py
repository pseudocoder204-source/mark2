# SPDX-License-Identifier: GPL-2.0-only
"""windows_audit_subgraph.py — LangGraph subgraph for the Windows host-hardening audit.

The Windows counterpart to lynis_subgraph.py. Same role in the pipeline (the host_audit
stage), same output contract, but Windows-native checks via PowerShell instead of Lynis.

    [scan_node] → [parse_node] → [build_node] → END
          ↓             ↓              ↓
         END           END            END   (on error)

Graph shape follows clamav_subgraph.py's simpler scan→parse→build (no separate enrich
node): the catalog lookup happens inline in windows_audit_parser's build stage, there is
no external report format to re-parse.

Usage — standalone:
    python3 -m scanners.windows.windows_audit_subgraph

Usage — as a subgraph node inside a parent graph:
    from scanners.windows.windows_audit_subgraph import build_windows_audit_subgraph
    parent.add_node("windows_audit", build_windows_audit_subgraph())

    No inputs required — the audit always inspects the local Windows host.
    On completion the subgraph writes back: raw_json, facts, payload, error.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from typing_extensions import TypedDict

from langgraph.graph import END, StateGraph
# from ..display_graph import display_graph  # testing-only visualization, not needed for the pipeline

from .windows_audit_parser import (
    build_llm_payload_from_windows_audit,
    parse_windows_audit,
    run_windows_audit,
)

# ── State ──────────────────────────────────────────────────────────────────────

class WindowsAuditSubgraphState(TypedDict):
    raw_json: str               # Stage 1: raw PowerShell JSON output
    facts:    Dict[str, Any]    # Stage 2: parsed check facts
    payload:  Dict[str, Any]    # Stage 3: condensed host_audit payload
    error:    Optional[str]

# ── Nodes ──────────────────────────────────────────────────────────────────────

def _scan_node(state: WindowsAuditSubgraphState) -> Dict[str, Any]:
    """Stage 1 — Run the batched PowerShell audit and capture its JSON."""
    print("[winaudit/scan]  launching PowerShell audit...", file=sys.stderr)
    try:
        raw = run_windows_audit()
        if not raw:
            return {"error": "Windows audit produced no output — is this a Windows host with PowerShell?"}
        return {"raw_json": raw}
    except Exception as exc:
        return {"error": str(exc)}


def _parse_node(state: WindowsAuditSubgraphState) -> Dict[str, Any]:
    """Stage 2 — Parse the JSON facts object."""
    print("[winaudit/parse] parsing audit facts...", file=sys.stderr)
    try:
        facts = parse_windows_audit(state["raw_json"])
        if not facts:
            return {"error": "Windows audit output was not valid JSON."}
        print(f"[winaudit/parse] {len(facts)} check fact(s) captured.", file=sys.stderr)
        return {"facts": facts}
    except Exception as exc:
        return {"error": str(exc)}


def _build_node(state: WindowsAuditSubgraphState) -> Dict[str, Any]:
    """Stage 3 — Evaluate facts into the ranked host_audit payload."""
    print("[winaudit/build] evaluating findings...", file=sys.stderr)
    try:
        payload = build_llm_payload_from_windows_audit(state["facts"])
        total = payload.get("risk_summary", {}).get("total_actionable", 0)
        idx   = payload.get("hardening_index")
        print(f"[winaudit/build] {total} actionable finding(s), hardening index: {idx}/100.",
              file=sys.stderr)
        return {"payload": payload}
    except Exception as exc:
        return {"error": str(exc)}

# ── Routing ────────────────────────────────────────────────────────────────────

def _route(state: WindowsAuditSubgraphState) -> str:
    return "error" if state.get("error") else "ok"

# ── Graph factory ──────────────────────────────────────────────────────────────

def build_windows_audit_subgraph():
    """Build and compile the Windows host-audit subgraph.

    No inputs required — always audits the local Windows host.
    On completion populates: raw_json, facts, payload, error.
    """
    graph = StateGraph(WindowsAuditSubgraphState)

    graph.add_node("scan",  _scan_node)
    graph.add_node("parse", _parse_node)
    graph.add_node("build", _build_node)

    graph.set_entry_point("scan")

    graph.add_conditional_edges("scan",  _route, {"ok": "parse", "error": END})
    graph.add_conditional_edges("parse", _route, {"ok": "build", "error": END})
    graph.add_conditional_edges("build", _route, {"ok": END,     "error": END})

    return graph.compile()

# ── Convenience wrapper ────────────────────────────────────────────────────────

def run_pipeline() -> Dict[str, Any]:
    """Run the full scan → parse → build pipeline.

    Mirrors lynis_subgraph.run_pipeline()'s interface so tools.audit_host() can swap it
    in on Windows with no downstream change. Raises RuntimeError if any stage fails.
    """
    app = build_windows_audit_subgraph()
    # display_graph(app)
    final_state = app.invoke({
        "raw_json": "",
        "facts":    {},
        "payload":  {},
        "error":    None,
    })
    if final_state.get("error"):
        raise RuntimeError(f"Windows audit pipeline failed: {final_state['error']}")
    return final_state["payload"]

# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[windows_audit_subgraph] auditing local host...", file=sys.stderr)
    try:
        payload = run_pipeline()
        print(json.dumps(payload, indent=2))
    except RuntimeError as exc:
        print(f"[windows_audit_subgraph] {exc}", file=sys.stderr)
        sys.exit(1)
