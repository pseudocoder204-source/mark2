# SPDX-License-Identifier: GPL-2.0-only
"""
nmap_subgraph.py — LangGraph subgraph edition of the nmap pipeline.

The DB init/sync stage is a separate graph from the scan/parse/enrich stage, so a
caller that invokes several nmap-backed scans back-to-back (e.g. agent.py's worker
spine, which calls scan_network then scan_iot_defaults) can sync the NVD cache once
instead of once per call:

    build_nmap_sync_subgraph():  [init_db_node] → [sync_db_node] → END
    build_nmap_subgraph():       [scan_node] → [parse_node] → [enrich_node] → END
                                        ↓              ↓               ↓
                                       END            END             END   (on error)

Usage — standalone:
    python3 nmap_subgraph.py [target]

Usage — as a subgraph node inside a parent graph:
    from nmap_subgraph import build_nmap_subgraph
    parent.add_node("nmap", build_nmap_subgraph())

    The parent state must expose at least: target, scan_type, db_path, nvd_api_key.
    On completion the subgraph writes back: raw_xml, findings, hosts, payload, error.
    The DB must already be initialised/synced — run build_nmap_sync_subgraph() (or
    call run_db_sync()) first.

    scan_type accepts: "version_detect" (default), "quick_syn", "host_discovery"
    (-sn, MAC-keyed host inventory — no CVE enrichment), "iot_default_creds"
    (-sV + http-default-accounts/upnp-info/snmp-info NSE scripts).
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from typing_extensions import TypedDict

from langgraph.graph import END, StateGraph
# from display_graph import display_graph  # testing-only visualization, not needed for the pipeline

from nmap_parser import (
    ScanType,
    ServiceFinding,
    HostFinding,
    build_host_os_findings,
    enrich_and_condense_findings,
    init_local_db,
    parse_nmap_xml,
    parse_nmap_host_discovery,
    run_nmap,
    sync_local_db_with_nvd,
)

# ── State ─────────────────────────────────────────────────────────────────────

class NmapSubgraphState(TypedDict):
    # Inputs
    target:      str           # IP address or hostname to scan
    scan_type:   str           # "version_detect" (default) | "quick_syn"
    db_path:     str           # path to vulnerability_cache.db
    nvd_api_key: str           # NVD API key — empty string uses the public (rate-limited) endpoint

    # Stage outputs — populated as the pipeline progresses
    db_ready: bool                   # True after init + sync complete
    raw_xml:  str                    # Stage 3: raw nmap XML string
    findings: List[Dict[str, Any]]   # Stage 4: serialised ServiceFinding dicts
    hosts:    List[Dict[str, Any]]   # Stage 4 (host_discovery only): serialised HostFinding dicts
    payload:  List[Dict[str, Any]]   # Stage 5: enriched LLM-ready payload

    # Set by any node on failure; causes the graph to route to END early
    error: Optional[str]


_SCAN_TYPE_MAP: Dict[str, ScanType] = {
    "version_detect":    ScanType.VERSION_DETECT,
    "quick_syn":         ScanType.QUICK_SYN,
    "host_discovery":    ScanType.HOST_DISCOVERY,
    "iot_default_creds": ScanType.IOT_DEFAULT_CREDS,
}

# ── Nodes ─────────────────────────────────────────────────────────────────────

def _init_db_node(state: NmapSubgraphState) -> Dict[str, Any]:
    """Stage 1 — Ensure the local SQLite schema exists.

    Creates the `local_cves` and `sync_metadata` tables if they are not already
    present, and migrates older DBs that predate the `resume_index` column.
    Safe to run on every invocation — all DDL statements use IF NOT EXISTS.
    """
    db_path = state.get("db_path") or "vulnerability_cache.db"
    print(f"[nmap/init_db] initialising DB at {db_path!r}", file=sys.stderr)
    try:
        init_local_db(db_path)
        return {"db_ready": False}   # db_ready becomes True only after sync succeeds
    except Exception as exc:
        return {"error": f"DB init failed: {exc}"}


def _sync_db_node(state: NmapSubgraphState) -> Dict[str, Any]:
    """Stage 2 — Incrementally sync the local CVE cache from NVD.

    On first run this performs a full NVD download (may take several minutes).
    On subsequent runs it only fetches CVEs modified since the last sync
    timestamp recorded in `sync_metadata`, making it fast for routine scans.
    """
    db_path     = state.get("db_path") or "vulnerability_cache.db"
    nvd_api_key = state.get("nvd_api_key") or ""
    print("[nmap/sync_db] syncing vulnerability cache with NVD...", file=sys.stderr)
    try:
        sync_local_db_with_nvd(db_path=db_path, api_key=nvd_api_key)
        return {"db_ready": True}
    except Exception as exc:
        return {"error": f"NVD sync failed: {exc}"}


def _scan_node(state: NmapSubgraphState) -> Dict[str, Any]:
    """Stage 1 — Run nmap and capture the raw XML output."""
    print(f"[nmap/scan]   target={state['target']!r}  type={state.get('scan_type', 'version_detect')}", file=sys.stderr)
    try:
        scan_type = _SCAN_TYPE_MAP.get(
            state.get("scan_type", "version_detect"), ScanType.VERSION_DETECT
        )
        raw_xml = run_nmap(state["target"], scan_type)
        return {"raw_xml": raw_xml}
    except Exception as exc:
        return {"error": str(exc)}


def _parse_node(state: NmapSubgraphState) -> Dict[str, Any]:
    """Stage 2 — Parse nmap XML into ServiceFinding (or HostFinding) records.

    Records are serialised to plain dicts for state storage because LangGraph
    state must be JSON-serialisable.
    """
    print("[nmap/parse]  parsing XML...", file=sys.stderr)
    scan_type = state.get("scan_type", "version_detect")
    try:
        if scan_type == "host_discovery":
            hosts: List[HostFinding] = parse_nmap_host_discovery(state["raw_xml"])
            print(f"[nmap/parse]  {len(hosts)} live host(s) found.", file=sys.stderr)
            return {"hosts": [asdict(h) for h in hosts], "findings": []}

        findings: List[ServiceFinding] = parse_nmap_xml(state["raw_xml"])
        print(f"[nmap/parse]  {len(findings)} open port(s) found.", file=sys.stderr)
        findings_dicts = [
            {
                "port":          f.port,
                "protocol":      f.protocol,
                "state":         f.state,
                "service_name":  f.service_name,
                "product":       f.product,
                "version":       f.version,
                "cpe":           f.cpe,
                "script_output": f.script_output,
            }
            for f in findings
        ]
        return {"findings": findings_dicts}
    except Exception as exc:
        return {"error": str(exc)}


def _enrich_node(state: NmapSubgraphState) -> Dict[str, Any]:
    """Stage 3 — Enrich findings with CVE data from the local SQLite cache.

    Host-discovery scans have no ports/CVEs to enrich — the host inventory list
    is already the final payload, so it passes through untouched.
    """
    if state.get("scan_type") == "host_discovery":
        hosts = state.get("hosts", [])
        print(f"[nmap/enrich] host_discovery scan — passing through {len(hosts)} host(s).", file=sys.stderr)
        return {"payload": hosts}

    print("[nmap/enrich] looking up CVEs...", file=sys.stderr)
    try:
        # Reconstruct ServiceFinding dataclasses from the serialised dicts
        findings = [
            ServiceFinding(
                port=d["port"],
                protocol=d["protocol"],
                state=d["state"],
                service_name=d["service_name"],
                product=d.get("product"),
                version=d.get("version"),
                cpe=d.get("cpe"),
                script_output=d.get("script_output", []),
            )
            for d in state["findings"]
        ]
        db_path = state.get("db_path") or "vulnerability_cache.db"
        payload = enrich_and_condense_findings(findings, db_path=db_path)
        # Host-OS CVEs are enriched here as a distinct host-level finding rather than
        # being mis-attributed to whichever service port carried the OS CPE.
        os_findings = build_host_os_findings(state.get("raw_xml", ""), db_path=db_path)
        if os_findings:
            print(f"[nmap/enrich] {len(os_findings)} host-OS finding(s) added.", file=sys.stderr)
        payload = payload + os_findings
        print(f"[nmap/enrich] enrichment complete — {len(payload)} record(s).", file=sys.stderr)
        return {"payload": payload}
    except Exception as exc:
        return {"error": str(exc)}

# ── Routing ───────────────────────────────────────────────────────────────────

def _route(state: NmapSubgraphState) -> str:
    """Continue to the next node unless a previous node set an error."""
    return "error" if state.get("error") else "ok"

# ── Graph factory ─────────────────────────────────────────────────────────────

def build_nmap_sync_subgraph():
    """Build and compile the DB init + NVD sync subgraph: init_db → sync_db → END.

    Split out from build_nmap_subgraph() so callers that make several nmap-backed
    calls in a row (e.g. agent.py's worker spine, which runs scan_network then
    scan_iot_defaults) can sync the NVD cache once via run_db_sync() rather than
    once per call.
    """
    graph = StateGraph(NmapSubgraphState)

    graph.add_node("init_db", _init_db_node)
    graph.add_node("sync_db", _sync_db_node)

    graph.set_entry_point("init_db")

    graph.add_conditional_edges("init_db", _route, {"ok": "sync_db", "error": END})
    graph.add_conditional_edges("sync_db", _route, {"ok": END,       "error": END})

    return graph.compile()


def build_nmap_subgraph():
    """Build and compile the nmap scan/parse/enrich subgraph: scan → parse → enrich → END.

    Returns a compiled CompiledStateGraph that can be:
      • Invoked directly:  app.invoke({...})  / app.stream({...})
      • Embedded as a node in a parent graph via parent.add_node("nmap", build_nmap_subgraph())

    Assumes the DB at db_path is already initialised and synced — run
    build_nmap_sync_subgraph() (or run_db_sync()) first.

    When embedded, the parent state must include the keys:
        target, scan_type, db_path
    and will receive back:
        raw_xml, findings, payload, error
    """
    graph = StateGraph(NmapSubgraphState)

    graph.add_node("scan",    _scan_node)
    graph.add_node("parse",   _parse_node)
    graph.add_node("enrich",  _enrich_node)

    graph.set_entry_point("scan")

    # Each node routes to END on error so the caller gets partial state with
    # the error message rather than an unhandled exception bubbling up.
    graph.add_conditional_edges("scan",    _route, {"ok": "parse",   "error": END})
    graph.add_conditional_edges("parse",   _route, {"ok": "enrich",  "error": END})
    graph.add_conditional_edges("enrich",  _route, {"ok": END,       "error": END})

    return graph.compile()

# ── Convenience wrappers ──────────────────────────────────────────────────────

def run_db_sync(db_path: str = "vulnerability_cache.db", nvd_api_key: str = "") -> None:
    """Run init_db → sync_db once. Raises RuntimeError if either stage fails.

    Call this once per process before a batch of run_pipeline(..., skip_sync=True)
    calls, instead of letting each one re-sync the NVD cache.
    """
    app = build_nmap_sync_subgraph()
    final_state = app.invoke({
        "db_path":     db_path,
        "nvd_api_key": nvd_api_key,
        "db_ready":    False,
        "error":       None,
    })
    if final_state.get("error"):
        raise RuntimeError(f"nmap DB sync failed: {final_state['error']}")


def run_pipeline(
    target:      str,
    scan_type:   str = "version_detect",
    db_path:     str = "vulnerability_cache.db",
    nvd_api_key: str = "",
    skip_sync:   bool = False,
) -> List[Dict[str, Any]]:
    """Run the nmap scan → parse → enrich pipeline.

    By default also runs init_db → sync_db first, so this remains a complete,
    self-contained call for standalone/manual use — mirrors the original
    nmap_parser.py interface so this module can be swapped in wherever
    enrich_and_condense_findings output is expected.

    Pass skip_sync=True when the caller has already synced the DB itself this
    process (via run_db_sync()) — e.g. agent.py's worker spine syncs once before
    calling scan_network/scan_iot_defaults, rather than syncing on every call.

    Raises RuntimeError if any stage fails.
    """
    if not skip_sync:
        run_db_sync(db_path=db_path, nvd_api_key=nvd_api_key)

    app = build_nmap_subgraph()
    # display_graph(app)
    final_state = app.invoke({
        "target":      target,
        "scan_type":   scan_type,
        "db_path":     db_path,
        "nvd_api_key": nvd_api_key,
        "db_ready":    True,
        "raw_xml":     "",
        "findings":    [],
        "hosts":       [],
        "payload":     [],
        "error":       None,
    })
    if final_state.get("error"):
        raise RuntimeError(f"nmap pipeline failed: {final_state['error']}")
    return final_state["payload"]


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    target      = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TARGET", "127.0.0.1")
    nvd_api_key = os.environ.get("NVD_API_KEY", "")
    db_path     = os.environ.get("DB_PATH", "vulnerability_cache.db")
    print(f"[nmap_parser_new] scanning {target}...", file=sys.stderr)
    try:
        payload = run_pipeline(target, nvd_api_key=nvd_api_key, db_path=db_path)
        print(json.dumps(payload, indent=2))
    except RuntimeError as exc:
        print(f"[nmap_parser_new] {exc}", file=sys.stderr)
        sys.exit(1)
