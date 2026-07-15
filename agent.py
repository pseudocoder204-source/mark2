#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
mark2 — AI-powered security diagnostic for everyday users.

Architecture (see futurePlan.txt §0/§1): a fixed LangGraph DAG with a deterministic
spine and the LLM used only as a bounded side-car — never as the thing choosing what
to scan.

    scope_gate → scan_network → scan_iot_defaults → scan_filesystem → audit_host
        → scan_malware → scan_web → enrich → drift → intel → triage (deterministic, refs-only)
        → persist → report (LLM, refs-only) → END

Load-bearing rules enforced by code, not by prompt wording:
  - SCOPE GATE: the target is resolved and HMAC-signed into a scope_token *before* any
    worker node exists in the executable path. Every worker re-validates the token
    against its target before touching the network. The LLM never sees or holds the
    signing secret, so it cannot express a scan the gate hasn't already blessed.
  - WORKERS run in a fixed, deterministic order — never chosen by the model — which
    also eliminates the concurrent-tool-call race that previously caused a
    "database is locked" crash (two nmap pipelines hitting vulnerability_cache.db at
    once). Each worker is wrapped so a scanner failure degrades that one result to
    {"status": "error", ...} instead of crashing the whole run.
  - ENRICH builds a single findings table with a stable integer `ref` per finding.
    This table is the one and only source of facts from here on.
  - DRIFT (`drift.compute_drift`, notes/DriftPlan.md Phase 3) reads scan_log.db's
    prior finding_state *before* this run is persisted and classifies every finding
    as NEW/PERSISTING/WORSENED/IMPROVED/REAPPEARED/UNOBSERVED, annotating each table
    row with `drift_status`/`age_days`/`first_seen`/`reappearance_count`.
    UNOBSERVED — a scanner that didn't run this pass — is never read as "fixed".
  - INTEL (`exploit_intel.py`, notes/DriftPlan.md Phase 4) refreshes the local
    CISA KEV / FIRST EPSS cache (daily-cadence, self-throttling, never raises —
    a feed outage just leaves the cache as-is) and attaches kev/epss lookups per
    finding via `priority.build_intel_map`. Entirely optional grounding: with no
    CVE IDs or an empty cache a finding's exploitability term is just 0.0, no
    different from before this node existed.
  - TRIAGE calls `priority.rank` (notes/DriftPlan.md Phase 5): a deterministic,
    explainable 0-100 score over severity/exploitability/exposure/drift/age/
    fixability, with hard escalations (active malware, KEV on a reachable service,
    default creds, a fix that keeps getting undone) pinned to the top band
    regardless of score.
  - PERSIST (`persist_node`, formerly `call_scan_log_node`) writes this run's scan
    log *after* triage, using drift's verdict to decide whether an absent finding's
    `finding_state.status` becomes resolved or stays untouched (UNOBSERVED).
  - REPORT (notes/DriftPlan.md Phase 7) turns the ordered findings table into plain
    language across three independent sections: `fix_now` (escalations + top priority
    band), `still_open` (everything else, with age surfaced), and `resolved` (findings
    drift confirmed gone since last run). Only `fix_now`/`still_open` call the LLM —
    `resolved` has no analysis to do, so it's a pure-Python template, keeping the LLM
    call count at two, not three. Each LLM section's output is regex-validated to
    contain no CVE ID / CVSS number / CPE string; on a second consecutive validation
    failure that section is rendered by a pure-Python template built directly from
    the table instead of ever shipping an unvalidated LLM report. Drift markers
    (🆕 NEW / ⚠️ WORSENED / 🔁 BACK AGAIN / ⏳ OPEN N DAYS) are attached to each
    finding after the section is built, from the findings table, not from the LLM —
    so they survive whichever of the two report paths produced the section.

There is deliberately no free-form/autonomous mode (see futurePlan.txt — an agent
that can decide what to scan next is unacceptable here). This is the only agent.

Usage:
  python3 agent.py [--target IP_OR_HOST] [--json]

Read-only/history CLI ops (DriftPlan.md Phase 8) — each of these reads or writes
only scan_log.db and exits without running a scan or the LLM:
  python3 agent.py --target IP --history          # risk-score-over-time sparkline
  python3 agent.py --target IP --diff             # what changed since the last scan
  python3 agent.py --target IP --list-open        # ranked list --resolve-ref indexes into
  python3 agent.py --target IP --resolve FINDING_KEY
  python3 agent.py --target IP --resolve-ref N     # Nth item from --list-open
  python3 agent.py --target IP --forget           # delete this target's scan history

Env vars (all optional):
  TARGET              Scan target          (default: 127.0.0.1)
  LLM_PROVIDER        ollama (default) or claude
  OLLAMA_MODEL        Ollama model name for the report node
                      (default: pseudocoder204/mark2-report; llama3.1:8b also works)
  OLLAMA_HOST         Ollama base URL      (default: http://localhost:11434)
  ANTHROPIC_MODEL     Claude model for the report node (default: claude-opus-4-8)
  NVD_API_KEY   NVD key for faster sync
  DB_PATH       Path to vulnerability_cache.db  (default: vulnerability_cache.db) —
                also where the intel node caches CISA KEV / FIRST EPSS
  SCOPE_SECRET  HMAC secret for scope tokens (default: random per process)
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from typing import Any, Dict, List, Optional, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph

# from scanners.display_graph import display_graph  # testing-only visualization, not needed for the pipeline
from core import drift as drift_engine
from core import exploit_intel
from core import priority
from core import tools
from core.scan_log_db import (
    STATUS_OPEN,
    STATUS_RESOLVED,
    forget_target,
    get_finding_state,
    get_last_scan,
    get_observations,
    mark_solved,
    save_scan_log,
)

# The fine-tuned report model is the default because it is what install.sh/install.ps1
# pull and what the report prompt/output contract was trained against. Stock
# llama3.1:8b still works via OLLAMA_MODEL, but it is the fallback, not the happy path.
DEFAULT_OLLAMA_MODEL = "pseudocoder204/mark2-report"
DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"

# ── Scope gate (pure Python, no LLM) ──────────────────────────────────────────

_SCOPE_SECRET = os.environ.get("SCOPE_SECRET") or secrets.token_hex(16)
_SCOPE_TTL_SECONDS = 900


class ScopeError(Exception):
    pass


def make_scope_token(target: str, ttl: int = _SCOPE_TTL_SECONDS) -> str:
    expiry = int(time.time()) + ttl
    mac = hmac.new(_SCOPE_SECRET.encode(), f"{target}|{expiry}".encode(), hashlib.sha256).hexdigest()
    return f"{expiry}:{mac}"


def verify_scope_token(target: str, token: str) -> bool:
    try:
        expiry_str, mac = token.split(":", 1)
        expiry = int(expiry_str)
    except (ValueError, AttributeError):
        return False
    if time.time() > expiry:
        return False
    expected = hmac.new(_SCOPE_SECRET.encode(), f"{target}|{expiry}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected)


_TARGET_RE = re.compile(r"^[\w.\-/]+$")


def resolve_scope(target: str) -> str:
    """Validate the target and mint its scope_token. Raises ScopeError if invalid."""
    if not target or not _TARGET_RE.match(target):
        raise ScopeError(f"Invalid target format: {target!r}")
    return make_scope_token(target)


# ── Deterministic worker spine ────────────────────────────────────────────────
# Fixed order, never chosen by the model. Each entry: (result_key, needs_target, fn).

def _call_network(target: str) -> Any:
    return json.loads(tools._scan_network_no_sync(target))


def _call_iot_defaults(target: str) -> Any:
    return json.loads(tools._scan_iot_defaults_no_sync(target))


def _call_filesystem(_target: str) -> Any:
    return json.loads(tools.scan_filesystem.func())


def _call_host_audit(_target: str) -> Any:
    return json.loads(tools.audit_host.func())


def _call_malware(_target: str) -> Any:
    # Reads the shared result store instead of triggering a live clamscan run —
    # a full scan can take 1-4+ hours, and this spine must never block that
    # long. See tools.get_last_malware_result / clamav_parser.save_last_result.
    return tools.get_last_malware_result()


def _pick_web_scheme(results: Dict[str, Any], target: str) -> str:
    """Choose the scheme scan_web hits based on ports nmap already found open, instead
    of always forcing http:// (nuclei_subgraph's own default). Home routers commonly
    serve their admin UI on 443-only with a self-signed cert; forcing http:// against
    those hits a dead/empty port 80 and silently reports zero findings. Only ever
    scans ONE scheme — not both — so this doesn't add a second nuclei pass and
    doesn't change scan_web's runtime, just which port it points at.
    """
    open_ports: set = set()
    for source in ("network", "iot_defaults"):
        data = results.get(source)
        if isinstance(data, list):
            for rec in data:
                if isinstance(rec, dict) and rec.get("port") is not None:
                    open_ports.add(rec["port"])
    if 443 in open_ports:
        return f"https://{target}"
    if 80 in open_ports:
        return f"http://{target}"
    return target  # no port data available — let nuclei_subgraph's own http:// default apply


def _call_web(target: str, results: Dict[str, Any]) -> Any:
    return json.loads(tools.scan_web.func(_pick_web_scheme(results, target)))


_WORKERS = [
    ("network",      True,  _call_network),
    ("iot_defaults", True,  _call_iot_defaults),
    ("filesystem",   False, _call_filesystem),
    ("host_audit",   False, _call_host_audit),
    ("malware",      False, _call_malware),
    ("web",          True,  _call_web),
]


def scanner_status_map(results: Dict[str, Any]) -> Dict[str, str]:
    """Per-scanner outcome for this run, persisted onto the `scans` row.

    Load-bearing, not bookkeeping: a finding that is absent because its scanner
    never ran ("unavailable", "error", "skipped", the malware cache's "pending")
    must never be read as a finding the user fixed. This is the only record of
    which absences are trustworthy.
    """
    status: Dict[str, str] = {}
    for name, _needs_target, _fn in _WORKERS:
        result = results.get(name)
        if result is None:
            status[name] = "missing"
        elif isinstance(result, dict) and result.get("status"):
            status[name] = str(result["status"])
        else:
            status[name] = "ok"
    return status


def run_scan_phase(target: str, scope_token: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {}

    # Sync the NVD cache once here rather than letting scan_network and
    # scan_iot_defaults each re-sync it inside their own nmap_subgraph.run_pipeline()
    # call — see the "no_sync" worker fns above, which assume this already ran.
    try:
        print("[scan]  syncing NVD vulnerability cache...", file=sys.stderr)
        tools.sync_nmap_db()
    except Exception as exc:
        print(f"[scan]  NVD sync failed, continuing with existing cache: {exc}", file=sys.stderr)

    for name, needs_target, fn in _WORKERS:
        try:
            if needs_target and not verify_scope_token(target, scope_token):
                raise ScopeError("scope token invalid or expired before worker ran")
            print(f"[scan]  running {name} scan...", file=sys.stderr)
            results[name] = fn(target, results) if name == "web" else fn(target)
        except Exception as exc:
            print(f"[scan]  {name} failed: {exc}", file=sys.stderr)
            results[name] = {"status": "error", "reason": str(exc)}
    return results


# ── Enrich: deterministic findings table (single source of facts) ────────────

_TIER_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _severity_bucket(cvss: float) -> str:
    if cvss >= 9:
        return "critical"
    if cvss >= 7:
        return "high"
    if cvss >= 4:
        return "medium"
    return "low"


# ── Stable cross-run identity (finding_key) ──────────────────────────────────
#
# `ref` is a per-run integer the LLM cites; it means nothing across runs.
# `finding_key` is the opposite: the identity of the *problem*, stable across
# scans so a later run can tell "same thing, changed state" apart from "new
# thing". Everything that changes when a user actually fixes something —
# version, cvss, cve set, severity — is deliberately kept OUT of the key and
# carried as an attribute instead. Keying on the version string is what makes
# a patched service read as a brand-new finding while the old row can never be
# cleared.
#
# The two namespaces must not be merged: finding_key is bookkeeping and is
# never shown to the LLM (see _INTERNAL_FIELDS / llm_view).

# Drift fields (drift_status/age_days/first_seen/reappearance_count) are bookkeeping
# too: `priority.rank` reads them, and `_attach_drift_markers` (Phase 7) reads them
# to annotate the *rendered* report after the fact — but the report LLM itself never
# sees them, same reasoning as finding_key/version.
_INTERNAL_FIELDS = ("finding_key", "version", "drift_status", "age_days", "first_seen", "reappearance_count")


def llm_view(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The findings table as the report model sees it — cross-run bookkeeping
    stripped. Keeping this a separate projection is what lets the table grow new
    state fields without changing the model's input bytes."""
    return [{k: v for k, v in row.items() if k not in _INTERNAL_FIELDS} for row in rows]


def _key_part(value: Any, default: str = "unknown") -> str:
    part = re.sub(r"\s+", "_", str(value or "").strip().lower())
    return part or default


def build_findings_table(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    table: List[Dict[str, Any]] = []
    ref = 0

    seen_os_cpes: set = set()
    seen_ports: Dict[Any, int] = {}  # port -> index into table, for cross-source dedup
    for source in ("network", "iot_defaults"):
        data = results.get(source)
        if not isinstance(data, list):
            continue
        for rec in data:
            if not isinstance(rec, dict):
                continue

            # Host-level OS finding (kernel/OS CVEs), enriched off the host OS CPE rather
            # than a service port. Both the network and iot scans hit the same host, so
            # dedup by CPE to avoid listing the same OS twice.
            if rec.get("finding_type") == "host_os":
                os_cpe = rec.get("cpe")
                if os_cpe in seen_os_cpes:
                    continue
                seen_os_cpes.add(os_cpe)
                cvss = (rec.get("risk_metrics") or {}).get("max_cvss_score") or 0.0
                cve_ids = [v.get("cve_id") for v in (rec.get("priority_vulnerabilities") or []) if v.get("cve_id")]
                table.append({
                    "ref": ref,
                    "finding_key": f"os:{_key_part(rec.get('os_name'), 'this_device')}",
                    "source": "host_os",
                    "affected": f"Operating system: {rec.get('os_name') or 'this device'}",
                    "cpe": None,  # not an app CPE — no lookup_cves escalation on it
                    "version": None,
                    "cvss": cvss,
                    "severity": _severity_bucket(cvss),
                    "cve_ids": cve_ids,
                    "description": (rec.get("priority_vulnerabilities") or [{}])[0].get("description", ""),
                    "remediation_refs": rec.get("verified_patch_urls") or [],
                    "script_findings": None,
                })
                ref += 1
                continue

            # Both the network and iot scans hit the same host's same ports, so dedup
            # by port to avoid listing each service twice — but iot_defaults carries
            # NSE script_findings (http-default-accounts/upnp-info/snmp-info) that the
            # plain network scan doesn't, so merge that in rather than discarding it.
            port = rec.get("port")
            if port is not None and port in seen_ports:
                existing = table[seen_ports[port]]
                if not existing.get("script_findings") and rec.get("script_findings"):
                    existing["script_findings"] = rec.get("script_findings")
                continue

            cvss = (rec.get("risk_metrics") or {}).get("max_cvss_score") or 0.0
            cve_ids = [v.get("cve_id") for v in (rec.get("priority_vulnerabilities") or []) if v.get("cve_id")]
            product = " ".join(p for p in (rec.get("product"), rec.get("version")) if p)
            affected = f"Port {rec.get('port')} — {rec.get('service', '')}"
            if product:
                affected += f" {product}"
            table.append({
                "ref": ref,
                # Port + service is the asset; the version bump that follows a patch
                # is an attribute change on this same key, not a new finding.
                "finding_key": f"net:{rec.get('port')}/{_key_part(rec.get('protocol'), 'tcp')}:{_key_part(rec.get('service'))}",
                "source": source,
                "affected": affected.strip(),
                "cpe": rec.get("cpe"),
                "version": rec.get("version"),
                "cvss": cvss,
                "severity": _severity_bucket(cvss),
                "cve_ids": cve_ids,
                "description": (rec.get("priority_vulnerabilities") or [{}])[0].get("description", "") if rec.get("priority_vulnerabilities") else "",
                "remediation_refs": rec.get("verified_patch_urls") or [],
                "script_findings": rec.get("script_findings"),
            })
            if port is not None:
                seen_ports[port] = len(table) - 1
            ref += 1

    fs = results.get("filesystem")
    if isinstance(fs, dict):
        # Trivy's own payload builder (trivy_parser.build_llm_payload_from_trivy) lists
        # one entry per CVE, not per package — a package with 8 distinct CVEs produces 8
        # near-identical "affected" rows in the report. Dedup by package+version like
        # network dedups by port above: keep one row, merge every CVE into cve_ids, and
        # let the worst CVE's severity/description win.
        seen_packages: Dict[str, int] = {}  # "package|version" -> index into table
        for v in fs.get("priority_findings", []) or []:
            sev = str(v.get("severity", "")).lower()
            cvss = {"critical": 9.5, "high": 7.5, "medium": 5.0}.get(sev, 3.0)
            cve_id = v.get("cve_id")
            fixed_version = v.get("fixed_version")
            pkg_key = f"{v.get('package')}|{v.get('installed_version', '')}"

            if pkg_key in seen_packages:
                existing = table[seen_packages[pkg_key]]
                if cve_id and cve_id not in existing["cve_ids"]:
                    existing["cve_ids"].append(cve_id)
                if fixed_version and fixed_version not in existing["remediation_refs"]:
                    existing["remediation_refs"].append(fixed_version)
                if cvss > existing["cvss"]:
                    existing["cvss"] = cvss
                    existing["severity"] = _severity_bucket(cvss)
                    existing["description"] = v.get("description", "") or existing["description"]
                continue

            table.append({
                "ref": ref,
                "finding_key": f"pkg:{_key_part(v.get('package'))}",
                "source": "filesystem",
                "affected": f"Package: {v.get('package')} {v.get('installed_version', '')}".strip(),
                "cpe": None,
                "version": v.get("installed_version"),
                "cvss": cvss,
                "severity": _severity_bucket(cvss),
                "cve_ids": [cve_id] if cve_id else [],
                "description": v.get("description", ""),
                "remediation_refs": [fixed_version] if fixed_version else [],
                "script_findings": None,
            })
            seen_packages[pkg_key] = len(table) - 1
            ref += 1

    host = results.get("host_audit")
    if isinstance(host, dict):
        for v in host.get("priority_findings", []) or []:
            sev = str(v.get("severity", "")).lower()
            cvss = {"high": 7.5, "medium": 5.0}.get(sev, 3.0)
            table.append({
                "ref": ref,
                # test_id is already a stable catalog ID (Lynis SSH-7408, Windows WIN-DEFENDER-RT).
                "finding_key": f"audit:{_key_part(v.get('test_id'))}",
                "source": "host_audit",
                "affected": f"Host setting: {v.get('test_id')}",
                "cpe": None,
                "version": None,
                "cvss": cvss,
                "severity": _severity_bucket(cvss),
                "cve_ids": [],
                "description": v.get("description", ""),
                "remediation_refs": [v.get("solution")] if v.get("solution") else [],
                "script_findings": None,
            })
            ref += 1

    malware = results.get("malware")
    if isinstance(malware, dict):
        # Engine differs by OS: ClamAV on Linux, Windows Defender history on Windows.
        malware_engine = malware.get("engine", "ClamAV")
        for v in malware.get("priority_findings", []) or []:
            sev = str(v.get("severity", "")).lower()
            cvss = {"high": 9.0, "medium": 6.0}.get(sev, 3.0)
            table.append({
                "ref": ref,
                # Content hash would be the better identity (a path flaps when malware
                # relocates), but neither clamscan's FOUND lines nor Defender's threat
                # history supply one — fall back to path+signature.
                "finding_key": f"mal:{_key_part(v.get('sha256') or v.get('file_path'))}:{_key_part(v.get('signature'))}",
                "source": "malware",
                "affected": f"File: {v.get('file_path')}",
                "cpe": None,
                "version": None,
                "cvss": cvss,
                "severity": _severity_bucket(cvss),
                "cve_ids": [],
                "description": f"{malware_engine} signature match: {v.get('signature', '')}",
                "remediation_refs": [],
                "script_findings": None,
            })
            ref += 1

    web = results.get("web")
    if isinstance(web, dict):
        for v in web.get("priority_findings", []) or []:
            cvss = v.get("cvss_score") or {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0}.get(str(v.get("severity", "")).lower(), 3.0)
            table.append({
                "ref": ref,
                "finding_key": f"web:{_key_part(v.get('template_id'))}:{_key_part(v.get('matched_at') or v.get('host'), '')}",
                "source": "web",
                "affected": f"{v.get('name')} on {v.get('matched_at') or v.get('host', '')}".strip(),
                "cpe": None,
                "version": None,
                "cvss": cvss,
                "severity": _severity_bucket(cvss),
                "cve_ids": [v.get("cve_id")] if v.get("cve_id") else [],
                "description": v.get("description", ""),
                "remediation_refs": v.get("references") or [],
                "script_findings": None,
            })
            ref += 1

    return table


# ── Regex guards used by the report validator ─────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_CPE_RE = re.compile(r"cpe:2\.3:", re.IGNORECASE)


def _split_by_band(ranked: List[Dict[str, Any]]) -> tuple:
    """Partitions `priority.rank`'s output into (fix_now_refs, still_open_refs) using
    each finding's priority `band` (escalated or top-score findings land in
    priority.BAND_FIX_NOW; everything else is SOON/WATCH). `ranked` is already in
    priority order, so both partitions preserve it — this is a filter, not a re-sort.

    DriftPlan.md Phase 7 replaces the old new-vs-unresolved split (by `drift_status`)
    with this fix-now-vs-still-open split (by priority band): "new" vs "seen before"
    was never the question that mattered for what to act on first — a REAPPEARED
    critical and a PERSISTING low both count as "not new," but only one demands
    immediate action, which is exactly what `priority.rank`'s band already encodes.
    """
    fix_now_refs, still_open_refs = [], []
    for r in ranked:
        (fix_now_refs if r["band"] == priority.BAND_FIX_NOW else still_open_refs).append(r["ref"])
    return fix_now_refs, still_open_refs


# ── Report: LLM turns ordered facts into plain language, no invented literals ─

_REPORT_SYSTEM_PROMPT = """You are a friendly, knowledgeable security diagnostician helping \
everyday home users and small business owners understand the security health of their \
devices and network. Your audience has NO technical background — always use plain, \
everyday language.

You are given a JSON array of already-verified findings in priority order. Each finding \
already has an "affected" string and a "severity" tier computed for you — do not change \
severity, and do not invent any fact not present in the data you were given.

FINAL REPORT — respond with ONLY this JSON object (no prose, no markdown fences):
{
  "overall_risk": "<low|medium|high|critical>",
  "summary": "<2-3 plain sentences describing the overall security situation>",
  "findings": [
    {
      "title": "<short plain-English title>",
      "severity": "<low|medium|high|critical>",
      "what_it_means": "<1-2 sentences explaining this to a non-technical person>",
      "why_it_matters": "<1 sentence on the real-world risk>",
      "how_to_fix": "<numbered steps the user can actually follow>",
      "affected": "<copy the given 'affected' string>",
      "references": ["<url1>", "<url2>"]
    }
  ],
  "good_news": ["<one reassuring bullet per item that looks healthy>"]
}

CRITICAL RULES:
- Never write a CVE ID, a CVSS number/score, or a CPE string anywhere in the report. \
Translate everything to everyday language instead.
- "severity" in each finding must match the severity you were given for that finding.
- "affected" must be copied from the input data, not invented.
- Output ONLY the JSON object. No text before or after it.
"""


def _validate_report_text(report: Dict[str, Any]) -> bool:
    """Reject a report that leaked a raw CVE ID, CVSS score, or CPE string into a
    narrative field. 'references' is exempt: it holds source advisory URLs the
    model is instructed to copy verbatim, and those URLs legitimately embed CVE
    IDs in their path (e.g. github.com/.../CVE-2019-19447) — that's not a leak,
    it's the correct behavior of not paraphrasing a link."""
    top_level = {k: v for k, v in report.items() if k != "findings"}
    chunks = [json.dumps(top_level)]
    for finding in report.get("findings", []):
        if not isinstance(finding, dict):
            continue
        chunks.append(json.dumps({k: v for k, v in finding.items() if k != "references"}))
    combined = "\n".join(chunks)
    return not (_CVE_RE.search(combined) or _CPE_RE.search(combined))


def _validate_report_severities(report: Dict[str, Any], table: List[Dict[str, Any]]) -> bool:
    """Reject a report that changed a finding's severity or copied an unknown 'affected'.

    Severity is computed deterministically in the findings table; the LLM may only
    reorder and rephrase, never re-tier. This catches the failure the literal regex
    can't see — e.g. a CVSS-5.5 MEDIUM finding narrated as CRITICAL. Each report
    finding must copy an 'affected' string from the table and keep that finding's tier.
    """
    tier_by_affected = {f["affected"]: f["severity"] for f in table}
    for finding in report.get("findings", []):
        if not isinstance(finding, dict):
            return False
        affected = finding.get("affected")
        severity = str(finding.get("severity", "")).lower()
        if affected not in tier_by_affected:
            print(f"[report] rejected — 'affected' not copied from the findings table: {affected!r}", file=sys.stderr)
            return False
        if severity != tier_by_affected[affected]:
            print(f"[report] rejected — severity changed for {affected!r}: "
                  f"{tier_by_affected[affected]} → {severity}", file=sys.stderr)
            return False
    return True


def _deterministic_report(table: List[Dict[str, Any]], order: List[int]) -> Dict[str, Any]:
    """Pure-Python fallback report — no LLM, built directly from the findings table.
    Ships only if the LLM report fails literal-validation twice in a row."""
    by_ref = {f["ref"]: f for f in table}
    findings = []
    good_news = []
    worst_tier = 0

    for ref in order:
        f = by_ref[ref]
        worst_tier = max(worst_tier, _TIER_RANK.get(f["severity"], 0))
        if f["severity"] == "low":
            good_news.append(f"{f['affected']} looks fine — no significant issues found.")
            continue
        refs = [r for r in f.get("remediation_refs", []) if isinstance(r, str) and r.startswith("http")]
        findings.append({
            "title": f"Issue detected: {f['affected']}",
            "severity": f["severity"],
            "what_it_means": f["description"] or "This item was flagged during the scan as a potential security risk.",
            "why_it_matters": "An attacker could use this weakness to gain access or disrupt the affected system.",
            "how_to_fix": "1. Update or patch the affected software/setting to the latest version.\n2. If no update is available, disable or restrict access to the affected service.",
            "affected": f["affected"],
            "references": refs,
        })

    overall = {3: "critical", 2: "high", 1: "medium", 0: "low"}[worst_tier]
    return {
        "overall_risk": overall,
        "summary": f"The scan found {len(findings)} issue(s) that need attention out of {len(table)} item(s) reviewed.",
        "findings": findings,
        "good_news": good_news,
    }


# mark2-report was trained on inputs with a bounded number of facts; real hosts with
# a vulnerable OS plus several open services and IoT script findings routinely exceed
# that. Past the training distribution the model stops copying and starts inventing
# content, tripping _validate_report_severities. Chunking keeps every LLM call
# in-distribution; this is a stopgap until the model is retrained on the full range.
_REPORT_CHUNK_SIZE = 10


def _run_report_chunk(llm, chunk_table: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run the report LLM on one chunk (<= _REPORT_CHUNK_SIZE facts), 2 attempts,
    then fall back to the deterministic template for just this chunk."""
    order = [f["ref"] for f in chunk_table]
    messages = [
        SystemMessage(content=_REPORT_SYSTEM_PROMPT),
        HumanMessage(content=json.dumps(llm_view(chunk_table))),
    ]

    for attempt in range(2):
        response = llm.invoke(messages)
        text = response.content
        try:
            report = _parse_report(text)
        except ValueError:
            report = None
        if report is not None and _validate_report_text(report) and _validate_report_severities(report, chunk_table):
            return report
        print(f"[report] chunk attempt {attempt + 1} failed literal/schema/severity validation", file=sys.stderr)
        messages.append(HumanMessage(content=(
            "Your previous response was rejected: it either contained a raw CVE ID, "
            "CVSS number, or CPE string; was invalid JSON; or changed a finding's "
            "severity or its 'affected' text. Rewrite it: plain language only, valid "
            "JSON only, no code fences, copy each 'affected' string verbatim, and keep "
            "every 'severity' exactly as given in the input."
        )))

    print("[report] chunk falling back to deterministic template report", file=sys.stderr)
    return _deterministic_report(chunk_table, order)


def run_report(llm, table: List[Dict[str, Any]], order: List[int]) -> Dict[str, Any]:
    if not table:
        return {"overall_risk": "low", "summary": "No findings were reported by any scanner.", "findings": [], "good_news": ["Nothing suspicious was found."]}

    by_ref = {f["ref"]: f for f in table}
    ordered_facts = [by_ref[r] for r in order if r in by_ref]
    chunks = [ordered_facts[i:i + _REPORT_CHUNK_SIZE] for i in range(0, len(ordered_facts), _REPORT_CHUNK_SIZE)]

    findings: List[Dict[str, Any]] = []
    good_news: List[str] = []
    worst_tier = 0
    for i, chunk in enumerate(chunks):
        print(f"[report] generating chunk {i + 1}/{len(chunks)} ({len(chunk)} finding(s))...", file=sys.stderr)
        chunk_report = _run_report_chunk(llm, chunk)
        findings.extend(chunk_report.get("findings", []))
        good_news.extend(chunk_report.get("good_news", []))
        worst_tier = max(worst_tier, _TIER_RANK.get(str(chunk_report.get("overall_risk", "low")).lower(), 0))

    # Stitched deterministically rather than with one more LLM call over the
    # already-generated chunk summaries — keeps the merge itself failure-proof.
    overall = {3: "critical", 2: "high", 1: "medium", 0: "low"}[worst_tier]
    summary = f"The scan found {len(findings)} issue(s) that need attention out of {len(ordered_facts)} item(s) reviewed."
    return {"overall_risk": overall, "summary": summary, "findings": findings, "good_news": good_news}


def _parse_report(raw: str) -> dict:
    """Extract and parse the JSON report from the model's final response."""
    text = raw.strip()

    fence = re.search(r"```(?:json)?\s*\n(.*?)\n\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()

    brace = text.find("{")
    if brace > 0:
        text = text[brace:]

    def _collapse_htf(m: re.Match) -> str:
        content = m.group(1)
        lines = []
        for line in content.split("\n"):
            line = line.strip().rstrip(",")
            line = re.sub(r"^\{.*?'description'\s*:\s*'([^']*)'.*\}$", r"\1", line)
            line = re.sub(r"^\d+[.)]\s*", "", line).strip().strip('"').strip()
            if line:
                lines.append(line)
        numbered = "\\n".join(f"{i + 1}. {l}" for i, l in enumerate(lines))
        numbered = numbered.replace('"', '\\"')
        return f'"how_to_fix": "{numbered}"'

    text = re.sub(r'"how_to_fix":\s*\[(.*?)\]', _collapse_htf, text, flags=re.DOTALL)

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Model returned invalid JSON.\nParse error: {exc}\n\nRaw response:\n{raw}"
        ) from exc


# ── Drift markers + resolved section (DriftPlan.md Phase 7) ──────────────────
#
# These read `drift_status`/`age_days` straight off the findings table — never off
# the LLM's output — so a marker survives regardless of whether a section's report
# came back from the model or from `_deterministic_report`'s fallback template.

_DRIFT_MARKER_TEXT = {
    drift_engine.STATUS_NEW: "\U0001f195 NEW",  # 🆕
    drift_engine.STATUS_WORSENED: "⚠️ WORSENED",  # ⚠️
    drift_engine.STATUS_REAPPEARED: "\U0001f501 BACK AGAIN",  # 🔁
}


def _drift_marker(row: Dict[str, Any]) -> Optional[str]:
    status = row.get("drift_status")
    if status in _DRIFT_MARKER_TEXT:
        return _DRIFT_MARKER_TEXT[status]
    age_days = row.get("age_days")
    if status == drift_engine.STATUS_PERSISTING and age_days:
        return f"⏳ OPEN {age_days} DAYS"  # ⏳
    return None


def _attach_drift_markers(report: Dict[str, Any], table: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Annotates each rendered finding with a `drift_marker` (or None), matched back
    to the findings table by its 'affected' string — the same key
    `_validate_report_severities` already trusts as copied verbatim from the table."""
    by_affected = {f["affected"]: f for f in table}
    for finding in report.get("findings", []):
        if not isinstance(finding, dict):
            continue
        row = by_affected.get(finding.get("affected"))
        finding["drift_marker"] = _drift_marker(row) if row else None
    return report


def _resolved_report(resolved_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pure-Python 'resolved' section — no LLM call. Per DriftPlan.md Phase 7's own
    cost note: unlike fix_now/still_open, this section has no analysis to do, just a
    list of good news, so it's rendered directly from drift's `resolved_findings`
    snapshots instead of spending a third LLM round-trip on it."""
    good_news = [
        f"Fixed: {f.get('affected', 'an issue')} is no longer present."
        for f in resolved_findings
    ]
    return {"count": len(resolved_findings), "good_news": good_news}


def _format_scan_date(iso_ts: str) -> str:
    parsed = time.strptime(iso_ts, "%Y-%m-%dT%H:%M:%SZ")
    return time.strftime("%b %d", parsed).replace(" 0", " ")


def _drift_header(
    table: List[Dict[str, Any]],
    resolved_findings: List[Dict[str, Any]],
    previous_scan_at: Optional[str],
) -> Optional[str]:
    """The one-line 'Since your last scan on Jul 6: 2 new, 1 worsened, 3 resolved.'
    header. None on a target's first-ever run — there is no prior scan to diff
    against, and a fabricated 'no changes' header would be a lie the same way an
    UNOBSERVED finding read as resolved would be (see drift.py's module docstring)."""
    if not previous_scan_at:
        return None
    new_count = sum(1 for f in table if f.get("drift_status") == drift_engine.STATUS_NEW)
    worsened_count = sum(1 for f in table if f.get("drift_status") == drift_engine.STATUS_WORSENED)
    reappeared_count = sum(1 for f in table if f.get("drift_status") == drift_engine.STATUS_REAPPEARED)
    resolved_count = len(resolved_findings)

    parts = []
    if new_count:
        parts.append(f"{new_count} new")
    if worsened_count:
        parts.append(f"{worsened_count} worsened")
    if reappeared_count:
        parts.append(f"{reappeared_count} back again")
    if resolved_count:
        parts.append(f"{resolved_count} resolved")

    change_summary = ", ".join(parts) if parts else "no changes"
    return f"Since your last scan on {_format_scan_date(previous_scan_at)}: {change_summary}."


# ── LangGraph DAG: scope_gate → scan_phase → enrich → drift → intel → triage → persist → report → END

class AgentState(TypedDict, total=False):
    target: str
    scope_token: str
    raw_results: Dict[str, Any]
    findings_table: List[Dict[str, Any]]
    scanner_status: Dict[str, str]
    drift_records: Dict[str, Any]
    resolved_findings: List[Dict[str, Any]]
    intel_map: Dict[str, Any]
    fix_now_refs: List[int]
    still_open_refs: List[int]
    priority_order: List[int]
    priority_ranked: List[Dict[str, Any]]
    previous_scan_at: Optional[str]
    report: Dict[str, Any]
    error: str


def _route(state: AgentState) -> str:
    return END if state.get("error") else "continue"


def _get_llm(model: Optional[str] = None):
    provider = os.environ.get("LLM_PROVIDER", "ollama").lower()
    if provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=model or os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL),
            base_url=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
        )
    if provider == "claude":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=model or os.environ.get("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL))
    raise ValueError(f"Unknown LLM_PROVIDER={provider!r}. Use 'ollama' or 'claude'.")


def _get_report_llm():
    """The report node — this is the one FinetuneGuide.txt Step 15 tunes."""
    return _get_llm()


def _scan_log_db_path() -> str:
    return os.environ.get("SCAN_LOG_DB", "scan_log.db")


def _vuln_cache_db_path() -> str:
    # Same env var and default tools.py already reads for the NVD cache — KEV/EPSS
    # are enrichment data of the same class, stored in the same file (exploit_intel.py).
    return os.environ.get("DB_PATH", "vulnerability_cache.db")


def _resolved_status_overrides(drift_records: Dict[str, Any]) -> Dict[str, str]:
    """The only `finding_state.status` transition drift needs to force onto
    `save_scan_log`: a finding absent this run that drift confirmed RESOLVED
    (its scanner ran and it's genuinely gone). Present findings need no entry —
    `save_scan_log` already defaults an unlisted key to STATUS_OPEN on insert/
    update. An absent UNOBSERVED finding is deliberately omitted too, so
    `save_scan_log` leaves its prior status untouched; passing a status for it
    here would be exactly the "scanner didn't run this time" lie drift.py's
    module docstring calls the worst failure mode available.
    """
    return {
        key: STATUS_RESOLVED
        for key, rec in drift_records.items()
        if rec.get("status") == drift_engine.STATUS_RESOLVED_
    }


def _build_graph(report_llm):
    def scope_gate_node(state: AgentState) -> AgentState:
        try:
            token = resolve_scope(state["target"])
        except ScopeError as exc:
            return {"error": str(exc)}
        return {"scope_token": token}

    def scan_phase_node(state: AgentState) -> AgentState:
        results = run_scan_phase(state["target"], state["scope_token"])
        return {"raw_results": results}

    def enrich_node(state: AgentState) -> AgentState:
        table = build_findings_table(state["raw_results"])
        return {"findings_table": table}

    def drift_node(state: AgentState) -> AgentState:
        # Must read scan_log.db's prior finding_state BEFORE this run is persisted
        # (persist_node, which runs after triage) — compute_drift does that read
        # internally via scan_log_db.get_finding_state.
        db_path = _scan_log_db_path()
        scanner_status = scanner_status_map(state["raw_results"])
        records = drift_engine.compute_drift(
            state["target"], state["findings_table"], scanner_status, db_path
        )

        table = state["findings_table"]
        for finding in table:
            rec = records.get(finding["finding_key"])
            if rec is None:
                continue
            finding["drift_status"] = rec["status"]
            finding["age_days"] = rec["age_days"]
            finding["first_seen"] = rec["first_seen"]
            finding["reappearance_count"] = rec["reappearance_count"]

        # Findings gone since last run, reconstructed from their last-known
        # snapshot — not yet surfaced in the report (notes/DriftPlan.md Phase 7's
        # "good_news: you fixed N things" section), but computed here since drift
        # is the only node that has both the prior and current state in hand.
        resolved = [
            rec["snapshot"]
            for rec in records.values()
            if rec["status"] == drift_engine.STATUS_RESOLVED_ and rec.get("snapshot")
        ]

        return {
            "findings_table": table,
            "scanner_status": scanner_status,
            "drift_records": records,
            "resolved_findings": resolved,
        }

    def intel_node(state: AgentState) -> AgentState:
        db_path = _vuln_cache_db_path()
        # Both syncs swallow their own network/parse failures (exploit_intel.py's
        # module docstring) and leave the existing cache untouched rather than
        # raising — an enrichment feed must never become a hard dependency here.
        exploit_intel.sync_exploit_intel(db_path)
        intel_map = priority.build_intel_map(state["findings_table"], db_path)
        return {"intel_map": intel_map}

    def triage_node(state: AgentState) -> AgentState:
        ranked = priority.rank(
            state["findings_table"],
            drift=state.get("drift_records"),
            intel=state.get("intel_map"),
        )
        order = priority.ordered_refs(ranked)
        fix_now_refs, still_open_refs = _split_by_band(ranked)
        return {
            "priority_order": order,
            "priority_ranked": ranked,
            "fix_now_refs": fix_now_refs,
            "still_open_refs": still_open_refs,
        }

    def persist_node(state: AgentState) -> AgentState:
        db_path = _scan_log_db_path()
        # Read before save_scan_log below writes this run's own `scans` row, or
        # "previous" would resolve to the run we're in the middle of persisting.
        previous_scan = get_last_scan(db_path, state["target"])
        drift_records = state.get("drift_records") or {}
        # Persist the tool-output JSON exactly as it stands right before the
        # report LLM sees it — the durable, literal scan log — alongside which
        # scanners actually ran (what makes a *missing* finding interpretable on
        # the next run) and drift's open/resolved verdict for this run.
        save_scan_log(
            db_path,
            state["target"],
            state["findings_table"],
            scanner_status=state.get("scanner_status") or scanner_status_map(state["raw_results"]),
            drift=_resolved_status_overrides(drift_records),
        )
        return {"previous_scan_at": previous_scan["started_at"] if previous_scan else None}

    def report_node(state: AgentState) -> AgentState:
        table = state["findings_table"]
        resolved_findings = state.get("resolved_findings") or []

        fix_now_report = _attach_drift_markers(run_report(report_llm, table, state["fix_now_refs"]), table)
        still_open_report = _attach_drift_markers(run_report(report_llm, table, state["still_open_refs"]), table)
        resolved_report = _resolved_report(resolved_findings)

        report = {
            "drift_header": _drift_header(table, resolved_findings, state.get("previous_scan_at")),
            "fix_now": fix_now_report,
            "still_open": still_open_report,
            "resolved": resolved_report,
        }
        return {"report": report}

    graph = StateGraph(AgentState)
    graph.add_node("scope_gate", scope_gate_node)
    graph.add_node("scan_phase", scan_phase_node)
    graph.add_node("enrich", enrich_node)
    graph.add_node("drift", drift_node)
    graph.add_node("intel", intel_node)
    graph.add_node("triage", triage_node)
    graph.add_node("persist", persist_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("scope_gate")
    graph.add_conditional_edges("scope_gate", _route, {"continue": "scan_phase", END: END})
    graph.add_edge("scan_phase", "enrich")
    graph.add_edge("enrich", "drift")
    graph.add_edge("drift", "intel")
    graph.add_edge("intel", "triage")
    graph.add_edge("triage", "persist")
    graph.add_edge("persist", "report")
    graph.add_edge("report", END)

    app = graph.compile()
    # display_graph(app)
    return app


def run_agent(target: str) -> dict:
    """Drive the deterministic-spine DAG and return the parsed report dict."""
    report_llm = _get_report_llm()
    app = _build_graph(report_llm)

    final_state = app.invoke({"target": target})

    if final_state.get("error"):
        raise ScopeError(final_state["error"])

    return final_state["report"]


_BADGE = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def _render_section(section: dict, label: str) -> List[str]:
    overall = section.get("overall_risk", "unknown").lower()
    badge   = _BADGE.get(overall, "⚪")
    lines   = [
        f"── {label}   {badge} {overall.upper()} RISK ──",
        "",
        section.get("summary", ""),
        "",
    ]

    findings = section.get("findings", [])
    if findings:
        lines.append(f"── ISSUES FOUND ({len(findings)}) ──────────────────────────────────────")
        for i, f in enumerate(findings, 1):
            sev    = f.get("severity", "unknown").lower()
            fb     = _BADGE.get(sev, "⚪")
            marker = f" {f['drift_marker']}" if f.get("drift_marker") else ""
            lines += [
                "",
                f"  {i}. {fb} [{sev.upper()}]  {f.get('title', 'Unnamed issue')}{marker}",
                f"     Affected       : {f.get('affected', 'N/A')}",
                f"     What it means  : {f.get('what_it_means', '')}",
                f"     Why it matters : {f.get('why_it_matters', '')}",
            ]
            how = f.get("how_to_fix") or ""
            if isinstance(how, list):
                parts = []
                for s in how:
                    if isinstance(s, dict):
                        parts.append(s.get("description") or s.get("text") or str(s))
                    else:
                        parts.append(str(s))
                how = "\n".join(parts)
            how = how.strip()
            if how:
                lines.append("     How to fix:")
                for step in how.splitlines():
                    lines.append(f"       {step}")
            refs = f.get("references") or []
            if refs:
                lines.append("     References:")
                for r in refs[:3]:
                    lines.append(f"       • {r}")
    else:
        lines.append("  ✅  No issues found!")

    good = section.get("good_news") or []
    if good:
        lines += ["", "── GOOD NEWS ──────────────────────────────────────────────"]
        for item in good:
            lines.append(f"  ✅  {item}")

    return lines


def render_report(report: dict) -> str:
    lines = [
        "",
        "=" * 62,
        "  SECURITY DIAGNOSTIC REPORT",
        "=" * 62,
        "",
    ]
    header = report.get("drift_header")
    if header:
        lines += [header, ""]
    lines += _render_section(report.get("fix_now") or {}, "FIX NOW")
    lines += ["", "=" * 62, ""]
    lines += _render_section(report.get("still_open") or {}, "STILL OPEN")
    lines += ["", "=" * 62, ""]

    resolved = report.get("resolved") or {}
    good_news = resolved.get("good_news") or []
    if good_news:
        lines.append("── RESOLVED SINCE LAST SCAN ────────────────────────────────")
        for item in good_news:
            lines.append(f"  ✅  {item}")
        lines += ["", "=" * 62, ""]

    return "\n".join(lines)


# ── Phase 8: read-only CLI operations (history/diff/resolve/forget) ──────────
#
# None of these touch a scanner or the LLM — they only read/write scan_log.db,
# so they run instantly and work offline. Handled in `main()` before the scope
# gate / worker spine, and each one exits the process rather than falling
# through to a live scan.

_SPARK_CHARS = "▁▂▃▄▅▆▇█"  # ▁▂▃▄▅▆▇█


def _sparkline(values: List[float], vmax: float = 10.0) -> str:
    if not values:
        return ""
    n = len(_SPARK_CHARS) - 1
    return "".join(_SPARK_CHARS[min(n, max(0, int((v / vmax) * n)))] for v in values)


def _risk_history(db_path: str, target: str) -> List[Dict[str, Any]]:
    """One point per logged scan: the highest CVSS among findings actually seen
    (seen=1) that run, oldest first. Built from `observations` alone — no new
    schema needed, since every scan already writes a seen=0/1 row per known key."""
    by_scan: Dict[str, Dict[str, Any]] = {}
    for row in get_observations(db_path, target):
        entry = by_scan.setdefault(row["scan_id"], {"started_at": row["started_at"], "max_cvss": 0.0})
        if row["seen"] and (row.get("cvss") or 0.0) > entry["max_cvss"]:
            entry["max_cvss"] = row["cvss"]
    ordered = sorted(by_scan.items(), key=lambda kv: kv[1]["started_at"])
    return [{"scan_id": sid, **data} for sid, data in ordered]


def _print_history(db_path: str, target: str) -> None:
    history = _risk_history(db_path, target)
    if not history:
        print(f"No scan history for {target!r} yet — run a scan first.")
        return
    scores = [h["max_cvss"] for h in history]
    print(f"Risk history for {target} — {len(history)} scan(s):")
    print(f"  {_sparkline(scores)}   ({history[0]['started_at'][:10]} → {history[-1]['started_at'][:10]})")
    for h in history:
        print(f"    {h['started_at']}  max CVSS {h['max_cvss']:.1f}")


def _print_diff(db_path: str, target: str) -> None:
    diff = drift_engine.diff_last_two_scans(db_path, target)
    if diff is None:
        print(f"Not enough scan history for {target!r} to diff — need at least 2 logged scans.")
        return
    changes = diff["changes"]
    print(f"Changes for {target} — {diff['older_scan_at']} → {diff['latest_scan_at']}:")
    if not changes:
        print("  No changes.")
        return
    for rec in sorted(changes.values(), key=lambda r: (r["status"], -(r.get("cvss") or 0.0))):
        print(f"  [{rec['status']}] {rec['affected']}  (severity={rec.get('severity')}, cvss={rec.get('cvss')})")


def _reconstruct_open_table(db_path: str, target: str) -> List[Dict[str, Any]]:
    """Rebuilds a findings-table-shaped list for every currently open, unsolved
    finding on `target`, hydrated from each finding's last-known snapshot in
    `finding_state`. Assigns a fresh sequential `ref` (this table only ever
    exists for the duration of one CLI call, so those refs mean nothing beyond
    it — same rule as any other `ref`, see `build_findings_table`'s docstring).
    """
    state = get_finding_state(db_path, target)
    open_items = sorted(
        (kv for kv in state.items() if kv[1].get("status") == STATUS_OPEN and not kv[1].get("solved")),
        key=lambda kv: kv[0],  # stable base order; priority.rank fully re-sorts below
    )
    table = []
    for ref, (key, rec) in enumerate(open_items):
        finding = dict(rec.get("snapshot") or {})
        finding["ref"] = ref
        finding["finding_key"] = key
        finding["_first_seen"] = rec.get("first_seen")
        table.append(finding)
    return table


def _reconstruct_drift_map(db_path: str, target: str, table: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Best-effort `priority.rank`-shaped drift map, built without a live scan.
    Prefers the real drift status from the last two logged scans
    (`drift.diff_last_two_scans`) so `--resolve-ref`'s ordering uses the same
    signal a live report would have; a finding with no usable diff entry (e.g.
    only one scan has ever run, or it was already open before that) falls back
    to PERSISTING — no evidence of a fresh change either way, the same default
    `priority.py` itself uses for a first-ever run.
    """
    changes = {}
    diff = drift_engine.diff_last_two_scans(db_path, target)
    if diff:
        changes = diff["changes"]

    live_statuses = {
        drift_engine.STATUS_NEW, drift_engine.STATUS_WORSENED,
        drift_engine.STATUS_IMPROVED, drift_engine.STATUS_REAPPEARED,
    }
    drift_map = {}
    for f in table:
        key = f["finding_key"]
        change = changes.get(key)
        status = change["status"] if change and change["status"] in live_statuses else drift_engine.STATUS_PERSISTING
        first_seen = f.get("_first_seen")
        age_days = drift_engine.age_days_since(first_seen) if first_seen else 0
        drift_map[key] = {"status": status, "age_days": age_days}
    return drift_map


def _open_findings_ranked(db_path: str, target: str, vuln_cache_db_path: str) -> List[Dict[str, Any]]:
    """Currently-open, not-yet-solved findings for `target`, ordered by the same
    `priority.rank` algorithm the last report used — not a plain severity/CVSS
    approximation of it. Backs `--resolve-ref`. Exploit intel (`kev`/`epss`) is
    read from whatever's already cached in vulnerability_cache.db; this is a
    read-only, offline CLI op, so it deliberately does not trigger a network
    sync the way the `intel` DAG node does.
    """
    table = _reconstruct_open_table(db_path, target)
    if not table:
        return []
    drift_map = _reconstruct_drift_map(db_path, target, table)
    intel_map = priority.build_intel_map(table, vuln_cache_db_path)
    ranked = priority.rank(table, drift=drift_map, intel=intel_map)
    by_ref = {f["ref"]: f for f in table}
    return [by_ref[r["ref"]] for r in ranked]


def _print_open_findings(db_path: str, target: str, vuln_cache_db_path: str) -> None:
    """Prints the exact ranked list `--resolve-ref` consumes, numbered the same
    way. Exists because the normal report numbers findings per-section (FIX NOW
    starts at 1, STILL OPEN starts at 1 again), which does not line up with
    `--resolve-ref`'s single flat ranking across every open finding — this is
    the thing to actually look at before picking an N."""
    candidates = _open_findings_ranked(db_path, target, vuln_cache_db_path)
    if not candidates:
        print(f"No open findings for {target!r}.")
        return
    print(f"Open findings for {target} — ranked by priority (use --resolve-ref N):")
    for i, f in enumerate(candidates, 1):
        sev = str(f.get("severity", "unknown")).upper()
        print(f"  {i}. [{sev}] {f.get('affected', '(unknown)')}  (cvss={f.get('cvss')})")


def _resolve_finding(db_path: str, target: str, finding_key: Optional[str], ref: Optional[int]) -> None:
    if finding_key is None:
        candidates = _open_findings_ranked(db_path, target, _vuln_cache_db_path())
        if not candidates:
            print(f"No open findings for {target!r}.", file=sys.stderr)
            sys.exit(1)
        if ref is None or ref < 1 or ref > len(candidates):
            print(f"--resolve-ref must be between 1 and {len(candidates)} for {target!r}.", file=sys.stderr)
            sys.exit(1)
        finding_key = candidates[ref - 1]["finding_key"]
    mark_solved(db_path, target, finding_key, solved=True)
    print(
        f"Marked {finding_key!r} as solved for {target}. If it shows up again in a "
        "future scan, the report will flag it as a fix that didn't take."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="mark2: AI-powered security diagnostic for everyday users.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 agent.py\n"
            "  python3 agent.py --target 192.168.1.1\n"
            "  python3 agent.py --json > report.json\n"
            "  python3 agent.py --target 192.168.1.1 --history\n"
            "  python3 agent.py --target 192.168.1.1 --diff\n"
            "  python3 agent.py --target 192.168.1.1 --list-open\n"
            "  python3 agent.py --target 192.168.1.1 --resolve-ref 1\n"
            "  python3 agent.py --target 192.168.1.1 --forget\n\n"
            "Env vars: TARGET, LLM_PROVIDER, OLLAMA_MODEL, OLLAMA_HOST, "
            "ANTHROPIC_MODEL, NVD_API_KEY, DB_PATH, SCAN_LOG_DB, SCOPE_SECRET"
        ),
    )
    parser.add_argument(
        "--target",
        default=os.environ.get("TARGET", "127.0.0.1"),
        help="IP address or hostname to scan (default: 127.0.0.1 or $TARGET)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Print raw JSON report to stdout instead of the human-readable view.",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show the risk-score-over-time sparkline for --target from scan_log.db. No scan is run.",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Show what changed between the last two logged scans for --target. No scan is run.",
    )
    parser.add_argument(
        "--list-open",
        action="store_true",
        help="List --target's currently-open findings in the exact ranked order "
        "--resolve-ref uses (the normal report numbers FIX NOW/STILL OPEN "
        "separately, which does not match --resolve-ref's flat numbering). No "
        "scan is run.",
    )
    parser.add_argument(
        "--resolve",
        metavar="FINDING_KEY",
        help="Mark FINDING_KEY as manually solved for --target. If it reappears in a "
        "later scan, the report will call it out as a fix that didn't take.",
    )
    parser.add_argument(
        "--resolve-ref",
        type=int,
        metavar="N",
        help="Mark the Nth item from --list-open as solved (same priority-engine "
        "ranking, same numbering — run --list-open first to see it). This does not "
        "match the report's per-section numbering (FIX NOW/STILL OPEN each restart "
        "at 1); see --resolve to target an exact finding_key instead.",
    )
    parser.add_argument(
        "--forget",
        action="store_true",
        help="Delete all scan history for --target from scan_log.db. Cannot be undone.",
    )
    args = parser.parse_args()

    scan_log_path = _scan_log_db_path()
    if args.forget:
        forget_target(scan_log_path, args.target)
        print(f"Forgot all scan history for {args.target}.")
        return
    if args.list_open:
        _print_open_findings(scan_log_path, args.target, _vuln_cache_db_path())
        return
    if args.resolve or args.resolve_ref:
        _resolve_finding(scan_log_path, args.target, args.resolve, args.resolve_ref)
        return
    if args.diff:
        _print_diff(scan_log_path, args.target)
        return
    if args.history:
        _print_history(scan_log_path, args.target)
        return

    provider     = os.environ.get("LLM_PROVIDER", "ollama")
    report_model = (
        os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
        if provider == "ollama"
        else os.environ.get("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL)
    )
    print(f"[mark2] Target  : {args.target}", file=sys.stderr)
    print(f"[mark2] Backend : {provider} / {report_model}", file=sys.stderr)

    try:
        report = run_agent(args.target)
    except Exception as exc:
        print(f"\n[mark2] Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.output_json:
        print(json.dumps(report, indent=2))
    else:
        print(render_report(report))


if __name__ == "__main__":
    main()
