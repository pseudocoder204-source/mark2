#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
mark2 — AI-powered security diagnostic for everyday users.

Architecture (see futurePlan.txt §0/§1): a fixed LangGraph DAG with a deterministic
spine and the LLM used only as a bounded side-car — never as the thing choosing what
to scan.

    scope_gate → scan_network → scan_iot_defaults → scan_filesystem → audit_host
        → scan_malware → scan_web → enrich → triage (LLM, refs-only)
        → report (LLM, refs-only) → END

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
  - TRIAGE is an LLM call that may only reorder findings *within* their deterministic
    severity tier and may request CVE-detail escalations by `ref` (validated against
    the table, budget-limited). It cannot invent a finding or promote severity.
  - REPORT is an LLM call that turns the ordered findings table into plain language.
    Its output is regex-validated to contain no CVE ID / CVSS number / CPE string; on
    a second consecutive validation failure the report is rendered by a pure-Python
    template built directly from the table instead of ever shipping an unvalidated
    LLM report.

There is deliberately no free-form/autonomous mode (see futurePlan.txt — an agent
that can decide what to scan next is unacceptable here). This is the only agent.

Usage:
  python3 agent.py [--target IP_OR_HOST] [--json]

Env vars (all optional):
  TARGET              Scan target          (default: 127.0.0.1)
  LLM_PROVIDER        ollama (default) or claude
  OLLAMA_MODEL        Ollama model name for the report node (default: llama3.1:8b)
  OLLAMA_TRIAGE_MODEL Ollama model override for the triage node (default: OLLAMA_MODEL)
  OLLAMA_HOST         Ollama base URL      (default: http://localhost:11434)
  ANTHROPIC_MODEL         Claude model for the report node (default: claude-opus-4-8)
  ANTHROPIC_TRIAGE_MODEL  Claude model override for the triage node (default: ANTHROPIC_MODEL)
  NVD_API_KEY   NVD key for faster sync
  DB_PATH       Path to vulnerability_cache.db  (default: vulnerability_cache.db)
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

from display_graph import display_graph
import tools

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
    return json.loads(tools.scan_network.func(target))


def _call_iot_defaults(target: str) -> Any:
    return json.loads(tools.scan_iot_defaults.func(target))


def _call_filesystem(_target: str) -> Any:
    return json.loads(tools.scan_filesystem.func())


def _call_host_audit(_target: str) -> Any:
    return json.loads(tools.audit_host.func())


def _call_malware(_target: str) -> Any:
    # Reads the shared result store instead of triggering a live clamscan run —
    # a full scan can take 1-4+ hours, and this spine must never block that
    # long. See tools.get_last_malware_result / clamav_parser.save_last_result.
    return tools.get_last_malware_result()


def _call_web(target: str) -> Any:
    return json.loads(tools.scan_web.func(target))


_WORKERS = [
    ("network",      True,  _call_network),
    ("iot_defaults", True,  _call_iot_defaults),
    ("filesystem",   False, _call_filesystem),
    ("host_audit",   False, _call_host_audit),
    ("malware",      False, _call_malware),
    ("web",          True,  _call_web),
]


def run_scan_phase(target: str, scope_token: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    for name, needs_target, fn in _WORKERS:
        try:
            if needs_target and not verify_scope_token(target, scope_token):
                raise ScopeError("scope token invalid or expired before worker ran")
            print(f"[scan]  running {name}...", file=sys.stderr)
            results[name] = fn(target)
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
                    "source": "host_os",
                    "affected": f"Operating system: {rec.get('os_name') or 'this device'}",
                    "cpe": None,  # not an app CPE — no lookup_cves escalation on it
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
                "source": source,
                "affected": affected.strip(),
                "cpe": rec.get("cpe"),
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
        for v in fs.get("priority_findings", []) or []:
            sev = str(v.get("severity", "")).lower()
            cvss = {"critical": 9.5, "high": 7.5, "medium": 5.0}.get(sev, 3.0)
            table.append({
                "ref": ref,
                "source": "filesystem",
                "affected": f"Package: {v.get('package')} {v.get('installed_version', '')}".strip(),
                "cpe": None,
                "cvss": cvss,
                "severity": _severity_bucket(cvss),
                "cve_ids": [v.get("cve_id")] if v.get("cve_id") else [],
                "description": v.get("description", ""),
                "remediation_refs": [v.get("fixed_version")] if v.get("fixed_version") else [],
                "script_findings": None,
            })
            ref += 1

    host = results.get("host_audit")
    if isinstance(host, dict):
        for v in host.get("priority_findings", []) or []:
            sev = str(v.get("severity", "")).lower()
            cvss = {"high": 7.5, "medium": 5.0}.get(sev, 3.0)
            table.append({
                "ref": ref,
                "source": "host_audit",
                "affected": f"Host setting: {v.get('test_id')}",
                "cpe": None,
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
                "source": "malware",
                "affected": f"File: {v.get('file_path')}",
                "cpe": None,
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
                "source": "web",
                "affected": f"{v.get('name')} on {v.get('matched_at') or v.get('host', '')}".strip(),
                "cpe": None,
                "cvss": cvss,
                "severity": _severity_bucket(cvss),
                "cve_ids": [v.get("cve_id")] if v.get("cve_id") else [],
                "description": v.get("description", ""),
                "remediation_refs": v.get("references") or [],
                "script_findings": None,
            })
            ref += 1

    return table


# ── Triage: LLM reorders within tier + bounded, gated escalation ─────────────

_MAX_ESCALATIONS = 3
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_CPE_RE = re.compile(r"cpe:2\.3:", re.IGNORECASE)

_TRIAGE_SYSTEM_PROMPT = """You are a triage assistant. You are given a JSON array of \
already-verified security findings, each with a stable integer "ref" and a "severity" \
tier already computed for you (critical/high/medium/low).

Your job: decide the priority order to present these findings in. You may reorder \
findings only WITHIN the same severity tier — never move a finding to a different \
tier, and never drop or invent a ref.

If you need more CVE detail on a specific finding to judge its priority, call the \
lookup_cves tool with that finding's exact "cpe" value (only present on network/iot \
findings) — you have at most {budget} such calls.

When you are done, respond with ONLY this JSON object, nothing else:
{{"priority_order": [<ref>, <ref>, ...]}}

Never include a CVE ID, a CVSS number, or a CPE string anywhere in your response — \
refer to findings only by their ref number."""


def _fallback_order(table: List[Dict[str, Any]]) -> List[int]:
    ordered = sorted(table, key=lambda f: (_TIER_RANK.get(f["severity"], 0), f["cvss"]), reverse=True)
    return [f["ref"] for f in ordered]


def _validate_triage_order(raw_text: str, table: List[Dict[str, Any]]) -> Optional[List[int]]:
    if _CVE_RE.search(raw_text) or _CPE_RE.search(raw_text):
        print("[triage] rejected — response contained a raw CVE/CPE literal", file=sys.stderr)
        return None
    try:
        text = raw_text.strip()
        brace = text.find("{")
        if brace > 0:
            text = text[brace:]
        parsed = json.loads(text)
        order = [int(r) for r in parsed["priority_order"]]
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        print("[triage] rejected — response was not valid {\"priority_order\": [...]}", file=sys.stderr)
        return None

    valid_refs = {f["ref"] for f in table}
    if not set(order).issubset(valid_refs):
        print("[triage] rejected — order referenced a ref not in the findings table", file=sys.stderr)
        return None

    tier_by_ref = {f["ref"]: _TIER_RANK.get(f["severity"], 0) for f in table}
    tiers_seen = [tier_by_ref[r] for r in order]
    if tiers_seen != sorted(tiers_seen, reverse=True):
        print("[triage] rejected — order violated severity-tier monotonicity", file=sys.stderr)
        return None

    # Any findings the model omitted are appended in fallback order, never dropped.
    missing = [r for r in _fallback_order(table) if r not in order]
    return order + missing


def run_triage(llm, target: str, scope_token: str, table: List[Dict[str, Any]]) -> List[int]:
    if not table:
        return []

    lookup_tool = tools.lookup_cves
    llm_with_tool = llm.bind_tools([lookup_tool])

    compact = [{k: v for k, v in f.items() if k not in ("script_findings",)} for f in table]
    messages = [
        SystemMessage(content=_TRIAGE_SYSTEM_PROMPT.format(budget=_MAX_ESCALATIONS)),
        HumanMessage(content=json.dumps(compact)),
    ]

    valid_cpes = {f["cpe"] for f in table if f.get("cpe")}
    escalations_used = 0

    for _ in range(_MAX_ESCALATIONS + 1):
        response = llm_with_tool.invoke(messages)
        messages.append(response)
        if not getattr(response, "tool_calls", None):
            break
        for tc in response.tool_calls:
            cpe = tc["args"].get("cpe")
            if escalations_used >= _MAX_ESCALATIONS or cpe not in valid_cpes:
                # Escalation budget exhausted, or the requested CPE isn't in the
                # deterministic table — deny it before it ever executes.
                result = json.dumps({"error": "escalation denied: budget exhausted or cpe out of scope"})
            else:
                escalations_used += 1
                result = lookup_tool.func(cpe)
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})

    final_text = messages[-1].content if hasattr(messages[-1], "content") else ""
    if not isinstance(final_text, str) or not final_text.strip():
        # Model ended on a tool call/empty message — ask once more for the final JSON.
        forced = llm.invoke(messages + [HumanMessage(content=(
            "Stop calling tools. Respond with ONLY the JSON object "
            '{"priority_order": [...]} now.'
        ))])
        final_text = forced.content

    order = _validate_triage_order(final_text, table)
    if order is None:
        print("[triage] falling back to deterministic severity-tier ordering", file=sys.stderr)
        order = _fallback_order(table)
    return order


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


_TRAINING_LOG_PATH = os.environ.get("REPORT_TRAINING_LOG", "report_training_log.jsonl")


def _log_training_input(ordered_facts: List[Dict[str, Any]], raw_output: Optional[str] = None, passed_validation: Optional[bool] = None) -> None:
    """Append one raw (input, output, pass/fail) triple to the report-LLM training log.

    Per FinetuneGuide.txt Step 2: this is the training-data collection point for the
    report LoRA — logging the exact ordered_facts the model saw plus whether its
    output passed the real validators gives a free rejection-rate baseline before
    any fine-tuning starts.
    """
    record = {
        "ordered_facts": ordered_facts,
        "raw_output": raw_output,
        "passed_validation": passed_validation,
        "logged_at": time.time(),
    }
    try:
        with open(_TRAINING_LOG_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        print(f"[report] failed to write training log: {e}", file=sys.stderr)


def run_report(llm, table: List[Dict[str, Any]], order: List[int]) -> Dict[str, Any]:
    if not table:
        return {"overall_risk": "low", "summary": "No findings were reported by any scanner.", "findings": [], "good_news": ["Nothing suspicious was found."]}

    by_ref = {f["ref"]: f for f in table}
    ordered_facts = [by_ref[r] for r in order if r in by_ref]
    _log_training_input(ordered_facts)
    messages = [
        SystemMessage(content=_REPORT_SYSTEM_PROMPT),
        HumanMessage(content=json.dumps(ordered_facts)),
    ]

    for attempt in range(2):
        response = llm.invoke(messages)
        text = response.content
        passed = False
        try:
            report = _parse_report(text)
        except ValueError:
            report = None
        if report is not None and _validate_report_text(report) and _validate_report_severities(report, table):
            passed = True
            _log_training_input(ordered_facts, raw_output=text, passed_validation=True)
            return report
        _log_training_input(ordered_facts, raw_output=text, passed_validation=passed)
        print(f"[report] attempt {attempt + 1} failed literal/schema/severity validation", file=sys.stderr)
        messages.append(HumanMessage(content=(
            "Your previous response was rejected: it either contained a raw CVE ID, "
            "CVSS number, or CPE string; was invalid JSON; or changed a finding's "
            "severity or its 'affected' text. Rewrite it: plain language only, valid "
            "JSON only, no code fences, copy each 'affected' string verbatim, and keep "
            "every 'severity' exactly as given in the input."
        )))

    print("[report] falling back to deterministic template report", file=sys.stderr)
    return _deterministic_report(table, order)


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


# ── LangGraph DAG: scope_gate → workers → enrich → triage → report → END ─────

class AgentState(TypedDict, total=False):
    target: str
    scope_token: str
    raw_results: Dict[str, Any]
    findings_table: List[Dict[str, Any]]
    priority_order: List[int]
    report: Dict[str, Any]
    error: str


def _route(state: AgentState) -> str:
    return END if state.get("error") else "continue"


def _get_llm(model: Optional[str] = None):
    provider = os.environ.get("LLM_PROVIDER", "ollama").lower()
    if provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=model or os.environ.get("OLLAMA_MODEL", "llama3.1:8b"),
            base_url=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
        )
    if provider == "claude":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=model or os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-8"))
    raise ValueError(f"Unknown LLM_PROVIDER={provider!r}. Use 'ollama' or 'claude'.")


def _get_report_llm():
    """The report node — this is the one FinetuneGuide.txt Step 15 tunes."""
    return _get_llm()


def _get_triage_llm():
    """Triage stays on the stock model unless a *_TRIAGE_MODEL override is set,
    so existing single-model deployments are unaffected by this split."""
    provider = os.environ.get("LLM_PROVIDER", "ollama").lower()
    override_env = "OLLAMA_TRIAGE_MODEL" if provider == "ollama" else "ANTHROPIC_TRIAGE_MODEL"
    return _get_llm(os.environ.get(override_env))


def _build_graph(triage_llm, report_llm):
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

    def triage_node(state: AgentState) -> AgentState:
        order = run_triage(triage_llm, state["target"], state["scope_token"], state["findings_table"])
        return {"priority_order": order}

    def report_node(state: AgentState) -> AgentState:
        report = run_report(report_llm, state["findings_table"], state["priority_order"])
        return {"report": report}

    graph = StateGraph(AgentState)
    graph.add_node("scope_gate", scope_gate_node)
    graph.add_node("scan_phase", scan_phase_node)
    graph.add_node("enrich", enrich_node)
    graph.add_node("triage", triage_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("scope_gate")
    graph.add_conditional_edges("scope_gate", _route, {"continue": "scan_phase", END: END})
    graph.add_edge("scan_phase", "enrich")
    graph.add_edge("enrich", "triage")
    graph.add_edge("triage", "report")
    graph.add_edge("report", END)

    app = graph.compile()
    display_graph(app)
    return app


def run_agent(target: str) -> dict:
    """Drive the deterministic-spine DAG and return the parsed report dict."""
    triage_llm = _get_triage_llm()
    report_llm = _get_report_llm()
    app = _build_graph(triage_llm, report_llm)

    final_state = app.invoke({"target": target})

    if final_state.get("error"):
        raise ScopeError(final_state["error"])

    return final_state["report"]


_BADGE = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def render_report(report: dict) -> str:
    overall = report.get("overall_risk", "unknown").lower()
    badge   = _BADGE.get(overall, "⚪")
    lines   = [
        "",
        "=" * 62,
        f"  SECURITY DIAGNOSTIC REPORT   {badge} {overall.upper()} RISK",
        "=" * 62,
        "",
        report.get("summary", ""),
        "",
    ]

    findings = report.get("findings", [])
    if findings:
        lines.append(f"── ISSUES FOUND ({len(findings)}) ──────────────────────────────────────")
        for i, f in enumerate(findings, 1):
            sev  = f.get("severity", "unknown").lower()
            fb   = _BADGE.get(sev, "⚪")
            lines += [
                "",
                f"  {i}. {fb} [{sev.upper()}]  {f.get('title', 'Unnamed issue')}",
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

    good = report.get("good_news") or []
    if good:
        lines += ["", "── GOOD NEWS ──────────────────────────────────────────────"]
        for item in good:
            lines.append(f"  ✅  {item}")

    lines += ["", "=" * 62, ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="mark2: AI-powered security diagnostic for everyday users.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 agent.py\n"
            "  python3 agent.py --target 192.168.1.1\n"
            "  python3 agent.py --json > report.json\n\n"
            "Env vars: TARGET, LLM_PROVIDER, OLLAMA_MODEL, OLLAMA_TRIAGE_MODEL, "
            "OLLAMA_HOST, ANTHROPIC_MODEL, ANTHROPIC_TRIAGE_MODEL, "
            "NVD_API_KEY, DB_PATH, SCOPE_SECRET"
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
    args = parser.parse_args()

    provider     = os.environ.get("LLM_PROVIDER", "ollama")
    report_model = (
        os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
        if provider == "ollama"
        else os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-8")
    )
    triage_override = os.environ.get(
        "OLLAMA_TRIAGE_MODEL" if provider == "ollama" else "ANTHROPIC_TRIAGE_MODEL"
    )
    triage_model = triage_override or report_model
    print(f"[mark2] Target  : {args.target}", file=sys.stderr)
    if triage_model == report_model:
        print(f"[mark2] Backend : {provider} / {report_model}", file=sys.stderr)
    else:
        print(f"[mark2] Backend : {provider} / triage={triage_model} report={report_model}", file=sys.stderr)

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
