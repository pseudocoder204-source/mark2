# SPDX-License-Identifier: GPL-2.0-only
"""The priority engine (DriftPlan.md Phase 5). Replaces the old severity-tier +
CVSS sort with a deterministic, explainable score.

Pure functions over the same `table` dicts `agent.build_findings_table` produces, plus
the optional `drift` (`drift.compute_drift`) and `intel` (`build_intel_map`, backed by
`exploit_intel.py`) maps keyed by `finding_key`. No LLM, no I/O beyond the read
`build_intel_map` does. Every term is attributable so `priority_explanation` can say
*why* a finding ranks where it does, not just present an ordering.

Wired into agent.py's DAG as the `triage` node (DriftPlan.md Phase 6).
"""
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .drift import (
    STATUS_IMPROVED,
    STATUS_NEW,
    STATUS_PERSISTING,
    STATUS_REAPPEARED,
    STATUS_WORSENED,
)
from .exploit_intel import get_intel_for_cves

# Tunable in one place, per DriftPlan.md Phase 5b, so weight changes are a one-line
# diff and testable against a fixed fixture (Phase 8) rather than scattered magic
# numbers.
WEIGHTS = {"S": 0.30, "E": 0.25, "X": 0.20, "D": 0.15, "A": 0.05, "F": 0.05}

_TERM_LABELS = {
    "S": "severity",
    "E": "exploitability",
    "X": "exposure",
    "D": "drift",
    "A": "age",
    "F": "fixability",
}

# X — can an attacker even reach it. Sources not listed default to 0.5 (unknown/other).
_EXPOSURE = {
    "network": 1.0,
    "iot_defaults": 1.0,
    "web": 1.0,
    "malware": 1.0,
    "host_os": 0.6,
    "host_audit": 0.5,
    "filesystem": 0.4,
}

# D — what time is telling us. A finding actually present in `table` can only ever
# carry one of these five drift statuses (drift.compute_drift only emits UNOBSERVED/
# RESOLVED for findings *absent* from the current table, so they never reach here).
# Findings scored with no drift record at all (drift=None, or a genuinely first-ever
# run) default to NEW's weight — no history means no evidence of persistence either way.
_DRIFT_WEIGHT = {
    STATUS_REAPPEARED: 1.0,
    STATUS_WORSENED: 0.85,
    STATUS_NEW: 0.6,
    STATUS_PERSISTING: 0.35,
    STATUS_IMPROVED: 0.2,
}
_DEFAULT_DRIFT_WEIGHT = _DRIFT_WEIGHT[STATUS_NEW]

_AGE_HORIZON_DAYS = 90.0

_CORRELATION_BONUS_PER_EXTRA = 5
_CORRELATION_BONUS_CAP = 15

# Rule 2 ("KEV on a network-reachable service") is scoped to sources an attacker can
# actually reach over the network — malware is already covered by rule 1, and
# host_audit/filesystem findings aren't a directly-reachable service.
_REACHABLE_SOURCES = {"network", "iot_defaults", "web"}

BAND_FIX_NOW = "FIX NOW"
BAND_SOON = "SOON"
BAND_WATCH = "WATCH"
_BAND_FIX_NOW_THRESHOLD = 70
_BAND_SOON_THRESHOLD = 40

_PORT_FINDING_KEY_RE = re.compile(r"^net:(\d+)/")


# ── Exposure/correlation asset grouping ───────────────────────────────────────

def _port_asset(finding: Dict[str, Any]) -> Optional[str]:
    match = _PORT_FINDING_KEY_RE.match(finding.get("finding_key") or "")
    return f"port:{match.group(1)}" if match else None


def _web_asset(finding: Dict[str, Any]) -> Optional[str]:
    # finding_key format: "web:{template_id}:{matched_path}" (agent.build_findings_table).
    parts = (finding.get("finding_key") or "").split(":", 2)
    if len(parts) < 3 or not parts[2]:
        return None
    target = parts[2] if "://" in parts[2] else f"http://{parts[2]}"
    try:
        parsed = urlsplit(target)
    except ValueError:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"port:{port}" if parsed.hostname else None


def _file_asset(finding: Dict[str, Any]) -> Optional[str]:
    affected = finding.get("affected") or ""
    path = affected.split("File: ", 1)[-1].strip()
    if "/" not in path:
        return None
    directory = path.rsplit("/", 1)[0]
    return f"dir:{directory}" if directory else None


def _asset_key(finding: Dict[str, Any]) -> Optional[str]:
    """The shared "thing" a finding sits on, for the correlation bonus (Phase 5b):
    same exposed port (network/iot_defaults/web) or same directory (malware). Returns
    None for sources where "same asset" isn't a meaningful grouping here (host_os,
    host_audit, filesystem are already deduped to one row per OS/test/package)."""
    source = finding.get("source")
    if source in ("network", "iot_defaults"):
        return _port_asset(finding)
    if source == "web":
        return _web_asset(finding)
    if source == "malware":
        return _file_asset(finding)
    return None


def _correlation_bonuses(table: List[Dict[str, Any]]) -> Dict[int, float]:
    groups: Dict[str, List[int]] = {}
    for finding in table:
        asset = _asset_key(finding)
        if asset is None:
            continue
        groups.setdefault(asset, []).append(finding["ref"])

    bonuses: Dict[int, float] = {}
    for refs in groups.values():
        if len(refs) < 2:
            continue
        bonus = min(_CORRELATION_BONUS_CAP, _CORRELATION_BONUS_PER_EXTRA * (len(refs) - 1))
        for ref in refs:
            bonuses[ref] = bonus
    return bonuses


# ── Score terms ────────────────────────────────────────────────────────────────

def _severity_term(finding: Dict[str, Any]) -> float:
    return max(0.0, min(1.0, (finding.get("cvss") or 0.0) / 10.0))


def _exploitability_term(finding: Dict[str, Any], intel: Optional[Dict[str, Dict[str, Any]]]) -> float:
    rec = (intel or {}).get(finding.get("finding_key"), {})
    if rec.get("kev"):
        return 1.0
    return max(0.0, min(1.0, rec.get("epss_percentile") or 0.0))


def _exposure_term(finding: Dict[str, Any]) -> float:
    return _EXPOSURE.get(finding.get("source"), 0.5)


def _drift_status(finding: Dict[str, Any], drift: Optional[Dict[str, Dict[str, Any]]]) -> str:
    rec = (drift or {}).get(finding.get("finding_key"))
    return rec["status"] if rec and rec.get("status") in _DRIFT_WEIGHT else STATUS_NEW


def _drift_term(finding: Dict[str, Any], drift: Optional[Dict[str, Dict[str, Any]]]) -> float:
    return _DRIFT_WEIGHT.get(_drift_status(finding, drift), _DEFAULT_DRIFT_WEIGHT)


def _age_term(finding: Dict[str, Any], drift: Optional[Dict[str, Dict[str, Any]]]) -> float:
    rec = (drift or {}).get(finding.get("finding_key"))
    age_days = (rec or {}).get("age_days") or 0
    return max(0.0, min(1.0, age_days / _AGE_HORIZON_DAYS))


def _fixability_term(finding: Dict[str, Any]) -> float:
    return 1.0 if finding.get("remediation_refs") else 0.3


# ── Hard escalations (Phase 5a) ────────────────────────────────────────────────

def _has_default_creds_finding(finding: Dict[str, Any]) -> bool:
    if finding.get("source") != "iot_defaults":
        return False
    for script in finding.get("script_findings") or []:
        script_id = str(script.get("id", ""))
        output = str(script.get("output", "")).strip()
        # http-default-accounts only emits script output at all when it found a match;
        # an unaffected host produces no <script> element for it in the XML.
        if "default-accounts" in script_id and output:
            return True
    return False


def _escalations(finding: Dict[str, Any], drift: Optional[Dict[str, Dict[str, Any]]], intel: Optional[Dict[str, Dict[str, Any]]]) -> List[str]:
    reasons = []

    if finding.get("source") == "malware" and finding.get("severity") in ("critical", "high"):
        reasons.append("active malware detection")

    if finding.get("source") in _REACHABLE_SOURCES:
        rec = (intel or {}).get(finding.get("finding_key"), {})
        if rec.get("kev"):
            reasons.append("CVE in CISA KEV on a reachable service")

    if _has_default_creds_finding(finding):
        reasons.append("factory-default credentials exposed")

    drift_rec = (drift or {}).get(finding.get("finding_key"))
    if drift_rec and _drift_status(finding, drift) == STATUS_REAPPEARED and (drift_rec.get("reappearance_count") or 0) >= 2:
        reasons.append("reappeared 2+ times — a fix keeps being undone")

    return reasons


# ── Public API ──────────────────────────────────────────────────────────────────

def build_intel_map(table: List[Dict[str, Any]], db_path: str = "vulnerability_cache.db") -> Dict[str, Dict[str, Any]]:
    """One `get_intel_for_cves` lookup per finding, keyed by `finding_key` — the shape
    `rank()` expects for its `intel` argument. A thin convenience so callers (the
    future Phase 6 `intel` node) don't need to know exploit_intel's per-CVE API."""
    return {
        finding["finding_key"]: get_intel_for_cves(finding.get("cve_ids"), db_path)
        for finding in table
    }


def _band(score: float, escalated: bool) -> str:
    if escalated or score >= _BAND_FIX_NOW_THRESHOLD:
        return BAND_FIX_NOW
    if score >= _BAND_SOON_THRESHOLD:
        return BAND_SOON
    return BAND_WATCH


def _explanation(band: str, score: float, top_terms: List[str], escalations: List[str]) -> str:
    factors = " and ".join(top_terms) if top_terms else "no dominant factor"
    text = f"{band} (score {score:.0f}) — top factors: {factors}."
    if escalations:
        text += " Escalated: " + "; ".join(escalations) + "."
    return text


def score_finding(
    finding: Dict[str, Any],
    drift: Optional[Dict[str, Dict[str, Any]]] = None,
    intel: Optional[Dict[str, Dict[str, Any]]] = None,
    correlation_bonus: float = 0.0,
) -> Dict[str, Any]:
    """Scores a single finding. Exposed standalone (not just via `rank`) so Phase 8's
    tests can pin term values and ordering without needing a full table/DB."""
    terms = {
        "S": _severity_term(finding),
        "E": _exploitability_term(finding, intel),
        "X": _exposure_term(finding),
        "D": _drift_term(finding, drift),
        "A": _age_term(finding, drift),
        "F": _fixability_term(finding),
    }
    weighted = {k: WEIGHTS[k] * v for k, v in terms.items()}
    raw_score = 100 * sum(weighted.values()) + correlation_bonus
    score = max(0.0, min(100.0, raw_score))

    escalations = _escalations(finding, drift, intel)
    band = _band(score, bool(escalations))
    top_terms = [
        _TERM_LABELS[k] for k, _ in sorted(weighted.items(), key=lambda kv: kv[1], reverse=True)[:2]
    ]

    return {
        "ref": finding["ref"],
        "finding_key": finding.get("finding_key"),
        "score": score,
        "band": band,
        "terms": terms,
        "escalations": escalations,
        "correlation_bonus": correlation_bonus,
        "priority_explanation": _explanation(band, score, top_terms, escalations),
    }


def rank(
    table: List[Dict[str, Any]],
    drift: Optional[Dict[str, Dict[str, Any]]] = None,
    intel: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Scores every finding and returns them best-first: escalated (FIX NOW) findings
    first — ordered among themselves by score, per Phase 5a — then the rest by score
    descending. Ties broken by `ref` for a fully deterministic order."""
    bonuses = _correlation_bonuses(table)
    scored = [
        score_finding(finding, drift, intel, correlation_bonus=bonuses.get(finding["ref"], 0.0))
        for finding in table
    ]
    scored.sort(key=lambda s: (0 if s["escalations"] else 1, -s["score"], s["ref"]))
    return scored


def ordered_refs(ranked: List[Dict[str, Any]]) -> List[int]:
    """Extracts just the ref order from `rank(...)`'s output as a plain `List[int]`."""
    return [r["ref"] for r in ranked]


def run_triage(
    table: List[Dict[str, Any]],
    drift: Optional[Dict[str, Dict[str, Any]]] = None,
    intel: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[int]:
    """Convenience wrapper matching DriftPlan.md's `run_triage(table, drift, intel)` signature."""
    return ordered_refs(rank(table, drift, intel))
