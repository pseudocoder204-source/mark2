# SPDX-License-Identifier: GPL-2.0-only
"""The drift engine (DriftPlan.md Phase 3) — a pure function, no LLM, no I/O beyond
`scan_log_db.py` reads, that turns "what does this scan see" plus "what did the last
scan see" into a per-finding state:

    NEW · PERSISTING · WORSENED · IMPROVED · RESOLVED · REAPPEARED · UNOBSERVED

`UNOBSERVED` is the correctness backbone of the whole feature: a finding whose scanner
did not run this pass (not installed, errored, timed out, or — for malware — just
hasn't produced a fresh background result yet) must never be read as fixed. Every
`RESOLVED` verdict this module hands out is provable: the finding was previously open,
its scanner's `scanner_status` for this run is "ok", and the finding is absent from the
current findings table.

Not wired into `agent.py`'s DAG yet — that's DriftPlan.md Phase 6.
"""
import calendar
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, TypedDict

from scan_log_db import STATUS_RESOLVED, get_finding_state, get_observations, list_scans

# Mirrors agent._TIER_RANK. Duplicated rather than imported: agent.py will import this
# module in Phase 6, so the reverse import would be circular.
_TIER_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

STATUS_NEW = "NEW"
STATUS_PERSISTING = "PERSISTING"
STATUS_WORSENED = "WORSENED"
STATUS_IMPROVED = "IMPROVED"
STATUS_RESOLVED_ = "RESOLVED"
STATUS_REAPPEARED = "REAPPEARED"
STATUS_UNOBSERVED = "UNOBSERVED"

# Which worker(s) (agent._WORKERS names) own each findings-table `source`. `host_os` is
# produced by OS detection inside either the network or the iot_defaults nmap scan
# (nmap_parser.build_host_os_findings), so either succeeding counts as "observed" for it.
_SOURCE_TO_WORKERS = {
    "host_os": ("network", "iot_defaults"),
    "network": ("network",),
    "iot_defaults": ("iot_defaults",),
    "filesystem": ("filesystem",),
    "host_audit": ("host_audit",),
    "malware": ("malware",),
    "web": ("web",),
}

_ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


class DriftRecord(TypedDict, total=False):
    finding_key: str
    status: str
    cvss: Optional[float]
    severity: Optional[str]
    new_cve_ids: List[str]
    first_seen: str
    last_seen: str
    age_days: int
    days_since_change: int
    occurrences: int
    reappearance_count: int
    fix_attempted: bool
    snapshot: Dict[str, Any]


def _now_ts() -> float:
    return time.time()


def _parse_ts(ts: str) -> float:
    return calendar.timegm(time.strptime(ts, _ISO_FMT))


def _age_days(ts: str, now: float) -> int:
    return max(0, int((now - _parse_ts(ts)) // 86400))


def _scanner_ran_ok(source: str, scanner_status: Dict[str, str]) -> bool:
    workers = _SOURCE_TO_WORKERS.get(source, ())
    return any(scanner_status.get(w) == "ok" for w in workers)


def _cve_set(cve_ids: Optional[List[str]]) -> set:
    return set(cve_ids or [])


def _attrs_equal(observation: Dict[str, Any], current: Dict[str, Any]) -> bool:
    return (
        observation.get("cvss") == current.get("cvss")
        and observation.get("severity") == current.get("severity")
        and _cve_set(observation.get("cve_ids")) == _cve_set(current.get("cve_ids"))
    )


def _classify_delta(prior_snapshot: Dict[str, Any], current: Dict[str, Any]) -> tuple:
    """Returns (status, new_cve_ids) for a finding present both before and now."""
    prior_cves = _cve_set(prior_snapshot.get("cve_ids"))
    current_cves = _cve_set(current.get("cve_ids"))
    new_cves = sorted(current_cves - prior_cves)

    prior_cvss = prior_snapshot.get("cvss") or 0.0
    current_cvss = current.get("cvss") or 0.0
    prior_tier = _TIER_RANK.get(prior_snapshot.get("severity"), 0)
    current_tier = _TIER_RANK.get(current.get("severity"), 0)

    if current_cvss > prior_cvss or new_cves or current_tier > prior_tier:
        return STATUS_WORSENED, new_cves
    if current_cvss < prior_cvss or current_tier < prior_tier:
        return STATUS_IMPROVED, new_cves
    return STATUS_PERSISTING, new_cves


def _last_change_ts(history: List[Dict[str, Any]], current: Dict[str, Any], fallback_ts: str) -> str:
    """Walks a finding_key's observation history (oldest-first, as returned by
    `get_observations`) backward from the most recent entry, and returns the
    timestamp of the oldest observation in the unbroken run of entries that already
    matched `current`'s attributes — i.e. "since when has this looked like it does
    right now." Falls back to `fallback_ts` (first_seen) if there's no usable history,
    e.g. this is the finding's first appearance.
    """
    seen = [o for o in history if o.get("seen")]
    if not seen:
        return fallback_ts
    change_ts = fallback_ts
    for obs in reversed(seen):
        if _attrs_equal(obs, current):
            change_ts = obs["started_at"]
        else:
            break
    return change_ts


def age_days_since(iso_ts: str) -> int:
    """Public wrapper around the age math `compute_drift` uses internally, for
    callers that need "how many days old" without re-running the full state
    machine -- e.g. `agent.py --resolve-ref` reconstructing a DriftRecord-shaped
    map for `priority.rank` from stored history rather than a live scan."""
    return _age_days(iso_ts, _now_ts())


def compute_drift(
    target: str,
    table: List[Dict[str, Any]],
    scanner_status: Dict[str, str],
    db_path: str,
) -> Dict[str, DriftRecord]:
    """Classifies every finding this target has ever produced — present in `table`
    this run, or only known from prior scans — into a `DriftRecord`. Must be called
    with `db_path` state as of *before* this run is persisted (`scan_log_db.save_scan_log`),
    otherwise every finding would be diffed against itself.
    """
    now = _now_ts()
    prior = get_finding_state(db_path, target)
    obs_by_key: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in get_observations(db_path, target):
        obs_by_key[row["finding_key"]].append(row)

    current_by_key = {f["finding_key"]: f for f in table}
    all_keys = set(current_by_key) | set(prior)

    records: Dict[str, DriftRecord] = {}
    for key in all_keys:
        current = current_by_key.get(key)
        was = prior.get(key)

        if was is None:
            # Never seen before — must be present, since it can't be "absent" from a
            # history that doesn't exist yet.
            records[key] = DriftRecord(
                finding_key=key,
                status=STATUS_NEW,
                cvss=current.get("cvss"),
                severity=current.get("severity"),
                new_cve_ids=sorted(_cve_set(current.get("cve_ids"))),
                first_seen=None,
                last_seen=None,
                age_days=0,
                days_since_change=0,
                occurrences=1,
                reappearance_count=0,
                fix_attempted=False,
                snapshot=current,
            )
            continue

        if current is None:
            # Known before, absent now. Whether that means "fixed" depends entirely on
            # whether its scanner actually ran — see module docstring.
            source = (was.get("snapshot") or {}).get("source", "")
            if _scanner_ran_ok(source, scanner_status):
                status = STATUS_RESOLVED_
                age_days = _age_days(was["first_seen"], now)
                days_since_change = 0
            else:
                status = STATUS_UNOBSERVED
                # Frozen: age/last-change are computed as of the last time we actually
                # observed this finding, not advanced to "now" — we have no evidence
                # about what happened today.
                as_of = _parse_ts(was["last_seen"])
                age_days = _age_days(was["first_seen"], as_of)
                history = obs_by_key.get(key, [])
                change_ts = _last_change_ts(history, was.get("snapshot") or {}, was["first_seen"])
                days_since_change = _age_days(change_ts, as_of)
            records[key] = DriftRecord(
                finding_key=key,
                status=status,
                cvss=(was.get("snapshot") or {}).get("cvss"),
                severity=(was.get("snapshot") or {}).get("severity"),
                new_cve_ids=[],
                first_seen=was["first_seen"],
                last_seen=was["last_seen"],
                age_days=age_days,
                days_since_change=days_since_change,
                occurrences=was["occurrences"],
                reappearance_count=was["reappearance_count"],
                fix_attempted=False,
                snapshot=was.get("snapshot") or {},
            )
            continue

        # Present both before and now. A genuine comeback (prior status was DB-confirmed
        # RESOLVED) outranks the attribute delta. A `solved` flag alone does *not* mean
        # REAPPEARED — if the finding's DB status was never actually `resolved`, the user's
        # manual claim just didn't hold, which is `fix_attempted`, not a reappearance.
        was_resolved = was["status"] == STATUS_RESOLVED
        if was_resolved:
            status = STATUS_REAPPEARED
            new_cves = sorted(_cve_set(current.get("cve_ids")) - _cve_set((was.get("snapshot") or {}).get("cve_ids")))
        else:
            status, new_cves = _classify_delta(was.get("snapshot") or {}, current)

        history = obs_by_key.get(key, [])
        if status in (STATUS_WORSENED, STATUS_IMPROVED, STATUS_REAPPEARED):
            days_since_change = 0
        else:
            change_ts = _last_change_ts(history, current, was["first_seen"])
            days_since_change = _age_days(change_ts, now)

        records[key] = DriftRecord(
            finding_key=key,
            status=status,
            cvss=current.get("cvss"),
            severity=current.get("severity"),
            new_cve_ids=new_cves,
            first_seen=was["first_seen"],
            last_seen=was["last_seen"],
            age_days=_age_days(was["first_seen"], now),
            days_since_change=days_since_change,
            occurrences=was["occurrences"] + 1,
            reappearance_count=was["reappearance_count"] + (1 if status == STATUS_REAPPEARED else 0),
            # Present again despite the user's manual "I fixed this" claim: the fix
            # didn't take. True for the ordinary still-open case and for REAPPEARED
            # alike — either way, `solved` no longer reflects reality.
            fix_attempted=bool(was.get("solved")),
            snapshot=current,
        )

    return records


# ── Read-only historical diff (DriftPlan.md Phase 8 `--diff`) ────────────────
#
# `compute_drift` above always compares a *live* scan's table against the DB. This
# is the no-scan counterpart: it diffs the two most recently *logged* scans purely
# from `scan_log.db`'s own history (`observations` + `finding_state`), so `agent.py
# --diff` can answer "what changed" instantly, without re-running any scanner.
# Reuses `_classify_delta`/`_scanner_ran_ok` rather than re-deriving the rules, so
# the two code paths can't quietly drift apart from each other.

def diff_last_two_scans(db_path: str, target: str) -> Optional[Dict[str, Any]]:
    """Returns {"older_scan_at", "latest_scan_at", "changes": {finding_key: {...}}}
    or None if fewer than two scans have ever been logged for `target`. `changes`
    omits PERSISTING findings (nothing to report) and any finding_key observed in
    neither of the two scans."""
    scans = list_scans(db_path, target, limit=2)
    if len(scans) < 2:
        return None
    older_scan, latest_scan = scans[0], scans[1]

    finding_state = get_finding_state(db_path, target)
    obs_by_key: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for row in get_observations(db_path, target):
        if row["scan_id"] in (older_scan["scan_id"], latest_scan["scan_id"]):
            obs_by_key[row["finding_key"]][row["scan_id"]] = row

    changes: Dict[str, Dict[str, Any]] = {}
    for key, by_scan in obs_by_key.items():
        older = by_scan.get(older_scan["scan_id"])
        latest = by_scan.get(latest_scan["scan_id"])
        older_present = bool(older and older["seen"])
        latest_present = bool(latest and latest["seen"])
        if not older_present and not latest_present:
            continue

        snapshot = (finding_state.get(key) or {}).get("snapshot") or {}
        source = snapshot.get("source", "")

        if not older_present and latest_present:
            status = STATUS_NEW
        elif older_present and not latest_present:
            status = (
                STATUS_RESOLVED_
                if _scanner_ran_ok(source, latest_scan["scanner_status"])
                else STATUS_UNOBSERVED
            )
        else:
            status, _new_cves = _classify_delta(older, latest)
            if status == STATUS_PERSISTING:
                continue

        current_or_prior = latest or older
        changes[key] = {
            "finding_key": key,
            "status": status,
            "affected": snapshot.get("affected", key),
            "severity": current_or_prior.get("severity"),
            "cvss": current_or_prior.get("cvss"),
        }

    return {
        "target": target,
        "older_scan_at": older_scan["started_at"],
        "latest_scan_at": latest_scan["started_at"],
        "changes": changes,
    }
