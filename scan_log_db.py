# SPDX-License-Identifier: GPL-2.0-only
"""Scan-log store (schema v2) — the durable memory that turns a one-shot scanner
into a stateful monitor.

Three tables, one file:

  scans          one row per run: which scanners actually ran, and how they ended.
                 Without this a finding that is absent because its scanner never
                 ran is indistinguishable from one that is absent because the user
                 fixed it — the drift engine's UNOBSERVED-vs-RESOLVED call depends
                 entirely on scanner_status_json.

  finding_state  the current belief about each distinct problem, keyed by the
                 cross-run identity (target, finding_key). Holds first/last seen,
                 occurrence and reappearance counts, the user's manual `solved`
                 flag, and snapshot_json — the last full findings-table row, kept
                 so a finding that has *disappeared* can still be described in the
                 report without re-deriving it from a scan that no longer sees it.

  observations   append-only history: one row per known finding per scan, carrying
                 the mutable attributes (cvss, severity, version, cve_ids) and a
                 `seen` flag that is 0 for keys that were expected this run but
                 absent. Nothing reads it yet; it is what makes sparklines,
                 "unfixed for 47 days" and flap detection possible later without
                 another schema change.

Identity is `finding_key` (agent.build_findings_table), never the `affected`
string and never the per-run `ref`.

Separate from vulnerability_cache.db (NVD CVE cache) and clamav_manifest.db
(incremental-scan state) — this one is a log of scan results, not scanner
inputs/cache.

No migration from v1, and no code to detect it: scan_log_db.py was never
committed or released, so the only v1 database that ever existed was one dev
file, which was deleted. Once this ships, that reasoning expires — the next
schema bump has real user history behind it and needs a real migration.
"""
import json
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional

_DEFAULT_DB_PATH = "scan_log.db"

SCHEMA_VERSION = 2

# finding_state.status — the drift engine (Phase 3) owns the transitions; this
# module only stores what it is told, and defaults a present finding to OPEN.
STATUS_OPEN = "open"
STATUS_RESOLVED = "resolved"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    # The version stamp is written but not enforced: there is no v1 database
    # anywhere to reject, since this module was never released. It exists so the
    # *next* bump — which will land after a release, with real user history —
    # has something to branch a real migration on.
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )

    conn.execute(
        """CREATE TABLE IF NOT EXISTS scans (
            scan_id             TEXT PRIMARY KEY,
            target              TEXT NOT NULL,
            started_at          TEXT NOT NULL,
            completed_at        TEXT,
            platform            TEXT,
            scanner_status_json TEXT NOT NULL DEFAULT '{}'
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS finding_state (
            target             TEXT NOT NULL,
            finding_key        TEXT NOT NULL,
            first_seen         TEXT NOT NULL,
            last_seen          TEXT NOT NULL,
            last_scan_id       TEXT NOT NULL,
            status             TEXT NOT NULL DEFAULT 'open',
            occurrences        INTEGER NOT NULL DEFAULT 1,
            resolved_at        TEXT,
            reappearance_count INTEGER NOT NULL DEFAULT 0,
            solved             INTEGER NOT NULL DEFAULT 0,
            solved_at          TEXT,
            snapshot_json      TEXT NOT NULL,
            PRIMARY KEY (target, finding_key)
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS observations (
            scan_id      TEXT NOT NULL,
            target       TEXT NOT NULL,
            finding_key  TEXT NOT NULL,
            seen         INTEGER NOT NULL,
            cvss         REAL,
            severity     TEXT,
            version      TEXT,
            cve_ids_json TEXT NOT NULL DEFAULT '[]',
            PRIMARY KEY (scan_id, finding_key)
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans (target, started_at)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_obs_key ON observations (target, finding_key, scan_id)"
    )
    conn.commit()
    return conn


def init_scan_log_db(db_path: str = _DEFAULT_DB_PATH) -> None:
    _connect(db_path).close()


# ── Reads (the drift engine's input) ─────────────────────────────────────────


def get_finding_state(db_path: str, target: str) -> Dict[str, Dict[str, Any]]:
    """Current belief about every finding ever seen on this target, keyed by
    finding_key. This is what Phase 3's drift engine reads *before* the current
    run's results are persisted."""
    conn = _connect(db_path)
    rows = conn.execute("SELECT * FROM finding_state WHERE target = ?", (target,)).fetchall()
    conn.close()
    state = {}
    for row in rows:
        rec = dict(row)
        rec["snapshot"] = json.loads(rec.pop("snapshot_json") or "{}")
        rec["solved"] = bool(rec["solved"])
        state[rec["finding_key"]] = rec
    return state


def get_last_scan(db_path: str, target: str) -> Optional[Dict[str, Any]]:
    """The most recently *started* scan of this target, with its scanner statuses
    decoded. Returns None if the target has never been scanned."""
    conn = _connect(db_path)
    row = conn.execute(
        "SELECT * FROM scans WHERE target = ? ORDER BY started_at DESC, rowid DESC LIMIT 1",
        (target,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    rec = dict(row)
    rec["scanner_status"] = json.loads(rec.pop("scanner_status_json") or "{}")
    return rec


def list_scans(db_path: str, target: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Every logged scan of `target`, oldest first, with scanner statuses decoded.
    `get_last_scan` is the single-row special case of this; `--history` (sparkline)
    and `--diff` (last-two comparison) both need the fuller series."""
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT * FROM scans WHERE target = ? ORDER BY started_at, rowid", (target,)
    ).fetchall()
    conn.close()
    out = []
    for row in rows:
        rec = dict(row)
        rec["scanner_status"] = json.loads(rec.pop("scanner_status_json") or "{}")
        out.append(rec)
    return out[-limit:] if limit else out


def get_observations(
    db_path: str, target: str, finding_key: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Append-only history, oldest first — the series behind `--history` and any
    future sparkline / flap detection."""
    conn = _connect(db_path)
    query = (
        "SELECT o.*, s.started_at FROM observations o JOIN scans s ON s.scan_id = o.scan_id "
        "WHERE o.target = ?"
    )
    params: List[Any] = [target]
    if finding_key:
        query += " AND o.finding_key = ?"
        params.append(finding_key)
    query += " ORDER BY s.started_at, o.rowid"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    out = []
    for row in rows:
        rec = dict(row)
        rec["seen"] = bool(rec["seen"])
        rec["cve_ids"] = json.loads(rec.pop("cve_ids_json") or "[]")
        out.append(rec)
    return out


# ── Writes ───────────────────────────────────────────────────────────────────


def save_scan_log(
    db_path: str,
    target: str,
    findings_table: List[Dict[str, Any]],
    scanner_status: Optional[Dict[str, str]] = None,
    platform_name: Optional[str] = None,
    drift: Optional[Dict[str, str]] = None,
) -> str:
    """Persist one run: a `scans` row, one `observations` row per known finding
    (seen=0 for keys that were expected but absent this run), and an upsert of
    every present finding's `finding_state`. Returns the scan_id.

    `drift` is an optional {finding_key: status} override from the drift engine.
    Without it — the Phase-2 baseline — present findings are simply OPEN and
    absent ones keep whatever status they already had, because deciding whether
    an absent finding is RESOLVED or merely UNOBSERVED requires reading
    scanner_status, which is Phase 3's job, not this module's.
    """
    scan_id = uuid.uuid4().hex
    now = _now()

    if platform_name is None:
        import platform as _platform

        platform_name = _platform.system().lower()

    conn = _connect(db_path)
    conn.execute(
        """INSERT INTO scans (scan_id, target, started_at, completed_at, platform, scanner_status_json)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scan_id, target, now, now, platform_name, json.dumps(scanner_status or {})),
    )

    prior = {
        row["finding_key"]: row
        for row in conn.execute(
            "SELECT finding_key, first_seen, occurrences, status, reappearance_count "
            "FROM finding_state WHERE target = ?",
            (target,),
        ).fetchall()
    }

    present: set = set()
    for f in findings_table:
        key = f["finding_key"]
        present.add(key)
        was = prior.get(key)
        status = (drift or {}).get(key, STATUS_OPEN)

        conn.execute(
            """INSERT INTO observations
                   (scan_id, target, finding_key, seen, cvss, severity, version, cve_ids_json)
               VALUES (?, ?, ?, 1, ?, ?, ?, ?)""",
            (
                scan_id,
                target,
                key,
                f.get("cvss"),
                f.get("severity"),
                f.get("version"),
                json.dumps(sorted(f.get("cve_ids") or [])),
            ),
        )

        if was is None:
            conn.execute(
                """INSERT INTO finding_state
                       (target, finding_key, first_seen, last_seen, last_scan_id, status,
                        occurrences, reappearance_count, snapshot_json)
                   VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?)""",
                (target, key, now, now, scan_id, status, json.dumps(f)),
            )
        else:
            # A finding that was RESOLVED and is present again has come back — that
            # is the reappearance the drift engine ranks above a same-CVSS NEW, so
            # count it here where we can still see the prior status.
            reappeared = was["status"] == STATUS_RESOLVED
            conn.execute(
                """UPDATE finding_state
                      SET last_seen = ?, last_scan_id = ?, status = ?,
                          occurrences = occurrences + 1,
                          reappearance_count = reappearance_count + ?,
                          resolved_at = NULL,
                          snapshot_json = ?
                    WHERE target = ? AND finding_key = ?""",
                (now, scan_id, status, 1 if reappeared else 0, json.dumps(f), target, key),
            )

    # Keys we knew about but did not see this run. They get a seen=0 observation
    # so the history has no holes; their state is left alone unless the drift
    # engine told us what it decided.
    for key, was in prior.items():
        if key in present:
            continue
        conn.execute(
            """INSERT INTO observations (scan_id, target, finding_key, seen) VALUES (?, ?, ?, 0)""",
            (scan_id, target, key),
        )
        status = (drift or {}).get(key)
        if status and status != was["status"]:
            conn.execute(
                """UPDATE finding_state
                      SET status = ?, last_scan_id = ?, resolved_at = ?
                    WHERE target = ? AND finding_key = ?""",
                (
                    status,
                    scan_id,
                    now if status == STATUS_RESOLVED else None,
                    target,
                    key,
                ),
            )

    conn.commit()
    conn.close()
    return scan_id


def mark_solved(
    db_path: str, target: str, finding_key: str, solved: bool = True
) -> None:
    """Flip the user's manual "I fixed this" flag. Deliberately does *not* change
    `status`: if the finding shows up in the next scan anyway, the fix did not
    take, and the gap between solved=1 and status=open is exactly the signal that
    says so."""
    conn = _connect(db_path)
    conn.execute(
        "UPDATE finding_state SET solved = ?, solved_at = ? WHERE target = ? AND finding_key = ?",
        (1 if solved else 0, _now() if solved else None, target, finding_key),
    )
    conn.commit()
    conn.close()


def forget_target(db_path: str, target: str) -> None:
    """Drop all history for a target. The scan log is a map of a user's
    weaknesses; being able to erase it is table stakes."""
    conn = _connect(db_path)
    for table in ("observations", "finding_state", "scans"):
        conn.execute(f"DELETE FROM {table} WHERE target = ?", (target,))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    import sys

    init_scan_log_db()
    conn = _connect(_DEFAULT_DB_PATH)
    targets = [row["target"] for row in conn.execute("SELECT DISTINCT target FROM scans")]
    conn.close()

    dump = {t: get_finding_state(_DEFAULT_DB_PATH, t) for t in targets}
    print(json.dumps(dump, indent=2))
    total = sum(len(v) for v in dump.values())
    print(f"[+] {total} finding(s) tracked across {len(targets)} target(s)", file=sys.stderr)
