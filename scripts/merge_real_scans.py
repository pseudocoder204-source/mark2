#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
merge_real_scans.py — maintainer-side ingestion of contributor files produced by
contribute_real_scan.py into the central trainset.db (FinetuneGuide.txt Step 3a).

Each contributor runs contribute_real_scan.py on their own machine and sends back
one `contrib_<label>_<timestamp>_<hash>.json` file. Run this here to fold those
files into trainset.db as unlabeled 'real' rows (source='real', status='pending'),
skipping anything already present by content hash.

Usage:
    python3 -m scripts.merge_real_scans contrib_*.json
    python3 -m scripts.merge_real_scans --db trainset.db contrib_alice_*.json contrib_bob_*.json
"""
import argparse
import json
import sqlite3
import sys

from scripts import collect_inputs

_TRAINSET_SCHEMA = """
CREATE TABLE IF NOT EXISTS examples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT,
    profile       TEXT,
    ordered_facts TEXT NOT NULL,
    label         TEXT,
    status        TEXT DEFAULT 'pending',
    platform      TEXT
)
"""


def _ensure_platform_column(conn: sqlite3.Connection) -> None:
    """Add the `platform` column to a pre-existing trainset.db and backfill old rows to
    'linux' (they predate Windows support). Mirrors contribute_real_scan._ensure_platform_column."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(examples)")}
    if "platform" not in cols:
        conn.execute("ALTER TABLE examples ADD COLUMN platform TEXT")
        conn.execute("UPDATE examples SET platform = 'linux' WHERE platform IS NULL")


def _platform_from_meta(meta: dict) -> str:
    """Derive the normalized OS family for the platform column from a contributor's _meta.
    Runs on the maintainer's box, so it must read the record, never the local OS.
    Prefers the normalized platform_system field; falls back to parsing the verbose
    platform string; else 'unknown'."""
    ps = meta.get("platform_system")
    if isinstance(ps, str) and ps:
        return ps.lower()
    verbose = str(meta.get("platform", "")).lower()
    for family in ("windows", "linux", "darwin"):
        if verbose.startswith(family):
            return family
    return "unknown"


def _existing_hashes(conn: sqlite3.Connection) -> set:
    hashes = set()
    for (facts_json,) in conn.execute("SELECT ordered_facts FROM examples"):
        try:
            hashes.add(collect_inputs._facts_hash(json.loads(facts_json)))
        except (json.JSONDecodeError, TypeError):
            continue
    return hashes


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="contrib_*.json files from contribute_real_scan.py")
    ap.add_argument("--db", default="trainset.db")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.execute(_TRAINSET_SCHEMA)
    _ensure_platform_column(conn)
    conn.commit()
    seen_hashes = _existing_hashes(conn)

    inserted = skipped = failed = 0
    for path in args.files:
        try:
            with open(path) as f:
                record = json.load(f)
            ordered_facts = record["ordered_facts"]
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            print(f"[merge] SKIP {path}: unreadable ({exc})", file=sys.stderr)
            failed += 1
            continue

        fhash = collect_inputs._facts_hash(ordered_facts)
        if fhash in seen_hashes:
            print(f"[merge] skip  {path}: duplicate (hash {fhash[:12]}) already in {args.db}")
            skipped += 1
            continue

        meta = record.get("_meta", {})
        plat = _platform_from_meta(meta)
        cur = conn.execute(
            "INSERT INTO examples (source, profile, ordered_facts, status, platform) "
            "VALUES ('real', NULL, ?, 'pending', ?)",
            (json.dumps(ordered_facts), plat),
        )
        conn.commit()
        seen_hashes.add(fhash)
        print(f"[merge] added id={cur.lastrowid} from {path} (label={meta.get('label', '?')}, "
              f"shape={meta.get('shape', '?')}, platform={plat})")
        inserted += 1

    conn.close()
    print(f"\n[merge] inserted={inserted} skipped_dupes={skipped} failed={failed} -> {args.db}")


if __name__ == "__main__":
    main()
