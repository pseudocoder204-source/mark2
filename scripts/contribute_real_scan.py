#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
contribute_real_scan.py — plug-n-play real-scan contributor for the report LoRA
training set (FinetuneGuide.txt Step 3a: ~30 real anchor rows).

Run this on a machine you own (or have explicit permission to scan). It:

  1. Shows you exactly what it's about to do and what data leaves your machine,
     and requires you to type an explicit confirmation before doing anything.
  2. Runs the same deterministic scan phase collect_inputs.py uses (nmap,
     Trivy, Lynis, Nuclei, and optionally ClamAV) against your own machine.
  3. Reduces the raw scan output to `ordered_facts` — the same derived findings
     table the live product feeds its report model. No raw file contents, no
     credentials, no full nmap/lynis logs ever leave this stage.
  4. Inserts the row into your local trainset.db (source='real', unlabeled,
     status='pending') if one exists next to this script, creating it if not.
  5. Writes a small standalone JSON file you can send back to whoever asked
     you to run this, so they can merge it into the shared trainset.db with
     merge_real_scans.py.

What actually gets scanned (all against --target, default 127.0.0.1 = this
machine): open ports/service versions (nmap), known-default-credential/open
UPnP/SNMP checks (nmap NSE scripts), outdated OS packages (Trivy), host
hardening settings (Lynis), and — only if you pass --malware live — a
malware signature scan of a fixed list of high-risk directories (ClamAV).

What gets recorded: port numbers, service/product/version strings, matched
CVE IDs/CVSS scores/severities, Lynis test IDs, package names and installed/
fixed versions, and (if --malware live) malware signature names and file
paths under the scanned directories. Nothing else leaves your machine.

Usage:
    python3 -m scripts.contribute_real_scan
    python3 -m scripts.contribute_real_scan --malware live --label my-laptop
    python3 -m scripts.contribute_real_scan --yes   # skip the interactive prompt (CI/scripted use)

Scanning anything other than your own machine requires the owner's explicit
permission and the --i-have-permission flag.
"""
import argparse
import json
import os
import platform
import shutil
import socket
import sqlite3
import sys
import time

from scripts import collect_inputs
from scanners.bin_resolver import resolve as _resolve_bin

_TRAINSET_SCHEMA = """
CREATE TABLE IF NOT EXISTS examples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT,                   -- 'synth' | 'real'
    profile       TEXT,                   -- profile name, or NULL for real anchors
    ordered_facts TEXT NOT NULL,           -- json.dumps(ordered_facts) — the model input
    label         TEXT,                   -- json.dumps(report) — NULL until labeled
    status        TEXT DEFAULT 'pending',  -- pending -> labeled -> validated | rejected
    platform      TEXT                     -- 'windows' | 'linux' | 'darwin' — OS the scan ran on
)
"""


def _ensure_platform_column(conn: sqlite3.Connection) -> None:
    """Add the `platform` column to a pre-existing trainset.db that lacks it, and backfill
    old rows to 'linux'. Those rows predate Windows support, so they were all Linux scans.
    Kept out of ordered_facts on purpose: _facts_hash() dedups on ordered_facts, so a
    sidecar column keeps every existing hash byte-identical while making the set
    OS-filterable."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(examples)")}
    if "platform" not in cols:
        conn.execute("ALTER TABLE examples ADD COLUMN platform TEXT")
        conn.execute("UPDATE examples SET platform = 'linux' WHERE platform IS NULL")

_LOOPBACK_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


def _tool_available(tool: str) -> "str | None":
    """Return the resolved path if `tool` is runnable, else None. Uses bin_resolver so an
    env override / bundled binary counts, not just PATH."""
    resolved = _resolve_bin(tool)
    if os.path.isabs(resolved) or os.sep in resolved or (os.altsep and os.altsep in resolved):
        return resolved if os.path.isfile(resolved) else None
    return shutil.which(resolved)


def _expected_tools(malware_mode: str) -> dict:
    """Scanners this run depends on, per OS. Missing ones are skipped, thinning the row."""
    if platform.system() == "Windows":
        # Trivy is skipped on Windows; host audit + Defender malware both go through PowerShell.
        tools = {
            "nmap":       "network / IoT / host port+CVE scan (needs Npcap for LAN scans)",
            "nuclei":     "web vulnerability scan",
            "powershell": "host hardening audit + malware (Windows Defender history)",
        }
    else:
        tools = {
            "nmap":   "network / IoT / host port+CVE scan",
            "trivy":  "filesystem package vulnerability scan",
            "nuclei": "web vulnerability scan",
            "lynis":  "host hardening audit",
        }
        if malware_mode == "live":
            tools["clamscan"] = "malware scan (ClamAV)"
    return tools


def _preflight(malware_mode: str, auto_yes: bool) -> None:
    """Report which scanners are present before scanning. A missing scanner is silently
    downgraded to 'unavailable' at scan time and its data is simply absent from the row —
    so warn (and, interactively, require confirmation) rather than let a volunteer
    contribute a half-empty scan without realizing it."""
    expected = _expected_tools(malware_mode)
    print("Scanner availability check:")
    missing = []
    for tool, purpose in expected.items():
        path = _tool_available(tool)
        if path:
            print(f"  [ok]      {tool:<11} -> {path}")
        else:
            print(f"  [MISSING] {tool:<11} ({purpose})")
            missing.append(tool)

    if not missing:
        print("All expected scanners found.\n")
        return

    print(f"\n{len(missing)} scanner(s) missing: {', '.join(missing)}.")
    print("Missing scanners are skipped — the contributed row will omit their findings,")
    print("which makes it less useful as training data. Install them and re-run for a full scan.")
    if auto_yes:
        print("(--yes given: continuing anyway.)\n")
        return
    try:
        answer = input("Continue with these tools missing? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer not in ("y", "yes"):
        print("Aborted — install the missing scanners and re-run.")
        sys.exit(1)
    print()


def _is_local_target(target: str) -> bool:
    if target in _LOOPBACK_HOSTNAMES:
        return True
    if target.startswith("127."):
        return True
    if target.startswith("192.168.") or target.startswith("10."):
        return True
    if target.startswith("172."):
        try:
            second = int(target.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


def _print_banner(target: str, malware_mode: str) -> None:
    print("=" * 78)
    print("mark2 — real-scan contribution for the report model's training set")
    print("=" * 78)
    print(f"""
This will scan:  {target}
Malware scan:     {"ENABLED (can take 1-4+ hours on first run)" if malware_mode == "live" else "disabled/cached (pass --malware live to include it)"}

What runs:
  - nmap version-detection + default-credential/UPnP/SNMP checks
  - Trivy filesystem package scan
  - Lynis host-hardening audit
  - Nuclei web-template scan against {target}
  {"- ClamAV malware scan of high-risk directories (home, tmp, opt, srv, root, var/www)" if malware_mode == "live" else "- (ClamAV skipped/cached — no live malware scan)"}

What gets recorded and may be sent to the project maintainer:
  - port numbers, service/product/version strings
  - matched CVE IDs, CVSS scores, severities
  - Lynis test IDs
  - package names + installed/fixed versions
  {"- malware signature names and the paths of any matched files" if malware_mode == "live" else ""}

What is NEVER recorded: file contents, credentials, full scan logs/XML, or
anything not already listed above.

This row is added to trainset.db as UNLABELED training input (source='real',
status='pending') — no report text is generated or sent anywhere.

DATA LICENSE. By submitting this scan summary you grant the mark2 project and
its maintainers a perpetual, irrevocable, worldwide, royalty-free,
non-exclusive license to use, reproduce, modify, publish, and distribute the
submitted data for any purpose, including training machine-learning models and
incorporating those models into commercial products. You confirm that you own
or control the systems scanned and have the right to grant this license. The
data is used as described above; no additional personal information is
collected.

Passing --yes constitutes acceptance of the data license above.
""".strip())
    print("=" * 78)


def _confirm(auto_yes: bool) -> None:
    if auto_yes:
        return
    print("\nBy typing 'I consent' you accept the DATA LICENSE shown above.")
    print("Type exactly:  I consent   (anything else cancels)")
    try:
        answer = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer != "I consent":
        print("Not confirmed — nothing was scanned or recorded. Exiting.")
        sys.exit(1)


def _init_trainset_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(_TRAINSET_SCHEMA)
    _ensure_platform_column(conn)
    conn.commit()
    return conn


def _existing_db_hashes(conn: sqlite3.Connection) -> set:
    hashes = set()
    for (facts_json,) in conn.execute("SELECT ordered_facts FROM examples"):
        try:
            hashes.add(collect_inputs._facts_hash(json.loads(facts_json)))
        except (json.JSONDecodeError, TypeError):
            continue
    return hashes


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--target", default=os.environ.get("TARGET", "127.0.0.1"),
                    help="IP/hostname to scan (default: 127.0.0.1 — this machine)")
    ap.add_argument("--i-have-permission", action="store_true",
                    help="Required if --target is not this machine or a private/loopback address")
    ap.add_argument("--label", default=None,
                    help="Provenance tag (default: this machine's hostname)")
    ap.add_argument("--db", default="trainset.db", help="local trainset.db path")
    ap.add_argument("--jsonl-out", default="report_training_log.jsonl",
                    help="also append the raw row here, same format collect_inputs.py uses")
    ap.add_argument("--malware", choices=["live", "cache", "skip"], default="skip",
                    help="live: run ClamAV now (slow, first run 1-4+ hours); "
                         "cache: read last background-scanner result; skip: omit (default)")
    ap.add_argument("--yes", action="store_true",
                    help="skip the interactive confirmation prompt")
    ap.add_argument("--export-dir", default=".",
                    help="directory to write the standalone contribution file into")
    args = ap.parse_args()

    if not _is_local_target(args.target) and not args.i_have_permission:
        sys.exit(
            f"[contribute] target {args.target!r} is not this machine or a private/loopback "
            f"address. Re-run with --i-have-permission only if you have the owner's explicit "
            f"authorization to scan it."
        )

    label = args.label or socket.gethostname()

    _preflight(args.malware, args.yes)
    _print_banner(args.target, args.malware)
    _confirm(args.yes)

    print(f"\n[contribute] target={args.target} label={label} malware={args.malware}")
    result = collect_inputs.collect(
        args.target, label, args.jsonl_out, args.malware, allow_dupes=True,
    )
    ordered_facts = result["ordered_facts"]
    fhash = result["hash"]

    hist = result.get("tier_histogram") or {}
    print(f"\n[contribute] scan complete — shape={result['shape']} "
          f"tiers={{critical:{hist.get('critical', 0)}, high:{hist.get('high', 0)}, "
          f"medium:{hist.get('medium', 0)}, low:{hist.get('low', 0)}}} "
          f"({len(ordered_facts)} finding(s) total)")
    for f in ordered_facts:
        print(f"  [{f.get('severity', '?'):<8}] {f.get('source', '?'):<10} {f.get('affected', '')}")
    print()

    db_conn = _init_trainset_db(args.db)
    if fhash in _existing_db_hashes(db_conn):
        print(f"[contribute] identical scan already present in {args.db} (hash {fhash[:12]}) "
              f"— not inserting a duplicate row.")
        inserted_id = None
    else:
        cur = db_conn.execute(
            "INSERT INTO examples (source, profile, ordered_facts, status, platform) "
            "VALUES ('real', NULL, ?, 'pending', ?)",
            (json.dumps(ordered_facts), platform.system().lower()),
        )
        db_conn.commit()
        inserted_id = cur.lastrowid
        print(f"[contribute] inserted row id={inserted_id} into {args.db} (source=real, status=pending)")
    db_conn.close()

    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    export_name = f"contrib_{label}_{ts}_{fhash[:8]}.json"
    export_path = os.path.join(args.export_dir, export_name)
    with open(export_path, "w") as f:
        json.dump({
            "ordered_facts": ordered_facts,
            "_meta": {
                "label": label,
                "target": args.target,
                "collector_host": socket.gethostname(),
                "platform": platform.platform(),
                "platform_system": platform.system().lower(),
                "malware_mode": args.malware,
                "shape": result["shape"],
                "tier_histogram": result.get("tier_histogram"),
                "facts_hash": fhash,
                "contributed_at": time.time(),
            },
        }, f, indent=2)

    print(f"""
[contribute] done. Findings written to {export_path}

Next step: send that file back to whoever asked you to run this script
(they'll merge it into the shared training set with merge_real_scans.py).
Nothing else needs to be sent — this file already contains everything above.
""".rstrip())


if __name__ == "__main__":
    main()
