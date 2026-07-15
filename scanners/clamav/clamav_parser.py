# SPDX-License-Identifier: GPL-2.0-only
import glob
import re
import signal
import sqlite3
import subprocess
import json
import os
import sys
import tempfile
import time
from typing import Dict, Iterator, List, Any, Optional, Tuple

# Directories where untrusted content realistically lands.
# Deliberately excludes /usr, /bin, /lib, /sbin — package-manager-owned files
# are already verified by dpkg/rpm integrity checks and don't need AV scanning.
_DEFAULT_SCAN_PATHS = [
    "/home",
    "/tmp",
    "/var/tmp",
    "/opt",
    "/srv",
    "/root",
    "/var/www",
]

# Pseudo-filesystems and noisy mount points that contain no real files.
_EXCLUDE_DIRS = [
    "/proc", "/sys", "/dev", "/run", "/snap",
]

# Directory name patterns that are enormous but never contain malware payloads.
# clamscan --exclude-dir matches against the full path component, so plain names work.
_EXCLUDE_DIR_PATTERNS = [
    r"\.cache$",
    r"\.git$",
    r"node_modules$",
    r"__pycache__$",
    r"\.venv$",
    r"venv$",
    r"\.tox$",
    r"\.mypy_cache$",
    r"\.pytest_cache$",
]

# Skip files larger than this — real malware is tiny; VM images / ISOs are not.
_MAX_FILESIZE = "50M"
# Cap how much data clamscan unpacks from archives before giving up on one file.
_MAX_SCANSIZE = "100M"

# How old (hours) ClamAV definitions can be before we bother running freshclam.
_FRESHCLAM_MAX_AGE_HOURS = 24

# Hard upper bound on the entire clamscan run (seconds). Partial results are
# preserved and a warning is emitted so the caller knows the scan was cut short.
DEFAULT_SCAN_TIMEOUT = 1800

# SQLite manifest tracking (path -> mtime/size/inode) so repeat runs can skip
# files that haven't changed since the last scan. Separate from
# vulnerability_cache.db, which is nmap/CVE-specific.
_DEFAULT_MANIFEST_DB = "clamav_manifest.db"

# A full scan (every file, content read and hashed against signatures) is
# forced at least this often, regardless of the manifest, so files that were
# never modified but are now covered by newer signatures still get re-checked
# on a bounded cadence rather than being skipped forever by the incremental path.
_FULL_SCAN_INTERVAL_DAYS = 30


def _definitions_are_fresh(max_age_hours: int = _FRESHCLAM_MAX_AGE_HOURS) -> bool:
    """Returns True if the newest ClamAV database file is younger than max_age_hours."""
    db_files = glob.glob("/var/lib/clamav/*.cvd") + glob.glob("/var/lib/clamav/*.cld")
    if not db_files:
        return False
    newest_mtime = max(os.path.getmtime(p) for p in db_files)
    return (time.time() - newest_mtime) / 3600 < max_age_hours


# --- Manifest (incremental-scan state) -------------------------------------

def _init_manifest_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS file_manifest (
            path  TEXT PRIMARY KEY,
            mtime REAL NOT NULL,
            size  INTEGER NOT NULL,
            inode INTEGER NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS scan_state (
            key   TEXT PRIMARY KEY,
            value TEXT
        )"""
    )
    conn.commit()
    return conn


def _get_last_full_scan_ts(conn: sqlite3.Connection) -> Optional[float]:
    row = conn.execute(
        "SELECT value FROM scan_state WHERE key = 'last_full_scan_ts'"
    ).fetchone()
    return float(row[0]) if row else None


def _set_last_full_scan_ts(conn: sqlite3.Connection, ts: float) -> None:
    conn.execute(
        "INSERT INTO scan_state (key, value) VALUES ('last_full_scan_ts', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(ts),),
    )
    conn.commit()


def _should_run_full_scan(conn: sqlite3.Connection, force_full: bool) -> bool:
    if force_full:
        return True
    last_ts = _get_last_full_scan_ts(conn)
    if last_ts is None:
        return True
    age_days = (time.time() - last_ts) / 86400
    return age_days >= _FULL_SCAN_INTERVAL_DAYS


# --- Last-result store (decouples "run the scan" from "read the result") ---
# Lets a scan be triggered out-of-band (cron/systemd timer/manual run) while a
# caller like agent.py's deterministic spine only ever reads whatever the most
# recently *completed* scan produced — an instant read regardless of how long
# the underlying clamscan invocation took. Uses the same scan_state key/value
# table as last_full_scan_ts, just two more keys, so no new DB/table is needed.

def save_last_result(manifest_db_path: str, payload: Dict[str, Any]) -> None:
    """Persists a completed scan's LLM-ready payload plus a completion timestamp,
    so a later, unrelated process can read it back via load_last_result without
    re-running clamscan."""
    conn = _init_manifest_db(manifest_db_path)
    try:
        conn.execute(
            "INSERT INTO scan_state (key, value) VALUES ('last_result_payload', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (json.dumps(payload),),
        )
        conn.execute(
            "INSERT INTO scan_state (key, value) VALUES ('last_result_completed_at', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(time.time()),),
        )
        conn.commit()
    finally:
        conn.close()


def load_last_result(manifest_db_path: str) -> Optional[Dict[str, Any]]:
    """Returns {"payload": <last saved payload>, "completed_at": <unix ts>} for the
    most recent completed scan, or None if no scan has ever completed against
    this manifest DB."""
    conn = _init_manifest_db(manifest_db_path)
    try:
        payload_row = conn.execute(
            "SELECT value FROM scan_state WHERE key = 'last_result_payload'"
        ).fetchone()
        ts_row = conn.execute(
            "SELECT value FROM scan_state WHERE key = 'last_result_completed_at'"
        ).fetchone()
        if not payload_row or not ts_row:
            return None
        return {
            "payload": json.loads(payload_row[0]),
            "completed_at": float(ts_row[0]),
        }
    finally:
        conn.close()


def _is_excluded_dir(dirpath: str) -> bool:
    for prefix in _EXCLUDE_DIRS:
        if dirpath == prefix or dirpath.startswith(prefix + os.sep):
            return True
    for pattern in _EXCLUDE_DIR_PATTERNS:
        if re.search(pattern, dirpath):
            return True
    return False


def _enumerate_candidate_files(existing_paths: List[str]) -> Iterator[str]:
    """Walks existing_paths, pruning excluded directories, yielding file paths.

    This mirrors clamscan's --exclude-dir behavior in Python so the
    incremental path can stat candidates directly without invoking clamscan
    just to find out what would have been scanned.
    """
    for root_path in existing_paths:
        for dirpath, dirnames, filenames in os.walk(root_path, onerror=lambda e: None):
            dirnames[:] = [
                d for d in dirnames if not _is_excluded_dir(os.path.join(dirpath, d))
            ]
            for fname in filenames:
                yield os.path.join(dirpath, fname)


def _diff_against_manifest(
    conn: sqlite3.Connection, candidate_files: Iterator[str]
) -> Tuple[List[str], Dict[str, Tuple[float, int, int]]]:
    """Returns (changed_or_new_paths, stat_by_path) by comparing each
    candidate's current (mtime, size, inode) against the stored manifest.
    Files that error on stat() (e.g. removed mid-walk) are skipped.
    """
    changed: List[str] = []
    stat_by_path: Dict[str, Tuple[float, int, int]] = {}
    cur = conn.cursor()
    for path in candidate_files:
        try:
            st = os.stat(path)
        except OSError:
            continue
        current = (st.st_mtime, st.st_size, st.st_ino)
        stat_by_path[path] = current
        row = cur.execute(
            "SELECT mtime, size, inode FROM file_manifest WHERE path = ?", (path,)
        ).fetchone()
        if row is None or tuple(row) != current:
            changed.append(path)
    return changed, stat_by_path


def _update_manifest(
    conn: sqlite3.Connection, stat_by_path: Dict[str, Tuple[float, int, int]]
) -> None:
    conn.executemany(
        "INSERT INTO file_manifest (path, mtime, size, inode) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(path) DO UPDATE SET mtime = excluded.mtime, "
        "size = excluded.size, inode = excluded.inode",
        [(p, m, s, i) for p, (m, s, i) in stat_by_path.items()],
    )
    conn.commit()


# STAGE 1: AUTOMATED EXECUTION ENGINE

def _run_clamscan_subprocess(
    command: List[str], scan_timeout: int
) -> Tuple[List[str], bool]:
    """Runs a clamscan command, streaming stdout and enforcing scan_timeout.

    Returns (collected_lines, timed_out). On timeout, SIGTERM is sent first so
    clamscan can flush its summary block, then SIGKILL after a 5s grace period.
    """
    collected_lines: List[str] = []
    timed_out = False
    with subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ) as proc:
        assert proc.stdout is not None
        deadline = time.monotonic() + scan_timeout
        for line in proc.stdout:
            line = line.rstrip("\n")
            collected_lines.append(line)
            if line.endswith("FOUND") or line.startswith("-------"):
                print(f"    {line}", file=sys.stderr)
            if time.monotonic() > deadline:
                timed_out = True
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
    return collected_lines, timed_out


def run_clamav_scan(
    scan_paths: Optional[List[str]] = None,
    scan_timeout: int = DEFAULT_SCAN_TIMEOUT,
    manifest_db_path: str = _DEFAULT_MANIFEST_DB,
    force_full_scan: bool = False,
) -> str:
    """
    Optionally updates virus definitions via freshclam (skipped when definitions
    are younger than _FRESHCLAM_MAX_AGE_HOURS), then runs clamscan across the
    targeted high-risk directories.

    Two modes, chosen automatically via the manifest DB at manifest_db_path:

    - FULL: every candidate file's content is scanned. Runs on first use, when
      force_full_scan is True, or when _FULL_SCAN_INTERVAL_DAYS have elapsed
      since the last completed full scan. This is the only mode that can
      detect a file that hasn't changed but is now matched by a signature
      added since the last scan, so it's forced periodically rather than
      left to the incremental path indefinitely.
    - INCREMENTAL: only files whose (mtime, size, inode) changed since the
      last recorded scan are passed to clamscan via --file-list. Everything
      else is skipped without opening it. This is what makes repeat runs fast.

    scan_timeout caps the clamscan invocation itself. Partial results collected
    before the timeout are returned with a warning line appended. A full scan
    that times out does NOT update last_full_scan_ts, so the next run retries
    a full scan rather than falsely believing full coverage was achieved.

    No daemon (clamd/clamdscan) is used — clamscan is invoked directly per run
    to avoid a persistent background process and its memory/CPU overhead.
    """
    if scan_paths is None:
        scan_paths = _DEFAULT_SCAN_PATHS

    existing_paths = [p for p in scan_paths if os.path.exists(p)]
    if not existing_paths:
        print("[!] None of the target scan paths exist on this host.", file=sys.stderr)
        return ""

    if _definitions_are_fresh():
        print("[*] ClamAV definitions are up-to-date — skipping freshclam.", file=sys.stderr)
    else:
        print("[*] Updating ClamAV virus definitions via freshclam...", file=sys.stderr)
        try:
            subprocess.run(
                ["freshclam", "--quiet"],
                check=False,        # non-zero exit when already up-to-date; don't raise
                timeout=120,
            )
        except FileNotFoundError:
            print("[!] freshclam not found — skipping definition update.", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print("[!] freshclam timed out — proceeding with existing definitions.", file=sys.stderr)

    conn = _init_manifest_db(manifest_db_path)
    try:
        run_full = _should_run_full_scan(conn, force_full_scan)

        exclude_flags: List[str] = []
        for d in _EXCLUDE_DIRS:
            exclude_flags += ["--exclude-dir", f"^{d}"]
        for pattern in _EXCLUDE_DIR_PATTERNS:
            exclude_flags += ["--exclude-dir", pattern]

        if run_full:
            print(f"[*] Running FULL scan across: {', '.join(existing_paths)}", file=sys.stderr)
            command = (
                ["clamscan", "--recursive", "--infected",
                 f"--max-filesize={_MAX_FILESIZE}",
                 f"--max-scansize={_MAX_SCANSIZE}"]
                + exclude_flags
                + existing_paths
            )
            try:
                collected_lines, timed_out = _run_clamscan_subprocess(command, scan_timeout)
            except FileNotFoundError:
                print("[!] Error: 'clamscan' is not installed on this host node.", file=sys.stderr)
                return ""
            except Exception as e:
                print(f"[!] Unexpected error during scan: {e}", file=sys.stderr)
                return ""

            # Refresh the manifest from a stat-only walk (cheap) so the next
            # run has a baseline to diff against, regardless of timeout.
            _, stat_by_path = _diff_against_manifest(conn, _enumerate_candidate_files(existing_paths))
            _update_manifest(conn, stat_by_path)

            if timed_out:
                warning = f"WARNING: scan timed out after {scan_timeout}s — results are partial"
                print(f"[!] {warning}", file=sys.stderr)
                collected_lines.append(warning)
                # Full scan didn't finish — don't mark it complete, so the
                # next run retries a full scan instead of waiting out the interval.
            else:
                _set_last_full_scan_ts(conn, time.time())

            collected_lines.append("SCAN_MODE: full")
            return "\n".join(collected_lines)

        else:
            changed_paths, stat_by_path = _diff_against_manifest(
                conn, _enumerate_candidate_files(existing_paths)
            )
            print(
                f"[*] Running INCREMENTAL scan — {len(changed_paths)} of "
                f"{len(stat_by_path)} candidate files changed since last scan.",
                file=sys.stderr,
            )

            if not changed_paths:
                _update_manifest(conn, stat_by_path)
                return "\n".join([
                    "----------- SCAN SUMMARY -----------",
                    "Infected files: 0",
                    f"Scanned files: {len(stat_by_path)}",
                    "SCAN_MODE: incremental",
                ])

            list_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            )
            try:
                list_file.write("\n".join(changed_paths))
                list_file.close()

                command = [
                    "clamscan", "--infected",
                    f"--max-filesize={_MAX_FILESIZE}",
                    f"--max-scansize={_MAX_SCANSIZE}",
                    f"--file-list={list_file.name}",
                ]
                try:
                    collected_lines, timed_out = _run_clamscan_subprocess(command, scan_timeout)
                except FileNotFoundError:
                    print("[!] Error: 'clamscan' is not installed on this host node.", file=sys.stderr)
                    return ""
                except Exception as e:
                    print(f"[!] Unexpected error during scan: {e}", file=sys.stderr)
                    return ""
            finally:
                os.unlink(list_file.name)

            # Only record stats for files clamscan actually got to scan.
            # On timeout we can't be sure which subset that was, so skip the
            # manifest update entirely — those files stay "changed" and will
            # be retried on the next incremental run rather than silently
            # marked as seen.
            if not timed_out:
                _update_manifest(conn, stat_by_path)
            else:
                warning = f"WARNING: scan timed out after {scan_timeout}s — results are partial"
                print(f"[!] {warning}", file=sys.stderr)
                collected_lines.append(warning)

            collected_lines.append("SCAN_MODE: incremental")
            return "\n".join(collected_lines)
    finally:
        conn.close()


# STAGE 2: REPORT PARSER

_SUMMARY_MARKER = "SCAN SUMMARY"


def _parse_infected_line(line: str) -> Optional[Dict[str, str]]:
    """
    Parses a clamscan infected-file line of the form:
      /path/to/file: Signature-Name FOUND

    Uses rsplit to anchor on the LAST ': ' so adversarially named files
    (e.g. '/evil: FOUND.txt') do not corrupt the path/signature split.
    """
    if not line.endswith(" FOUND"):
        return None

    body  = line[: -len(" FOUND")]
    parts = body.rsplit(": ", 1)
    if len(parts) != 2:
        return None

    file_path, signature = parts[0].strip(), parts[1].strip()
    if not file_path or not signature:
        return None

    return {
        "file_path": file_path,
        "signature": signature,
        "severity":  _infer_severity(signature),
    }


_HIGH_KEYWORDS = {
    "trojan", "backdoor", "rootkit", "exploit", "ransomware",
    "worm", "virus", "malware", "keylogger", "stealer",
    "dropper", "downloader", "injector", "rat", "botnet",
    "shellcode", "webshell", "cryptominer", "miner",
}
_MEDIUM_KEYWORDS = {
    "adware", "spyware", "pua", "pup", "riskware",
    "heuristics.encrypted", "heuristics.structured", "heuristics.ole",
    "hacktool", "tool.crack", "tool.keygen", "tool.patcher",
    "suspicious", "obfuscated", "countermeasure",
}


def _infer_severity(signature: str) -> str:
    sig_lower = signature.lower()
    for kw in _HIGH_KEYWORDS:
        if kw in sig_lower:
            return "HIGH"
    for kw in _MEDIUM_KEYWORDS:
        if kw in sig_lower:
            return "MEDIUM"
    return "LOW"


def _parse_summary_block(lines: List[str]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for line in lines:
        line = line.strip()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        try:
            counts[key.strip().lower().replace(" ", "_")] = int(val.strip())
        except ValueError:
            continue
    return counts


def parse_clamav_output(raw_output: str) -> Dict[str, Any]:
    infected: List[Dict[str, str]] = []
    summary_lines: List[str]       = []
    in_summary = False
    scan_truncated = False
    scan_mode = "full"

    for line in raw_output.splitlines():
        if line.startswith("WARNING: scan timed out"):
            scan_truncated = True
            continue

        if line.startswith("SCAN_MODE:"):
            scan_mode = line.split(":", 1)[1].strip()
            continue

        if _SUMMARY_MARKER in line:
            in_summary = True
            continue

        if in_summary:
            summary_lines.append(line)
        else:
            parsed = _parse_infected_line(line.strip())
            if parsed:
                infected.append(parsed)

    return {
        "infected":       infected,
        "summary":        _parse_summary_block(summary_lines),
        "scan_truncated": scan_truncated,
        "scan_mode":      scan_mode,
    }


# STAGE 3: CLEAN TEXT TRUNCATION ENGINE

def clean_truncate_description(text_block: str, max_chars: int = 400) -> str:
    if not text_block or len(text_block) <= max_chars:
        return text_block
    raw_cut   = text_block[:max_chars]
    clean_cut = raw_cut.rsplit(" ", 1)[0]
    return clean_cut


# STAGE 4: THE LLM CONDENSING AND ENRICHMENT LAYER

_SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def build_llm_payload_from_clamav(
    parsed_report: Dict[str, Any],
    scan_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    infected: List[Dict[str, str]] = parsed_report.get("infected", [])
    summary:  Dict[str, int]       = parsed_report.get("summary", {})
    scan_truncated: bool            = parsed_report.get("scan_truncated", False)
    scan_mode: str                  = parsed_report.get("scan_mode", "full")

    high_count   = sum(1 for f in infected if f["severity"] == "HIGH")
    medium_count = sum(1 for f in infected if f["severity"] == "MEDIUM")
    low_count    = sum(1 for f in infected if f["severity"] == "LOW")

    priority_findings: List[Dict[str, Any]] = [
        {
            "file_path": f["file_path"],
            "signature": clean_truncate_description(f["signature"]),
            "severity":  f["severity"],
        }
        for f in infected
    ]

    priority_findings.sort(
        key=lambda x: _SEVERITY_ORDER.get(x["severity"], 0),
        reverse=True,
    )

    payload: Dict[str, Any] = {
        "scan_target": scan_paths or _DEFAULT_SCAN_PATHS,
        "engine":      "ClamAV",
        "scan_mode":   scan_mode,
        "risk_summary": {
            "critical_count":   0,
            "high_count":       high_count,
            "medium_count":     medium_count,
            "low_count":        low_count,
            "total_actionable": len(infected),
            "scanned_files":    summary.get("scanned_files", 0),
            "infected_files":   summary.get("infected_files", 0),
        },
        "priority_findings": priority_findings[:10],
    }
    if scan_truncated:
        payload["warning"] = "Scan timed out — results cover only the portion of the filesystem scanned before the timeout. Re-run with a higher scan_timeout or narrower scan_paths for complete coverage."
    return payload


def main():
    env_paths = os.environ.get("CLAMAV_SCAN_PATHS")
    scan_paths = env_paths.split(",") if env_paths else None

    timeout_env = os.environ.get("CLAMAV_SCAN_TIMEOUT")
    scan_timeout = int(timeout_env) if timeout_env else DEFAULT_SCAN_TIMEOUT

    manifest_db_path = os.environ.get("CLAMAV_MANIFEST_DB", _DEFAULT_MANIFEST_DB)
    force_full_scan = os.environ.get("CLAMAV_FORCE_FULL_SCAN", "").lower() in ("1", "true", "yes")

    raw_output = run_clamav_scan(
        scan_paths=scan_paths,
        scan_timeout=scan_timeout,
        manifest_db_path=manifest_db_path,
        force_full_scan=force_full_scan,
    )

    if not raw_output:
        print("[!] Pipeline aborted. No scan data captured.", file=sys.stderr)
        sys.exit(1)

    parsed_report     = parse_clamav_output(raw_output)
    llm_ready_payload = build_llm_payload_from_clamav(parsed_report, scan_paths=scan_paths)
    print(json.dumps(llm_ready_payload, indent=2))


if __name__ == "__main__":
    main()
