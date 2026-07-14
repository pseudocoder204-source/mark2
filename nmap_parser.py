# SPDX-License-Identifier: GPL-2.0-only
import subprocess
import xml.etree.ElementTree as ET
from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import urllib.request
import urllib.parse
import json
import sqlite3
import time
import os
import sys
from datetime import datetime, timedelta, timezone
from bin_resolver import resolve as _resolve_bin
import re
import threading

# Concurrent nmap-pipeline runs (e.g. scan_network + scan_iot_defaults called in the
# same agent turn) each init/sync the same SQLite file — without this, two writers can
# collide mid-transaction and SQLite raises "database is locked". Serialize DB setup
# and NVD sync so only one pipeline touches the file at a time; scanning/parsing itself
# is unaffected and still runs concurrently.
_DB_WRITE_LOCK = threading.Lock()


def _synchronized(func):
    def _wrapper(*args, **kwargs):
        with _DB_WRITE_LOCK:
            return func(*args, **kwargs)
    return _wrapper

# STAGE 1: PORT SCANNING
class ScanType(Enum):
    # Enum locks args to hardcoded values, preventing command injection via the target parameter
    # --stats-every emits periodic "About X% done" progress lines on stderr — run_nmap
    # parses these to surface live progress instead of going silent until completion.
    # -T4 + --min-rate tune nmap's default conservative T3 timing/adaptive send-rate for
    # trusted local/home-network scanning, where WAN-safe stealth pacing just adds wait
    # time — not appropriate if this pipeline is ever pointed at a target outside the
    # operator's own network.
    VERSION_DETECT     = ["-sV", "--version-light", "-T4", "--min-rate", "100", "--stats-every", "5s"]
    QUICK_SYN          = ["-sS", "-F", "--open", "-T4", "--min-rate", "100", "--stats-every", "5s"]   # requires NET_RAW capability (root/Docker)
    # Host-discovery only (no port scan) — answers "who's on my network" and gives a
    # MAC-keyed inventory anchor for drift detection across repeat scans.
    HOST_DISCOVERY     = ["-sn", "-T4", "--stats-every", "5s"]
    # Home-network IoT/default-credential exposure check: router/camera/admin-panel
    # factory passwords and open UPnP. Same XML shape as VERSION_DETECT, plus <script> output.
    IOT_DEFAULT_CREDS  = ["-sV", "--version-light", "-T4", "--min-rate", "100", "--script", "http-default-accounts,upnp-info,snmp-info", "--stats-every", "5s"]

# Default hard timeout (seconds) for the nmap subprocess. A hung nmap process was a
# latent production hang with no prior bound — every worker must fail bounded, not hang.
DEFAULT_NMAP_TIMEOUT = 300

# Matches nmap's periodic progress lines, e.g. "Service scan Timing: About 40.00% done; ETC: ..."
_STATS_DONE_RE = re.compile(r"About\s+([\d.]+)%\s+done")


def run_nmap(target: str, scan_type: ScanType, timeout: int = DEFAULT_NMAP_TIMEOUT) -> str:
    # -oX - streams XML directly to stdout instead of writing a file
    command = [_resolve_bin("nmap"), "-oX", "-", *scan_type.value, target]
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError("Nmap binary not found. Please install Nmap and add it to your PATH.")

    stdout_chunks: List[str] = []
    stderr_chunks: List[str] = []

    def _drain_stdout():
        for line in proc.stdout:
            stdout_chunks.append(line)

    def _drain_stderr():
        for line in proc.stderr:
            stderr_chunks.append(line)
            match = _STATS_DONE_RE.search(line)
            if match:
                print(f"[nmap] {float(match.group(1)):.0f}% done...", file=sys.stderr)

    # Read stdout/stderr in separate threads while waiting — --stats-every writes to
    # stderr as the scan progresses, and a single-threaded read-after-wait would only
    # see it once the process (and the pipe buffer) has already finished.
    t_out = threading.Thread(target=_drain_stdout, daemon=True)
    t_err = threading.Thread(target=_drain_stderr, daemon=True)
    t_out.start()
    t_err.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise RuntimeError(f"Nmap scan of {target!r} exceeded the {timeout}s timeout and was killed.")
    finally:
        t_out.join(timeout=2)
        t_err.join(timeout=2)

    if proc.returncode != 0:
        raise RuntimeError(f"Nmap failed execution: {''.join(stderr_chunks).strip()}")

    return "".join(stdout_chunks)

# STAGE 2: DATA STRUCTURES & XML PARSING
@dataclass
class ServiceFinding:
    port: int
    protocol: str
    state: str
    service_name: str
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None  # Common Platform Enumeration — used as the DB lookup key
    cves: List[Dict[str, Any]] = field(default_factory=list)
    highest_cvss: float = 0.0
    critical_cve_count: int = 0
    high_cve_count: int = 0
    remediation_links: List[str] = field(default_factory=list)
    # Raw NSE script output (e.g. http-default-accounts, upnp-info, snmp-info) — deterministic
    # facts straight from nmap XML, never LLM-generated.
    script_output: List[Dict[str, str]] = field(default_factory=list)

@dataclass
class HostFinding:
    """Result of a -sn host-discovery scan: one live host on the network."""
    ip: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    status: str = "unknown"

def parse_nmap_xml(xml_data: str) -> List[ServiceFinding]:
    findings = []
    if not xml_data.strip():
        return findings
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall("host"):
            ports_node = host.find("ports")
            if ports_node is None:
                continue
            for port_node in ports_node.findall("port"):
                port_id  = int(port_node.attrib.get("portid", 0))
                protocol = port_node.attrib.get("protocol", "tcp")

                state = "unknown"
                state_node = port_node.find("state")
                if state_node is not None:
                    state = state_node.attrib.get("state", "unknown")

                service_name = "unknown"
                product, version, cpe_str = None, None, None
                service_node = port_node.find("service")
                if service_node is not None:
                    service_name = service_node.attrib.get("name", "unknown")
                    product      = service_node.attrib.get("product")
                    version      = service_node.attrib.get("version")
                    # Nmap may list several <cpe> under one service — typically an
                    # application CPE plus the host OS CPE (e.g. cpe:/o:linux:linux_kernel).
                    # Prefer the application CPE: attributing an OS-level CVE to a single
                    # service port is a false positive (a kernel CVE is not reachable via
                    # a UPnP port). Never let an :o:/:h: CPE win when an :a: one exists.
                    cpe_candidates = [c.text for c in service_node.findall("cpe") if c.text]
                    cpe_str = next(
                        (c for c in cpe_candidates if _cpe_part(c) == "a"),
                        cpe_candidates[0] if cpe_candidates else None,
                    )

                # Nmap emits legacy cpe:/ format; NVD API v2 requires cpe:2.3:
                if cpe_str and cpe_str.startswith("cpe:/"):
                    cpe_str = cpe_str.replace("cpe:/", "cpe:2.3:")

                script_output = [
                    {"id": s.attrib.get("id", ""), "output": s.attrib.get("output", "")}
                    for s in port_node.findall("script")
                ]

                findings.append(ServiceFinding(
                    port=port_id, protocol=protocol, state=state,
                    service_name=service_name, product=product, version=version, cpe=cpe_str,
                    script_output=script_output
                ))
        return findings
    except ET.ParseError as e:
        raise ValueError(f"Failed to parse Nmap XML: {e}")

def parse_nmap_host_discovery(xml_data: str) -> List[HostFinding]:
    """Parses the output of a -sn host-discovery scan into HostFinding records.

    Keyed by MAC (not IP) wherever nmap reports one, since home-network IPs churn
    via DHCP but MACs are the stable identity for drift detection across scans.
    """
    hosts = []
    if not xml_data.strip():
        return hosts
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall("host"):
            status_node = host.find("status")
            status = status_node.attrib.get("state", "unknown") if status_node is not None else "unknown"

            ip, mac, vendor = None, None, None
            for addr_node in host.findall("address"):
                addrtype = addr_node.attrib.get("addrtype")
                if addrtype in ("ipv4", "ipv6") and ip is None:
                    ip = addr_node.attrib.get("addr")
                elif addrtype == "mac":
                    mac = addr_node.attrib.get("addr")
                    vendor = addr_node.attrib.get("vendor")

            hostname = None
            hostnames_node = host.find("hostnames")
            if hostnames_node is not None:
                hostname_node = hostnames_node.find("hostname")
                if hostname_node is not None:
                    hostname = hostname_node.attrib.get("name")

            hosts.append(HostFinding(ip=ip, mac=mac, vendor=vendor, hostname=hostname, status=status))
        return hosts
    except ET.ParseError as e:
        raise ValueError(f"Failed to parse Nmap XML: {e}")

# STAGE 3: LOCAL CVE CACHE (SQLite + NVD API)
@_synchronized
def init_local_db(db_path: str = "vulnerability_cache.db"):
    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # NVD stores vulnerability ranges as (cpe_base, start, end) rather than one row per version,
    # so we mirror that structure to support range-based matching queries.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS local_cves (
        id                       INTEGER PRIMARY KEY AUTOINCREMENT,
        cpe_base                 TEXT NOT NULL,
        vulnerable_version       TEXT,
        version_start_including  TEXT,
        version_end_including    TEXT,
        cve_id                   TEXT NOT NULL,
        cvss_score               REAL,
        severity                 TEXT,
        description              TEXT,
        patch_links              TEXT
    )
    """)

    # B-Tree index on cpe_base turns per-scan lookups from O(N) full scans to O(log N)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpe_base ON local_cves (cpe_base);")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sync_metadata (
        id                   INTEGER PRIMARY KEY,
        last_sync_timestamp  TEXT,
        resume_index         INTEGER
    )
    """)
    # Migrate existing DBs that predate the resume_index column
    try:
        cursor.execute("ALTER TABLE sync_metadata ADD COLUMN resume_index INTEGER")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()
    print("[+] DB structures configured with range-matching support.")

def get_last_sync_time(db_path: str) -> Optional[str]:
    """Returns ISO timestamp of last completed sync, or None if the db has never been synced."""
    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT last_sync_timestamp FROM sync_metadata WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    return row[0] if row and row[0] else None

def get_resume_index(db_path: str) -> Optional[int]:
    """Returns the batch start_index to resume from if a full sync was interrupted, else None."""
    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT resume_index FROM sync_metadata WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    return row[0] if row and row[0] is not None else None

def save_sync_time(db_path: str, timestamp: str):
    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO sync_metadata (id, last_sync_timestamp, resume_index) VALUES (1, ?, NULL)",
        (timestamp,)
    )
    conn.commit()
    conn.close()

def _checkpoint_resume(cursor, conn, next_index: int):
    """Persists next_index so an interrupted full sync can resume from this batch."""
    cursor.execute("INSERT OR IGNORE INTO sync_metadata (id, last_sync_timestamp) VALUES (1, '')")
    cursor.execute("UPDATE sync_metadata SET resume_index = ? WHERE id = 1", (next_index,))
    conn.commit()

def _cpe_part(cpe_str: str) -> str:
    """Returns the CPE 'part' letter: 'a' (application), 'o' (OS), or 'h' (hardware).

    Empty string if it can't be determined. Used to keep OS/hardware CPEs from being
    matched against a service/port finding (that mis-attributes host-wide CVEs to a port).
    """
    if not cpe_str:
        return ""
    raw = cpe_str.replace("cpe:/", "").replace("cpe:2.3:", "")
    return raw.split(":", 1)[0] if raw else ""


def parse_cpe(cpe_str: str):
    """
    Splits a full CPE string into (base, version).
    e.g. 'cpe:2.3:a:apache:http_server:2.4.49' -> ('cpe:2.3:a:apache:http_server', '2.4.49')
    """
    if not cpe_str:
        return None, None
    raw   = cpe_str.replace("cpe:/", "").replace("cpe:2.3:", "")
    parts = raw.split(":")
    if len(parts) >= 3:
        part, vendor, product = parts[0], parts[1], parts[2]
        version = parts[3] if (len(parts) > 3 and parts[3] not in ["", "*", "-"]) else "*"
        return f"cpe:2.3:{part}:{vendor}:{product}", version
    return None, None

def parse_version_tuple(version_str: str):
    """
    Extracts numeric version components, stripping OS suffixes.
    e.g. '9.6p1 Ubuntu 3ubuntu13.16' -> (9, 6)
    """
    if not version_str or version_str in ["*", "-"]:
        return ()
    match = re.match(r'^(\d+(?:\.\d+)*)', str(version_str))
    if not match:
        return ()
    return tuple(int(p) for p in match.group(1).split("."))

def is_version_in_range(target: str, exact: str, start_inc: str, end_inc: str) -> bool:
    if not target or target == "*":
        return False

    clean_target = str(target).split(' ')[0]

    if exact and exact != "*":
        # Allow patch-level suffixes: '9.6p1' matches exact '9.6', but '10.0' does not match '1'
        return bool(re.match(rf"^{re.escape(exact)}([\.\-p_]|$)", clean_target))

    if not start_inc and not end_inc:
        return False

    target_tup = parse_version_tuple(clean_target)
    if not target_tup:
        return False

    if start_inc:
        start_tup = parse_version_tuple(start_inc)
        if not start_tup:
            return False
        if target_tup < start_tup:
            return False
        # When NVD omits an upper bound, cap at +1 major version to avoid false positives
        # on unrelated future releases that share the same vendor/product CPE base.
        if not end_inc and target_tup[0] > start_tup[0] + 1:
            return False

    if end_inc:
        end_tup = parse_version_tuple(end_inc)
        if not end_tup:
            return False
        if target_tup > end_tup:
            return False

    return True

@_synchronized
def sync_local_db_with_nvd(db_path: str = "vulnerability_cache.db", api_key: str = ""):
    """
    Syncs the local CVE cache from NVD.
    First run: full download of all CVEs (no date filter).
    Subsequent runs: incremental fetch of CVEs modified since last sync.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    now_utc  = datetime.now(timezone.utc)
    end_time = (now_utc - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%S")

    last_sync = get_last_sync_time(db_path)
    if last_sync is None:
        resume_index = get_resume_index(db_path)
        if resume_index is not None:
            print(f"[*] Resuming interrupted full sync from index {resume_index}...")
            start_index = resume_index
        else:
            print("[*] No prior sync found. Performing full NVD database download (this will take a while)...")
            start_index = 0
        date_params = {}
    else:
        start_time = last_sync
        if start_time >= end_time:
            start_time = (now_utc - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        print(f"[*] Commencing incremental sync from window: {start_time} to {end_time}")
        date_params = {"lastModStartDate": start_time, "lastModEndDate": end_time}
        start_index = 0
    results_per_page = 500
    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    sync_completed  = False

    while True:
        params = {**date_params, "startIndex": start_index, "resultsPerPage": results_per_page}
        req = urllib.request.Request(
            f"{base_url}?{urllib.parse.urlencode(params)}",
            headers={"User-Agent": "SecurityPipelineSyncEngine/3.0", **({"apiKey": api_key} if api_key else {})}
        )

        max_retries = 5
        retry_count = 0
        success     = False
        data        = {}

        while retry_count < max_retries and not success:
            try:
                time.sleep(1.5 if api_key else 6.5)  # stay under NVD rate limits
                print(f"    [+] Querying page batch starting at index: {start_index} (Attempt {retry_count + 1}/{max_retries})...")
                with urllib.request.urlopen(req, timeout=90) as response:  # 90s: NVD is slow
                    if response.status == 200:
                        data    = json.loads(response.read().decode("utf-8"))
                        success = True
                    else:
                        print(f"    [-] NVD Server returned status code: {response.status}. Retrying...")
                        retry_count += 1
            except Exception as e:
                print(f"    [-] Read timeout or connection error: {e}. Retrying...")
                retry_count += 1
                time.sleep(5 * retry_count)

        if not success:
            print(f"[-] Failed to fetch batch at index {start_index} after {max_retries} attempts. Aborting.")
            break

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            print("[+] No additional modifications discovered in this index bracket.")
            sync_completed = True
            break

        # Explicit transaction batches all inserts into a single disk flush instead of one per row
        cursor.execute("BEGIN TRANSACTION;")

        for item in vulnerabilities:
            cve_box  = item.get("cve", {})
            cve_id   = cve_box.get("id")
            desc_text = next(
                (d.get("value") for d in cve_box.get("descriptions", []) if d.get("lang") == "en"),
                "No description."
            )

            metrics    = cve_box.get("metrics", {})
            cvss_score = 0.0
            severity   = "UNKNOWN"
            if "cvssMetricV31" in metrics:
                cvss_data  = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0.0))
                severity   = cvss_data.get("baseSeverity", "UNKNOWN").upper()
            elif "cvssMetricV30" in metrics:
                cvss_data  = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0.0))
                severity   = cvss_data.get("baseSeverity", "UNKNOWN").upper()

            links_string = ",".join(ref.get("url") for ref in cve_box.get("references", []))

            for config in cve_box.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe_name = cpe_match.get("criteria")
                        if not cpe_name:
                            continue
                        cpe_base, vuln_ver = parse_cpe(cpe_name)
                        start_inc = cpe_match.get("versionStartIncluding")
                        end_inc   = cpe_match.get("versionEndIncluding")
                        if not cpe_base:
                            continue
                        cursor.execute("""
                            DELETE FROM local_cves
                            WHERE cpe_base = ? AND cve_id = ?
                            AND vulnerable_version IS ? AND version_start_including IS ? AND version_end_including IS ?
                        """, (cpe_base, cve_id, vuln_ver, start_inc, end_inc))
                        cursor.execute("""
                            INSERT INTO local_cves
                            (cpe_base, vulnerable_version, version_start_including, version_end_including,
                             cve_id, cvss_score, severity, description, patch_links)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (cpe_base, vuln_ver, start_inc, end_inc, cve_id, cvss_score, severity, desc_text, links_string))

        conn.commit()
        print(f"    [+] Successfully committed batch indices {start_index} to {start_index + len(vulnerabilities)}")

        total_results = data.get("totalResults", 0)
        start_index  += results_per_page

        if not date_params:
            _checkpoint_resume(cursor, conn, start_index)

        if start_index >= total_results:
            sync_completed = True

    conn.close()
    if sync_completed:
        save_sync_time(db_path, end_time)
        print(f"[+] Sync complete. Cache snapshot updated to: {end_time}")
    else:
        print("[-] Sync aborted prematurely. Remaining data will be caught on the next run.")

def fetch_cves_from_local_cache(cpe_name: str, db_path: str = "vulnerability_cache.db", allow_non_app: bool = False) -> List[Dict[str, Any]]:
    if not cpe_name:
        return []
    # Only application CPEs describe a service on a port. An OS/hardware CPE
    # (e.g. cpe:2.3:o:linux:linux_kernel) attached to a service finding would
    # otherwise pull in host-wide kernel CVEs and mis-attribute them to that port.
    # The one sanctioned exception is the host-OS finding path (build_host_os_findings),
    # which passes allow_non_app=True to enrich the OS CPE as a host-level finding.
    if not allow_non_app and _cpe_part(cpe_name) != "a":
        return []
    cpe_base, target_version = parse_cpe(cpe_name)
    if not cpe_base:
        return []

    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cve_id, vulnerable_version, version_start_including, version_end_including,
               cvss_score, severity, description, patch_links
        FROM local_cves WHERE cpe_base = ?
    """, (cpe_base,))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for cve_id, vuln_ver, start_inc, end_inc, cvss_score, severity, description, links_string in rows:
        if is_version_in_range(target_version, vuln_ver, start_inc, end_inc):
            links = [l.strip() for l in (links_string or "").split(",") if l.strip()]
            results.append({
                "cve_id":      cve_id,
                "cvss_score":  float(cvss_score) if cvss_score else 0.0,
                "severity":    severity or "UNKNOWN",
                "description": description or "No description provided.",
                "links":       links[:2]  # cap at 2 to limit LLM token cost
            })
    return results

def enrich_and_condense_findings(findings: List[ServiceFinding], db_path: str = "vulnerability_cache.db") -> List[Dict[str, Any]]:
    # Never skip a finding with no CVEs — host inventory (port/version/service) is always preserved
    llm_payload = []
    for finding in findings:
        raw_cves = fetch_cves_from_local_cache(finding.cpe, db_path) if finding.cpe else []
        raw_cves = [c for c in raw_cves if float(c["cvss_score"]) > 0.0 and c["severity"] != "UNKNOWN"]

        all_scores = [float(c["cvss_score"]) for c in raw_cves]
        finding.highest_cvss       = max(all_scores) if all_scores else 0.0
        finding.critical_cve_count = sum(1 for c in raw_cves if c["severity"] == "CRITICAL")
        finding.high_cve_count     = sum(1 for c in raw_cves if c["severity"] == "HIGH")

        seen_links = set()
        for c in raw_cves:
            seen_links.update(c["links"])
        finding.remediation_links = list(seen_links)[:4]

        finding.cves = sorted(raw_cves, key=lambda x: float(x["cvss_score"]), reverse=True)[:5]

        llm_payload.append({
            "port":    finding.port,
            "service": finding.service_name,
            "product": finding.product,
            "version": finding.version,
            "cpe":     finding.cpe,
            "risk_metrics": {
                "max_cvss_score":          finding.highest_cvss,
                "total_critical_cves_found": finding.critical_cve_count,
                "total_high_cves_found":   finding.high_cve_count
            },
            "priority_vulnerabilities": finding.cves,
            "verified_patch_urls":      finding.remediation_links,
            "script_findings":          finding.script_output
        })
    return llm_payload


def _humanize_cpe(cpe_str: str) -> str:
    """'cpe:2.3:o:linux:linux_kernel:5.15' -> 'Linux Kernel 5.15' (best-effort label)."""
    base, version = parse_cpe(cpe_str)
    if not base:
        return cpe_str
    product = base.split(":")[-1].replace("_", " ").strip().title()
    return f"{product} {version}".strip() if version and version != "*" else product


def parse_nmap_os_cpes(xml_data: str) -> List[Dict[str, str]]:
    """Harvest distinct host OS CPEs (:o:) from an nmap scan.

    Two sources: the <os> detection block (-O) and any OS CPE nmap attaches to a
    service fingerprint (e.g. the cpe:/o:linux:linux_kernel:5.15 that used to get
    mis-stapled onto a service port). Deduplicated by CPE, first human label wins.
    """
    if not xml_data.strip():
        return []
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return []

    def _norm(c: Optional[str]) -> Optional[str]:
        if not c:
            return None
        return c.replace("cpe:/", "cpe:2.3:") if c.startswith("cpe:/") else c

    labels: Dict[str, Optional[str]] = {}
    for host in root.findall("host"):
        os_node = host.find("os")
        if os_node is not None:
            for osmatch in os_node.findall("osmatch"):
                name = osmatch.attrib.get("name")
                for cpe_el in osmatch.iter("cpe"):
                    c = _norm(cpe_el.text)
                    if c and _cpe_part(c) == "o":
                        labels.setdefault(c, name)
        ports = host.find("ports")
        if ports is not None:
            for svc in ports.iter("service"):
                for cpe_el in svc.findall("cpe"):
                    c = _norm(cpe_el.text)
                    if c and _cpe_part(c) == "o":
                        labels.setdefault(c, None)
    return [{"cpe": c, "name": n or _humanize_cpe(c)} for c, n in labels.items()]


def build_host_os_findings(xml_data: str, db_path: str = "vulnerability_cache.db") -> List[Dict[str, Any]]:
    """Enrich the host's OS CPE(s) into host-level findings.

    This is the sanctioned home for OS/kernel CVEs: enriched once against the host OS
    rather than mis-attributed to a service port (see fetch_cves_from_local_cache guard).
    Only emits a finding when the OS CPE carries a concrete version AND matches real CVEs
    — a versionless remote fingerprint matches nothing and is silently dropped.
    """
    out = []
    for entry in parse_nmap_os_cpes(xml_data):
        cpe = entry["cpe"]
        cves = fetch_cves_from_local_cache(cpe, db_path, allow_non_app=True)
        cves = [c for c in cves if float(c["cvss_score"]) > 0.0 and c["severity"] != "UNKNOWN"]
        if not cves:
            continue
        cves = sorted(cves, key=lambda x: float(x["cvss_score"]), reverse=True)
        scores = [float(c["cvss_score"]) for c in cves]
        links: List[str] = []
        for c in cves:
            for l in c["links"]:
                if l not in links:
                    links.append(l)
        out.append({
            "finding_type": "host_os",
            "cpe":          cpe,
            "os_name":      entry["name"],
            "risk_metrics": {
                "max_cvss_score":            max(scores),
                "total_critical_cves_found": sum(1 for c in cves if c["severity"] == "CRITICAL"),
                "total_high_cves_found":     sum(1 for c in cves if c["severity"] == "HIGH"),
            },
            "priority_vulnerabilities": cves[:5],
            "verified_patch_urls":      links[:4],
        })
    return out

# ==============================================================================
# ENTRY POINT
# ==============================================================================

def main():
    DB_FILE     = "vulnerability_cache.db"
    TARGET      = os.environ.get("TARGET", "127.0.0.1")
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

    print("==================================================")
    print("      STARTING SECURITY PIPELINE EXECUTION        ")
    print("==================================================")

    init_local_db(DB_FILE)

    print("\n[*] Synchronizing local vulnerability cache with NVD...")
    sync_local_db_with_nvd(db_path=DB_FILE, api_key=NVD_API_KEY)

    try:
        print(f"\n[*] Stage 1: Running Nmap scan against {TARGET}...")
        raw_xml = run_nmap(target=TARGET, scan_type=ScanType.VERSION_DETECT)

        print("[*] Stage 2: Parsing Nmap XML...")
        parsed_findings = parse_nmap_xml(xml_data=raw_xml)
        print(f"    [+] Found {len(parsed_findings)} open network port(s).")

        print("[*] Stage 3: Enriching findings using local CVE cache...")
        llm_payload = enrich_and_condense_findings(findings=parsed_findings, db_path=DB_FILE)

        print("\n==================================================")
        print("STAGE 3 COMPLETED PAYLOAD (Ready for LLM Context):")
        print("==================================================")
        print(json.dumps(llm_payload, indent=2))

    except Exception as e:
        print(f"\n[-] Pipeline execution aborted: {e}")

    # print("\n[*] Verifying CVE lookup using known-vulnerable mock asset...")
    # mock_findings = [
    #     ServiceFinding(
    #         port=80, protocol="tcp", state="open", service_name="http",
    #         product="Apache httpd", version="2.4.49",
    #         cpe="cpe:2.3:a:apache:http_server:2.4.49"
    #     )
    # ]
    # test_payload = enrich_and_condense_findings(findings=mock_findings, db_path=DB_FILE)
    # print("\n[+] Verification Test Output:")
    # print(json.dumps(test_payload, indent=2))


if __name__ == "__main__":
    main()
