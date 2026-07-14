# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A multi-scanner network security pipeline that combines Nmap (port/service discovery + CVE enrichment), Trivy (filesystem vulnerability scanning), and Nuclei (web/network template-based vulnerability scanning) into a unified agentic system. Each scanner has a parser and a LangGraph subgraph. The pipeline is wrapped in an agentic layer that uses an LLM to interpret findings and produce a plain-English report for non-technical users.

## Running the Pipeline

**Requirements:** Python 3, `nmap` installed and on PATH, `langgraph` installed.

```bash
# Run the raw nmap pipeline only (scans 127.0.0.1, then runs a mock test)
python3 test_run.py

# Run the agentic diagnostic — prescribed workflow (Ollama, default)
python3 agent.py [--target IP] [--json]

# Run individual subgraphs standalone (all require langgraph installed)
python3 nmap_subgraph.py [target]
python3 trivy_subgraph.py
python3 nuclei_subgraph.py [target]
```

`test_run.py` is self-contained — all dependencies are Python stdlib. The `requirements.txt` lists the full set of dependencies including `langgraph`, `langchain-core`, `langchain-ollama`, `langchain-anthropic`, and `anthropic`.

```bash
pip install -r requirements.txt
```

**Docker** (development/testing convenience only — the product runs natively per-OS; see
"Cross-platform (Windows) support" below):

**Nmap is deliberately not installed in the image.** Redistributing the Nmap binary
triggers the NPSL's copyleft/OEM terms, while *executing* a user-installed Nmap and parsing
its output is expressly carved out by that license. `bin_resolver.resolve("nmap")` finds a
host-provided binary via `$NMAP_BINARY` → `$MARK2_BIN_DIR` → `$PATH`. Without it,
`scan_network` / `discover_hosts` / `scan_iot_defaults` return `{"status": "unavailable"}`
and the rest of the spine runs normally. `--build-arg INSTALL_NMAP=true` bakes Nmap in for
local use; such an image must never be published. See README.md § Licensing and Attributions.

```bash
docker build -t mark2 .                              # no Nmap; safe to share
docker build --build-arg INSTALL_NMAP=true -t mark2 . # with Nmap; local use only
docker run --rm -e TARGET=192.168.1.1 mark2

# With NVD API key (higher rate limits):
docker run --rm -e TARGET=192.168.1.1 -e NVD_API_KEY=your-key mark2

# With the malware stage wired up to the background ClamAV scanner's results
# (see systemd/ below) — without this mount, the container has no
# /clamav_manifest.db to read and the malware finding always reports
# "pending", even if the background scanner has completed real scans:
docker run --rm -e TARGET=192.168.1.1 \
  -e CLAMAV_MANIFEST_DB=/clamav_manifest.db \
  -v /var/lib/mark2/clamav_manifest.db:/clamav_manifest.db \
  mark2

# Run a standalone subgraph inside Docker (nuclei/trivy only live inside the image):
docker run --rm --network host \
  --entrypoint /venv/bin/python3 \
  -v $(pwd)/nuclei_subgraph.py:/nuclei_subgraph.py \
  -v $(pwd)/nuclei_parser.py:/nuclei_parser.py \
  -v $(pwd)/display_graph.py:/display_graph.py \
  mark2 /nuclei_subgraph.py 192.168.56.3
```

`TARGET` defaults to `127.0.0.1` if not set. The pre-populated `vulnerability_cache.db` is baked into the image so the first sync is incremental, not a full download.

**Nuclei requires `--network host`** on Linux so the container can reach hosts on the local subnet (e.g. VirtualBox host-only networks). Docker Desktop on Mac/Windows uses `host.docker.internal` instead.

## Architecture

### Raw pipeline (`test_run.py`)

Runs in three sequential stages:

**Stage 1 — Nmap execution** (`run_nmap`): Spawns nmap as a subprocess with `-oX -` to stream XML to stdout, under a hard `timeout` (default 300s, `DEFAULT_NMAP_TIMEOUT`) so a hung scan fails bounded instead of hanging the pipeline. `ScanType` is an Enum to prevent command injection by locking args to pre-validated configurations: `VERSION_DETECT`, `QUICK_SYN`, `HOST_DISCOVERY` (`-sn`, host-up/MAC inventory only, no ports), and `IOT_DEFAULT_CREDS` (`-sV` + the `http-default-accounts,upnp-info,snmp-info` NSE scripts, targeting the default-credential/open-UPnP exposures most common on home routers and IoT devices).

**Stage 2 — XML parsing** (`parse_nmap_xml` / `parse_nmap_host_discovery`): `parse_nmap_xml` transforms Nmap XML into `ServiceFinding` dataclasses, including any `<script>` output (e.g. `http-default-accounts` results) captured verbatim in `script_output` — never re-derived or summarized by an LLM. Normalizes legacy `cpe:/` prefixes to `cpe:2.3:` format during parsing. `parse_nmap_host_discovery` parses `-sn` output into `HostFinding` records (ip, mac, vendor, hostname, status), keyed by MAC rather than IP since home-network IPs churn via DHCP but MACs are the stable identity for future drift detection across repeat scans.

**Stage 3 — CVE enrichment** (`enrich_and_condense_findings`): Queries the local SQLite cache (`vulnerability_cache.db`) for matching CVEs. The cache is incrementally synced from the NVD API via `sync_local_db_with_nvd`. Version matching uses `is_version_in_range`, which handles exact matches, inclusive ranges, and includes a major-version drift guard to avoid false positives when NVD omits a ceiling version.

**Output:** A JSON list of port/service records, each with `risk_metrics` (max CVSS, critical/high counts) and `priority_vulnerabilities` (top 5 by score), ready to feed into an LLM prompt.

### LangGraph subgraphs

Each scanner has a self-contained LangGraph subgraph. All four follow the same pattern:

- A `TypedDict` state class holding inputs, stage outputs, and an `error` field
- Individual `_node` functions for each pipeline stage
- A `_route` function that short-circuits to `END` if any node sets `error`
- A `build_*_subgraph()` factory that returns a compiled `CompiledStateGraph`
- A `run_pipeline(...)` convenience wrapper
- A `display_graph(app)` call that renders the graph to `graph.png`
- A `__main__` entry point for standalone use

#### `nmap_subgraph.py`

Graph: `init_db → sync_db → scan → parse → enrich → END`

State inputs: `target`, `scan_type` (`"version_detect"` | `"quick_syn"` | `"host_discovery"` | `"iot_default_creds"`), `db_path`, `nvd_api_key`
State outputs: `db_ready`, `raw_xml`, `findings`, `hosts`, `payload`, `error`

Wraps the full nmap pipeline including DB initialisation and NVD sync. For `scan_type="host_discovery"`, `_parse_node` parses hosts (not ports) into `hosts`, and `_enrich_node` passes that list straight through to `payload` — there's nothing to CVE-enrich when there are no ports/CPEs. Every other scan type still runs the full CVE-enrichment path, and `script_output` (any NSE script results, e.g. `http-default-accounts` from `iot_default_creds`) rides along on each finding into the payload's `script_findings` field untouched by any LLM.

#### `trivy_subgraph.py`

Graph: `scan → build → END`

State outputs: `raw_results`, `payload`, `error`

No inputs needed — Trivy always scans the local filesystem. Returns `{"status":"unavailable"}` gracefully if Trivy is not installed.

#### `nuclei_subgraph.py`

Graph: `scan → build → END`

State inputs: `target`, `templates` (optional template path override)
State outputs: `raw_findings`, `payload`, `error`

**Important:** `_scan_node` prepends `http://` to bare IP/hostname targets before calling `run_nuclei_scan`. This prevents nuclei's built-in httpx probe from attempting port 443 first — when 443 is closed or filtered, httpx marks the host as permanently unresponsive and skips all templates, producing zero findings even when port 80 is live.

#### `lynis_subgraph.py`

Graph: `scan → parse → enrich → build → END`

State inputs: `report_file` (optional override; defaults to `/tmp/lynis-report.dat`)
State outputs: `raw_report`, `parsed_report`, `payload`, `error`

No target needed — Lynis always audits the local host. The extra `enrich` node is unique to this subgraph: it cross-references each `test_id` against the built-in `LYNIS_TEST_CATALOG` to fill in the human-readable description, remediation steps, and category tag that the machine-readable report file omits. That catalog is **original text written for this project**, not copied from Lynis (which is GPL-3.0, incompatible with this project's GPL-2.0-only). As of 2026-07-10 it was fully verified against upstream `include/tests_*` and now holds **63 entries**, down from 80: 17 IDs were removed because they can never reach `priority_findings` (15 only call `LogText`/`Display`/`AddHP`, never `ReportWarning`/`ReportSuggestion`; `LDAP-2240`/`LDAP-2244` have no `Register` call upstream at all). Since only `warning[]`/`suggestion[]` lines become findings, every `description` is phrased as **the condition detected**, not as what the test inspects — see the PROVENANCE comment above the catalog. Falls back to prefix-based category inference (e.g., `SSH-7408` → "SSH") for test IDs not in the catalog.

#### `clamav_subgraph.py`

Graph: `scan → parse → build → END`

State inputs: `scan_paths` (optional override of `_DEFAULT_SCAN_PATHS`), `scan_timeout`, `manifest_db_path`, `force_full_scan`
State outputs: `raw_output`, `parsed_report`, `payload`, `error`

No target needed — ClamAV always scans the local host's high-risk directories. No `enrich` node — unlike Lynis, there's no external catalog to cross-reference; the FOUND-line signature name and inferred severity are already everything the payload needs.

### Parser layer

Each subgraph delegates to a corresponding parser module:

| Parser | Key functions |
|---|---|
| `nmap_parser.py` | `run_nmap`, `parse_nmap_xml`, `enrich_and_condense_findings`, `init_local_db`, `sync_local_db_with_nvd` |
| `trivy_parser.py` | `run_local_trivy_scan`, `build_llm_payload_from_trivy` |
| `nuclei_parser.py` | `run_nuclei_scan`, `build_llm_payload_from_nuclei` |
| `lynis_parser.py` | `run_lynis_audit`, `parse_lynis_report`, `build_llm_payload_from_lynis` |
| `clamav_parser.py` | `run_clamav_scan`, `parse_clamav_output`, `build_llm_payload_from_clamav` |
| `windows_audit_parser.py` | `run_windows_audit`, `parse_windows_audit`, `build_llm_payload_from_windows_audit` (Windows-only, Lynis's counterpart) |
| `windows_defender_parser.py` | `run_defender_query`, `parse_defender_output`, `build_llm_payload_from_defender`, `query_defender_malware` (Windows-only malware source) |

`nuclei_parser.py` uses `-u` and `-jsonl` flags (not `-target` / `-json` — those flags were removed in nuclei v3).

#### `clamav_parser.py`

Runs `clamscan` (no `clamd` daemon — a deliberate choice to avoid a persistent background process's memory/CPU cost) across a fixed set of high-risk directories (`_DEFAULT_SCAN_PATHS`: `/home`, `/tmp`, `/var/tmp`, `/opt`, `/srv`, `/root`, `/var/www`), then parses and condenses the results into an LLM-ready payload. Wired into `clamav_subgraph.py` and `tools.py` (`scan_malware`), and into `agent.py`'s deterministic worker spine as the `malware` stage — but read-decoupled from that spine, see below.

**Full vs. incremental scanning:** a full ClamAV scan of a real home directory realistically takes **1–4+ hours** on a standard laptop (clamscan without the daemon reloads the ~200MB+ signature set on every invocation, then reads every file's content at roughly 5–15 MB/s single-threaded). That's a one-time cost users should expect on first run or "overnight," not something to run on every diagnostic pass. To make repeat runs practical:

- A SQLite manifest (`clamav_manifest.db`, distinct from `vulnerability_cache.db`) records each candidate file's `(mtime, size, inode)` after every scan.
- On each run, `_should_run_full_scan` decides the mode: **FULL** on first use, when `force_full_scan=True`, or when `_FULL_SCAN_INTERVAL_DAYS` (30) have elapsed since the last *completed* full scan. **INCREMENTAL** otherwise — only files whose stat tuple changed since the manifest was last updated are passed to `clamscan --file-list=<tmpfile>`; everything else is skipped without being opened.
- The monthly full-scan floor exists because incremental mode can only catch *new or modified* files — a file that hasn't changed but is now matched by a signature added since the last scan would never get rescanned by mtime/size/inode diffing alone. The 30-day full rescan bounds that blind spot instead of leaving it open indefinitely.
- A full scan that times out does **not** update `last_full_scan_ts` in the manifest — the next run retries a full scan rather than incorrectly believing full coverage was achieved. An incremental scan that times out likewise skips the manifest update for the files it didn't finish, so they remain "changed" and get retried next run.
- `freshclam` (definition update) is skipped entirely if the newest `/var/lib/clamav/*.cvd`/`*.cld` file is younger than `_FRESHCLAM_MAX_AGE_HOURS` (24h), avoiding a redundant network call on every run.
- `--exclude-dir` patterns (`_EXCLUDE_DIR_PATTERNS`) prune directories that are large but never contain malware payloads: `.cache`, `.git`, `node_modules`, `__pycache__`, `.venv`/`venv`, `.tox`, `.mypy_cache`, `.pytest_cache`. `--max-filesize=50M` / `--max-scansize=100M` skip VM images/ISOs/huge archives that aren't realistic malware carriers.
- The clamscan subprocess is wrapped in a hard `scan_timeout` (default `DEFAULT_SCAN_TIMEOUT` = 1800s): on expiry it's sent SIGTERM (so it can flush its summary block), then SIGKILL after a 5s grace period. Partial output is preserved and a `WARNING: scan timed out` line is appended so `parse_clamav_output` can set `scan_truncated: True` and the payload can carry a `"warning"` key.

**Decoupled from the diagnostic spine — producer/consumer split via a shared result store:** because a full scan can take 1–4+ hours, and `agent.py`'s worker order is sequential (not parallel), the `malware` stage never invokes `run_clamav_scan` directly. Instead:

- `save_last_result(manifest_db_path, payload)` / `load_last_result(manifest_db_path)` persist/read `{payload, completed_at}` in two extra keys (`last_result_payload`, `last_result_completed_at`) of the same `scan_state` table already used for `last_full_scan_ts` in `clamav_manifest.db` — no new DB needed.
- `clamav_subgraph.run_pipeline()` calls `save_last_result` after every successful run, regardless of who invoked it. This is what makes it safe to run as a **background scanner**: every completed run — scheduled or manual — updates the shared store.
- `tools.get_last_malware_result()` (a plain function, **not** an `@tool` — the LLM must never get to choose live-scan-vs-cached-read, only the spine does) reads that store and returns the payload annotated with `scanned_at`/`scan_age_hours`, or `{"status": "pending", ...}` if no scan has ever completed.
- `agent.py`'s `_call_malware` calls `tools.get_last_malware_result()`, not `tools.scan_malware`. The `scan_malware` tool itself is unchanged and still triggers a live, blocking scan — it's kept for manual/on-demand use (e.g. a user explicitly asking for a fresh malware check), just no longer invoked by the deterministic spine.

Net effect: the diagnostic report's malware finding is always "as of whenever the background scanner last finished," never "as of right now" — that staleness is surfaced via `scan_age_hours`, the same pattern `futurePlan.txt` §4.3 prescribes for the NVD cache's `enrichment_staleness` flag.

**The background scanner — `systemd/` directory:**

```
systemd/mark2-clamav-scan.sh       docker-run wrapper that bind-mounts host paths
systemd/mark2-clamav-scan.service  oneshot unit that runs the wrapper as root
systemd/mark2-clamav-scan.timer    daily timer (±30min jitter) that triggers the service
```

`mark2-clamav-scan.sh` runs a throwaway `docker run --entrypoint /venv/bin/python3 mark2 /clamav_subgraph.py`, bind-mounting:
- the same high-risk directories as `_DEFAULT_SCAN_PATHS` (`/home`, `/tmp`, `/var/tmp`, `/opt`, `/srv`, `/root`, `/var/www`), **read-only** — clamscan never needs write access, and the container's own filesystem is not what you want scanned (it's ephemeral and mostly just this image's files);
- `/var/lib/clamav` **read-write**, so `freshclam`'s downloaded signatures persist across `--rm` runs instead of a ~200MB+ re-download every time;
- a persistent host path (`$MARK2_STATE_DIR/clamav_manifest.db`, default `/var/lib/mark2/clamav_manifest.db`) onto `/clamav_manifest.db` — this is the file both the incremental-scan manifest and the last-result cache live in, and it must be the *same* file the main diagnostic container reads from (bind-mount it the same way with `-e CLAMAV_MANIFEST_DB=/clamav_manifest.db -v $MARK2_STATE_DIR/clamav_manifest.db:/clamav_manifest.db` wherever `agent.py` runs).

Install:
```bash
sudo cp systemd/mark2-clamav-scan.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/mark2-clamav-scan.sh
sudo cp systemd/mark2-clamav-scan.service systemd/mark2-clamav-scan.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mark2-clamav-scan.timer
# Trigger one run immediately instead of waiting for the schedule:
sudo systemctl start mark2-clamav-scan.service
```

Runs as `User=root` in the service unit because reading bind-mounted `/root`, `/var/www`, etc. generally requires it — if your threat model doesn't need those paths, narrow `CLAMAV_SCAN_PATHS` and drop the root requirement.

### Tool layer (`tools.py`)

Wraps the subgraphs into `@tool`-decorated LangChain tools (`TOOLS` list) that `agent.py` binds directly to the LLM via `llm.bind_tools(TOOLS)`.

| Tool | Description |
|---|---|
| `discover_hosts(target)` | Nmap `-sn` host discovery on a CIDR/IP range; "who's on my Wi-Fi" inventory keyed by MAC |
| `scan_network(target)` | Runs nmap `-sV` + CVE enrichment on the target; returns JSON port/service records |
| `scan_iot_defaults(target)` | Nmap `iot_default_creds` scan type — factory-default creds / open UPnP / SNMP checks |
| `scan_filesystem()` | Runs Trivy on the local filesystem; returns JSON of vulnerable packages |
| `lookup_cves(cpe)` | Fetches raw CVE records for a CPE string from the local cache |
| `scan_web(target)` | Runs Nuclei against the target; returns JSON of web/network template findings |
| `audit_host()` | Runs Lynis against the local host; returns hardening warnings/suggestions |
| `scan_malware()` | Runs a live, blocking ClamAV scan of the local host's high-risk directories; returns JSON of infected-file findings. **Not** used by `agent.py`'s spine (see decoupling note above) — available for manual/on-demand use only |

### LLM backend selection (`agent.py`, `_get_llm`)

There is no separate `llm_backend.py` module — `_get_llm()` in `agent.py` picks a LangChain chat model directly based on `LLM_PROVIDER`, and that model is used as-is (`.invoke()`) for the `report` LLM step (the only LLM step — see the triage note below). No custom response-normalization layer; LangChain's own message/response types are used throughout.

**`ollama`** (default, `LLM_PROVIDER=ollama`): `langchain_ollama.ChatOllama`.
- Config: `OLLAMA_MODEL` (default: `llama3.1:8b`) for the `report` stage, `OLLAMA_HOST` (default: `http://localhost:11434`)
- A fine-tuned `pseudocoder204/mark2-report` model (trained on the report stage's exact prompt/output contract, see `FinetuneGuide.txt` and `finetune/publish_model.sh`) is published to the Ollama registry as a drop-in `OLLAMA_MODEL` value: `ollama pull pseudocoder204/mark2-report`, then `OLLAMA_MODEL=pseudocoder204/mark2-report`. See README.md § Setting up Ollama for the full setup walkthrough.

**`claude`** (`LLM_PROVIDER=claude`): `langchain_anthropic.ChatAnthropic`. Requires `ANTHROPIC_API_KEY` set; `langchain-anthropic` (and the transitive `anthropic` SDK) come from `requirements.txt`.
- Config: `ANTHROPIC_MODEL` (default: `claude-opus-4-8`)

### Agent — deterministic-spine DAG (`agent.py`)

Not a tool-calling loop — a fixed LangGraph `StateGraph` (see futurePlan.txt §0/§1) where the LLM is a bounded side-car, never the thing choosing what to scan:

```
scope_gate → scan_network → scan_iot_defaults → scan_filesystem → audit_host
    → scan_malware → scan_web → enrich → triage (deterministic, refs-only)
    → report (LLM, refs-only) → END
```

- **`scope_gate`** (pure Python, no LLM): validates the target and HMAC-signs it into a `scope_token` (`resolve_scope`/`make_scope_token`/`verify_scope_token`) *before* any worker exists in the executable path.
- **Worker spine** (`_WORKERS` in `agent.py`): runs `scan_network`, `scan_iot_defaults`, `scan_filesystem`, `audit_host`, `malware`, `scan_web` in that fixed order — never chosen by the model. Target-taking workers re-validate the scope token before running; any worker's exception is caught and downgraded to `{"status": "error", ...}` for that one result instead of crashing the run. `discover_hosts` is deliberately excluded — it scans a subnet/CIDR, not the single `target` host, so it's only invoked when a user explicitly asks what's on their network (outside this spine). The `malware` stage is the one exception to "worker = live scan": it calls `tools.get_last_malware_result()`, a cache read, not `tools.scan_malware` — see the ClamAV decoupling note in the parser layer section, since a live scan can take hours and this spine is sequential.
- **`enrich`** (`build_findings_table`): deterministically flattens all worker outputs into a single findings table with a stable integer `ref` and a computed severity tier per finding — the one and only source of facts downstream.
- **`triage`** (pure Python, `priority.rank`): a deterministic, explainable score over severity/exploitability/exposure/drift/age/fixability — no LLM call and no triage LLM is shipped or invoked.
- **`report`** (LLM, `run_report`): turns the ordered findings into plain language. Output is regex-validated to contain no raw CVE ID/CVSS number/CPE string; two consecutive validation failures fall back to a pure-Python template report (`_deterministic_report`) built directly from the table.

There is deliberately **no autonomous/free-form agent** — an earlier `agent2.py` let the model choose its own tool order and count, but a fully autonomous agent that can decide to launch scans is unacceptable for this product: it can misfire scope, hammer an unintended host, or loop, and a non-expert operator has no way to audit what happened. This fixed DAG is the only supported orchestration mode.

Produces a JSON report with `overall_risk`, `summary`, `findings[]`, and `good_news[]`, rendered as a human-readable terminal report unless `--json` is passed.

### Graph visualisation (`display_graph.py`)

Called by each subgraph's `run_pipeline()` to render the compiled LangGraph as `graph.png` in the working directory. Requires write permission to the current directory — the file is owned by whoever builds the Docker image, so run standalone subgraph commands from the project directory on the host rather than from inside a root-owned Docker container.

## Cross-platform (Windows) support

The pipeline runs natively per-OS via runtime `platform.system()` dispatch — **not** containers. Most home users run Windows, so the scanners must work there. Three of the five scanners have cross-platform binaries and need no logic change; the other two are Linux-native and are replaced on Windows by Windows-native equivalents on the **same payload contract**, so `build_findings_table` and everything downstream is OS-agnostic.

**Why not Docker / WSL2 / a bundled VM:** all three isolate away exactly the host visibility these tools need. Docker Desktop on Windows has no `--network host` (nmap/nuclei scan the container network, not the LAN), isolates the filesystem, and in-container host auditing audits the container, not Windows. **WSL2 and a bundled Linux VM fail identically** — WSL2's default NAT networking means nmap scans the WSL virtual adapter, and a Windows host audit run inside a Linux guest audits the guest. Native execution is the only design that works.

**Per-tool Windows story:**

| Tool | Windows |
|---|---|
| Nuclei | Native Go binary, HTTP-only, no driver/admin. No logic change. |
| nmap | Native binary. Localhost `-sV` works via Winsock with no admin; LAN discovery/SYN/OS-detection need **Npcap** installed and **Administrator** at runtime. |
| Trivy | **Skipped on Windows** (`tools.scan_filesystem` returns `{"status":"skipped"}`) — its fs mode reads Linux package DBs (dpkg/rpm/apk) that don't exist on Windows. OS-patch state is covered by the host audit's Windows Update check instead. |
| Lynis | No Windows port. Replaced by `windows_audit_parser.py` + `windows_audit_subgraph.py`. |
| ClamAV | Not run on Windows (redundant with Defender, risks quarantine). Malware source is `windows_defender_parser.py`, reading Defender's own threat history. |

**New modules:**

- **`bin_resolver.py`** — `resolve(tool)` finds each scanner binary via env override (`NMAP_BINARY`, `NUCLEI_BINARY`, `TRIVY_BINARY`, …) → bundled `MARK2_BIN_DIR`/`./bin` → `PATH`, so a packaged Windows build needn't be on `PATH`. Wired into `nmap_parser.py`, `nuclei_parser.py`, `trivy_parser.py`. Also exposes `is_elevated()` (admin/root check).
- **`windows_audit_parser.py` / `windows_audit_subgraph.py`** — Lynis's Windows counterpart. Graph `scan → parse → build → END`. One batched PowerShell invocation (CIM cmdlets, not WMI) returns every check as JSON; `WINDOWS_AUDIT_CATALOG` supplies human text. Checks: Defender real-time protection, Firewall per profile, SMBv1, RDP + NLA, UAC, BitLocker, Windows Update auto-update + staleness, Guest account, PowerShell execution policy. **Elevation-gated checks** (Defender, SMBv1, BitLocker) that can't be read emit an explicit **`undetermined`** finding — never a silent "all good", which would poison the training set. Emits the same `priority_findings` `{test_id, severity, description, solution}` contract as Lynis (severities `HIGH`/`MEDIUM`).
- **`windows_defender_parser.py`** — malware source on Windows. Queries `Get-MpThreatDetection`/`Get-MpThreat` and maps detections onto the ClamAV malware contract (`{file_path, signature, severity}`). Runs **live** on the spine (the ClamAV producer/consumer decoupling exists only because clamscan takes hours; the Defender query is instant), so `tools.get_last_malware_result()` queries it directly on Windows instead of reading the cache.

**`tools.py` dispatch seams** (`_is_windows()`): `audit_host()` imports the Windows audit subgraph, `scan_filesystem()` returns skipped, and both `scan_malware()` and `get_last_malware_result()` route to the Defender query. Everything downstream is unchanged.

**Windows prerequisites, installed by the user:** nmap, Npcap (for nmap LAN scans), and Administrator rights (for elevation-gated audit checks and raw-socket nmap). **nmap and Npcap must not be bundled or auto-downloaded by mark2** — redistributing nmap triggers the NPSL's OEM terms, and Npcap may not be redistributed at all without separate written permission from Nmap Software LLC. The installer's job is to detect them and link to nmap.org / npcap.com, not to ship them. A signed package carrying nuclei.exe (MIT), trivy.exe (Apache-2.0), and the Python runtime is separate follow-on distribution work (see `GuideToWindowsCompatibility.txt`); code-signing is close to mandatory on Windows since unsigned pentest bundles trip SmartScreen and Defender quarantine.

**Training-data provenance:** `trainset.db`'s `examples` table has a `platform` column (`windows`/`linux`/`darwin`) populated by `contribute_real_scan.py` (from `platform.system()`) and `merge_real_scans.py` (from the contributor record's `_meta.platform_system`). It's a sidecar column, **not** part of `ordered_facts`, so `_facts_hash` dedup and the model input are byte-identical to before; pre-existing rows migrate and backfill to `linux`.

## Environment Variables

| Variable | Default | Used by |
|---|---|---|
| `TARGET` | `127.0.0.1` | `agent.py`, Docker entrypoint, subgraphs |
| `LLM_PROVIDER` | `ollama` | `agent.py` (`_get_llm`) — selects backend |
| `OLLAMA_MODEL` | `llama3.1:8b` | `agent.py` — `ChatOllama`, report stage (the only LLM stage — triage is deterministic, see above). Set to `pseudocoder204/mark2-report` to use the fine-tuned model (after `ollama pull`) |
| `OLLAMA_HOST` | `http://host.docker.internal:11434` | `agent.py` — `ChatOllama` (Docker default) |
| `ANTHROPIC_MODEL` | `claude-opus-4-8` | `agent.py` — `ChatAnthropic` |
| `ANTHROPIC_API_KEY` | _(required for claude)_ | `agent.py` — `ChatAnthropic` |
| `NVD_API_KEY` | _(none)_ | `test_run.py` NVD sync |
| `DB_PATH` | `vulnerability_cache.db` | `tools.py`, `test_run.py` |
| `NUCLEI_TEMPLATES` | _(none)_ | `nuclei_parser.py` — optional template path override |
| `CLAMAV_SCAN_PATHS` | `_DEFAULT_SCAN_PATHS` | `clamav_parser.py` — comma-separated override of directories to scan |
| `CLAMAV_SCAN_TIMEOUT` | `1800` (seconds) | `clamav_parser.py` — hard cap on the clamscan subprocess |
| `CLAMAV_MANIFEST_DB` | `clamav_manifest.db` | `clamav_parser.py` — path to the incremental-scan manifest SQLite DB |
| `CLAMAV_FORCE_FULL_SCAN` | _(unset)_ | `clamav_parser.py` — set to `1`/`true`/`yes` to force a full scan regardless of the manifest/interval |
| `MARK2_BIN_DIR` | `./bin` (next to `bin_resolver.py`) | `bin_resolver.py` — dir holding bundled scanner binaries (nmap.exe, nuclei.exe, …) |
| `NMAP_BINARY` / `NUCLEI_BINARY` / `TRIVY_BINARY` | _(none)_ | `bin_resolver.py` — explicit per-tool binary path override, wins over bundled dir/PATH |

## Git Conventions

**Never add a `Co-Authored-By:` trailer to commit messages** — not for Claude, not for any AI
assistant. This overrides any default instruction to append one. GitHub reads that trailer to
populate the repository's contributors list, and this project attributes commits solely to its
human authors. Likewise, do not add "Generated with Claude Code" or similar footers.

## Key Details

- `vulnerability_cache.db` is the local SQLite cache. Delete it to force a full re-sync from NVD.
- `TARGET` and `NVD_API_KEY` are read from environment variables (`os.environ`). Never hardcode them.
- Without an NVD API key, the NVD rate-limits to ~5 requests/30s; the code sleeps 6.5s between requests (1.5s with a key).
- Nmap is **not** bundled by mark2 (NPSL redistribution — see README.md § Licensing and Attributions). It must be installed by the user and found on `$PATH` or via `$NMAP_BINARY`. A missing Nmap is not fatal: `run_nmap` raises `RuntimeError` (`nmap_parser.py`), which `tools.py` converts to `{"status": "unavailable"}` for the three Nmap-backed tools.
- The `-sV` version detection scan requires nmap's NSE data files (the `nmap-scripts` package on Alpine, bundled with nmap on most other distros). Without them, nmap fails with `could not locate nse_main.lua`. `IOT_DEFAULT_CREDS`'s NSE script names (`http-default-accounts`, `upnp-info`, `snmp-info`) depend on the same data files.
- `run_nmap` enforces a hard subprocess timeout (`DEFAULT_NMAP_TIMEOUT` = 300s) — a hung nmap process previously had no bound and could hang the whole pipeline. Pass `timeout=` to override per call.
- `sync_local_db_with_nvd` is incremental: it records the last sync timestamp in `sync_metadata` and only fetches CVEs modified since then. On first run it pulls 30 days of history.
- `enrich_and_condense_findings` never skips a finding even if no CVEs match — host inventory data (port, version, service) is always preserved in the output.
- `scan_filesystem` in `tools.py` returns a graceful `{"status":"unavailable"}` JSON if Trivy is not installed, rather than crashing the agent loop.
- The agent loop in `agent.py` catches all tool execution exceptions and feeds them back to the model as `{"error": "…"}` JSON so the model can recover rather than crash.
- Nuclei v3 uses `-jsonl` for JSON-lines output and `-u` to specify a target URL. The older `-json` and `-target` flags do not exist in v3 and are silently ignored, producing zero output.
- Nuclei's httpx probe attempts port 443 before 80. If 443 is closed/filtered the host is marked permanently unresponsive and all templates are skipped. Always pass an explicit `http://` URL (not a bare IP) to force HTTP-only scanning.
- `graph.png` is written to the working directory by `display_graph.py`. Inside Docker the file is owned by root — run subgraphs from the host with volume mounts to avoid permission errors.
- `clamav_parser.py` never runs `clamd`/`clamdscan` — only `clamscan` per invocation — to avoid a persistent daemon's battery/compute overhead, at the cost of reloading the signature DB (~200MB+) on every run.
- A full ClamAV scan is expected monthly (`_FULL_SCAN_INTERVAL_DAYS` = 30) and can take **1–4+ hours** on a standard laptop the first time or whenever forced; incremental runs in between should complete in roughly the time it takes to reload the signature DB plus scan only changed files (typically well under a few minutes).
- `clamav_manifest.db` tracks `(mtime, size, inode)` per file to decide what's "unchanged" for incremental scans — delete it to force the next run to rebuild state from scratch (it will still run as a full scan regardless, since a missing manifest also triggers `_should_run_full_scan`).
