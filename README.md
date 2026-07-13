# Pulser

[![License: GPL v2](https://img.shields.io/badge/license-GPL--2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/pseudocoder204-source/Pulser?style=social)](https://github.com/pseudocoder204-source/Pulser/stargazers)

⭐ Star it if this is useful — helps me a lot as a 15-year-old student dev.

A multi-scanner home-network security pipeline. It combines several open-source
scanners into one agentic system that produces a **plain-English** security report for
non-technical users:

| Scanner | What it covers |
|---|---|
| **Nmap** | Open ports, service/version detection, CVE enrichment, IoT default-credential checks |
| **Trivy** | Local filesystem package vulnerabilities (Linux/macOS) |
| **Nuclei** | Web/network template-based vulnerability checks |
| **Lynis** / **Windows audit** | Host hardening audit (Linux/macOS via Lynis, Windows via a native PowerShell audit) |
| **ClamAV** / **Windows Defender** | Malware scan (ClamAV on Linux/macOS, Defender threat history on Windows) |

Each scanner has a parser and a self-contained [LangGraph](https://github.com/langchain-ai/langgraph)
subgraph. A deterministic orchestration layer (`agent.py`) runs the scanners in a fixed
order, flattens all findings into a single table, and uses an LLM **only** to reorder and
explain those findings — never to choose what to scan. See `CLAUDE.md` for the full
architecture.

![Pulser demo](docs/demo.gif)

## Why I built this

I'm a 15-year-old self-taught developer, and this is my passion project. Small business owners and everyday people want to know their devices and network are safe, but there's no single tool that just tells you, in plain English, what's actually wrong and how to fix it. I'm not trying to replace Windows Defender or the pile of antivirus software already out there. I built Pulser to be a quick "health checkup" for your network and devices: run it, and it tells you exactly what it found and what to do about it, so you get peace of mind without needing to be a security expert.

## Example output

```
==============================================================
  SECURITY DIAGNOSTIC REPORT   🔴 CRITICAL RISK
==============================================================

The scan found 12 issue(s) that need attention out of 14 item(s) reviewed.

── ISSUES FOUND (12) ──────────────────────────────────────

  1. 🔴 [CRITICAL]  SSH login could leak information about your smartcard setup
     Affected       : Port 22 — ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
     What it means  : This device's remote-login software (SSH) has a bug that could let someone learn more about your smartcard setup than they should.
     Why it matters : This is worth fixing soon to avoid leaking information that shouldn't be public.
     How to fix:
       1. Update the SSH software to the latest version.
       2. If you don't use this feature, consider turning it off in your SSH client settings.
     References:
       • https://access.redhat.com/errata/RHSA-2024:4312
       • https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AN2UDTXEUSKFIOIYMV6JNI5VSBMYZOFT/
 ...
```

## Get the code

Clone the repository, then move into the new directory it creates before running anything
else in this guide:

```bash
git clone https://github.com/pseudocoder204-source/Pulser.git
cd Pulser
```

(Prefer SSH? `git clone git@github.com:pseudocoder204-source/Pulser.git` works the same
way.) Every command below — `install.sh`/`install.ps1`, `pip install`, `python3 agent.py`,
`docker build` — assumes you're running it from inside that `Pulser/` directory.

## Requirements

- Python 3.10+
- The scanner binaries for your OS (see [Install the scanners](CONTRIBUTING_SCAN_DATA.md#install-the-scanners))
- **[Nmap](https://nmap.org/download.html), installed by you.** Pulser does not ship Nmap
  for licensing reasons (see [Licensing and Attributions](#licensing-and-attributions)).
  Install it from your package manager (`apt install nmap`, `brew install nmap`,
  `apk add nmap nmap-scripts`) or nmap.org, and make sure it is on `$PATH` — or point
  `NMAP_BINARY` at it. On Windows, LAN scans additionally need
  [Npcap](https://npcap.com/#download), also installed by you.
- An LLM backend: a local [Ollama](https://ollama.com) model (default, see
  [Setting up Ollama](#setting-up-ollama) below) **or** an Anthropic API key

Without Nmap, Pulser still runs: the port/service, CVE-enrichment, and IoT default-credential
stages report `{"status": "unavailable"}` and the remaining scanners (Trivy, Nuclei, Lynis,
ClamAV) proceed normally. You lose the network findings, not the run.

## Quick install

An installer script provisions the scanner tools and the Python dependencies in one shot. It
**installs**, never bundles — every tool comes from your OS package manager or the tool's own
upstream release (nmap from your distro/`winget`, Trivy and Nuclei from their official
installers), so Pulser redistributes nothing. It's idempotent: anything already present is
skipped.

**Linux / macOS:**

```bash
python3 -m venv .venv && source .venv/bin/activate   # recommended
./install.sh
```

> **macOS:** while `brew install`s Lynis, you may see a system prompt like *"Terminal would
> like to access files in your Documents folder."* That's macOS's own privacy protection
> (TCC) reacting to Lynis's post-install step touching your home directory — `install.sh`
> itself never runs Lynis, it only installs the binary. It's safe to click **Allow**. You may
> see a similar prompt again later for real, when you actually run a diagnostic — Lynis's
> `audit_host` stage genuinely scans your filesystem for hardening checks, so that one's
> expected too.

**Windows** (PowerShell):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1   # recommended
.\install.ps1
```

The script prints a summary of what it installed and what you must still do yourself. It
deliberately does **not** touch three things:

- **Ollama itself, or any Ollama model** — the script only checks whether `ollama` is on
  `PATH` and tells you where to get it if not. It never pulls a model: `llama3.1:8b` and the
  fine-tuned `mark2-report` are both multi-gigabyte downloads, and which one you want (or
  whether you're using Claude instead) is your call, not something worth blocking `install.sh`
  on. See [Setting up Ollama](#setting-up-ollama) below.
- **Npcap** (Windows LAN scans) — its license forbids redistribution, so `install.ps1` only
  detects it and links to [npcap.com](https://npcap.com/#download); you install it yourself.
- **The CVE cache** (~3.2 GB) — download it from Releases (see [The CVE cache](#the-cve-cache)).

Prefer to do it by hand? Everything the script does is spelled out below — install the
scanners ([Install the scanners](CONTRIBUTING_SCAN_DATA.md#install-the-scanners)), then:

```bash
pip install -r requirements.txt
```

## Setting up Ollama

Pulser has a single LLM stage: **report** (writes the plain-English report). Triage
(ordering findings by priority) is deterministic Python, not an LLM call — three tuned
triage models were evaluated and none beat the plain severity-tier+CVSS ordering on
held-out data, so no LLM is invoked for it (see `notes/FinetuneGuideTriage.txt` Phase 5).

Neither [Quick install](#quick-install) nor `install.sh`/`install.ps1` pulls an Ollama model
for you — both are multi-gigabyte downloads, and picking one is up to you, not something to
wait on during setup. Pick one of these:

- **`pseudocoder204/mark2-report`** (recommended) — a fine-tuned model trained on the report
  stage's actual prompt/output contract; produces better home-user-facing reports than the
  stock model at the same size.
- **`llama3.1:8b`** (stock) — pick this if you'd rather stay on an untuned, more widely-used
  base model, or if you're already using it for something else and don't want a second
  multi-GB pull.

1. **Install Ollama** — see [ollama.com/download](https://ollama.com/download) for
   macOS/Windows/Linux instructions. Make sure it's running (`ollama serve`, or just
   launch the app — it starts a background service automatically on macOS/Windows).

2. **Pull a model** (pick one from above):

   ```bash
   ollama pull "pseudocoder204/mark2-report"        # recommended
   # or
   ollama pull llama3.1:8b                          # stock
   ```

3. **Point the report stage at it** (only needed for `mark2-report` — `llama3.1:8b` is
   already the default if `OLLAMA_MODEL` is unset):

   ```bash
   export OLLAMA_MODEL=pseudocoder204/mark2-report
   ```

## Running a diagnostic

**Linux / macOS:**

```bash
# Scan your own machine (default target 127.0.0.1) with the default Ollama backend
# (stock llama3.1:8b for the report stage)
python3 agent.py [--target IP]

# Use the fine-tuned mark2-report model for the report stage instead of stock
# llama3.1:8b (after pulling it — see [Setting up Ollama](#setting-up-ollama)):
OLLAMA_MODEL=pseudocoder204/mark2-report python3 agent.py [--target IP]

# Use Anthropic instead of Ollama
LLM_PROVIDER=claude ANTHROPIC_API_KEY=sk-... python3 agent.py
```

**Windows** (PowerShell — inline `VAR=value` prefixes like the bash examples above aren't
valid syntax; set the environment variable first, then run the script):

```powershell
# Scan your own machine (default target 127.0.0.1) with the default Ollama backend
# (stock llama3.1:8b for the report stage)
python agent.py --target IP

# Use the fine-tuned mark2-report model for the report stage instead of stock
# llama3.1:8b (after pulling it — see [Setting up Ollama](#setting-up-ollama)):
$env:OLLAMA_MODEL = "pseudocoder204/mark2-report"
python agent.py --target IP

# Use Anthropic instead of Ollama
$env:LLM_PROVIDER = "claude"
$env:ANTHROPIC_API_KEY = "sk-..."
python agent.py
```

Both the LLM-generated report and everything under it are produced either way — `--json`
only changes how the *same* output is printed. Without it, the report is rendered as
human-readable text for a person to read in the terminal. With it, the identical report
object (`overall_risk`, `summary`, `findings[]`, `good_news[]`) is printed as raw JSON
instead, e.g. `python3 agent.py --json > report.json`. Only pass `--json` when the caller
wants machine-readable output (piping into another program) rather than a human-readable
report — it's not needed for normal interactive use, which is why it's omitted from the
examples above.

> **First run:** if `vulnerability_cache.db` needs a sync against the live NVD API (see
> [The CVE cache](#the-cve-cache) below), the first `agent.py` run can take a while —
> the NVD rate-limits requests, so the sync sleeps between calls (6.5s without an
> `NVD_API_KEY`, 1.5s with one). This is expected; subsequent runs sync incrementally
> and are fast.

You can also run any single scanner's subgraph standalone:

```bash
python3 nmap_subgraph.py [target]
python3 nuclei_subgraph.py [target]
python3 trivy_subgraph.py
python3 lynis_subgraph.py
python3 clamav_subgraph.py
```

### The CVE cache

CVE enrichment reads a local SQLite cache, `vulnerability_cache.db`. It's **~3.2 GB**, so
it is **not** in the repo — download the compressed copy (~126 MB) from the Releases page
and unpack it into the repo root:

**Linux / macOS:**

```bash
gunzip -c vulnerability_cache.db.gz > vulnerability_cache.db
```

**Windows** (PowerShell — `gunzip`/`gzip` aren't available by default; this uses .NET's
built-in `GzipStream` so no extra tools are required):

```powershell
# Run from the repo root with vulnerability_cache.db.gz already in this folder
# (move it here from Downloads first if that's where your browser saved it).
if (-not (Test-Path .\vulnerability_cache.db.gz)) {
    throw "vulnerability_cache.db.gz not found in $(Get-Location) - move/download it here first."
}
# Windows PowerShell 5.1 doesn't load System.IO.Compression by default (PowerShell Core does) -
# without this, GzipStream fails with "Cannot find type [System.IO.Compression.GzipStream]".
Add-Type -AssemblyName System.IO.Compression
$in  = [System.IO.File]::OpenRead((Resolve-Path .\vulnerability_cache.db.gz))
# Use a path built from PowerShell's own location, not a bare relative string -
# .NET's Create()/OpenRead() resolve relative paths against Environment.CurrentDirectory,
# which can silently differ from PowerShell's $PWD and send/deny the file elsewhere.
$out = [System.IO.File]::Create((Join-Path (Get-Location) "vulnerability_cache.db"))
$gz  = New-Object System.IO.Compression.GzipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
$gz.CopyTo($out)
$gz.Close(); $out.Close(); $in.Close()
```

Without it, the pipeline creates an empty cache and syncs ~30 days of recent CVEs from NVD
on first run (slower, less complete). Set `NVD_API_KEY` for higher NVD rate limits.

The release asset is re-synced from NVD and re-uploaded every Monday by
`.github/workflows/refresh-cve-cache.yml`, so a fresh download is never more than a week
behind and the first run only has to catch up a few days.

## Docker

```bash
docker build -t mark2 .
docker run --rm --network host -e TARGET=192.168.1.1 mark2
```

The default image **does not contain Nmap** (see
[Licensing and Attributions](#licensing-and-attributions)), so the network-scan stages
report `unavailable`. To get them back, build an image with Nmap included **for your own
local use**:

```bash
docker build --build-arg INSTALL_NMAP=true -t mark2 .
```

An image built that way must not be pushed to a registry or otherwise redistributed —
that would require an [Nmap OEM license](https://nmap.org/oem/). Building it for yourself
is not redistribution.

`--network host` is needed on Linux so Nmap/Nuclei can reach hosts on your LAN. See
`CLAUDE.md` for the full set of environment variables and volume mounts (CVE cache,
ClamAV manifest, etc.).

## Contributing scan data

This project is collecting **real, anonymized** scan findings to improve the report
model. If you'd like to help, run one scan on a machine you own and submit a single
small JSON file via this [Google Form](https://docs.google.com/forms/d/e/1FAIpQLSfQIl3y1xTYoaWhLFSuIMLQh6TmnucyQUBe1x5bK01qFlD1zw/viewform).
It records only a findings summary (ports, versions, CVE IDs, hardening test IDs,
package names) — **never** file contents, credentials, or logs, and it makes you review
and consent before scanning.

👉 **See [CONTRIBUTING_SCAN_DATA.md](CONTRIBUTING_SCAN_DATA.md) for the full walkthrough.**

## Team

**Aditya Soni — Founder, Sole Architect & Engineer.** I conceived this project and built
the entire codebase from scratch myself. 

**Andrew Macedo — Outreach & Community Partner.** Andrew, my high school friend handles outreach and the
non-technical side of the project. While I am actively involved here as well, having him on my team
frees up more of my time to spend on engineering and product design. 

## License & attributions

Pulser is licensed under the **GNU General Public License v2** (see [`LICENSE`](LICENSE)).

Pulser is just an orchestration layer: **it ships no scanner binaries.** You install the
scanners yourself, and Pulser runs each as a separate program and reads its output — it never
contains, links against, or modifies their code. So each scanner stays under its own license,
and using Pulser asks nothing of you beyond installing the tools. Credit for the actual scanning
belongs to their authors:

| Tool | Author / Maintainer | License | Role in Pulser |
|---|---|---|---|
| [Nmap](https://nmap.org) | Nmap Software LLC (Gordon "Fyodor" Lyon) | [Nmap Public Source License](https://nmap.org/npsl/) (NPSL, GPLv2-derived) | Port/service discovery, version detection, IoT default-credential NSE checks |
| [ClamAV](https://www.clamav.net) | Cisco Systems, Inc. / Talos | [GPL-2.0](https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt) | Malware scanning (`clamscan`) |
| [Lynis](https://cisofy.com/lynis/) | CISOfy / Michael Boelen | [GPL-3.0](https://github.com/CISOfy/lynis/blob/master/LICENSE) | Host hardening audit |
| [Trivy](https://trivy.dev) | Aqua Security | [Apache-2.0](https://github.com/aquasecurity/trivy/blob/main/LICENSE) | Filesystem package vulnerability scanning |
| [Nuclei](https://projectdiscovery.io) | ProjectDiscovery, Inc. | [MIT](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md) | Template-based web/network vulnerability checks |

Each tool's full license text is kept in [`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/).
CVE data comes from the [NVD](https://nvd.nist.gov/), which is public domain (NIST does not
endorse this project).

Two things worth knowing: Pulser does **not** bundle [Nmap](https://nmap.org/download.html)
(install it yourself — a deliberate licensing choice), and you should only scan systems you own
or are authorized to test.

Packaging Pulser commercially, hosting it as a service, or bundling any scanner binary? The full
license analysis — NPSL/OEM, Docker source-offer, Npcap, hosted-deployment notices — lives in
[LICENSING.md](LICENSING.md).
