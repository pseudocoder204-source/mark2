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
explain those findings rather than choosing what to scan. See `CLAUDE.md` for the full
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

## Install

One command. It installs the scanners, the Python dependencies, Ollama and the report
model, and the CVE cache — then puts a `pulser` launcher on your `PATH`.

**Linux / macOS:**

```bash
curl -fsSL https://raw.githubusercontent.com/pseudocoder204-source/Pulser/main/install.sh | bash
```

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/pseudocoder204-source/Pulser/main/install.ps1 | iex
```

Then run a diagnostic:

```bash
pulser                          # scan this machine (127.0.0.1)
pulser --target 192.168.1.1     # scan something else on your network
```

That's the whole setup. You don't need to clone anything first, make a virtualenv, export
any environment variable, or download the CVE cache by hand — the installer does all of it.
Re-running the same command later **upgrades** an existing install instead of reinstalling it.

**It will take a while, and most of that is two big downloads:** the report model (multi-GB,
from Ollama) and the CVE cache (~126 MB compressed, ~3.2 GB unpacked). Both run in the
background while the scanners install, so they overlap rather than queue. Everything else is
quick.

### "You want me to pipe a script from the internet into my shell?"

Fair — and doubly fair for a security tool. Read it first, then run the identical thing from
a clone:

```bash
git clone https://github.com/pseudocoder204-source/Pulser.git
cd Pulser
less install.sh          # or install.ps1 on Windows — read it
./install.sh             # byte-for-byte the same installer the curl form runs
```

The installer also prints exactly what it's about to do — every directory it will write to,
every tool it will install — and waits for you to confirm before touching anything.

### Installer options

| Flag (Linux/macOS) | Flag (Windows) | What it does |
|---|---|---|
| `--claude` | `-Claude` | You're using the Anthropic backend: skip Ollama and the model pull entirely |
| `--skip-cache` | `-SkipCache` | Skip the ~3.2 GB CVE cache (CVE enrichment degrades; everything else runs) |
| `--model NAME` | `-Model NAME` | Pull a different Ollama model (default: `pseudocoder204/mark2-report`) |
| `--dir PATH` | `-Dir PATH` | Where to install (default: `~/.local/share/pulser`, `%LOCALAPPDATA%\Pulser` on Windows) |
| `--skip-shim` | `-SkipShim` | Don't put the `pulser` launcher on your `PATH` |
| `--yes` | `-Yes` | Don't prompt for confirmation |

Pass them through the piped form like this:

```bash
curl -fsSL https://raw.githubusercontent.com/pseudocoder204-source/Pulser/main/install.sh | bash -s -- --claude
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/pseudocoder204-source/Pulser/main/install.ps1))) -Claude
```

### What the installer deliberately will *not* do

- **Bundle any scanner binary.** Every tool comes from your OS package manager or the tool's
  own upstream release (nmap from your distro/`winget`, Trivy and Nuclei from their official
  installers), so Pulser redistributes nothing. See
  [Licensing and Attributions](#license--attributions).
- **Install Npcap** (Windows LAN scans) — its license forbids redistribution, so `install.ps1`
  only detects it and links to [npcap.com](https://npcap.com/#download). You install it yourself.
- **Elevate.** On Windows, run Pulser as Administrator for the elevation-gated audit checks
  and raw-socket nmap scans; the installer won't do that for you.

> **macOS:** while `brew` installs Lynis, you may see a system prompt like *"Terminal would
> like to access files in your Documents folder."* That's macOS's own privacy protection
> (TCC) reacting to Lynis's post-install step touching your home directory — the installer
> itself never runs Lynis, it only installs the binary. It's safe to click **Allow**. You may
> see a similar prompt again later for real, when you actually run a diagnostic, because
> Lynis's `audit_host` stage genuinely scans your filesystem for hardening checks — so that
> one's expected too.

## Requirements

The installer handles all of these except Python itself, but for reference:

- Python 3.10+
- The scanner binaries for your OS (see [Install the scanners](CONTRIBUTING_SCAN_DATA.md#install-the-scanners))
- **[Nmap](https://nmap.org/download.html).** Pulser does not ship Nmap for licensing reasons
  (see [Licensing and Attributions](#license--attributions)); the installer installs it
  from your package manager. If you install it by hand, make sure it's on `$PATH` — or point
  `NMAP_BINARY` at it. On Windows, LAN scans additionally need
  [Npcap](https://npcap.com/#download), which you must install yourself.
- An LLM backend: a local [Ollama](https://ollama.com) model (default) **or** an Anthropic API key

Without Nmap, Pulser still runs: the port/service, CVE-enrichment, and IoT default-credential
stages report `{"status": "unavailable"}` and the remaining scanners (Trivy, Nuclei, Lynis,
ClamAV) proceed normally. You lose the network findings, not the run.

## Manual install, step by step

Prefer to do it yourself, or want to know exactly what the installer did? This is the same
sequence, by hand.

**1. Get the code.**

```bash
git clone https://github.com/pseudocoder204-source/Pulser.git
cd Pulser
```

(Prefer SSH? `git clone git@github.com:pseudocoder204-source/Pulser.git` works the same way.)
Every command below assumes you're inside that `Pulser/` directory.

**2. Install the scanners** — nmap, ClamAV, Lynis, Trivy, and Nuclei on Linux/macOS; only
nmap and Nuclei on Windows (Lynis, ClamAV, and Trivy aren't used there — see
[Cross-platform support](CLAUDE.md#cross-platform-windows-support)). Per-tool commands are in
[Install the scanners](CONTRIBUTING_SCAN_DATA.md#install-the-scanners).

**3. Create a virtualenv and install the Python dependencies.** Use a venv — on most current
Linux distros a bare `pip install` fails outright with `externally-managed-environment`
(PEP 668).

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**4. Set up Ollama.** Pulser has a single LLM stage — **report**, which writes the
plain-English report. Triage (ordering findings by priority) is deterministic Python
(`priority.rank`), not an LLM call, so no LLM is invoked for it.

Install Ollama from [ollama.com/download](https://ollama.com/download) and make sure it's
running (`ollama serve`, or just launch the app — it starts a background service
automatically on macOS/Windows). Then pull a model:

```bash
ollama pull pseudocoder204/mark2-report     # the default
```

`pseudocoder204/mark2-report` is fine-tuned on the report stage's actual prompt/output
contract and produces better home-user-facing reports than the stock model at the same size.
It's what `agent.py` uses unless you say otherwise. To use a stock base model instead, pull it
and point `OLLAMA_MODEL` at it:

```bash
ollama pull llama3.1:8b
export OLLAMA_MODEL=llama3.1:8b
```

Using Anthropic instead of a local model? Skip this step entirely and set `LLM_PROVIDER=claude`
and `ANTHROPIC_API_KEY` when you run.

**5. Download the CVE cache.** CVE enrichment reads a local SQLite cache,
`vulnerability_cache.db`. It's ~3.2 GB, so it isn't in the repo — grab the compressed copy
(~126 MB) and unpack it into the repo root:

```bash
curl -fL -o vulnerability_cache.db.gz \
  https://github.com/pseudocoder204-source/Pulser/releases/download/v0.1.0-data/vulnerability_cache.db.gz
gunzip -c vulnerability_cache.db.gz > vulnerability_cache.db
```

On Windows, see [The CVE cache](#the-cve-cache) below for the PowerShell equivalent (`gunzip`
isn't available there by default).

**6. Run it.**

```bash
python3 agent.py --target 127.0.0.1
```

## Running a diagnostic

If you used the installer, `pulser` is on your `PATH` and works from any directory — no
`cd` into the repo, no virtualenv to activate:

```bash
pulser                          # scan this machine (default target 127.0.0.1)
pulser --target 192.168.1.1     # scan something else
pulser --json > report.json     # machine-readable output
```

`pulser` is a thin launcher around `agent.py` and forwards every argument to it, so anything
below works with either spelling. From a manual install, run `python3 agent.py` (Windows:
`python agent.py`) from inside the repo with your venv active.

The report stage uses `pseudocoder204/mark2-report` by default — the model the installer
pulls. To point it at a different one:

**Linux / macOS:**

```bash
# Use a stock base model for the report stage instead (after `ollama pull llama3.1:8b`)
OLLAMA_MODEL=llama3.1:8b pulser --target IP

# Use Anthropic instead of Ollama
LLM_PROVIDER=claude ANTHROPIC_API_KEY=sk-... pulser
```

**Windows** (PowerShell — inline `VAR=value` prefixes like the bash examples above aren't
valid syntax; set the environment variable first, then run):

```powershell
# Use a stock base model for the report stage instead (after `ollama pull llama3.1:8b`)
$env:OLLAMA_MODEL = "llama3.1:8b"
pulser --target IP

# Use Anthropic instead of Ollama
$env:LLM_PROVIDER = "claude"
$env:ANTHROPIC_API_KEY = "sk-..."
pulser
```

Both the LLM-generated report and everything under it are produced either way — `--json`
only changes how the *same* output is printed. Without it, the report is rendered as
human-readable text for a person to read in the terminal. With it, the identical report
object (`overall_risk`, `summary`, `findings[]`, `good_news[]`) is printed as raw JSON
instead, e.g. `pulser --json > report.json`. Only pass `--json` when the caller
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

CVE enrichment reads a local SQLite cache, `vulnerability_cache.db`. It's **~3.2 GB**, so it
is **not** in the repo.

**The installer downloads and unpacks this for you** — you only need this section if you
installed manually, passed `--skip-cache`, or want to refresh the cache by hand. Grab the
compressed copy (~126 MB) from the Releases page and unpack it into the repo root:

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
[Licensing and Attributions](#license--attributions)), so the network-scan stages
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
package names), **never** file contents, credentials, or logs, and it makes you review
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
