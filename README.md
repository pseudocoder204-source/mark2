# mark2

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

## Requirements

- Python 3.10+
- The scanner binaries for your OS (see [Install the scanners](CONTRIBUTING_SCAN_DATA.md#install-the-scanners))
- **[Nmap](https://nmap.org/download.html), installed by you.** mark2 does not ship Nmap
  for licensing reasons (see [Licensing and Attributions](#licensing-and-attributions)).
  Install it from your package manager (`apt install nmap`, `brew install nmap`,
  `apk add nmap nmap-scripts`) or nmap.org, and make sure it is on `$PATH` — or point
  `NMAP_BINARY` at it. On Windows, LAN scans additionally need
  [Npcap](https://npcap.com/#download), also installed by you.
- An LLM backend: a local [Ollama](https://ollama.com) model (default, see
  [Setting up Ollama](#setting-up-ollama) below) **or** an Anthropic API key

Without Nmap, mark2 still runs: the port/service, CVE-enrichment, and IoT default-credential
stages report `{"status": "unavailable"}` and the remaining scanners (Trivy, Nuclei, Lynis,
ClamAV) proceed normally. You lose the network findings, not the run.

```bash
pip install -r requirements.txt
```

## Setting up Ollama

mark2 uses two LLM stages: **triage** (reorders findings, may pull in a few extra CVE
details) and **report** (writes the plain-English report). By default both run on
stock `llama3.1:8b`. mark2 also publishes a fine-tuned `mark2-report` model — trained on
the report stage's actual prompt/output contract — that produces better home-user-facing
reports than the stock model at the same size. Triage isn't fine-tuned yet, so it stays
on `llama3.1:8b` for now; a fine-tuned `mark2-triage` is planned as a follow-up.

1. **Install Ollama** — see [ollama.com/download](https://ollama.com/download) for
   macOS/Windows/Linux instructions. Make sure it's running (`ollama serve`, or just
   launch the app — it starts a background service automatically on macOS/Windows).

2. **Pull both models:**

   ```bash
   ollama pull llama3.1:8b                       # triage stage
   ollama pull pseudocoder204/mark2-report        # report stage (fine-tuned)
   ```

3. **Point each stage at the right model:**

   ```bash
   export OLLAMA_MODEL=pseudocoder204/mark2-report
   export OLLAMA_TRIAGE_MODEL=llama3.1:8b
   ```

   These default to `llama3.1:8b` for both stages if unset, so this step is only needed
   to opt into the fine-tuned report model.

## Running a diagnostic

```bash
# Scan your own machine (default target 127.0.0.1) with the default Ollama backend
python3 agent.py [--target IP] [--json]

# Use Anthropic instead of Ollama
LLM_PROVIDER=claude ANTHROPIC_API_KEY=sk-... python3 agent.py
```

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

```bash
gunzip -c vulnerability_cache.db.gz > vulnerability_cache.db
```

Without it, the pipeline creates an empty cache and syncs ~30 days of recent CVEs from NVD
on first run (slower, less complete). Set `NVD_API_KEY` for higher NVD rate limits.

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

| Name | Role |
|---|---|
| Aditya Soni | Lead Developer & Architect |
| Andrew Macedo | Community Outreach |

## License & attributions

mark2 is licensed under the **GNU General Public License v2** (see [`LICENSE`](LICENSE)).

mark2 is just an orchestration layer: **it ships no scanner binaries.** You install the
scanners yourself, and mark2 runs each as a separate program and reads its output — it never
contains, links against, or modifies their code. So each scanner stays under its own license,
and using mark2 asks nothing of you beyond installing the tools. Credit for the actual scanning
belongs to their authors:

| Tool | Author / Maintainer | License | Role in mark2 |
|---|---|---|---|
| [Nmap](https://nmap.org) | Nmap Software LLC (Gordon "Fyodor" Lyon) | [Nmap Public Source License](https://nmap.org/npsl/) (NPSL, GPLv2-derived) | Port/service discovery, version detection, IoT default-credential NSE checks |
| [ClamAV](https://www.clamav.net) | Cisco Systems, Inc. / Talos | [GPL-2.0](https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt) | Malware scanning (`clamscan`) |
| [Lynis](https://cisofy.com/lynis/) | CISOfy / Michael Boelen | [GPL-3.0](https://github.com/CISOfy/lynis/blob/master/LICENSE) | Host hardening audit |
| [Trivy](https://trivy.dev) | Aqua Security | [Apache-2.0](https://github.com/aquasecurity/trivy/blob/main/LICENSE) | Filesystem package vulnerability scanning |
| [Nuclei](https://projectdiscovery.io) | ProjectDiscovery, Inc. | [MIT](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md) | Template-based web/network vulnerability checks |

Each tool's full license text is kept in [`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/).
CVE data comes from the [NVD](https://nvd.nist.gov/), which is public domain (NIST does not
endorse this project).

Two things worth knowing: mark2 does **not** bundle [Nmap](https://nmap.org/download.html)
(install it yourself — a deliberate licensing choice), and you should only scan systems you own
or are authorized to test.

Packaging mark2 commercially, hosting it as a service, or bundling any scanner binary? The full
license analysis — NPSL/OEM, Docker source-offer, Npcap, hosted-deployment notices — lives in
[LICENSING.md](LICENSING.md).
