# Contributing a real scan to the Mark2 training set

Thanks for volunteering scan data! This guide walks you through running
`contribute_real_scan.py` on **a machine you own** and sending back one small JSON file.
It takes ~10–15 minutes plus one scan.

> **What this does:** runs a few security scanners against your own machine, reduces the
> results to a compact list of findings (open ports, service versions, matched CVE IDs,
> hardening settings, package versions), and writes them to one file you send back.
>
> **What it never sends:** file contents, credentials, full scan logs, or anything not in
> that findings list. The script prints exactly what will be recorded and makes you type
> `I consent` before it scans anything.

---

## 1. Requirements

You need **the whole repo** (not just the one `.py` file — it imports the rest of the
pipeline), Python 3.10+, and the scanner tools for your OS.

```bash
git clone https://github.com/pseudocoder204-source/mark2.git
cd mark2
pip install -r requirements.txt
```

### Download the CVE cache (recommended)

The local CVE cache (`vulnerability_cache.db`) is **too large to ship in the repo** (~3.2 GB
uncompressed), so it's hosted separately. Download it once into the repo root before
scanning — it lets the CVE lookup start from a full local cache instead of a slow
first-time download from NVD:

```bash
# Download the compressed cache (~126 MB) from the project's Releases page, then:
gunzip -c vulnerability_cache.db.gz > vulnerability_cache.db
```

> Skipping this still works — the pipeline will create an empty cache and sync ~30 days of
> recent CVEs from NVD on first run — but your CVE enrichment (and therefore the value of
> your contribution) is much better with the full cache in place.

### Install the scanners

**Linux (Debian/Ubuntu):**
```bash
sudo apt install nmap clamav          # nmap + ClamAV (ClamAV only needed with --malware live)
# Trivy:  https://aquasecurity.github.io/trivy/latest/getting-started/installation/
# Nuclei: https://github.com/projectdiscovery/nuclei#install-nuclei  (or: go install ...)
# Lynis:  sudo apt install lynis       (or https://cisofy.com/lynis/)
```

**macOS (Homebrew):**
```bash
brew install nmap trivy nuclei lynis clamav
```

**Windows:** ⚠️ The Windows path works differently and is **not yet validated on a real
Windows machine** — please coordinate with the maintainer before contributing from
Windows. When it is ready you'll need `nmap` (plus the **Npcap** driver) and `nuclei`;
the host audit and malware check use Windows Defender + PowerShell, which are already
built in (Trivy, Lynis, and ClamAV are *not* used on Windows).

> The script runs a **preflight check** and prints which scanners it found. Missing ones
> are skipped and simply won't appear in your contribution — so install them all for the
> most useful data. Point the script at a binary that isn't on your `PATH` with an env var,
> e.g. `NUCLEI_BINARY=/opt/nuclei/nuclei`, or drop binaries in a `./bin` folder.

---

## 2. Run it

Scan **your own machine** (the default target `127.0.0.1`):

```bash
python3 contribute_real_scan.py
```

You'll see the scanner check, then a summary of exactly what will be recorded, then a
consent prompt. Type `I consent` to proceed.

Useful flags:

| Flag | Purpose |
|---|---|
| `--label my-laptop` | A name for your machine (default: its hostname). Just provenance. |
| `--malware live` | Also run a malware scan. **Slow** — the first ClamAV run can take 1–4+ hours. Omitted by default. |
| `--yes` | Skip the interactive prompts (for scripted use). Still warns about missing tools. |

You should **not** need to scan anything other than your own machine. Scanning another
host requires that owner's explicit permission and the `--i-have-permission` flag.

---

## 3. Send back the result

When it finishes it prints something like:

```
[contribute] done. Findings written to contrib_my-laptop_20260708T161143Z_cfab1f25.json
```

Submit **that one `contrib_*.json` file** through this form:

👉 **[Submit your contribution](https://docs.google.com/forms/d/e/1FAIpQLSfQIl3y1xTYoaWhLFSuIMLQh6TmnucyQUBe1x5bK01qFlD1zw/viewform)**

That's it — the file already contains everything needed. (Note: the form's file-upload
question requires signing in with a Google account — that's a Google Forms platform
limit, not something specific to this project.) It also inserts a row into a local
`trainset.db` next to the script; you don't need to send that.

---

## FAQ

**Is any of my personal data in the file?** No file contents, credentials, or logs — only
the findings summary the script listed before scanning (ports, versions, CVE IDs,
hardening test IDs, package names/versions, and — only with `--malware live` — malware
signature names and matched file paths).

**A scanner is missing / I can't install one.** You can still contribute; that scanner's
data will just be absent. Installing all of them gives the most useful row.

**It's taking hours.** You almost certainly passed `--malware live` — the first ClamAV
scan is genuinely that slow. Omit it (the default) for a fast run.
