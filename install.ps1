# SPDX-License-Identifier: GPL-2.0-only
#
# mark2 native installer for Windows.
#
# What this does: installs the scanners that have Windows binaries (Trivy,
# Nuclei), the Python dependencies, and pulls the Ollama models. On Windows the
# host audit uses the native PowerShell audit and malware uses Windows Defender's
# own threat history, so Lynis and ClamAV are intentionally NOT installed here.
#
# Licensing note (see LICENSING.md): mark2 ships no scanner binaries.
#   * nmap  — installed via winget if available (from nmap.org's own published
#             package), never bundled or hosted by mark2. If winget can't do it,
#             this script only LINKS to nmap.org; it will not fetch the binary.
#   * Npcap — required for nmap LAN scans on Windows. Its license forbids
#             redistribution without written permission, so this script NEVER
#             downloads or installs it. It only detects it and links to
#             https://npcap.com/#download. You install Npcap yourself.
#   * Administrator rights are needed for elevation-gated audit checks and
#             raw-socket nmap scans; this script does not elevate for you.

$ErrorActionPreference = 'Stop'

$installed = @()
$already   = @()
$missing   = @()
$manual    = @()

function Have($name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }
function Info($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [ok] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Failm($m){ Write-Host "  [x]  $m" -ForegroundColor Red }

Info "mark2 Windows installer"

$hasWinget = Have winget
if (-not $hasWinget) {
    Warn "winget not found — tools that would install via winget will be listed for manual install."
}

# ── 1. nmap (via winget only — never bundled) ─────────────────────────────────
if (Have nmap) {
    Ok "nmap already installed"; $already += "nmap"
} elseif ($hasWinget) {
    Info "Installing nmap via winget (from nmap.org's published package)"
    try {
        winget install --id Insecure.Nmap --accept-package-agreements --accept-source-agreements -e | Out-Null
        if (Have nmap) { Ok "nmap installed"; $installed += "nmap" }
        else { Warn "nmap installed but not on PATH — reopen your shell"; $installed += "nmap" }
    } catch {
        Failm "winget could not install nmap"; $manual += "nmap — download from https://nmap.org/download.html"
    }
} else {
    $manual += "nmap — download from https://nmap.org/download.html"
}

# ── 2. Npcap — DETECT AND LINK ONLY (never downloaded; license forbids it) ────
$npcapPresent = Test-Path "$env:SystemRoot\System32\Npcap"
if ($npcapPresent) {
    Ok "Npcap detected (nmap LAN scans available)"
} else {
    Warn "Npcap NOT detected. LAN discovery/SYN/OS-detection scans need it."
    $manual += "Npcap — install yourself from https://npcap.com/#download (mark2 cannot redistribute it)"
}

# ── 3. Trivy + Nuclei (Windows binaries from upstream) ────────────────────────
$binDir = if ($env:MARK2_BIN_DIR) { $env:MARK2_BIN_DIR } else { Join-Path $PSScriptRoot "bin" }
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

if (Have trivy) {
    Ok "Trivy already installed"; $already += "Trivy"
} elseif ($hasWinget) {
    Info "Installing Trivy via winget"
    try { winget install --id AquaSecurity.Trivy --accept-package-agreements --accept-source-agreements -e | Out-Null
          Ok "Trivy installed"; $installed += "Trivy" }
    catch { Failm "Trivy install failed"; $manual += "Trivy — https://trivy.dev (or drop trivy.exe in $binDir)" }
} else {
    $manual += "Trivy — download trivy.exe from https://github.com/aquasecurity/trivy/releases into $binDir"
}
Warn "Note: Trivy's filesystem scan is skipped on Windows (no dpkg/rpm/apk DB); host audit covers OS patch state instead."

if (Have nuclei) {
    Ok "Nuclei already installed"; $already += "Nuclei"
} else {
    Info "Installing Nuclei (Windows amd64) from upstream into $binDir"
    try {
        $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
        $rel  = Invoke-RestMethod "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
        $ver  = $rel.tag_name.TrimStart('v')
        $url  = "https://github.com/projectdiscovery/nuclei/releases/download/v$ver/nuclei_${ver}_windows_${arch}.zip"
        $zip  = Join-Path $env:TEMP "mark2-nuclei.zip"
        Invoke-WebRequest $url -OutFile $zip
        Expand-Archive $zip -DestinationPath $binDir -Force
        Remove-Item $zip
        Ok "Nuclei installed (v$ver) into $binDir"; $installed += "Nuclei"
        try { & (Join-Path $binDir "nuclei.exe") -update-templates | Out-Null; Ok "Nuclei templates updated" }
        catch { Warn "Template update failed — run 'nuclei -update-templates' later" }
    } catch {
        Failm "Nuclei install failed"; $manual += "Nuclei — https://github.com/projectdiscovery/nuclei/releases into $binDir"
    }
}

# ── 4. Python dependencies ────────────────────────────────────────────────────
if (Have python) {
    Info "Installing Python dependencies (requirements.txt)"
    try { python -m pip install -r (Join-Path $PSScriptRoot "requirements.txt") | Out-Null
          Ok "Python dependencies installed"; $installed += "Python deps" }
    catch { Warn "pip install failed — try it inside a venv"; $missing += "Python deps" }
} else {
    Failm "python not found — install Python 3.10+ from https://python.org"; $missing += "Python 3.10+"
}

# ── 5. Ollama models ──────────────────────────────────────────────────────────
# Edit this list as you publish more models.
$ollamaModels = @("llama3.1:8b", "pseudocoder204/mark2-report")
if (Have ollama) {
    foreach ($m in $ollamaModels) {
        $present = (ollama list 2>$null | Select-String -SimpleMatch ($m -split ' ')[0])
        if ($present) { Ok "Ollama model $m already present"; $already += "ollama:$m" }
        else {
            Info "Pulling Ollama model $m"
            try { ollama pull $m | Out-Null; Ok "Pulled $m"; $installed += "ollama:$m" }
            catch { Warn "Could not pull $m — is Ollama running?"; $missing += "ollama:$m" }
        }
    }
} else {
    Warn "Ollama not found — skipping model pulls"
    $manual += "Ollama — install from https://ollama.com/download, then re-run this script"
}

# ── summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Info "Summary"
if ($installed) { Write-Host "  Installed now:"; $installed | ForEach-Object { Ok $_ } }
if ($already)   { Write-Host "  Already present:"; $already | ForEach-Object { Write-Host "  ( ) $_" -ForegroundColor DarkGray } }
if ($missing)   { Write-Host "  Needs attention:"; $missing | ForEach-Object { Failm $_ } }

Write-Host ""
Write-Host "  You must still do yourself:" -ForegroundColor White
$manual | ForEach-Object { Warn $_ }
Warn "Run mark2 as Administrator for elevation-gated audit checks and raw-socket nmap scans."
Warn "The CVE cache (~3.2 GB) is not installed here — download vulnerability_cache.db.gz from Releases (see README)."

Write-Host ""
if (-not $missing) { Ok "Ready. Run: python agent.py --target 127.0.0.1" }
else { Warn "Some components need manual attention; mark2 still runs degraded (missing scanners report 'unavailable')." }
