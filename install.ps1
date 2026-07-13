# SPDX-License-Identifier: GPL-2.0-only
#
# Pulser native installer for Windows.
#
# What this does: installs nmap, Nuclei, the Python dependencies, and checks
# for Ollama. It deliberately does not pull any Ollama model - see the
# README's "Setting up Ollama" section to pick and pull one. On Windows the
# host audit uses the native PowerShell audit and malware uses Windows
# Defender's own threat history, so Lynis and ClamAV are intentionally NOT
# installed here. Trivy is also NOT installed - its filesystem-scan mode is
# always skipped on Windows (see below), so Pulser never invokes it there.
#
# Licensing note (see LICENSING.md): Pulser ships no scanner binaries.
#   * nmap  - installed via winget if available (from nmap.org's own published
#             package), never bundled or hosted by Pulser. If winget can't do it,
#             this script only LINKS to nmap.org; it will not fetch the binary.
#   * Npcap - required for nmap LAN scans on Windows. Its license forbids
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

Info "Pulser Windows installer"

$hasWinget = Have winget
if (-not $hasWinget) {
    Warn "winget not found - tools that would install via winget will be listed for manual install."
}

# --- 1. nmap (via winget only - never bundled) --------------------------------
if (Have nmap) {
    Ok "nmap already installed"; $already += "nmap"
} elseif ($hasWinget) {
    Info "Installing nmap via winget (from nmap.org's published package)"
    try {
        winget install --id Insecure.Nmap --accept-package-agreements --accept-source-agreements -e | Out-Null
        if (Have nmap) { Ok "nmap installed"; $installed += "nmap" }
        else { Warn "nmap installed but not on PATH - reopen your shell"; $installed += "nmap" }
    } catch {
        Failm "winget could not install nmap"; $manual += "nmap - download from https://nmap.org/download.html"
    }
} else {
    $manual += "nmap - download from https://nmap.org/download.html"
}

# --- 2. Npcap - DETECT AND LINK ONLY (never downloaded; license forbids it) ---
$npcapPresent = Test-Path "$env:SystemRoot\System32\Npcap"
if ($npcapPresent) {
    Ok "Npcap detected (nmap LAN scans available)"
} else {
    Warn "Npcap NOT detected. LAN discovery/SYN/OS-detection scans need it."
    $manual += "Npcap - install yourself from https://npcap.com/#download (Pulser cannot redistribute it)"
}

# --- 3. Nuclei (Windows binary from upstream) ----------------------------------
# Trivy is deliberately NOT installed here: tools.scan_filesystem() always
# returns {"status":"skipped"} on Windows (its fs mode reads Linux package DBs
# - dpkg/rpm/apk - that don't exist on Windows; host audit's Windows Update
# check covers OS-patch state instead), so installing it would just be wasted
# time/bandwidth for a scanner Pulser will never invoke on this platform.
$binDir = if ($env:MARK2_BIN_DIR) { $env:MARK2_BIN_DIR } else { Join-Path $PSScriptRoot "bin" }
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

Info "Skipping Trivy on purpose: its filesystem scan needs Linux package DBs (dpkg/rpm/apk) that don't exist on Windows -- the host audit's Windows Update check covers OS-patch state instead."

if (Have nuclei) {
    Ok "Nuclei already installed"; $already += "Nuclei"
} else {
    Info "Installing Nuclei (Windows amd64) from upstream into $binDir"
    try {
        $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
        $rel  = Invoke-RestMethod "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
        $ver  = $rel.tag_name.TrimStart('v')
        $url  = "https://github.com/projectdiscovery/nuclei/releases/download/v$ver/nuclei_${ver}_windows_${arch}.zip"
        $zip  = Join-Path $env:TEMP "pulser-nuclei.zip"
        Invoke-WebRequest $url -OutFile $zip
        Expand-Archive $zip -DestinationPath $binDir -Force
        Remove-Item $zip
        Ok "Nuclei installed (v$ver) into $binDir"; $installed += "Nuclei"
        try { & (Join-Path $binDir "nuclei.exe") -update-templates | Out-Null; Ok "Nuclei templates updated" }
        catch { Warn "Template update failed - run 'nuclei -update-templates' later" }
    } catch {
        Failm "Nuclei install failed"; $manual += "Nuclei - https://github.com/projectdiscovery/nuclei/releases into $binDir"
    }
}

# --- 4. Python dependencies -----------------------------------------------
if (Have python) {
    Info "Installing Python dependencies (requirements.txt)"
    try { python -m pip install -r (Join-Path $PSScriptRoot "requirements.txt") | Out-Null
          Ok "Python dependencies installed"; $installed += "Python deps" }
    catch { Warn "pip install failed - try it inside a venv"; $missing += "Python deps" }
} else {
    Failm "python not found - install Python 3.10+ from https://python.org"; $missing += "Python 3.10+"
}

# --- 5. Ollama ---------------------------------------------------------------
# Model pulls are deliberately not automated here - llama3.1:8b and
# mark2-report are multi-GB downloads, and which one (or neither, if you're
# on Claude) you want is a choice for the user, not this script. See the
# README's "Setting up Ollama" section for the pull commands.
if (Have ollama) {
    Ok "Ollama already installed"; $already += "ollama"
} else {
    Warn "Ollama not found - skipping"
    $manual += "Ollama - install from https://ollama.com/download, then see the README's 'Setting up Ollama' section to pull a report-stage model"
}

# --- summary -----------------------------------------------------------------
Write-Host ""
Info "Summary"
if ($installed) { Write-Host "  Installed now:"; $installed | ForEach-Object { Ok $_ } }
if ($already)   { Write-Host "  Already present:"; $already | ForEach-Object { Write-Host "  ( ) $_" -ForegroundColor DarkGray } }
if ($missing)   { Write-Host "  Needs attention:"; $missing | ForEach-Object { Failm $_ } }

Write-Host ""
Write-Host "  You must still do yourself:" -ForegroundColor White
$manual | ForEach-Object { Warn $_ }
Warn "Run Pulser as Administrator for elevation-gated audit checks and raw-socket nmap scans."
Warn "The CVE cache (~3.2 GB) is not installed here - download vulnerability_cache.db.gz from Releases (see README)."

Write-Host ""
if (-not $missing) { Ok "Ready. Run: python agent.py --target 127.0.0.1" }
else { Warn "Some components need manual attention; Pulser still runs degraded (missing scanners report 'unavailable')." }
