# SPDX-License-Identifier: GPL-2.0-only
#
# Pulser one-command installer for Windows.
#
#   irm https://raw.githubusercontent.com/pseudocoder204-source/Pulser/main/install.ps1 | iex
#
# or, from a clone:
#
#   .\install.ps1
#
# Both paths do the same thing. Piped, it clones the repo for you first. To pass
# flags through the piped form, PowerShell needs the scriptblock spelling:
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/pseudocoder204-source/Pulser/main/install.ps1))) -Claude
#
# What this does, in order:
#   1. clones Pulser (only if it isn't already around this script)
#   2. installs the scanners Pulser uses on Windows (nmap, Nuclei)
#   3. creates a .venv and installs the Python dependencies into it
#   4. installs Ollama and pulls the report model
#   5. downloads and unpacks the CVE cache (~126 MB compressed, ~3.2 GB on disk)
#   6. drops a `pulser` launcher on your PATH
#
# Steps 4 and 5 are the slow ones and run as background jobs while 2 and 3 proceed.
# It is idempotent: anything already present is skipped, so re-running it upgrades
# an existing install rather than reinstalling it.
#
# Windows installs a deliberately smaller scanner set than Linux/macOS:
#   * Lynis  - no Windows port; the native PowerShell audit replaces it.
#   * ClamAV - not run on Windows (redundant with Defender, risks quarantine);
#              Defender's own threat history is the malware source instead.
#   * Trivy  - tools.scan_filesystem() always returns {"status":"skipped"} on
#              Windows (its fs mode reads Linux package DBs - dpkg/rpm/apk - that
#              don't exist here; the host audit's Windows Update check covers
#              OS-patch state instead), so installing it would be wasted bandwidth
#              for a scanner Pulser will never invoke on this platform.
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

[CmdletBinding()]
param(
    [Alias('SkipOllama')]
    [switch]$Claude,          # Anthropic backend: skip Ollama and the model pull
    [switch]$SkipCache,       # skip the ~3.2 GB CVE cache download
    [switch]$SkipShim,        # don't install the `pulser` launcher onto PATH
    [switch]$Yes,             # don't prompt for confirmation
    [string]$Model = "pseudocoder204/mark2-report",
    [string]$Dir              # where to clone (default: $env:LOCALAPPDATA\Pulser)
)

$ErrorActionPreference = 'Stop'

$RepoUrl  = "https://github.com/pseudocoder204-source/Pulser.git"
$CacheUrl = "https://github.com/pseudocoder204-source/Pulser/releases/download/v0.1.0-data/vulnerability_cache.db.gz"

$installed = @()
$already   = @()
$missing   = @()
$manual    = @()

function Have($name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }
function Info($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [ok] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Failm($m){ Write-Host "  [x]  $m" -ForegroundColor Red }
function Skipm($m){ Write-Host "  ( )  $m" -ForegroundColor DarkGray }

# winget and Wait-Job both give long stretches (a multi-hundred-MB Ollama install,
# a multi-GB model pull, a 3.2 GB cache decompression) with zero console output,
# which reads as "the installer is stuck." This prints an elapsed-time heartbeat
# every few seconds until the job finishes, then reports its outcome.
function Wait-ForHttp($url, $maxSeconds, $label) {
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $maxSeconds) {
        try {
            Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 2 | Out-Null
            Write-Host "`r$(' ' * 80)`r" -NoNewline
            return $true
        } catch {
            $elapsed = [int]((Get-Date) - $start).TotalSeconds
            Write-Host "`r  ...  $label ($elapsed`s elapsed, still waiting)  " -NoNewline -ForegroundColor DarkGray
            Start-Sleep -Seconds 2
        }
    }
    Write-Host "`r$(' ' * 80)`r" -NoNewline
    return $false
}

function Wait-WithHeartbeat($job, $label) {
    $start = Get-Date
    while (-not (Wait-Job $job -Timeout 3)) {
        $elapsed = [int]((Get-Date) - $start).TotalSeconds
        Write-Host "`r  ...  $label ($elapsed`s elapsed, still running)  " -NoNewline -ForegroundColor DarkGray
    }
    Write-Host "`r$(' ' * 80)`r" -NoNewline
    return $job
}

# --- 0. bootstrap: find or clone the repo ------------------------------------
# Run from a clone, $PSScriptRoot sits next to agent.py and we use that tree. Piped
# through iex there is no script on disk ($PSScriptRoot is empty), so clone instead.
$srcDir = $null
if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "agent.py"))) {
    $srcDir = $PSScriptRoot
}
if ($srcDir) {
    $repoDir = $srcDir
} elseif ($Dir) {
    $repoDir = $Dir
} else {
    $repoDir = Join-Path $env:LOCALAPPDATA "Pulser"
}

$hasWinget = Have winget

Write-Host ""
Info "Pulser Windows installer"
Write-Host "  This will:"
if ($srcDir) { Write-Host "    - use the clone at        $repoDir" }
else         { Write-Host "    - clone Pulser into       $repoDir" }
Write-Host "    - install scanners        nmap, Nuclei (Lynis/ClamAV/Trivy are not used on Windows)"
Write-Host "    - create a venv at        $repoDir\.venv"
if (-not $Claude) { Write-Host "    - install Ollama + pull   $Model (multi-GB)" }
else              { Skipm "skip Ollama (-Claude)" }
if (-not $SkipCache) { Write-Host "    - download the CVE cache  ~126 MB compressed -> ~3.2 GB on disk" }
else                 { Skipm "skip the CVE cache (-SkipCache)" }
if (-not $SkipShim) { Write-Host "    - install the launcher    $env:LOCALAPPDATA\Programs\Pulser\pulser.cmd" }
Write-Host ""
if (-not $Yes) {
    $reply = Read-Host "Proceed? [Y/n]"
    if ($reply -match '^[nN]') { Warn "Aborted."; exit 1 }
}
Write-Host ""

if (-not $srcDir) {
    if (Test-Path (Join-Path $repoDir ".git")) {
        Info "Updating existing clone at $repoDir"
        try { git -C $repoDir pull --ff-only | Out-Null; Ok "Updated" }
        catch { Warn "Could not fast-forward - leaving as-is" }
        $already += "Pulser clone"
    } else {
        if (-not (Have git)) { Failm "git not found - install Git for Windows first (https://git-scm.com)"; exit 1 }
        Info "Cloning Pulser into $repoDir"
        try {
            git clone --depth 1 $RepoUrl $repoDir | Out-Null
            Ok "Cloned"; $installed += "Pulser clone"
        } catch {
            Failm "Clone failed - check your network or clone manually from $RepoUrl"; exit 1
        }
    }
}

# --- background job 1: the CVE cache -----------------------------------------
# Kicked off first: it's the longest pole (126 MB down, 3.2 GB decompressed) and
# it's pure network+disk, so it overlaps cleanly with the installs below.
$cacheDb  = Join-Path $repoDir "vulnerability_cache.db"
$cacheJob = $null
if ($SkipCache) {
    Skipm "CVE cache skipped (-SkipCache)"
} elseif (Test-Path $cacheDb) {
    Ok "CVE cache already present"; $already += "CVE cache"
} else {
    Info "Downloading the CVE cache in the background (~126 MB -> ~3.2 GB)"
    $cacheJob = Start-Job -ArgumentList $CacheUrl, $cacheDb -ScriptBlock {
        param($url, $db)
        $ErrorActionPreference = 'Stop'
        $gz = "$db.gz"
        # Invoke-WebRequest's progress bar makes large downloads crawl; suppressing it
        # is worth roughly an order of magnitude here.
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest $url -OutFile $gz
        # Windows PowerShell 5.1 doesn't load System.IO.Compression by default
        # (PowerShell Core does) - without this, GzipStream fails with
        # "Cannot find type [System.IO.Compression.GzipStream]".
        Add-Type -AssemblyName System.IO.Compression
        $in   = [System.IO.File]::OpenRead($gz)
        $gzs  = New-Object System.IO.Compression.GzipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
        # Decompress to .part, then move: a killed run never leaves a half-written DB
        # that later looks like a valid cache.
        $out  = [System.IO.File]::Create("$db.part")
        try   { $gzs.CopyTo($out) }
        finally { $out.Close(); $gzs.Close(); $in.Close() }
        Move-Item "$db.part" $db -Force
        Remove-Item $gz -Force
    }
}

# --- background job 2: Ollama + the report model ------------------------------
$ollamaJob = $null
if ($Claude) {
    Skipm "Ollama skipped (-Claude) - set ANTHROPIC_API_KEY and LLM_PROVIDER=claude"
} else {
    if (Have ollama) {
        Ok "Ollama already installed"; $already += "Ollama"
    } elseif ($hasWinget) {
        Info "Installing Ollama via winget (a few hundred MB - this can take a few minutes)"
        try {
            $j = Start-Job -ScriptBlock {
                winget install --id Ollama.Ollama --accept-package-agreements --accept-source-agreements -e
                if ($LASTEXITCODE -ne 0) { throw "winget exited with code $LASTEXITCODE" }
            }
            Wait-WithHeartbeat $j "installing Ollama" | Out-Null
            if ($j.State -ne 'Completed') { throw (Receive-Job $j -ErrorAction SilentlyContinue | Select-Object -Last 1) }
            Remove-Job $j -Force
            # winget updates the machine PATH but not this already-running process's
            # copy of it, so a freshly installed ollama.exe is invisible to Have until
            # we re-read PATH from the registry.
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                        [System.Environment]::GetEnvironmentVariable("PATH","User")
            if (Have ollama) { Ok "Ollama installed"; $installed += "Ollama" }
            else { Warn "Ollama installed but not on PATH yet - reopen your shell"; $installed += "Ollama" }
        } catch {
            Failm "winget could not install Ollama"; $manual += "Ollama - https://ollama.com/download"
        }
    } else {
        $manual += "Ollama - https://ollama.com/download"
    }

    if (Have ollama) {
        # The Windows installer starts the server as a background service, but not
        # always instantly - `ollama pull` needs a live server on :11434.
        $up = Wait-ForHttp "http://localhost:11434/api/version" 20 "checking for the Ollama server"
        $serveLog = Join-Path $env:TEMP "pulser-ollama-serve.log"
        # Tracks whether THIS run spawned the server. Only a server we ourselves
        # started is ever safe to kill/restart later - one that was already
        # running might be serving other apps or hold state we don't own, and a
        # slow first health-check response (not an actual outage) must not be
        # mistaken for licence to touch it.
        $weStartedServer = $false
        if (-not $up) {
            Info "Starting the Ollama server"
            # A just-installed ollama.exe can be slow to come up on first run
            # (Defender scanning the new binary, cold disk cache) - 90s here,
            # not 20, since this is after we've explicitly launched it ourselves
            # and there's nothing left to wait on but the process itself.
            # Redirected to a log instead of discarded: if it never comes up,
            # we otherwise have zero idea why (port conflict, missing dep, etc).
            Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden `
                -RedirectStandardOutput $serveLog -RedirectStandardError "$serveLog.err"
            $weStartedServer = $true
            $up = Wait-ForHttp "http://localhost:11434/api/version" 90 "waiting for the Ollama server to start"
            if (-not $up) {
                # Our own spawn can fail to bind :11434 if the ORIGINAL server was
                # actually up all along and our first check just caught it mid-
                # response - that's not a real outage, so don't credit ourselves
                # with having started anything, and give the real server a beat.
                $errText = ""
                if (Test-Path "$serveLog.err") { $errText = Get-Content "$serveLog.err" -Raw -ErrorAction SilentlyContinue }
                if ($errText -match "bind:") {
                    Info "Port already bound by an existing Ollama process - rechecking"
                    $weStartedServer = $false
                    $up = Wait-ForHttp "http://localhost:11434/api/version" 20 "rechecking the existing Ollama server"
                }
            }
        }
        if ($up) {
            if ((ollama list 2>$null | Out-String) -match [regex]::Escape($Model)) {
                Ok "Model $Model already pulled"; $already += "model $Model"
            } else {
                Info "Pulling $Model in the background (multi-GB - this is the slow part, retries automatically on transient failures)"
                $ollamaJob = Start-Job -ArgumentList $Model, $weStartedServer -ScriptBlock {
                    param($m, $weStarted)
                    for ($attempt = 1; $attempt -le 3; $attempt++) {
                        & ollama pull $m 2>&1 | Out-String | Write-Output
                        if ($LASTEXITCODE -eq 0) { return }
                        if ($weStarted) {
                            # We own this process's lifecycle (we started it a few
                            # seconds ago in this same run), so it's safe to restart
                            # if its state is broken (e.g. a wiped keypair).
                            Write-Output "--- pull attempt $attempt failed, restarting the Ollama server we started and retrying in 5s ---"
                            Get-Process ollama -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 1
                            Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden
                            Start-Sleep -Seconds 4
                        } else {
                            # Someone else's server - never kill it out from under
                            # them. Just retry the pull as-is.
                            Write-Output "--- pull attempt $attempt failed - not restarting a pre-existing Ollama server; retrying in 5s ---"
                            Start-Sleep -Seconds 5
                        }
                    }
                    throw "ollama pull failed after 3 attempts"
                }
            }
        } else {
            Warn "Ollama server didn't come up on :11434 - pull the model yourself later"
            foreach ($f in @($serveLog, "$serveLog.err")) {
                if (Test-Path $f) {
                    Get-Content $f -Tail 5 -ErrorAction SilentlyContinue |
                        ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
                }
            }
            $manual += "ollama pull $Model"
        }
    }
}

# --- 1. nmap (via winget only - never bundled) --------------------------------
if (Have nmap) {
    Ok "nmap already installed"; $already += "nmap"
} elseif ($hasWinget) {
    Info "Installing nmap via winget (from nmap.org's published package)"
    try {
        $j = Start-Job -ScriptBlock {
            winget install --id Insecure.Nmap --accept-package-agreements --accept-source-agreements -e
            if ($LASTEXITCODE -ne 0) { throw "winget exited with code $LASTEXITCODE" }
        }
        Wait-WithHeartbeat $j "installing nmap" | Out-Null
        if ($j.State -ne 'Completed') { throw (Receive-Job $j -ErrorAction SilentlyContinue | Select-Object -Last 1) }
        Remove-Job $j -Force
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
        if (Have nmap) { Ok "nmap installed"; $installed += "nmap" }
        else { Warn "nmap installed but not on PATH - reopen your shell"; $installed += "nmap" }
    } catch {
        Failm "winget could not install nmap"; $manual += "nmap - download from https://nmap.org/download.html"
    }
} else {
    Warn "winget not found - nmap must be installed by hand"
    $manual += "nmap - download from https://nmap.org/download.html"
}

# --- 2. Npcap - DETECT AND LINK ONLY (never downloaded; license forbids it) ---
if (Test-Path "$env:SystemRoot\System32\Npcap") {
    Ok "Npcap detected (nmap LAN scans available)"
} else {
    Warn "Npcap NOT detected. LAN discovery/SYN/OS-detection scans need it."
    $manual += "Npcap - install yourself from https://npcap.com/#download (Pulser cannot redistribute it)"
}

# --- 3. Nuclei (Windows binary from upstream) ---------------------------------
$binDir = if ($env:MARK2_BIN_DIR) { $env:MARK2_BIN_DIR } else { Join-Path $repoDir "bin" }
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

if (Have nuclei) {
    Ok "Nuclei already installed"; $already += "Nuclei"
} elseif (Test-Path (Join-Path $binDir "nuclei.exe")) {
    Ok "Nuclei already present in $binDir"; $already += "Nuclei"
} else {
    Info "Installing Nuclei (Windows) from upstream into $binDir"
    try {
        $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
        $rel  = Invoke-RestMethod "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
        $ver  = $rel.tag_name.TrimStart('v')
        $url  = "https://github.com/projectdiscovery/nuclei/releases/download/v$ver/nuclei_${ver}_windows_${arch}.zip"
        $zip  = Join-Path $env:TEMP "pulser-nuclei.zip"
        $ProgressPreference = 'SilentlyContinue'
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

# --- 4. Python venv + dependencies -------------------------------------------
# The installer owns the venv rather than asking the user to create one first, so
# nothing is ever installed into the system interpreter.
$venv   = Join-Path $repoDir ".venv"
$venvPy = Join-Path $venv "Scripts\python.exe"
if (Have python) {
    if (-not (Test-Path $venvPy)) {
        Info "Creating a virtualenv at $venv"
        try { python -m venv $venv | Out-Null } catch { Failm "venv creation failed"; $missing += "venv" }
    }
    if (Test-Path $venvPy) {
        Info "Installing Python dependencies into the venv"
        try {
            & $venvPy -m pip install --upgrade pip | Out-Null
            & $venvPy -m pip install -r (Join-Path $repoDir "requirements.txt") | Out-Null
            Ok "Python dependencies installed"; $installed += "Python deps"
        } catch {
            Failm "pip install failed"
            $missing += "Python deps - & '$venvPy' -m pip install -r '$repoDir\requirements.txt'"
        }
    }
} else {
    Failm "python not found - install Python 3.10+ from https://python.org"; $missing += "Python 3.10+"
}

# --- 5. the `pulser` launcher -------------------------------------------------
# So a user never has to cd into the repo or activate the venv: `pulser` from
# anywhere runs agent.py on the venv's interpreter with all args forwarded.
$shimDir = Join-Path $env:LOCALAPPDATA "Programs\Pulser"
$shim    = Join-Path $shimDir "pulser.cmd"
if ($SkipShim) {
    Skipm "Launcher skipped (-SkipShim)"
} elseif (-not (Test-Path $venvPy)) {
    Warn "Skipping the launcher - no venv to point it at"
} else {
    New-Item -ItemType Directory -Force -Path $shimDir | Out-Null
    # %* forwards every argument; @echo off keeps the shim itself out of the output.
    # The `cd /d` is load-bearing, not cosmetic: agent.py resolves DB_PATH
    # ("vulnerability_cache.db") and SCAN_LOG_DB ("scan_log.db") relative to the working
    # directory. Without it, `pulser` from anywhere else would miss the CVE cache and
    # silently trigger a full NVD re-sync against an empty DB.
    $shimBody = "@echo off`r`ncd /d `"$repoDir`" || exit /b 1`r`n`"$venvPy`" agent.py %*`r`n"
    $shimBody | Set-Content -Path $shim -Encoding ASCII -NoNewline
    Ok "Launcher installed at $shim"; $installed += "pulser launcher"

    $userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -notlike "*$shimDir*") {
        Info "Adding $shimDir to your user PATH"
        [System.Environment]::SetEnvironmentVariable("PATH", "$userPath;$shimDir", "User")
        $manual += 'Reopen your terminal so "pulser" is on PATH (it was added to your user PATH just now)'
    }
}

# --- 6. wait on the background jobs ------------------------------------------
if ($ollamaJob) {
    Info "Waiting for the $Model pull to finish (multi-GB - this is normal)"
    Wait-WithHeartbeat $ollamaJob "pulling $Model" | Out-Null
    if ($ollamaJob.State -eq 'Completed') { Ok "Model $Model pulled"; $installed += "model $Model" }
    else {
        Failm "Model pull failed"
        Receive-Job $ollamaJob -ErrorAction SilentlyContinue | Select-Object -Last 1 | Write-Host
        $manual += "ollama pull $Model"
    }
    Remove-Job $ollamaJob -Force
}
if ($cacheJob) {
    Info "Waiting for the CVE cache download to finish"
    Wait-WithHeartbeat $cacheJob "downloading + unpacking the CVE cache" | Out-Null
    if ($cacheJob.State -eq 'Completed' -and (Test-Path $cacheDb)) {
        Ok "CVE cache ready"; $installed += "CVE cache"
    } else {
        Failm "CVE cache download failed"
        Receive-Job $cacheJob -ErrorAction SilentlyContinue | Select-Object -Last 1 | Write-Host
        Remove-Item "$cacheDb.gz","$cacheDb.part" -Force -ErrorAction SilentlyContinue
        $manual += "CVE cache - download $CacheUrl and unpack it to $cacheDb (see README)"
    }
    Remove-Job $cacheJob -Force
}

# --- summary -----------------------------------------------------------------
Write-Host ""
Info "Summary"
if ($installed) { Write-Host "  Installed now:";    $installed | ForEach-Object { Ok $_ } }
if ($already)   { Write-Host "  Already present:";  $already   | ForEach-Object { Skipm $_ } }
if ($missing)   { Write-Host "  Needs attention:";  $missing   | ForEach-Object { Failm $_ } }
if ($manual)    { Write-Host "  You must still do yourself:"; $manual | ForEach-Object { Warn $_ } }

Write-Host ""
Warn "Run Pulser as Administrator for elevation-gated audit checks and raw-socket nmap scans."
Write-Host ""
if (-not $missing) {
    if (-not $SkipShim -and (Test-Path $shim)) { Ok "Ready. Run: pulser" }
    else { Ok "Ready. Run: & '$venvPy' '$repoDir\agent.py'" }
} else {
    Warn "Some components need attention above; Pulser still runs degraded (missing scanners report 'unavailable')."
}
