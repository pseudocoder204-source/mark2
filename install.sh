#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# mark2 native installer for Linux and macOS.
#
# What this does: installs the scanner tools mark2 orchestrates, the Python
# dependencies, and pulls the Ollama models — so a fresh clone is one command
# away from `python3 agent.py`.
#
# Licensing note (see LICENSING.md): mark2 ships no scanner binaries. This
# script does not bundle or host any tool — it drives your OS package manager
# and each tool's own upstream installer. In particular, nmap is installed via
# your package manager (apt/dnf/apk/brew), so the binary comes from your distro,
# not from mark2. That is installation, not redistribution, and asks nothing of
# you under the NPSL. Npcap (Windows only) is never touched here.

set -euo pipefail

# ── pretty output ─────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    BOLD=$(printf '\033[1m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m')
    RED=$(printf '\033[31m'); DIM=$(printf '\033[2m'); RESET=$(printf '\033[0m')
else
    BOLD=""; GREEN=""; YELLOW=""; RED=""; DIM=""; RESET=""
fi
info()  { printf '%s\n' "${BOLD}==>${RESET} $*"; }
ok()    { printf '%s\n' "  ${GREEN}✓${RESET} $*"; }
warn()  { printf '%s\n' "  ${YELLOW}!${RESET} $*"; }
skip()  { printf '%s\n' "  ${DIM}·${RESET} $*"; }
fail()  { printf '%s\n' "  ${RED}✗${RESET} $*"; }

# Track what happened so the closing summary is honest about it.
INSTALLED=()
ALREADY=()
MISSING=()
MANUAL=()

have() { command -v "$1" >/dev/null 2>&1; }

# ── detect OS + package manager ───────────────────────────────────────────────
OS="$(uname -s)"
PM=""
PM_INSTALL=""
SUDO=""

case "$OS" in
    Linux)
        if have apt-get; then PM="apt";  PM_INSTALL="apt-get install -y"
        elif have dnf;    then PM="dnf";  PM_INSTALL="dnf install -y"
        elif have yum;    then PM="yum";  PM_INSTALL="yum install -y"
        elif have apk;    then PM="apk";  PM_INSTALL="apk add --no-cache"
        elif have pacman; then PM="pacman"; PM_INSTALL="pacman -S --noconfirm"
        fi
        [ "$(id -u)" -ne 0 ] && have sudo && SUDO="sudo"
        ;;
    Darwin)
        if have brew; then PM="brew"; PM_INSTALL="brew install"; fi
        ;;
    *)
        fail "Unsupported OS: $OS. On Windows, run install.ps1 in PowerShell instead."
        exit 1
        ;;
esac

if [ -z "$PM" ]; then
    fail "No supported package manager found."
    if [ "$OS" = "Darwin" ]; then
        warn "Install Homebrew first: https://brew.sh"
    fi
    exit 1
fi

info "Detected ${BOLD}$OS${RESET} with package manager ${BOLD}$PM${RESET}"

# pkg_install <display-name> <binary-to-check> <pkg1> [pkg2...]
# Installs via the OS package manager only if the binary isn't already present.
pkg_install() {
    local name="$1" bin="$2"; shift 2
    if have "$bin"; then
        ok "$name already installed"; ALREADY+=("$name"); return 0
    fi
    info "Installing $name via $PM"
    if $SUDO $PM_INSTALL "$@"; then
        if have "$bin"; then ok "$name installed"; INSTALLED+=("$name")
        else warn "$name package installed but '$bin' not on PATH yet"; INSTALLED+=("$name"); fi
    else
        fail "Could not install $name via $PM"; MISSING+=("$name (pkg: $*)")
    fi
}

# ── 1. nmap (package-manager install — NOT bundled by mark2) ───────────────────
# Package names differ by distro; -sV needs the NSE scripts, which are a separate
# package on Alpine (nmap-scripts) but bundled with nmap elsewhere.
case "$PM" in
    apk) pkg_install "nmap" nmap nmap nmap-scripts ;;
    *)   pkg_install "nmap" nmap nmap ;;
esac

# ── 2. ClamAV + Lynis (GPL tools, via package manager) ────────────────────────
case "$PM" in
    apt)    pkg_install "ClamAV" clamscan clamav ;;
    *)      pkg_install "ClamAV" clamscan clamav ;;
esac
pkg_install "Lynis" lynis lynis

# ── 3. Trivy + Nuclei ─────────────────────────────────────────────────────────
# On Homebrew both ship as formulae, which is far more reliable than dropping a
# binary into /usr/local/bin by hand (unwritable on Apple Silicon). Everywhere
# else, use each tool's own upstream installer — the same sources the Dockerfile
# uses. Neither path bundles a binary into mark2.
if [ "$PM" = "brew" ]; then
    pkg_install "Trivy" trivy trivy
    pkg_install "Nuclei" nuclei nuclei
    if have nuclei; then
        info "Fetching Nuclei templates"
        nuclei -update-templates >/dev/null 2>&1 && ok "Nuclei templates updated" || warn "Template update failed — run 'nuclei -update-templates' later"
    fi
else
    BIN_DIR="${MARK2_BIN_DIR:-/usr/local/bin}"
    if [ ! -w "$BIN_DIR" ] && [ -n "$SUDO" ]; then WBIN="$SUDO"; else WBIN=""; fi

    if have trivy; then
        ok "Trivy already installed"; ALREADY+=("Trivy")
    else
        info "Installing Trivy from upstream into $BIN_DIR"
        if curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
             | $WBIN sh -s -- -b "$BIN_DIR" >/dev/null 2>&1 && have trivy; then
            ok "Trivy installed"; INSTALLED+=("Trivy")
        else
            fail "Trivy install failed"; MISSING+=("Trivy — see https://trivy.dev")
        fi
    fi

    if have nuclei; then
        ok "Nuclei already installed"; ALREADY+=("Nuclei")
    else
        info "Installing Nuclei from upstream"
        case "$(uname -m)" in
            x86_64|amd64) NMACH="amd64" ;;
            arm64|aarch64) NMACH="arm64" ;;
            *) NMACH="amd64" ;;
        esac
        NVER="$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
                | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v' || true)"
        if [ -n "$NVER" ] && \
           curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NVER}/nuclei_${NVER}_linux_${NMACH}.zip" -o /tmp/mark2-nuclei.zip && \
           $WBIN unzip -oq /tmp/mark2-nuclei.zip nuclei -d "$BIN_DIR" && have nuclei; then
            rm -f /tmp/mark2-nuclei.zip
            ok "Nuclei installed (v$NVER)"; INSTALLED+=("Nuclei")
            info "Fetching Nuclei templates"
            nuclei -update-templates >/dev/null 2>&1 && ok "Nuclei templates updated" || warn "Template update failed — run 'nuclei -update-templates' later"
        else
            fail "Nuclei install failed"; MISSING+=("Nuclei — see https://github.com/projectdiscovery/nuclei/releases")
        fi
    fi
fi

# ── 4. Python dependencies ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if have python3; then
    info "Installing Python dependencies (requirements.txt)"
    if python3 -m pip install -r "$SCRIPT_DIR/requirements.txt" >/dev/null 2>&1; then
        ok "Python dependencies installed"; INSTALLED+=("Python deps")
    else
        warn "pip install failed — try 'python3 -m pip install -r requirements.txt' in a venv"
        MISSING+=("Python deps — pip install -r requirements.txt")
    fi
else
    fail "python3 not found — install Python 3.10+ first"
    MISSING+=("Python 3.10+")
fi

# ── 5. Ollama models ──────────────────────────────────────────────────────────
# Edit this list as you publish more models; the script pulls each one.
OLLAMA_MODELS=("llama3.1:8b" "pseudocoder204/mark2-report")
if have ollama; then
    for m in "${OLLAMA_MODELS[@]}"; do
        if ollama list 2>/dev/null | grep -q "^${m%% *}"; then
            ok "Ollama model $m already present"; ALREADY+=("ollama:$m")
        else
            info "Pulling Ollama model $m"
            if ollama pull "$m" >/dev/null 2>&1; then ok "Pulled $m"; INSTALLED+=("ollama:$m")
            else warn "Could not pull $m — is 'ollama serve' running?"; MISSING+=("ollama:$m"); fi
        fi
    done
else
    warn "Ollama not found — skipping model pulls"
    MANUAL+=("Ollama: install from https://ollama.com/download, then re-run this script (or: ${OLLAMA_MODELS[*]/#/ollama pull })")
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo
info "${BOLD}Summary${RESET}"
[ ${#INSTALLED[@]} -gt 0 ] && { echo "  Installed now:"; for x in "${INSTALLED[@]}"; do ok "$x"; done; }
[ ${#ALREADY[@]}   -gt 0 ] && { echo "  Already present:"; for x in "${ALREADY[@]}"; do skip "$x"; done; }
[ ${#MISSING[@]}   -gt 0 ] && { echo "  Needs attention:"; for x in "${MISSING[@]}"; do fail "$x"; done; }

echo
echo "  ${BOLD}You must still do yourself:${RESET}"
[ ${#MANUAL[@]} -gt 0 ] && for x in "${MANUAL[@]}"; do warn "$x"; done
warn "The CVE cache (~3.2 GB) is not installed here — download vulnerability_cache.db.gz from Releases (see README)."

echo
if [ ${#MISSING[@]} -eq 0 ]; then
    ok "${GREEN}Ready.${RESET} Run: ${BOLD}python3 agent.py --target 127.0.0.1${RESET}"
else
    warn "Some components need manual attention above, but mark2 runs degraded without them (missing scanners report 'unavailable')."
fi
