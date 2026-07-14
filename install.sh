#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Pulser one-command installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/pseudocoder204-source/Pulser/main/install.sh | bash
#
# or, from a clone:
#
#   ./install.sh
#
# Both paths do the same thing. Piped, it clones the repo for you first.
#
# What this does, in order:
#   1. clones Pulser (only if it isn't already around this script)
#   2. installs the scanner tools it orchestrates (nmap, ClamAV, Lynis, Trivy, Nuclei)
#   3. creates a .venv and installs the Python dependencies into it
#   4. installs Ollama and pulls the report model
#   5. downloads and unpacks the CVE cache (~126 MB compressed, ~3.2 GB on disk)
#   6. drops a `pulser` launcher on your PATH
#
# Steps 4 and 5 are the slow ones and run in the background while 2 and 3 proceed.
# It is idempotent: anything already present is skipped, so re-running it upgrades
# an existing install rather than reinstalling it.
#
# Licensing note (see LICENSING.md): Pulser ships no scanner binaries. This script
# does not bundle or host any tool — it drives your OS package manager and each
# tool's own upstream installer. In particular, nmap is installed via your package
# manager (apt/dnf/apk/brew), so the binary comes from your distro, not from Pulser.
# That is installation, not redistribution, and asks nothing of you under the NPSL.
# Npcap (Windows only) is never touched here.

# No `set -u`: macOS still ships bash 3.2, where an empty array (`${#INSTALLED[@]}`
# before anything has been installed) counts as unset and would abort the summary.
set -eo pipefail

REPO_URL="https://github.com/pseudocoder204-source/Pulser.git"
CACHE_URL="https://github.com/pseudocoder204-source/Pulser/releases/download/v0.1.0-data/vulnerability_cache.db.gz"
DEFAULT_MODEL="pseudocoder204/mark2-report"

# ── flags ─────────────────────────────────────────────────────────────────────
SKIP_OLLAMA=0     # --claude / --skip-ollama: no Ollama, no model pull
SKIP_CACHE=0      # --skip-cache: don't fetch the 3.2 GB CVE cache
SKIP_SHIM=0       # --skip-shim: don't put `pulser` on PATH
ASSUME_YES=0      # --yes: never prompt
MODEL="$DEFAULT_MODEL"
INSTALL_DIR="${PULSER_HOME:-}"

usage() {
    cat <<'EOF'
Pulser installer

  --claude          Using the Anthropic backend: skip Ollama and the model pull
  --skip-ollama     Same as --claude
  --skip-cache      Skip the ~3.2 GB CVE cache download (CVE enrichment degrades)
  --skip-shim       Don't install the `pulser` launcher onto PATH
  --model NAME      Ollama model to pull (default: pseudocoder204/mark2-report)
  --dir PATH        Where to clone Pulser (default: ~/.local/share/pulser)
  --yes, -y         Don't prompt for confirmation
  --help, -h        This message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --claude|--skip-ollama) SKIP_OLLAMA=1 ;;
        --skip-cache)           SKIP_CACHE=1 ;;
        --skip-shim)            SKIP_SHIM=1 ;;
        --yes|-y)               ASSUME_YES=1 ;;
        --model)                MODEL="${2:?--model needs a value}"; shift ;;
        --dir)                  INSTALL_DIR="${2:?--dir needs a value}"; shift ;;
        --help|-h)              usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
done

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

# Confirmation has to come from the terminal, not stdin: under `curl | bash`,
# stdin is the script itself, so `read` would eat the script's own remaining bytes.
confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    [ -e /dev/tty ] || return 0   # non-interactive (CI, piped with no tty): proceed
    local reply=""
    printf '%s' "${BOLD}Proceed?${RESET} [Y/n] " > /dev/tty
    read -r reply < /dev/tty || return 0
    case "$reply" in [nN]*) return 1 ;; *) return 0 ;; esac
}

# A backgrounded `wait $PID` gives zero console output for as long as the job
# runs (a multi-GB model pull or a 3.2 GB cache decompression), which reads as
# a hung installer. Print an elapsed-time heartbeat every few seconds instead,
# then return the child's real exit status via a final `wait`.
wait_with_heartbeat() {
    local pid="$1" label="$2" start elapsed
    start=$(date +%s)
    while kill -0 "$pid" 2>/dev/null; do
        elapsed=$(( $(date +%s) - start ))
        printf '\r  ...  %s (%ss elapsed, still running)  ' "$label" "$elapsed"
        sleep 3
    done
    printf '\r%80s\r' ""
    wait "$pid"
}

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
    [ "$OS" = "Darwin" ] && warn "Install Homebrew first: https://brew.sh"
    exit 1
fi

# ── 0. bootstrap: find or clone the repo ──────────────────────────────────────
# When run from a clone, $BASH_SOURCE sits next to agent.py and we use that tree.
# When piped from curl there is no script on disk, so clone into $INSTALL_DIR.
SRC_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    [ -f "$_d/agent.py" ] && SRC_DIR="$_d"
fi

if [ -n "$SRC_DIR" ]; then
    REPO_DIR="$SRC_DIR"
else
    REPO_DIR="${INSTALL_DIR:-$HOME/.local/share/pulser}"
fi

echo
info "${BOLD}Pulser installer${RESET}  ($OS, $PM)"
echo "  This will:"
if [ -n "$SRC_DIR" ]; then
    echo "    · use the clone at        $REPO_DIR"
else
    echo "    · clone Pulser into       $REPO_DIR"
fi
echo "    · install scanners        nmap, ClamAV, Lynis, Trivy, Nuclei (via $PM / upstream)"
echo "    · create a venv at        $REPO_DIR/.venv"
if [ "$SKIP_OLLAMA" -eq 0 ]; then
    echo "    · install Ollama + pull   $MODEL (multi-GB)"
else
    echo "    · ${DIM}skip Ollama${RESET} (--claude)"
fi
if [ "$SKIP_CACHE" -eq 0 ]; then
    echo "    · download the CVE cache  ~126 MB compressed → ~3.2 GB on disk"
else
    echo "    · ${DIM}skip the CVE cache${RESET} (--skip-cache)"
fi
[ "$SKIP_SHIM" -eq 0 ] && echo "    · install the launcher    $HOME/.local/bin/pulser"
[ -n "$SUDO" ] && echo "    · use ${BOLD}sudo${RESET} for package installs"
echo
confirm || { warn "Aborted."; exit 1; }
echo

if [ -z "$SRC_DIR" ]; then
    if [ -d "$REPO_DIR/.git" ]; then
        info "Updating existing clone at $REPO_DIR"
        git -C "$REPO_DIR" pull --ff-only >/dev/null 2>&1 && ok "Updated" || warn "Could not fast-forward — leaving as-is"
        ALREADY+=("Pulser clone")
    else
        have git || { fail "git not found — install git first"; exit 1; }
        info "Cloning Pulser into $REPO_DIR"
        mkdir -p "$(dirname "$REPO_DIR")"
        git clone --depth 1 "$REPO_URL" "$REPO_DIR" >/dev/null 2>&1 \
            && { ok "Cloned"; INSTALLED+=("Pulser clone"); } \
            || { fail "Clone failed — check your network or clone manually from $REPO_URL"; exit 1; }
    fi
fi

# ── background job 1: the CVE cache ───────────────────────────────────────────
# Kicked off first: it's the longest pole (126 MB down, 3.2 GB decompressed) and
# it's pure network+disk, so it overlaps cleanly with the package installs below.
CACHE_PID=""
CACHE_LOG="$(mktemp)"
CACHE_DB="$REPO_DIR/vulnerability_cache.db"
if [ "$SKIP_CACHE" -eq 1 ]; then
    skip "CVE cache skipped (--skip-cache)"
elif [ -f "$CACHE_DB" ]; then
    ok "CVE cache already present ($(du -h "$CACHE_DB" | cut -f1))"
    ALREADY+=("CVE cache")
else
    info "Downloading the CVE cache in the background (~126 MB → ~3.2 GB)"
    (
        set -e
        # --continue-at - so a dropped connection resumes instead of restarting the
        # whole 126 MB; stream straight through gunzip so the .gz is never kept.
        curl -fL --retry 5 --retry-delay 2 --continue-at - "$CACHE_URL" -o "$CACHE_DB.gz"
        gunzip -c "$CACHE_DB.gz" > "$CACHE_DB.part"
        mv "$CACHE_DB.part" "$CACHE_DB"   # atomic: a killed run never leaves a half DB
        rm -f "$CACHE_DB.gz"
    ) > "$CACHE_LOG" 2>&1 &
    CACHE_PID=$!
fi

# ── background job 2: Ollama + the report model ───────────────────────────────
OLLAMA_PID=""
OLLAMA_LOG="$(mktemp)"
if [ "$SKIP_OLLAMA" -eq 1 ]; then
    skip "Ollama skipped (--claude) — set ANTHROPIC_API_KEY and LLM_PROVIDER=claude"
else
    if have ollama; then
        ok "Ollama already installed"; ALREADY+=("Ollama")
    else
        info "Installing Ollama (upstream installer)"
        if [ "$PM" = "brew" ]; then
            brew install --cask ollama >/dev/null 2>&1 && ok "Ollama installed" && INSTALLED+=("Ollama") \
                || { fail "Ollama install failed"; MANUAL+=("Ollama — https://ollama.com/download"); }
        else
            curl -fsSL https://ollama.com/install.sh | sh >/dev/null 2>&1 && ok "Ollama installed" && INSTALLED+=("Ollama") \
                || { fail "Ollama install failed"; MANUAL+=("Ollama — https://ollama.com/download"); }
        fi
    fi

    OLLAMA_SERVE_LOG="$(mktemp)"
    # Tracks whether THIS run spawned the server. Only a server we ourselves
    # started is ever safe to kill/restart later - one that was already running
    # might be serving other apps or hold state we don't own.
    WE_STARTED_OLLAMA=0
    if have ollama; then
        # The Linux installer registers a systemd service; the macOS cask does not
        # start anything until the app runs. Either way, `ollama pull` needs a live
        # server on :11434, so make sure one is up before pulling.
        if ! curl -fsS --noproxy '*' http://localhost:11434/api/version >/dev/null 2>&1; then
            info "Starting the Ollama server"
            nohup ollama serve > "$OLLAMA_SERVE_LOG" 2>&1 &
            WE_STARTED_OLLAMA=1
            for _ in $(seq 1 30); do
                curl -fsS --noproxy '*' http://localhost:11434/api/version >/dev/null 2>&1 && break
                sleep 1
            done
            # Our own spawn can fail to bind :11434 if the ORIGINAL server was
            # actually up all along and our first check just caught it mid-
            # response - that's not a real outage, so don't credit ourselves with
            # having started anything, and give the real server a beat.
            if ! curl -fsS --noproxy '*' http://localhost:11434/api/version >/dev/null 2>&1 && grep -q "bind:" "$OLLAMA_SERVE_LOG" 2>/dev/null; then
                info "Port already bound by an existing Ollama process — rechecking"
                WE_STARTED_OLLAMA=0
                for _ in $(seq 1 20); do
                    curl -fsS --noproxy '*' http://localhost:11434/api/version >/dev/null 2>&1 && break
                    sleep 1
                done
            fi
        fi
        if curl -fsS --noproxy '*' http://localhost:11434/api/version >/dev/null 2>&1; then
            if ollama list 2>/dev/null | grep -q "^${MODEL%%:*}"; then
                ok "Model $MODEL already pulled"; ALREADY+=("model $MODEL")
            else
                info "Pulling $MODEL in the background (multi-GB — this is the slow part, retries automatically on transient failures)"
                (
                    set -e
                    attempt=1
                    until ollama pull "$MODEL"; do
                        [ "$attempt" -ge 3 ] && exit 1
                        if [ "$WE_STARTED_OLLAMA" -eq 1 ]; then
                            # We own this process's lifecycle (we started it a few
                            # seconds ago in this same run), so it's safe to restart
                            # if its state is broken (e.g. a wiped keypair).
                            echo "--- pull attempt $attempt failed, restarting the Ollama server we started and retrying in 5s ---"
                            pkill -f "ollama serve" 2>/dev/null || true
                            sleep 1
                            nohup ollama serve >/dev/null 2>&1 &
                            sleep 4
                        else
                            # Someone else's server - never kill it out from under them.
                            echo "--- pull attempt $attempt failed - not restarting a pre-existing Ollama server; retrying in 5s ---"
                            sleep 5
                        fi
                        attempt=$((attempt + 1))
                    done
                ) > "$OLLAMA_LOG" 2>&1 &
                OLLAMA_PID=$!
            fi
        else
            warn "Ollama server didn't come up on :11434 — pull the model yourself later"
            tail -n 5 "$OLLAMA_SERVE_LOG" 2>/dev/null | sed 's/^/    /' >&2 || true
            MANUAL+=("ollama serve && ollama pull $MODEL")
        fi
    fi
fi

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

# ── 1. nmap (package-manager install — NOT bundled by Pulser) ─────────────────
# Package names differ by distro; -sV needs the NSE scripts, which are a separate
# package on Alpine (nmap-scripts) but bundled with nmap elsewhere.
case "$PM" in
    apk) pkg_install "nmap" nmap nmap nmap-scripts ;;
    *)   pkg_install "nmap" nmap nmap ;;
esac

# ── 2. ClamAV + Lynis (GPL tools, via package manager) ────────────────────────
pkg_install "ClamAV" clamscan clamav
pkg_install "Lynis" lynis lynis

# ── 3. Trivy + Nuclei ─────────────────────────────────────────────────────────
# On Homebrew both ship as formulae, which is far more reliable than dropping a
# binary into /usr/local/bin by hand (unwritable on Apple Silicon). Everywhere
# else, use each tool's own upstream installer — the same sources the Dockerfile
# uses. Neither path bundles a binary into Pulser.
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
           curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NVER}/nuclei_${NVER}_linux_${NMACH}.zip" -o /tmp/pulser-nuclei.zip && \
           $WBIN unzip -oq /tmp/pulser-nuclei.zip nuclei -d "$BIN_DIR" && have nuclei; then
            rm -f /tmp/pulser-nuclei.zip
            ok "Nuclei installed (v$NVER)"; INSTALLED+=("Nuclei")
            info "Fetching Nuclei templates"
            nuclei -update-templates >/dev/null 2>&1 && ok "Nuclei templates updated" || warn "Template update failed — run 'nuclei -update-templates' later"
        else
            fail "Nuclei install failed"; MISSING+=("Nuclei — see https://github.com/projectdiscovery/nuclei/releases")
        fi
    fi
fi

# ── 4. Python venv + dependencies ─────────────────────────────────────────────
# The installer owns the venv rather than asking the user to make one first. A
# bare `pip install` would fail outright on any PEP 668 distro (Debian/Ubuntu/
# Fedora ship an "externally-managed-environment" marker that blocks it), so
# install into $VENV explicitly and never touch the system interpreter.
VENV="$REPO_DIR/.venv"
VENV_PY="$VENV/bin/python3"
if have python3; then
    if [ ! -x "$VENV_PY" ]; then
        info "Creating a virtualenv at $VENV"
        python3 -m venv "$VENV" || { fail "venv creation failed — is python3-venv installed?"; MISSING+=("python3-venv"); }
    fi
    if [ -x "$VENV_PY" ]; then
        info "Installing Python dependencies into the venv"
        if "$VENV_PY" -m pip install --upgrade pip >/dev/null 2>&1 && \
           "$VENV_PY" -m pip install -r "$REPO_DIR/requirements.txt" >/dev/null 2>&1; then
            ok "Python dependencies installed"; INSTALLED+=("Python deps")
        else
            fail "pip install failed"
            MISSING+=("Python deps — $VENV_PY -m pip install -r $REPO_DIR/requirements.txt")
        fi
    fi
else
    fail "python3 not found — install Python 3.10+ first"
    MISSING+=("Python 3.10+")
fi

# ── 5. the `pulser` launcher ──────────────────────────────────────────────────
# So a user never has to cd into the repo or activate the venv: `pulser` from
# anywhere runs agent.py on the venv's interpreter with all args forwarded.
SHIM_DIR="$HOME/.local/bin"
SHIM="$SHIM_DIR/pulser"
if [ "$SKIP_SHIM" -eq 1 ]; then
    skip "Launcher skipped (--skip-shim)"
elif [ ! -x "$VENV_PY" ]; then
    warn "Skipping the launcher — no venv to point it at"
else
    mkdir -p "$SHIM_DIR"
    # The cd is load-bearing, not cosmetic: agent.py resolves DB_PATH
    # ("vulnerability_cache.db") and SCAN_LOG_DB ("scan_log.db") relative to the
    # working directory. Without it, `pulser` from ~ would miss the CVE cache and
    # silently trigger a full NVD re-sync against an empty DB.
    cat > "$SHIM" <<EOF
#!/usr/bin/env bash
# Pulser launcher — generated by install.sh. Safe to delete.
cd "$REPO_DIR" || exit 1
exec "$VENV_PY" agent.py "\$@"
EOF
    chmod +x "$SHIM"
    ok "Launcher installed at $SHIM"; INSTALLED+=("pulser launcher")
    case ":$PATH:" in
        *":$SHIM_DIR:"*) ;;
        *)
            # macOS has defaulted to zsh since Catalina; Linux distros vary. Target
            # whatever $SHELL actually says, not a hardcoded ~/.bashrc that a zsh
            # user would never source.
            case "${SHELL:-}" in
                */zsh) RC="~/.zshrc" ;;
                *)     RC="~/.bashrc" ;;
            esac
            MANUAL+=("Add $SHIM_DIR to your PATH:  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> $RC")
            ;;
    esac
fi

# ── 6. wait on the background jobs ────────────────────────────────────────────
if [ -n "$OLLAMA_PID" ]; then
    info "Waiting for the $MODEL pull to finish"
    if wait_with_heartbeat "$OLLAMA_PID" "pulling $MODEL"; then
        ok "Model $MODEL pulled"; INSTALLED+=("model $MODEL")
    else
        fail "Model pull failed after retries"; sed -n '$p' "$OLLAMA_LOG" >&2 || true
        MANUAL+=("ollama pull $MODEL")
    fi
fi
if [ -n "$CACHE_PID" ]; then
    info "Waiting for the CVE cache download to finish"
    if wait_with_heartbeat "$CACHE_PID" "downloading + unpacking the CVE cache"; then
        ok "CVE cache ready ($(du -h "$CACHE_DB" 2>/dev/null | cut -f1))"; INSTALLED+=("CVE cache")
    else
        fail "CVE cache download failed"; sed -n '$p' "$CACHE_LOG" >&2 || true
        rm -f "$CACHE_DB.gz" "$CACHE_DB.part"
        MANUAL+=("CVE cache — download $CACHE_URL and gunzip it to $CACHE_DB")
    fi
fi
rm -f "$CACHE_LOG" "$OLLAMA_LOG" "${OLLAMA_SERVE_LOG:-}"

# ── summary ───────────────────────────────────────────────────────────────────
echo
info "${BOLD}Summary${RESET}"
[ ${#INSTALLED[@]} -gt 0 ] && { echo "  Installed now:"; for x in "${INSTALLED[@]}"; do ok "$x"; done; }
[ ${#ALREADY[@]}   -gt 0 ] && { echo "  Already present:"; for x in "${ALREADY[@]}"; do skip "$x"; done; }
[ ${#MISSING[@]}   -gt 0 ] && { echo "  Needs attention:"; for x in "${MISSING[@]}"; do fail "$x"; done; }
[ ${#MANUAL[@]}    -gt 0 ] && { echo "  You must still do yourself:"; for x in "${MANUAL[@]}"; do warn "$x"; done; }

echo
if [ ${#MISSING[@]} -eq 0 ]; then
    if [ "$SKIP_SHIM" -eq 0 ] && [ -x "$SHIM" ]; then
        ok "${GREEN}Ready.${RESET} Run: ${BOLD}pulser${RESET}"
    else
        ok "${GREEN}Ready.${RESET} Run: ${BOLD}$VENV_PY $REPO_DIR/agent.py${RESET}"
    fi
else
    warn "Some components need attention above, but Pulser runs degraded without them (missing scanners report 'unavailable')."
fi
