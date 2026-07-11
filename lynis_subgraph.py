# SPDX-License-Identifier: GPL-2.0-only
"""
lynis_subgraph.py — LangGraph subgraph edition of the Lynis host-security-audit pipeline.

Four stages, each modelled as a LangGraph node:

    [scan_node] → [parse_node] → [enrich_node] → [build_node] → END
          ↓              ↓               ↓               ↓
         END            END             END             END   (on error)

The extra enrich_node is unique to Lynis: it cross-references each test_id against
LYNIS_TEST_CATALOG — a mapping of Lynis test IDs to human-readable descriptions and
remediation steps, written for this project. This fills in the description/solution
fields that the machine-readable report file omits (it stores test_id and severity only).

See the PROVENANCE note above LYNIS_TEST_CATALOG: it only carries test IDs that upstream
Lynis can actually report on, and each description states the condition that was detected.

Usage — standalone:
    python3 lynis_subgraph.py

Usage — as a subgraph node inside a parent graph:
    from lynis_subgraph import build_lynis_subgraph
    parent.add_node("lynis", build_lynis_subgraph())

    No inputs required — Lynis always audits the local host.
    On completion the subgraph writes back: raw_report, parsed_report, payload, error.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

from typing_extensions import TypedDict

from langgraph.graph import END, StateGraph
from display_graph import display_graph

from lynis_parser import (
    build_llm_payload_from_lynis,
    parse_lynis_report,
    run_lynis_audit,
)

# ── Lynis test catalog ─────────────────────────────────────────────────────────
# Maps test_id → {category, description, solution} so the enrich_node can fill in
# the fields that the machine-readable report file omits.
#
# Original text, not copied from Lynis. Keep it that way: Lynis is GPL-3.0 and this
# project is GPL-2.0-only, so pasting upstream text in here would be a license conflict.
#
# PROVENANCE — verified 2026-07-10 against all 43 include/tests_* files in
# CISOfy/lynis@master. For each ID, the `Register --test-no ...` line and every
# ReportWarning/ReportSuggestion call in its block were read directly.
#
# Only warning[] and suggestion[] lines in the report file ever reach
# `priority_findings` (see lynis_parser.build_llm_payload_from_lynis). So a catalog
# entry is only meaningful for a test that actually calls ReportWarning or
# ReportSuggestion, and its `description` must state *the condition that was found*,
# not what the test looks at — it is rendered to the user as a finding.
#
# 17 IDs were removed on 2026-07-10 because they can never appear in a report:
#   - 15 register normally but only ever LogText/Display/AddHP, never
#     ReportWarning/ReportSuggestion: AUTH-9234, AUTH-9252, AUTH-9266, AUTH-9268,
#     CONT-8004, CONT-8102, CRYP-7930, CRYP-8002, FILE-6374, MACF-6290, MALW-3280,
#     SHLL-6220, SHLL-6230, SSH-7440, TOOL-5102.
#   - 2 have no `Register` call at all — they exist only as commented-out placeholder
#     headers upstream: LDAP-2240, LDAP-2244.
# Keeping them meant synth_findings.py fabricated host_audit findings that the real
# pipeline can never emit (e.g. CONT-8004, a Solaris-zone inventory query, surfacing
# as a HIGH finding on a Linux laptop).
#
# SSH-7408 *does* exist upstream (include/tests_ssh) — an earlier revision of this note
# wrongly flagged it as nonexistent.
#
# These strings reach end users via enrich_node and seed synth_findings.py's training
# rows, so a wrong mapping is a wrong report and a poisoned training example.
# Before adding an entry: confirm the ID calls ReportWarning/ReportSuggestion upstream,
# and phrase `description` as the detected condition, in the same voice as its neighbours.

LYNIS_TEST_CATALOG: Dict[str, Dict[str, str]] = {
    # ── AUTH — Authentication ──────────────────────────────────────────────────
    "AUTH-9204": {
        "category":    "Authentication",
        "description": "An account other than root has UID 0, giving it full root-equivalent privileges",
        "solution":    "Remove UID 0 from any account that isn't root: usermod -u <new-uid> <user>, or delete the account with userdel <user>.",
    },
    "AUTH-9208": {
        "category":    "Authentication",
        "description": "Two or more accounts in /etc/passwd share the same UID, so the system cannot tell them apart",
        "solution":    "Give each account a unique UID; list duplicates with: cut -d: -f3 /etc/passwd | sort | uniq -d.",
    },
    "AUTH-9218": {
        "category":    "Authentication",
        "description": "An account with no password has a usable login shell, so it can be logged into without credentials",
        "solution":    "Set the account's shell to /usr/sbin/nologin, or give it a password: passwd <user>.",
    },
    "AUTH-9228": {
        "category":    "Authentication",
        "description": "The account database (/etc/passwd) failed a pwck consistency check — it has duplicate, malformed, or orphaned entries",
        "solution":    "Review the problems with pwck -r, then run pwck to correct each one.",
    },
    "AUTH-9262": {
        "category":    "Authentication",
        "description": "No PAM password-strength module (pam_pwquality, pam_cracklib, or pam_passwdqc) is installed, so weak passwords are accepted",
        "solution":    "Install a password-strength module: apt install libpam-pwquality; enable it in /etc/pam.d/common-password.",
    },
    "AUTH-9282": {
        "category":    "Authentication",
        "description": "Password-protected accounts have no password expiration date set",
        "solution":    "Set an expiry policy on interactive accounts: chage -M 90 <user>; set PASS_MAX_DAYS in /etc/login.defs for new accounts.",
    },
    "AUTH-9286": {
        "category":    "Authentication",
        "description": "Minimum and/or maximum password age is not configured in /etc/login.defs",
        "solution":    "Set PASS_MIN_DAYS=1 and PASS_MAX_DAYS=90 in /etc/login.defs; apply to existing accounts with chage -m 1 -M 90 <user>.",
    },
    "AUTH-9288": {
        "category":    "Authentication",
        "description": "One or more accounts have a password that has passed its expiration date and may no longer be in use",
        "solution":    "Reset the password (passwd <user>) or remove the account if it's no longer needed: userdel <user>.",
    },

    # ── BOOT — Bootloader ──────────────────────────────────────────────────────
    "BOOT-5122": {
        "category":    "Boot",
        "description": "The GRUB bootloader has no password set, so anyone at the keyboard can alter boot options or boot to single-user mode",
        "solution":    "Set a GRUB superuser password (generate one with grub-mkpasswd-pbkdf2) and rebuild the config: update-grub.",
    },
    "BOOT-5180": {
        "category":    "Boot",
        "description": "The set of services started at boot for the current runlevel could not be fully determined",
        "solution":    "Review what starts at boot (systemctl list-unit-files --state=enabled) and disable anything unnecessary: systemctl disable <service>.",
    },

    # ── CRYP — Cryptography ───────────────────────────────────────────────────
    "CRYP-7902": {
        "category":    "Cryptography",
        "description": "One or more SSL/TLS certificates on this device have expired or are close to expiring",
        "solution":    "Renew the expired certificates; automate future renewals with an ACME client such as certbot.",
    },

    # ── FILE — File permissions ────────────────────────────────────────────────
    "FILE-6310": {
        "category":    "File Permissions",
        "description": "/home, /tmp, or /var is not on its own partition, so filling one can fill the whole root filesystem",
        "solution":    "Give /home, /tmp, and /var dedicated partitions at your next repartition or reinstall.",
    },
    "FILE-6362": {
        "category":    "File Permissions",
        "description": "/tmp does not have the sticky bit set, so any user can delete another user's files there",
        "solution":    "Set the sticky bit: chmod +t /tmp.",
    },
    "FILE-6430": {
        "category":    "File Permissions",
        "description": "Unused filesystem kernel modules (cramfs, hfs, jffs2, udf, and similar) are loadable and not disabled",
        "solution":    "Disable them in /etc/modprobe.d/: e.g. add 'install cramfs /bin/true'.",
    },

    # ── FINT — File Integrity ─────────────────────────────────────────────────
    "FINT-4350": {
        "category":    "File Integrity",
        "description": "No file integrity monitoring (FIM) tool detected",
        "solution":    "Install AIDE (apt install aide) and initialise a baseline: aideinit; schedule daily aide --check via cron.",
    },
    "FINT-4402": {
        "category":    "File Integrity",
        "description": "AIDE is configured to create checksums with a weak hash algorithm rather than SHA-256 or SHA-512",
        "solution":    "Change the AIDE rules to use sha256 or sha512 and drop md5, then rebuild the baseline: aide --init.",
    },

    # ── FIRE — Firewall ───────────────────────────────────────────────────────
    "FIRE-4512": {
        "category":    "Firewall",
        "description": "iptables ruleset is empty — no firewall rules active",
        "solution":    "Define a default-deny policy and add explicit ACCEPT rules for required services.",
    },
    "FIRE-4590": {
        "category":    "Firewall",
        "description": "No active firewall (iptables, nftables, or ufw) detected",
        "solution":    "Enable ufw (ufw enable) or start nftables and load a hardened ruleset.",
    },

    # ── HOME — Home directories ───────────────────────────────────────────────
    "HOME-9304": {
        "category":    "Home Directories",
        "description": "One or more home directories have permissions loose enough for other users to read them",
        "solution":    "Tighten each interactive account's home directory: chmod 750 /home/<user>.",
    },
    "HOME-9310": {
        "category":    "Home Directories",
        "description": "A shell history file is not a regular file (it may be a symlink), which can indicate tampering or an attempt to discard history",
        "solution":    "Inspect the history file and replace it with a regular file owned by that account; only set HISTFILE=/dev/null in configs you intend to.",
    },

    # ── HRDN — Hardening ──────────────────────────────────────────────────────
    "HRDN-7222": {
        "category":    "Hardening",
        "description": "Compiler binaries are world-accessible — restrict to root/admin group",
        "solution":    "Restrict compiler access: chmod 750 /usr/bin/gcc; chown root:adm /usr/bin/gcc.",
    },
    "HRDN-7230": {
        "category":    "Hardening",
        "description": "No malware scanner installed on this host",
        "solution":    "Install ClamAV (apt install clamav clamav-daemon) and configure freshclam for signature updates.",
    },

    # ── HTTP — Web servers ────────────────────────────────────────────────────
    "HTTP-6640": {
        "category":    "Web Servers",
        "description": "Apache mod_evasive (DDoS/brute-force protection) not installed",
        "solution":    "Install libapache2-mod-evasive and configure DOSPageCount, DOSSiteCount thresholds.",
    },
    "HTTP-6643": {
        "category":    "Web Servers",
        "description": "Apache mod_security (WAF) not installed",
        "solution":    "Install libapache2-mod-security2 and enable the OWASP ModSecurity Core Rule Set.",
    },
    "HTTP-6660": {
        "category":    "Web Servers",
        "description": "Apache TraceEnable directive is not disabled (HTTP TRACE method active)",
        "solution":    "Add 'TraceEnable Off' to Apache's main config or VirtualHost block.",
    },

    # ── INSE — Insecure services ──────────────────────────────────────────────
    "INSE-8016": {
        "category":    "Insecure Services",
        "description": "Telnet is enabled as a service through inetd/xinetd — it sends passwords in cleartext",
        "solution":    "Remove the telnet entry from the inetd/xinetd configuration and use SSH instead.",
    },
    "INSE-8300": {
        "category":    "Insecure Services",
        "description": "The rsh client package is installed — rsh transmits credentials in cleartext",
        "solution":    "Remove it if unused: apt purge rsh-client; use the ssh client instead.",
    },
    "INSE-8322": {
        "category":    "Insecure Services",
        "description": "Telnet server is installed and/or running",
        "solution":    "Remove telnetd: apt purge telnetd; use SSH instead.",
    },

    # ── KRNL — Kernel ────────────────────────────────────────────────────────
    "KRNL-5820": {
        "category":    "Kernel",
        "description": "Kernel core dumps are not disabled",
        "solution":    "Add 'fs.suid_dumpable=0' to /etc/sysctl.d/99-hardening.conf; set 'ulimit -c 0' in /etc/profile.",
    },
    "KRNL-5830": {
        "category":    "Kernel",
        "description": "System requires a reboot to activate a newly installed kernel",
        "solution":    "Schedule a maintenance window and reboot: shutdown -r now.",
    },
    "KRNL-6000": {
        "category":    "Kernel",
        "description": "One or more sysctl hardening parameters are not set to the recommended value",
        "solution":    "Apply kernel hardening in /etc/sysctl.d/99-hardening.conf: kernel.randomize_va_space=2, "
                       "net.ipv4.conf.all.rp_filter=1, net.ipv4.conf.all.accept_redirects=0, "
                       "kernel.dmesg_restrict=1; run sysctl --system.",
    },

    # ── LOGG — Logging ────────────────────────────────────────────────────────
    "LOGG-2154": {
        "category":    "Logging",
        "description": "No remote syslog server configured",
        "solution":    "Configure rsyslog/syslog-ng to forward logs to a central log server or SIEM.",
    },
    "LOGG-2190": {
        "category":    "Logging",
        "description": "Open log file handles detected for deleted files (log rotation gap)",
        "solution":    "Restart daemons with deleted log handles: systemctl restart <service>; run logrotate.",
    },

    # ── MACF — MAC Frameworks ─────────────────────────────────────────────────
    "MACF-6208": {
        "category":    "MAC Frameworks",
        "description": "AppArmor is not enabled or not in enforcing mode",
        "solution":    "Enable AppArmor: aa-enforce /etc/apparmor.d/*; add security=apparmor to kernel cmdline.",
    },
    "MACF-6234": {
        "category":    "MAC Frameworks",
        "description": "SELinux is not enabled or not in enforcing mode",
        "solution":    "Set SELINUX=enforcing in /etc/selinux/config and relabel the filesystem (touch /.autorelabel).",
    },

    # ── MAIL — Mail ───────────────────────────────────────────────────────────
    "MAIL-8818": {
        "category":    "Mail",
        "description": "Postfix SMTP banner reveals version or OS information",
        "solution":    "Set 'smtpd_banner = $myhostname ESMTP' in /etc/postfix/main.cf; reload postfix.",
    },
    "MAIL-8820": {
        "category":    "Mail",
        "description": "SMTP VRFY command is enabled — allows user enumeration",
        "solution":    "Disable VRFY in Postfix: set 'disable_vrfy_command = yes' in main.cf.",
    },

    # ── MALW — Malware ────────────────────────────────────────────────────────
    "MALW-3286": {
        "category":    "Malware",
        "description": "freshclam anti-virus signature update daemon is not running",
        "solution":    "Enable freshclam: systemctl enable --now clamav-freshclam.",
    },

    # ── NAME — Name services ───────────────────────────────────────────────────
    "NAME-4210": {
        "category":    "Name Services",
        "description": "BIND nameserver version is exposed in DNS responses",
        "solution":    "Hide BIND version: set 'version \"none\";' inside the options block of named.conf.",
    },
    "NAME-4304": {
        "category":    "Name Services",
        "description": "NIS (YP) is in use — transmits credentials in cleartext",
        "solution":    "Migrate from NIS to LDAP with TLS or Kerberos for secure directory services.",
    },

    # ── NETW — Networking ─────────────────────────────────────────────────────
    "NETW-3015": {
        "category":    "Networking",
        "description": "A network interface is in promiscuous mode — possible packet sniffing",
        "solution":    "Investigate the interface: ip link show; disable promiscuous mode: ip link set <iface> promisc off.",
    },
    "NETW-3032": {
        "category":    "Networking",
        "description": "No ARP monitoring tool installed — ARP spoofing attacks undetected",
        "solution":    "Install arpwatch: apt install arpwatch; systemctl enable --now arpwatch.",
    },
    "NETW-3200": {
        "category":    "Networking",
        "description": "Uncommon/unused network protocols (dccp, sctp, rds, tipc) are not disabled",
        "solution":    "Blacklist protocols in /etc/modprobe.d/disable-net-protocols.conf: 'install dccp /bin/true'.",
    },

    # ── PHP — PHP ─────────────────────────────────────────────────────────────
    "PHP-2320": {
        "category":    "PHP",
        "description": "Dangerous PHP functions (exec, passthru, shell_exec, system) are enabled",
        "solution":    "Add to php.ini: disable_functions = exec,passthru,shell_exec,system,popen,proc_open.",
    },
    "PHP-2372": {
        "category":    "PHP",
        "description": "PHP expose_php is On — version disclosed in HTTP headers",
        "solution":    "Set 'expose_php = Off' in php.ini.",
    },
    "PHP-2376": {
        "category":    "PHP",
        "description": "PHP allow_url_fopen is On — enables remote file inclusion (RFI) risk",
        "solution":    "Set 'allow_url_fopen = Off' in php.ini.",
    },

    # ── PKGS — Packages ───────────────────────────────────────────────────────
    "PKGS-7346": {
        "category":    "Packages",
        "description": "Packages in rc state have residual config files that were not purged",
        "solution":    "Purge residual configs: dpkg --purge $(dpkg -l | awk '/^rc/{print $2}').",
    },
    "PKGS-7392": {
        "category":    "Packages",
        "description": "Pending Debian/Ubuntu security updates available",
        "solution":    "Apply security patches immediately: apt-get update && apt-get upgrade.",
    },
    "PKGS-7420": {
        "category":    "Packages",
        "description": "Automatic security updates are not configured",
        "solution":    "Install and enable unattended-upgrades: apt install unattended-upgrades; dpkg-reconfigure unattended-upgrades.",
    },

    # ── PRNT — Printing ───────────────────────────────────────────────────────
    "PRNT-2307": {
        "category":    "Printing",
        "description": "CUPS configuration file has insecure permissions",
        "solution":    "Restrict permissions: chmod 640 /etc/cups/cupsd.conf; chown root:lp /etc/cups/cupsd.conf.",
    },
    "PRNT-2308": {
        "category":    "Printing",
        "description": "CUPS is listening on a network interface (not restricted to localhost)",
        "solution":    "Restrict CUPS: set 'Listen 127.0.0.1:631' in /etc/cups/cupsd.conf; restart CUPS.",
    },

    # ── PROC — Processes ──────────────────────────────────────────────────────
    "PROC-3612": {
        "category":    "Processes",
        "description": "Zombie processes detected — child processes not reaped by parent",
        "solution":    "Identify zombie parents with ps aux | grep Z; restart or fix the parent process.",
    },
    "PROC-3614": {
        "category":    "Processes",
        "description": "High I/O wait detected — possible disk bottleneck or failing drive",
        "solution":    "Diagnose with iostat -x 1 10; check for failing drives with smartctl -a /dev/sdX.",
    },

    # ── SCHD — Scheduling ────────────────────────────────────────────────────
    "SCHD-7704": {
        "category":    "Scheduling",
        "description": "Crontab or cron directory files have insecure permissions",
        "solution":    "Restrict crontab: chmod 600 /etc/crontab; ensure /etc/cron.d/ files are owned by root:root.",
    },

    # ── SNMP — SNMP ───────────────────────────────────────────────────────────
    "SNMP-3306": {
        "category":    "SNMP",
        "description": "SNMP is configured with default community strings (public/private)",
        "solution":    "Change default community strings to unique values; migrate to SNMPv3 with authPriv security level.",
    },

    # ── SSH — SSH ─────────────────────────────────────────────────────────────
    "SSH-7408": {
        "category":    "SSH",
        "description": "SSH server configuration has one or more insecure settings "
                       "(e.g., PermitRootLogin, PasswordAuthentication, Protocol version, MaxAuthTries)",
        "solution":    "Harden /etc/ssh/sshd_config: PermitRootLogin no, Protocol 2, "
                       "PasswordAuthentication no, MaxAuthTries 3, "
                       "ClientAliveInterval 300, ClientAliveCountMax 2, "
                       "AllowTcpForwarding no, X11Forwarding no; reload: systemctl reload sshd.",
    },

    # ── STRG — Storage ────────────────────────────────────────────────────────
    "STRG-1846": {
        "category":    "Storage",
        "description": "FireWire kernel module is loaded — susceptible to DMA-based memory attacks",
        "solution":    "Blacklist FireWire: add 'blacklist firewire-core' to /etc/modprobe.d/blacklist.conf; unload: rmmod firewire-core.",
    },
    "STRG-1930": {
        "category":    "Storage",
        "description": "NFS export access controls are too permissive",
        "solution":    "Restrict NFS exports in /etc/exports: add root_squash, nosuid, noexec options per export.",
    },

    # ── TIME — Time/NTP ───────────────────────────────────────────────────────
    "TIME-3104": {
        "category":    "Time/NTP",
        "description": "No NTP daemon (chronyd, ntpd, timesyncd) is running — clock may drift",
        "solution":    "Enable NTP synchronisation: systemctl enable --now chronyd (or ntpd/systemd-timesyncd).",
    },
    "TIME-3116": {
        "category":    "Time/NTP",
        "description": "NTP stratum is 16 — clock is not synchronised to any time source",
        "solution":    "Configure NTP servers in /etc/chrony.conf (e.g., pool pool.ntp.org iburst); restart chronyd.",
    },

    # ── TOOL — Tooling / IDS ──────────────────────────────────────────────────
    "TOOL-5190": {
        "category":    "Tooling",
        "description": "No IDS/IPS (Snort, Suricata, OSSEC/Wazuh) installed",
        "solution":    "Install Suricata (apt install suricata) or Wazuh for host-based and network intrusion detection.",
    },

    # ── USB — USB ─────────────────────────────────────────────────────────────
    "USB-1000": {
        "category":    "USB",
        "description": "USB storage kernel module is not disabled — external drives can be mounted",
        "solution":    "Blacklist USB storage: add 'blacklist usb-storage' to /etc/modprobe.d/blacklist.conf.",
    },
    "USB-3000": {
        "category":    "USB",
        "description": "USBGuard is not installed — no USB device whitelist enforced",
        "solution":    "Install USBGuard: apt install usbguard; run usbguard generate-policy > /etc/usbguard/rules.conf.",
    },
}

# ── State ──────────────────────────────────────────────────────────────────────

class LynisSubgraphState(TypedDict):
    # Optional input — override via env var LYNIS_REPORT_FILE or pass directly
    report_file: str

    # Stage outputs — populated as the pipeline progresses
    raw_report:    str              # Stage 1: raw Lynis report file content
    parsed_report: Dict[str, Any]  # Stage 2: structured warnings/suggestions/metadata
    payload:       Dict[str, Any]  # Stage 4: condensed LLM-ready payload

    # Set by any node on failure; causes the graph to route to END early
    error: Optional[str]

# ── Nodes ──────────────────────────────────────────────────────────────────────

def _scan_node(state: LynisSubgraphState) -> Dict[str, Any]:
    """Stage 1 — Run the Lynis host-security audit and capture the report file."""
    report_file = state.get("report_file") or "/tmp/lynis-report.dat"
    print(f"[lynis/scan]   launching audit (report → {report_file!r})...", file=sys.stderr)
    try:
        raw_report = run_lynis_audit(report_file=report_file)
        if not raw_report:
            return {"error": "Lynis audit produced an empty report — is lynis installed?"}
        lines = raw_report.count("\n")
        print(f"[lynis/scan]   captured {lines} report lines.", file=sys.stderr)
        return {"raw_report": raw_report}
    except Exception as exc:
        return {"error": str(exc)}


def _parse_node(state: LynisSubgraphState) -> Dict[str, Any]:
    """Stage 2 — Parse the key=value report file into structured dicts."""
    print("[lynis/parse]  parsing report file...", file=sys.stderr)
    try:
        parsed = parse_lynis_report(state["raw_report"])
        w = len(parsed.get("warnings", []))
        s = len(parsed.get("suggestions", []))
        print(f"[lynis/parse]  {w} warning(s), {s} suggestion(s) extracted.", file=sys.stderr)
        return {"parsed_report": parsed}
    except Exception as exc:
        return {"error": str(exc)}


def _enrich_node(state: LynisSubgraphState) -> Dict[str, Any]:
    """Stage 3 — Cross-reference each test_id against LYNIS_TEST_CATALOG.

    Lynis's machine-readable report file stores only test_id and severity;
    the human-readable description and remediation steps are in the catalog.
    This node fills in any empty description/solution fields and attaches
    a category tag to every finding.
    """
    print("[lynis/enrich] enriching findings from test catalog...", file=sys.stderr)
    try:
        parsed = state["parsed_report"]

        def _enrich_list(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            enriched = []
            for f in findings:
                tid  = f.get("test_id", "")
                meta = LYNIS_TEST_CATALOG.get(tid, {})
                entry = dict(f)
                entry["category"] = meta.get("category", _infer_category(tid))
                # Only fill description/solution if the report left them blank or as "-"
                if not entry.get("description") or entry["description"] in ("-", ""):
                    entry["description"] = meta.get("description", "")
                if not entry.get("solution") or entry["solution"] in ("-", ""):
                    entry["solution"] = meta.get("solution", "")
                enriched.append(entry)
            return enriched

        enriched_parsed = dict(parsed)
        enriched_parsed["warnings"]    = _enrich_list(parsed.get("warnings", []))
        enriched_parsed["suggestions"] = _enrich_list(parsed.get("suggestions", []))

        catalog_hits = sum(
            1 for f in enriched_parsed["warnings"] + enriched_parsed["suggestions"]
            if f.get("test_id", "") in LYNIS_TEST_CATALOG
        )
        print(
            f"[lynis/enrich] {catalog_hits} test ID(s) matched in catalog "
            f"({len(LYNIS_TEST_CATALOG)} entries).",
            file=sys.stderr,
        )
        return {"parsed_report": enriched_parsed}
    except Exception as exc:
        return {"error": str(exc)}


def _infer_category(test_id: str) -> str:
    """Derive a human-readable category from the test_id prefix when not in catalog."""
    _PREFIX_MAP = {
        "AUTH": "Authentication", "BOOT": "Boot",    "CONT": "Containers",
        "CRYP": "Cryptography",  "DBS":  "Databases","DNS":  "DNS",
        "FILE": "File Permissions", "FINT": "File Integrity", "FIRE": "Firewall",
        "HOME": "Home Directories", "HRDN": "Hardening", "HTTP": "Web Servers",
        "INSE": "Insecure Services", "KRB":  "Kerberos", "KRNL": "Kernel",
        "LDAP": "LDAP",  "LOGG": "Logging", "MACF": "MAC Frameworks",
        "MAIL": "Mail",  "MALW": "Malware", "NAME": "Name Services",
        "NETW": "Networking", "PHP": "PHP", "PKGS": "Packages",
        "PRNT": "Printing", "PROC": "Processes", "RBAC": "RBAC",
        "SCHD": "Scheduling", "SHLL": "Shell", "SINT": "System Integrity",
        "SNMP": "SNMP",  "SQD":  "Squid Proxy", "SSH":  "SSH",
        "STRG": "Storage", "TIME": "Time/NTP", "TOOL": "Tooling",
        "USB":  "USB",   "VIRT": "Virtualization",
    }
    prefix = test_id.split("-")[0] if "-" in test_id else test_id[:4]
    return _PREFIX_MAP.get(prefix, "General")


def _build_node(state: LynisSubgraphState) -> Dict[str, Any]:
    """Stage 4 — Condense the enriched parsed report into a ranked LLM-ready payload."""
    print("[lynis/build]  condensing findings for LLM context...", file=sys.stderr)
    try:
        payload = build_llm_payload_from_lynis(state["parsed_report"])
        total   = payload.get("risk_summary", {}).get("total_actionable", 0)
        idx     = payload.get("hardening_index")
        print(
            f"[lynis/build]  enrichment complete — {total} actionable finding(s), "
            f"hardening index: {idx}/100.",
            file=sys.stderr,
        )
        return {"payload": payload}
    except Exception as exc:
        return {"error": str(exc)}

# ── Routing ────────────────────────────────────────────────────────────────────

def _route(state: LynisSubgraphState) -> str:
    """Continue to the next node unless a previous node set an error."""
    return "error" if state.get("error") else "ok"

# ── Graph factory ──────────────────────────────────────────────────────────────

def build_lynis_subgraph():
    """Build and compile the Lynis parser subgraph.

    Returns a compiled CompiledStateGraph that can be:
      • Invoked directly:  app.invoke({...})  / app.stream({...})
      • Embedded as a node in a parent graph via parent.add_node("lynis", build_lynis_subgraph())

    No inputs are required — Lynis always audits the local host.
    On completion the subgraph populates:
        raw_report, parsed_report, payload, error
    """
    graph = StateGraph(LynisSubgraphState)

    graph.add_node("scan",   _scan_node)
    graph.add_node("parse",  _parse_node)
    graph.add_node("enrich", _enrich_node)
    graph.add_node("build",  _build_node)

    graph.set_entry_point("scan")

    graph.add_conditional_edges("scan",   _route, {"ok": "parse",  "error": END})
    graph.add_conditional_edges("parse",  _route, {"ok": "enrich", "error": END})
    graph.add_conditional_edges("enrich", _route, {"ok": "build",  "error": END})
    graph.add_conditional_edges("build",  _route, {"ok": END,      "error": END})

    return graph.compile()

# ── Convenience wrapper ────────────────────────────────────────────────────────

def run_pipeline(report_file: str = "/tmp/lynis-report.dat") -> Dict[str, Any]:
    """Run the full scan → parse → enrich → build pipeline.

    Mirrors the original lynis_parser.py interface so this module can be swapped
    in wherever build_llm_payload_from_lynis output is expected.

    Raises RuntimeError if any stage fails.
    """
    app = build_lynis_subgraph()
    display_graph(app)
    final_state = app.invoke({
        "report_file":   report_file,
        "raw_report":    "",
        "parsed_report": {},
        "payload":       {},
        "error":         None,
    })
    if final_state.get("error"):
        raise RuntimeError(f"Lynis pipeline failed: {final_state['error']}")
    return final_state["payload"]

# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    report_file = os.environ.get("LYNIS_REPORT_FILE", "/tmp/lynis-report.dat")
    print("[lynis_subgraph] auditing local host...", file=sys.stderr)
    try:
        payload = run_pipeline(report_file=report_file)
        print(json.dumps(payload, indent=2))
    except RuntimeError as exc:
        print(f"[lynis_subgraph] {exc}", file=sys.stderr)
        sys.exit(1)
