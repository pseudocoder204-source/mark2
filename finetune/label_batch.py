# SPDX-License-Identifier: GPL-2.0-only
"""One-off batch-labeling helper for trainset.db rows (FinetuneGuide.txt Step 4/5).

Not part of the shipped pipeline — a scratch script used interactively through Claude
Code to draft gold report JSON for a range of rows, then run it through the real
validators (agent.py) before promoting status to 'validated'.

Usage: python3 finetune/label_batch.py <lo> <hi> [--relabel]
  --relabel  re-draft rows already labeled/validated in this range (default: pending only)
"""

import json
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import _validate_report_text, _validate_report_severities, _parse_report, build_findings_table, _CVE_RE, _CPE_RE
from scanners.lynis.lynis_subgraph import LYNIS_TEST_CATALOG


def _clean_refs(refs, limit=2):
    """http(s) links only, and never one containing a raw CVE/CPE literal in the path —
    _validate_report_text scans the WHOLE output text, references included."""
    out = []
    for r in refs or []:
        if not isinstance(r, str) or not r.startswith("http"):
            continue
        if _CVE_RE.search(r) or _CPE_RE.search(r):
            continue
        out.append(r)
        if len(out) == limit:
            break
    return out

_SERVICE_BLURB = {
    "ssh": "You can log into this device remotely, and it's set up fine — nothing to worry about.",
    "http": "This device hosts a website, and it looks good — nothing to worry about.",
    "https": "This device hosts a website over a secure connection — that's the safer way to do it, and everything checks out.",
    "smb": "File sharing is turned on here, and it's set up fine — nothing to worry about.",
    "mysql": "This device stores information in a database behind the scenes, and everything checks out.",
    "http-proxy": "There's a second web service running on this device, and it looks good.",
    "telnet": "This device can be reached with an older, less secure remote-login method. We didn't find anything actively wrong with it, but newer alternatives (like SSH) are generally safer if you have a choice.",
    "upnp": "This device can automatically find other devices on your network — a common convenience feature — and everything checks out.",
}

# Low-severity findings that DO have a description (a CVE matched, just a low score) —
# a lighter-touch good_news phrasing than the generic _SERVICE_BLURB, keyed by the
# exact `description` text from the finding.
_GOOD_NEWS_WITH_DESC = {
    "In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences.":
        "This device's older remote-login software had a very minor, low-risk quirk (it could hide filenames in certain archive listings) — nothing that puts you at real risk.",
}

# Real, human-reviewed translations of the CVE descriptions this batch's finding pool
# draws from (see FinetuneGuide.txt PHASE 1B — the 8-service CPE pool recurs across
# profiles, so this table is reused/extended in later batches, not rebuilt per-batch).
# Keyed by the exact `description` string on the finding.
_FINDING_TRANSLATIONS = {
    "An attacker-controlled pointer free in Busybox's hush applet leads to denial of service and possible code execution when processing a crafted shell command, due to the shell mishandling the &&& string. This may be used for remote code execution under rare conditions of filtered command input.": {
        "title": "A serious flaw in this device's remote-command software",
        "what_it_means": "The software that lets someone send commands to this device remotely has a bug that could let an attacker crash it or, in rare cases, run their own commands on it.",
        "why_it_matters": "This is one of the more serious kinds of issues, because an attacker doesn't need a password to attempt it.",
        "how_to_fix": "1. Check whether this device's manufacturer has a firmware update available, and install it.\n2. If you don't use remote command access on this device, turn it off in its settings.\n3. If you can't update it, keep this device off the open internet and only reachable from your home network.",
    },
    "The installation scripts in the Gentoo dev-db/mysql, dev-db/mariadb, dev-db/percona-server, dev-db/mysql-cluster, and dev-db/mariadb-galera packages before 2017-09-29 have chown calls for user-writable directory trees, which allows local users to gain privileges by leveraging access to the mysql account for creation of a link.": {
        "title": "A permissions issue in how this device's database software was set up",
        "what_it_means": "The way your database software's files were installed could let another account on this same device gain more access than it should have.",
        "why_it_matters": "This mainly matters if other people or programs already have some access to this device — it could let them go from limited access to full control.",
        "how_to_fix": "1. Update your database software to the latest version, which fixes this installation issue.\n2. Make sure you recognize and trust every user account on this device.",
    },
    "MiniUPnPd has information disclosure use of snprintf()": {
        "title": "Your network device-discovery service could leak information",
        "what_it_means": "A bug in the service that lets devices find each other on your network could let an attacker see internal information they shouldn't have access to.",
        "why_it_matters": "This is worth fixing soon since it doesn't require a password and could hand an attacker useful details about your device.",
        "how_to_fix": "1. Update this device's firmware or UPnP software to the latest version.\n2. If you don't rely on devices auto-discovering each other (UPnP), turn that feature off in your router/device settings.\n3. Avoid exposing this device directly to the internet.",
    },
    "If, after successful installation of MantisBT through 2.5.2 on MySQL/MariaDB, the administrator does not remove the 'admin' directory (as recommended in the \"Post-installation and upgrade tasks\" section of the MantisBT Admin Guide), and the MySQL client has a local_infile setting enabled (in php.ini mysqli.allow_local_infile, or the MySQL client config file, depending on the PHP setup), an attacker may take advantage of MySQL's \"connect file read\" feature to remotely access files on the MantisBT server.": {
        "title": "A database configuration issue could expose files on this device",
        "what_it_means": "Under certain setup conditions, this device's database service could be tricked into reading files it shouldn't have access to.",
        "why_it_matters": "If exploited, someone could view files stored on this device without ever needing to log in.",
        "how_to_fix": "1. Update the database software to the latest version.\n2. If you installed any web applications that use this database, make sure their setup/installer folders were removed after setup.\n3. Turn off the database's remote 'file read' feature if you don't specifically need it.",
    },
    "OpenSSH 7.7 through 7.9 and 8.x before 8.1, when compiled with an experimental key type, has a pre-authentication integer overflow if a client or server is configured to use a crafted XMSS key. This leads to memory corruption and local code execution because of an error in the XMSS key parsing algorithm. NOTE: the XMSS implementation is considered experimental in all released OpenSSH versions, and there is no supported way to enable it when building portable OpenSSH.": {
        "title": "A rare bug tied to an experimental remote-login feature",
        "what_it_means": "This device's remote-login software (SSH) has a bug tied to an experimental, rarely-used key type.",
        "why_it_matters": "This only matters if that unusual feature was specifically turned on, which is uncommon — but if it was, an attacker could potentially crash the service or run code on the device.",
        "how_to_fix": "1. Update the SSH software to the latest version.\n2. Unless you know you specifically enabled this experimental feature, no further action is needed.",
    },
    "OpenSSH 5.6 and earlier, when J-PAKE is enabled, does not properly validate the public parameters in the J-PAKE protocol, which allows remote attackers to bypass the need for knowledge of the shared secret, and successfully authenticate, by sending crafted values in each round of the protocol, a related issue to CVE-2010-4252.": {
        "title": "A serious flaw could let someone log in without the correct password",
        "what_it_means": "This device's remote-login software (SSH) has a bug in one of its authentication methods that could let an attacker skip the normal password check.",
        "why_it_matters": "This is rated urgent because it could let an attacker gain remote access to the device without ever knowing the password.",
        "how_to_fix": "1. Update the SSH software to the latest version immediately.\n2. If your device's settings let you choose the authentication method, switch to a standard password or key-based login.\n3. Use a strong, unique password either way.",
    },
    "Integer signedness error in MiniUPnP MiniUPnPc v1.4.20101221 through v2.0 allows remote attackers to cause a denial of service or possibly have unspecified other impact.": {
        "title": "A bug in your network device-discovery service could crash it",
        "what_it_means": "A flaw in the software that lets devices find each other on your network could be used to crash that service.",
        "why_it_matters": "An attacker on your network — and in some setups, the internet — could knock this service offline.",
        "how_to_fix": "1. Update this device's firmware or UPnP software to the latest version.\n2. If you don't rely on automatic device discovery, turn UPnP off.\n3. Avoid exposing this device directly to the internet.",
    },
    "The NETLOGON service in Samba 3.x and 4.x before 4.2.11, 4.3.x before 4.3.8, and 4.4.x before 4.4.2, when a domain controller is configured, allows remote attackers to spoof the computer name of a secure channel's endpoint, and obtain sensitive session information, by running a crafted application and leveraging the ability to sniff network traffic, a related issue to CVE-2015-0005.": {
        "title": "A flaw in your file-sharing service could leak session information",
        "what_it_means": "This device's file-sharing software (Samba) has a bug that could let someone on your network impersonate part of the sign-in process and see session details.",
        "why_it_matters": "Someone already connected to your local network could use this to learn information they shouldn't have — it can't be done from outside your home network.",
        "how_to_fix": "1. Update the file-sharing (Samba) software to the latest version.\n2. Make sure your Wi-Fi network has a strong password so untrusted people can't get onto your local network in the first place.",
    },
    "Out-of-bounds Read vulnerability in mod_macro of Apache HTTP Server.This issue affects Apache HTTP Server: through 2.4.57.": {
        "title": "A bug in your website software",
        "what_it_means": "The software that runs your website has a flaw in one of its optional add-ons that could cause it to crash or behave unexpectedly.",
        "why_it_matters": "In the worst case, this could let someone disrupt your website or, more rarely, view data it shouldn't reveal.",
        "how_to_fix": "1. Update the web server software to the latest version.\n2. If you don't specifically use this add-on (mod_macro), consider turning it off.",
    },
    "ssh-keysign.c in ssh-keysign in OpenSSH before 5.8p2 on certain platforms executes ssh-rand-helper with unintended open file descriptors, which allows local users to obtain sensitive key information via the ptrace system call.": {
        "title": "A local information-leak bug in a remote-login helper tool",
        "what_it_means": "A helper tool used during SSH login has a bug that could let another local user on this device see sensitive key information.",
        "why_it_matters": "This mainly matters if multiple people or accounts share this device — it doesn't allow attacks from outside the device by itself.",
        "how_to_fix": "1. Update the SSH software to the latest version.\n2. Make sure you trust every user account that has access to this device.",
    },
    "In Eclipse Jetty version 7.x, 8.x, 9.2.27 and older, 9.3.26 and older, and 9.4.16 and older, the server running on any OS and Jetty version combination will reveal the configured fully qualified directory base resource location on the output of the 404 error for not finding a Context that matches the requested path. The default server behavior on jetty-distribution and jetty-home will include at the end of the Handler tree a DefaultHandler, which is responsible for reporting this 404 error, it presents the various configured contexts as HTML for users to click through to. This produced HTML includes output that contains the configured fully qualified directory base resource location for each context.": {
        "title": "Your secondary web service reveals some internal file-path details",
        "what_it_means": "When a page isn't found on this web service, its error page shows part of its internal folder structure.",
        "why_it_matters": "This information by itself is low-risk, but it can help an attacker plan a more targeted attack against this device.",
        "how_to_fix": "1. Update this web service to the latest version, which fixes the information leak.\n2. If you don't need this secondary web service, consider turning it off.",
    },
    "Uninitialized stack variable vulnerability in NameValueParserEndElt (upnpreplyparse.c) in miniupnpd < 2.0 allows an attacker to cause Denial of Service (Segmentation fault and Memory Corruption) or possibly have unspecified other impact": {
        "title": "A bug in your network device-discovery service could crash it",
        "what_it_means": "A flaw in the software that lets devices find each other on your network could be used to crash that service or corrupt its memory.",
        "why_it_matters": "An attacker on your network could use this to knock the service offline or cause it to misbehave.",
        "how_to_fix": "1. Update this device's firmware or UPnP software to the latest version.\n2. If you don't rely on automatic device discovery, turn UPnP off.\n3. Avoid exposing this device directly to the internet.",
    },
    "A Denial Of Service vulnerability in MiniUPnP MiniUPnPd through 2.1 exists due to a NULL pointer dereference in GetOutboundPinholeTimeout in upnpsoap.c for int_port.": {
        "title": "A bug in your network device-discovery service could crash it",
        "what_it_means": "A flaw in the software that lets devices find each other on your network could be used to crash that service.",
        "why_it_matters": "An attacker on your network could use this to knock the service offline, interrupting the devices that rely on it.",
        "how_to_fix": "1. Update this device's firmware or UPnP software to the latest version.\n2. If you don't rely on automatic device discovery, turn UPnP off.\n3. Avoid exposing this device directly to the internet.",
    },
    "The Apache HTTP Server 2.4.18 through 2.4.20, when mod_http2 and mod_ssl are enabled, does not properly recognize the \"SSLVerifyClient require\" directive for HTTP/2 request authorization, which allows remote attackers to bypass intended access restrictions by leveraging the ability to send multiple requests over a single connection and aborting a renegotiation.": {
        "title": "Your website software could let an access restriction be bypassed",
        "what_it_means": "Under a specific combination of settings, this web server has a bug that could let a visitor bypass a security check meant to require client certificates.",
        "why_it_matters": "If you rely on this kind of certificate-based access restriction anywhere on your site, an attacker could get around it.",
        "how_to_fix": "1. Update the web server software to the latest version.\n2. If you don't use HTTP/2 with client-certificate checks, this issue doesn't apply to you, but updating is still recommended.",
    },
    "The default vhost configuration file in Puppet before 3.6.2 does not include the SSLCARevocationCheck directive, which might allow remote attackers to obtain sensitive information via a revoked certificate when a Puppet master runs with Apache 2.4.": {
        "title": "A website setup issue could allow a revoked security certificate to still be trusted",
        "what_it_means": "This web server's default setup doesn't check whether a security certificate has been revoked (cancelled), which is normally supposed to be checked.",
        "why_it_matters": "In rare setups, this could let information be exposed using a certificate that should no longer be trusted.",
        "how_to_fix": "1. Update the affected software to the latest version.\n2. If you manage certificates for this device, confirm your server is configured to check certificate revocation.",
    },
    "The auth_parse_options function in auth-options.c in sshd in OpenSSH before 5.7 provides debug messages containing authorized_keys command options, which allows remote authenticated users to obtain potentially sensitive information by reading these messages, as demonstrated by the shared user account required by Gitolite.  NOTE: this can cross privilege boundaries because a user account may intentionally have no shell or filesystem access, and therefore may have no supported way to read an authorized_keys file in its own home directory.": {
        "title": "A minor information leak in remote-login debug messages",
        "what_it_means": "This device's remote-login software (SSH) can include extra configuration details in its debug output that shouldn't normally be visible.",
        "why_it_matters": "This only matters if you already share login accounts with other people — it doesn't allow access from someone who isn't already authenticated.",
        "how_to_fix": "1. Update the SSH software to the latest version.\n2. Avoid sharing individual login accounts between multiple people when possible.",
    },
    "The ldb_wildcard_compare function in ldb_match.c in ldb before 1.1.24, as used in the AD LDAP server in Samba 4.x before 4.1.22, 4.2.x before 4.2.7, and 4.3.x before 4.3.3, mishandles certain zero values, which allows remote attackers to cause a denial of service (infinite loop) via crafted packets.": {
        "title": "A flaw in your file-sharing service could freeze it",
        "what_it_means": "This device's file-sharing software (Samba) has a bug that could be used to make part of it get stuck in an endless loop.",
        "why_it_matters": "Someone on your network could use this to make file sharing on this device stop responding.",
        "how_to_fix": "1. Update the file-sharing (Samba) software to the latest version.\n2. Make sure your Wi-Fi network has a strong password so untrusted people can't get onto your local network.",
    },
    "The mod_http2 module in the Apache HTTP Server 2.4.17 through 2.4.23, when the Protocols configuration includes h2 or h2c, does not restrict request-header length, which allows remote attackers to cause a denial of service (memory consumption) via crafted CONTINUATION frames in an HTTP/2 request.": {
        "title": "A bug in your website software could be used to slow it down",
        "what_it_means": "This web server has a bug in its newer HTTP/2 support that could let someone send specially crafted requests that use up more memory than they should.",
        "why_it_matters": "In the worst case, this could make your website slow or temporarily unresponsive for visitors.",
        "how_to_fix": "1. Update the web server software to the latest version.\n2. If you don't specifically need HTTP/2, you can disable it as a temporary precaution.",
    },
    "The default configuration of OpenSSH through 6.1 enforces a fixed time limit between establishing a TCP connection and completing a login, which makes it easier for remote attackers to cause a denial of service (connection-slot exhaustion) by periodically making many new TCP connections.": {
        "title": "This device's remote-login service could be slowed down by repeated connection attempts",
        "what_it_means": "This device's remote-login software (SSH) has a default setting that makes it possible for someone to tie up all its available connection slots by repeatedly connecting and not logging in.",
        "why_it_matters": "This could temporarily prevent legitimate remote logins while the attack is happening, though it doesn't grant access to the device itself.",
        "how_to_fix": "1. Update the SSH software to the latest version, which includes improved defenses for this.\n2. If your device supports it, enable a connection-rate limit or a tool like fail2ban.",
    },
    "The (1) roaming_read and (2) roaming_write functions in roaming_common.c in the client in OpenSSH 5.x, 6.x, and 7.x before 7.1p2, when certain proxy and forward options are enabled, do not properly maintain connection file descriptors, which allows remote servers to cause a denial of service (heap-based buffer overflow) or possibly have unspecified other impact by requesting many forwardings.": {
        "title": "A bug in how this device connects out to remote servers over SSH",
        "what_it_means": "When this device makes outgoing SSH connections with certain proxy/forwarding options turned on, a bug in that process could be triggered by a malicious remote server it connects to.",
        "why_it_matters": "This is the reverse direction from most issues here — it's about a server this device connects to acting maliciously, potentially crashing the connection or worse.",
        "how_to_fix": "1. Update the SSH software to the latest version.\n2. Avoid enabling proxy/forwarding options for SSH connections to servers you don't fully trust.",
    },
    "The updateDevice function in minissdpd.c in MiniUPnP MiniSSDPd 1.4 and 1.5 allows a remote attacker to crash the process due to a Use After Free vulnerability.": {
        "title": "A bug in your network device-discovery service could crash it",
        "what_it_means": "A flaw in the software that lets devices find each other on your network could be used to crash that service.",
        "why_it_matters": "An attacker on your network could use this to knock the service offline.",
        "how_to_fix": "1. Update this device's firmware or UPnP software to the latest version.\n2. If you don't rely on automatic device discovery, turn UPnP off.\n3. Avoid exposing this device directly to the internet.",
    },
    "A Denial Of Service vulnerability in MiniUPnP MiniUPnPd through 2.1 exists due to a NULL pointer dereference in copyIPv6IfDifferent in pcpserver.c.": {
        "title": "A bug in your network device-discovery service could crash it",
        "what_it_means": "A flaw in the software that lets devices find each other on your network could be used to crash that service.",
        "why_it_matters": "An attacker on your network could use this to knock the service offline, interrupting the devices that rely on it.",
        "how_to_fix": "1. Update this device's firmware or UPnP software to the latest version.\n2. If you don't rely on automatic device discovery, turn UPnP off.\n3. Avoid exposing this device directly to the internet.",
    },
    "ldb before 1.1.24, as used in the AD LDAP server in Samba 4.x before 4.1.22, 4.2.x before 4.2.7, and 4.3.x before 4.3.3, mishandles string lengths, which allows remote attackers to obtain sensitive information from daemon heap memory by sending crafted packets and then reading (1) an error message or (2) a database value.": {
        "title": "A flaw in your file-sharing service could leak small bits of internal memory",
        "what_it_means": "This device's file-sharing software (Samba) has a bug that could let someone on your network see small fragments of the service's internal memory by sending it crafted requests.",
        "why_it_matters": "This could occasionally expose small pieces of sensitive data to someone already on your network.",
        "how_to_fix": "1. Update the file-sharing (Samba) software to the latest version.\n2. Make sure your Wi-Fi network has a strong password so untrusted people can't get onto your local network.",
    },
    "A use-after-free vulnerability in BusyBox v.1.36.1 allows attackers to cause a denial of service via a crafted awk pattern in the awk.c evaluate function.": {
        "title": "A bug in this device's built-in command tools could crash a service",
        "what_it_means": "A small text-processing tool built into this device's software has a bug that could be used to crash whatever is using it.",
        "why_it_matters": "This mainly causes a temporary disruption rather than giving an attacker access to the device.",
        "how_to_fix": "1. Check whether this device's manufacturer has a firmware update available, and install it.\n2. No further action is needed if an update isn't available yet — this is a lower-urgency issue.",
    },
    "The bundled LDAP client library in Samba 3.x and 4.x before 4.2.11, 4.3.x before 4.3.8, and 4.4.x before 4.4.2 does not recognize the \"client ldap sasl wrapping\" setting, which allows man-in-the-middle attackers to perform LDAP protocol-downgrade attacks by modifying the client-server data stream.": {
        "title": "A flaw in your file-sharing service could let its encryption be downgraded",
        "what_it_means": "This device's file-sharing software (Samba) has a bug that could let someone intercepting your network traffic force part of a connection to use weaker protection than intended.",
        "why_it_matters": "Someone already positioned on your network could use this to weaken the security of file-sharing traffic.",
        "how_to_fix": "1. Update the file-sharing (Samba) software to the latest version.\n2. Make sure your Wi-Fi network has a strong password so untrusted people can't get onto your local network.",
    },
}


def _service_key(affected: str) -> str:
    # "Port 3306 — mysql MySQL 5.7.21" -> "mysql"; host_os records have no "—".
    if "—" not in affected:
        return None
    after_dash = affected.split("—", 1)[1].strip()
    return after_dash.split(" ", 1)[0]


# --- Scalable fallback for network/host_os CVE findings not in the hand-written
# _FINDING_TRANSLATIONS table above: classify by service + vulnerability class
# (from real keywords in the real CVE description) onto a template matrix. Facts
# (service, severity, CVE existence) stay real; only the class->wording mapping is
# templated, same principle _deterministic_report uses for its generic fallback.

_SERVICE_DESC_LABEL = {
    "ssh": "remote-login software (SSH)",
    "http": "web server software",
    "https": "web server software (running over a secure connection)",
    "http-proxy": "secondary web service (Jetty)",
    "smb": "file-sharing software (Samba)",
    "mysql": "database software",
    "telnet": "older remote-command tools (BusyBox telnet)",
    "upnp": "network device-discovery service (UPnP)",
}


def _describe_target(affected: str) -> str:
    if affected.startswith("Operating system:"):
        return "device's operating system"
    return _SERVICE_DESC_LABEL.get(_service_key(affected), "software running on this device")


_VULN_CLASS_KEYWORDS = [
    # order matters — first match wins, most-severe-sounding classes checked first
    ("rce", ["code execution", "execute arbitrary", "arbitrary code", "run arbitrary"]),
    ("downgrade", ["downgrade", "man-in-the-middle", "mitm", "protocol-downgrade"]),
    ("bypass", ["bypass", "spoof", "does not properly validate", "does not require",
                "authenticate", "without the need", "enumerat"]),
    ("privesc", ["privilege", "gain privileges", "elevat"]),
    ("infoleak", ["information disclosure", "obtain sensitive", "sensitive information",
                  "disclose", "read secret", "out-of-bounds read", "memory read",
                  "leak", "process memory"]),
    ("crash", ["denial of service", "crash", "use-after-free", "null pointer",
               "buffer overflow", "stack overflow", "segmentation fault",
               "memory consumption", "memory corruption", "uninitialized",
               "out of bound", "out-of-bounds write"]),
]

_VULN_CLASS_TEMPLATES = {
    "rce": {
        "title": "A serious flaw in the {target}",
        "what_it_means": "The {target} on this device has a bug that could let an attacker run their own commands on it.",
        "why_it_matters": "This is one of the more serious kinds of issues, because it could give an attacker real control over the device.",
        "how_to_fix": "1. Update the affected software to the latest version.\n2. If no update is available, turn this service off or restrict it to your home network only, not the open internet.",
    },
    "downgrade": {
        "title": "A flaw could let a connection's protection be weakened",
        "what_it_means": "The {target} on this device has a bug that could let someone intercepting your network traffic force it to use weaker protection than intended.",
        "why_it_matters": "Someone already positioned on your network could use this to weaken the security of this connection.",
        "how_to_fix": "1. Update the affected software to the latest version.\n2. Make sure your Wi-Fi network has a strong password so untrusted people can't get onto your local network.",
    },
    "bypass": {
        "title": "A flaw could let someone get around normal login checks",
        "what_it_means": "The {target} on this device has a bug that could let an attacker skip or trick part of its normal security checks.",
        "why_it_matters": "This could let someone gain access they shouldn't have, without needing the right credentials.",
        "how_to_fix": "1. Update the affected software to the latest version.\n2. Use a strong, unique password on this service either way.",
    },
    "privesc": {
        "title": "A flaw could let another account gain more access than it should",
        "what_it_means": "The {target} on this device has a bug that could let another user or program already on the device gain more access than intended.",
        "why_it_matters": "This mainly matters if other people or programs already have some access to this device — it could let them go from limited access to full control.",
        "how_to_fix": "1. Update the affected software to the latest version.\n2. Make sure you recognize and trust every user account on this device.",
    },
    "infoleak": {
        "title": "The {target} could leak some internal information",
        "what_it_means": "A bug in the {target} could let someone see internal information they shouldn't have access to.",
        "why_it_matters": "This is often low-risk by itself, but it can help an attacker plan a more targeted attack, or in some cases expose sensitive data directly.",
        "how_to_fix": "1. Update the affected software to the latest version.\n2. Avoid exposing this device directly to the internet if you don't need to.",
    },
    "crash": {
        "title": "A bug in the {target} could crash it",
        "what_it_means": "A flaw in the {target} could be used to crash it or make it misbehave.",
        "why_it_matters": "An attacker could use this to knock the service offline or make it unreliable, though this alone doesn't grant them access to the device.",
        "how_to_fix": "1. Update the affected software to the latest version.\n2. If you don't need this service, consider turning it off.",
    },
    "other": {
        "title": "A known security weakness in the {target}",
        "what_it_means": "The {target} on this device has a known security weakness.",
        "why_it_matters": "It's worth addressing to keep this device on the safe side.",
        "how_to_fix": "1. Update the affected software to the latest version.\n2. Review this service's settings to make sure it's configured securely.",
    },
}


def _classify_vuln(description: str) -> str:
    desc_l = description.lower()
    for cls, keywords in _VULN_CLASS_KEYWORDS:
        if any(kw in desc_l for kw in keywords):
            return cls
    return "other"


def translate_cve_finding(affected: str, description: str) -> dict:
    target = _describe_target(affected)
    cls = _classify_vuln(description or "")
    t = _VULN_CLASS_TEMPLATES[cls]
    return {
        "title": t["title"].format(target=target),
        "what_it_means": t["what_it_means"].format(target=target),
        "why_it_matters": t["why_it_matters"].format(target=target),
        "how_to_fix": t["how_to_fix"].format(target=target),
    }


_URGENCY_BY_SEVERITY = {
    "critical": "urgent",
    "high": "worth fixing soon",
    "medium": "worth knowing about",
}


def _summarize_overall(n_issues: int, worst_tier_rank: int, total_ok: int) -> str:
    if worst_tier_rank == 3:
        lead = f"We found {n_issues} issue{'s' if n_issues != 1 else ''} that need attention, including something urgent."
    elif worst_tier_rank == 2:
        lead = f"We found {n_issues} issue{'s' if n_issues != 1 else ''} worth fixing soon."
    elif worst_tier_rank == 1:
        lead = f"We found {n_issues} issue{'s' if n_issues != 1 else ''} worth knowing about."
    elif total_ok == 1:
        lead = "We looked over your device and everything checks out — nothing to worry about right now."
    else:
        lead = f"We looked over your device and checked {total_ok} things running on it — everything checks out, nothing to worry about right now."
    if worst_tier_rank > 0 and total_ok:
        lead += f" {total_ok} other thing{'s' if total_ok != 1 else ''} checked out fine."
    return lead


# Shared severity->urgency clause, appended after a source-specific "why" sentence
# rather than standing in for it alone — severity alone was the whole reason both
# Trivy and Lynis translations used to collapse to just a handful of
# near-identical why_it_matters strings project-wide.
_SEVERITY_URGENCY_CLAUSE = {
    "critical": "It's rated urgent — worth fixing as soon as possible.",
    "high": "It's worth fixing soon.",
    "medium": "It's not urgent, but worth doing when convenient.",
}
_DEFAULT_URGENCY_CLAUSE = "It's worth addressing to keep this device on the safe side."


# --- Trivy (filesystem) translations: procedural by package, since the CVE-bearing
# `description` Trivy hands us literally embeds the raw CVE ID — that text must
# never be echoed into report output, only `package`/`installed_version`/
# `fixed_version` (all CVE-literal-free) are used here.
_PACKAGE_INFO = {
    "openssl": ("OpenSSL", "the encryption software used to secure network connections"),
    "curl": ("curl", "a tool other installed programs use to fetch data from the internet"),
    "libxml2": ("libxml2", "a document-parsing library used by other installed programs"),
    "zlib1g": ("zlib", "a file-compression library used by other installed programs"),
    "python3.8": ("Python 3.8", "the Python programming language runtime"),
}

# Package-name-pattern -> category, used only to pick a why_it_matters angle (never
# shown to the user) — coarse on purpose, since we can't hand-curate every package
# name Trivy might report. Checked in order; first match wins.
_PACKAGE_CATEGORY_PATTERNS = [
    ("kernel",         ("linux-headers", "linux-image", "linux-modules", "linux-libc-dev", "linux-tools", "linux-firmware")),
    ("crypto",         ("openssl", "libssl", "gnutls", "libgnutls", "ca-certificates")),
    ("network_client", ("curl", "libcurl", "wget")),
    ("remote_access",  ("openssh", "ssh")),
    ("web_server",     ("apache2", "nginx", "httpd", "lighttpd")),
    ("core_library",   ("glibc", "libc6", "libc-bin", "libc-dev")),
    ("runtime",        ("python", "perl", "ruby", "openjdk", "nodejs", "php")),
    ("system_service", ("systemd", "dbus", "udev", "polkit")),
]

_PACKAGE_CATEGORY_WHY = {
    "kernel": "This is part of the device's core operating system, so a flaw here can potentially affect everything else running on it.",
    "crypto": "This handles encryption for network connections, so a flaw here could let someone intercept or tamper with data in transit.",
    "network_client": "Other installed programs use this to fetch data from the internet, so a flaw here can be triggered just by reaching the wrong server.",
    "remote_access": "This handles remote logins to this device, so a flaw here is particularly sensitive.",
    "web_server": "This is what serves web pages from this device, so a flaw here is directly exposed to anyone who can reach it over the network.",
    "core_library": "This is used by nearly every program on the device, so a flaw here has a wide blast radius.",
    "runtime": "Other software installed on this device runs on top of this, so a flaw here could affect any of it.",
    "system_service": "This runs in the background on every boot, so a flaw here could be triggered without any user action.",
    "general": "The real-world risk depends on how exposed or privileged the software using this component is.",
}


def _classify_package(pkg: str) -> str:
    p = pkg.lower()
    for category, prefixes in _PACKAGE_CATEGORY_PATTERNS:
        if any(p.startswith(prefix) or prefix in p for prefix in prefixes):
            return category
    return "general"


def translate_trivy_finding(affected: str, severity: str, remediation_refs: list) -> dict:
    pkg, _, installed = affected[len("Package: "):].partition(" ")
    fixed = remediation_refs[0] if remediation_refs else None
    short, desc = _PACKAGE_INFO.get(pkg, (pkg, f"the '{pkg}' software component"))
    how = f"1. Update {short} to version {fixed} or later." if fixed else f"1. Update {short} to the latest available version."
    how += "\n2. Most systems can do this automatically through their regular software updates."
    why_base = _PACKAGE_CATEGORY_WHY[_classify_package(pkg)]
    urgency = _SEVERITY_URGENCY_CLAUSE.get(severity, _DEFAULT_URGENCY_CLAUSE)
    return {
        "title": f"{short} is out of date and has a known security issue",
        "what_it_means": f"This device has an older version of {desc} installed, and that version has a known security issue.",
        "why_it_matters": f"{why_base} {urgency}",
        "how_to_fix": how,
    }


# --- Lynis (host_audit) translations: procedural by catalog category, reusing the
# real LYNIS_TEST_CATALOG description/solution text (already plain, curated, no
# CVE/CPE literals) wrapped in home-user framing.
_LYNIS_CATEGORY_INTRO = {
    "Authentication": "This is about how logins and passwords are set up on this device.",
    "Boot": "This is about how this device starts up.",
    "Cryptography": "This is about encryption settings on this device.",
    "File Integrity": "This is about noticing if important system files get changed.",
    "File Permissions": "This is about which files on this device can be read or changed, and by whom.",
    "Firewall": "This is about this device's firewall (its network traffic filter).",
    "Hardening": "This is a general device-hardening setting.",
    "Home Directories": "This is about who can read the personal files in each account's home folder.",
    "Insecure Services": "This is about an outdated service on this device that sends data unprotected.",
    "Kernel": "This is about a low-level system setting.",
    "Logging": "This is about how this device records activity logs.",
    "MAC Frameworks": "This is about an extra layer of protection that limits what each program is allowed to do.",
    "Mail": "This is about this device's email-handling setup.",
    "Malware": "This is about malware-scanning setup on this device.",
    "Name Services": "This is about how this device looks up other computers by name.",
    "Networking": "This is about this device's network settings.",
    "Packages": "This is about how software is installed and updated on this device.",
    "PHP": "This is about a web-scripting configuration on this device.",
    "Printing": "This is about this device's printing setup.",
    "Processes": "This is about how programs run on this device.",
    "Scheduling": "This is about scheduled/automatic tasks on this device.",
    "SNMP": "This is about a network-monitoring feature on this device.",
    "SSH": "This is about remote-login (SSH) settings on this device.",
    "Storage": "This is about storage/disk settings on this device.",
    "Time/NTP": "This is about keeping this device's clock accurate.",
    "Tooling": "This is about diagnostic tools installed on this device.",
    "USB": "This is about USB device settings on this device.",
    "Web Servers": "This is about the web server software running on this device.",
}

# What could actually happen if each category's setting is left as-is — this is what
# was missing before: why_it_matters used to be picked from severity alone, so e.g.
# an SSH gap and a printing gap read identically. Content now tracks the category;
# urgency still tracks severity (appended separately below).
_LYNIS_CATEGORY_WHY = {
    "Authentication": "A weak spot here could make it easier for someone to guess or brute-force their way into an account.",
    "Boot": "Someone with physical access to the device could use this to bypass normal login protections entirely.",
    "Cryptography": "Weaker encryption here could let someone read or tamper with data that's supposed to be protected.",
    "File Integrity": "Without this, unauthorized changes to important system files could go unnoticed.",
    "File Permissions": "Overly loose permissions here could let other accounts or programs on the device read or change files they shouldn't.",
    "Firewall": "A gap here could let unwanted network traffic reach services on this device that shouldn't be exposed.",
    "Hardening": "This is a general safety margin — on its own it's low-risk, but gaps like this add up.",
    "Home Directories": "Someone else with an account on this device could read personal files they shouldn't have access to.",
    "Insecure Services": "Data sent through this service isn't protected, so it could be intercepted by someone else on the same network.",
    "Kernel": "This affects the device at its most fundamental level, so a problem here can affect everything else running on it.",
    "Logging": "Without proper logs, it's harder to notice or investigate suspicious activity after the fact.",
    "MAC Frameworks": "Without this extra layer, a compromised program has more freedom to affect the rest of the device.",
    "Mail": "A misconfiguration here could let this device be used to send spam or intercept email.",
    "Malware": "Without this in place, malware landing on this device is less likely to be caught early.",
    "Name Services": "A problem here could let someone redirect this device to a malicious server without it being obvious.",
    "Networking": "This affects how this device communicates over the network, which is a common point of attack.",
    "Packages": "Software that isn't kept up to date is more likely to have unpatched security holes.",
    "PHP": "A misconfigured web-scripting setup is a common way attackers gain a foothold on a web server.",
    "Printing": "This is a narrow, low-impact area — it mainly matters if the printing service is exposed to others.",
    "Processes": "A weakness here could let one program interfere with or gain more access than another.",
    "Scheduling": "A scheduled task with too much access could be abused to run something unintended.",
    "SNMP": "This network-monitoring feature can leak information about the device if left open to more than intended.",
    "SSH": "SSH is a common target for automated attacks, so weaknesses here are worth taking seriously.",
    "Storage": "A problem here could affect data availability or let someone tamper with stored data.",
    "Time/NTP": "An inaccurate clock can weaken security features (like certificate checks) that depend on correct timing.",
    "Tooling": "This is a supporting tool rather than a direct exposure — it mainly helps you catch other problems sooner.",
    "USB": "This affects what happens when a USB device is plugged in, which matters most if the device isn't physically secured.",
    "Web Servers": "Web server misconfigurations are one of the most common ways attackers find a way in.",
}

# A title is derived from a LYNIS_TEST_CATALOG description's lead clause instead of
# repeating the same "<category> setting worth reviewing" string for every finding in
# a category — those descriptions are written as full "condition detected" sentences.
# Guards against two bad cuts a naive comma-split produces: (1) descriptions that open
# with a subordinate clause ("If not required, consider...") — the lead clause alone
# is meaningless, so those skip straight to the category fallback; (2) a comma inside
# parentheses ("No PAM module (pam_pwquality, pam_cracklib, ...) is installed") — split
# only counts commas/" so "/" which "/"; " outside any (...) span.
_TITLE_LEAD_SUBORDINATORS = {"if", "when", "since", "although", "unless", "while", "because", "as"}


def _split_top_level_clause(text: str) -> str:
    depth = 0
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            if ch in ",;":
                return text[:i]
            if text[i:i + 4] == " so " or text[i:i + 7] == " which ":
                return text[:i]
        i += 1
    return text


def _short_title(description: str, category: str) -> str:
    text = (description or "").strip()
    if not text:
        return f"{category} setting worth reviewing"
    first_word = text.split(" ", 1)[0].lower().rstrip(",")
    if first_word in _TITLE_LEAD_SUBORDINATORS:
        return f"{category} setting worth reviewing"
    lead = _split_top_level_clause(text).strip().rstrip(".")
    if not (8 <= len(lead) <= 70):
        return f"{category} setting worth reviewing"
    return lead[0].upper() + lead[1:]


def translate_lynis_finding(affected: str, description: str, solution: str, severity: str) -> dict:
    test_id = affected[len("Host setting: "):]
    category = LYNIS_TEST_CATALOG.get(test_id, {}).get("category", "General")
    intro = _LYNIS_CATEGORY_INTRO.get(category, "This is a device-hardening setting worth reviewing.")
    desc_sentence = (description or "").strip()
    if desc_sentence and not desc_sentence.endswith("."):
        desc_sentence += "."
    why_base = _LYNIS_CATEGORY_WHY.get(category, "Tightening this setting reduces your overall risk over time.")
    urgency = _SEVERITY_URGENCY_CLAUSE.get(severity, _DEFAULT_URGENCY_CLAUSE)
    sol_sentence = (solution or "Review this setting and apply the recommended fix.").strip()
    if not sol_sentence.endswith("."):
        sol_sentence += "."
    return {
        "title": _short_title(description, category),
        "what_it_means": f"{intro} {desc_sentence}".strip(),
        "why_it_matters": f"{why_base} {urgency}",
        "how_to_fix": f"1. {sol_sentence}",
    }


# --- ClamAV (malware) translations: hand-written, keyed by description. Note one
# signature name literally contains "CVE-2016-3714" — used only as a dict KEY here,
# never echoed into output text (which is what _validate_report_text guards against).
_MALWARE_TRANSLATIONS = {
    "ClamAV signature match: Unix.Trojan.Generic-1234": {
        "title": "A malicious file was found on this device",
        "what_it_means": "Our antivirus scan found a file that matches a known trojan — malicious software disguised as something legitimate.",
        "why_it_matters": "This kind of file can give an attacker remote access to your device or let it steal information from you.",
        "how_to_fix": "1. Do not open this file.\n2. Delete it or move it to quarantine using your antivirus software.\n3. Run a full scan of your device to check for anything else related to it.\n4. Change your important passwords afterward, in case this file was already active.",
    },
    "ClamAV signature match: Unix.Malware.Agent-9981": {
        "title": "A malicious file was found on this device",
        "what_it_means": "Our antivirus scan found a file that matches a known piece of malicious software.",
        "why_it_matters": "Malicious software like this can spy on your activity, steal information, or let an attacker control your device.",
        "how_to_fix": "1. Do not open this file.\n2. Delete it or move it to quarantine using your antivirus software.\n3. Run a full scan of your device to check for anything else related to it.\n4. Change your important passwords afterward, in case this file was already active.",
    },
    "ClamAV signature match: PUA.Script.Coinminer-4521": {
        "title": "A cryptocurrency-mining script was found on this device",
        "what_it_means": "Our antivirus scan found a script that secretly uses your device's processing power to mine cryptocurrency for someone else.",
        "why_it_matters": "This can slow your device down significantly and increase your power usage, and it means something got onto your device without your permission.",
        "how_to_fix": "1. Delete the file or move it to quarantine using your antivirus software.\n2. Run a full scan of your device to check for anything else related to it.\n3. Check which program or download brought this onto your device, and remove that too.",
    },
    "ClamAV signature match: Win.Trojan.Downloader-771": {
        "title": "A malicious downloader file was found on this device",
        "what_it_means": "Our antivirus scan found a file whose job is to secretly download and install more malicious software.",
        "why_it_matters": "Even if this specific file hasn't caused visible harm yet, its purpose is to bring in additional malware — this needs quick attention.",
        "how_to_fix": "1. Do not open this file.\n2. Delete it or move it to quarantine using your antivirus software.\n3. Run a full scan of your device to check for anything it may have already downloaded.\n4. Change your important passwords afterward, in case this file was already active.",
    },
    "ClamAV signature match: Unix.Exploit.CVE-2016-3714-1": {
        "title": "A file exploiting a known software weakness was found on this device",
        "what_it_means": "Our antivirus scan found a file built to take advantage of a known weakness in some software, in order to compromise this device.",
        "why_it_matters": "This kind of file is designed to actively attack a security hole in your software — it's a strong sign something tried to break in.",
        "how_to_fix": "1. Do not open this file.\n2. Delete it or move it to quarantine using your antivirus software.\n3. Make sure all your software (especially anything related to image or file processing) is fully up to date.\n4. Run a full scan of your device to check for anything else related to it.",
    },
}

# --- Nuclei (web) translations: hand-written, keyed by description (fixed 6-template pool).
_WEB_TRANSLATIONS = {
    "Apache Struts RCE was detected during a template-based web scan.": {
        "title": "A serious flaw in your website software could let an attacker take it over",
        "what_it_means": "Your website is running software (Apache Struts) with a bug that could let an attacker run their own commands on your web server.",
        "why_it_matters": "This is one of the most serious kinds of issues — it could give an attacker full control of your website.",
        "how_to_fix": "1. Update the affected web software to the latest version immediately.\n2. If you're not sure how, contact whoever manages your website or hosting for help.\n3. Consider taking the site offline temporarily until it's updated.",
    },
    "Jenkins default credentials was detected during a template-based web scan.": {
        "title": "A tool on your network is still using its factory-default login",
        "what_it_means": "A development tool (Jenkins) on your network can be logged into using its original, publicly-known default username and password.",
        "why_it_matters": "Default logins are public knowledge — anyone who finds this tool can log in and take control of it.",
        "how_to_fix": "1. Log in and change the default username/password immediately.\n2. If you don't recognize or use this tool, consider taking it offline.",
    },
    "WordPress outdated core version was detected during a template-based web scan.": {
        "title": "Your website's software is out of date",
        "what_it_means": "Your website runs on WordPress, and the installed version is out of date and has known security issues.",
        "why_it_matters": "Outdated website software is one of the most common ways attackers break into websites.",
        "how_to_fix": "1. Update WordPress, along with its plugins and themes, to the latest version.\n2. Turn on automatic updates if your hosting provider supports it.",
    },
    "Default admin login page was detected during a template-based web scan.": {
        "title": "An admin login page is publicly reachable",
        "what_it_means": "A login page for administering part of your website or a connected tool is reachable by anyone on the internet.",
        "why_it_matters": "If the login uses a weak or default password, this page is a direct route for an attacker to gain control.",
        "how_to_fix": "1. Make sure this admin login uses a strong, unique password.\n2. If possible, restrict access to this page to your home network only.\n3. Turn on two-factor authentication if it's supported.",
    },
    "Open Redis instance (no auth) was detected during a template-based web scan.": {
        "title": "A database service is open to the internet with no password",
        "what_it_means": "A backend data-storage service (Redis) on your network can be accessed by anyone, without needing a password.",
        "why_it_matters": "This is rated urgent — anyone who finds it could read, change, or delete the data it holds, or use it to gain further access to your network.",
        "how_to_fix": "1. Set a password on this service immediately.\n2. Make sure it isn't reachable from the open internet — restrict it to your home network only.\n3. If you don't recognize this service, find out what installed it and consider removing it.",
    },
    "Exposed .git directory was detected during a template-based web scan.": {
        "title": "Your website is exposing its source code files",
        "what_it_means": "A folder that's meant to stay private during website development (used by the Git version-control tool) is publicly accessible on your website.",
        "why_it_matters": "This can let someone download your website's underlying source code, which may contain passwords or other sensitive details.",
        "how_to_fix": "1. Remove or block public access to this folder on your web server.\n2. Review your website's deployment process so this folder isn't published again in the future.\n3. If passwords or keys were in that code, change them as a precaution.",
    },
}


def _good_news_text(f: dict) -> str:
    desc = f.get("description") or ""
    if desc in _GOOD_NEWS_WITH_DESC:
        return _GOOD_NEWS_WITH_DESC[desc]
    key = _service_key(f["affected"])
    if key is None:  # host_os record with low severity
        return "This device's operating system checked out fine — no known security problems were found."
    return _SERVICE_BLURB.get(key, "This checked out fine — no known security problems were found.")


def _finding_translation(f: dict) -> dict:
    source = f.get("source")
    if source == "filesystem":
        return translate_trivy_finding(f["affected"], f["severity"], f.get("remediation_refs"))
    if source == "host_audit":
        return translate_lynis_finding(f["affected"], f.get("description"), (f.get("remediation_refs") or [None])[0], f["severity"])
    if source == "malware":
        t = _MALWARE_TRANSLATIONS.get(f.get("description") or "")
        if t is None:
            raise KeyError(f"no malware translation for: {f.get('description')!r}")
        return t
    if source == "web":
        t = _WEB_TRANSLATIONS.get(f.get("description") or "")
        if t is None:
            raise KeyError(f"no web translation for: {f.get('description')!r}")
        return t
    # network / iot_defaults / host_os
    desc = f.get("description") or ""
    return _FINDING_TRANSLATIONS.get(desc) or translate_cve_finding(f["affected"], desc)


def draft_label(ordered_facts: list) -> dict:
    """Unified drafting path: findings above 'low' become real 'findings' entries
    (dispatched by source to the right translator); 'low' findings fold into
    'good_news', per the _deterministic_report convention (agent.py:509-511)."""
    by_tier = {"critical": [], "high": [], "medium": []}
    good_news = []
    worst_tier_rank = 0
    _RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

    for f in ordered_facts:
        sev = f["severity"]
        worst_tier_rank = max(worst_tier_rank, _RANK.get(sev, 0))
        if sev == "low":
            good_news.append(_good_news_text(f))
            continue

        t = _finding_translation(f)
        refs = _clean_refs(f.get("remediation_refs")) if f.get("source") not in ("filesystem", "host_audit") else []
        by_tier[sev].append({
            "title": t["title"],
            "severity": sev,
            "what_it_means": t["what_it_means"],
            "why_it_matters": t["why_it_matters"],
            "how_to_fix": t["how_to_fix"],
            "affected": f["affected"],
            "references": refs,
        })

    findings = by_tier["critical"] + by_tier["high"] + by_tier["medium"]
    overall_risk = {3: "critical", 2: "high", 1: "medium", 0: "low"}[worst_tier_rank]
    summary = _summarize_overall(len(findings), worst_tier_rank, len(good_news))

    return {
        "overall_risk": overall_risk,
        "summary": summary,
        "findings": findings,
        "good_news": good_news,
    }


def main():
    lo, hi = int(sys.argv[1]), int(sys.argv[2])
    relabel = "--relabel" in sys.argv[3:]
    conn = sqlite3.connect("trainset.db")
    status_clause = "" if relabel else "AND status = 'pending'"
    rows = conn.execute(
        f"SELECT id, ordered_facts FROM examples WHERE id BETWEEN ? AND ? {status_clause} ORDER BY id",
        (lo, hi),
    ).fetchall()

    labeled = validated = rejected = 0
    for _id, of in rows:
        ordered_facts = json.loads(of)
        report = draft_label(ordered_facts)
        raw_text = json.dumps(report)

        # Same table build_findings_table would have produced for this row's severities —
        # reconstruct the minimal {affected: severity} mapping _validate_report_severities needs.
        fake_table = [{"affected": f["affected"], "severity": f["severity"]} for f in ordered_facts]

        conn.execute("UPDATE examples SET label = ?, status = 'labeled' WHERE id = ?", (raw_text, _id))
        labeled += 1

        ok = True
        try:
            parsed = _parse_report(raw_text)
        except ValueError as e:
            print(f"[id={_id}] REJECTED — parse error: {e}")
            ok = False
        else:
            if not _validate_report_text(raw_text):
                print(f"[id={_id}] REJECTED — literal CVE/CPE leak")
                ok = False
            elif not _validate_report_severities(parsed, fake_table):
                print(f"[id={_id}] REJECTED — severity/affected mismatch")
                ok = False

        status = "validated" if ok else "rejected"
        conn.execute("UPDATE examples SET status = ? WHERE id = ?", (status, _id))
        if ok:
            validated += 1
        else:
            rejected += 1

    conn.commit()
    print(f"\nbatch [{lo}-{hi}]: labeled={labeled} validated={validated} rejected={rejected}")


if __name__ == "__main__":
    main()
