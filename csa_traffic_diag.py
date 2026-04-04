#!/usr/bin/env python3
"""Cisco Secure Access Traffic Diagnostic Tool.

Diagnoses traffic routing, TLS interception, egress IP path, route interface
selection, log events, and client status for Cisco Secure Access (Secure Client)
on macOS and Windows.
"""

import argparse
import datetime
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


def _resolve_version():
    try:
        from importlib.metadata import version as _pkg_version

        return _pkg_version("csadiag")
    except Exception:
        pass
    # Fallback: read version from pyproject.toml next to this file
    try:
        toml_path = Path(__file__).resolve().parent / "pyproject.toml"
        for line in toml_path.read_text().splitlines():
            if line.startswith("version"):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "dev"


VERSION = _resolve_version()
TIMEOUT = 5  # seconds for network operations
TRACEROUTE_TIMEOUT = 30
ZTA_TAIL_LINES = 100  # lines to read from end of ZTA log for state detection
MAX_LOG_LINE_LEN = 200  # truncation length for log line previews
MAX_DB_ROWS = 200  # max rows per table when scanning SQLite databases
MAX_SAMPLE_ENTRIES = 5  # sample entries kept per domain bucket

# Cisco/OpenDNS IP prefixes indicating DNS-layer redirection or SSE egress
CISCO_IP_PREFIXES = ("146.112.", "155.190.", "151.186.", "163.129.")

# Egress IP detection services (tried in order; first success wins)
EGRESS_IP_SERVICES = (
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
)

# IP Chicken — used as the bypass-side egress check.
# Add ipchicken.com to your Cisco Secure Access traffic steering bypass list;
# the tool will compare its IP against the tunneled egress to confirm bypass works.
IPCHICKEN_URL = "http://ipchicken.com"

# Tunnel interface name patterns (matched case-insensitively)
# macOS ZTA uses utun*; Windows uses virtual adapters named "Cisco *"
TUNNEL_IFACE_PATTERNS = ("utun", "cisco", "csc_", "anyconnect")

# Strings in cert chain indicating Cisco interception (matched case-insensitively)
CISCO_CERT_MARKERS = ("cisco", "umbrella", "opendns", "secure access")

# Reverse-DNS substring → display name for hosting/CDN provider identification
# More specific entries must come before less specific ones (first match wins)
KNOWN_PROVIDERS = (
    ("akamaiedge.net", "Akamai"),
    ("akamaitechnologies.com", "Akamai"),
    ("edgekey.net", "Akamai"),
    ("cloudfront.net", "AWS CloudFront"),
    ("amazonaws.com", "AWS"),
    ("msedge.net", "Microsoft"),
    ("azure", "Microsoft Azure"),
    ("cloudflare", "Cloudflare"),
    ("fastlylb.net", "Fastly"),
    ("fastly.net", "Fastly"),
    ("1e100.net", "Google"),
    ("googleusercontent.com", "Google Cloud"),
    ("llnwi.net", "Limelight"),
    ("llnw.net", "Limelight"),
    ("zscaler.net", "Zscaler"),
    ("level3.net", "Lumen/Level3"),
    ("cisco.com", "Cisco"),
)

# Domain suffix → owner name for well-known services whose IPs lack useful reverse DNS.
# Checked as a fallback when cert org and reverse DNS both fail to identify the owner.
# More specific suffixes must come before less specific ones (first match wins).
KNOWN_DOMAIN_OWNERS = (
    (".icloud.com", "Apple"),
    (".apple.com", "Apple"),
    (".mzstatic.com", "Apple"),
    (".microsoft.com", "Microsoft"),
    (".office.com", "Microsoft"),
    (".office365.com", "Microsoft"),
    (".windows.com", "Microsoft"),
    (".live.com", "Microsoft"),
    (".msftconnecttest.com", "Microsoft"),
    (".azure.com", "Microsoft Azure"),
    (".googleapis.com", "Google"),
    (".gstatic.com", "Google"),
    (".google.com", "Google"),
    (".youtube.com", "Google"),
    (".ytimg.com", "Google"),
    (".amazon.com", "Amazon"),
    (".amazonaws.com", "AWS"),
    (".webex.com", "Cisco Webex"),
    (".cisco.com", "Cisco"),
    (".zoom.us", "Zoom"),
    (".zoomgov.com", "Zoom"),
    (".akamaized.net", "Akamai"),
    (".akamai.com", "Akamai"),
    (".cloudflare.com", "Cloudflare"),
    (".fastly.com", "Fastly"),
    (".okta.com", "Okta"),
    (".oktacdn.com", "Okta"),
    (".salesforce.com", "Salesforce"),
    (".force.com", "Salesforce"),
    (".dropbox.com", "Dropbox"),
    (".dropboxstatic.com", "Dropbox"),
    (".box.com", "Box"),
    (".boxcdn.net", "Box"),
    (".slack.com", "Slack"),
    (".slack-edge.com", "Slack"),
    (".github.com", "GitHub"),
    (".githubusercontent.com", "GitHub"),
)

# Regex for log scanning keywords
LOG_PATTERNS = re.compile(
    r"\b(block(?:ed)?|deny|denied|drop(?:ped)?|refused|certificate"
    r"|error|fail(?:ed|ure)?|timeout|unreachable|decrypt(?:ed|ion)?|bypass(?:ed)?)\b",
    re.IGNORECASE,
)

# Keyword-to-category mapping for traffic discovery
KEYWORD_CATEGORIES = {
    "bypass": "bypass",
    "bypassed": "bypass",
    "block": "block",
    "blocked": "block",
    "deny": "block",
    "denied": "block",
    "drop": "block",
    "dropped": "block",
    "refused": "block",
    "error": "error",
    "failed": "error",
    "failure": "error",
    "timeout": "error",
    "unreachable": "error",
    "certificate": "error",
    "decrypted": "decrypt",
    "decryption": "decrypt",
}

# Regex for extracting timestamps from log lines
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}")

# Regex for extracting domain names from log lines
# Requires at least one label with 2+ alpha chars as TLD to avoid matching IPs/timestamps
DOMAIN_RE = re.compile(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,})")

# Regex for extracting commonName from certificate subject/issuer strings
_CN_RE = re.compile(r"commonName=([^,]+)")

# Regex for extracting Organization from cert subject strings
_ORG_RE = re.compile(r"organizationName=([^,]+)")

# Platform detection
IS_MACOS = platform.system() == "Darwin"
IS_WINDOWS = platform.system() == "Windows"

# Platform-specific paths
if IS_MACOS:
    CSC_BASE = Path("/opt/cisco/secureclient")
    ZTA_LOG_PATHS = [
        CSC_BASE / "zta" / "logs" / "flowlog.db",
        CSC_BASE / "ztna" / "log" / "ZeroTrustAccess.log",
    ]
    UMBRELLA_DIR = CSC_BASE / "umbrella"
elif IS_WINDOWS:
    CSC_BASE = Path(r"C:\ProgramData\Cisco\Cisco Secure Client")
    ZTA_LOG_PATHS = [
        CSC_BASE / "ZTA" / "logs",
    ]
    UMBRELLA_DIR = CSC_BASE / "Umbrella"
else:
    CSC_BASE = Path("/opt/cisco/secureclient")
    ZTA_LOG_PATHS = []
    UMBRELLA_DIR = CSC_BASE / "umbrella"


def _detect_os_version():
    """Detect and return a human-readable OS version string."""
    system = platform.system()
    if system == "Darwin":
        try:
            # sw_vers gives clean macOS version
            proc = subprocess.run(
                ["sw_vers", "-productVersion"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            ver = proc.stdout.strip()
            if ver:
                return f"macOS {ver}"
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return f"macOS {platform.mac_ver()[0] or 'unknown'}"
    elif system == "Windows":
        try:
            # Get Windows edition and display version (e.g., "Windows 11 24H2")
            proc = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "(Get-CimInstance Win32_OperatingSystem).Caption + ' ' + "
                    "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            ver = proc.stdout.strip()
            if ver:
                return ver
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return f"Windows {platform.version()}"
    elif system == "Linux":
        try:
            proc = subprocess.run(
                ["lsb_release", "-ds"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            ver = proc.stdout.strip().strip('"')
            if ver:
                return ver
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return f"Linux {platform.release()}"
    return f"{system} {platform.release()}"


# Lazy OS version cache (avoid subprocess at import time)
_os_version_cache = None


def _get_os_version():
    global _os_version_cache
    if _os_version_cache is None:
        _os_version_cache = _detect_os_version()
    return _os_version_cache


# ---------------------------------------------------------------------------
# Color output
# ---------------------------------------------------------------------------


class ColorOutput:
    """ANSI color output with --no-color support."""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    def __init__(self, no_color=False):
        self.enabled = not no_color and sys.stdout.isatty()

    def _wrap(self, code, text):
        if self.enabled:
            return f"{code}{text}{self.RESET}"
        return text

    def red(self, text):
        return self._wrap(self.RED, text)

    def green(self, text):
        return self._wrap(self.GREEN, text)

    def yellow(self, text):
        return self._wrap(self.YELLOW, text)

    def cyan(self, text):
        return self._wrap(self.CYAN, text)

    def bold(self, text):
        return self._wrap(self.BOLD, text)

    def dim(self, text):
        return self._wrap(self.DIM, text)

    def status_icon(self, status):
        icons = {
            "ok": self.green("\u2705"),
            "warning": self.yellow("\u26a0\ufe0f"),
            "error": self.red("\u274c"),
            "info": self.cyan("\u2139\ufe0f"),
        }
        return icons.get(status, "  ")

    def banner(self):
        line = "\u2550" * 55
        return (
            f"\n{self.bold(line)}\n"
            f"  {self.bold('Cisco Secure Access Traffic Diagnostic Tool')} v{VERSION}\n"
            f"  {self.dim(f'Platform: {_get_os_version()}')}\n"
            f"  {self.dim(f'Log path: {CSC_BASE}')}\n"
            f"{self.bold(line)}\n"
        )


# ---------------------------------------------------------------------------
# Result factory
# ---------------------------------------------------------------------------


def _warn(msg):
    """Print a diagnostic warning to stderr (never to stdout/JSON stream)."""
    print(f"warning: {msg}", file=sys.stderr)


def make_result(check, status, message, details=None):
    return {
        "check": check,
        "status": status,
        "message": message,
        "details": details or {},
        "timestamp": datetime.datetime.now().isoformat(),
    }


def _matches_domain_filter(entry, domain_filter):
    """Return True if the entry matches the domain filter (or has no domain)."""
    domain = entry.get("domain")
    if not domain:
        return True
    return domain_filter.lower() in domain.lower()


# ---------------------------------------------------------------------------
# DNS diagnosis
# ---------------------------------------------------------------------------


def is_cisco_ip(ip):
    return any(ip.startswith(prefix) for prefix in CISCO_IP_PREFIXES)


def diagnose_dns(domain):
    """Resolve a domain and check if IPs belong to Cisco/OpenDNS ranges."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(TIMEOUT)
    try:
        results = socket.getaddrinfo(domain, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = sorted({str(addr[4][0]) for addr in results})
        cisco_ips = [ip for ip in ips if is_cisco_ip(ip)]
        status = "warning" if cisco_ips else "ok"
        msg = f"Resolved to {', '.join(ips)}"
        if cisco_ips:
            msg += f" — Cisco/OpenDNS IP detected: {', '.join(cisco_ips)}"
        return make_result(
            "dns",
            status,
            msg,
            {
                "domain": domain,
                "ips": ips,
                "cisco_ips": cisco_ips,
                "is_cisco_dns": bool(cisco_ips),
            },
        )
    except socket.gaierror as e:
        return make_result(
            "dns",
            "error",
            f"DNS resolution failed: {e}",
            {
                "domain": domain,
                "error": str(e),
            },
        )
    except TimeoutError:
        return make_result(
            "dns",
            "error",
            f"DNS resolution timed out ({TIMEOUT}s)",
            {
                "domain": domain,
            },
        )
    finally:
        socket.setdefaulttimeout(old_timeout)


# ---------------------------------------------------------------------------
# TLS certificate chain inspection
# ---------------------------------------------------------------------------


def _parse_cert_tuple_field(field_tuples):
    """Convert ssl cert field tuples like ((('commonName', 'example.com'),),) to string."""
    parts = []
    if not field_tuples:
        return ""
    for rdn in field_tuples:
        for attr_type, attr_value in rdn:
            parts.append(f"{attr_type}={attr_value}")
    return ", ".join(parts)


def _is_zta_enrolled():
    """Check if this endpoint has an active ZTA enrollment.

    Looks for enrollment JSON files in the ZTA enrollments directory.
    These files are world-readable (no sudo required) and their presence
    means the endpoint is enrolled in a ZTA profile — which means the
    ZTA profile's Secure Internet Access exceptions control traffic
    steering, NOT the Internet Security > Traffic Steering page.
    """
    if IS_MACOS:
        enroll_dir = CSC_BASE / "zta" / "enrollments"
    elif IS_WINDOWS:
        enroll_dir = CSC_BASE / "ZTA" / "enrollments"
    else:
        return False
    try:
        if enroll_dir.is_dir():
            return any(f.suffix == ".json" for f in enroll_dir.iterdir())
    except OSError:
        pass
    return False


def _identify_by_domain_name(domain):
    """Identify a domain's owner from its name using KNOWN_DOMAIN_OWNERS suffixes.

    Returns owner name string or None. Used as a fallback when cert org and
    reverse DNS both fail — common for Apple, Google, and other large operators
    whose IP ranges have no meaningful reverse DNS.
    """
    dl = domain.lower()
    for suffix, owner in KNOWN_DOMAIN_OWNERS:
        if dl == suffix.lstrip(".") or dl.endswith(suffix):
            return owner
    return None


def _get_cert_org(tls_result):
    """Extract organization name from a TLS result's leaf cert subject.

    Returns None if the cert is Cisco-issued (decrypted traffic) or unavailable.
    """
    details = tls_result.get("details", {})
    leaf_subject = details.get("leaf_subject", "")
    if not leaf_subject:
        return None
    m = _ORG_RE.search(leaf_subject)
    if not m:
        return None
    org = m.group(1).strip()
    if any(marker in org.lower() for marker in CISCO_CERT_MARKERS):
        return None
    return org


def _resolve_domain_info(domain):
    """Resolve domain IPs and identify hosting provider via reverse DNS.

    Returns dict with keys: ips, rdns (ip -> hostname), provider (name, rdns_host) or None.
    Limits reverse DNS to 3 IPs to avoid excessive latency.
    """
    result = {"ips": [], "rdns": {}, "provider": None}
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(TIMEOUT)
        addrs = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list(dict.fromkeys(addr[4][0] for addr in addrs))[:3]
        result["ips"] = ips
        for ip in ips:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                result["rdns"][ip] = hostname
                if result["provider"] is None:
                    hl = hostname.lower()
                    for substr, name in KNOWN_PROVIDERS:
                        if substr in hl:
                            result["provider"] = (name, hostname)
                            break
            except (socket.herror, socket.gaierror, OSError):
                pass
    except (socket.gaierror, OSError):
        pass
    finally:
        socket.setdefaulttimeout(old_timeout)
    return result


def _parse_der_cert_with_openssl(der_bytes):
    """Parse subject and issuer from DER certificate bytes using openssl."""
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer"],
            input=der_bytes,
            capture_output=True,
            timeout=TIMEOUT,
        )
        if proc.returncode == 0:
            output = proc.stdout.decode("utf-8", errors="replace")
            subject = ""
            issuer = ""
            for line in output.strip().splitlines():
                if line.startswith("subject="):
                    subject = line[len("subject=") :].strip()
                elif line.startswith("issuer="):
                    issuer = line[len("issuer=") :].strip()
            return {"subject": subject, "issuer": issuer}
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def is_cisco_in_chain(chain_entries):
    """Check if any cert in chain has Cisco/Umbrella/OpenDNS markers."""
    for entry in chain_entries:
        combined = f"{entry.get('subject', '')} {entry.get('issuer', '')}".lower()
        for marker in CISCO_CERT_MARKERS:
            if marker in combined:
                return True, entry.get("subject", "") or entry.get("issuer", "")
    return False, None


def inspect_tls(domain, port=443):
    """Inspect TLS certificate chain for Cisco interception indicators."""
    chain_entries = []
    method = "unknown"
    leaf_issuer = ""
    leaf_subject = ""
    sans = []

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_default_certs()

        with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get leaf cert info via getpeercert()
                leaf = ssock.getpeercert()
                if leaf:
                    leaf_subject = _parse_cert_tuple_field(leaf.get("subject", ()))
                    leaf_issuer = _parse_cert_tuple_field(leaf.get("issuer", ()))
                    sans = [v for k, v in leaf.get("subjectAltName", ()) if k == "DNS"]
                    chain_entries.append(
                        {
                            "subject": leaf_subject,
                            "issuer": leaf_issuer,
                            "type": "leaf",
                        }
                    )

                # Get full chain via get_verified_chain() (Python 3.13+)
                if hasattr(ssock, "get_verified_chain"):
                    method = "native"
                    der_chain = ssock.get_verified_chain()
                    # Skip index 0 (leaf, already captured above).
                    # get_verified_chain() returns DER-encoded bytes on Python 3.13+.
                    for i, der_bytes in enumerate(der_chain[1:], start=1):
                        parsed = _parse_der_cert_with_openssl(der_bytes)
                        if parsed:
                            cert_type = "root" if i == len(der_chain) - 1 else "intermediate"
                            parsed["type"] = cert_type
                            chain_entries.append(parsed)
                        else:
                            chain_entries.append(
                                {
                                    "subject": f"(cert #{i}, openssl unavailable)",
                                    "issuer": "(unknown)",
                                    "type": "intermediate",
                                }
                            )
                else:
                    method = "leaf_only"

    except ssl.SSLCertVerificationError as e:
        # Cert verification failed — could be self-signed or Cisco cert not trusted
        # Try without verification to still inspect the chain
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
                with ctx2.wrap_socket(sock, server_hostname=domain) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        parsed = _parse_der_cert_with_openssl(der)
                        if parsed:
                            parsed["type"] = "leaf (unverified)"
                            chain_entries.append(parsed)
                            method = "unverified"
        except (TimeoutError, ssl.SSLError, OSError) as fallback_err:
            _warn(f"TLS unverified fallback also failed for {domain}: {fallback_err}")

        if not chain_entries:
            return make_result(
                "tls",
                "error",
                f"TLS verification failed: {e}",
                {
                    "domain": domain,
                    "error": str(e),
                    "chain": [],
                },
            )

    except TimeoutError:
        return make_result(
            "tls",
            "error",
            f"TLS connection timed out ({TIMEOUT}s)",
            {
                "domain": domain,
                "chain": [],
            },
        )
    except ConnectionRefusedError:
        return make_result(
            "tls",
            "error",
            "Connection refused (port 443)",
            {
                "domain": domain,
                "chain": [],
            },
        )
    except ssl.SSLError as e:
        return make_result(
            "tls",
            "error",
            f"TLS error: {e}",
            {
                "domain": domain,
                "error": str(e),
                "chain": [],
            },
        )
    except OSError as e:
        return make_result(
            "tls",
            "error",
            f"Connection error: {e}",
            {
                "domain": domain,
                "error": str(e),
                "chain": [],
            },
        )

    # Determine verdict
    is_proxied, matching_cert = is_cisco_in_chain(chain_entries)

    if is_proxied:
        verdict = "PROXIED / DECRYPTED"
        status = "warning"
        msg = "Cisco SubCA FOUND — traffic is being proxied/decrypted"
    else:
        verdict = "DIRECT / BYPASSED"
        status = "ok"
        msg = "No Cisco SubCA detected — traffic appears direct"

    # Build human-readable chain string
    chain_display = []
    for entry in chain_entries:
        s = entry.get("subject", "")
        # Extract CN if available
        cn_match = _CN_RE.search(s)
        if cn_match:
            chain_display.append(cn_match.group(1))
        elif s:
            chain_display.append(s)
    chain_str = " \u2192 ".join(reversed(chain_display)) if chain_display else "(empty)"

    return make_result(
        "tls",
        status,
        msg,
        {
            "domain": domain,
            "verdict": verdict,
            "is_proxied": is_proxied,
            "matching_cert": matching_cert,
            "chain": chain_entries,
            "chain_display": chain_str,
            "leaf_issuer": leaf_issuer,
            "leaf_subject": leaf_subject,
            "sans": sans,
            "method": method,
        },
    )


# ---------------------------------------------------------------------------
# Traceroute
# ---------------------------------------------------------------------------


def run_traceroute(domain, max_hops=10):
    """Run a short traceroute and return parsed results."""
    if IS_MACOS:
        cmd = ["traceroute", "-m", str(max_hops), domain]
    elif IS_WINDOWS:
        cmd = ["tracert", "-h", str(max_hops), domain]
    else:
        cmd = ["traceroute", "-m", str(max_hops), domain]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TRACEROUTE_TIMEOUT,
        )
        lines = proc.stdout.strip().splitlines()
        hops = []
        for line in lines[1:]:  # Skip header
            line = line.strip()
            if line:
                hops.append(line)
        return make_result(
            "traceroute",
            "info",
            f"Traceroute to {domain} ({len(hops)} hops)",
            {
                "domain": domain,
                "hops": hops,
                "raw": proc.stdout,
            },
        )
    except FileNotFoundError:
        return make_result("traceroute", "warning", "traceroute command not found", {"domain": domain})
    except subprocess.TimeoutExpired:
        return make_result("traceroute", "warning", f"Traceroute timed out ({TRACEROUTE_TIMEOUT}s)", {"domain": domain})
    except OSError as e:
        return make_result("traceroute", "error", f"Traceroute error: {e}", {"domain": domain})


# ---------------------------------------------------------------------------
# Egress IP check
# ---------------------------------------------------------------------------


def _unverified_ssl_ctx():
    """Return an SSL context that skips certificate verification.

    When Cisco Secure Access intercepts HTTPS traffic it presents its own CA
    certificate.  Python's bundled CA store does not include that cert (it lives
    in the macOS Keychain), so verified connections always fail.  For egress-IP
    checks we only care about the response body, not the server's identity, so
    skipping verification is safe here.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch_egress_ip():
    """Get the public egress IP by querying external IP-echo services."""
    ctx = _unverified_ssl_ctx()
    for url in EGRESS_IP_SERVICES:
        try:
            req = Request(url, headers={"User-Agent": "csa_traffic_diag"})
            with urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
                ip = resp.read().decode("utf-8").strip()
                # Basic validation: should look like an IP
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    return ip, url
                # Also accept IPv6
                if ":" in ip and len(ip) <= 45:
                    return ip, url
        except (URLError, OSError, ValueError):
            continue
    return None, None


def _fetch_ipchicken_ip():
    """Fetch egress IP from ipchicken.com by parsing its HTML response.

    ipchicken.com should be added to the Cisco Secure Access traffic steering
    bypass list so that this request exits via the ISP rather than Cisco's tunnel.
    Returns the IP string on success, or None on failure.
    """
    try:
        req = Request(IPCHICKEN_URL, headers={"User-Agent": "csa_traffic_diag"})
        # SSL context handles potential HTTP→HTTPS redirect by the proxy
        with urlopen(req, timeout=TIMEOUT, context=_unverified_ssl_ctx()) as resp:
            html = resp.read().decode("utf-8", errors="replace")
        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", html)
        if match:
            return match.group(1)
    except (URLError, OSError, ValueError):
        pass
    return None


def check_egress_ip():
    """Check the public egress IP and determine if it belongs to Cisco."""
    ip, source = _fetch_egress_ip()
    if not ip:
        return make_result(
            "egress_ip",
            "warning",
            "Could not determine egress IP — all IP-echo services unreachable",
            {
                "services_tried": list(EGRESS_IP_SERVICES),
            },
        )

    is_cisco = is_cisco_ip(ip)

    # Try reverse DNS for additional context
    rdns = ""
    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    if is_cisco:
        status = "warning"
        msg = f"Egress IP {ip} belongs to Cisco — traffic is tunneled through Secure Access"
        verdict = "TUNNELED"
    else:
        status = "ok"
        msg = f"Egress IP {ip} — appears to be a direct/ISP connection"
        verdict = "DIRECT"

    return make_result(
        "egress_ip",
        status,
        msg,
        {
            "ip": ip,
            "rdns": rdns,
            "source": source,
            "is_cisco": is_cisco,
            "verdict": verdict,
        },
    )


def print_egress_comparison(color):
    """Print a side-by-side egress IP comparison at the top of tool output.

    Fetches the egress IP via the normal tunneled path (likely Cisco) and via
    ipchicken.com (which should be on the traffic steering bypass list).  The
    two IPs together let the user instantly confirm whether bypass is working:
    they should differ when ipchicken.com is correctly bypassed.

    Helper text is context-aware: ZTA-enrolled endpoints use the ZTA profile's
    Secure Internet Access exceptions, while non-ZTA endpoints (Umbrella, SWG)
    use the Internet Security > Traffic Steering page.
    """
    tunneled_ip, _ = _fetch_egress_ip()
    bypass_ip = _fetch_ipchicken_ip()
    zta = _is_zta_enrolled()

    # Context-aware helper text for where to configure bypass
    if zta:
        tunneled_hint = "tunneled via ZTA (Cisco Secure Access)"
        bypass_ok_hint = "ipchicken.com — ZTA profile bypass exception active"
        bypass_fail_hint = "still Cisco — add ipchicken.com to ZTA profile exceptions (Secure Internet Access)"
        bypass_add_hint = "add ipchicken.com to ZTA profile exceptions (Secure Internet Access)"
    else:
        tunneled_hint = "tunneled via Cisco Secure Access"
        bypass_ok_hint = "ipchicken.com — Internet Security traffic steering bypass active"
        bypass_fail_hint = "still Cisco — add ipchicken.com to Internet Security > Traffic Steering"
        bypass_add_hint = "add ipchicken.com to Internet Security > Traffic Steering"

    label_w = 20  # column width for labels
    print(f"  {color.bold('Egress IP Check:')}")

    if tunneled_ip:
        print(
            f"    {'Tunneled (Cisco):':<{label_w}} {color.yellow(tunneled_ip)}"
            f"  {color.dim('← ' + tunneled_hint)}"
        )
    else:
        print(f"    {'Tunneled (Cisco):':<{label_w}} {color.dim('unreachable')}")

    if bypass_ip:
        if bypass_ip == tunneled_ip or is_cisco_ip(bypass_ip):
            print(
                f"    {'Bypass (ISP):':<{label_w}} {color.yellow(bypass_ip)}"
                f"  {color.dim('← ' + bypass_fail_hint)}"
            )
        else:
            print(
                f"    {'Bypass (ISP):':<{label_w}} {color.green(bypass_ip)}"
                f"  {color.dim('← ' + bypass_ok_hint)}"
            )
    else:
        print(
            f"    {'Bypass (ISP):':<{label_w}} {color.dim('unreachable')}  "
            f"{color.dim('← ' + bypass_add_hint)}"
        )

    print()


# ---------------------------------------------------------------------------
# macOS Keychain — Cisco CA certificate trust check
# ---------------------------------------------------------------------------


def _real_user_home_macos():
    """Return the home directory of the invoking user, even when run via sudo.

    Under ``sudo``, Path.home() resolves to /var/root and
    security dump-trust-settings reads root's keychain — not the actual
    user's.  SUDO_USER contains the original username when present.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return Path(f"~{sudo_user}").expanduser()
    return Path.home()


def _is_cisco_ca_cert(name):
    """Return True if *name* looks like a Cisco CA certificate.

    Matches CISCO_CERT_MARKERS but excludes device-identity certs
    (URN-style names like ``urn:cisco:sse:ztna:deviceid:…``) which are
    not CA certs and do not need to be trusted.
    """
    lower = name.lower()
    if lower.startswith("urn:"):
        return False
    return any(m in lower for m in CISCO_CERT_MARKERS)


def _find_cisco_certs_macos():
    """Search System and login keychains for Cisco CA certificates.

    Returns a list of dicts with 'name' and 'hash' keys for every certificate
    whose label matches a known Cisco marker.
    """
    real_home = _real_user_home_macos()
    keychains = [
        Path("/Library/Keychains/System.keychain"),
        real_home / "Library/Keychains/login.keychain-db",
        real_home / "Library/Keychains/login.keychain",
    ]
    found = []
    seen_hashes = set()

    for kc in keychains:
        if not kc.exists():
            continue
        try:
            result = subprocess.run(
                ["security", "find-certificate", "-a", "-Z", str(kc)],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue

        current_hash = None
        current_name = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("SHA-1 hash:"):
                # Evaluate the previous cert before starting a new one
                if current_hash and current_name and current_hash not in seen_hashes:
                    if _is_cisco_ca_cert(current_name):
                        found.append({"name": current_name, "hash": current_hash})
                        seen_hashes.add(current_hash)
                current_hash = line.split(":", 1)[1].strip()
                current_name = None
            elif '"labl"<blob>=' in line:
                m = re.search(r'"labl"<blob>="([^"]+)"', line)
                if m:
                    current_name = m.group(1)

        # Evaluate final cert in the output
        if current_hash and current_name and current_hash not in seen_hashes:
            if _is_cisco_ca_cert(current_name):
                found.append({"name": current_name, "hash": current_hash})
                seen_hashes.add(current_hash)

    return found


def _get_trusted_cert_names_macos():
    """Return names of certs explicitly trusted in macOS trust settings.

    Checks both user-level and admin-level trust domains.  A cert is
    considered trusted when it appears in ``security dump-trust-settings``
    with either:
      - ``Number of trust settings : 0`` (Always Trust for all policies), or
      - at least one per-policy entry with Result Type TrustRoot / TrustAsRoot.

    Output format of ``security dump-trust-settings``::

        Cert 0: Cisco Secure Access Root CA
           Number of trust settings : 10
           Trust Setting 0:
              Policy OID            : SSL
              Result Type           : kSecTrustSettingsResultTrustRoot
        Cert 1: FortiClient DNS Root
           Number of trust settings : 0
    """
    trusted = set()
    trust_results = (
        "kSecTrustSettingsResultTrustRoot",
        "kSecTrustSettingsResultTrustAsRoot",
    )

    sudo_user = os.environ.get("SUDO_USER")
    for flags in ([], ["-d"]):  # user domain, admin domain
        try:
            # User-domain trust settings must be read as the real user —
            # running as root via sudo would query /var/root's keychain instead.
            if flags == [] and sudo_user:
                cmd = ["sudo", "-u", sudo_user, "security", "dump-trust-settings"]
            else:
                cmd = ["security", "dump-trust-settings"] + flags
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue

        current_name = None
        has_trust = False
        for line in result.stdout.splitlines():
            line = line.strip()
            # Match "Cert N: <cert name>"
            m = re.match(r"^Cert \d+: (.+)$", line)
            if m:
                if current_name and has_trust:
                    trusted.add(current_name.lower())
                current_name = m.group(1)
                has_trust = False
            elif line.startswith("Number of trust settings : 0"):
                # "Always Trust" for all policies — no per-policy entries follow
                has_trust = True
            elif any(t in line for t in trust_results):
                has_trust = True

        if current_name and has_trust:
            trusted.add(current_name.lower())

    return trusted


def print_keychain_cert_check_macos(color):
    """macOS only: print Cisco CA certificate installation and trust status.

    Read-only — queries Keychain but never modifies it.  Alerts the user if
    the Cisco CA cert is missing or present but not set to Always Trust.
    """
    cisco_certs = _find_cisco_certs_macos()
    label = "Cisco CA Cert:"
    label_w = 20

    print(f"  {color.bold('Keychain Trust Check:')}")

    if not cisco_certs:
        print(
            f"    {label:<{label_w}} {color.red('NOT FOUND')}"
            f"  {color.dim('← install Cisco CA cert in Keychain and set to Always Trust')}"
        )
        print()
        return

    trusted_names = _get_trusted_cert_names_macos()
    for cert in cisco_certs:
        name = cert["name"]
        if name.lower() in trusted_names:
            print(f"    {label:<{label_w}} {color.green('TRUSTED')}  {color.dim(f'← {name}')}")
        else:
            print(
                f"    {label:<{label_w}} {color.yellow('NOT TRUSTED')}"
                f"  {color.dim(f'← {name} — Keychain Access → find cert → Get Info → Trust → Always Trust')}"
            )

    print()


# ---------------------------------------------------------------------------
# Route path check — determines which interface traffic would use
# ---------------------------------------------------------------------------


def _parse_route_get_macos(output):
    """Parse macOS `route get` output to extract interface and gateway."""
    info = {"interface": None, "gateway": None, "flags": None, "raw": output}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            info["interface"] = line.split(":", 1)[1].strip()
        elif line.startswith("gateway:"):
            info["gateway"] = line.split(":", 1)[1].strip()
        elif line.startswith("flags:"):
            info["flags"] = line.split(":", 1)[1].strip()
    return info


def _is_tunnel_interface(iface_name):
    """Check if an interface name matches known tunnel interface patterns."""
    if not iface_name:
        return False
    lower = iface_name.lower()
    return any(pat in lower for pat in TUNNEL_IFACE_PATTERNS)


def check_route_path(domain, resolved_ips=None):
    """Check the routing path for a domain's IP to determine tunnel vs. direct.

    On macOS: uses `route get <ip>` to check which interface traffic would traverse.
    On Windows: uses `route print` and `Find-NetRoute` PowerShell cmdlet.
    """
    # Resolve the domain if IPs not provided
    if not resolved_ips:
        try:
            results = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            resolved_ips = sorted({str(addr[4][0]) for addr in results})
        except (TimeoutError, socket.gaierror):
            return make_result(
                "route_path",
                "warning",
                f"Cannot resolve {domain} to check route path",
                {
                    "domain": domain,
                },
            )

    if not resolved_ips:
        return make_result("route_path", "warning", f"No IPs resolved for {domain}", {"domain": domain})

    # Use first resolved IP for route check
    target_ip = resolved_ips[0]

    if IS_MACOS:
        return _check_route_macos(domain, target_ip)
    elif IS_WINDOWS:
        return _check_route_windows(domain, target_ip)
    return make_result(
        "route_path",
        "info",
        f"Route path check not supported on {platform.system()}",
        {
            "domain": domain,
        },
    )


def _check_route_macos(domain, target_ip):
    """macOS route path check using `route get`."""
    try:
        proc = subprocess.run(
            ["route", "get", target_ip],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        info = _parse_route_get_macos(proc.stdout)
        iface = info.get("interface")
        gateway = info.get("gateway")
        is_tunnel = _is_tunnel_interface(iface)

        if is_tunnel:
            status = "warning"
            verdict = "TUNNELED"
            msg = (
                f"Traffic to {domain} ({target_ip}) routes through tunnel interface {iface} — NOT bypassed at KDF level"
            )
        else:
            status = "ok"
            verdict = "DIRECT"
            msg = f"Traffic to {domain} ({target_ip}) routes through local interface {iface} — bypassed at KDF level"

        return make_result(
            "route_path",
            status,
            msg,
            {
                "domain": domain,
                "target_ip": target_ip,
                "interface": iface,
                "gateway": gateway,
                "is_tunnel": is_tunnel,
                "verdict": verdict,
                "raw": proc.stdout.strip(),
            },
        )
    except FileNotFoundError:
        return make_result("route_path", "warning", "route command not found", {"domain": domain})
    except subprocess.TimeoutExpired:
        return make_result("route_path", "warning", f"Route check timed out ({TIMEOUT}s)", {"domain": domain})
    except OSError as e:
        return make_result("route_path", "error", f"Route check error: {e}", {"domain": domain, "error": str(e)})


def _check_route_windows(domain, target_ip):
    """Windows route path check using Find-NetRoute PowerShell cmdlet."""
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        return make_result("route_path", "error", f"Invalid IP address: {target_ip}", {"domain": domain})
    try:
        ps_cmd = (
            f"Find-NetRoute -RemoteIPAddress '{target_ip}' "
            f"| Select-Object -Property InterfaceAlias, InterfaceIndex, NextHop "
            f"| ConvertTo-Json"
        )
        proc = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        if proc.stdout.strip():
            try:
                route_info = json.loads(proc.stdout)
                if isinstance(route_info, list):
                    route_info = route_info[0]
                iface = route_info.get("InterfaceAlias", "")
                next_hop = route_info.get("NextHop", "")
                is_tunnel = _is_tunnel_interface(iface)

                if is_tunnel:
                    status = "warning"
                    verdict = "TUNNELED"
                    msg = f"Traffic to {domain} ({target_ip}) routes through tunnel interface '{iface}' — NOT bypassed"
                else:
                    status = "ok"
                    verdict = "DIRECT"
                    msg = f"Traffic to {domain} ({target_ip}) routes through local interface '{iface}' — bypassed"

                return make_result(
                    "route_path",
                    status,
                    msg,
                    {
                        "domain": domain,
                        "target_ip": target_ip,
                        "interface": iface,
                        "next_hop": next_hop,
                        "is_tunnel": is_tunnel,
                        "verdict": verdict,
                    },
                )
            except json.JSONDecodeError:
                pass

        return make_result(
            "route_path",
            "warning",
            f"Could not parse route info for {target_ip}",
            {
                "domain": domain,
                "raw": proc.stdout[:500],
            },
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return make_result("route_path", "warning", f"Route check failed: {e}", {"domain": domain, "error": str(e)})


# ---------------------------------------------------------------------------
# Domain diagnosis orchestrator
# ---------------------------------------------------------------------------


def diagnose_domain(domains_str, trace=False):
    """Run DNS + TLS + route path (+ optional traceroute) for comma-separated domains."""
    domains = [d.strip() for d in domains_str.split(",") if d.strip()]
    all_results = []

    # Global egress IP check (once, not per-domain)
    all_results.append(check_egress_ip())

    for domain in domains:
        dns_result = diagnose_dns(domain)
        all_results.append(dns_result)

        tls_result = inspect_tls(domain)
        all_results.append(tls_result)

        # Extract resolved IPs from DNS result to pass to route check
        resolved_ips = dns_result.get("details", {}).get("ips", [])
        route_result = check_route_path(domain, resolved_ips=resolved_ips)
        all_results.append(route_result)

        if trace:
            tr_result = run_traceroute(domain)
            all_results.append(tr_result)

    return all_results


# ---------------------------------------------------------------------------
# Client status — macOS
# ---------------------------------------------------------------------------


def _check_process_macos(name, pattern):
    """Check if a process matching pattern is running on macOS."""
    try:
        proc = subprocess.run(
            ["pgrep", "-fl", pattern],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            lines = proc.stdout.strip().splitlines()
            pid = lines[0].split()[0]
            return make_result(
                "process",
                "ok",
                f"{name}: Running (PID {pid})",
                {
                    "name": name,
                    "running": True,
                    "pid": pid,
                    "matches": lines,
                },
            )
        return make_result(
            "process",
            "warning",
            f"{name}: Not running",
            {
                "name": name,
                "running": False,
            },
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return make_result(
            "process",
            "error",
            f"{name}: Check failed — {e}",
            {
                "name": name,
                "error": str(e),
            },
        )


def _check_system_extension_macos():
    """Check for acsockext system extension on macOS."""
    try:
        proc = subprocess.run(
            ["systemextensionsctl", "list"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        output = proc.stdout + proc.stderr
        for line in output.splitlines():
            if "acsockext" in line.lower():
                if "activated enabled" in line.lower() or "[activated enabled]" in line.lower():
                    return make_result(
                        "sysext",
                        "ok",
                        "acsockext: Loaded (activated enabled)",
                        {
                            "extension": "acsockext",
                            "loaded": True,
                            "detail": line.strip(),
                        },
                    )
                return make_result(
                    "sysext",
                    "warning",
                    f"acsockext: Found but state unclear — {line.strip()}",
                    {
                        "extension": "acsockext",
                        "loaded": False,
                        "detail": line.strip(),
                    },
                )
        return make_result(
            "sysext",
            "warning",
            "acsockext: Not found",
            {
                "extension": "acsockext",
                "loaded": False,
            },
        )
    except FileNotFoundError:
        return make_result(
            "sysext",
            "warning",
            "systemextensionsctl not available",
            {
                "extension": "acsockext",
            },
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return make_result(
            "sysext",
            "error",
            f"System extension check failed: {e}",
            {
                "extension": "acsockext",
                "error": str(e),
            },
        )


def _check_zta_state_macos():
    """Check ZTA connection state from log files."""
    # Find a readable text log from ZTA_LOG_PATHS
    zta_log = None
    for path in ZTA_LOG_PATHS:
        if path.exists() and path.is_file() and not path.suffix == ".db":
            zta_log = path
            break
    # Fallback: look for any .log file in ZTA dirs
    if zta_log is None:
        for path in ZTA_LOG_PATHS:
            search_dir = path.parent if path.is_file() or not path.exists() else path
            if search_dir.exists():
                for log_file in search_dir.glob("*.log"):
                    zta_log = log_file
                    break
            if zta_log:
                break
    if zta_log is None:
        return make_result(
            "zta_state",
            "info",
            "ZTA log not found — cannot determine connection state",
            {
                "checked_paths": [str(p) for p in ZTA_LOG_PATHS],
            },
        )

    try:
        with open(zta_log, errors="replace") as f:
            lines = list(deque(f, maxlen=ZTA_TAIL_LINES))
        for line in reversed(lines):
            ll = line.lower()
            if "connected" in ll and "disconnect" not in ll:
                return make_result(
                    "zta_state",
                    "ok",
                    "ZTA State: Connected",
                    {
                        "state": "connected",
                        "log_line": line.strip(),
                    },
                )
            if "disconnect" in ll:
                return make_result(
                    "zta_state",
                    "warning",
                    "ZTA State: Disconnected",
                    {
                        "state": "disconnected",
                        "log_line": line.strip(),
                    },
                )
        return make_result(
            "zta_state",
            "info",
            "ZTA State: Unable to determine from logs",
            {
                "state": "unknown",
            },
        )
    except PermissionError:
        return make_result(
            "zta_state",
            "warning",
            "ZTA log requires elevated permissions (try sudo)",
            {
                "state": "unknown",
            },
        )
    except OSError as e:
        return make_result(
            "zta_state",
            "error",
            f"Cannot read ZTA log: {e}",
            {
                "state": "unknown",
                "error": str(e),
            },
        )


def check_status_macos():
    """Check Cisco Secure Client status on macOS."""
    results = []

    # Process checks
    processes = [
        ("csc_vpnagentd", "vpnagentd"),
        ("csc_swgagent", "csc_swgagent"),
        ("aciseposture", "aciseposture"),
    ]
    for name, pattern in processes:
        results.append(_check_process_macos(name, pattern))

    # System extension
    results.append(_check_system_extension_macos())

    # ZTA state
    results.append(_check_zta_state_macos())

    return results


# ---------------------------------------------------------------------------
# Client status — Windows
# ---------------------------------------------------------------------------


def _check_process_windows(name, exe_name):
    """Check if a process is running on Windows."""
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe_name}"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        if exe_name.lower() in proc.stdout.lower():
            # Extract PID from tasklist output
            for line in proc.stdout.splitlines():
                if exe_name.lower() in line.lower():
                    parts = line.split()
                    pid = parts[1] if len(parts) > 1 else "?"
                    return make_result(
                        "process",
                        "ok",
                        f"{name}: Running (PID {pid})",
                        {
                            "name": name,
                            "running": True,
                            "pid": pid,
                        },
                    )
        return make_result(
            "process",
            "warning",
            f"{name}: Not running",
            {
                "name": name,
                "running": False,
            },
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return make_result(
            "process",
            "error",
            f"{name}: Check failed — {e}",
            {
                "name": name,
                "error": str(e),
            },
        )


def _check_service_windows(service_name):
    """Check a Windows service status."""
    try:
        proc = subprocess.run(
            ["sc", "query", service_name],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        output = proc.stdout
        state_match = re.search(r"STATE\s+:\s+\d+\s+(\w+)", output)
        if state_match:
            state = state_match.group(1)
            status = "ok" if state == "RUNNING" else "warning"
            return make_result(
                "service",
                status,
                f"{service_name}: {state}",
                {
                    "service": service_name,
                    "state": state,
                },
            )
        return make_result(
            "service",
            "warning",
            f"{service_name}: Not found",
            {
                "service": service_name,
            },
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return make_result(
            "service",
            "error",
            f"{service_name}: Check failed — {e}",
            {
                "service": service_name,
                "error": str(e),
            },
        )


def check_status_windows():
    """Check Cisco Secure Client status on Windows."""
    results = []

    processes = [
        ("vpnagent", "vpnagent.exe"),
        ("csc_swgagent", "csc_swgagent.exe"),
        ("aciseagent", "aciseagent.exe"),
    ]
    for name, exe in processes:
        results.append(_check_process_windows(name, exe))

    results.append(_check_service_windows("csc_vpnagentd"))

    return results


def check_status():
    """Check Cisco Secure Client component status (cross-platform)."""
    if not CSC_BASE.exists():
        return [
            make_result(
                "status",
                "warning",
                f"Cisco Secure Client not detected at {CSC_BASE}",
                {
                    "installed": False,
                },
            )
        ]
    if IS_MACOS:
        return check_status_macos()
    elif IS_WINDOWS:
        return check_status_windows()
    return [make_result("status", "warning", f"Unsupported platform: {platform.system()}", {})]


# ---------------------------------------------------------------------------
# Log scan — shared utilities
# ---------------------------------------------------------------------------


def _parse_log_line(line, source):
    """Extract keyword, domain, and timestamp from a log line.

    Returns an entry dict if the line matches LOG_PATTERNS, else None.
    """
    match = LOG_PATTERNS.search(line)
    if not match:
        return None
    ts_match = TIMESTAMP_RE.search(line)
    domain_match = DOMAIN_RE.search(line)
    return {
        "source": source,
        "line": line.strip()[:MAX_LOG_LINE_LEN],
        "keyword": match.group(1),
        "domain": domain_match.group(1) if domain_match else None,
        "timestamp": ts_match.group(0) if ts_match else None,
    }


def _scan_text_file(filepath, minutes):
    """Scan a text log file for matching patterns within the time window."""
    entries = []
    cutoff = datetime.datetime.now() - datetime.timedelta(minutes=minutes)

    try:
        with open(filepath, errors="replace") as f:
            for line in f:
                entry = _parse_log_line(line, str(filepath))
                if not entry:
                    continue

                # Check timestamp if present — skip entries before cutoff
                ts_str = entry.get("timestamp")
                if ts_str:
                    try:
                        ts = datetime.datetime.strptime(ts_str.replace("T", " "), "%Y-%m-%d %H:%M:%S")
                        if ts < cutoff:
                            continue
                    except ValueError:
                        pass  # Can't parse timestamp, include the line anyway

                entries.append(entry)
    except PermissionError:
        entries.append(
            {
                "source": str(filepath),
                "line": "Permission denied — try running with sudo",
                "keyword": "error",
                "domain": None,
                "timestamp": None,
            }
        )
    except OSError as e:
        entries.append(
            {
                "source": str(filepath),
                "line": f"Cannot read file: {e}",
                "keyword": "error",
                "domain": None,
                "timestamp": None,
            }
        )

    return entries


class _DomainBucket:
    """Accumulator for log entries grouped by domain."""

    __slots__ = ("count", "keywords", "entries")

    def __init__(self):
        self.count = 0
        self.keywords: dict[str, int] = defaultdict(int)
        self.entries: list[dict] = []

    def add(self, entry):
        self.count += 1
        self.keywords[entry["keyword"]] += 1
        if len(self.entries) < MAX_SAMPLE_ENTRIES:
            self.entries.append(entry)

    def to_dict(self):
        return {
            "count": self.count,
            "keywords": dict(self.keywords),
            "sample_entries": self.entries[:MAX_SAMPLE_ENTRIES],
        }


def _analyze_entries(entries):
    """Group log entries by domain and compute frequency counts."""
    by_domain: dict[str, _DomainBucket] = defaultdict(_DomainBucket)
    no_domain = _DomainBucket()

    for entry in entries:
        domain = entry.get("domain")
        if domain:
            by_domain[domain].add(entry)
        else:
            no_domain.add(entry)

    sorted_domains = sorted(by_domain.items(), key=lambda x: x[1].count, reverse=True)

    result = {}
    for domain, bucket in sorted_domains:
        result[domain] = bucket.to_dict()
    if no_domain.count:
        result["(no domain)"] = no_domain.to_dict()

    return result


# ---------------------------------------------------------------------------
# Log scan — macOS
# ---------------------------------------------------------------------------

_SAFE_SQL_IDENT = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _scan_zta_flowlog(db_path, minutes):
    """Attempt to read ZTA flow log SQLite database."""
    import sqlite3

    entries = []
    conn = None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

        # Discover tables
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        cutoff = datetime.datetime.now() - datetime.timedelta(minutes=minutes)
        cutoff_ts = cutoff.timestamp()

        for table in tables:
            if not _SAFE_SQL_IDENT.match(table):
                _warn(f"Skipping table with unexpected name in {db_path}: {table!r}")
                continue
            try:
                cursor = conn.execute(f'SELECT * FROM "{table}" LIMIT 1')
                columns = [desc[0] for desc in cursor.description]

                # Find timestamp-like columns
                ts_col = None
                for col in columns:
                    if not _SAFE_SQL_IDENT.match(col):
                        continue
                    if any(k in col.lower() for k in ("time", "date", "ts", "created", "stamp")):
                        ts_col = col
                        break

                if ts_col:
                    rows = conn.execute(
                        f'SELECT * FROM "{table}" WHERE "{ts_col}" > ? ORDER BY "{ts_col}" DESC LIMIT {MAX_DB_ROWS}',
                        (cutoff_ts,),
                    ).fetchall()
                else:
                    rows = conn.execute(f'SELECT * FROM "{table}" ORDER BY rowid DESC LIMIT {MAX_DB_ROWS}').fetchall()

                for row in rows:
                    row_text = " ".join(str(v) for v in row if v is not None)
                    match = LOG_PATTERNS.search(row_text)
                    if match:
                        domain_match = DOMAIN_RE.search(row_text)
                        entries.append(
                            {
                                "source": f"{db_path} ({table})",
                                "line": row_text[:MAX_LOG_LINE_LEN],
                                "keyword": match.group(1),
                                "domain": domain_match.group(1) if domain_match else None,
                                "timestamp": None,
                            }
                        )
            except sqlite3.OperationalError:
                continue
    except sqlite3.OperationalError as e:
        if "unable to open" in str(e).lower() or "readonly" in str(e).lower():
            entries.append(
                {
                    "source": str(db_path),
                    "line": "Cannot open database — try running with sudo",
                    "keyword": "error",
                    "domain": None,
                    "timestamp": None,
                }
            )
    except PermissionError:
        entries.append(
            {
                "source": str(db_path),
                "line": "Permission denied — try running with sudo",
                "keyword": "error",
                "domain": None,
                "timestamp": None,
            }
        )
    except (sqlite3.Error, OSError, ValueError) as e:
        entries.append(
            {
                "source": str(db_path),
                "line": f"Error reading database: {e}",
                "keyword": "error",
                "domain": None,
                "timestamp": None,
            }
        )
    finally:
        if conn is not None:
            conn.close()

    return entries


def _scan_system_log_macos(minutes):
    """Scan macOS system log for Cisco-related entries."""
    entries = []
    try:
        proc = subprocess.run(
            [
                "log",
                "show",
                "--predicate",
                'process CONTAINS "cisco" OR process CONTAINS "csc_"',
                "--last",
                f"{minutes}m",
                "--style",
                "compact",
            ],
            capture_output=True,
            text=True,
            timeout=max(10, min(120, minutes * 2)),
        )
        for line in proc.stdout.splitlines():
            entry = _parse_log_line(line, "system_log")
            if entry:
                entries.append(entry)
    except subprocess.TimeoutExpired:
        entries.append(
            {
                "source": "system_log",
                "line": f"System log query timed out (consider reducing --minutes from {minutes})",
                "keyword": "timeout",
                "domain": None,
                "timestamp": None,
            }
        )
    except OSError as e:
        entries.append(
            {
                "source": "system_log",
                "line": f"Cannot query system log: {e}",
                "keyword": "error",
                "domain": None,
                "timestamp": None,
            }
        )

    return entries


def scan_logs_macos(minutes=60, domain_filter=None):
    """Scan all Cisco Secure Client log sources on macOS."""
    all_entries = []

    # Scan ZTA log paths from ZTA_LOG_PATHS
    for zta_path in ZTA_LOG_PATHS:
        if not zta_path.exists():
            continue
        if zta_path.suffix == ".db":
            all_entries.extend(_scan_zta_flowlog(str(zta_path), minutes))
        elif zta_path.is_file():
            all_entries.extend(_scan_text_file(zta_path, minutes))

    # Umbrella logs
    if UMBRELLA_DIR.exists():
        for log_file in UMBRELLA_DIR.glob("**/*.log"):
            all_entries.extend(_scan_text_file(log_file, minutes))

    # System log
    all_entries.extend(_scan_system_log_macos(minutes))

    if domain_filter:
        all_entries = [e for e in all_entries if _matches_domain_filter(e, domain_filter)]

    grouped = _analyze_entries(all_entries)
    total = sum(d["count"] for d in grouped.values())

    if total:
        status = "warning"
        msg = f"Found {total} matching log entries across {len(grouped)} domains"
    else:
        status = "ok"
        msg = f"No matching events found in the last {minutes} minutes"

    return make_result(
        "log_scan",
        status,
        msg,
        {
            "minutes": minutes,
            "total_entries": total,
            "by_domain": grouped,
            "domain_filter": domain_filter,
        },
    )


# ---------------------------------------------------------------------------
# Log scan — Windows
# ---------------------------------------------------------------------------


def _scan_winevents(minutes):
    """Query Windows Event Log for Cisco Secure Client events."""
    entries = []
    event_logs = [
        "Cisco Secure Client - Zero Trust Access",
        "Cisco AnyConnect Secure Mobility Client",
    ]

    for log_name in event_logs:
        try:
            ps_cmd = (
                f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; "
                f"StartTime=(Get-Date).AddMinutes(-{minutes})}} "
                f"-MaxEvents 100 -ErrorAction SilentlyContinue | "
                f"Select-Object TimeCreated, Message | ConvertTo-Json"
            )
            proc = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.stdout.strip():
                try:
                    events = json.loads(proc.stdout)
                    if isinstance(events, dict):
                        events = [events]
                    for evt in events:
                        msg = evt.get("Message", "")
                        match = LOG_PATTERNS.search(msg)
                        if match:
                            domain_match = DOMAIN_RE.search(msg)
                            entries.append(
                                {
                                    "source": f"EventLog:{log_name}",
                                    "line": msg[:MAX_LOG_LINE_LEN],
                                    "keyword": match.group(1),
                                    "domain": domain_match.group(1) if domain_match else None,
                                    "timestamp": evt.get("TimeCreated"),
                                }
                            )
                except json.JSONDecodeError as e:
                    entries.append(
                        {
                            "source": f"EventLog:{log_name}",
                            "line": f"Failed to parse event log JSON: {e}",
                            "keyword": "error",
                            "domain": None,
                            "timestamp": None,
                        }
                    )
        except (subprocess.TimeoutExpired, OSError):
            continue

    return entries


def scan_logs_windows(minutes=60, domain_filter=None):
    """Scan all Cisco Secure Client log sources on Windows."""
    all_entries = []

    # Windows Event Log
    all_entries.extend(_scan_winevents(minutes))

    # Text log files under CSC base
    if CSC_BASE.exists():
        for log_file in CSC_BASE.rglob("*.log"):
            all_entries.extend(_scan_text_file(log_file, minutes))

    # Umbrella logs
    if UMBRELLA_DIR.exists():
        for log_file in UMBRELLA_DIR.glob("**/*.log"):
            all_entries.extend(_scan_text_file(log_file, minutes))

    if domain_filter:
        all_entries = [e for e in all_entries if _matches_domain_filter(e, domain_filter)]

    grouped = _analyze_entries(all_entries)
    total = sum(d["count"] for d in grouped.values())

    if total:
        status = "warning"
        msg = f"Found {total} matching log entries across {len(grouped)} domains"
    else:
        status = "ok"
        msg = f"No matching events found in the last {minutes} minutes"

    return make_result(
        "log_scan",
        status,
        msg,
        {
            "minutes": minutes,
            "total_entries": total,
            "by_domain": grouped,
            "domain_filter": domain_filter,
        },
    )


def scan_logs(minutes=60, domain_filter=None):
    """Scan Cisco Secure Client logs (cross-platform)."""
    if IS_MACOS:
        return scan_logs_macos(minutes, domain_filter)
    elif IS_WINDOWS:
        return scan_logs_windows(minutes, domain_filter)
    return make_result("log_scan", "warning", f"Log scanning not supported on {platform.system()}", {})


# ---------------------------------------------------------------------------
# Full mode
# ---------------------------------------------------------------------------


def run_full_diagnosis(domain, minutes=60, trace=False):
    """Run domain diagnosis + log scan + client status."""
    results = []
    results.extend(diagnose_domain(domain, trace=trace))
    # Scan logs for each domain separately
    domains = [d.strip() for d in domain.split(",") if d.strip()]
    for d in domains:
        results.append(scan_logs(minutes, domain_filter=d))
    results.extend(check_status())
    return results


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def print_domain_results(results, color):
    """Print domain diagnosis results in the specified format."""
    # Separate egress IP (global), domain-specific, and other results
    egress_results = []
    domain_results = defaultdict(list)
    other_results = []

    for r in results:
        if r["check"] == "egress_ip":
            egress_results.append(r)
        elif r.get("details", {}).get("domain"):
            domain_results[r["details"]["domain"]].append(r)
        else:
            other_results.append(r)

    # Print egress IP check first (global context)
    for r in egress_results:
        details = r.get("details", {})
        icon = color.status_icon(r["status"])
        ip = details.get("ip", "unknown")
        rdns = details.get("rdns", "")
        print(f"\n{color.bold('[Egress IP Check]')}")
        rdns_str = f" ({rdns})" if rdns else ""
        if ip == "unknown":
            print(f"  Public IP:       {color.yellow('UNKNOWN')} \u2014 could not reach IP-echo services")
            print(f"  {icon} Verdict:       {color.yellow('UNABLE TO DETERMINE')} \u2014 run: curl -s ifconfig.me")
        elif details.get("is_cisco"):
            print(f"  Public IP:       {ip}{rdns_str}")
            print(f"  {icon} Verdict:       {color.red('TUNNELED')} \u2014 traffic exits through Cisco Secure Access")
            print("                   Netflix/streaming household detection WILL fail")
        else:
            print(f"  Public IP:       {ip}{rdns_str}")
            print(f"  {icon} Verdict:       {color.green('DIRECT')} \u2014 traffic exits through local ISP")

    for domain, checks in domain_results.items():
        print(f"\n{color.bold(f'[Domain Check: {domain}]')}")
        for r in checks:
            check = r["check"]
            details = r.get("details", {})
            icon = color.status_icon(r["status"])

            if check == "dns":
                ips = details.get("ips", [])
                ip_str = ", ".join(ips) if ips else "failed"
                cisco_flag = ""
                if details.get("is_cisco_dns"):
                    cisco_flag = color.yellow(" (Cisco/OpenDNS IP!)")
                print(f"  DNS Resolution:  {ip_str}{cisco_flag}")

            elif check == "tls":
                if r["status"] == "error":
                    print(f"  TLS Check:       {color.red(r['message'])}")
                    print(f"  {icon} Verdict:       {color.yellow('UNABLE TO DETERMINE')}")
                else:
                    chain_str = details.get("chain_display", "(unknown)")
                    print(f"  TLS Chain:       {chain_str}")

                    if details.get("is_proxied"):
                        print(f"  Cisco SubCA:     {color.yellow('FOUND')} \u26a0\ufe0f")
                        print(
                            f"  {icon} Verdict:       {color.red(details.get('verdict', 'PROXIED / DECRYPTED'))}"
                            f" \u2014 add to Traffic Steering Bypass"
                        )
                    else:
                        print(f"  Cisco SubCA:     {color.green('NOT FOUND')}")
                        print(f"  {icon} Verdict:       {color.green(details.get('verdict', 'DIRECT / BYPASSED'))}")

            elif check == "route_path":
                iface = details.get("interface", "unknown")
                target_ip = details.get("target_ip", "")
                is_tunnel = details.get("is_tunnel", False)
                gateway = details.get("gateway", "")

                gw_str = f" via {gateway}" if gateway else ""
                print(f"  Route Path:      {target_ip} \u2192 {iface}{gw_str}")
                if is_tunnel:
                    print(f"  {icon} KDF Verdict:   {color.red('TUNNELED')} — TSB not active for this domain")
                else:
                    print(f"  {icon} KDF Verdict:   {color.green('BYPASSED')} — traffic routes locally")

            elif check == "traceroute":
                hops = details.get("hops", [])
                print(f"  Traceroute:      {len(hops)} hops")
                for hop in hops:
                    print(f"    {color.dim(hop)}")

    for r in other_results:
        print(f"  {color.status_icon(r['status'])} {r['message']}")


def print_log_results(result, color, verbose=False):
    """Print log scan results."""
    details = result.get("details", {})
    minutes = details.get("minutes", 60)
    by_domain = details.get("by_domain", {})

    print(f"\n{color.bold(f'[Log Scan: last {minutes} minutes]')}")

    total = details.get("total_entries", 0)
    if total == 0:
        print(f"  {color.status_icon('ok')} No matching events found")
        return

    print(f"  Found {total} matching events:")
    for domain, data in by_domain.items():
        keywords = data.get("keywords", {})
        kw_str = ", ".join(f"{c}x {k}" for k, c in sorted(keywords.items(), key=lambda x: -x[1]))
        print(f"    {domain:<30s} \u2014 {kw_str}")
        if verbose:
            for entry in data.get("sample_entries", []):
                ts = entry.get("timestamp") or ""
                line = entry.get("line", "")
                if ts and line.startswith(ts):
                    line = line[len(ts) :].lstrip()
                prefix = f"{ts} | " if ts else "  "
                print(f"      {color.dim(prefix + line)}")


def print_status_results(results, color):
    """Print client status results."""
    print(f"\n{color.bold('[Client Status]')}")
    for r in results:
        details = r.get("details", {})
        icon = color.status_icon(r["status"])

        check = r["check"]
        if check == "process":
            name = details.get("name", "unknown")
            if details.get("running"):
                pid = details.get("pid", "?")
                print(f"  {name:<20s} {icon} Running (PID {pid})")
            else:
                print(f"  {name:<20s} {icon} Not running")
        elif check == "sysext":
            ext = details.get("extension", "unknown")
            if details.get("loaded"):
                print(f"  {ext:<20s} {icon} Loaded")
            else:
                print(f"  {ext:<20s} {icon} {r['message']}")
        elif check == "zta_state":
            print(f"  {'ZTA State':<20s} {icon} {r['message']}")
        elif check == "service":
            svc = details.get("service", "unknown")
            print(f"  {svc:<20s} {icon} {r['message']}")
        else:
            print(f"  {icon} {r['message']}")


def print_verdict_box(all_results, color):
    """Print summary verdict box."""
    statuses = [r.get("status") for r in all_results]
    has_error = "error" in statuses
    has_warning = "warning" in statuses

    line = "\u2500" * 55
    print(f"\n{color.bold(line)}")

    if has_error:
        verdict = color.red("ISSUES DETECTED")
        errors = sum(1 for s in statuses if s == "error")
        warnings = sum(1 for s in statuses if s == "warning")
        print(f"  Summary: {verdict} ({errors} errors, {warnings} warnings)")
    elif has_warning:
        verdict = color.yellow("WARNINGS")
        warnings = sum(1 for s in statuses if s == "warning")
        print(f"  Summary: {verdict} ({warnings} warnings)")
    else:
        verdict = color.green("ALL CLEAR")
        print(f"  Summary: {verdict}")

    print(color.bold(line))


def format_json(results):
    """Format results as JSON."""
    return json.dumps(results, indent=2, default=str)


# ---------------------------------------------------------------------------
# Traffic discovery — scan logs, categorize, and verify bypass routes
# ---------------------------------------------------------------------------


def _categorize_domain(bucket_dict):
    """Determine the primary category for a domain based on keyword counts."""
    keywords = bucket_dict.get("keywords", {})
    category_counts = defaultdict(int)
    for kw, count in keywords.items():
        cat = KEYWORD_CATEGORIES.get(kw.lower(), "error")
        category_counts[cat] += count
    if not category_counts:
        return "error"
    return max(category_counts, key=category_counts.get)


def _extract_base_domain(domain):
    """Extract a rough base domain for grouping (heuristic, no tldextract)."""
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return domain.lower()
    # Known two-part TLDs
    two_part = {"co.uk", "com.au", "co.jp", "co.nz", "com.br"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _group_by_base_domain(domains):
    """Group a list of domains by their base/registered domain."""
    groups = defaultdict(list)
    for d in domains:
        base = _extract_base_domain(d)
        groups[base].append(d)
    return dict(groups)


# Known macOS subsystem prefixes that look like domains but aren't
_PROCESS_ID_PREFIXES = (
    "com.cisco.",
    "com.apple.",
    "com.microsoft.",
    "com.google.",
    "org.mozilla.",
    "io.sentry.",
    "com.github.",
)

# File extensions that DOMAIN_RE matches as TLDs but are source/binary file names
# appearing in log messages (e.g. libMobileGestalt.dylib, IPCClient.cpp).
# Only includes extensions that are NOT real gTLDs or ccTLDs — excludes .app
# (gTLD), .py (Paraguay), .js (Jersey), .sh (Saint Helena), .so (Somalia),
# .rs (Serbia), .mm (Myanmar) to avoid filtering real domains.
_FILE_EXTENSIONS = frozenset({
    "cpp", "h", "c", "swift", "java", "class", "jar",
    "ts", "rb", "go",
    "dylib", "dll", "exe", "sys", "ko",
    "plist", "log", "conf", "cfg", "ini", "json", "xml", "yaml", "yml",
    "bat", "cmd", "ps1",
})


def _is_process_identifier(name):
    """Check if a string is a non-domain artifact from log messages.

    Catches macOS subsystem IDs (com.cisco.anyconnect.macos.acsockext),
    file references (libMobileGestalt.dylib, IPCClient.cpp), and other
    non-domain strings that DOMAIN_RE incorrectly matches.
    """
    lower = name.lower()
    parts = lower.split(".")

    # File extensions masquerading as TLDs — only for 2-part names (filename.ext).
    # Real domains like play.app or api.py have 3+ parts and are not caught here.
    if len(parts) == 2 and parts[-1] in _FILE_EXTENSIONS:
        return True

    # Reverse-DNS subsystem IDs (com.apple.securityd, com.cisco.secureclient.zta)
    if any(lower.startswith(prefix) for prefix in _PROCESS_ID_PREFIXES):
        if len(parts) >= 3:
            last = parts[-1]
            # Real TLDs are 2-6 chars, all alpha. Subsystem names like
            # "securityd", "CFNetwork", "acsockext" are longer or mixed case
            if len(last) > 6 or not last.isalpha():
                return True
            # If starts with com/org/io and last part isn't a known TLD pattern,
            # it's likely a subsystem ID
            known_tlds = {"com", "net", "org", "io", "edu", "gov", "mil", "int"}
            if parts[0] in ("com", "org", "io") and last not in known_tlds:
                return True
    return False


def discover_traffic(minutes=60, verify=False):
    """Scan logs, categorize domains, and optionally verify via TLS probing.

    Without --verify: categorizes by log keyword (bypass/block/error).
    With --verify: probes TLS cert chain per domain to determine:
        DECRYPTED    = Cisco SubCA in chain (SWG inspecting)
        NOT DECRYPTED = real cert (Do Not Decrypt or Traffic Steering Bypass)
        TLS ERROR    = connection failed (needs DND or TSB)

    Returns a dict with discovery results.
    """
    # 1. Scan logs
    log_result = scan_logs(minutes)
    by_domain = log_result.get("details", {}).get("by_domain", {})

    # 2. Categorize each domain by log keyword
    bypassed_domains = {}  # domain -> bucket_dict
    blocked_domains = {}
    error_domains = {}
    process_entries = None
    process_extra = _DomainBucket()

    for domain, bucket_dict in by_domain.items():
        if domain == "(no domain)":
            process_entries = bucket_dict
            continue

        if _is_process_identifier(domain):
            for entry in bucket_dict.get("sample_entries", []):
                process_extra.add(entry)
            for kw, count in bucket_dict.get("keywords", {}).items():
                process_extra.keywords[kw] += count
            process_extra.count += bucket_dict.get("count", 0)
            continue

        category = _categorize_domain(bucket_dict)
        if category == "bypass":
            bypassed_domains[domain] = bucket_dict
        elif category == "block":
            blocked_domains[domain] = bucket_dict
        else:
            error_domains[domain] = bucket_dict

    # Merge extra process entries
    if process_extra.count:
        if process_entries is None:
            process_entries = process_extra.to_dict()
        else:
            process_entries["count"] = process_entries.get("count", 0) + process_extra.count
            merged_kw = defaultdict(int, process_entries.get("keywords", {}))
            for kw, c in process_extra.keywords.items():
                merged_kw[kw] += c
            process_entries["keywords"] = dict(merged_kw)

    # 3. Group by base domain
    all_discovered = {}
    all_discovered.update(bypassed_domains)
    all_discovered.update(blocked_domains)
    all_discovered.update(error_domains)

    bypassed_groups = _group_by_base_domain(list(bypassed_domains.keys()))
    blocked_groups = _group_by_base_domain(list(blocked_domains.keys()))
    error_groups = _group_by_base_domain(list(error_domains.keys()))

    def _group_totals(groups, domain_data):
        result = {}
        for base, members in sorted(groups.items()):
            total = sum(domain_data[d]["count"] for d in members)
            kw_merged = defaultdict(int)
            for d in members:
                for kw, c in domain_data[d].get("keywords", {}).items():
                    kw_merged[kw] += c
            result[base] = {
                "domains": sorted(members),
                "count": total,
                "keywords": dict(kw_merged),
            }
        return result

    bypassed_summary = _group_totals(bypassed_groups, bypassed_domains)
    blocked_summary = _group_totals(blocked_groups, blocked_domains)
    error_summary = _group_totals(error_groups, error_domains)

    # 4. TLS verification (replaces route checks)
    tls_results = {}  # base_domain -> tls inspect result
    decrypted = {}  # base_domain -> group info (Cisco SubCA found)
    not_decrypted = {}  # base_domain -> group info (real cert — DND or TSB)
    tls_errors = {}  # base_domain -> group info (connection failed)

    if verify:
        # Probe all domain groups that had bypass or error keywords
        all_groups_to_probe = {}
        all_groups_to_probe.update(bypassed_groups)
        all_groups_to_probe.update(error_groups)

        print(f"Verifying {len(all_groups_to_probe)} domain groups...", file=sys.stderr)

        for base, members in all_groups_to_probe.items():
            representative = members[0]
            tls_result = inspect_tls(representative)
            tls_results[base] = tls_result

            # Get the group summary (from whichever category it came from)
            group_info = bypassed_summary.get(base) or error_summary.get(base)
            if not group_info:
                continue

            # Add TLS result to group info
            group_info = dict(group_info)  # copy
            tls_details = tls_result.get("details", {})
            group_info["tls_verdict"] = tls_details.get("verdict", "UNKNOWN")
            group_info["tls_chain"] = tls_details.get("chain_display", "")
            group_info["tls_probed"] = representative

            if tls_result["status"] == "error":
                # TLS connection failed
                group_info["tls_verdict"] = "TLS ERROR"
                group_info["tls_error"] = tls_result.get("message", "")
                tls_errors[base] = group_info
            elif tls_details.get("is_proxied"):
                # Cisco SubCA found — being decrypted
                group_info["tls_verdict"] = "DECRYPTED"
                decrypted[base] = group_info
            else:
                # Real cert — DND or TSB
                group_info["tls_verdict"] = "NOT DECRYPTED"
                not_decrypted[base] = group_info

    return {
        # Log-based categories (used when --verify is not set)
        "bypassed": bypassed_summary,
        "blocked": blocked_summary,
        "errors": error_summary,
        # TLS-based categories (used when --verify is set)
        "verified": verify,
        "decrypted": decrypted,
        "not_decrypted": not_decrypted,
        "tls_errors": tls_errors,
        "tls_results": tls_results,
        # Common
        "process_errors": process_entries,
        "minutes": minutes,
        "total_entries": log_result.get("details", {}).get("total_entries", 0),
    }


def print_discover_results(discovery, color, verbose=False):
    """Print traffic discovery results in a clean, actionable format."""
    minutes = discovery["minutes"]
    total = discovery["total_entries"]
    verified = discovery.get("verified", False)

    # Traffic discovery header
    print(f"\n{color.bold(f'[Traffic Discovery: last {minutes} minutes \u2014 {total} events]')}")

    if verified:
        _print_verified_results(discovery, color, verbose)
    else:
        _print_keyword_results(discovery, color, verbose)

    # Process errors (always shown)
    proc = discovery.get("process_errors")
    if proc and proc.get("count"):
        kw = proc.get("keywords", {})
        kw_str = ", ".join(f"{c}x {k}" for k, c in sorted(kw.items(), key=lambda x: -x[1])[:4])
        proc_count = proc.get("count", 0)
        print(f"\n  {color.bold(color.dim('PROCESS-LEVEL'))} (no domain \u2014 flow/kernel events):")
        print(f"    {color.dim(f'{proc_count} events: {kw_str}')}")

    # Recommendations (only in verify mode)
    if verified:
        actionable, related = _print_recommendations(discovery, color)
        if actionable and sys.stdin.isatty():
            try:
                answer = input("\n  Research these domains before making changes? [y/N]: ").strip().lower()
                if answer == "y":
                    _research_domains(actionable, related, discovery, color)
            except (EOFError, KeyboardInterrupt):
                print()


def _print_domain_group(base, info, color, verbose, tag=""):
    """Print a single domain group line."""
    members = info["domains"]
    count = info["count"]
    tag_str = f"  {tag}" if tag else ""
    if len(members) == 1:
        print(f"    {members[0]:<50s} {color.dim(f'{count}x')}{tag_str}")
    else:
        padding = max(1, 37 - len(base))
        print(f"    *.{base} ({len(members)} domains){' ' * padding}{color.dim(f'{count}x')}{tag_str}")
        if verbose:
            for m in members:
                print(f"      {color.dim(m)}")


def _print_keyword_results(discovery, color, verbose):
    """Print log-keyword-based results (when --verify is not used)."""
    bypassed = discovery["bypassed"]
    if bypassed:
        label = color.bold(color.green("BYPASSED"))
        print(f"\n  {label} (log keyword \u2014 run with --verify for TLS classification):")
        for base, info in sorted(bypassed.items(), key=lambda x: -x[1]["count"]):
            _print_domain_group(base, info, color, verbose)
    else:
        print(f"\n  {color.bold(color.green('BYPASSED'))}: None")

    blocked = discovery["blocked"]
    if blocked:
        print(f"\n  {color.bold(color.red('BLOCKED'))} (denied by policy):")
        for base, info in sorted(blocked.items(), key=lambda x: -x[1]["count"]):
            kw = info["keywords"]
            kw_str = ", ".join(f"{c}x {k}" for k, c in sorted(kw.items(), key=lambda x: -x[1]))
            _print_domain_group(base, info, color, verbose, tag=color.dim(kw_str))
    else:
        print(f"\n  {color.bold(color.red('BLOCKED'))}: None")

    errors = discovery["errors"]
    if errors:
        label = color.bold(color.yellow("ERRORS"))
        print(f"\n  {label} (TLS failures, timeouts \u2014 may need Do Not Decrypt or TSB):")
        for base, info in sorted(errors.items(), key=lambda x: -x[1]["count"]):
            kw = info["keywords"]
            kw_str = ", ".join(f"{c}x {k}" for k, c in sorted(kw.items(), key=lambda x: -x[1])[:4])
            _print_domain_group(base, info, color, verbose, tag=color.dim(kw_str))


def _print_verified_results(discovery, color, verbose):
    """Print TLS-verified results (when --verify is used)."""
    decrypted = discovery.get("decrypted", {})
    not_decrypted = discovery.get("not_decrypted", {})
    tls_errors = discovery.get("tls_errors", {})
    blocked = discovery.get("blocked", {})

    # DECRYPTED — Cisco SubCA found
    if decrypted:
        label = color.bold(color.cyan("DECRYPTED"))
        print(f"\n  {label} (Cisco SubCA in cert chain \u2014 SWG inspecting with full TLS interception):")
        print(f"    {color.dim('Egress: Cisco cloud IP addresses (visible to destination sites)')}")
        for base, info in sorted(decrypted.items(), key=lambda x: -x[1]["count"]):
            chain = info.get("tls_chain", "")
            tag = color.dim(f"chain: {chain}") if chain and verbose else ""
            _print_domain_group(base, info, color, verbose, tag=tag)
    else:
        print(f"\n  {color.bold(color.cyan('DECRYPTED'))}: None (no Cisco SubCA detected on any probed domain)")

    # NOT DECRYPTED — real cert, either DND or TSB
    if not_decrypted:
        label = color.bold(color.green("NOT DECRYPTED"))
        print(f"\n  {label} (real cert \u2014 Do Not Decrypt or Traffic Steering Bypass):")
        print(f"    {color.dim('Egress: your ISP IP address (direct connection)')}")
        for base, info in sorted(not_decrypted.items(), key=lambda x: -x[1]["count"]):
            chain = info.get("tls_chain", "")
            tag = color.green("\u2705 real cert")
            if verbose and chain:
                tag += color.dim(f"  chain: {chain}")
            _print_domain_group(base, info, color, verbose, tag=tag)

        # Helpful distinction note
        print(f"\n    {color.dim('\u2139\ufe0f  To distinguish Do Not Decrypt from Traffic Steering Bypass:')}")
        print(f"    {color.dim('   DND = still proxied (visible in Activity Search at connection layer)')}")
        print(f"    {color.dim('   TSB = fully bypassed (invisible to Activity Search at connection layer)')}")
    else:
        print(f"\n  {color.bold(color.green('NOT DECRYPTED'))}: None")

    # TLS ERRORS — connection failed
    if tls_errors:
        label = color.bold(color.yellow("TLS ERRORS"))
        print(f"\n  {label} (connection failed \u2014 likely needs Do Not Decrypt or TSB):")
        for base, info in sorted(tls_errors.items(), key=lambda x: -x[1]["count"]):
            err = info.get("tls_error", "unknown")
            tag = color.red(f"\u274c {err[:60]}")
            _print_domain_group(base, info, color, verbose, tag=tag)

    # BLOCKED — from log keywords, not TLS-verified
    if blocked:
        print(f"\n  {color.bold(color.red('BLOCKED'))} (denied by policy):")
        for base, info in sorted(blocked.items(), key=lambda x: -x[1]["count"]):
            kw = info["keywords"]
            kw_str = ", ".join(f"{c}x {k}" for k, c in sorted(kw.items(), key=lambda x: -x[1]))
            _print_domain_group(base, info, color, verbose, tag=color.dim(kw_str))


def _is_likely_noise(domain):
    """Check if a domain is likely ephemeral infrastructure noise.

    These are domains that commonly appear in TLS errors but are not
    actionable — they rotate, are special-use, or are media-path only.
    """
    lower = domain.lower().rstrip(".")
    parts = lower.split(".")

    # .arpa domains — special-use (reverse DNS, DDR/RFC 9462, etc.)
    if parts[-1] == "arpa":
        return "special-use .arpa domain (DNS infrastructure, not a web endpoint)"

    # STUN/TURN media servers — ephemeral NAT traversal endpoints
    if any(p in ("stun", "turn", "stun-us", "stun-eu", "stun-ap", "turn-us", "turn-eu", "turn-ap") for p in parts):
        return "STUN/TURN media server (ephemeral NAT traversal endpoint)"

    # SRV record targets — tcp./udp./_sip. prefixed hostnames
    if parts[0] in ("tcp", "udp", "_tcp", "_udp", "_sip", "_sips"):
        return "SRV record target (service discovery, not a direct endpoint)"

    return None


def _print_recommendations(discovery, color):
    """Print actionable recommendations with explicit domain lists.

    Cisco Secure Access Do Not Decrypt and Traffic Steering Bypass lists
    do NOT support wildcards — every domain must be entered individually.
    """
    tls_errors = discovery.get("tls_errors", {})
    decrypted = discovery.get("decrypted", {})

    if not tls_errors:
        return [], []

    # Separate actionable domains from likely noise
    actionable_domains = []
    noise_domains = []  # (domain, reason)
    for base, info in sorted(tls_errors.items()):
        for domain in sorted(info.get("domains", [base])):
            reason = _is_likely_noise(domain)
            if reason:
                noise_domains.append((domain, reason))
            else:
                actionable_domains.append(domain)

    # Find related domains in DECRYPTED that share a service root with actionable errors
    related_decrypted = []
    if decrypted and actionable_domains:
        error_roots = {_extract_service_root(d) for d in actionable_domains}
        for _, dec_info in decrypted.items():
            for d in dec_info.get("domains", []):
                if _extract_service_root(d) in error_roots:
                    related_decrypted.append(d)

    print(f"\n{color.bold('[Recommended Actions]')}")
    print(f"  {color.dim('Note: Wildcards are not supported. Each domain must be added individually.')}")

    if actionable_domains:
        print(f"\n  {color.bold('Add to Do Not Decrypt')} (traffic stays proxied \u2014 more secure than TSB):")
        for domain in actionable_domains:
            print(f"    {color.yellow(domain)}")
        print(f"\n  {color.dim('  Do Not Decrypt keeps traffic proxied through Cisco Secure Access (maintaining')}")
        print(f"  {color.dim('  visibility and security policy) but skips TLS interception.')}")
        print(f"  {color.dim('  If issues persist, escalate to Traffic Steering Bypass.')}")

    if related_decrypted:
        related_decrypted = sorted(set(related_decrypted))
        label = color.bold(color.yellow("Also add these related domains"))
        print(f"\n  {label} (currently DECRYPTED but related to error domains above):")
        for domain in related_decrypted:
            print(f"    {color.yellow(domain)}")
        print(f"  {color.dim('  These share a service with the error domains above. Add to Do Not Decrypt')}")
        print(f"  {color.dim('  for consistent coverage.')}")

    if noise_domains:
        label = color.bold(color.dim("Likely safe to ignore"))
        print(f"\n  {label} (ephemeral infrastructure \u2014 no action needed):")
        for domain, reason in noise_domains:
            print(f"    {color.dim(domain)}")
            print(f"      {color.dim(reason)}")

    if actionable_domains or related_decrypted:
        warn = "Do not blindly add domains to the Do Not Decrypt or Traffic Steering lists."
        print(f"\n  {color.bold(color.yellow('⚠️  ' + warn))}")
        print(f"  {color.yellow('   Research each domain before adding to any exclusion list.')}")

    return actionable_domains, related_decrypted


def _research_domains(actionable, related, discovery, color):
    """Research recommended domains — resolve IPs, identify owner, show SANs.

    Groups domains by identified owner (cert org or hosting provider) so the
    user can make an informed decision before adding to DND or TSB lists.
    """
    all_domains = list(actionable) + list(related)
    if not all_domains:
        return

    tls_results = discovery.get("tls_results", {})

    # Build domain → base mapping so we can look up TLS data per domain
    domain_to_base = {}
    for base, info in discovery.get("tls_errors", {}).items():
        for d in info.get("domains", [base]):
            domain_to_base[d] = base
    for base, info in discovery.get("decrypted", {}).items():
        for d in info.get("domains", [base]):
            domain_to_base[d] = base

    # Resolve each domain (show progress since DNS + rDNS can be slow)
    domain_data = {}
    for i, domain in enumerate(all_domains, 1):
        print(f"  Researching {domain} ({i}/{len(all_domains)})...{' ' * 20}", end="\r", file=sys.stderr)
        base = domain_to_base.get(domain)
        tls_result = tls_results.get(base) if base else None
        cert_org = _get_cert_org(tls_result) if tls_result else None
        info = _resolve_domain_info(domain)
        domain_data[domain] = {
            "cert_org": cert_org,
            "ips": info["ips"],
            "rdns": info["rdns"],
            "provider": info["provider"],
        }
    # Clear progress line
    print(" " * 60, end="\r", file=sys.stderr)

    # Collect SANs keyed by base domain (from TLS probe of representative)
    base_sans = {}
    for base, tls_result in tls_results.items():
        sans = tls_result.get("details", {}).get("sans", [])
        if sans:
            base_sans[base] = sans

    # Determine owner for each domain: cert org → hosting provider → domain name → Unidentified
    domain_owner = {}  # domain -> (owner_name, id_method)
    for domain in all_domains:
        data = domain_data[domain]
        if data.get("cert_org"):
            domain_owner[domain] = (data["cert_org"], "Certificate")
        elif data.get("provider"):
            pname, _ = data["provider"]
            domain_owner[domain] = (pname, "Hosting Provider")
        elif name_owner := _identify_by_domain_name(domain):
            domain_owner[domain] = (name_owner, "Domain Name")
        else:
            domain_owner[domain] = ("Unidentified", None)

    # Group domains by owner name
    groups = defaultdict(list)
    for domain, (owner, _) in domain_owner.items():
        groups[owner].append(domain)

    print(f"\n{color.bold('[Domain Research]')}")

    # Print identified groups first, Unidentified last
    sorted_owners = sorted(groups.keys(), key=lambda o: (o == "Unidentified", o))
    for owner in sorted_owners:
        domains_in_group = groups[owner]
        id_methods = {domain_owner[d][1] for d in domains_in_group if domain_owner[d][1]}
        id_label = f" \u2014 identified via {', '.join(sorted(id_methods))}" if id_methods else ""
        count = len(domains_in_group)
        header = f"{owner} ({count} domain{'s' if count != 1 else ''}{id_label})"
        print(f"\n  {color.bold(header)}")

        # Cert org (if identified via cert, show the actual org string)
        cert_orgs = sorted({domain_data[d]["cert_org"] for d in domains_in_group if domain_data[d].get("cert_org")})
        if cert_orgs:
            print(f"    Cert Org:  {', '.join(cert_orgs)}")

        # Hosting providers seen across the group
        seen_providers = {}
        for d in domains_in_group:
            p = domain_data[d].get("provider")
            if p:
                pname, phost = p
                if pname not in seen_providers:
                    seen_providers[pname] = phost
        for pname, phost in sorted(seen_providers.items()):
            print(f"    Hosting:   {color.dim(pname + ' (' + phost + ')')}")

        # SANs — show for first domain in group that has them
        for d in domains_in_group:
            base = domain_to_base.get(d)
            sans = base_sans.get(base, [])
            if sans:
                if len(sans) > 5:
                    sans_str = ", ".join(sans[:5]) + f", +{len(sans) - 5} more"
                else:
                    sans_str = ", ".join(sans)
                print(f"    SANs:      {color.dim(sans_str)}")
                break

        if owner == "Unidentified":
            print(f"    {color.yellow('⚠️  Could not identify owner — research manually before adding')}")

        print(f"    {color.dim('─' * 45)}")

        for d in sorted(domains_in_group):
            data = domain_data[d]
            label = "(related — currently decrypted)" if d in related else ""
            if data["ips"]:
                ip_str = color.dim(", ".join(data["ips"]))
            else:
                ip_str = color.dim("(DNS resolution failed)")
            suffix = f"  {color.dim(label)}" if label else ""
            print(f"    {d:<50s} {ip_str}{suffix}")


def _extract_service_root(domain):
    """Extract a rough service identifier for grouping related domains.

    e.g., 'ipv4-c007-smf001-consolidated-isp.1.oca.nflxvideo.net' -> 'nflx'
          'help.nflxext.com' -> 'nflx'
          'web.prod.cloud.netflix.com' -> 'netflix'
    """
    parts = domain.lower().rstrip(".").split(".")
    # Get the second-level domain (before TLD)
    if len(parts) >= 2:
        sld = parts[-2]
        # Strip common suffixes to find root brand
        for suffix in ("video", "ext", "so", "cdn"):
            if sld.endswith(suffix) and len(sld) > len(suffix):
                return sld[: -len(suffix)]
        return sld
    return domain.lower()


def _make_discover_results_list(discovery):
    """Convert discovery dict to a flat list of results for JSON/verdict."""
    results = []

    if discovery.get("verified"):
        for category, status in [("decrypted", "ok"), ("not_decrypted", "ok")]:
            data = discovery.get(category, {})
            if data:
                results.append(
                    make_result(
                        f"discover_{category}",
                        status,
                        f"{len(data)} domain group(s) {category}",
                        data,
                    )
                )
        # One warning per TLS error group so each domain group counts
        for base, info in discovery.get("tls_errors", {}).items():
            results.append(
                make_result(
                    "discover_tls_error",
                    "warning",
                    f"TLS error: {base}",
                    info,
                )
            )
        # Blocked domains (from log keywords, not TLS-verified)
        blocked = discovery.get("blocked", {})
        if blocked:
            results.append(
                make_result("discover_blocked", "warning", f"{len(blocked)} domain group(s) blocked", blocked)
            )
    else:
        for category in ("bypassed", "blocked", "errors"):
            data = discovery.get(category, {})
            if data:
                status = {"bypassed": "ok", "blocked": "warning", "errors": "warning"}[category]
                results.append(
                    make_result(
                        f"discover_{category}",
                        status,
                        f"{len(data)} domain group(s) {category}",
                        data,
                    )
                )

    return results


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(
        prog="csa_traffic_diag",
        description="Cisco Secure Access Traffic Diagnostic Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --discover --minutes 30           # scan & categorize by log keyword\n"
            "  %(prog)s --discover --verify --minutes 30   # + TLS probe to verify decryption\n"
            "  %(prog)s --discover --verify -v             # + show subdomains and cert chains\n"
            "  %(prog)s -d netflix.com,nflxvideo.net       # check specific domains\n"
            "  %(prog)s --full netflix.com                 # full diagnosis\n"
            "  %(prog)s --scan-logs --minutes 30           # raw log scan\n"
            "  %(prog)s --status                           # client status\n"
        ),
    )
    parser.add_argument(
        "--discover", action="store_true", help="Scan logs, discover domains, categorize (bypassed/blocked/errors)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="With --discover: TLS-probe each domain to classify as decrypted/not-decrypted/error",
    )
    parser.add_argument("-d", "--domain", help="Domain(s) to diagnose (comma-separated)")
    parser.add_argument("-t", "--trace", action="store_true", help="Include traceroute (10 hops max)")
    parser.add_argument(
        "--scan-logs", action="store_true", help="Scan Cisco Secure Client logs for block/error events (raw output)"
    )
    parser.add_argument("--status", action="store_true", help="Check Secure Client component status")
    parser.add_argument("--full", metavar="DOMAIN", help="Run full diagnosis (domain + logs + status)")
    parser.add_argument("--minutes", type=int, default=60, help="Log scan lookback in minutes (default: 60)")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show expanded detail (subdomains in discover, sample lines in scan-logs)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not any([args.domain, args.scan_logs, args.status, args.full, args.discover]):
        parser.print_help()
        return 1

    if args.minutes < 1:
        parser.error("--minutes must be at least 1")

    if args.verify and not args.discover:
        parser.error("--verify requires --discover")

    color = ColorOutput(no_color=args.no_color or args.json)
    all_results = []

    # Modes that involve network diagnosis benefit from the egress/cert header
    needs_network_header = args.domain or args.full or args.discover

    if not args.json:
        print(color.banner())
        if needs_network_header:
            print_egress_comparison(color)
            if IS_MACOS:
                print_keychain_cert_check_macos(color)

    # Discover mode: scan, categorize, verify
    if args.discover:
        discovery = discover_traffic(
            minutes=args.minutes,
            verify=args.verify,
        )
        all_results.extend(_make_discover_results_list(discovery))

        if args.json:
            print(format_json(discovery))
        else:
            print_discover_results(discovery, color, verbose=args.verbose)
            print_verdict_box(all_results, color)

        statuses = [r.get("status") for r in all_results]
        if "error" in statuses:
            sys.exit(1)
        if "warning" in statuses:
            sys.exit(2)
        return

    # Full mode: combines everything
    if args.full:
        results = run_full_diagnosis(
            args.full,
            minutes=args.minutes,
            trace=args.trace,
        )
        all_results.extend(results)

        if not args.json:
            # Separate domain results from status/log results
            domain_checks = ("dns", "tls", "traceroute", "egress_ip", "route_path")
            domain_results = [r for r in results if r["check"] in domain_checks]
            log_results = [r for r in results if r["check"] == "log_scan"]
            status_results = [r for r in results if r["check"] not in domain_checks and r["check"] != "log_scan"]

            print_domain_results(domain_results, color)
            for lr in log_results:
                print_log_results(lr, color, verbose=args.verbose)
            if status_results:
                print_status_results(status_results, color)

    else:
        # Domain diagnosis
        if args.domain:
            results = diagnose_domain(args.domain, trace=args.trace)
            all_results.extend(results)
            if not args.json:
                print_domain_results(results, color)

        # Log scan
        if args.scan_logs:
            domain_filter = args.domain.split(",")[0].strip() if args.domain else None
            result = scan_logs(args.minutes, domain_filter)
            all_results.append(result)
            if not args.json:
                print_log_results(result, color, verbose=args.verbose)

        # Client status
        if args.status:
            results = check_status()
            all_results.extend(results)
            if not args.json:
                print_status_results(results, color)

    # Output
    if args.json:
        print(format_json(all_results))
    else:
        print_verdict_box(all_results, color)

    # Exit code
    statuses = [r.get("status") for r in all_results]
    if "error" in statuses:
        sys.exit(1)
    if "warning" in statuses:
        sys.exit(2)


if __name__ == "__main__":
    main()
