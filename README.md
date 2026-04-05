# csa-traffic-diag

[![CodeQL](https://github.com/teak421/CSA-Traffic-Diag-Tool/actions/workflows/codeql.yml/badge.svg)](https://github.com/teak421/CSA-Traffic-Diag-Tool/actions/workflows/codeql.yml)

**CLI diagnostic tool for troubleshooting Cisco Secure Access (SSE) traffic routing on macOS and Windows.**

If you manage Cisco Secure Access (formerly Umbrella SIG / Secure Client with ZTA) in an enterprise environment, you've probably spent hours figuring out why a specific app or website breaks when the client is connected. This tool automates that investigation.

It answers the questions:
- **Is traffic to `example.com` being decrypted by Cisco's cloud proxy?** (TLS certificate chain inspection)
- **Is DNS being redirected through Cisco/OpenDNS?** (IP range detection)
- **Which domains are throwing errors in Cisco's logs?** (log scanning + categorization)
- **What should I add to Do Not Decrypt or Traffic Steering Bypass?** (actionable recommendations)

## Requirements

- **Python 3.13+** (uses [`ssl.SSLSocket.get_verified_chain()`](https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.get_verified_chain) for full certificate chain inspection)
- **No external dependencies** (stdlib only -- deploys anywhere Python runs)
- `openssl` CLI in PATH (optional, used for parsing intermediate certificate details)
- `sudo` on macOS / Administrator on Windows (required for log access; the tool runs without it but some checks will be limited)

## Installation

```bash
# Option 1: Run directly (no install)
python3 csa_traffic_diag.py -d example.com

# Option 2: Install as a CLI tool with uv
uv tool install .
csa-traffic-diag -d example.com

# Option 3: Install as a CLI tool with pip/pipx
pipx install .
csa-traffic-diag -d example.com
```

## Quick Start

```bash
# "Is Netflix being decrypted?"
csa-traffic-diag -d netflix.com

# "What's breaking in the last 30 minutes?"
sudo csa-traffic-diag --discover --minutes 30

# "Show me exactly what needs to go on the Do Not Decrypt list"
sudo csa-traffic-diag --discover --verify --minutes 30

# "Full workup on a specific domain"
sudo csa-traffic-diag --full netflix.com
```

## Modes

### Traffic Discovery (`--discover`)

The most powerful mode. Scans all Cisco Secure Client log sources, extracts every domain mentioned alongside error/block/bypass keywords, and categorizes them.

```bash
# Scan and categorize by log keyword
sudo csa-traffic-diag --discover

# Narrow the time window
sudo csa-traffic-diag --discover --minutes 15

# Show individual subdomains (not just base domain groups)
sudo csa-traffic-diag --discover -v
```

**Output categories:**
- **BYPASSED** -- domains with bypass keywords in logs
- **BLOCKED** -- domains denied by policy (block/deny/drop/refused)
- **ERRORS** -- domains with TLS failures, timeouts, certificate errors

#### With `--verify`: TLS Verification

Adding `--verify` goes beyond log keywords -- it actually connects to each discovered domain and inspects the TLS certificate chain to definitively classify traffic:

```bash
sudo csa-traffic-diag --discover --verify --minutes 30
```

**Verified output categories:**
- **DECRYPTED** -- Cisco SubCA found in the certificate chain (SWG is performing full TLS interception)
- **NOT DECRYPTED** -- real CA certificate (domain is on Do Not Decrypt or Traffic Steering Bypass)
- **TLS ERRORS** -- connection failed (domain likely needs to be added to Do Not Decrypt or TSB)
- **BLOCKED** -- denied by policy

When TLS errors are found, the tool prints **actionable recommendations** with the exact domain list to add to Do Not Decrypt, filtering out ephemeral infrastructure noise (STUN/TURN servers, `.arpa` domains, SRV targets).

#### Domain Research

After recommendations print, the tool prompts:

```
  ⚠️  Do not blindly add domains to the Do Not Decrypt or Traffic Steering lists.
     Research each domain before adding to any exclusion list.

  Research these domains before making changes? [y/N]:
```

Answering `y` resolves each domain and identifies its owner by checking the TLS certificate organization and reverse DNS hosting provider (Akamai, AWS, Cloudflare, Azure, Fastly, Google, and others). Results are grouped by owner:

```
[Domain Research]

  Microsoft (2 domains — identified via Hosting Provider)
    Hosting:   AWS CloudFront (d1234.cloudfront.net)
    SANs:      *.office.com, *.microsoft.com, +4 more
    ─────────────────────────────────────────────────
    login.microsoftonline.com                          52.98.208.2
    graph.microsoft.com                                13.107.42.14

  Unidentified (1 domain)
    ⚠️  Could not identify owner — research manually before adding
    ─────────────────────────────────────────────────
    api.unknown-service.io                             (DNS resolution failed)
```

This step is skipped when output is piped (`| tee log.txt`), so scripted use is unaffected.

### Domain Diagnosis (`-d`)

Check specific domains for DNS redirection and TLS interception:

```bash
# Single domain
csa-traffic-diag -d netflix.com

# Multiple domains
csa-traffic-diag -d netflix.com,nflxvideo.net,nflxext.com

# Include traceroute
csa-traffic-diag -d netflix.com -t
```

**What it checks:**
1. **DNS resolution** -- resolves the domain, flags Cisco/OpenDNS IP ranges, and identifies the DNS resolver (Cisco Secure Access when tunneled, or local resolver). When tunneled, compares against Google DNS-over-HTTPS to detect stale cache mismatches
2. **TLS certificate chain** -- connects on port 443, retrieves the full cert chain, checks for Cisco SubCA certificates
3. **Egress IP** -- queries external IP-echo services to determine if traffic exits through Cisco's cloud or your local ISP
4. **Route path** -- checks the OS routing table to see if the domain's IP routes through a tunnel interface (macOS: `route get`, Windows: `Find-NetRoute`)

### Log Scan (`--scan-logs`)

Raw log scanning with domain grouping and frequency counts:

```bash
# Scan last 60 minutes (default)
sudo csa-traffic-diag --scan-logs

# Scan last 5 minutes, filtered to a domain
sudo csa-traffic-diag --scan-logs --minutes 5 -d netflix.com

# Verbose: show sample log lines per domain
sudo csa-traffic-diag --scan-logs -v
```

**Log sources scanned:**

| Platform | Sources |
|----------|---------|
| macOS | ZTA flow log database (SQLite), ZTA text logs, Umbrella logs, system log (`log show`) |
| Windows | Windows Event Log (Cisco Secure Client, AnyConnect providers), Secure Client log files, Umbrella logs |

### Client Status (`--status`)

Check whether Cisco Secure Client components are running:

```bash
csa-traffic-diag --status
```

| Platform | What it checks |
|----------|---------------|
| macOS | `vpnagentd`, `csc_swgagent`, `aciseposture` processes; `acsockext` system extension; ZTA connection state from logs |
| Windows | `vpnagent.exe`, `csc_swgagent.exe`, `aciseagent.exe` processes; `csc_vpnagentd` service |

### Full Diagnosis (`--full`)

Combines domain diagnosis + log scan + client status:

```bash
sudo csa-traffic-diag --full netflix.com
sudo csa-traffic-diag --full netflix.com,nflxvideo.net --minutes 30 -t
```

## Output Options

```bash
# JSON output (for scripting, piping to jq, etc.)
csa-traffic-diag -d example.com --json

# Disable colored output
csa-traffic-diag -d example.com --no-color
```

Color is automatically disabled when output is piped to a file or another program.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | Errors detected (DNS failure, TLS connection refused, etc.) |
| `2` | Warnings detected (traffic proxied, processes not running, etc.) |

Useful for scripting:
```bash
sudo csa-traffic-diag --discover --verify --json > results.json
if [ $? -eq 2 ]; then echo "Warnings found -- review results.json"; fi
```

## Verifying Traffic Steering Bypass

The tool displays a dual egress IP comparison at the top of every run so you can instantly confirm whether your traffic steering bypass policy is working.

### Setup

Add `ipchicken.com` to your **Traffic Steering Bypass** list in the Cisco Secure Access dashboard (Policy → Traffic Steering). Once added, requests to ipchicken.com will exit directly through your ISP rather than Cisco's tunnel.

### What You'll See

```
  Egress IP Check:
    Tunneled (Cisco):    146.112.x.x   ← not in traffic steering bypass
    Bypass (ISP):        98.xx.xx.xx   ← ipchicken.com (traffic steering bypass)
```

- **Tunneled** — the egress IP for normal traffic routed through Cisco Secure Access
- **Bypass** — the egress IP fetched from `ipchicken.com`; should show your ISP's public IP

If both IPs are the **same**, ipchicken.com is not yet on the bypass list (or your bypass policy hasn't taken effect).

If ipchicken.com is **unreachable**, the tool will prompt you to add it to the bypass list.

### macOS: Cisco CA Certificate Trust Check

On macOS, the tool automatically checks whether the Cisco CA certificates are installed **and** trusted in your Keychain. This is a common gotcha — the Cisco Secure Client installer places the certificates in the System Keychain, but they must be **manually set to "Always Trust"** before TLS interception will work correctly. Without this step, browsers and apps will reject Cisco's re-signed certificates with SSL errors.

```
  Keychain Trust Check:
    Cisco CA Cert:       TRUSTED      ← Cisco Secure Access Root CA
    Cisco CA Cert:       TRUSTED      ← Cisco Umbrella Root CA
```

If a certificate shows **NOT TRUSTED**, open **Keychain Access**, find the certificate, right-click **Get Info**, expand the **Trust** section, and set "When using this certificate" to **Always Trust**. You will be prompted for your admin password.

> This check is **read-only** — the tool never modifies your Keychain or trust settings.

### Important: Bypass ≠ Do Not Decrypt

> ⚠️ **The Do Not Decrypt list is not the same as Traffic Steering Bypass.**
>
> Domains on the *Do Not Decrypt* list are still **proxied through Cisco Secure Access** — your traffic still exits via Cisco's IP. TLS inspection is simply skipped. Only domains on the *Traffic Steering Bypass* list are routed directly through your ISP and will show the ISP egress IP.

## How It Works

### TLS Interception Detection

When Cisco Secure Access decrypts traffic (via its Secure Web Gateway), it terminates the original TLS connection at its cloud proxy and re-encrypts it with a Cisco-issued SubCA certificate. The tool detects this by:

1. Connecting to the target domain on port 443
2. Retrieving the full certificate chain (using Python 3.13's `get_verified_chain()`)
3. Checking issuer fields for markers: `cisco`, `umbrella`, `opendns`, `secure access`

If a Cisco SubCA is found, traffic is being **proxied and decrypted**. If the real CA appears (DigiCert, Let's Encrypt, Sectigo, etc.), traffic is either on a **Do Not Decrypt** list or a **Traffic Steering Bypass** rule.

### DNS Redirection Detection

Cisco Umbrella's DNS-layer protection redirects queries to Cisco IP ranges. The tool flags resolved IPs in known Cisco/OpenDNS prefixes: `146.112.x.x`, `155.190.x.x`, `151.186.x.x`, `163.129.x.x`.

When ZTA is tunneling traffic, the tool labels DNS results as "(via Cisco Secure Access)" and queries Google DNS-over-HTTPS (`dns.google`) as an independent comparison. If the results differ, a mismatch warning is shown to help identify stale DNS cache issues.

> **Tip:** Add `dns.google` to your Traffic Steering Bypass list to enable the DNS comparison feature. Without it, ZTA intercepts the DoH request and the comparison is unavailable.

### Log Scanning

The tool reads Cisco Secure Client log files and databases, matching lines against keywords (`block`, `deny`, `error`, `timeout`, `certificate`, `decrypt`, `bypass`), extracting domain names and timestamps, and grouping results by domain with frequency counts.

## Example Output

### Domain Diagnosis

```
═══════════════════════════════════════════════════════
  Cisco Secure Access Traffic Diagnostic Tool v1.3.0
  Platform: macOS 15.4
  Log path: /opt/cisco/secureclient
═══════════════════════════════════════════════════════

[Egress IP Check]
  Public IP:       203.0.113.42 (example-isp.net)
  ✅ Verdict:       DIRECT -- traffic exits through local ISP

[Domain Check: netflix.com]
  DNS Resolution:  52.94.228.167, 54.155.178.5
  TLS Chain:       DigiCert Global Root G2 -> DigiCert TLS RSA SHA256 -> *.netflix.com
  Cisco SubCA:     NOT FOUND
  ✅ Verdict:       DIRECT / BYPASSED
  Route Path:      52.94.228.167 -> en0
  ✅ KDF Verdict:   BYPASSED -- traffic routes locally

───────────────────────────────────────────────────────
  Summary: ALL CLEAR
───────────────────────────────────────────────────────
```

### Traffic Discovery with `--verify`

```
[Traffic Discovery: last 30 minutes -- 247 events]

  DECRYPTED (Cisco SubCA in cert chain):
    *.example.com (3 domains)                        42x

  NOT DECRYPTED (real cert -- Do Not Decrypt or TSB):
    *.netflix.com (5 domains)                        89x  ✅ real cert

  TLS ERRORS (connection failed -- likely needs DND or TSB):
    *.nflxvideo.net (12 domains)                     63x  ❌ TLS error: ...

  BLOCKED (denied by policy):
    malware-site.example.org                          2x  2x blocked

[Recommended Actions]
  Note: Wildcards are not supported. Each domain must be added individually.

  Add to Do Not Decrypt (traffic stays proxied -- more secure than TSB):
    ipv4-c001-sjc001.1.oca.nflxvideo.net
    ipv4-c002-sjc001.1.oca.nflxvideo.net
    ...

  ⚠️  Do not blindly add domains to the Do Not Decrypt or Traffic Steering lists.
     Research each domain before adding to any exclusion list.

  Research these domains before making changes? [y/N]:
```

## Interpreting Results

### Not every TLS error means something is broken

The tool reports what it finds in the logs -- TLS handshake failures, connection timeouts, certificate errors. But many apps (especially ones with heavy redundancy like Webex, Teams, and Zoom) gracefully handle these failures by falling over to alternate endpoints.

**Example: Webex**

You might see output like this:

```
[Recommended Actions]

  Add to Do Not Decrypt:
    dfw21.hosted-us.bcld.webex.com

  Likely safe to ignore:
    da01.stun-us.bcld.webex.com
      STUN/TURN media server (ephemeral NAT traversal endpoint)
    tcp.dfw21.hosted-us.bcld.webex.com
      SRV record target (service discovery, not a direct endpoint)
```

The tool flags `dfw21.hosted-us.bcld.webex.com` because a real TLS error occurred in the logs. But if Webex meetings, calls, and screen sharing all work fine, the app silently recovered by using a different endpoint. The log entry is real, but the impact is zero.

**When to act vs. when to ignore:**
- **App is broken** (calls dropping, pages failing, cert errors in browser) -- follow the recommendations
- **App works fine** despite TLS errors in logs -- the errors are harmless failovers. Adding the domains to Do Not Decrypt won't hurt (and cleans up future scans), but it's not urgent
- **STUN/TURN and SRV entries** -- the tool filters these automatically. They're ephemeral media-path infrastructure and not actionable

The tool errs on the side of showing you everything. It can't know whether an app recovered from a TLS failure -- only you can tell by testing the app.

## Common Scenarios

### "Netflix/streaming is buffering or won't load"
```bash
csa-traffic-diag -d netflix.com,nflxvideo.net,nflxext.com
```
If you see `PROXIED / DECRYPTED`, the streaming CDN domains need to be on the Traffic Steering Bypass list.

### "A SaaS app is throwing certificate errors"
```bash
sudo csa-traffic-diag --discover --verify --minutes 60
```
Look for domains in the **TLS ERRORS** section. Add them to Do Not Decrypt first; escalate to Traffic Steering Bypass if issues persist.

### "Webex/Teams/Zoom has intermittent issues"
```bash
sudo csa-traffic-diag --discover --verify --minutes 60
```
Check for TLS errors on the app's domains. If the app mostly works, the errors may be harmless failovers (see [Interpreting Results](#interpreting-results)). If calls are dropping or meetings fail to connect, add the flagged domains to Do Not Decrypt.

### "I need to audit what Cisco is decrypting"
```bash
sudo csa-traffic-diag --discover --verify -v --json > audit.json
```
The JSON output contains the full TLS chain for every probed domain.

### "Is the Cisco client even running?"
```bash
csa-traffic-diag --status
```

## Security & Privacy

### GitHub Security Scanning

This repository has the following GitHub security features enabled:

- **[CodeQL Analysis](https://github.com/teak421/CSA-Traffic-Diag-Tool/actions/workflows/codeql.yml)** -- automated static analysis runs on every push, pull request, and weekly. Scans for security vulnerabilities, injection flaws, and unsafe code patterns
- **Secret Scanning** -- monitors the repository for accidentally committed API keys, tokens, and passwords
- **Push Protection** -- blocks pushes that contain detected secrets before they reach the repository
- **Dependabot** -- monitors dependencies for known vulnerabilities (this project has zero external dependencies)

### Code Safety

- **No external dependencies** -- nothing to supply-chain attack
- **Read-only** -- the tool never modifies system configuration, logs, or Cisco client settings
- **Subprocess safety** -- all subprocess calls use list-form arguments (no `shell=True`); no shell injection vectors
- **SQLite access** -- flow log databases are opened in read-only mode (`?mode=ro`)
- **Egress IP check** -- queries public IP-echo services (ifconfig.me, api.ipify.org, icanhazip.com, checkip.amazonaws.com) to determine your outbound IP. These are HTTPS requests
- **DNS-over-HTTPS** -- when ZTA is tunneling, queries `dns.google` and/or `cloudflare-dns.com` for DNS comparison. Only the domain name being diagnosed is sent. No other data is sent externally
- **Log content** -- output may include hostnames, IP addresses, and log snippets from your system. Review before sharing diagnostics externally

## License

MIT
