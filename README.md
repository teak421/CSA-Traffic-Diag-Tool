# csa-traffic-diag

[![CodeQL](https://github.com/teak421/CSA-Traffic-Diag-Tool/actions/workflows/codeql.yml/badge.svg)](https://github.com/teak421/CSA-Traffic-Diag-Tool/actions/workflows/codeql.yml)

**CLI diagnostic tool for troubleshooting Cisco Secure Access (SSE) traffic routing on macOS and Windows.**

If you manage Cisco Secure Access (formerly Umbrella SIG / Secure Client with ZTA) in an enterprise environment, you've probably spent hours figuring out why a specific app or website breaks when the client is connected. This tool automates that investigation.

It answers the questions:
- **Is traffic to `example.com` being decrypted by Cisco's cloud proxy?** (TLS certificate chain inspection)
- **Is DNS being redirected through Cisco/OpenDNS?** (resolver identification + Google DoH comparison)
- **Why is my app broken even though the domain isn't blocked?** (HTTPS connectivity test + app impact analysis)
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

# "Why can't LM Studio download models?"
sudo csa-traffic-diag -d huggingface.co

# "What's breaking in the last 30 minutes?"
sudo csa-traffic-diag --discover --minutes 30

# "Show me exactly what needs to go on the Do Not Decrypt list"
sudo csa-traffic-diag --discover --verify --minutes 30

# "Full workup on a specific domain"
sudo csa-traffic-diag --full netflix.com
```

## Modes

### Domain Diagnosis (`-d`)

Check specific domains for DNS redirection, TLS interception, and app compatibility:

```bash
# Single domain
csa-traffic-diag -d netflix.com

# Multiple domains
csa-traffic-diag -d netflix.com,nflxvideo.net,nflxext.com

# Include traceroute
csa-traffic-diag -d netflix.com -t
```

**What it checks:**
1. **DNS resolution** -- resolves the domain, flags Cisco/OpenDNS IP ranges, and identifies the DNS resolver. When tunneled via ZTA, labels DNS as "(via Cisco Secure Access)" and compares against Google DNS-over-HTTPS to detect stale cache mismatches
2. **TLS certificate chain** -- connects on port 443, retrieves the full cert chain, checks for Cisco SubCA certificates indicating decryption
3. **HTTPS connectivity test** -- when Cisco SubCA is detected, makes an HTTPS request to determine if the system trusts the re-signed certificate or if Cisco is actively blocking the domain. Shows which apps with bundled CA stores (pip, Docker, Node.js, Git, LM Studio, etc.) will reject the connection
4. **Route path** -- checks the OS routing table to detect tunnel interfaces and Cisco's local SWG loopback proxy (`127.x.x.x` on `lo0`). Only shown when TLS is inconclusive (e.g., ECH or connection-reset servers)
5. **Egress IP** -- queries external IP-echo services to determine if traffic exits through Cisco's cloud or your local ISP

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
  Research these domains before making changes? [y/N]:
```

Answering `y` resolves each domain and identifies its owner by checking the TLS certificate organization and reverse DNS hosting provider (Akamai, AWS, Cloudflare, Azure, Fastly, Google, and others). Results are grouped by owner so administrators can make informed decisions before adding domains to exclusion lists.

This step is skipped when output is piped (`| tee log.txt`), so scripted use is unaffected.

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
| macOS | VPN Agent, Web Security (SWG), ISE Posture processes; Network Extension (acsockext); ZTA connection state from flow log database |
| Windows | VPN Agent, Web Security (SWG), ISE Posture processes; VPN Agent service |

### Full Diagnosis (`--full`)

Combines domain diagnosis + log scan:

```bash
sudo csa-traffic-diag --full netflix.com
sudo csa-traffic-diag --full netflix.com,nflxvideo.net --minutes 30 -t
```

> **Note:** Client status is not included in `--full`. Use `--status` separately to check Cisco Secure Client components.

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

## Setup: Traffic Steering Bypass Verification

The tool displays a dual egress IP comparison at the top of every run so you can instantly confirm whether your traffic steering bypass policy is working.

### Required: Add `ipchicken.com` to Bypass

Add `ipchicken.com` to your **Traffic Steering Bypass** list in the Cisco Secure Access dashboard. Once added, requests to ipchicken.com will exit directly through your ISP rather than Cisco's tunnel.

### Optional: Add `dns.google` to Bypass

Add `dns.google` to your **Traffic Steering Bypass** list to enable the DNS-over-HTTPS comparison feature. This allows the tool to query Google DNS independently of Cisco's DNS path and detect stale cache mismatches. Without it, ZTA intercepts the DoH request and the comparison is unavailable.

### What You'll See

```
  Egress IP Check:
    Tunneled (Cisco):    146.112.x.x   <- tunneled via ZTA (Cisco Secure Access)
    Bypass (ISP):        98.xx.xx.xx   <- ipchicken.com -- ZTA profile bypass exception active
```

- **Tunneled** -- the egress IP for normal traffic routed through Cisco Secure Access
- **Bypass** -- the egress IP fetched from `ipchicken.com`; should show your ISP's public IP

If both IPs are the **same**, ipchicken.com is not yet on the bypass list (or your bypass policy hasn't taken effect).

### macOS: Cisco CA Certificate Trust Check

On macOS, the tool automatically checks whether the Cisco CA certificates are installed **and** trusted in your Keychain. This is a common gotcha -- the Cisco Secure Client installer places the certificates in the System Keychain, but they must be **manually set to "Always Trust"** before TLS interception will work correctly. Without this step, browsers and apps will reject Cisco's re-signed certificates with SSL errors.

```
  Keychain Trust Check:
    Cisco CA Cert:       TRUSTED      <- Cisco Secure Access Root CA
    Cisco CA Cert:       TRUSTED      <- Cisco Umbrella Root CA
```

If a certificate shows **NOT TRUSTED**, open **Keychain Access**, find the certificate, right-click **Get Info**, expand the **Trust** section, and set "When using this certificate" to **Always Trust**.

> This check is **read-only** -- the tool never modifies your Keychain or trust settings.

## Important Concepts

### Bypass vs. Do Not Decrypt

> **The Do Not Decrypt list is not the same as Traffic Steering Bypass.**
>
> - **Do Not Decrypt** -- traffic is still **proxied through Cisco Secure Access** (your traffic exits via Cisco's IP), but TLS inspection is skipped. Cisco retains visibility at the connection layer. **Try this first.**
> - **Traffic Steering Bypass** -- traffic is routed **directly through your ISP**, completely bypassing Cisco's cloud. No visibility, no policy enforcement. **Use only when DND doesn't resolve the issue.**

### Why Apps Break with TLS Decryption

When Cisco SWG decrypts HTTPS traffic, it re-signs the certificate with a Cisco CA. The system (macOS Keychain / Windows Certificate Store) may trust this CA, but many applications bundle their own CA store and will reject the re-signed certificate:

- **pip/Python** (uses `certifi`)
- **Docker**
- **Node.js**
- **Git**
- **LM Studio**
- **curl** (on some distributions)
- **Go applications**
- **Ruby/gems**

The tool detects this pattern and shows an **App Impact** note when Cisco SubCA is found, explaining which apps will be affected and recommending Do Not Decrypt as the first step.

## How It Works

### TLS Interception Detection

When Cisco Secure Access decrypts traffic (via its Secure Web Gateway), it terminates the original TLS connection at its cloud proxy and re-encrypts it with a Cisco-issued SubCA certificate. The tool detects this by:

1. Connecting to the target domain on port 443 (with ALPN `h2`/`http/1.1`)
2. Retrieving the full certificate chain (using Python 3.13's `get_verified_chain()`)
3. Checking issuer fields for markers: `cisco`, `umbrella`, `opendns`, `secure access`

If a Cisco SubCA is found, the tool runs an **HTTPS connectivity test** to determine whether the system trusts the re-signed certificate or whether Cisco is actively blocking the domain.

Servers that reject TLS probes (ECH/proprietary TLS like Apple Private Relay, or agent-only endpoints like NinjaRMM) show a clean "not inspectable" note, and the route path check serves as the fallback signal.

### DNS Resolver Detection

The tool identifies which DNS resolver answered:
- **When ZTA is tunneling**: labels DNS as "(via Cisco Secure Access)" since ZTA transparently intercepts DNS at the network extension level
- **When not tunneled**: shows the configured system resolver with classification (Umbrella, Google, Cloudflare, local/private)

When tunneled, the tool queries **Google DNS-over-HTTPS** (`dns.google`) as an independent reference. If the results differ, a mismatch warning helps identify stale DNS cache issues in Cisco's DNS path.

### Loopback Proxy Detection

Cisco ZTA's SWG module can intercept DNS and return loopback IPs (`127.x.x.x`) to funnel traffic through a local proxy on `lo0`. The tool detects this pattern and reports "PROXIED" instead of the misleading "BYPASSED" that a naive route check would show.

### Log Scanning

The tool reads Cisco Secure Client log files and databases, matching lines against keywords (`block`, `deny`, `error`, `timeout`, `certificate`, `decrypt`, `bypass`), extracting domain names and timestamps, and grouping results by domain with frequency counts.

## Common Scenarios

### "An app can't connect / download / authenticate"
```bash
sudo csa-traffic-diag -d huggingface.co
```
If you see `Cisco SubCA: FOUND` with `HTTPS Test: 200 OK` and an `App Impact` note, the app is rejecting Cisco's re-signed certificate. Add the domain to **Do Not Decrypt** first; escalate to **Traffic Steering Bypass** if issues persist.

### "Netflix/streaming is buffering or won't load"
```bash
csa-traffic-diag -d netflix.com,nflxvideo.net,nflxext.com
```
If you see `PROXIED / DECRYPTED`, the streaming CDN domains need to be on the Traffic Steering Bypass list (DND alone won't help for streaming -- these services need direct ISP routing for household verification).

### "A SaaS app is throwing certificate errors"
```bash
sudo csa-traffic-diag --discover --verify --minutes 60
```
Look for domains in the **TLS ERRORS** section. Add them to Do Not Decrypt first; escalate to Traffic Steering Bypass if issues persist.

### "Webex/Teams/Zoom has intermittent issues"
```bash
sudo csa-traffic-diag --discover --verify --minutes 60
```
Check for TLS errors on the app's domains. If the app mostly works, the errors may be harmless failovers. If calls are dropping or meetings fail to connect, add the flagged domains to Do Not Decrypt.

### "DNS seems wrong / domain resolves to different IPs"
```bash
sudo csa-traffic-diag -d example.com
```
Look for `DNS Mismatch` between system DNS (via Cisco) and Google DoH. If there's a mismatch, Cisco's DNS path may have stale cached records.

### "I need to audit what Cisco is decrypting"
```bash
sudo csa-traffic-diag --discover --verify -v --json > audit.json
```
The JSON output contains the full TLS chain for every probed domain.

### "Is the Cisco client even running?"
```bash
csa-traffic-diag --status
```

## Interpreting Results

### Not every TLS error means something is broken

The tool reports what it finds in the logs -- TLS handshake failures, connection timeouts, certificate errors. But many apps (especially ones with heavy redundancy like Webex, Teams, and Zoom) gracefully handle these failures by falling over to alternate endpoints.

**When to act vs. when to ignore:**
- **App is broken** (calls dropping, pages failing, cert errors in browser) -- follow the recommendations
- **App works fine** despite TLS errors in logs -- the errors are harmless failovers. Adding the domains to Do Not Decrypt won't hurt (and cleans up future scans), but it's not urgent
- **STUN/TURN and SRV entries** -- the tool filters these automatically. They're ephemeral media-path infrastructure and not actionable

The tool errs on the side of showing you everything. It can't know whether an app recovered from a TLS failure -- only you can tell by testing the app.

## Security & Privacy

### GitHub Security Scanning

This repository has the following GitHub security features enabled:

- **[CodeQL Analysis](https://github.com/teak421/CSA-Traffic-Diag-Tool/actions/workflows/codeql.yml)** -- automated static analysis runs on every push, pull request, and weekly
- **Secret Scanning** -- monitors the repository for accidentally committed API keys, tokens, and passwords
- **Push Protection** -- blocks pushes that contain detected secrets before they reach the repository
- **Dependabot** -- monitors dependencies for known vulnerabilities (this project has zero external dependencies)

### Code Safety

- **No external dependencies** -- nothing to supply-chain attack
- **Read-only** -- the tool never modifies system configuration, logs, or Cisco client settings
- **TLS 1.2 minimum** -- all SSL contexts enforce TLS 1.2+ (no deprecated protocol negotiation)
- **Subprocess safety** -- all subprocess calls use list-form arguments (no `shell=True`); no shell injection vectors
- **SQLite access** -- flow log databases are opened in read-only mode (`?mode=ro`) with validated table/column names
- **Egress IP check** -- queries public IP-echo services (ifconfig.me, api.ipify.org, icanhazip.com, checkip.amazonaws.com) to determine your outbound IP. These are HTTPS requests
- **DNS-over-HTTPS** -- when ZTA is tunneling, queries `dns.google` and/or `cloudflare-dns.com` for DNS comparison. Only the domain name being diagnosed is sent
- **HTTPS connectivity test** -- when Cisco SubCA is detected, makes a single HEAD request to the diagnosed domain to test system trust. No data is sent beyond the request itself
- **Log content** -- output may include hostnames, IP addresses, and log snippets from your system. Review before sharing diagnostics externally

## License

MIT
