# Changelog

All notable changes to this project will be documented in this file.

## [1.6.0] - 2026-04-05

### Added
- **Unaccounted DNS discovery** — scans Cisco's network extension `host_firewall` logs for every DNS query the machine made, diffs against domains already captured by the diagnostic pipeline, and surfaces the difference as "UNACCOUNTED DNS." These are domains flowing through Cisco that aren't appearing in diagnostic logs — typically silently decrypted domains that break apps with bundled CA stores (pip, Docker, LM Studio, Git, etc.). Includes requesting process name attribution (e.g., `(LM Studio)`, `(Safari)`). Currently macOS (`log show`); Windows support (`Get-WinEvent`) planned.
- **Base domain grouping** in UNACCOUNTED DNS — groups subdomains under `*.base.com (N domains)` to reduce noise, with `-v` to expand individual domains.
- **Noise filtering** — excludes system infrastructure (Apple, Microsoft, Cisco, YouTube/Google Video, OCSP/CRL), the tool's own domains (ifconfig.me, ipchicken.com, dns.google), and SRV/STUN service discovery records from unaccounted results.
- **Troubleshooting walkthrough** in README — step-by-step diagnostic flow from "app is broken" through UNACCOUNTED DNS discovery, TLS confirmation, DND fix, and verification. Uses a real-world LM Studio example.
- **"When will you see a BLOCKED entry?"** section in README — explains Cisco's silent decryption blind spot and why UNACCOUNTED DNS exists.

### Changed
- README restructured with DND-first guidance throughout: callout box emphasizing "Always start with Do Not Decrypt," note that DND takes effect immediately after sync while TSB requires several minutes.

## [1.5.1] - 2026-04-05

### Fixed
- **SSL error detection in HTTPS test** — `urlopen` wraps `SSLCertVerificationError` inside `URLError`, which caused the SSL error to display as a generic "Connection failed" instead of the specific "SSL error — system does NOT trust Cisco CA" message with Keychain fix instructions.
- **App impact note on SSL errors** — the app impact note and DND-first guidance now also appear when the system itself doesn't trust the Cisco CA (not just when the system trusts it but apps don't).
- **Consistent DND-first guidance** — all verdict text standardized to "Try Do Not Decrypt first, escalate to Traffic Steering Bypass if needed" instead of the previous "Add to Traffic Steering Bypass" wording.

## [1.5.0] - 2026-04-05

### Added
- **HTTPS connectivity test** — when Cisco SubCA is detected (traffic decrypted), the tool makes an HTTPS HEAD request to determine whether the system trusts the re-signed certificate, or whether Cisco is actively blocking the domain by policy. Distinguishes "decrypted but connectable" from "blocked by Cisco policy" from "SSL verification failed."
- **App impact note** — when the system trusts the Cisco CA but apps may not, displays which common apps bundle their own CA store (pip/Python, Docker, Node.js, Git, LM Studio, curl, Go, Ruby) and will reject the re-signed certificate. Recommends trying Do Not Decrypt first, then escalating to Traffic Steering Bypass.
- **Cisco block page detection** — identifies Cisco Umbrella/SWG block pages by checking HTTP response body for Cisco markers (403 + "cisco umbrella", "this site is blocked", etc.).

## [1.4.1] - 2026-04-04

### Fixed
- **CodeQL security alerts** — all SSL contexts now enforce TLS 1.2 minimum (`minimum_version = TLSv1_2`), preventing negotiation of deprecated TLS 1.0/1.1. Resolves GitHub CodeQL alerts #1 and #2 (`py/insecure-protocol`).

## [1.4.0] - 2026-04-04

### Added
- **DNS resolver visibility** — domain diagnosis now shows which DNS resolver answered: "Cisco Secure Access" when ZTA is tunneling, or the configured system resolver (with classification: Umbrella, Google, Cloudflare, local/private) when not tunneled.
- **Google DoH comparison** — when tunneled, the tool queries Google DNS-over-HTTPS (`dns.google`) as an independent reference and displays both results side by side. Mismatches are flagged with a warning to help catch stale DNS cache issues in Cisco's DNS path. Requires `dns.google` on the Traffic Steering Bypass list.
- **TLS ALPN negotiation** — TLS probes now send `h2` and `http/1.1` ALPN protocols in the client hello, matching real browser behavior for better compatibility with modern servers.
- **Graceful handling of non-standard TLS** — servers that reject TLS probes with `ILLEGAL_PARAMETER` (ECH/proprietary TLS, e.g. Apple Private Relay) or `Connection reset by peer` (agent-only endpoints) now show a clean "not inspectable" note instead of a misleading "UNABLE TO DETERMINE" error. The route check (KDF verdict) serves as the authoritative signal.

- **Loopback proxy detection** — route path check now recognizes `127.x.x.x → lo0` as Cisco's local SWG proxy, reporting "PROXIED" instead of the misleading "BYPASSED" verdict.
- **ZTA state from flowlog.db** — when no ZTA text log exists, the status check falls back to querying the SQLite flow log database for recent activity to determine whether ZTA is actively connected.
- **Friendly process names** in `--status` output: "VPN Agent", "Web Security (SWG)", "ISE Posture", "Network Extension" instead of internal process names.

### Changed
- **Egress tunneled note** — replaced the bare "Netflix/streaming household detection WILL fail" text with a labeled, actionable note: "household IP verification (e.g. Netflix) may fail / Add affected domains to ZTA bypass profile if needed".
- DNS display label changed from `DNS Resolution:` to `DNS (system):` when tunneled, paired with `DNS (Google):` reference line.
- **Route path display** — only shown when TLS is inconclusive (ECH, connection reset, error). When TLS gives a clear proxied/not-proxied verdict, route path is suppressed to reduce noise.
- **`--full` mode** — no longer includes client status output (use `--status` separately).
- **Verdict spacing** — blank line added before every verdict line for cleaner readability.
- **Exclusion list disclaimer** — "Do not blindly add domains to exclusion lists" warning now appears on all output modes except `--status`.

## [1.3.0] - 2026-04-04

### Added
- **Interactive domain research** (`--discover --verify`): after printing recommendations, the tool prompts "Research these domains before making changes? [y/N]". On confirmation, it resolves each domain's IPs, performs reverse DNS lookups, and identifies the hosting provider (Akamai, AWS, Cloudflare, Azure, Fastly, Google, etc.). Results are grouped by identified owner — cert organization, hosting provider, or "Unidentified" — so administrators can make informed decisions before adding domains to Do Not Decrypt or Traffic Steering Bypass lists.
- **`KNOWN_PROVIDERS`** — reverse-DNS substring mapping covering major cloud and CDN providers used for hosting identification during domain research.
- **SAN capture** in `inspect_tls()`: Subject Alternative Names from the leaf certificate are now stored in the TLS result and displayed during domain research, showing what other domains share the same certificate.
- **Disclaimer warning** after recommendations: "Do not blindly add domains to the Do Not Decrypt or Traffic Steering lists. Research each domain before adding to any exclusion list."
- **`_get_cert_org()`** helper: extracts the organization name from a TLS result's leaf certificate subject, skipping Cisco-issued certs (decrypted traffic).
- **`_resolve_domain_info()`** helper: resolves domain IPs via `socket.getaddrinfo()` and identifies hosting provider by matching reverse DNS hostnames against `KNOWN_PROVIDERS` (limited to 3 IPs per domain to avoid excessive latency).
- **`KNOWN_DOMAIN_OWNERS`** — domain suffix-to-owner mapping for well-known services (Apple, Microsoft, Google, Zoom, Okta, Slack, GitHub, etc.) whose IP ranges lack useful reverse DNS. Used as a fallback when cert org and rDNS both fail to identify the owner.
- **Context-aware egress helper text** — detects ZTA enrollment via local enrollment files and adjusts all egress IP comparison labels to point users to the correct bypass configuration: ZTA profile exceptions (Secure Internet Access) for ZTA-enrolled endpoints, or Internet Security > Traffic Steering for non-ZTA endpoints. Prevents users from adding domains to the wrong bypass list.
- **File extension filtering** in log scanning — prevents file references like `libMobileGestalt.dylib` (macOS) and `IPCClient.cpp` (Windows) from being treated as domain names. Only filters extensions that are not real gTLDs/ccTLDs to avoid false positives on domains like `play.app`.

### Changed
- `_print_recommendations()` now returns `(actionable_domains, related_decrypted)` so the caller can pass them to the research function.
- Prompt and research output are suppressed when output is piped (non-TTY), preventing hangs in scripted use.

## [1.2.0] - 2026-04-04

### Added
- **Dual egress IP comparison** displayed at the top of every network diagnostic run. Fetches egress IPs from two sources (tunneled via Cisco and bypassed via ipchicken.com) so users can instantly confirm whether traffic steering bypass is working.
- **macOS Keychain trust check** verifies that Cisco CA certificates are installed and set to "Always Trust" in the macOS Keychain. Read-only -- alerts users if trust is missing, which is a common cause of SSL errors. Filters out device identity certs (urn: prefix) to avoid false positives.
- **`_unverified_ssl_ctx()`** for egress IP checks. Python's bundled CA store does not include the Cisco CA cert (installed in the macOS Keychain / Windows Certificate Store), so SSL verification would silently fail on all HTTPS IP-echo services when the Cisco client is active.
- **sudo-aware user context** for macOS Keychain checks. Resolves the real user's home directory and trust settings instead of `/var/root` when run with `sudo`.
- README section: **Verifying Traffic Steering Bypass** with ipchicken.com setup instructions.
- README section: **macOS: Cisco CA Certificate Trust Check** documenting the Keychain check and how to fix trust issues.
- README callout: **Bypass is not equal to Do Not Decrypt** -- explains that Do Not Decrypt domains are still proxied through Cisco (just not TLS-inspected), while only Traffic Steering Bypass routes directly via the ISP.

### Changed
- Egress IP comparison and Keychain trust check only run for network diagnostic modes (`-d`, `--full`, `--discover`), avoiding 5-10 seconds of unnecessary network overhead for local-only modes (`--status`, `--scan-logs`).
- Bypass IP detection now flags as tunneled when the IP falls within any known Cisco IP range, not just when identical to the tunneled IP.

## [1.0.0] - 2026-04-04

### Added
- Initial release of the CSA Traffic Diagnostic Tool.
- **Domain diagnosis** (`-d`): DNS resolution, TLS certificate chain inspection, egress IP check, route path analysis.
- **Traffic discovery** (`--discover`): Scans Cisco Secure Client logs, extracts domains, categorizes by keyword (bypass/block/error/decrypt).
- **TLS verification** (`--verify`): Connects to each discovered domain and inspects the certificate chain to definitively classify traffic as decrypted, not decrypted, or erroring.
- **Log scanning** (`--scan-logs`): Raw log scanning with domain grouping and frequency counts across ZTA databases, text logs, Umbrella logs, and system logs.
- **Client status** (`--status`): Checks Cisco Secure Client processes, system extensions, and ZTA connection state.
- **Full diagnosis** (`--full`): Combines domain diagnosis, log scan, and client status.
- JSON output (`--json`) and colored terminal output with auto-detection.
- macOS and Windows support with platform-specific log paths and process checks.
- Exit codes: 0 (pass), 1 (errors), 2 (warnings).
