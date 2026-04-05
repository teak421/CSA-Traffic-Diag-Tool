# Changelog

All notable changes to this project will be documented in this file.

## [1.3.1] - 2026-04-04

### Added
- **DNS resolver visibility** — domain diagnosis now shows which DNS resolver answered: "Cisco Secure Access" when ZTA is tunneling, or the configured system resolver (with classification: Umbrella, Google, Cloudflare, local/private) when not tunneled.
- **Google DoH comparison** — when tunneled, the tool queries Google DNS-over-HTTPS (`dns.google`) as an independent reference and displays both results side by side. Mismatches are flagged with a warning to help catch stale DNS cache issues in Cisco's DNS path. Requires `dns.google` on the Traffic Steering Bypass list.
- **TLS ALPN negotiation** — TLS probes now send `h2` and `http/1.1` ALPN protocols in the client hello, matching real browser behavior for better compatibility with modern servers.
- **Graceful handling of non-standard TLS** �� servers that reject TLS probes with `ILLEGAL_PARAMETER` (ECH/proprietary TLS, e.g. Apple Private Relay) or `Connection reset by peer` (agent-only endpoints) now show a clean "not inspectable" note instead of a misleading "UNABLE TO DETERMINE" error. The route check (KDF verdict) serves as the authoritative signal.

### Changed
- **Egress tunneled note** — replaced the bare "Netflix/streaming household detection WILL fail" text with a labeled, actionable note: "household IP verification (e.g. Netflix) may fail / Add affected domains to ZTA bypass profile if needed".
- DNS display label changed from `DNS Resolution:` to `DNS (system):` when tunneled, paired with `DNS (Google):` reference line.

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
