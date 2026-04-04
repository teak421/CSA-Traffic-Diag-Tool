# Changelog

All notable changes to this project will be documented in this file.

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
