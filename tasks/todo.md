# Interactive Domain Research After Recommendations

## Context
When `--discover --verify` recommends domains for Do Not Decrypt / Traffic Steering Bypass, users may add them without understanding what the domains are. We want an interactive prompt offering to research each domain — showing who owns it, where it's hosted, and what service it belongs to — so users make informed decisions.

## File
All changes in `csa_traffic_diag.py`.

---

## Tasks

- [ ] **Step 1: Add constants** (~line 112, after `_CN_RE`)
  - `_ORG_RE` — regex to extract Organization from cert subject strings
  - `KNOWN_PROVIDERS` — map reverse DNS substrings to provider names (~line 75, after `CISCO_CERT_MARKERS`)

- [ ] **Step 2: Capture SANs in `inspect_tls()`** (~line 411)
  - Extract SANs from `leaf.get("subjectAltName", ())`
  - Add `"sans"` and `"leaf_subject"` to the return details dict

- [ ] **Step 3: Add helper `_get_cert_org(tls_result)`** (after `_parse_cert_tuple_field`, ~line 362)
  - Extracts organization name from a TLS inspection result's leaf_subject

- [ ] **Step 4: Add helper `_resolve_domain_info(domain)`** (~same area)
  - Resolves domain IPs via `socket.getaddrinfo()`
  - Reverse DNS each IP (limit to 3) via `socket.gethostbyaddr()`
  - Matches reverse DNS against `KNOWN_PROVIDERS`
  - Returns `{"ips": [...], "rdns": {...}, "provider": "..."}`

- [ ] **Step 5: Add `_research_domains()` function** (after `_print_recommendations`)
  - Groups all recommended domains by identified owner
  - For each domain: check cert org → reverse DNS provider → fallback to "Unidentified"
  - Skip cert org if it matches Cisco markers (decrypted domains)
  - Prints consolidated report grouped by owner
  - Shows: source of identification, SANs, hosting provider, IPs
  - Flags unidentified domains with warning

- [ ] **Step 6: Modify `_print_recommendations()` to return data** (line 2503)
  - Return `(actionable_domains, related_decrypted)` so the caller can pass to research

- [ ] **Step 7: Add interactive prompt in `print_discover_results()`** (line 2372)
  - After `_print_recommendations()`, if actionable domains exist and `sys.stdin.isatty()`
  - Prompt: "Research these domains before making changes? [y/N]:"
  - On "y": call `_research_domains(actionable, related, discovery, color)`
  - Handle `EOFError` / `KeyboardInterrupt` gracefully

- [ ] **Step 8: Lint and verify**
  - Run `ruff check csa_traffic_diag.py` — no lint errors
  - Run `python3 csa_traffic_diag.py --discover --verify` to test end-to-end

---

## Important considerations

- **TLS error domains have no cert data** — research relies entirely on DNS/reverse DNS
- **Decrypted domains have Cisco cert** — skip cert org, fall through to DNS/reverse DNS
- **Latency** — limit reverse DNS to 3 IPs per domain, show progress indicator
- **No whois for v1** — slow, platform-dependent, unreliable parsing. Add later.
- **Non-interactive safety** — `sys.stdin.isatty()` prevents hanging when piped

## Output format
```
[Domain Research]

  Microsoft (3 domains — identified via Certificate)
    Cert Org:  Microsoft Corporation
    Hosting:   Akamai (e278.dscb.akamaiedge.net)
    SANs:      *.office.com, *.microsoft.com, +12 more
    ─────────────────────────────
    login.microsoftonline.com    146.112.62.10
    outlook.office365.com        52.98.208.2
    graph.microsoft.com          13.107.42.14

  Unidentified (1 domain)
    Hosting:   AWS (ec2-54-200-1-1.compute-1.amazonaws.com)
    ⚠️  Could not identify owner — research manually
    ─────────────────────────────
    api.unknown-thing.io         54.200.1.1
```
