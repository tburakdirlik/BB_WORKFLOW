# Changelog

All notable changes to `recon.py`. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are listed newest-first.

---

## v1.3 — Planned / candidate features
*(not yet implemented — ideas for the next iteration)*

### AI agent layer (optional, bring-your-own API key)
- An opt-in `--ai` stage that layers an LLM **on top of** the deterministic
  pipeline (never replacing it):
  - **Triage & prioritization** — rank discovered subdomains and live endpoints by
    "interestingness" (admin/staging/dev/api panels, legacy tech, exposed
    services) so the most promising targets surface first.
  - **Reporting** — turn the raw output into an executive summary plus
    attack-surface notes and suggested next steps.
  - **Test suggestions** — for specific hosts/parameters, propose targeted checks
    (parameter-fuzzing ideas, SSRF/SSTI/auth vectors) as *suggestions*, not
    autonomous exploitation.
  - **Agent hand-off** — shape the `--json` output so it can feed an existing
    agent framework (e.g. CAI / PentAGI / ptai) rather than reinventing one.
- Guardrails: keep it **human-in-the-loop**, keep **detection and validation
  deterministic** (LLMs are unreliable validators and produce false positives),
  stay aware of token cost, and respect scope / rate-limit discipline.

### Recall (find more)
- **Chaos** (ProjectDiscovery dataset), native **Wayback / CommonCrawl / OTX**,
  and **certspotter** queries — more coverage with fewer tool dependencies.
- **TLS SAN scraping** of live IPs — pull hostnames from certificates (catches
  names that never appear in CT logs).
- **ASN / CIDR expansion** — discover the org's IP ranges and reverse-DNS them to
  find hosts that name-based enumeration misses.

### Accuracy & robustness
- **Per-source coverage summary** — how many subdomains each source contributed
  (and which silently returned nothing), for completeness confidence.
- **Resume / checkpointing** so a long run survives a crash or Ctrl+C.
- **Per-level wildcard detection** on the native-resolver path (currently
  apex-level only).

### Configuration & UX
- First-class **API-key management** (Shodan / VirusTotal / SecurityTrails /
  Chaos), including a native `--vt-key` source independent of subfinder.
- **nuclei integration** — takeover and exposure templates against the live set.
- **Rate-limit / politeness** controls and **target-level parallelism**.

---

## v1.2 — Takeover detection & continuous monitoring
*(1,406 lines)*

The focus of this release shifts from *finding* assets to *acting on* them and
tracking them over time.

### Added
- **Subdomain takeover detection** (on by default, `--no-takeover`). Checks the
  CNAME of every live host (from httpx) and of dead hosts with a resolvable
  dangling CNAME against a built-in fingerprint table (GitHub Pages, S3, Heroku,
  Shopify, Fastly, Zendesk, Netlify, and ~12 more). A body-signature match is
  reported as `confirmed`; a CNAME-only match as `potential` (verify manually).
  Dead-host CNAMEs are resolved via `dnspython` or `dig` when available.
  → new `_takeover.txt` companion file.
- **Monitoring / diff mode** (`--monitor`, `--state-dir`). Saves a JSON baseline
  per target and, on the next run, reports **new live**, **no-longer-live**, and
  **new dead** subdomains. Adds a "CHANGES SINCE LAST RUN" section to the report.
- **Webhook notifications** (`--notify-webhook`). Posts a summary of newly
  discovered live assets to a Slack/Discord-compatible webhook (used with
  `--monitor`). Ideal for a recurring cron job.
- **Structured JSON output** (`--json`) — full results written to
  `<output>.json` for piping into other tooling.

### Internal
- New helpers: `takeover_scan`, `resolve_cname`, `http_get`,
  `TAKEOVER_FINGERPRINTS`, `result_to_dict`, `write_json`, `load_state`,
  `save_state`, `diff_results`, `notify_webhook`, `build_diff_message`.

---

## v1.1 — Breadth, accuracy & depth
*(760 → 1,109 lines)*

A large release that turns a basic recon chain into a serious enumeration
pipeline: more sources, fewer false positives, and deeper discovery.

### Added
- **Multi-source passive enumeration.** On top of subfinder + crt.sh, it now
  pulls from `gau`/`waybackurls` (URL archives), `assetfinder`,
  `github-subdomains` (`--github-token`), and `amass` passive (`--amass`).
- **Source tracking.** Every subdomain is tagged with which source(s) found it
  and shown in the report (`found via: subfinder, wayback`).
- **Virtual-host enumeration** (`--vhost`). Uses the dead (non-resolving)
  subdomains as a `Host`-header wordlist and fuzzes them against live IPs with
  `ffuf` to surface vhosts with no public DNS record.
- **Recursive brute-force** (`--recursive`, `--recursion-depth`,
  `--recursion-wordlist`) and **iterated permutations** (`--perm-rounds`, stops
  early when a round finds nothing new).
- **Companion output files** — `<output>_live.txt`, `_dead.txt`, `_vhosts.txt`
  alongside the main report; report restructured into separate **LIVE** and
  **DEAD** subdomain sections.

### Changed / Improved
- **Resolver re-validation** (`--resolvers-trusted`). Mass-resolves with a bulk
  resolver list, then re-validates hits against a small trusted list to kill
  false positives. `setup_resolvers` replaces the old single-list `ensure_resolvers`.
- **Input sanitization** (`clean_domain`) — strips scheme, path, port, and `*.`
  so URLs/wildcards no longer break `subfinder -d`.
- **Wildcard handling** (`detect_wildcard`) — filters `*.domain` catch-all hits
  out of permutation results on the native-resolver path.
- **Hardened crt.sh** — added retry/backoff so a transient 502 no longer drops
  the source silently.
- **`--verbose`** now surfaces child-process stderr (was previously unused) for
  debugging missing/failing tools.

### Internal
- New helpers: `clean_domain`, `hosts_from_urls`, `detect_wildcard`,
  `vhost_enum`, `parse_ffuf_json`, `setup_resolvers`, `find_recursion_wordlist`,
  `write_companions`, `_found_set`, `write_temp`.

---

## v1.0 — Initial release
*(760 lines)*

First working version: an end-to-end recon orchestrator in a single file.

### Features
- Pipeline: WHOIS root-domain discovery → passive enumeration (subfinder +
  native crt.sh) → DNS resolution (puredns, with a native threaded fallback) →
  active discovery (puredns brute-force + alterx permutations) → HTTP probing
  (httpx) → optional port scan (nmap).
- Reverse-WHOIS root-domain expansion via `--whoxy-key` / `--expand-roots`.
- Single combined, human-readable report with resolved/unresolved subdomains,
  live web services, and open ports.
- Graceful degradation: any missing external tool simply skips its phase.
- CLI: `-t`/`-T` targets, `-o` output, `-w` wordlist, `-r` resolvers,
  `--passive-only`, `--no-bruteforce`/`--no-permutations`/`--no-httpx`,
  `--ports`/`--full-ports`, `--threads`, `--no-color`, `-v`.
