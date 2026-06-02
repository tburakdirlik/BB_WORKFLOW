# recon.py

A single-file **subdomain enumeration & attack-surface mapping** pipeline for bug bounty and authorized penetration testing.

Point it at a domain (or a list of domains) and it produces the most complete, accurate set of **live subdomains** it can — plus the dead ones (so you can reuse them for virtual-host enumeration), the live web services, subdomain-takeover candidates, and optionally open ports — all combined into one human-readable report with machine-readable companion files.

> ⚠️ Only test assets you are explicitly authorized to assess (in-scope bug bounty programs, your own infrastructure, or systems you have written permission to test).

---

## What it does

Given a target domain, `recon.py` runs an end-to-end pipeline:

1. **Root domain discovery** — finds related root domains via WHOIS.
2. **Passive enumeration** — pulls subdomains from many public sources at once.
3. **DNS resolution** — resolves candidates and *re-validates* with trusted resolvers to kill false positives.
4. **Active discovery** — expands the set with brute-force, permutations, and optional recursion.
5. **HTTP probing** — finds what is actually live over HTTP and fingerprints it.
6. **Subdomain takeover detection** — flags hosts pointing at unclaimed third-party services.
7. **Virtual-host enumeration** *(optional)* — fuzzes dead names as `Host` headers against live IPs.
8. **Port scan** *(optional)* — nmap on the live IPs.
9. **Monitoring mode** *(optional)* — diffs against the previous run and surfaces only what is **new**.

Every stage **degrades gracefully**: if an external tool isn't installed, that phase is skipped or falls back to a built-in implementation rather than crashing. With *zero* external tools, the native crt.sh source + threaded resolver still produce useful output.

---

## Requirements

- **Python 3.7+** — standard library only, no `pip install` needed.
- External tools are **optional**; each one unlocks or improves a phase.

### Install (macOS)

```bash
brew install nmap subfinder httpx massdns ffuf amass
# whois already ships with macOS

go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/gwen001/github-subdomains@latest

# make sure Go binaries are on PATH (zsh)
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc && source ~/.zshrc

# wordlists (auto-detected at this path)
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/SecLists
```

### Tool → phase map

| Tool | Used for | If missing |
|------|----------|------------|
| `subfinder` | passive enumeration | crt.sh still runs |
| `puredns` (+ `massdns`) | resolution & brute-force | native threaded resolver; brute-force skipped |
| `alterx` | permutations | skipped |
| `gau` / `waybackurls` | passive (URL archives) | skipped |
| `assetfinder` | passive | skipped |
| `github-subdomains` | passive (needs token) | skipped |
| `amass` | passive (`--amass`) | skipped |
| `httpx` | HTTP probing | skipped |
| `ffuf` | virtual-host enum (`--vhost`) | skipped |
| `nmap` | port scan (`--ports`) | skipped |
| `whois` | root domain discovery | skipped |
| `dig` or `dnspython` | takeover (dead-host CNAMEs) | takeover limited to live hosts |

> Note: API keys for sources like SecurityTrails / Chaos / VirusTotal are configured inside **subfinder's** own config (`~/.config/subfinder/provider-config.yaml`); `recon.py` picks up the extra coverage automatically. (Dedicated key handling in `recon.py` is on the roadmap.)

---

## Usage

```bash
# single target
python3 recon.py -t example.com -o output.txt

# list of targets
python3 recon.py -T targets.txt -o output.txt

# thorough: big wordlist, validated resolvers, recursion, vhost, JSON
python3 recon.py -t example.com -w ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
    -r resolvers.txt --recursive --vhost --json -o out.txt

# continuous monitoring with Slack/Discord alerts on new assets
python3 recon.py -t example.com --monitor \
    --notify-webhook https://hooks.slack.com/services/XXX -o out.txt
```

`-t` takes a host (`example.com`) or a full URL — scheme, path, port, and `*.` are stripped automatically.

---

## How it works (step by step)

### 1. Root domain discovery
Runs `whois` on the target and extracts the registrant organization. With `--whoxy-key`, it performs a reverse-WHOIS lookup to find other root domains owned by the same org. By default these are only **reported** (so you can verify scope first); `--expand-roots` feeds them back into the pipeline.

### 2. Passive enumeration
Queries every available source in parallel and merges the results:
- `subfinder` (certificate transparency, DNS aggregators, and any keyed sources you've configured),
- **crt.sh** natively (with retry/backoff so a 502 doesn't silently drop the source),
- `gau` / `waybackurls` — extracts hostnames seen in Wayback/CommonCrawl URLs,
- `assetfinder`,
- `github-subdomains` (with `--github-token` or `$GITHUB_TOKEN`),
- `amass` passive (with `--amass`).

Every discovered name is tagged with **which source(s)** found it, so the report shows provenance (`found via: subfinder, wayback`).

### 3. DNS resolution
Resolves the passive set with `puredns`. Critically, it uses a **two-tier resolver setup**: a large bulk list (`-r`) for mass resolution, then re-validates every hit against a small list of **trusted resolvers** (`--resolvers-trusted`, built-in by default). This is what keeps brute-force output free of false positives caused by broken or poisoned resolvers. If `puredns` isn't available, it falls back to a native threaded resolver that filters apex-level wildcard catch-alls.

### 4. Active discovery
Three techniques, all feeding the same de-duplicated set:
- **Brute-force** (`puredns bruteforce`) against your wordlist (auto-detected from SecLists, or `-w`).
- **Permutations** (`alterx`), seeded from the confirmed-live hosts and **iterated** until a round finds nothing new (`--perm-rounds`, default 2).
- **Recursive brute-force** (`--recursive`) into discovered subdomains, depth-limited (`--recursion-depth`) with a smaller wordlist — off by default because it's expensive.

Wildcard hits are filtered out of permutation results so a `*.domain` catch-all doesn't make everything look live.

### 5. HTTP probing
Feeds the resolved set to `httpx` and records status code, title, detected technologies, IP, and CNAME for each live web service.

### 6. Subdomain takeover detection *(on by default)*
For every host with a CNAME (from httpx) and for dead hosts whose CNAME can be resolved, it checks the CNAME against a built-in fingerprint table (GitHub Pages, S3, Heroku, Shopify, Fastly, and more). A match plus the service's "unclaimed" body signature is reported as **`confirmed`**; a CNAME-only match is reported as **`potential`**. All findings still require **manual verification** before you report them. Disable with `--no-takeover`.

### 7. Virtual-host enumeration *(optional, `--vhost`)*
Uses the **dead subdomain list** as a `Host`-header wordlist and fuzzes it against each live IP with `ffuf` (auto-calibration filters the default response). This finds internal/staging virtual hosts that have no public DNS record. Needs `ffuf`.

### 8. Port scan *(optional, `--ports`)*
Runs `nmap -sV` against the unique live IPs (top 1000 ports, or `--full-ports` for all 65535).

### 9. Monitoring / diff *(optional, `--monitor`)*
Saves a JSON baseline per target under `--state-dir` (default `~/.recon/state`). On the next run it diffs against the baseline and reports **new live**, **no longer live**, and **new dead** subdomains. With `--notify-webhook`, it posts a summary of newly-discovered live assets to a Slack/Discord-compatible webhook. Ideal for a cron job on programs you watch continuously.

---

## Output files

For `-o output.txt` the tool writes:

| File | Contents |
|------|----------|
| `output.txt` | full human-readable report (everything combined) |
| `output_live.txt` | live (resolving) subdomains, one per line |
| `output_dead.txt` | dead (non-resolving) subdomains — your vhost input |
| `output_vhosts.txt` | discovered virtual hosts (only with `--vhost`) |
| `output_takeover.txt` | takeover candidates (only if any found) |
| `output.json` | full structured results (only with `--json`) |

The report itself lists every subdomain once with its status and the source(s) that found it, plus sections for live web services, takeover candidates, virtual hosts, open ports, and — in monitor mode — changes since the last run.

---

## Options

| Flag | Description |
|------|-------------|
| `-t, --target` | single target domain |
| `-T, --targets` | file of target domains (one per line) |
| `-o, --output` | report file (companions written alongside) |
| `-w, --wordlist` | brute-force wordlist |
| `-r, --resolvers` | bulk resolvers file for mass resolution |
| `--resolvers-trusted` | trusted resolvers for re-validation (default: built-in) |
| `--passive-only` | passive enumeration + resolution only |
| `--no-bruteforce` / `--no-permutations` / `--no-httpx` / `--no-takeover` | skip a phase |
| `--perm-rounds N` | max permutation rounds (default 2) |
| `--recursive` / `--recursion-depth N` / `--recursion-wordlist` | recursive brute-force |
| `--vhost` | virtual-host enumeration (needs ffuf) |
| `--ports` / `--full-ports` | nmap port scan |
| `--amass` | add amass as a passive source |
| `--github-token` | token for github-subdomains (or `$GITHUB_TOKEN`) |
| `--expand-roots` | run the full pipeline on WHOIS-discovered roots |
| `--whoxy-key` | whoxy.com key for reverse WHOIS |
| `--monitor` / `--state-dir` / `--notify-webhook` | monitoring & alerts |
| `--json` | also write `<output>.json` |
| `--threads N` | concurrency for the native resolver fallback |
| `-v, --verbose` | show child-process stderr (debug missing/failing tools) |

---

## Notes & caveats

- **Resolver quality matters.** Without a large validated bulk list via `-r` (e.g. [trickest/resolvers](https://github.com/trickest/resolvers)), the tool reuses its small built-in list for everything; resolution still works but heavy brute-force is less reliable.
- **Takeover findings are heuristic.** Always confirm manually before claiming a takeover — third-party services change behaviour and false positives happen.
- **macOS file-descriptor limit.** Before very large brute-force runs, raise it with `ulimit -n 10000`.
- **Optional source tools vary by version.** Each passive source is best-effort and skipped on error; run with `-v` to see if one is failing.
- **Scope discipline.** Related root domains are reported, not auto-attacked, unless you pass `--expand-roots`.

---

## Roadmap / ideas for the next version

- **More passive sources** — Chaos (ProjectDiscovery dataset), native Wayback/CommonCrawl/OTX queries (fewer tool dependencies), and certspotter as an additional CT source.
- **TLS SAN scraping** — pull hostnames from the certificates of live IPs (`tlsx`-style); catches names that never appear in CT logs.
- **Per-source coverage summary** — end-of-run report of how many subdomains each source contributed (and which silently returned nothing), for completeness confidence.
- **Resume / checkpointing** — persist progress so a long run can resume after a crash or Ctrl+C instead of only writing partial results.
- **Per-level wildcard detection** on the native resolver path (currently apex-level only).
- **ASN / CIDR expansion** — discover the org's IP ranges and reverse-DNS them to find hosts that DNS-name enumeration misses.
- **Native VirusTotal source** (`--vt-key`) so it doesn't depend on subfinder being configured, plus first-class API-key management.
- **nuclei integration** — run takeover and exposure templates against the live set for higher-coverage detection.
- **Rate-limit / politeness controls** — global throttle and per-host rate limits for programs that require gentle scanning.
- **Target-level parallelism** — process multiple `-T` targets concurrently (with rate-limit awareness).


Aracın iş akışı oluşturulmasına sırasında refarans site olarak https://www.wiz.io/bug-bounty-masterclass/reconnaissance/overview kullanıldı. 
