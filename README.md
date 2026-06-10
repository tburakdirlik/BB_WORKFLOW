# subrecon.py

A single-file **subdomain enumeration & attack-surface mapping** pipeline for bug bounty and authorized penetration testing.

Point it at a domain (or a list) and it produces the most complete, accurate set of **live subdomains** it can — plus the dead ones (reuse them for virtual-host enumeration), the live web services, subdomain-takeover candidates, and optionally open ports — in one human-readable report with machine-readable companions.

> ⚠️ Only test assets you are explicitly authorized to assess.

---

## Install

Get `subrecon.py` and `setup.py` into the same folder, then run the setup script **from that folder**:

```bash
git clone https://github.com/tburakdirlik/BB_WORKFLOW.git
cd BB_WORKFLOW
python3 setup.py          # interactive: installs deps + asks VirusTotal/Chaos keys
```

`setup.py` audits the toolchain and prints the exact install command for anything missing (Go tools via `go install`, system tools via brew/apt, SecLists, plus Homebrew/Go themselves), adds `~/go/bin` to your shell PATH, and asks for your **VirusTotal + Chaos** keys — press Enter to skip either (they're saved to `~/.recon/config`). For a read-only audit that only reports what's missing, run `python3 setup.py --check` first.

`subrecon.py` is **stdlib-only** (Python 3.7+); every external tool is optional and just unlocks or improves a phase — with zero tools installed, the native crt.sh source + threaded resolver still produce useful output. After setup, run `subrecon.py` from the same folder (see Usage below).

> Inside Claude-BugHunter you don't run this by hand — `integrate.sh` places `setup.py` in `engine/` and the `/recon-setup` command runs it for you (see [Claude-BugHunter integration](#claude-bughunter-integration)).

---

## Usage

```bash
# single target
python3 subrecon.py -t example.com -o out.txt

# list of targets
python3 subrecon.py -T targets.txt -o out.txt

# thorough: big wordlist, validated resolvers, recursion, vhost, ASN, JSON
python3 subrecon.py -t example.com \
    -w ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
    -r resolvers.txt --recursive --vhost --asn --json -o out.txt

# continuous monitoring with Slack/Discord alerts on new assets
python3 subrecon.py -t example.com --monitor \
    --notify-webhook https://hooks.slack.com/services/XXX -o out.txt
```

`-t` takes a host or a full URL — scheme, path, port, and `*.` are stripped automatically.

---

## What it does

An end-to-end pipeline, every stage **degrading gracefully** (missing tool → phase skipped or native fallback, never a crash):

1. **Root discovery** — `whois` registrant org; `--whoxy-key` adds reverse-WHOIS to find sibling roots (reported only unless `--expand-roots`).
2. **Passive enumeration** — queried in parallel and merged, each name tagged with its source: subfinder, crt.sh, **Chaos**, **VirusTotal**, **certspotter**, **OTX** (all native), gau/waybackurls, assetfinder, github-subdomains, amass (`--amass`).
3. **TLS-SAN harvest** — pulls hostnames from the certificates of live IPs (catches names absent from CT logs). Disable with `--no-tls-san`.
4. **DNS resolution** — `puredns` with a **two-tier resolver** setup: bulk list (`-r`) for mass resolution, then re-validation against trusted resolvers to kill false positives. Wildcard catch-alls filtered. Native threaded fallback if `puredns` is absent.
5. **Active discovery** — brute-force (`puredns` + wordlist), `alterx` permutations (iterated, `--perm-rounds`), and optional recursive brute-force (`--recursive`).
6. **ASN / CIDR expansion** *(opt-in `--asn`)* — resolves the org's announced IP ranges (RIPEstat) and reverse-DNSes them to find hosts that name-based enumeration misses.
7. **HTTP probing** — `httpx` records status, title, tech, IP, and CNAME per live service.
8. **Takeover detection** *(on by default)* — checks CNAMEs against a built-in fingerprint table; `confirmed` vs `potential`, both needing manual verification. Disable with `--no-takeover`.
9. **Optional** — virtual-host enum (`--vhost`, ffuf, dead names as `Host` headers), port scan (`--ports` / `--full-ports`, nmap), and **monitor mode** (`--monitor`) that diffs against the last run and posts only new assets to a webhook.

---

## API keys

Keys live in **`~/.recon/config`** (`KEY=value`, one per line) — `setup.py` writes them there, or add by hand:

```
VT_API_KEY=...
CHAOS_KEY=...
```

`subrecon.py` reads them natively each run (env vars of the same name override the file). **certspotter and OTX need no key.** `github-subdomains` needs `$GITHUB_TOKEN` or `--github-token`.

---

## Common flags

| Flag | Description |
|------|-------------|
| `-t` / `-T` | single target / file of targets |
| `-o` | report file (companions written alongside) |
| `-w` / `-r` | brute-force wordlist / bulk resolvers file |
| `--passive-only` | passive enumeration + resolution only |
| `--recursive` / `--vhost` / `--ports` / `--asn` | enable the heavier optional phases |
| `--no-bruteforce` / `--no-permutations` / `--no-takeover` / `--no-tls-san` | skip a phase |
| `--monitor` / `--notify-webhook` | diff vs last run + alert on new assets |
| `--json` | also write `<output>.json` |
| `-v` | show child-process stderr (debug missing/failing tools) |

Full list: `python3 subrecon.py -h`.

## Output

For `-o out.txt`: `out.txt` (full report), `out_live.txt` / `out_dead.txt` (resolving / non-resolving subs), `out_vhosts.txt` (`--vhost`), `out_takeover.txt` (if any), `out.json` (`--json`).

---

## Claude-BugHunter integration

`subrecon.py` slots into [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) as the horizontal asset-discovery layer behind its `/recon` command — the step BugHunter deliberately leaves thin. Two ways to wire it in; pick one.

### Method 1 — `integrate.sh` (deterministic)

Run once in a **normal terminal** (Claude not needed), pointing at your Claude-BugHunter checkout:

```bash
curl -fsSL https://raw.githubusercontent.com/tburakdirlik/BB_WORKFLOW/refs/heads/main/integrate.sh -o integrate.sh
bash integrate.sh /path/to/Claude-BugHunter
#   or, from inside the repo: cd Claude-BugHunter && bash integrate.sh
```

It downloads `subrecon.py` + `setup.py` into `engine/`, adds a `/recon-setup` command, rewires `/recon` Step 1+2 to call `subrecon.py` (Steps 3–9 untouched, backup at `commands/recon.md.bak`), and runs `scripts/install.sh`. **Idempotent** — safe to re-run.

### Method 2 — integration prompt (Claude-driven)

Prefer Claude to do it (and review each edit)? Start `claude` from the repo root, then copy everything between `PROMPT START` and `PROMPT END` and paste it. It makes the same file changes, described step by step — plain text, so it pastes cleanly.

```text
================== PROMPT START ==================
You are in the Claude-BugHunter repo. Wire my subdomain-enumeration tool
subrecon.py into the /recon pipeline as a durable, file-based change. Do EXACTLY
the steps below and nothing more. Do not commit or push.

1. Download my tool and installer into the engine:
     curl -fsSL https://raw.githubusercontent.com/tburakdirlik/BB_WORKFLOW/refs/heads/main/subrecon.py -o engine/subrecon.py
     curl -fsSL https://raw.githubusercontent.com/tburakdirlik/BB_WORKFLOW/refs/heads/main/setup.py    -o engine/setup.py
     chmod +x engine/subrecon.py engine/setup.py

2. Edit commands/recon.md. First copy it to commands/recon.md.bak. Then replace
   the whole section from the line   ### Step 1: Subdomain Enumeration   up to
   (but NOT including) the line   ### Step 3: URL Crawl   with a new section
   titled   ### Step 1+2: Asset Discovery (subdomain enum + live hosts + takeover)
   The new section must hold ONE bash code block that runs, in this order:
     TARGET="$1"
     mkdir -p recon/$TARGET
     python3 engine/subrecon.py -t "$TARGET" -o recon/$TARGET/subrecon.txt --json
     cp recon/$TARGET/subrecon_live.txt recon/$TARGET/subdomains.txt 2>/dev/null
     httpx -l recon/$TARGET/subdomains.txt -silent -status-code -title -tech-detect | tee recon/$TARGET/live-hosts.txt
   Add one line under it: takeover candidates are already in subrecon.txt
   (subrecon runs its own takeover scan), so the later subzy step stays only as a
   cross-check. Leave Steps 3 through 9 completely untouched.

3. Create commands/recon-setup.md: a /recon-setup slash command with YAML
   frontmatter (a   name: recon-setup   line and a one-line   description: ).
   Its body tells the user to run   python3 engine/setup.py --check   to see what
   is missing, install the missing tools, and configure VirusTotal + Chaos keys
   by running   python3 engine/setup.py   in their OWN terminal so secrets never
   pass through chat. certspotter and OTX need no key.

4. Run   ./scripts/install.sh   so the updated commands reach ~/.claude/commands/.

5. Report exactly which files you created or modified. Do not commit, do not
   push, do not touch anything outside engine/ and commands/.

Notes: subrecon.py reads VirusTotal/Chaos keys natively from ~/.recon/config, so
it needs no code changes. Its outputs are subrecon_live.txt / subrecon_dead.txt /
subrecon.json next to the -o path; the commands above map those into the
subdomains.txt and live-hosts.txt that the later steps consume.
=================== PROMPT END ===================
```

### After either method

Inside Claude, from the repo root:

```
/recon-setup          # install the recon toolchain (asks VirusTotal + Chaos)
/recon target.com     # full pipeline — now front-ended by subrecon.py
```

> Start `claude` from the repo root so the relative `engine/` paths resolve. `integrate.sh` fetches `subrecon.py`/`setup.py` from this repo's raw URLs, so make sure they're pushed here first (override with `SUBRECON_URL=` / `SETUP_URL=` otherwise).

---

## Notes

- **Resolver quality matters.** Supply a large validated bulk list via `-r` (e.g. [trickest/resolvers](https://github.com/trickest/resolvers)) for reliable heavy brute-force; without it the small built-in list is reused.
- **Takeover findings are heuristic** — always confirm manually before reporting.
- **macOS fd limit** — `ulimit -n 10000` before very large brute-force runs.

---

Aracın iş akışı oluşturulması sırasında referans site olarak <https://www.wiz.io/bug-bounty-masterclass/reconnaissance/overview> kullanıldı.
