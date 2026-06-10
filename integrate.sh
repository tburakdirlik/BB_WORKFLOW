#!/usr/bin/env bash
#
# integrate.sh — wire subrecon.py into a Claude-BugHunter checkout (durable, idempotent).
#
# What it does, once, as file changes:
#   1. Downloads subrecon.py + setup.py into engine/.
#   2. Writes commands/recon-setup.md (the /recon-setup deps installer command).
#   3. Patches commands/recon.md Step 1+2 to call engine/subrecon.py (keeps Steps 3-9).
#   4. Re-runs scripts/install.sh so the updated commands reach ~/.claude/commands/.
#
# Usage:
#   bash integrate.sh                       # run from the Claude-BugHunter repo root
#   bash integrate.sh /path/to/Claude-BugHunter
#   bash integrate.sh --no-install          # skip the install.sh re-run
#
# URLs can be overridden via env (SUBRECON_URL / SETUP_URL).
#
set -euo pipefail

SUBRECON_URL="${SUBRECON_URL:-https://raw.githubusercontent.com/tburakdirlik/BB_WORKFLOW/refs/heads/main/subrecon.py}"
SETUP_URL="${SETUP_URL:-https://raw.githubusercontent.com/tburakdirlik/BB_WORKFLOW/refs/heads/main/setup.py}"

# ---- args -----------------------------------------------------------------
RUN_INSTALL=1
REPO=""
for arg in "$@"; do
  case "$arg" in
    --no-install) RUN_INSTALL=0 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) REPO="$arg" ;;
  esac
done
REPO="${REPO:-$PWD}"

# ---- validate target repo -------------------------------------------------
if [ ! -f "$REPO/commands/recon.md" ] || [ ! -d "$REPO/engine" ]; then
  echo "[-] Not a Claude-BugHunter checkout: $REPO"
  echo "    Run from the repo root, or: bash integrate.sh /path/to/Claude-BugHunter"
  exit 1
fi
cd "$REPO"
echo "[*] Claude-BugHunter repo: $PWD"

# ---- 1. fetch subrecon.py + setup.py into engine/ -------------------------
echo "[*] Fetching subrecon.py + setup.py into engine/ ..."
curl -fsSL "$SUBRECON_URL" -o engine/subrecon.py
curl -fsSL "$SETUP_URL"    -o engine/setup.py
chmod +x engine/subrecon.py engine/setup.py
echo "[+] engine/subrecon.py"
echo "[+] engine/setup.py"

# ---- 2. write commands/recon-setup.md -------------------------------------
cat > commands/recon-setup.md <<'MD'
---
name: recon-setup
description: One-time setup for the subdomain-enumeration toolchain that engine/subrecon.py needs. Detects and installs the missing binaries (subfinder, puredns, httpx, alterx, gau, assetfinder, github-subdomains, ffuf, amass, nmap, massdns), clones SecLists, and puts ~/go/bin on PATH. Run once before /recon. Usage: /recon-setup
---

# /recon-setup

Bootstraps everything `engine/subrecon.py` (the horizontal asset-discovery layer
behind `/recon` Step 1+2) needs. Safe to re-run — only installs what is missing.
Run `claude` from the repo root so the relative `engine/` paths resolve.

## Steps

### Step 1 — Audit what's installed

```bash
python3 engine/setup.py --check
```

For every tool this prints `present` / `MISSING`, and for each missing one it
prints the exact install command for this OS. Read it before installing.

### Step 2 — Install the missing pieces

Run the commands Step 1 printed (ask the user before any `sudo`/Homebrew step):

- Prerequisites first if missing: Homebrew (macOS), then Go.
- Go tools (`go install ...`, land in `~/go/bin`): subfinder, httpx, puredns,
  alterx, gau, waybackurls, assetfinder, github-subdomains, ffuf, amass.
- System tools: `brew install ...` (macOS) / `sudo apt-get install -y ...` (Linux):
  nmap, massdns, whois. On Debian/Ubuntu massdns may need a source build (Step 1 prints it).
- SecLists if missing:
  `git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/SecLists`

`engine/setup.py` (run without `--check`) also adds `~/go/bin` to your shell rc.
Reload the shell once afterwards: `source ~/.zshrc`.

### Step 3 — Verify

```bash
python3 engine/setup.py --check    # everything required should now say "present"
```

## API keys (do this in your OWN terminal, not through Claude)

`engine/subrecon.py` reads keys from `~/.recon/config`. Configure them once by
running this in your own terminal — the prompts hide each key, so nothing
sensitive lands in this conversation:

```bash
python3 engine/setup.py        # interactive: VirusTotal + Chaos (both skippable)
```

Or add them by hand to `~/.recon/config` (then `chmod 600`):

```
VT_API_KEY=...
CHAOS_KEY=...
```

certspotter and OTX need no key (they run rate-limited without one). Env vars
override the file if you prefer to `export` instead.

## Next

```
/recon target.com
```
MD
echo "[+] commands/recon-setup.md"

# ---- 3. patch commands/recon.md Step 1+2 (idempotent) ---------------------
python3 - <<'PY'
import pathlib, sys

p = pathlib.Path("commands/recon.md")
src = p.read_text()

if "engine/subrecon.py" in src:
    print("[i] recon.md already wired to subrecon.py - skipping patch")
    sys.exit(0)

START = "### Step 1: Subdomain Enumeration"
END   = "### Step 3: URL Crawl"
i, j = src.find(START), src.find(END)
if i == -1 or j == -1:
    print("[!] Could not find the Step 1 / Step 3 markers in recon.md.")
    print("    Leaving it unchanged - patch Step 1+2 by hand (see README/notes).")
    sys.exit(0)

NEW = '''### Step 1+2: Asset Discovery (subdomain enum + live hosts + takeover)

Horizontal discovery — subdomain enumeration, DNS resolution, HTTP probing,
TLS-SAN harvesting, and subdomain-takeover — is one deterministic engine:
`engine/subrecon.py`. Far more thorough than hand-rolled bash: 8+ passive sources
(subfinder, crt.sh, Chaos, VirusTotal, certspotter, OTX, gau/waybackurls,
assetfinder, github-subdomains, amass), puredns mass-resolution with wildcard
filtering, bruteforce + alterx permutations, ASN/CIDR expansion, and a built-in
CNAME/fingerprint takeover scan. Every phase degrades gracefully — a missing
binary just skips its phase. Keys (VirusTotal, Chaos) come from `~/.recon/config`.

```bash
TARGET="$1"
mkdir -p recon/$TARGET

# Horizontal discovery: passive+active enum -> resolve -> live hosts -> takeover
python3 engine/subrecon.py -t "$TARGET" -o recon/$TARGET/subrecon.txt --json
#   deeper run: add --vhost --recursive --asn      fast pass: --passive-only

# Normalize the engine output to the filenames the later steps expect:
cp recon/$TARGET/subrecon_live.txt recon/$TARGET/subdomains.txt 2>/dev/null

# Re-probe the live set with tech detection for the crawl/classify phases:
httpx -l recon/$TARGET/subdomains.txt -silent -status-code -title -tech-detect \\
  | tee recon/$TARGET/live-hosts.txt

echo "[+] Live subs:  $(wc -l < recon/$TARGET/subdomains.txt 2>/dev/null || echo 0)"
echo "[+] Live hosts: $(wc -l < recon/$TARGET/live-hosts.txt 2>/dev/null || echo 0)"
echo "[+] Dead/vhost: $(wc -l < recon/$TARGET/subrecon_dead.txt 2>/dev/null || echo 0)"
```

> Takeover candidates are already in `subrecon.txt` (the engine runs a
> CNAME/fingerprint takeover scan); Step 7 (subzy) stays as a cross-check.
> If `engine/subrecon.py` is unavailable, fall back to the old path:
> `subfinder -d $TARGET -silent | dnsx -silent | httpx -silent -sc -title -td`.

'''

pathlib.Path("commands/recon.md.bak").write_text(src)
p.write_text(src[:i] + NEW + src[j:])
print("[+] recon.md Step 1+2 -> engine/subrecon.py  (backup: commands/recon.md.bak)")
PY

# ---- 4. install so commands reach ~/.claude/commands ----------------------
if [ "$RUN_INSTALL" = "1" ] && [ -x scripts/install.sh ]; then
  echo "[*] Running scripts/install.sh ..."
  ./scripts/install.sh
else
  echo "[i] Skipped scripts/install.sh — run it yourself so the commands load:"
  echo "      ./scripts/install.sh"
fi

cat <<'NEXT'

[+] Integration complete. Next:
    1. Install recon deps:           /recon-setup        (or: python3 engine/setup.py --check)
    2. Configure keys (own terminal): python3 engine/setup.py    (VirusTotal + Chaos)
    3. Run the pipeline:             /recon target.com
NEXT
