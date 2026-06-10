#!/usr/bin/env python3
"""
recon.py - subdomain enumeration & attack-surface mapping pipeline - recon_v1.1.py

Goal: enumerate *all* live subdomains of a target as completely and
accurately as possible, and separately surface the dead (non-resolving)
names so they can be reused for virtual-host enumeration.

Pipeline per target:
    root domain discovery (whois / whoxy)
      -> passive enumeration   (subfinder, crt.sh, gau/waybackurls,
                                 assetfinder, github-subdomains, amass)
      -> DNS resolution        (puredns: bulk resolve + trusted re-validation,
                                 native threaded fallback)
      -> active discovery      (puredns bruteforce, alterx permutations,
                                 optional recursive bruteforce)
      -> HTTP probing          (httpx)
      -> virtual-host enum      (ffuf, optional, uses the dead list)
      -> port scan             (nmap, optional)

Outputs:
    <output>            full human-readable report (everything combined)
    <output>_live.txt   resolving subdomains, one per line
    <output>_dead.txt   non-resolving subdomains, one per line (vhost input)
    <output>_vhosts.txt  discovered virtual hosts (if --vhost)

Everything degrades gracefully: a missing binary skips its phase, and
crt.sh + a threaded resolver keep it useful with none of the Go tools.

Usage:
    python3 recon.py -t example.com -o output.txt
    python3 recon.py -T targets.txt -o output.txt --vhost --recursive

Only test assets you are explicitly authorized to assess.
"""

import argparse
import json
import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Set from --verbose; when True, child-process stderr is shown for debugging.
VERBOSE = False


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GREY = "\033[90m"
    enabled = True

    @classmethod
    def disable(cls):
        cls.enabled = False

    @classmethod
    def w(cls, color, text):
        return f"{color}{text}{cls.RESET}" if cls.enabled else text


def phase(msg):
    print()
    print(C.w(C.BOLD + C.BLUE, f"[*] {msg}"))


def info(msg):
    print(C.w(C.CYAN, f"[i] {msg}"))


def good(msg):
    print(C.w(C.GREEN, f"[+] {msg}"))


def warn(msg):
    print(C.w(C.YELLOW, f"[!] {msg}"))


def err(msg):
    print(C.w(C.RED, f"[-] {msg}"), file=sys.stderr)


def banner():
    print(C.w(C.BOLD + C.CYAN, "recon.py - subdomain enumeration pipeline"))


# --------------------------------------------------------------------------- #
# Generic process / network helpers
# --------------------------------------------------------------------------- #
def have(tool):
    return shutil.which(tool) is not None


def run_stream(cmd, stdin_data=None, quiet=False, indent="    "):
    """
    Run `cmd`, stream stdout live (unless quiet), return list of stdout lines.
    Returns None if the binary is missing. stderr shown only with --verbose.

    stdin is fed from a writer thread so large inputs cannot deadlock against
    a filling stdout pipe.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=None if VERBOSE else subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        return None

    if stdin_data is not None:
        def _feed():
            try:
                proc.stdin.write(stdin_data)
                proc.stdin.close()
            except (BrokenPipeError, ValueError, OSError):
                pass
        threading.Thread(target=_feed, daemon=True).start()

    lines = []
    try:
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            if not quiet:
                print(f"{indent}{line}")
            lines.append(line)
    finally:
        proc.stdout.close()
        proc.wait()
    return lines


def in_scope(name, domain):
    """True if `name` is the apex or a subdomain of `domain` (boundary safe)."""
    return name == domain or name.endswith("." + domain)


def clean_domain(value):
    """Normalize user input to a bare domain: strip scheme, path, port, wildcard."""
    d = value.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)   # scheme
    d = d.split("/", 1)[0]                         # path
    d = d.split("?", 1)[0]                         # query
    d = d.split(":", 1)[0]                         # port
    d = d.lstrip("*.").strip(".")
    return d


def hosts_from_urls(lines, domain):
    """Extract in-scope hostnames from a list of URLs (gau / waybackurls)."""
    out = set()
    for u in lines:
        u = u.strip()
        if not u:
            continue
        try:
            netloc = urllib.parse.urlsplit(u if "://" in u else "//" + u).netloc
        except ValueError:
            continue
        host = netloc.split("@")[-1].split(":")[0].lower().strip(".")
        if host and in_scope(host, domain):
            out.add(host)
    return out


def detect_wildcard(domain):
    """
    Return the set of IPs a wildcard DNS record resolves to (empty if none).

    Used only on the native resolver path - puredns does its own wildcard
    filtering. Catches the common `*.domain` catch-all that would otherwise
    make every permutation candidate look live.
    """
    ips = set()
    socket.setdefaulttimeout(4)
    for _ in range(3):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        try:
            for ai in socket.getaddrinfo(f"{label}.{domain}", None):
                ips.add(ai[4][0])
        except (socket.gaierror, socket.timeout, UnicodeError, OSError):
            pass
    return ips


# --------------------------------------------------------------------------- #
# Phase 4 - root domain discovery
# --------------------------------------------------------------------------- #
def whois_org(domain):
    if not have("whois"):
        warn("whois not found - skipping registrant lookup")
        return None
    lines = run_stream(["whois", domain], quiet=True) or []
    redacted = ("redacted", "privacy", "n/a", "not disclosed", "data protected")
    for line in lines:
        low = line.lower()
        if ("registrant organization" in low or "registrant org:" in low
                or low.strip().startswith("org-name")):
            val = line.split(":", 1)[1].strip() if ":" in line else ""
            if val and not any(r in val.lower() for r in redacted):
                return val
    return None


def whoxy_reverse(org, api_key):
    """Reverse WHOIS via whoxy.com. Returns a set of domain names."""
    found = set()
    url = ("https://api.whoxy.com/?key=" + urllib.parse.quote(api_key)
           + "&reverse=whois&company=" + urllib.parse.quote(org))
    try:
        with urllib.request.urlopen(url, timeout=40) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        warn(f"whoxy query failed: {e}")
        return found
    if str(data.get("status")) != "1":
        warn(f"whoxy status {data.get('status')}: {data.get('status_reason', '')}")
        return found
    for item in data.get("search_result", []):
        d = (item.get("domain_name") or "").strip().lower()
        if d:
            found.add(d)
            print(f"    {d}")
    return found


def root_domains(domain, whoxy_key):
    org = whois_org(domain)
    if org:
        good(f"registrant organization: {org}")
    else:
        info("registrant organization not found or redacted")

    roots = set()
    if org and whoxy_key:
        info("reverse WHOIS via whoxy.com ...")
        roots = whoxy_reverse(org, whoxy_key)
    elif org:
        info("pass --whoxy-key to expand related root domains via reverse WHOIS")
    return org, roots


# --------------------------------------------------------------------------- #
# Phase 1 - passive enumeration (multi-source)
# --------------------------------------------------------------------------- #
def crtsh(domain, timeout=60, retries=3):
    """Certificate-transparency lookup with retry (crt.sh 502s on big domains)."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    found = set()
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "recon.py/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            for entry in data:
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name and in_scope(name, domain):
                        found.add(name)
            return found
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2 * (attempt + 1))
                continue
            warn(f"crt.sh query failed after {retries} tries: {e}")
    return found


def passive_enum(domain, amass=False, github_token=None):
    """Query every available passive source. Returns {host: set(source_tags)}."""
    found = {}

    def add(names, src):
        new = []
        for n in names:
            n = n.strip().lower().strip(".")
            if n and in_scope(n, domain):
                if n not in found:
                    new.append(n)
                found.setdefault(n, set()).add(src)
        if new:
            good(f"{src}: +{len(new)} new")
            for n in sorted(new):
                print(f"    {n}")

    if have("subfinder"):
        add(run_stream(["subfinder", "-d", domain, "-silent"], quiet=True) or [], "subfinder")
    else:
        warn("subfinder not found - skipping (github.com/projectdiscovery/subfinder)")

    info("querying crt.sh (certificate transparency) ...")
    add(crtsh(domain), "crtsh")

    if have("gau"):
        add(hosts_from_urls(run_stream(["gau", "--subs", domain], quiet=True) or [], domain),
            "wayback")
    elif have("waybackurls"):
        add(hosts_from_urls(run_stream(["waybackurls"], stdin_data=domain + "\n", quiet=True) or [],
                            domain), "wayback")
    else:
        info("gau/waybackurls not found - skipping URL-archive source")

    if have("assetfinder"):
        add(run_stream(["assetfinder", "--subs-only", domain], quiet=True) or [], "assetfinder")

    if have("github-subdomains"):
        if github_token:
            add(run_stream(["github-subdomains", "-d", domain, "-t", github_token], quiet=True) or [],
                "github")
        else:
            info("github-subdomains present but no token - set --github-token or $GITHUB_TOKEN")

    if amass and have("amass"):
        info("amass passive (this can be slow) ...")
        add(run_stream(["amass", "enum", "-passive", "-d", domain, "-timeout", "8"], quiet=True) or [],
            "amass")
    elif amass:
        warn("amass not found - skipping")

    return found


# --------------------------------------------------------------------------- #
# Phase 2/3 - resolution + active discovery
# --------------------------------------------------------------------------- #
def resolve_python(hosts, threads=50, wildcard_ips=None):
    """
    Threaded socket fallback used when puredns is unavailable.

    If wildcard_ips is given, hosts that resolve *only* to those IPs are
    treated as wildcard catch-all noise and dropped.
    """
    resolved = set()
    wildcard_ips = wildcard_ips or set()
    socket.setdefaulttimeout(4)

    def check(h):
        try:
            ips = {ai[4][0] for ai in socket.getaddrinfo(h, None)}
            return h, ips
        except (socket.gaierror, socket.timeout, UnicodeError, OSError):
            return h, None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(check, h) for h in hosts]
        for fut in as_completed(futs):
            h, ips = fut.result()
            if not ips:
                continue
            if wildcard_ips and ips <= wildcard_ips:
                continue
            print(f"    {h}")
            resolved.add(h)
    return resolved


def resolve_hosts(hosts, resolvers, trusted, threads=50, wildcard_ips=None):
    hosts = sorted(set(hosts))
    if not hosts:
        return set()
    if have("puredns"):
        cmd = ["puredns", "resolve", "-q"]
        if resolvers:
            cmd += ["-r", resolvers]
        if trusted:
            cmd += ["--resolvers-trusted", trusted]
        lines = run_stream(cmd, stdin_data="\n".join(hosts) + "\n")
        if lines is not None:  # binary ran (empty list = nothing resolved)
            return {l.strip().lower() for l in lines if l.strip()}
    warn("puredns unavailable - using built-in resolver (slower)")
    return resolve_python(hosts, threads, wildcard_ips)


def bruteforce(base, wordlist, resolvers, trusted):
    """Brute-force <word>.<base> with puredns (bulk resolve + trusted verify)."""
    if not have("puredns"):
        warn("puredns not found - skipping DNS brute-force")
        return set()
    if not wordlist or not os.path.isfile(wordlist):
        warn("no wordlist available - skipping DNS brute-force (use -w)")
        return set()
    cmd = ["puredns", "bruteforce", wordlist, base, "-q"]
    if resolvers:
        cmd += ["-r", resolvers]
    if trusted:
        cmd += ["--resolvers-trusted", trusted]
    lines = run_stream(cmd)
    return {l.strip().lower() for l in (lines or []) if l.strip()}


def permutations(seed_hosts, resolvers, trusted, threads=50, wildcard_ips=None):
    if not have("alterx"):
        warn("alterx not found - skipping DNS permutations")
        return set()
    if not seed_hosts:
        return set()
    info("generating permutations with alterx ...")
    perms = run_stream(["alterx", "-silent"],
                       stdin_data="\n".join(sorted(seed_hosts)) + "\n", quiet=True)
    candidates = {p.strip().lower() for p in (perms or []) if p.strip()}
    if not candidates:
        return set()
    info(f"{len(candidates)} permutation candidates - resolving ...")
    return resolve_hosts(candidates, resolvers, trusted, threads, wildcard_ips)


# --------------------------------------------------------------------------- #
# Phase 5 - public exposure (httpx) + ports (nmap)
# --------------------------------------------------------------------------- #
def fmt_http(rec):
    tech = rec.get("tech") or []
    if isinstance(tech, list):
        tech = ", ".join(str(t) for t in tech)
    title = (rec.get("title") or "").replace("\n", " ").strip()
    if len(title) > 50:
        title = title[:47] + "..."
    status = rec.get("status", "")
    parts = [
        rec.get("url", ""),
        f"[{status}]" if status != "" else "",
        f"[{title}]" if title else "",
        f"[{tech}]" if tech else "",
        rec.get("ip", ""),
    ]
    return "  ".join(p for p in parts if p)


def probe_http(hosts):
    results = []
    if not hosts:
        return results
    if not have("httpx"):
        warn("httpx not found - skipping web probing (github.com/projectdiscovery/httpx)")
        return results

    cmd = ["httpx", "-silent", "-json", "-title", "-status-code",
           "-tech-detect", "-ip", "-cname", "-no-color"]
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=None if VERBOSE else subprocess.DEVNULL,
                                text=True, bufsize=1)
    except FileNotFoundError:
        warn("httpx not found - skipping web probing")
        return results

    data = "\n".join(sorted(hosts)) + "\n"

    def _feed():
        try:
            proc.stdin.write(data)
            proc.stdin.close()
        except (BrokenPipeError, ValueError, OSError):
            pass
    threading.Thread(target=_feed, daemon=True).start()

    for raw in proc.stdout:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        ip = ""
        if isinstance(obj.get("a"), list) and obj["a"]:
            ip = obj["a"][0]
        elif obj.get("host"):
            ip = obj["host"]
        elif obj.get("ip"):
            ip = obj["ip"]
        rec = {
            "url": obj.get("url") or obj.get("input") or "",
            "status": obj.get("status_code", ""),
            "title": obj.get("title") or "",
            "tech": obj.get("tech") or obj.get("technologies") or [],
            "ip": ip,
            "cname": obj.get("cname") or [],
        }
        results.append(rec)
        print("    " + fmt_http(rec))
    proc.stdout.close()
    proc.wait()
    return results


def port_scan(ips, full=False):
    out = {}
    if not ips:
        return out
    if not have("nmap"):
        warn("nmap not found - skipping port scan")
        return out
    port_arg = "-p-" if full else "--top-ports=1000"
    for ip in sorted(ips):
        phase(f"port scan: {ip}")
        cmd = ["nmap", "-sV", "-Pn", "-n", port_arg, "--min-rate", "1000", ip]
        lines = run_stream(cmd, quiet=True) or []
        open_lines = []
        for l in lines:
            s = l.strip()
            if ("/tcp" in s or "/udp" in s) and "open" in s and "/" in s.split()[0]:
                print("    " + s)
                open_lines.append(s)
        out[ip] = open_lines
    return out


def ips_from_http(http_results):
    return {r["ip"] for r in http_results if r.get("ip")}


def ips_from_hosts(hosts):
    ips = set()
    socket.setdefaulttimeout(4)

    def res(h):
        try:
            return socket.gethostbyname(h)
        except (socket.gaierror, socket.timeout, UnicodeError, OSError):
            return None

    with ThreadPoolExecutor(max_workers=50) as ex:
        for ip in ex.map(res, list(hosts)):
            if ip:
                ips.add(ip)
    return ips


# --------------------------------------------------------------------------- #
# Virtual-host enumeration (ffuf)
# --------------------------------------------------------------------------- #
def parse_ffuf_json(path):
    """Parse ffuf -of json output into [(host, status, length), ...]."""
    out = []
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return out
    for r in data.get("results", []):
        host = (r.get("input") or {}).get("FUZZ", "")
        if host:
            out.append((host, r.get("status", ""), r.get("length", "")))
    return out


def vhost_enum(dead_hosts, live_ips, schemes=("https", "http")):
    """
    Fuzz the Host header of dead (non-resolving) names against live IPs to
    find virtual hosts that have no public DNS record. Returns
    {ip: [(host, scheme, status, length), ...]}.
    """
    out = {}
    if not dead_hosts or not live_ips:
        return out
    if not have("ffuf"):
        warn("ffuf not found - skipping virtual-host enumeration (install ffuf)")
        return out

    fd, wl = tempfile.mkstemp(prefix="recon_vhost_", suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(sorted(dead_hosts)) + "\n")

    tmp_files = [wl]
    try:
        for ip in sorted(live_ips):
            hits = []
            for scheme in schemes:
                info(f"vhost fuzzing {scheme}://{ip} ({len(dead_hosts)} candidates)")
                ofd, ojson = tempfile.mkstemp(prefix="recon_ffuf_", suffix=".json")
                os.close(ofd)
                tmp_files.append(ojson)
                cmd = ["ffuf", "-w", f"{wl}:FUZZ", "-u", f"{scheme}://{ip}/",
                       "-H", "Host: FUZZ", "-ac", "-mc", "all",
                       "-of", "json", "-o", ojson, "-s"]
                run_stream(cmd, quiet=True)
                for host, status, length in parse_ffuf_json(ojson):
                    hits.append((host, scheme, status, length))
                    print(f"    {scheme}://{ip}  Host: {host}  [{status}] ({length} bytes)")
            if hits:
                out[ip] = hits
    finally:
        for p in tmp_files:
            try:
                os.remove(p)
            except OSError:
                pass
    return out


# --------------------------------------------------------------------------- #
# Setup helpers (resolvers / wordlists / tool summary)
# --------------------------------------------------------------------------- #
TRUSTED_RESOLVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                     "9.9.9.9", "149.112.112.112", "208.67.222.222"]

DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"),
    os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"),
]

DEFAULT_RECURSION_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
]


def write_temp(lines, prefix):
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def setup_resolvers(bulk_path, trusted_path):
    """
    Return (bulk_resolvers, trusted_resolvers, temp_files_to_cleanup).

    trusted = small reliable list used by puredns for re-validation (kills
    false positives). bulk = large list for mass resolution; falls back to
    the trusted list if the user provides none (with a warning).
    """
    temps = []
    if trusted_path and os.path.isfile(trusted_path):
        trusted = trusted_path
    else:
        if trusted_path:
            warn(f"trusted resolvers file not found: {trusted_path} - using built-in")
        trusted = write_temp(TRUSTED_RESOLVERS, "recon_trusted_")
        temps.append(trusted)

    if bulk_path and os.path.isfile(bulk_path):
        bulk = bulk_path
    else:
        if bulk_path:
            warn(f"resolvers file not found: {bulk_path} - using built-in fallback")
        warn("no bulk resolver list (-r) given - using built-in list for mass resolution too; "
             "for serious brute-force supply a large validated list (e.g. trickest/resolvers)")
        bulk = trusted
    return bulk, trusted, temps


def _find(paths, label, user):
    if user:
        if os.path.isfile(user):
            return user
        warn(f"{label} not found: {user}")
        return None
    for p in paths:
        if os.path.isfile(p):
            info(f"using detected {label}: {p}")
            return p
    return None


def find_wordlist(user):
    return _find(DEFAULT_WORDLISTS, "wordlist", user)


def find_recursion_wordlist(user, fallback):
    wl = _find(DEFAULT_RECURSION_WORDLISTS, "recursion wordlist", user)
    if wl:
        return wl
    if fallback:
        warn("no smaller recursion wordlist found - reusing main wordlist (heavy)")
    return fallback


def summarize_tools():
    tools = ["subfinder", "puredns", "massdns", "alterx", "httpx", "nmap", "whois",
             "gau", "waybackurls", "assetfinder", "github-subdomains", "amass", "ffuf"]
    present = [t for t in tools if have(t)]
    missing = [t for t in tools if not have(t)]
    info("tools available: " + (", ".join(present) if present else "none"))
    if missing:
        warn("tools missing (phases skipped or using fallbacks): " + ", ".join(missing))
    if "puredns" in present and "massdns" not in present:
        warn("puredns present but massdns missing - puredns will likely fail; install massdns")


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
def run_pipeline(domain, args, ctx, queue, visited):
    domain = clean_domain(domain)
    bulk, trusted = ctx["bulk"], ctx["trusted"]
    result = {
        "target": domain, "org": None, "extra_roots": set(),
        "resolved": set(), "unresolved": set(), "sources": {},
        "http": [], "vhosts": {}, "ports": {},
    }
    sources = result["sources"]

    def tag(names, label):
        for n in names:
            sources.setdefault(n, set()).add(label)

    bar = "=" * 70
    print()
    print(C.w(C.BOLD + C.CYAN, bar))
    print(C.w(C.BOLD + C.CYAN, f" TARGET: {domain}"))
    print(C.w(C.BOLD + C.CYAN, bar))

    # Phase 4 - cheap, run first to surface scope
    phase(f"root domain discovery - {domain}")
    org, roots = root_domains(domain, args.whoxy_key)
    result["org"], result["extra_roots"] = org, roots
    if args.expand_roots and roots:
        for r in roots:
            r = clean_domain(r)
            if r and r not in visited:
                visited.add(r)
                queue.append(r)
                good(f"queued related root domain: {r}")

    # Wildcard DNS only matters for the native resolver path; puredns self-filters.
    wildcard_ips = set()
    need_native_active = (not args.passive_only
                          and (not args.no_permutations or args.recursive)
                          and not have("puredns"))
    if need_native_active:
        wildcard_ips = detect_wildcard(domain)
        if wildcard_ips:
            warn(f"wildcard DNS detected for {domain} "
                 f"({', '.join(sorted(wildcard_ips))}) - permutation hits to those IPs dropped")

    # Phase 1 - passive (multi-source)
    phase(f"passive subdomain enumeration - {domain}")
    passive_map = passive_enum(domain, amass=args.amass, github_token=ctx["github_token"])
    passive_map.setdefault(domain, set()).add("apex")
    for h, srcs in passive_map.items():
        sources.setdefault(h, set()).update(srcs)
    good(f"{len(passive_map)} unique names from passive sources")

    # Phase 2 - resolve passive set (CT/archive-backed names: no wildcard filtering)
    phase(f"resolving {len(passive_map)} hosts - {domain}")
    resolved = resolve_hosts(passive_map, bulk, trusted, args.threads)
    good(f"{len(resolved)} hosts resolved")

    if not args.passive_only:
        # Phase 3a - brute-force apex
        if not args.no_bruteforce:
            phase(f"active discovery - DNS brute-force - {domain}")
            bf = bruteforce(domain, ctx["wordlist"], bulk, trusted)
            tag(bf, "brute-force")
            new = bf - resolved
            if new:
                good(f"{len(new)} new hosts from brute-force")
            resolved |= bf

        # Phase 3b - permutations, iterated until a round adds nothing
        if not args.no_permutations:
            rounds = max(1, args.perm_rounds)
            for i in range(rounds):
                phase(f"active discovery - permutations round {i + 1}/{rounds} - {domain}")
                pm = permutations(resolved, bulk, trusted, args.threads, wildcard_ips)
                tag(pm, "permutation")
                new = pm - resolved
                resolved |= pm
                good(f"{len(new)} new hosts this round")
                if not new:
                    break

        # Phase 3c - recursive brute-force (opt-in, expensive)
        if args.recursive and not args.no_bruteforce and ctx["recursion_wordlist"]:
            phase(f"active discovery - recursive brute-force (depth {args.recursion_depth}) - {domain}")
            current = sorted(h for h in resolved if h != domain)
            seen = set()
            depth = 1
            while current and depth <= args.recursion_depth:
                info(f"recursion depth {depth}: {len(current)} base name(s)")
                nxt = []
                for base in current:
                    if base in seen:
                        continue
                    seen.add(base)
                    bf = bruteforce(base, ctx["recursion_wordlist"], bulk, trusted)
                    tag(bf, "recursive-brute")
                    new = bf - resolved
                    resolved |= bf
                    nxt.extend(sorted(new))
                current = nxt
                depth += 1

    result["resolved"] = resolved
    result["unresolved"] = set(sources) - resolved
    good(f"{len(sources)} subdomains found total "
         f"({len(resolved)} live / {len(result['unresolved'])} dead) for {domain}")

    # Phase 5 - HTTP probing
    if not args.passive_only and not args.no_httpx:
        phase(f"public exposure - HTTP probing (httpx) - {domain}")
        result["http"] = probe_http(resolved)
        good(f"{len(result['http'])} live web services")

    # Virtual-host enumeration (uses the dead list)
    if args.vhost and not args.passive_only:
        dead = result["unresolved"]
        live_ips = ips_from_http(result["http"]) if result["http"] else ips_from_hosts(resolved)
        if not dead:
            info("no dead subdomains to use as vhost candidates")
        elif not live_ips:
            info("no live IPs to fuzz virtual hosts against")
        else:
            phase(f"virtual-host enumeration - {len(dead)} candidates x {len(live_ips)} IP(s)")
            result["vhosts"] = vhost_enum(dead, live_ips)
            good(f"{sum(len(v) for v in result['vhosts'].values())} virtual-host hit(s)")

    # Port scan (optional)
    if args.ports and not args.passive_only:
        ips = ips_from_http(result["http"]) if result["http"] else ips_from_hosts(resolved)
        if ips:
            phase(f"network exposure - port scan of {len(ips)} unique IP(s)")
            result["ports"] = port_scan(ips, args.full_ports)

    return result


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _found_set(r):
    return r.get("sources") or {n: {"passive"} for n in (r["resolved"] | r["unresolved"])}


def write_report(results, path, elapsed):
    out = []
    A = out.append
    A("#" * 80)
    A("# RECON REPORT")
    A(f"# Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    A(f"# Duration  : {int(elapsed)}s")
    A(f"# Targets   : {', '.join(r['target'] for r in results)}")
    A("#" * 80)
    A("")

    total_found = sum(len(_found_set(r)) for r in results)
    total_live = sum(len(r["resolved"]) for r in results)
    total_dead = sum(len(r["unresolved"]) for r in results)
    total_web = sum(len(r["http"]) for r in results)
    total_vh = sum(sum(len(v) for v in r["vhosts"].values()) for r in results)
    A(f"SUMMARY: {len(results)} target(s) | {total_found} subdomains found "
      f"({total_live} live / {total_dead} dead) | {total_web} live web services "
      f"| {total_vh} virtual-host hits")
    A("")

    for r in results:
        A("=" * 80)
        A(f" TARGET: {r['target']}")
        A("=" * 80)
        A("")

        A("--- ROOT DOMAINS ---")
        A(f"  registrant organization : {r['org'] or '(not found / redacted)'}")
        if r["extra_roots"]:
            A("  related root domains (verify scope before testing):")
            for d in sorted(r["extra_roots"]):
                A(f"    {d}")
        else:
            A("  related root domains    : none discovered")
        A("")

        sources = _found_set(r)
        resolved = r["resolved"]
        live = sorted(n for n in sources if n in resolved)
        dead = sorted(n for n in sources if n not in resolved)

        A(f"--- LIVE SUBDOMAINS [{len(live)}] ---")
        if live:
            width = min(max(len(n) for n in live), 55)
            for n in live:
                A(f"  {n.ljust(width)}  (found via: {', '.join(sorted(sources[n]))})")
        else:
            A("  (none)")
        A("")

        A(f"--- DEAD / NON-RESOLVING SUBDOMAINS [{len(dead)}]  (vhost candidates) ---")
        if dead:
            width = min(max(len(n) for n in dead), 55)
            for n in dead:
                A(f"  {n.ljust(width)}  (found via: {', '.join(sorted(sources[n]))})")
        else:
            A("  (none)")
        A("")

        if r["http"]:
            A(f"--- LIVE WEB SERVICES (httpx) [{len(r['http'])}] ---")
            for rec in sorted(r["http"], key=lambda x: str(x.get("url"))):
                A("  " + fmt_http(rec))
            A("")

        if r["vhosts"]:
            n = sum(len(v) for v in r["vhosts"].values())
            A(f"--- VIRTUAL HOSTS (ffuf, Host-header) [{n}] ---")
            for ip in sorted(r["vhosts"]):
                A(f"  {ip}")
                for host, scheme, status, length in r["vhosts"][ip]:
                    A(f"    {scheme}://{ip}  Host: {host}  [{status}] ({length} bytes)")
            A("")

        if r["ports"]:
            A("--- OPEN PORTS (nmap) ---")
            for ip in sorted(r["ports"]):
                A(f"  {ip}")
                if r["ports"][ip]:
                    for pl in r["ports"][ip]:
                        A(f"    {pl}")
                else:
                    A("    (no open ports found)")
            A("")

    try:
        with open(path, "w") as f:
            f.write("\n".join(out) + "\n")
    except OSError as e:
        err(f"failed to write report: {e}")


def write_companions(results, output_path):
    """Write machine-friendly one-per-line lists next to the main report."""
    base = os.path.splitext(output_path)[0]
    live = sorted({n for r in results for n in r["resolved"]})
    dead = sorted({n for r in results for n in r["unresolved"]})
    vhosts = sorted({f"{host}  {scheme}://{ip}  [{status}]"
                     for r in results for ip, hits in r["vhosts"].items()
                     for host, scheme, status, _ in hits})
    written = []
    for suffix, lines in (("_live.txt", live), ("_dead.txt", dead), ("_vhosts.txt", vhosts)):
        if suffix == "_vhosts.txt" and not lines:
            continue
        p = base + suffix
        try:
            with open(p, "w") as f:
                f.write("\n".join(lines) + ("\n" if lines else ""))
            written.append((p, len(lines)))
        except OSError as e:
            err(f"failed to write {p}: {e}")
    return written


def print_summary(results):
    print()
    print(C.w(C.BOLD, "-- Summary --"))
    for r in results:
        found = len(_found_set(r))
        ports = sum(1 for ip in r["ports"] if r["ports"][ip])
        vh = sum(len(v) for v in r["vhosts"].values())
        good(f"{r['target']}: {found} found "
             f"({len(r['resolved'])} live / {len(r['unresolved'])} dead), "
             f"{len(r['http'])} web, {vh} vhosts, {ports} host(s) with open ports")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Subdomain enumeration pipeline (passive + active discovery, "
                    "resolution with trusted re-validation, web probing, vhost enum).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python3 recon.py -t example.com -o output.txt\n"
               "  python3 recon.py -T targets.txt -o output.txt\n"
               "  python3 recon.py -t example.com -w big.txt -r resolvers.txt --recursive --vhost -o out.txt\n"
               "\nOnly test assets you are authorized to assess.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-t", "--target", help="single target domain")
    g.add_argument("-T", "--targets", help="file with target domains, one per line")

    p.add_argument("-o", "--output", default="recon_output.txt",
                   help="output report file (default: recon_output.txt); "
                        "companion _live/_dead/_vhosts lists are written alongside it")
    p.add_argument("-w", "--wordlist", help="wordlist for DNS brute-force (puredns)")
    p.add_argument("-r", "--resolvers", help="bulk DNS resolvers file for mass resolution")
    p.add_argument("--resolvers-trusted", dest="trusted_resolvers",
                   help="trusted resolvers file for re-validation (default: built-in)")
    p.add_argument("--threads", type=int, default=50,
                   help="concurrency for the native resolver fallback (default: 50)")

    p.add_argument("--passive-only", action="store_true",
                   help="passive enumeration + resolution only (no active probing of target)")
    p.add_argument("--no-bruteforce", action="store_true", help="skip DNS brute-force")
    p.add_argument("--no-permutations", action="store_true", help="skip alterx permutations")
    p.add_argument("--perm-rounds", type=int, default=2,
                   help="max permutation rounds, stops early on no new (default: 2)")
    p.add_argument("--recursive", action="store_true",
                   help="recursive brute-force into discovered subdomains (slow)")
    p.add_argument("--recursion-depth", type=int, default=1,
                   help="recursion levels when --recursive (default: 1)")
    p.add_argument("--recursion-wordlist", help="smaller wordlist for recursion")
    p.add_argument("--no-httpx", action="store_true", help="skip HTTP probing")
    p.add_argument("--vhost", action="store_true",
                   help="virtual-host enumeration: fuzz dead names as Host headers (needs ffuf)")
    p.add_argument("--ports", action="store_true", help="run nmap on live IPs (slow)")
    p.add_argument("--full-ports", action="store_true",
                   help="scan all 65535 ports instead of top 1000 (very slow)")
    p.add_argument("--amass", action="store_true", help="add amass passive source (slow)")
    p.add_argument("--github-token", help="GitHub token for github-subdomains (or $GITHUB_TOKEN)")
    p.add_argument("--expand-roots", action="store_true",
                   help="also run the full pipeline on root domains found via WHOIS")
    p.add_argument("--whoxy-key", help="whoxy.com API key for reverse WHOIS")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-v", "--verbose", action="store_true", help="show child-process stderr")
    return p.parse_args()


def load_targets(args):
    raw = []
    if args.target:
        raw = [args.target]
    else:
        try:
            with open(args.targets) as f:
                raw = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        except OSError as e:
            err(f"cannot read targets file: {e}")
            sys.exit(1)
    return [d for d in (clean_domain(x) for x in raw) if d]


def main():
    global VERBOSE
    args = parse_args()
    VERBOSE = args.verbose
    if args.no_color or not sys.stdout.isatty():
        C.disable()

    banner()

    targets = load_targets(args)
    if not targets:
        err("no targets provided")
        sys.exit(1)

    bulk, trusted, temps = setup_resolvers(args.resolvers, args.trusted_resolvers)
    wordlist = None
    recursion_wordlist = None
    if not args.passive_only and not args.no_bruteforce:
        wordlist = find_wordlist(args.wordlist)
        if args.recursive:
            recursion_wordlist = find_recursion_wordlist(args.recursion_wordlist, wordlist)

    ctx = {
        "bulk": bulk, "trusted": trusted,
        "wordlist": wordlist, "recursion_wordlist": recursion_wordlist,
        "github_token": args.github_token or os.environ.get("GITHUB_TOKEN"),
    }

    summarize_tools()

    queue = list(dict.fromkeys(targets))
    visited = set(queue)
    results = []
    start = time.time()
    try:
        while queue:
            results.append(run_pipeline(queue.pop(0), args, ctx, queue, visited))
    except KeyboardInterrupt:
        warn("interrupted - writing partial results ...")
    finally:
        for p in temps:
            try:
                os.remove(p)
            except OSError:
                pass

    if results:
        write_report(results, args.output, time.time() - start)
        good(f"report written to {args.output}")
        for p, n in write_companions(results, args.output):
            good(f"wrote {p} ({n} entries)")
        print_summary(results)
    else:
        warn("no results to write")


if __name__ == "__main__":
    main()
