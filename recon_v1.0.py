#!/usr/bin/env python3
"""
subrecon.py - subdomain enumeration & attack-surface mapping pipeline

Goal: enumerate *all* live subdomains of a target as completely and
accurately as possible, and separately surface the dead (non-resolving)
names so they can be reused for virtual-host enumeration.

Pipeline per target:
    root domain discovery (whois / whoxy)
      -> passive enumeration   (subfinder, crt.sh, Chaos, VirusTotal,
                                 certspotter, OTX, gau/waybackurls,
                                 assetfinder, github-subdomains, amass)
      -> DNS resolution        (puredns: bulk resolve + trusted re-validation,
                                 native threaded fallback)
      -> active discovery      (puredns bruteforce, alterx permutations,
                                 optional recursive bruteforce)
      -> TLS SAN harvesting     (read live certificates for non-CT names)
      -> ASN/CIDR expansion     (opt-in: org ranges -> reverse DNS)
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
import ipaddress
import random
import re
import shutil
import socket
import ssl
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
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


def chaos_source(domain, api_key):
    """
    ProjectDiscovery Chaos DNS dataset (native, no chaos binary needed).
        GET https://dns.projectdiscovery.io/dns/<domain>/subdomains
        Authorization: <api_key>
    Returns (set_of_hosts, status) where status is "ok" or "error".
    The API returns leaf prefixes ("www", "*.cfe", "1.dev"); we rebuild the
    full name and drop wildcard entries.
    """
    url = f"https://dns.projectdiscovery.io/dns/{urllib.parse.quote(domain)}/subdomains"
    try:
        req = urllib.request.Request(url, headers={
            "Authorization": api_key,
            "User-Agent": "recon.py/2.1",
            "Connection": "close",
        })
        with urllib.request.urlopen(req, timeout=40) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        warn(f"chaos query failed: {e}")
        return set(), "error"
    found = set()
    for prefix in data.get("subdomains", []):
        p = str(prefix).strip().lower().strip(".").lstrip("*.")
        if not p:
            continue
        full = f"{p}.{domain}"
        if "*" not in full and in_scope(full, domain):
            found.add(full)
    return found, "ok"


def virustotal_source(domain, api_key, max_pages=15, page_size=40, pause=1.0):
    """
    VirusTotal v3 passive-DNS subdomains (native, no key in argv - x-apikey
    header). The free public key is rate-limited (~4 req/min, ~500/day), so we
    cap pagination and stop cleanly on HTTP 429.
    Returns (set_of_hosts, status) in {"ok", "partial", "error"}.
    """
    found = set()
    url = (f"https://www.virustotal.com/api/v3/domains/"
           f"{urllib.parse.quote(domain)}/subdomains?limit={page_size}")
    status = "ok"
    for _ in range(max_pages):
        try:
            req = urllib.request.Request(url, headers={
                "x-apikey": api_key,
                "User-Agent": "recon.py/2.1",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                warn("virustotal rate limit hit (429) - stopping, keeping partial results")
                status = "partial" if found else "error"
            else:
                warn(f"virustotal query failed: HTTP {e.code}")
                status = "partial" if found else "error"
            break
        except Exception as e:
            warn(f"virustotal query failed: {e}")
            status = "partial" if found else "error"
            break
        for item in data.get("data", []):
            n = str(item.get("id", "")).strip().lower().strip(".")
            if n and in_scope(n, domain):
                found.add(n)
        nxt = (data.get("links") or {}).get("next")
        if not nxt:
            break
        url = nxt
        time.sleep(pause)
    return found, status


def certspotter_source(domain, api_key=None, max_pages=10, retries=3):
    """
    Cert Spotter (SSLMate) CT search - native, works without a key (free tier is
    rate-limited; an optional token raises the limit). Paginates with the
    `after` cursor until an empty array, with retry/backoff per page so a
    transient 5xx/429/network blip doesn't drop the whole source. Returns
    (set, status).
    """
    found = set()
    after = None
    status = "ok"
    base = (f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(domain)}"
            f"&include_subdomains=true&expand=dns_names")
    headers = {"User-Agent": "recon.py/2.1", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    for _ in range(max_pages):
        url = base + (f"&after={urllib.parse.quote(str(after))}" if after else "")
        data = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                break
            except urllib.error.HTTPError as e:
                note = "rate limit (429)" if e.code == 429 else f"HTTP {e.code}"
                if attempt < retries - 1:
                    time.sleep(2 * (attempt + 1))
                    continue
                warn(f"certspotter query failed after {retries} tries: {note}")
                status = "partial" if found else "error"
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(2 * (attempt + 1))
                    continue
                warn(f"certspotter query failed after {retries} tries: {e}")
                status = "partial" if found else "error"
        if data is None:                   # all retries exhausted for this page
            break
        if not data:                       # empty array -> no more pages
            break
        for issuance in data:
            for n in issuance.get("dns_names", []):
                n = str(n).strip().lower().strip(".").lstrip("*.")
                if n and in_scope(n, domain):
                    found.add(n)
        after = data[-1].get("id")
        if not after:
            break
    return found, status


def otx_source(domain, api_key=None):
    """
    AlienVault OTX passive DNS - native, works without a key (an optional key is
    sent as X-OTX-API-KEY). Returns (set, status).
    """
    url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
           f"{urllib.parse.quote(domain)}/passive_dns")
    headers = {"User-Agent": "recon.py/2.1", "Accept": "application/json"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        warn(f"otx query failed: {e}")
        return set(), "error"
    found = set()
    for rec in data.get("passive_dns", []):
        h = str(rec.get("hostname", "")).strip().lower().strip(".").lstrip("*.")
        if h and in_scope(h, domain):
            found.add(h)
    return found, "ok"


def passive_enum(domain, amass=False, github_token=None, keys=None):
    """
    Query every available passive source.

    Returns (found, stats):
        found = {host: set(source_tags)}
        stats = {source: {"status": ..., "total": n, "unique": n}}
    where status is one of: ok, partial, no-key, no-tool, error. `total` is how
    many in-scope names the source returned; `unique` is how many ONLY it found.
    """
    keys = keys or {}
    found = {}
    stats = {}

    def add(names, src, status="ok"):
        cleaned = set()
        for n in (names or []):
            n = n.strip().lower().strip(".")
            if n and in_scope(n, domain):
                cleaned.add(n)
        new = [n for n in cleaned if n not in found]
        for n in cleaned:
            found.setdefault(n, set()).add(src)
        stats[src] = {"status": status}
        if new:
            good(f"{src}: +{len(new)} new")
            for n in sorted(new):
                print(f"    {n}")
        elif status in ("ok", "partial"):
            info(f"{src}: {len(cleaned)} found, 0 new")

    def skip(src, status):
        stats[src] = {"status": status}

    if have("subfinder"):
        add(run_stream(["subfinder", "-d", domain, "-silent"], quiet=True) or [], "subfinder")
    else:
        warn("subfinder not found - skipping (github.com/projectdiscovery/subfinder)")
        skip("subfinder", "no-tool")

    info("querying crt.sh (certificate transparency) ...")
    add(crtsh(domain), "crtsh")

    if keys.get("chaos"):
        info("querying Chaos (projectdiscovery dataset) ...")
        names, st = chaos_source(domain, keys["chaos"])
        add(names, "chaos", status=st)
    else:
        info("chaos: no API key - skipping (set CHAOS_KEY or add to config)")
        skip("chaos", "no-key")

    if keys.get("virustotal"):
        info("querying VirusTotal (passive DNS) ...")
        names, st = virustotal_source(domain, keys["virustotal"])
        add(names, "virustotal", status=st)
    else:
        info("virustotal: no API key - skipping (set VT_API_KEY or add to config)")
        skip("virustotal", "no-key")

    info("querying certspotter (certificate transparency) ...")
    names, st = certspotter_source(domain, keys.get("certspotter"))
    add(names, "certspotter", status=st)

    info("querying OTX (alienvault passive DNS) ...")
    names, st = otx_source(domain, keys.get("otx"))
    add(names, "otx", status=st)

    if have("gau"):
        add(hosts_from_urls(run_stream(["gau", "--subs", domain], quiet=True) or [], domain),
            "wayback")
    elif have("waybackurls"):
        add(hosts_from_urls(run_stream(["waybackurls"], stdin_data=domain + "\n", quiet=True) or [],
                            domain), "wayback")
    else:
        info("gau/waybackurls not found - skipping URL-archive source")
        skip("wayback", "no-tool")

    if have("assetfinder"):
        add(run_stream(["assetfinder", "--subs-only", domain], quiet=True) or [], "assetfinder")
    else:
        skip("assetfinder", "no-tool")

    if have("github-subdomains"):
        if github_token:
            add(run_stream(["github-subdomains", "-d", domain, "-t", github_token], quiet=True) or [],
                "github")
        else:
            info("github-subdomains present but no token - set --github-token or $GITHUB_TOKEN")
            skip("github", "no-key")
    else:
        skip("github", "no-tool")

    if amass and have("amass"):
        info("amass passive (this can be slow) ...")
        add(run_stream(["amass", "enum", "-passive", "-d", domain, "-timeout", "8"], quiet=True) or [],
            "amass")
    elif amass:
        warn("amass not found - skipping")
        skip("amass", "no-tool")

    # Authoritative, order-independent per-source coverage.
    for src, st in stats.items():
        if st["status"] in ("ok", "partial"):
            st["total"] = sum(1 for tags in found.values() if src in tags)
            st["unique"] = sum(1 for tags in found.values() if tags == {src})

    return found, stats


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
# Subdomain takeover detection
# --------------------------------------------------------------------------- #
# Curated fingerprints (subset of can-i-take-over-xyz). A match on `cnames`
# plus the `fingerprint` string in the body is a high-confidence takeover.
# All findings still require manual verification before reporting.
TAKEOVER_FINGERPRINTS = [
    {"service": "GitHub Pages", "cnames": ["github.io"],
     "fingerprint": "There isn't a GitHub Pages site here"},
    {"service": "AWS S3", "cnames": ["amazonaws.com"],
     "fingerprint": "The specified bucket does not exist"},
    {"service": "Heroku", "cnames": ["herokuapp.com", "herokudns.com", "herokussl.com"],
     "fingerprint": "No such app"},
    {"service": "Shopify", "cnames": ["myshopify.com"],
     "fingerprint": "Sorry, this shop is currently unavailable"},
    {"service": "Fastly", "cnames": ["fastly.net"],
     "fingerprint": "Fastly error: unknown domain"},
    {"service": "Tumblr", "cnames": ["domains.tumblr.com"],
     "fingerprint": "Whatever you were looking for doesn't currently exist at this address"},
    {"service": "Surge.sh", "cnames": ["surge.sh"],
     "fingerprint": "project not found"},
    {"service": "Bitbucket", "cnames": ["bitbucket.io"],
     "fingerprint": "Repository not found"},
    {"service": "Ghost", "cnames": ["ghost.io"],
     "fingerprint": "The thing you were looking for is no longer here"},
    {"service": "Pantheon", "cnames": ["pantheonsite.io"],
     "fingerprint": "The gods are wise, but do not know of the site which you seek"},
    {"service": "Webflow", "cnames": ["proxy-ssl.webflow.com", "webflow.io"],
     "fingerprint": "The page you are looking for doesn't exist or has been moved"},
    {"service": "WordPress", "cnames": ["wordpress.com"],
     "fingerprint": "Do you want to register"},
    {"service": "Zendesk", "cnames": ["zendesk.com"],
     "fingerprint": "Help Center Closed"},
    {"service": "Help Scout", "cnames": ["helpscoutdocs.com"],
     "fingerprint": "No settings were found for this company"},
    {"service": "Cargo", "cnames": ["cargocollective.com"],
     "fingerprint": "If you're moving your domain away from Cargo"},
    {"service": "Readme.io", "cnames": ["readme.io"],
     "fingerprint": "Project doesnt exist... yet!"},
    {"service": "Unbounce", "cnames": ["unbouncepages.com"],
     "fingerprint": "The requested URL was not found on this server"},
    {"service": "Netlify", "cnames": ["netlify.app", "netlify.com"],
     "fingerprint": "Not Found - Request ID"},
]

_NOVERIFY_SSL = ssl.create_default_context()
_NOVERIFY_SSL.check_hostname = False
_NOVERIFY_SSL.verify_mode = ssl.CERT_NONE


def _has_dnspython():
    try:
        import dns.resolver  # noqa: F401
        return True
    except ImportError:
        return False


def resolve_cname(host):
    """Return the CNAME target for host (dnspython > dig > None)."""
    try:
        import dns.resolver  # type: ignore
        try:
            ans = dns.resolver.resolve(host, "CNAME")
            return str(ans[0].target).rstrip(".").lower()
        except Exception:
            return None
    except ImportError:
        pass
    if have("dig"):
        for l in (run_stream(["dig", "+short", "CNAME", host], quiet=True) or []):
            l = l.strip().rstrip(".").lower()
            if l:
                return l
    return None


def http_get(url, timeout=8):
    """Native GET returning (status, body[:64k]) or (None, '') on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "recon.py/2.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=_NOVERIFY_SSL) as resp:
            return resp.status, resp.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(65536).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return None, ""


def takeover_scan(http_results, dead_hosts, threads=30):
    """
    Detect dangling subdomains pointing to unclaimed third-party services.

    Candidates = live hosts whose CNAME (from httpx) matches a known service,
    plus dead hosts whose CNAME we can resolve. A body-fingerprint match is
    'confirmed'; a CNAME-only match is 'potential' (verify manually).
    Returns [{host, cname, service, confidence}].
    """
    candidates = {}

    for r in http_results:
        cn = r.get("cname") or []
        cn = cn[0] if isinstance(cn, list) and cn else (cn if isinstance(cn, str) else "")
        host = urllib.parse.urlsplit(r.get("url", "")).hostname or ""
        if cn and host:
            candidates[host] = cn.rstrip(".").lower()

    dead_list = sorted(h for h in dead_hosts if h not in candidates)
    if dead_list:
        if _has_dnspython() or have("dig"):
            with ThreadPoolExecutor(max_workers=threads) as ex:
                for h, c in zip(dead_list, ex.map(resolve_cname, dead_list)):
                    if c:
                        candidates[h] = c
        else:
            info("no CNAME resolver (dnspython/dig) - takeover check limited to live hosts")

    findings = []
    for host, cname in candidates.items():
        fp = next((f for f in TAKEOVER_FINGERPRINTS
                   if any(p in cname for p in f["cnames"])), None)
        if not fp:
            continue
        confidence = "potential"
        for scheme in ("https", "http"):
            _, body = http_get(f"{scheme}://{host}/")
            if body and fp["fingerprint"].lower() in body.lower():
                confidence = "confirmed"
                break
        findings.append({"host": host, "cname": cname,
                         "service": fp["service"], "confidence": confidence})
        colour = C.RED if confidence == "confirmed" else C.YELLOW
        print(C.w(colour, f"    [{confidence}] {host} -> {cname}  ({fp['service']})"))
    return findings


# --------------------------------------------------------------------------- #
# Monitoring / diff + structured (JSON) output
# --------------------------------------------------------------------------- #
def result_to_dict(r):
    """Serialize a result (sets -> sorted lists) for JSON / state."""
    return {
        "target": r["target"],
        "org": r["org"],
        "extra_roots": sorted(r["extra_roots"]),
        "live": sorted(r["resolved"]),
        "dead": sorted(r["unresolved"]),
        "sources": {k: sorted(v) for k, v in r.get("sources", {}).items()},
        "http": r["http"],
        "vhosts": {ip: [list(t) for t in hits] for ip, hits in r["vhosts"].items()},
        "takeover": r.get("takeover", []),
        "ports": r["ports"],
        "source_stats": r.get("source_stats", {}),
        "diff": r.get("diff", {}),
    }


def write_json(results, output_path):
    path = os.path.splitext(output_path)[0] + ".json"
    data = {"generated": datetime.now().isoformat(timespec="seconds"),
            "targets": [result_to_dict(r) for r in results]}
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return path
    except OSError as e:
        err(f"failed to write JSON: {e}")
        return None


def _state_path(state_dir, target):
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    return os.path.join(os.path.expanduser(state_dir), safe + ".json")


def load_state(state_dir, target):
    try:
        with open(_state_path(state_dir, target)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_state(state_dir, target, result):
    d = os.path.expanduser(state_dir)
    try:
        os.makedirs(d, exist_ok=True)
        with open(_state_path(state_dir, target), "w") as f:
            json.dump(result_to_dict(result), f, indent=2)
    except OSError as e:
        warn(f"could not save monitoring state for {target}: {e}")


def diff_results(prev, result):
    if not prev:
        return {"first_run": True, "new_live": [], "gone_live": [], "new_dead": []}
    prev_live = set(prev.get("live", []))
    prev_dead = set(prev.get("dead", []))
    return {
        "first_run": False,
        "new_live": sorted(result["resolved"] - prev_live),
        "gone_live": sorted(prev_live - result["resolved"]),
        "new_dead": sorted(result["unresolved"] - prev_dead),
    }


def notify_webhook(url, message):
    payload = json.dumps({"text": message, "content": message}).encode()
    try:
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=15)
        good("webhook notification sent")
    except Exception as e:
        warn(f"webhook notify failed: {e}")


def build_diff_message(results):
    lines = []
    for r in results:
        nl = (r.get("diff") or {}).get("new_live", [])
        if nl:
            lines.append(f"[recon] {r['target']}: {len(nl)} new live subdomain(s)")
            lines += [f"  + {h}" for h in nl[:25]]
            if len(nl) > 25:
                lines.append(f"  ... and {len(nl) - 25} more")
    return "\n".join(lines)


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
# API keys / config
# --------------------------------------------------------------------------- #
# Canonical source name -> environment variables checked, in order. The same
# names work as KEY=value lines in the config file. Env vars take precedence.
KEY_ENV = {
    "virustotal": ["VT_API_KEY", "VIRUSTOTAL_API_KEY", "VIRUSTOTAL_KEY"],
    "chaos": ["CHAOS_KEY", "PDCP_API_KEY", "CHAOS_API_KEY"],
    "certspotter": ["CERTSPOTTER_API_KEY", "CERTSPOTTER_KEY"],
    "otx": ["OTX_API_KEY", "OTX_KEY"],
}
DEFAULT_KEY_CONFIG = "~/.recon/config"


def load_keys(config_path):
    """
    Load API keys for native keyed sources (VirusTotal, Chaos).

    Precedence: environment variable > config file. The config file is a simple
    list of `KEY=value` lines ('#' comments allowed), e.g.

        VT_API_KEY=xxxxxxxx
        CHAOS_KEY=yyyyyyyy

    Returns {canonical_source: key_or_None}. Key VALUES are never logged - only
    which source was loaded and from where (env vs config).
    """
    file_vals = {}
    path = os.path.expanduser(config_path or DEFAULT_KEY_CONFIG)
    if os.path.isfile(path):
        try:
            with open(path) as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    v = v.strip().strip('"').strip("'")
                    if v:
                        file_vals[k.strip().upper()] = v
        except OSError as e:
            warn(f"could not read key config {path}: {e}")

    keys = {}
    loaded = []
    for canon, names in KEY_ENV.items():
        val, origin = None, None
        for n in names:
            if os.environ.get(n):
                val, origin = os.environ[n], f"env:{n}"
                break
        if not val:
            for n in names:
                if file_vals.get(n):
                    val, origin = file_vals[n], "config"
                    break
        keys[canon] = val
        if val:
            loaded.append(f"{canon} ({origin})")

    if loaded:
        info("API keys loaded: " + ", ".join(loaded))
    else:
        hint = ", ".join(ns[0] for ns in KEY_ENV.values())
        info(f"no API keys found - set {hint} in env or {path} (keyed sources skipped)")
    return keys


def print_source_coverage(stats):
    """Per-source contribution summary for the passive phase (console)."""
    if not stats:
        return
    print(C.w(C.BOLD, "  -- passive source coverage --"))
    label = {"no-key": "no API key", "no-tool": "not installed", "error": "error"}
    order = sorted(stats.items(), key=lambda kv: (-kv[1].get("total", 0), kv[0]))
    for src, st in order:
        status = st.get("status", "ok")
        if status in ("ok", "partial"):
            total, uniq = st.get("total", 0), st.get("unique", 0)
            tag = "  (partial / rate-limited)" if status == "partial" else ""
            line = f"    {src:<14} {total:>5} found  {uniq:>4} unique{tag}"
            print(C.w(C.GREEN if total else C.GREY, line))
        else:
            print(C.w(C.GREY, f"    {src:<14}   (skipped: {label.get(status, status)})"))


# --------------------------------------------------------------------------- #
# TLS SAN harvesting (native, stdlib only) - names from live certificates
# --------------------------------------------------------------------------- #
_SAN_OID = b"\x06\x03\x55\x1d\x11"      # DER encoding of OID 2.5.29.17 (subjectAltName)


def _der_len(buf, i):
    """Read a DER length field at offset i. Returns (length, next_offset)."""
    n = buf[i]
    i += 1
    if n < 0x80:
        return n, i
    num = n & 0x7f
    return int.from_bytes(buf[i:i + num], "big"), i + num


def _san_from_der(der):
    """
    Extract dNSName entries from the subjectAltName extension of a DER-encoded
    certificate with a minimal TLV walk (no external deps). Best-effort: returns
    a set of hostnames (lowercased, wildcard prefixes stripped).
    """
    names = set()
    pos = der.find(_SAN_OID)
    if pos < 0:
        return names
    i = pos + len(_SAN_OID)
    if i < len(der) and der[i] == 0x01:          # optional critical BOOLEAN
        ln, i = _der_len(der, i + 1)
        i += ln
    if i >= len(der) or der[i] != 0x04:          # extnValue OCTET STRING
        return names
    _, i = _der_len(der, i + 1)
    if i >= len(der) or der[i] != 0x30:          # GeneralNames SEQUENCE
        return names
    seq_len, i = _der_len(der, i + 1)
    end = min(i + seq_len, len(der))
    while i < end:
        tag = der[i]
        i += 1
        ln, i = _der_len(der, i)
        val = der[i:i + ln]
        i += ln
        if tag == 0x82:                          # [2] dNSName (IA5String)
            try:
                h = val.decode("ascii").strip().lower().strip(".").lstrip("*.")
            except UnicodeDecodeError:
                continue
            if h:
                names.add(h)
    return names


def _is_ip_literal(s):
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        return False


def _cert_san(host, port=443, timeout=8):
    """Connect over TLS, grab the peer certificate (DER), return its SAN names."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    server_name = None if _is_ip_literal(host) else host
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                der = ssock.getpeercert(binary_form=True)
        return _san_from_der(der) if der else set()
    except Exception:
        return set()


def tls_san_scan(hosts, domain, threads=50, port=443):
    """
    Connect to each live host on TLS, read its certificate's SANs, and return
    the in-scope hostnames found - including names that never appear in CT logs
    (internal/self-signed certs, certs on IPs, freshly issued certs).
    """
    hosts = [h for h in set(hosts) if h]
    found = set()
    if not hosts:
        return found
    info(f"reading certificates from {len(hosts)} live host(s) ...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_cert_san, h, port) for h in hosts]
        for fut in as_completed(futs):
            for n in fut.result():
                if in_scope(n, domain):
                    found.add(n)
    return found


# --------------------------------------------------------------------------- #
# ASN / CIDR expansion (opt-in) - IP-first discovery via reverse DNS
# --------------------------------------------------------------------------- #
# Holders we never expand: shared cloud/CDN ranges yield noise, not the org.
CLOUD_ASN_KEYWORDS = (
    "cloudflare", "amazon", "aws", "google", "microsoft", "azure", "akamai",
    "fastly", "oracle", "digitalocean", "linode", "ovh", "hetzner", "vultr",
    "godaddy", "namecheap", "incapsula", "imperva", "sucuri", "stackpath",
    "automattic", "shopify", "squarespace", "wix", "alibaba", "tencent",
    "leaseweb", "contabo", "scaleway", "gcore", "bunny", "cloudfront",
)


def _ripe_json(datacall, resource):
    """Query a RIPEstat data call (free, no key). Returns the 'data' object."""
    url = (f"https://stat.ripe.net/data/{datacall}/data.json"
           f"?resource={urllib.parse.quote(str(resource))}&sourceapp=recon-py")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "recon.py/2.1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", "replace")).get("data", {})
    except Exception as e:
        warn(f"ripestat {datacall} failed for {resource}: {e}")
        return {}


def asn_for_ip(ip):
    """Announcing ASN(s) for an IP (RIPEstat network-info)."""
    return [str(a) for a in (_ripe_json("network-info", ip).get("asns") or [])]


def asn_holder(asn):
    """Holder/org name for an ASN (RIPEstat as-overview) - used for cloud filter."""
    return (_ripe_json("as-overview", f"AS{asn}").get("holder") or "").strip()


def asn_prefixes(asn):
    """IPv4 CIDR prefixes announced by an ASN (RIPEstat announced-prefixes)."""
    out = []
    for p in _ripe_json("announced-prefixes", f"AS{asn}").get("prefixes", []):
        pref = p.get("prefix", "")
        if pref and ":" not in pref:             # IPv4 only
            out.append(pref)
    return out


def reverse_dns(ips, threads=50):
    """PTR lookups for a set of IPs. Returns {ip: hostname}."""
    out = {}
    socket.setdefaulttimeout(4)

    def ptr(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0].strip(".").lower()
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return ip, None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for ip, name in ex.map(ptr, list(ips)):
            if name:
                out[ip] = name
    return out


def asn_expand(seed_ips, domain, threads=50, max_ips=8192):
    """
    IP-first discovery. From known live IPs, find the org's ASNs, expand their
    announced IPv4 prefixes, reverse-DNS the addresses, and return in-scope
    hostnames that name enumeration would miss. Skips shared cloud/CDN ASNs and
    caps the number of addresses probed.
    """
    seed_ips = [ip for ip in set(seed_ips) if ip and ":" not in ip]
    if not seed_ips:
        info("no seed IPs for ASN expansion")
        return set()

    asns = set()
    for ip in seed_ips:
        asns.update(asn_for_ip(ip))
    if not asns:
        info("no ASNs resolved for seed IPs")
        return set()

    keep = []
    for a in sorted(asns):
        holder = asn_holder(a)
        if any(k in holder.lower() for k in CLOUD_ASN_KEYWORDS):
            info(f"skipping AS{a} ({holder or 'unknown'}) - shared cloud/CDN range")
            continue
        keep.append((a, holder))
    if not keep:
        info("all candidate ASNs are shared cloud/CDN - nothing to expand "
             "(target has no own IP space)")
        return set()

    cidrs = []
    for a, holder in keep:
        good(f"expanding AS{a} ({holder or 'unknown holder'})")
        cidrs.extend(asn_prefixes(a))
    cidrs = sorted(set(cidrs),
                   key=lambda c: ipaddress.ip_network(c, strict=False).num_addresses)

    targets = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        for ip in net.hosts():
            targets.append(str(ip))
            if len(targets) >= max_ips:
                break
        if len(targets) >= max_ips:
            warn(f"ASN address cap ({max_ips}) reached - stopping (raise with --asn-max-ips)")
            break
    if not targets:
        return set()

    info(f"reverse-DNS on {len(targets)} address(es) across {len(cidrs)} prefix(es) ...")
    ptr = reverse_dns(targets, threads)
    found = {name for name in ptr.values() if in_scope(name, domain)}
    good(f"{len(found)} in-scope name(s) from reverse DNS ({len(ptr)} PTR records seen)")
    return found


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
def run_pipeline(domain, args, ctx, queue, visited):
    domain = clean_domain(domain)
    bulk, trusted = ctx["bulk"], ctx["trusted"]
    result = {
        "target": domain, "org": None, "extra_roots": set(),
        "resolved": set(), "unresolved": set(), "sources": {},
        "http": [], "vhosts": {}, "ports": {}, "takeover": [], "diff": {},
        "source_stats": {},
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
    passive_map, src_stats = passive_enum(domain, amass=args.amass,
                                          github_token=ctx["github_token"], keys=ctx["keys"])
    result["source_stats"] = src_stats
    passive_map.setdefault(domain, set()).add("apex")
    for h, srcs in passive_map.items():
        sources.setdefault(h, set()).update(srcs)
    good(f"{len(passive_map)} unique names from passive sources")
    print_source_coverage(src_stats)

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

    # Phase 3d - TLS SAN harvest from live certificates (catches non-CT names)
    if not args.passive_only and not args.no_tls_san and resolved:
        phase(f"TLS SAN harvesting - {domain}")
        san_names = tls_san_scan(resolved, domain, threads=args.threads)
        if san_names:
            tag(san_names, "tls-san")
            new = san_names - resolved
            if new:
                live = resolve_hosts(new, bulk, trusted, args.threads)
                resolved |= live
                good(f"{len(san_names)} SAN name(s); {len(live)} newly live")
            else:
                good(f"{len(san_names)} SAN name(s); none new")
        else:
            good("no SAN names harvested")

    # Phase 3e - ASN / CIDR expansion + reverse DNS (opt-in; org-owned ranges)
    if not args.passive_only and args.asn:
        phase(f"ASN / CIDR expansion - {domain}")
        seed_ips = ips_from_hosts(resolved)
        asn_names = asn_expand(seed_ips, domain, threads=args.threads, max_ips=args.asn_max_ips)
        if asn_names:
            tag(asn_names, "asn-ptr")
            new = asn_names - resolved
            if new:
                live = resolve_hosts(new, bulk, trusted, args.threads)
                resolved |= live
                good(f"{len(asn_names)} in-scope name(s); {len(live)} newly live")
            else:
                good(f"{len(asn_names)} in-scope name(s); none new")

    result["resolved"] = resolved
    result["unresolved"] = set(sources) - resolved
    good(f"{len(sources)} subdomains found total "
         f"({len(resolved)} live / {len(result['unresolved'])} dead) for {domain}")

    # Phase 5 - HTTP probing
    if not args.passive_only and not args.no_httpx:
        phase(f"public exposure - HTTP probing (httpx) - {domain}")
        result["http"] = probe_http(resolved)
        good(f"{len(result['http'])} live web services")

    # Subdomain takeover detection (uses httpx CNAMEs + dangling dead-host CNAMEs)
    if not args.no_takeover and not args.passive_only:
        phase(f"subdomain takeover detection - {domain}")
        result["takeover"] = takeover_scan(result["http"], result["unresolved"], args.threads)
        good(f"{len(result['takeover'])} takeover candidate(s)")

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
    total_to = sum(len(r.get("takeover", [])) for r in results)
    total_new = sum(len((r.get("diff") or {}).get("new_live", [])) for r in results)
    A(f"SUMMARY: {len(results)} target(s) | {total_found} subdomains found "
      f"({total_live} live / {total_dead} dead) | {total_web} live web services "
      f"| {total_vh} vhost hits | {total_to} takeover candidates"
      + (f" | {total_new} NEW since last run" if total_new else ""))
    A("")

    for r in results:
        A("=" * 80)
        A(f" TARGET: {r['target']}")
        A("=" * 80)
        A("")

        d = r.get("diff") or {}
        if d.get("first_run"):
            A("--- CHANGES SINCE LAST RUN ---")
            A("  (first run - baseline saved)")
            A("")
        elif d:
            nl, gl = d.get("new_live", []), d.get("gone_live", [])
            if nl or gl:
                A("--- CHANGES SINCE LAST RUN ---")
                A(f"  new live [{len(nl)}]:")
                for h in nl:
                    A(f"    + {h}")
                if gl:
                    A(f"  no longer live [{len(gl)}]:")
                    for h in gl:
                        A(f"    - {h}")
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

        st = r.get("source_stats") or {}
        if st:
            A("--- PASSIVE SOURCE COVERAGE ---")
            label = {"no-key": "no API key", "no-tool": "not installed", "error": "error"}
            for src, s in sorted(st.items(), key=lambda kv: (-(kv[1].get("total", 0)), kv[0])):
                status = s.get("status", "ok")
                if status in ("ok", "partial"):
                    tag = "  (partial / rate-limited)" if status == "partial" else ""
                    A(f"  {src:<14} {s.get('total', 0):>5} found, "
                      f"{s.get('unique', 0):>4} unique{tag}")
                else:
                    A(f"  {src:<14}   (skipped: {label.get(status, status)})")
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

        if r.get("takeover"):
            A(f"--- SUBDOMAIN TAKEOVER CANDIDATES [{len(r['takeover'])}]  (verify manually) ---")
            for t in sorted(r["takeover"], key=lambda x: (x["confidence"] != "confirmed", x["host"])):
                A(f"  [{t['confidence']}]  {t['host']}  ->  {t['cname']}  ({t['service']})")
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
    takeover = sorted({f"[{t['confidence']}]  {t['host']} -> {t['cname']}  ({t['service']})"
                       for r in results for t in r.get("takeover", [])})
    written = []
    optional = {"_vhosts.txt", "_takeover.txt"}
    for suffix, lines in (("_live.txt", live), ("_dead.txt", dead),
                          ("_vhosts.txt", vhosts), ("_takeover.txt", takeover)):
        if suffix in optional and not lines:
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
        to = len(r.get("takeover", []))
        nl = len((r.get("diff") or {}).get("new_live", []))
        extra = f", {nl} NEW" if nl else ""
        good(f"{r['target']}: {found} found "
             f"({len(r['resolved'])} live / {len(r['unresolved'])} dead), "
             f"{len(r['http'])} web, {vh} vhosts, {to} takeover, {ports} ports{extra}")


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
    p.add_argument("--config", default=DEFAULT_KEY_CONFIG,
                   help="API key file with KEY=value lines (VT_API_KEY, CHAOS_KEY); "
                        "environment variables override it (default: ~/.recon/config)")
    p.add_argument("--expand-roots", action="store_true",
                   help="also run the full pipeline on root domains found via WHOIS")
    p.add_argument("--whoxy-key", help="whoxy.com API key for reverse WHOIS")
    p.add_argument("--no-takeover", action="store_true",
                   help="disable subdomain takeover detection (on by default)")
    p.add_argument("--no-tls-san", action="store_true",
                   help="disable TLS SAN harvesting from live certificates (on by default)")
    p.add_argument("--asn", action="store_true",
                   help="ASN/CIDR expansion + reverse DNS (opt-in; expands only org-owned "
                        "ranges, skips shared cloud/CDN ASNs)")
    p.add_argument("--asn-max-ips", type=int, default=8192,
                   help="max addresses to reverse-DNS during ASN expansion (default: 8192)")
    p.add_argument("--monitor", action="store_true",
                   help="diff against the previous run, save a baseline, highlight new assets")
    p.add_argument("--state-dir", default="~/.recon/state",
                   help="where monitoring baselines are stored (default: ~/.recon/state)")
    p.add_argument("--notify-webhook", dest="notify_webhook",
                   help="Slack/Discord webhook URL for new-asset alerts (use with --monitor)")
    p.add_argument("--json", action="store_true",
                   help="also write structured results to <output>.json")
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

    keys = load_keys(args.config)

    ctx = {
        "bulk": bulk, "trusted": trusted,
        "wordlist": wordlist, "recursion_wordlist": recursion_wordlist,
        "github_token": args.github_token or os.environ.get("GITHUB_TOKEN"),
        "keys": keys,
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
        if args.monitor:
            for r in results:
                prev = load_state(args.state_dir, r["target"])
                r["diff"] = diff_results(prev, r)
                save_state(args.state_dir, r["target"], r)
            if args.notify_webhook:
                msg = build_diff_message(results)
                if msg:
                    notify_webhook(args.notify_webhook, msg)

        write_report(results, args.output, time.time() - start)
        good(f"report written to {args.output}")
        if args.json:
            jp = write_json(results, args.output)
            if jp:
                good(f"wrote {jp}")
        for p, n in write_companions(results, args.output):
            good(f"wrote {p} ({n} entries)")
        print_summary(results)
    else:
        warn("no results to write")


if __name__ == "__main__":
    main()
