#!/usr/bin/env python3
"""
recon.py - bug bounty reconnaissance pipeline

Turns a company domain (or a list of domains) into a map of the external
attack surface: subdomains (passive + active), resolved hosts, live web
services, and - optionally - open ports.

Pipeline per target:
    root domain discovery (whois / whoxy)
        -> passive enumeration (subfinder + crt.sh)
        -> DNS resolution (puredns, with a native fallback)
        -> active discovery (puredns bruteforce + alterx permutations)
        -> HTTP probing (httpx)
        -> [optional] port scan (nmap)

It wraps the standard tooling and degrades gracefully: if a binary is
missing the matching phase is skipped, and crt.sh + a threaded resolver
keep it producing useful output even with none of the Go tools installed.

Usage:
    python3 recon.py -t example.com -o output.txt
    python3 recon.py -T targets.txt -o output.txt

Only test assets you are explicitly authorized to assess.
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


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
    print(C.w(C.BOLD + C.CYAN, "recon.py - attack surface mapping pipeline"))


# --------------------------------------------------------------------------- #
# Generic process / network helpers
# --------------------------------------------------------------------------- #
def have(tool):
    return shutil.which(tool) is not None


def run_stream(cmd, stdin_data=None, quiet=False, indent="    "):
    """
    Run `cmd`, stream stdout live (unless quiet), and return the list of
    stdout lines. stderr is discarded. Returns None if the binary is missing.

    stdin is fed from a writer thread so large inputs cannot deadlock against
    a filling stdout pipe.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
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
    except Exception as e:  # network / json / http
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
# Phase 1 - passive enumeration
# --------------------------------------------------------------------------- #
def crtsh(domain, timeout=40):
    """Native certificate-transparency lookup (no API key, always available)."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    found = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "recon.py/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        warn(f"crt.sh query failed: {e}")
        return found
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and in_scope(name, domain):
                found.add(name)
    return found


def passive_enum(domain):
    found = set()
    if have("subfinder"):
        lines = run_stream(["subfinder", "-d", domain, "-silent"])
        for l in (lines or []):
            l = l.strip().lower()
            if in_scope(l, domain):
                found.add(l)
    else:
        warn("subfinder not found - skipping (github.com/projectdiscovery/subfinder)")

    info("querying crt.sh (certificate transparency) ...")
    cs = crtsh(domain)
    for n in sorted(cs - found):
        print(f"    {n}")
    found |= cs
    return found


# --------------------------------------------------------------------------- #
# Phase 2/3 - resolution + active discovery
# --------------------------------------------------------------------------- #
def resolve_python(hosts, threads=50):
    """Threaded socket fallback used when puredns is unavailable."""
    resolved = set()
    socket.setdefaulttimeout(4)

    def check(h):
        try:
            socket.getaddrinfo(h, None)
            return h
        except (socket.gaierror, socket.timeout, UnicodeError, OSError):
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(check, h): h for h in hosts}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                print(f"    {r}")
                resolved.add(r)
    return resolved


def resolve_hosts(hosts, resolvers_file, threads=50):
    hosts = sorted(set(hosts))
    if not hosts:
        return set()
    if have("puredns"):
        cmd = ["puredns", "resolve", "-q"]
        if resolvers_file:
            cmd += ["-r", resolvers_file]
        lines = run_stream(cmd, stdin_data="\n".join(hosts) + "\n")
        if lines is not None:  # binary ran (empty list = nothing resolved)
            return {l.strip().lower() for l in lines if l.strip()}
    warn("puredns unavailable - using built-in resolver (slower, no wildcard filtering)")
    return resolve_python(hosts, threads)


def bruteforce(domain, wordlist, resolvers_file):
    if not have("puredns"):
        warn("puredns not found - skipping DNS brute-force")
        return set()
    if not wordlist or not os.path.isfile(wordlist):
        warn("no wordlist available - skipping DNS brute-force (use -w)")
        return set()
    cmd = ["puredns", "bruteforce", wordlist, domain, "-q"]
    if resolvers_file:
        cmd += ["-r", resolvers_file]
    lines = run_stream(cmd)
    return {l.strip().lower() for l in (lines or []) if l.strip()}


def permutations(seed_hosts, resolvers_file, threads=50):
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
    return resolve_hosts(candidates, resolvers_file, threads)


# --------------------------------------------------------------------------- #
# Phase 5 - public exposure
# --------------------------------------------------------------------------- #
def fmt_http(rec):
    tech = rec.get("tech") or []
    if isinstance(tech, list):
        tech = ", ".join(tech)
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
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
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
# Setup helpers (resolvers / wordlists / tool summary)
# --------------------------------------------------------------------------- #
FALLBACK_RESOLVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                      "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"]

DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"),
    os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"),
]


def ensure_resolvers(user_path):
    """Return (resolvers_path, temp_path_or_None). Writes a built-in list if needed."""
    if user_path:
        if os.path.isfile(user_path):
            return user_path, None
        warn(f"resolvers file not found: {user_path} - using built-in fallback")
    fd, path = tempfile.mkstemp(prefix="recon_resolvers_", suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(FALLBACK_RESOLVERS) + "\n")
    return path, path


def find_wordlist(user_path):
    if user_path:
        if os.path.isfile(user_path):
            return user_path
        warn(f"wordlist not found: {user_path}")
        return None
    for p in DEFAULT_WORDLISTS:
        if os.path.isfile(p):
            info(f"using detected wordlist: {p}")
            return p
    return None


def summarize_tools():
    tools = ["subfinder", "puredns", "massdns", "alterx", "httpx", "nmap", "whois"]
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
def run_pipeline(domain, args, resolvers_file, wordlist, queue, visited):
    domain = domain.strip().lower()
    result = {
        "target": domain, "org": None, "extra_roots": set(),
        "passive": set(), "resolved": set(), "unresolved": set(),
        "http": [], "ports": {},
    }

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
            r = r.strip().lower()
            if r and r not in visited:
                visited.add(r)
                queue.append(r)
                good(f"queued related root domain: {r}")

    # Phase 1 - passive
    phase(f"passive subdomain enumeration - {domain}")
    passive = passive_enum(domain)
    passive.add(domain)
    result["passive"] = passive
    good(f"{len(passive)} unique names from passive sources")

    # Phase 2 - resolve passive set
    phase(f"resolving {len(passive)} hosts - {domain}")
    resolved = resolve_hosts(passive, resolvers_file, args.threads)
    good(f"{len(resolved)} hosts resolved")

    if not args.passive_only:
        # Phase 3a - brute-force
        if not args.no_bruteforce:
            phase(f"active discovery - DNS brute-force - {domain}")
            bf = bruteforce(domain, wordlist, resolvers_file)
            new = bf - resolved
            if new:
                good(f"{len(new)} new hosts from brute-force")
            resolved |= bf
        # Phase 3b - permutations (seeded from confirmed live hosts)
        if not args.no_permutations:
            phase(f"active discovery - permutations (alterx) - {domain}")
            pm = permutations(resolved, resolvers_file, args.threads)
            new = pm - resolved
            if new:
                good(f"{len(new)} new hosts from permutations")
            resolved |= pm

    result["resolved"] = resolved
    result["unresolved"] = passive - resolved
    good(f"{len(resolved)} total resolved hosts for {domain}")

    # Phase 5 - HTTP probing
    if not args.passive_only and not args.no_httpx:
        phase(f"public exposure - HTTP probing (httpx) - {domain}")
        result["http"] = probe_http(resolved)
        good(f"{len(result['http'])} live web services")

    # Phase 5 - network exposure
    if args.ports and not args.passive_only:
        if result["http"]:
            ips = ips_from_http(result["http"])
        else:
            info("resolving hosts to IPs for port scan ...")
            ips = ips_from_hosts(resolved)
        if ips:
            phase(f"network exposure - port scan of {len(ips)} unique IP(s)")
            result["ports"] = port_scan(ips, args.full_ports)

    return result


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
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
    total_resolved = sum(len(r["resolved"]) for r in results)
    total_live = sum(len(r["http"]) for r in results)
    A(f"SUMMARY: {len(results)} target(s), {total_resolved} resolved hosts, "
      f"{total_live} live web services")
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

        res = sorted(r["resolved"])
        unres = sorted(r["unresolved"])
        A(f"--- SUBDOMAINS [{len(res)} resolved / {len(r['passive'])} discovered] ---")
        if res:
            A("  [resolved]")
            for d in res:
                A(f"    {d}")
        if unres:
            A("")
            A(f"  [discovered but not resolving] ({len(unres)})")
            for d in unres:
                A(f"    {d}")
        if not res and not unres:
            A("  (none)")
        A("")

        if r["http"]:
            A(f"--- LIVE WEB SERVICES (httpx) [{len(r['http'])}] ---")
            for rec in sorted(r["http"], key=lambda x: str(x.get("url"))):
                A("  " + fmt_http(rec))
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


def print_summary(results):
    print()
    print(C.w(C.BOLD, "-- Summary --"))
    for r in results:
        ports = sum(1 for ip in r["ports"] if r["ports"][ip])
        good(f"{r['target']}: {len(r['resolved'])} resolved, "
             f"{len(r['http'])} live web, {ports} host(s) with open ports")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Bug bounty reconnaissance pipeline (passive + active subdomain "
                    "enumeration, resolution, web probing, port scanning).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python3 recon.py -t example.com -o output.txt\n"
               "  python3 recon.py -T targets.txt -o output.txt\n"
               "  python3 recon.py -t example.com -w wordlist.txt -r resolvers.txt --ports -o out.txt\n"
               "\nOnly test assets you are authorized to assess.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-t", "--target", help="single target domain")
    g.add_argument("-T", "--targets", help="file with target domains, one per line")

    p.add_argument("-o", "--output", default="recon_output.txt",
                   help="output report file (default: recon_output.txt)")
    p.add_argument("-w", "--wordlist", help="wordlist for DNS brute-force (puredns)")
    p.add_argument("-r", "--resolvers", help="DNS resolvers file (puredns)")
    p.add_argument("--threads", type=int, default=50,
                   help="concurrency for the native resolver fallback (default: 50)")

    p.add_argument("--passive-only", action="store_true",
                   help="passive enumeration + resolution only (no active probing of target)")
    p.add_argument("--no-bruteforce", action="store_true", help="skip DNS brute-force")
    p.add_argument("--no-permutations", action="store_true", help="skip alterx permutations")
    p.add_argument("--no-httpx", action="store_true", help="skip HTTP probing")
    p.add_argument("--ports", action="store_true",
                   help="run nmap on live IPs (slow)")
    p.add_argument("--full-ports", action="store_true",
                   help="scan all 65535 ports instead of top 1000 (very slow)")
    p.add_argument("--expand-roots", action="store_true",
                   help="also run the full pipeline on root domains found via WHOIS")
    p.add_argument("--whoxy-key", help="whoxy.com API key for reverse WHOIS")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    return p.parse_args()


def load_targets(args):
    if args.target:
        return [args.target.strip().lower()]
    targets = []
    try:
        with open(args.targets) as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    targets.append(line)
    except OSError as e:
        err(f"cannot read targets file: {e}")
        sys.exit(1)
    return targets


def main():
    args = parse_args()
    if args.no_color or not sys.stdout.isatty():
        C.disable()

    banner()

    targets = load_targets(args)
    if not targets:
        err("no targets provided")
        sys.exit(1)

    resolvers_file, tmp_resolvers = ensure_resolvers(args.resolvers)
    wordlist = None
    if not args.passive_only and not args.no_bruteforce:
        wordlist = find_wordlist(args.wordlist)

    summarize_tools()

    queue = list(dict.fromkeys(targets))  # dedupe, keep order
    visited = set(queue)
    results = []
    start = time.time()
    try:
        while queue:
            results.append(
                run_pipeline(queue.pop(0), args, resolvers_file, wordlist, queue, visited)
            )
    except KeyboardInterrupt:
        warn("interrupted - writing partial results ...")
    finally:
        if tmp_resolvers and os.path.isfile(tmp_resolvers):
            try:
                os.remove(tmp_resolvers)
            except OSError:
                pass

    if results:
        write_report(results, args.output, time.time() - start)
        good(f"report written to {args.output}")
        print_summary(results)
    else:
        warn("no results to write")


if __name__ == "__main__":
    main()
