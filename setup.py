#!/usr/bin/env python3
"""
setup.py - dependency installer & configuration bootstrapper for subrecon.py

What it does:
  1. Detects your OS (macOS / Linux) and package manager.
  2. Installs the prerequisites (Homebrew on macOS, Go) if they are missing.
  3. Checks every tool subrecon.py can use and PRINTS the exact install command
     for whatever is missing (it does NOT run those installs for you - you stay
     in control of what touches your system).
  4. Checks for the SecLists wordlists subrecon.py auto-detects.
  5. Adds the Go bin directory (~/go/bin) to your shell PATH automatically.
  6. Prompts (optionally) for API keys and writes them all to one file that
     subrecon.py reads directly each run (so editing keys never needs a reload):
       VirusTotal / Chaos  ->  ~/.recon/config
     The file is chmod 600. Every key prompt can be skipped by pressing Enter.

Run:
    python3 setup.py            # full setup
    python3 setup.py --check    # read-only audit (no installs, no edits, no prompts)
    python3 setup.py --yes      # assume "yes" for prerequisite installs / no confirms

Only set this up to test assets you are explicitly authorized to assess.
"""

import argparse
import getpass
import os
import platform
import shutil
import subprocess
import sys


# --------------------------------------------------------------------------- #
# Output helpers (mirrors subrecon.py's style for a consistent look)
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


def cmd_line(text):
    """Print a copy-pasteable command, indented and dim."""
    print("    " + C.w(C.GREY, "$ ") + text)


def banner():
    print(C.w(C.BOLD + C.CYAN, "subrecon.py setup - dependency installer & key configuration"))


# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #
def have(tool):
    return shutil.which(tool) is not None


def confirm(question, default=True, assume_yes=False):
    if assume_yes:
        return True
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        ans = input(C.w(C.YELLOW, f"[?] {question} {suffix} ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not ans:
        return default
    return ans in ("y", "yes")


def prompt_secret(label):
    """Hidden prompt. Returns the entered value, or None if skipped (empty)."""
    try:
        val = getpass.getpass(C.w(C.CYAN, f"[?] {label} (Enter to skip): "))
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    val = val.strip()
    return val or None


def mask(value):
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return "…" + value[-4:]


def run(cmd, shell=False):
    """Run an install command, streaming output. Returns True on success."""
    printable = cmd if shell else " ".join(cmd)
    info(f"running: {printable}")
    try:
        rc = subprocess.call(cmd, shell=shell)
    except (FileNotFoundError, OSError) as e:
        err(f"could not run command: {e}")
        return False
    if rc != 0:
        warn(f"command exited with status {rc}")
        return False
    return True


# --------------------------------------------------------------------------- #
# OS detection
# --------------------------------------------------------------------------- #
def detect_os():
    """Return ('darwin'|'linux'|'other', package_manager_or_None)."""
    system = platform.system()
    if system == "Darwin":
        return "darwin", ("brew" if have("brew") else None)
    if system == "Linux":
        for mgr in ("apt-get", "dnf", "pacman", "zypper"):
            if have(mgr):
                return "linux", mgr
        return "linux", None
    return "other", None


# --------------------------------------------------------------------------- #
# Tool / dependency tables
# --------------------------------------------------------------------------- #
# Pure-Go tools: `go install` works identically on macOS and Linux once Go is
# present, so subrecon.py gets the same set everywhere.
GO_TOOLS = [
    ("subfinder", "passive enumeration",
     "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("httpx", "HTTP probing / fingerprinting",
     "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("puredns", "resolution + DNS brute-force",
     "go install github.com/d3mondev/puredns/v2@latest"),
    ("alterx", "permutation generation",
     "go install github.com/projectdiscovery/alterx/cmd/alterx@latest"),
    ("gau", "passive (Wayback/CommonCrawl URLs)",
     "go install github.com/lc/gau/v2/cmd/gau@latest"),
    ("waybackurls", "passive (Wayback) - gau fallback",
     "go install github.com/tomnomnom/waybackurls@latest"),
    ("assetfinder", "passive enumeration",
     "go install github.com/tomnomnom/assetfinder@latest"),
    ("github-subdomains", "passive (GitHub code search, needs token)",
     "go install github.com/gwen001/github-subdomains@latest"),
    ("ffuf", "virtual-host enumeration (--vhost)",
     "go install github.com/ffuf/ffuf/v2@latest"),
    ("amass", "passive enumeration (--amass)",
     "go install -v github.com/owasp-amass/amass/v4/...@master"),
]

# System / C tools: package-manager specific.
SYSTEM_TOOLS = {
    "nmap": {
        "purpose": "port scan (--ports)",
        "darwin": "brew install nmap",
        "apt-get": "sudo apt-get install -y nmap",
    },
    "massdns": {
        "purpose": "puredns backend (REQUIRED by puredns)",
        "darwin": "brew install massdns",
        "apt-get": ("sudo apt-get install -y massdns 2>/dev/null || "
                    "(git clone https://github.com/blechschmidt/massdns.git /tmp/massdns "
                    "&& make -C /tmp/massdns && sudo make -C /tmp/massdns install)"),
    },
    "whois": {
        "purpose": "root domain discovery",
        "darwin": "# ships with macOS - nothing to do",
        "apt-get": "sudo apt-get install -y whois",
    },
}

# Optional extras: improve coverage but subrecon.py degrades gracefully without them.
OPTIONAL_TOOLS = {
    "dig": {
        "purpose": "takeover CNAME checks / native resolver",
        "darwin": "# ships with macOS (bind tools)",
        "apt-get": "sudo apt-get install -y dnsutils",
    },
}


def _sys_cmd(spec, pkg_mgr, os_):
    """Pick the right install command string for a system tool, or None."""
    if os_ == "darwin":
        return spec.get("darwin")
    if pkg_mgr and pkg_mgr in spec:
        return spec.get(pkg_mgr)
    # Linux without apt (dnf/pacman/etc.): we don't ship exact strings.
    return None


# --------------------------------------------------------------------------- #
# Prerequisites: Homebrew + Go (auto-install if missing)
# --------------------------------------------------------------------------- #
HOMEBREW_INSTALL = ('/bin/bash -c "$(curl -fsSL '
                    'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')


def ensure_homebrew(os_, pkg_mgr, assume_yes, check):
    """macOS only. Returns True if brew is available afterwards."""
    if os_ != "darwin":
        return True  # not needed off macOS
    if have("brew"):
        good("Homebrew present")
        return True
    if check:
        warn("Homebrew missing")
        info("install it with:")
        cmd_line(HOMEBREW_INSTALL)
        return False
    warn("Homebrew not found - it is needed to install nmap/massdns and Go on macOS")
    if confirm("Install Homebrew now?", default=True, assume_yes=assume_yes):
        if run(HOMEBREW_INSTALL, shell=True) and have("brew"):
            good("Homebrew installed")
            return True
        err("Homebrew install did not complete - run it manually, then re-run setup.py:")
        cmd_line(HOMEBREW_INSTALL)
        return False
    info("skipping Homebrew - install it manually when ready:")
    cmd_line(HOMEBREW_INSTALL)
    return False


def ensure_go(os_, pkg_mgr, assume_yes, check, brew_ok):
    """Install Go if missing. Returns True if `go` is available afterwards."""
    if have("go"):
        good("Go present")
        return True

    if os_ == "darwin":
        install_cmd = ["brew", "install", "go"]
    elif pkg_mgr == "apt-get":
        install_cmd = ["sudo", "apt-get", "install", "-y", "golang-go"]
    else:
        install_cmd = None

    if check:
        warn("Go missing (required for most passive-enumeration tools)")
        if install_cmd:
            info("install it with:")
            cmd_line(" ".join(install_cmd))
        else:
            info("install Go from https://go.dev/dl/ for your platform")
        return False

    warn("Go not found - the Go-based tools cannot be installed without it")
    if install_cmd is None:
        err("no known Go install command for this platform - install from https://go.dev/dl/")
        return False
    if os_ == "darwin" and not brew_ok:
        err("Go install on macOS needs Homebrew first (see above)")
        return False
    if confirm("Install Go now?", default=True, assume_yes=assume_yes):
        if run(install_cmd) and have("go"):
            good("Go installed")
            return True
        err("Go install did not complete - install manually, then re-run setup.py:")
        cmd_line(" ".join(install_cmd))
        return False
    info("skipping Go - install it manually, then re-run setup.py:")
    cmd_line(" ".join(install_cmd))
    return False


# --------------------------------------------------------------------------- #
# Tool checking (detect + print commands, never auto-run)
# --------------------------------------------------------------------------- #
def check_tools(os_, pkg_mgr, go_ok):
    """Report present/missing tools and print install commands for the missing."""
    phase("Checking tools subrecon.py can use")

    missing_go, missing_sys, missing_opt = [], [], []

    for name, purpose, install in GO_TOOLS:
        if have(name):
            good(f"{name:<18} present   ({purpose})")
        else:
            warn(f"{name:<18} MISSING   ({purpose})")
            missing_go.append((name, install))

    for name, spec in SYSTEM_TOOLS.items():
        if have(name):
            good(f"{name:<18} present   ({spec['purpose']})")
        else:
            cmd = _sys_cmd(spec, pkg_mgr, os_)
            warn(f"{name:<18} MISSING   ({spec['purpose']})")
            missing_sys.append((name, cmd))

    for name, spec in OPTIONAL_TOOLS.items():
        if have(name):
            good(f"{name:<18} present   ({spec['purpose']})")
        else:
            cmd = _sys_cmd(spec, pkg_mgr, os_)
            info(f"{name:<18} optional  ({spec['purpose']})")
            missing_opt.append((name, cmd))

    # ---- print the install commands, grouped --------------------------------
    if missing_sys:
        print()
        info("Install the missing SYSTEM packages:")
        for name, cmd in missing_sys:
            if cmd and not cmd.lstrip().startswith("#"):
                cmd_line(cmd)
            elif cmd:  # comment, e.g. "ships with macOS"
                print("    " + C.w(C.GREY, f"{name}: {cmd}"))
            else:
                warn(f"  {name}: no preset command for this platform - install via your package manager")

    if missing_go:
        print()
        if not go_ok:
            warn("Go is not available yet - install Go first (above), then run these:")
        else:
            info("Install the missing GO tools (binaries land in ~/go/bin):")
        for _, cmd in missing_go:
            cmd_line(cmd)

    if missing_opt:
        print()
        info("Optional (improves coverage, safe to skip):")
        for name, cmd in missing_opt:
            if cmd and not cmd.lstrip().startswith("#"):
                cmd_line(cmd)
        cmd_line("python3 -m pip install dnspython   # better native resolver fallback")

    if not (missing_go or missing_sys):
        good("All required tools are already installed.")

    return bool(missing_go or missing_sys)


# --------------------------------------------------------------------------- #
# SecLists wordlists
# --------------------------------------------------------------------------- #
# Paths subrecon.py auto-detects (kept in sync with subrecon.py's DEFAULT_WORDLISTS).
SECLISTS_PROBE = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"),
    os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"),
]
SECLISTS_CLONE = "git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/SecLists"


def check_seclists():
    phase("Checking SecLists wordlists")
    found = next((p for p in SECLISTS_PROBE if os.path.isfile(p)), None)
    if found:
        good(f"wordlist found: {found}")
        return
    if os.path.isdir(os.path.expanduser("~/SecLists")):
        warn("~/SecLists exists but the expected DNS wordlist was not found inside it")
    else:
        warn("SecLists not found - subrecon.py needs it for DNS brute-force")
    info("clone it where subrecon.py auto-detects it:")
    cmd_line(SECLISTS_CLONE)


# --------------------------------------------------------------------------- #
# Shell PATH / env configuration (auto-edit, idempotent)
# --------------------------------------------------------------------------- #
BLOCK_START = "# >>> subrecon.py setup >>>"
BLOCK_END = "# <<< subrecon.py setup <<<"
RECON_DIR = os.path.expanduser("~/.recon")
CONFIG_PATH = os.path.join(RECON_DIR, "config")


def shell_rc_path():
    shell = os.environ.get("SHELL", "")
    home = os.path.expanduser("~")
    if "zsh" in shell:
        return os.path.join(home, ".zshrc")
    if "bash" in shell:
        if platform.system() == "Darwin":
            return os.path.join(home, ".bash_profile")
        return os.path.join(home, ".bashrc")
    return os.path.join(home, ".profile")


def _managed_block():
    return (
        f'{BLOCK_START}\n'
        f'export PATH="$PATH:$HOME/go/bin"\n'
        f'{BLOCK_END}\n'
    )


def update_shell_rc(check):
    phase("Configuring shell PATH (Go binaries)")
    rc = shell_rc_path()
    block = _managed_block()

    try:
        existing = ""
        if os.path.isfile(rc):
            with open(rc) as f:
                existing = f.read()
    except OSError as e:
        err(f"could not read {rc}: {e}")
        return

    if check:
        if "$HOME/go/bin" in existing or "/go/bin" in existing:
            good(f"~/go/bin already on PATH via {rc}")
        else:
            warn(f"~/go/bin is NOT on PATH - setup.py (without --check) would add it to {rc}")
        return

    if BLOCK_START in existing and BLOCK_END in existing:
        pre = existing.split(BLOCK_START, 1)[0]
        post = existing.split(BLOCK_END, 1)[1]
        new_content = pre + block + post.lstrip("\n")
        action = "updated"
    else:
        sep = "" if existing.endswith("\n") or not existing else "\n"
        new_content = existing + sep + "\n" + block
        action = "added"

    try:
        with open(rc, "w") as f:
            f.write(new_content)
    except OSError as e:
        err(f"could not write {rc}: {e}")
        return

    good(f"{action} PATH block in {rc}")
    info('contains: export PATH="$PATH:$HOME/go/bin"')
    warn(f"reload your shell once to apply it:  source {rc}   (or open a new terminal)")


# --------------------------------------------------------------------------- #
# API key file (~/.recon/config) - read by subrecon.py's load_keys()
# --------------------------------------------------------------------------- #
def ensure_recon_dir():
    try:
        os.makedirs(RECON_DIR, exist_ok=True)
        os.chmod(RECON_DIR, 0o700)
    except OSError as e:
        err(f"could not create {RECON_DIR}: {e}")
        raise


def _read_kv(path):
    """Read KEY=value (and 'export KEY=value') lines into an upper-cased dict."""
    vals = {}
    if not os.path.isfile(path):
        return vals
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                k, v = line.split("=", 1)
                v = v.strip().strip('"').strip("'")
                if v:
                    vals[k.strip().upper()] = v
    except OSError as e:
        warn(f"could not read {path}: {e}")
    return vals


def write_config(updates):
    """Merge `updates` into ~/.recon/config (KEY=value), preserving existing keys."""
    existing = _read_kv(CONFIG_PATH)
    for k, v in updates.items():
        if v:
            existing[k] = v
    if not existing:
        return None
    ensure_recon_dir()
    try:
        with open(CONFIG_PATH, "w") as f:
            f.write("# subrecon.py API keys - managed by setup.py\n")
            f.write("# format: KEY=value  (read by subrecon.py load_keys; env vars override)\n")
            for k in sorted(existing):
                f.write(f"{k}={existing[k]}\n")
        os.chmod(CONFIG_PATH, 0o600)
    except OSError as e:
        err(f"could not write {CONFIG_PATH}: {e}")
        return None
    return CONFIG_PATH


def configure_keys():
    phase("API keys (optional - press Enter to skip any of them)")
    info(f"all keys go to a single file:  {CONFIG_PATH}   (chmod 600)")
    info("subrecon.py reads this file directly each run - no shell reload needed")
    print()

    config_updates = {}

    vt = prompt_secret("VirusTotal API key  [VT_API_KEY]")
    if vt:
        config_updates["VT_API_KEY"] = vt
        good(f"VirusTotal key captured ({mask(vt)})")

    chaos = prompt_secret("Chaos / ProjectDiscovery key  [CHAOS_KEY]")
    if chaos:
        config_updates["CHAOS_KEY"] = chaos
        good(f"Chaos key captured ({mask(chaos)})")

    print()
    cp = write_config(config_updates)
    if cp:
        good(f"wrote {cp}")
    elif os.path.isfile(CONFIG_PATH):
        info("no new keys entered - existing config left unchanged")
    else:
        info("no keys entered - subrecon.py will simply skip the keyed sources")


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #
def final_notes(check):
    phase("Next steps")
    if check:
        info("this was a read-only audit; re-run without --check to install/configure")
    print("    1. Run any install commands printed above.")
    print("    2. Reload your shell ONCE so ~/go/bin is on PATH:  "
          + C.w(C.BOLD, f"source {shell_rc_path()}"))
    print("    3. Verify subrecon.py sees everything:  "
          + C.w(C.BOLD, "python3 subrecon.py -t example.com -o out.txt"))
    print()
    info("API keys (only if you entered any):")
    print(f"      {CONFIG_PATH}  - VirusTotal / Chaos")
    print("      read directly by subrecon.py each run - editing it never needs a shell reload")
    print()
    warn("Only test assets you are explicitly authorized to assess.")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(
        prog="setup.py",
        description="Install dependencies and configure API keys for subrecon.py.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python3 setup.py            full setup (install prereqs, print tool cmds, configure)\n"
               "  python3 setup.py --check    read-only audit, no changes\n"
               "  python3 setup.py --yes      assume yes for prerequisite installs\n",
    )
    p.add_argument("--check", action="store_true",
                   help="read-only: report status and print commands, but make no changes")
    p.add_argument("-y", "--yes", action="store_true",
                   help="assume 'yes' for prerequisite (Homebrew/Go) installs")
    p.add_argument("--no-keys", action="store_true", help="skip the API key prompts")
    p.add_argument("--no-path", action="store_true", help="do not edit the shell rc for PATH")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    return p.parse_args()


def main():
    args = parse_args()
    if args.no_color or not sys.stdout.isatty():
        C.disable()

    banner()

    phase("Detecting platform")
    os_, pkg_mgr = detect_os()
    info(f"OS: {platform.system()} ({platform.machine()})")
    if os_ == "linux":
        info(f"package manager: {pkg_mgr or 'none detected'}")
        if pkg_mgr and pkg_mgr != "apt-get":
            warn(f"detected {pkg_mgr}; preset commands target apt - adapt them for your distro")
    elif os_ == "other":
        warn("unrecognized OS - tool detection still works, but install commands may not fit")

    # --- prerequisites: brew (mac) + go ------------------------------------
    phase("Checking prerequisites (Homebrew / Go)")
    brew_ok = ensure_homebrew(os_, pkg_mgr, args.yes, args.check)
    go_ok = ensure_go(os_, pkg_mgr, args.yes, args.check, brew_ok)

    # --- tools (detect + print, never run) ---------------------------------
    check_tools(os_, pkg_mgr, go_ok)

    # --- wordlists ----------------------------------------------------------
    check_seclists()

    # --- PATH ---------------------------------------------------------------
    if args.no_path and not args.check:
        phase("Configuring shell PATH (Go binaries)")
        info("skipped (--no-path). Make sure ~/go/bin is on your PATH manually.")
    else:
        update_shell_rc(args.check)

    # --- API keys -----------------------------------------------------------
    if args.check:
        phase("API keys")
        info("skipped in --check mode")
        info(f"would write all keys to {CONFIG_PATH}")
    elif args.no_keys:
        phase("API keys")
        info("skipped (--no-keys)")
    else:
        try:
            configure_keys()
        except Exception as e:  # never let key handling crash the whole run
            err(f"key configuration failed: {e}")

    final_notes(args.check)


if __name__ == "__main__":
    main()
