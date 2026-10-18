#!/usr/bin/env python3
import subprocess
import requests
import argparse
import re
import json
import sys
import os
from urllib.parse import quote
from datetime import datetime

# =============================================
#               CONFIG SECTION
# =============================================

# ---- API KEYS (load from environment / .env — never hard-code) ----
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
C99_API_KEY            = os.getenv("C99_API_KEY", "")

# ---- TIMEOUTS ----
TIMEOUT_SUBFINDER = 120
TIMEOUT_DNSRECON  = 60
TIMEOUT_AXFR      = 60
TIMEOUT_BRUTE     = 120
TIMEOUT_FFUF      = 180

# ---- WORDLIST ----
DEFAULT_WORDLIST = "/usr/share/wordlists/dnsmap.txt"

# =============================================
#               COMMON UTILITIES
# =============================================

def run_cmd(cmd, timeout):
    """Run a shell command with timeout and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout: {cmd}")
        return ""

def extract_subdomains(text, domain):
    """Extract domain + subdomains using regex."""
    pattern = rf"(?:[a-zA-Z0-9-_]+\.)+{re.escape(domain)}"
    return set(re.findall(pattern, text, re.IGNORECASE))


# =============================================
#               ENUMERATION MODULES
# =============================================

def enum_subfinder(domain):
    print("[*] Running Subfinder...")
    output = run_cmd(f"subfinder -silent -d {domain}", TIMEOUT_SUBFINDER)
    return extract_subdomains(output, domain)


def enum_dnsrecon(domain):
    print("[*] Running dnsrecon basic...")
    out = run_cmd(f"dnsrecon -d {domain}", TIMEOUT_DNSRECON)
    return extract_subdomains(out, domain)

def enum_dnsrecon_axfr(domain):
    print("[*] Running dnsrecon AXFR...")
    out = run_cmd(f"dnsrecon -d {domain} -t axfr", TIMEOUT_AXFR)
    return extract_subdomains(out, domain)

def enum_dnsrecon_bruteforce(domain, wordlist):
    print("[*] Running dnsrecon bruteforce...")
    out = run_cmd(
        f"dnsrecon -d {domain} -D {wordlist} -t brt",
        TIMEOUT_BRUTE
    )
    return extract_subdomains(out, domain)


def enum_ffuf(domain, wordlist):
    print("[*] Running ffuf bruteforce...")
    tmp_file = "ffuf_tmp.txt"

    cmd = f"""
        ffuf -u http://FUZZ.{domain} \
             -w {wordlist} \
             -of csv -o {tmp_file} -mc all -t 50 2>/dev/null
    """

    run_cmd(cmd, TIMEOUT_FFUF)

    subs = set()
    if os.path.exists(tmp_file):
        with open(tmp_file) as f:
            for line in f:
                if domain in line:
                    parts = line.split(",")
                    host = parts[1].replace("http://", "").strip()
                    subs.add(host)
        os.remove(tmp_file)

    return subs


def enum_securitytrails(domain):
    print("[*] Querying SecurityTrails API...")

    if not SECURITYTRAILS_API_KEY:
        print("[!] SECURITYTRAILS_API_KEY not set — skipping.")
        return set()

    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        return set(f"{s}.{domain}" for s in data.get("subdomains", []))
    except Exception:
        return set()


def enum_c99(domain):
    print("[*] Querying C99 API...")

    if not C99_API_KEY:
        print("[!] C99_API_KEY not set — skipping.")
        return set()

    url = f"https://api.c99.nl/subdomainfinder?key={C99_API_KEY}&domain={domain}&json"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        return set(data.get("subdomains", []))
    except Exception:
        return set()


def enum_shodan(domain):
    print("[*] Querying Shodan InternetDB...")
    try:
        r = requests.get(f"https://internetdb.shodan.io/{domain}", timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        return set(data.get("hostnames", []))
    except Exception:
        return set()


def enum_crtsh(domain):
    print("[*] Scraping crt.sh...")
    try:
        r = requests.get(
            f"https://crt.sh/?q={quote(domain)}&output=json",
            timeout=20
        )
        if r.status_code != 200:
            return set()
        entries = json.loads(r.text)
        subs = set()
        for e in entries:
            name = e.get("name_value", "")
            if domain in name:
                for s in name.split("\n"):
                    subs.add(s.strip())
        return subs
    except Exception:
        return set()


# =============================================
#               MAIN LOGIC
# =============================================

def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("domain", help="Target domain (only test domains you are authorized to assess)")
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, help="Wordlist for bruteforce (ffuf + dnsrecon)")
    parser.add_argument("-o", "--output", default="subdomains.txt", help="Output file")

    args = parser.parse_args()
    domain = args.domain
    wl = args.wordlist
    outfile = args.output

    print(f"\n=== Subdomain Enumeration for {domain} ===\n")

    all_subs = set()
    modules = [
        enum_subfinder,
        enum_dnsrecon,
        enum_dnsrecon_axfr,
        lambda d: enum_dnsrecon_bruteforce(d, wl),
        lambda d: enum_ffuf(d, wl),
        enum_securitytrails,
        enum_c99,
        enum_shodan,
        enum_crtsh
    ]

    for m in modules:
        try:
            result = m(domain)
            name = getattr(m, "__name__", "module")
            print(f"[+] {name}: {len(result)} found")
            all_subs.update(result)
        except KeyboardInterrupt:
            print("Interrupted.")
            sys.exit()
        except Exception as e:
            print(f"[!] Error: {e}")

    all_subs = sorted(all_subs)
    with open(outfile, "w") as f:
        for s in all_subs:
            f.write(s + "\n")

    print(f"\n=== DONE! Total subdomains: {len(all_subs)} ===")
    print(f"Saved to: {outfile}\n")


if __name__ == "__main__":
    main()
