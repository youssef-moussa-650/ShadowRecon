#!/usr/bin/env python3
import subprocess
import sys
import os

if len(sys.argv) != 2:
    print(f"Usage: python3 {sys.argv[0]} subdomains.txt")
    sys.exit(1)

input_file = sys.argv[1]
unique_file = "subdomains_unique.txt"
httpx_file = "httpx_hits.txt"
urls_file = "urls.txt"
ips_file = "ips.txt"

# 1) Sort & remove duplicates
print("[*] Sorting & removing duplicates...")
subprocess.run(f"sort {input_file} | uniq > {unique_file}", shell=True, check=True)
print(f"[+] Unique sorted subdomains saved to {unique_file}")

# 2) Run httpx (keep only live hosts)
print("[*] Running httpx... (filtering live domains)")
subprocess.run(f"httpx-toolkit -l {unique_file} -mc 200,301,302,429 -o {httpx_file}", shell=True)
print(f"[+] Live filtered subdomains saved to {httpx_file}")

# 3) waybackurls with timeout
print("[*] Fetching URLs using waybackurls (timeout: 60s)...")
try:
    with open(unique_file, "rb") as f, open(urls_file, "w") as out_f:
        subprocess.run(
            ["waybackurls"],
            stdin=f,
            stdout=out_f,
            stderr=subprocess.DEVNULL,
            timeout=60
        )
    print(f"[+] URLs saved to {urls_file}")
except subprocess.TimeoutExpired:
    print("[!] waybackurls timed out. Partial output saved.")
except Exception as e:
    print(f"[!] Error running waybackurls: {e}")

# 4) Domain -> IP resolution
print("[*] Resolving IPs for domains...")
ips = set()
with open(unique_file) as f:
    for domain in f:
        domain = domain.strip()
        if not domain:
            continue
        try:
            result = subprocess.check_output(["dig", "+short", domain]).decode().strip()
            if result:
                for line in result.split("\n"):
                    if line.strip():
                        ips.add(line.strip())
        except Exception:
            pass

with open(ips_file, "w") as f:
    for ip in sorted(ips):
        f.write(ip + "\n")
print(f"[+] IPs saved to {ips_file}")

print("\n=== DONE ===")
print(f"Unique Subdomains  => {unique_file}")
print(f"HTTPX Live Domains => {httpx_file}")
print(f"Wayback URLs       => {urls_file}")
print(f"Resolved IPs       => {ips_file}")
