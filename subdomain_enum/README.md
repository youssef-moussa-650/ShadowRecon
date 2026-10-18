# Subdomain Enumeration & Filtering

My contribution to the ShadowRecon project (DEPI — Vulnerability Analyst & Penetration Tester track): the subdomain discovery and filtering stage of the recon pipeline.

> ⚠️ **Authorized testing only.** Run these tools exclusively against domains you own or are explicitly permitted to assess (e.g. an in-scope bug-bounty program).

## `subdomain.py`
Aggregates subdomains for a target from multiple sources and merges the results:
- **Passive:** crt.sh, Shodan InternetDB, SecurityTrails, C99
- **Active:** Subfinder, dnsrecon (basic / AXFR / brute-force), ffuf

```bash
python3 subdomain.py example.com -w /path/to/wordlist.txt -o subdomains.txt
```

## `filter.py`
Cleans and enriches the raw list:
1. Sort + de-duplicate
2. Probe for live hosts with `httpx`
3. Collect historical URLs with `waybackurls`
4. Resolve each host to its IP(s)

```bash
python3 filter.py subdomains.txt
```

## API keys
`subdomain.py` reads keys from environment variables — **nothing is hard-coded**. Copy `.env.example` to `.env` and fill in your own keys:

```bash
cp .env.example .env
# then: export the vars, or load the .env before running
```

Output files (`*.txt`) and `.env` are git-ignored and never committed.
