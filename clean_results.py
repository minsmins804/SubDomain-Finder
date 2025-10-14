# clean_results.py
# Usage:
#   python clean_results.py example.com
# or
#   python clean_results.py
# If no arg given, default domain is "example.com" (change default as needed).

import asyncio
import json
import re
import sys
from typing import List, Set

# import ServiceScanner from your package
from subdomainfinder.services import ServiceScanner

# hostname validation: allow a-z0-9 - and dots, must start and end with alnum
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-\.]{0,251}[a-z0-9])?$")

def normalize_candidate(candidate: str) -> List[str]:
    """
    Break candidate into possible hostnames (split on commas/newlines/spaces),
    strip and lowercase.
    Returns list of cleaned strings.
    """
    out = []
    if candidate is None:
        return out
    # split common separators
    parts = re.split(r"[,;\n\r]+", str(candidate))
    for p in parts:
        # further split on whitespace (but avoid splitting hostnames with dots)
        for q in p.split():
            q = q.strip().lower().strip('.')
            if q:
                out.append(q)
    return out

def is_valid_hostname(h: str, domain: str) -> bool:
    if not h:
        return False
    h = h.strip().lower()
    # exclude emails
    if '@' in h:
        return False
    # exclude wildcard entries
    if h.startswith('*.'):
        return False
    # must end with the domain
    if not h.endswith(domain):
        return False
    # must be composed of allowed chars
    if not HOST_RE.match(h):
        return False
    return True

async def scan_services(domain: str) -> Set[str]:
    scanner = ServiceScanner(domain)
    results = await scanner.scan()
    # ensure it's a set/list
    if results is None:
        return set()
    return set(results)

def clean_and_dedupe(raw_iterable, domain):
    seen = set()
    cleaned = []
    for item in raw_iterable:
        for cand in normalize_candidate(item):
            if is_valid_hostname(cand, domain) and cand not in seen:
                seen.add(cand)
                cleaned.append(cand)
    # sort for consistent order
    cleaned.sort()
    return cleaned

def save_json(path: str, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def save_csv(path: str, items: List[str]):
    with open(path, "w", encoding="utf-8") as f:
        f.write("subdomain\n")
        for s in items:
            f.write(s + "\n")

def main():
    # domain from argv or default
    if len(sys.argv) >= 2:
        domain = sys.argv[1].strip().lower()
    else:
        domain = "example.com"   # change default if you want

    print(f"[+] Scanning services for domain: {domain}")

    raw_results = asyncio.run(scan_services(domain))
    print(f"[+] Raw results fetched: {len(raw_results)} items")

    # Save raw results as list
    raw_list = list(raw_results)
    save_json("raw_results.json", {"domain": domain, "raw": raw_list})
    print("[+] Wrote raw_results.json")

    # Clean and dedupe
    cleaned = clean_and_dedupe(raw_list, domain)
    save_json("cleaned_results.json", {"domain": domain, "subdomains": cleaned})
    save_csv("cleaned_results.csv", cleaned)
    print(f"[+] Wrote cleaned_results.json and cleaned_results.csv ({len(cleaned)} hosts)")

    # Print short sample
    if cleaned:
        print("\nSample cleaned results (first 30):")
        for s in cleaned[:30]:
            print(s)
    else:
        print("\nNo cleaned subdomains found. Check raw_results.json for raw data.")

if __name__ == "__main__":
    main()
