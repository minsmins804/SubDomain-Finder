# clean_from_file.py
# Usage:
#   python clean_from_file.py results_new.json example.com
# Produces cleaned_results_<timestamp>.json and cleaned_results_<timestamp>.csv

import json, sys, re, datetime, os

HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-\.]{0,251}[a-z0-9])?$")

def normalize_candidate(candidate: str):
    out = []
    if candidate is None:
        return out
    parts = re.split(r"[,;\n\r]+", str(candidate))
    for p in parts:
        for q in p.split():
            q = q.strip().lower().strip('.')
            if q:
                out.append(q)
    return out

def is_valid_hostname(h: str, domain: str) -> bool:
    if not h:
        return False
    if '@' in h:
        return False
    if h.startswith('*.'):
        return False
    if not h.endswith(domain):
        return False
    if not HOST_RE.match(h):
        return False
    return True

def clean_and_dedupe(raw_iterable, domain):
    seen = set()
    cleaned = []
    for item in raw_iterable:
        for cand in normalize_candidate(item):
            if is_valid_hostname(cand, domain) and cand not in seen:
                seen.add(cand)
                cleaned.append(cand)
    cleaned.sort()
    return cleaned

def main():
    if len(sys.argv) < 3:
        print("Usage: python clean_from_file.py <input_results.json> <domain>")
        sys.exit(1)

    inpath = sys.argv[1]
    domain = sys.argv[2].strip().lower()

    # ✅ tạo timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        with open(inpath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print("Failed to open input file:", e)
        sys.exit(1)

    # extract candidate subdomain strings
    raw = []
    if isinstance(data, dict):
        if "subdomains" in data and isinstance(data["subdomains"], list):
            raw = data["subdomains"]
        elif "raw" in data and isinstance(data["raw"], list):
            raw = data["raw"]
        else:
            for v in data.values():
                if isinstance(v, list):
                    raw.extend(v)
                elif isinstance(v, str):
                    raw.append(v)
    elif isinstance(data, list):
        raw = data
    else:
        print("Unknown data structure in input JSON.")
        sys.exit(1)

    cleaned = clean_and_dedupe(raw, domain)
    out_json = {"domain": domain, "subdomains": cleaned}

    json_name = f"cleaned_results_{timestamp}.json"
    csv_name = f"cleaned_results_{timestamp}.csv"

    with open(json_name, "w", encoding="utf-8") as f:
        json.dump(out_json, f, indent=2, ensure_ascii=False)

    with open(csv_name, "w", encoding="utf-8") as f:
        f.write("subdomain\n")
        for s in cleaned:
            f.write(s + "\n")

    print(f"Wrote {json_name} and {csv_name} ({len(cleaned)} hosts)")

if __name__ == "__main__":
    main()
