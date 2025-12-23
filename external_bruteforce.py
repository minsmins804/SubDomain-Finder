import dns.resolver

def brute_force(domain, wordlist_path):
    results = []
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            subnames = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print("[!] Wordlist not found:", wordlist_path)
        return results

    print(f"[+] Starting brute-force with {len(subnames)} words...")

    for sub in subnames:
        full = f"{sub}.{domain}"
        try:
            dns.resolver.resolve(full, "A")
            print(f"[FOUND] {full}")
            results.append(full)
        except:
            pass
    return results


def brute_force_deep(domain, wordlist_path):
    """
    Deep brute-force: thêm dạng sub.sub.domain
    """
    results = []
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            subnames = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print("[!] Wordlist not found:", wordlist_path)
        return results

    print(f"[+] Starting DEEP brute-force with {len(subnames)**2} combinations...")

    for sub1 in subnames:
        for sub2 in subnames:
            full = f"{sub1}.{sub2}.{domain}"
            try:
                dns.resolver.resolve(full, "A")
                print(f"[FOUND-DEEP] {full}")
                results.append(full)
            except:
                pass
    return results
