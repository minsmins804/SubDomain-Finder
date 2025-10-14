# verify_and_resolve.py
# Usage:
#   python verify_and_resolve.py cleaned_results_*.json
# Output:
#   verified_results_<timestamp>.json

import asyncio
import aiohttp
import json
import sys
import datetime
from typing import List, Dict, Any

CONCURRENCY = 40
DNS_TIMEOUT = 5
HTTP_TIMEOUT = 8

async def resolve_host(host: str, loop: asyncio.AbstractEventLoop) -> List[str]:
    ips = set()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=DNS_TIMEOUT)
        for info in infos:
            sockaddr = info[4]
            if isinstance(sockaddr, tuple) and len(sockaddr) >= 1:
                ip = sockaddr[0]
                ips.add(ip)
    except asyncio.TimeoutError:
        return []
    except Exception:
        return []
    return list(ips)

async def check_http(session: aiohttp.ClientSession, host: str) -> Dict[str, Any]:
    for scheme in ("http://", "https://"):
        url = scheme + host
        try:
            async with session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True) as resp:
                return {
                    "host": host,
                    "http_ok": True,
                    "http_status": resp.status,
                    "final_url": str(resp.url)
                }
        except asyncio.TimeoutError:
            continue
        except Exception:
            continue
    return {"host": host, "http_ok": False, "http_status": None, "final_url": None}

async def worker(host: str, sem: asyncio.Semaphore, loop: asyncio.AbstractEventLoop, session: aiohttp.ClientSession) -> Dict[str, Any]:
    async with sem:
        out = {"host": host, "ips": [], "http_ok": False, "http_status": None, "final_url": None, "error": None}
        try:
            ips = await resolve_host(host, loop)
            out["ips"] = ips
        except Exception as e:
            out["error"] = f"DNS error: {e}"

        try:
            http_res = await check_http(session, host)
            out["http_ok"] = http_res.get("http_ok", False)
            out["http_status"] = http_res.get("http_status")
            out["final_url"] = http_res.get("final_url")
        except Exception as e:
            out["error"] = (out.get("error") or "") + f" HTTP error: {e}"

        return out

async def verify_all(hosts: List[str], concurrency: int = CONCURRENCY) -> List[Dict[str, Any]]:
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT + 4)
    conn = aiohttp.TCPConnector(limit=concurrency)
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        tasks = [worker(h, sem, loop, session) for h in hosts]
        results = []
        for fut in asyncio.as_completed(tasks):
            res = await fut
            results.append(res)
    return results

def read_hosts_from_file(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            if "subdomains" in data and isinstance(data["subdomains"], list):
                return data["subdomains"]
            for v in data.values():
                if isinstance(v, list):
                    return v
        if isinstance(data, list):
            return data
    except Exception as e:
        print("Error reading hosts file:", e)
    return []

def main():
    if len(sys.argv) >= 2:
        inpath = sys.argv[1]
    else:
        inpath = "cleaned_results.json"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    outpath = f"verified_results_{timestamp}.json"

    hosts = read_hosts_from_file(inpath)
    if not hosts:
        print("No hosts found in", inpath)
        sys.exit(1)

    print(f"[+] Verifying {len(hosts)} hosts (concurrency={CONCURRENCY}) ...")
    results = asyncio.run(verify_all(hosts, concurrency=CONCURRENCY))

    with open(outpath, "w", encoding="utf-8") as f:
        json.dump({"count": len(results), "results": results}, f, indent=2, ensure_ascii=False)

    ok = [r for r in results if r.get("http_ok")]
    print(f"[+] Done. {len(ok)}/{len(results)} hosts responded to HTTP/HTTPS. Results -> {outpath}")

if __name__ == "__main__":
    main()
