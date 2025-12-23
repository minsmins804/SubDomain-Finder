import aiohttp
import re
import asyncio

# --------------------------
# 1. RapidDNS (scrape HTML)
# --------------------------
async def fetch_rapiddns(session, domain):
    url = f"https://rapiddns.io/subdomain/{domain}?full=1&down=1"
    try:
        async with session.get(url, timeout=10) as r:
            html = await r.text()
            subs = set(re.findall(r'([\w.-]+\.' + re.escape(domain) + r')', html))
            return subs
    except:
        return set()

# --------------------------
# 2. HackerTarget (simple text)
# --------------------------
async def fetch_hackertarget(session, domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with session.get(url, timeout=10) as r:
            txt = await r.text()
            lines = txt.splitlines()
            subs = set(l.split(',')[0] for l in lines if domain in l)
            return subs
    except:
        return set()

# --------------------------
# 3. BufferOver.run (JSON)
# --------------------------
async def fetch_bufferover(session, domain):
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        async with session.get(url, timeout=10) as r:
            js = await r.json()
            subs = set()
            for item in js.get("FDNS_A", []):
                sub = item.split(",")[1]
                if domain in sub:
                    subs.add(sub)
            return subs
    except:
        return set()

# --------------------------
# 4. Archive.org (Wayback)
# --------------------------
async def fetch_wayback(session, domain):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original"
    try:
        async with session.get(url, timeout=10) as r:
            js = await r.json()
            subs = set()
            for item in js[1:]:
                url = item[0]
                match = re.search(r'https?://([^/]+)', url)
                if match and domain in match.group(1):
                    subs.add(match.group(1))
            return subs
    except:
        return set()

# --------------------------
# 5. AlienVault OTX (JSON)
# --------------------------
async def fetch_otx(session, domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        async with session.get(url, timeout=10) as r:
            js = await r.json()
            subs = set()
            for item in js.get("passive_dns", []):
                host = item.get("hostname")
                if host and domain in host:
                    subs.add(host)
            return subs
    except:
        return set()

# --------------------------
# Gộp thành 1 hàm duy nhất để main.py gọi
# --------------------------
async def fetch_passive_sources(domain):
    async with aiohttp.ClientSession() as session:
        tasks = [
            fetch_rapiddns(session, domain),
            fetch_hackertarget(session, domain),
            fetch_bufferover(session, domain),
            fetch_wayback(session, domain),
            fetch_otx(session, domain)
        ]
        results = await asyncio.gather(*tasks)
        merged = set()
        for r in results:
            merged |= r
        return merged
