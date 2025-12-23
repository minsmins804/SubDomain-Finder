import asyncio
import logging
from typing import List, Set
import aiohttp
from bs4 import BeautifulSoup
import json
import os
from dotenv import load_dotenv

load_dotenv()

class ServiceScanner:
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger('subdomainfinder.services')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')

    # -----------------------------
    # 1) VIRUSTOTAL (cũ)
    # -----------------------------
    async def _search_virustotal(self, session: aiohttp.ClientSession) -> Set[str]:
        if not self.virustotal_api_key:
            return set()

        url = "https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': self.virustotal_api_key, 'domain': self.domain}

        try:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return set(data.get('subdomains', []))
        except:
            pass
        return set()

    # -----------------------------
    # 2) DNSDumpster (cũ)
    # -----------------------------
    async def _search_dnsdumpster(self, session: aiohttp.ClientSession) -> Set[str]:
        url = "https://dnsdumpster.com/"
        subdomains = set()

        try:
            async with session.get(url) as response:
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                csrf_elem = soup.find('input', {'name': 'csrfmiddlewaretoken'})
                if not csrf_elem:
                    return subdomains

                csrf_token = csrf_elem.get('value')
                headers = {
                    'Referer': url,
                    'Cookie': f'csrftoken={csrf_token}',
                    'User-Agent': 'Mozilla/5.0'
                }
                data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'targetip': self.domain
                }

                async with session.post(url, headers=headers, data=data) as search_response:
                    html = await search_response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    tables = soup.findAll('table')
                    for table in tables:
                        for row in table.findAll('tr'):
                            cols = row.findAll('td')
                            if cols:
                                s = cols[0].text.strip()
                                if s.endswith(self.domain):
                                    subdomains.add(s.lower())
        except:
            pass

        return subdomains

    # -----------------------------
    # 3) CRT.SH (cũ)
    # -----------------------------
    async def _search_crtsh(self, session: aiohttp.ClientSession) -> Set[str]:
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        subdomains = set()

        try:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        name = entry.get('name_value', '').lower()
                        if name.endswith(self.domain):
                            subdomains.add(name)
        except:
            pass

        return subdomains

    # ======================================
    # 🔥 THÊM 5 NGUỒN PASSIVE MỚI SIÊU MẠNH
    # ======================================

    # 4) WAYBACK MACHINE
    async def _search_wayback(self, session: aiohttp.ClientSession) -> Set[str]:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original"
        subs = set()

        try:
            async with session.get(url) as response:
                data = await response.json()
                for row in data[1:]:
                    host = row[0].split("/")[2]
                    if host.endswith(self.domain):
                        subs.add(host.lower())
        except:
            pass
        return subs

    # 5) BUFFERRUN / BUFOVER.RUN
    async def _search_bufferover(self, session: aiohttp.ClientSession) -> Set[str]:
        url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
        subs = set()
        try:
            async with session.get(url) as response:
                data = await response.json()
                for item in data.get("FDNS_A", []):
                    host = item.split(",")[-1]
                    if host.endswith(self.domain):
                        subs.add(host.lower())
        except:
            pass
        return subs

    # 6) THREATCROWD
    async def _search_threatcrowd(self, session: aiohttp.ClientSession) -> Set[str]:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        subs = set()
        try:
            async with session.get(url) as response:
                data = await response.json()
                for s in data.get("subdomains", []):
                    if s.endswith(self.domain):
                        subs.add(s.lower())
        except:
            pass
        return subs

    # 7) CERTSPOTTER
    async def _search_certspotter(self, session: aiohttp.ClientSession) -> Set[str]:
        url = f"https://api.certspotter.com/v1/issuances?domain=*.{self.domain}&include_subdomains=true&expand=dns_names"
        subs = set()
        try:
            async with session.get(url) as response:
                data = await response.json()
                for entry in data:
                    for dns in entry.get("dns_names", []):
                        if dns.endswith(self.domain):
                            subs.add(dns.lower())
        except:
            pass
        return subs

    # 8) ALIENVAULT OTX
    async def _search_otx(self, session: aiohttp.ClientSession) -> Set[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        subs = set()

        try:
            async with session.get(url) as response:
                data = await response.json()
                for item in data.get("passive_dns", []):
                    host = item.get("hostname", "")
                    if host.endswith(self.domain):
                        subs.add(host.lower())
        except:
            pass
        return subs

    # ======================================
    # RUN ALL SERVICES
    # ======================================

    async def scan(self) -> Set[str]:
        self.logger.info(f"Running passive service scan for {self.domain}")

        async with aiohttp.ClientSession() as session:
            tasks = [
                self._search_virustotal(session),
                self._search_dnsdumpster(session),
                self._search_crtsh(session),
                self._search_wayback(session),
                self._search_bufferover(session),
                self._search_threatcrowd(session),
                self._search_certspotter(session),
                self._search_otx(session),
            ]

            results = await asyncio.gather(*tasks)

        all_subs = set()
        for rs in results:
            all_subs.update(rs)

        self.logger.info(f"[Services] Found {len(all_subs)} subdomains")
        return all_subs
