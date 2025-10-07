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

    async def _search_virustotal(self, session: aiohttp.ClientSession) -> Set[str]:
        """Search VirusTotal for subdomains."""
        if not self.virustotal_api_key:
            self.logger.warning("VirusTotal API key not found. Skipping VirusTotal search.")
            return set()

        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {
            'apikey': self.virustotal_api_key,
            'domain': self.domain
        }

        try:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = data.get('subdomains', [])
                    return set(subdomains)
        except Exception as e:
            self.logger.error(f"Error querying VirusTotal: {str(e)}")
        
        return set()

    async def _search_dnsdumpster(self, session: aiohttp.ClientSession) -> Set[str]:
        """Search DNSDumpster for subdomains."""
        url = "https://dnsdumpster.com/"
        subdomains = set()

        try:
            # Get CSRF token
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']

                    # Submit search
                    headers = {
                        'Referer': url,
                        'Cookie': f'csrftoken={csrf_token}'
                    }
                    data = {
                        'csrfmiddlewaretoken': csrf_token,
                        'targetip': self.domain
                    }
                    async with session.post(url, headers=headers, data=data) as search_response:
                        if search_response.status == 200:
                            text = await search_response.text()
                            soup = BeautifulSoup(text, 'html.parser')
                            
                            # Extract subdomains from the table
                            tables = soup.findAll('table')
                            for table in tables:
                                if table.find('td', {'class': 'col-md-4'}):
                                    for row in table.findAll('tr'):
                                        cols = row.findAll('td')
                                        if cols and len(cols) >= 1:
                                            subdomain = cols[0].text.strip()
                                            if subdomain.endswith(self.domain):
                                                subdomains.add(subdomain)
        except Exception as e:
            self.logger.error(f"Error querying DNSDumpster: {str(e)}")

        return subdomains

    async def _search_crtsh(self, session: aiohttp.ClientSession) -> Set[str]:
        """Search crt.sh (Certificate Transparency) for subdomains."""
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
        except Exception as e:
            self.logger.error(f"Error querying crt.sh: {str(e)}")

        return subdomains

    async def scan(self) -> Set[str]:
        """Perform scanning using all available services."""
        self.logger.info(f"Starting service scan for {self.domain}")
        
        async with aiohttp.ClientSession() as session:
            tasks = [
                self._search_virustotal(session),
                self._search_dnsdumpster(session),
                self._search_crtsh(session)
            ]
            
            results = await asyncio.gather(*tasks)
            
            all_subdomains = set()
            for subdomains in results:
                all_subdomains.update(subdomains)

        self.logger.info(f"Service scan completed. Found {len(all_subdomains)} subdomains")
        return all_subdomains