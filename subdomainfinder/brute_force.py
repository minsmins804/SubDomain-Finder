import asyncio
import logging
from pathlib import Path
from typing import List, Set
import dns.resolver
from tqdm import tqdm

class BruteForceScanner:
    def __init__(self, domain: str, wordlist_path: str, concurrency: int = 10):
        self.domain = domain
        self.wordlist_path = Path(wordlist_path)
        self.concurrency = concurrency
        self.logger = logging.getLogger('subdomainfinder.bruteforce')
        self.resolver = dns.resolver.Resolver()
        # Sử dụng Google DNS và Cloudflare DNS
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']

    async def _resolve_subdomain(self, subdomain: str) -> str:
        """Attempt to resolve a subdomain."""
        try:
            # Chạy DNS query trong thread pool để không block event loop
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.resolver.resolve, subdomain, 'A')
            return subdomain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None
        except Exception as e:
            self.logger.debug(f"Error resolving {subdomain}: {str(e)}")
            return None

    async def _process_chunk(self, chunk: List[str]) -> Set[str]:
        """Process a chunk of subdomains concurrently."""
        tasks = []
        for word in chunk:
            subdomain = f"{word}.{self.domain}"
            tasks.append(self._resolve_subdomain(subdomain))

        results = await asyncio.gather(*tasks)
        return {r for r in results if r is not None}

    async def scan(self) -> Set[str]:
        """Perform brute force scanning of subdomains."""
        self.logger.info(f"Starting brute force scan for {self.domain}")
        
        with open(self.wordlist_path) as f:
            wordlist = [line.strip() for line in f if line.strip()]

        discovered = set()
        chunk_size = self.concurrency
        chunks = [wordlist[i:i + chunk_size] for i in range(0, len(wordlist), chunk_size)]

        for chunk in tqdm(chunks, desc="Brute forcing subdomains"):
            chunk_results = await self._process_chunk(chunk)
            discovered.update(chunk_results)

        self.logger.info(f"Brute force scan completed. Found {len(discovered)} subdomains")
        return discovered