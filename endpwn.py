	#!/usr/bin/env python3
# endpwn.py — Bug Bounty Recon (JS Mapper)
# Python 3.13+

import argparse
import asyncio
import json
import re
from hashlib import sha256
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

# =========================
# Configuración
# =========================

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
TIMEOUT = 20.0
CONCURRENCY = 5
MAX_PAGES = 2000

# =========================
# Utilidades
# =========================

def normalize(base: str, link: str) -> Optional[str]:
    try:
        return urljoin(base, link.split("#")[0])
    except Exception:
        return None

def same_domain(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc

# =========================
# Crawler
# =========================

class Crawler:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.seen_pages: Set[str] = set()
        self.found_js: Set[str] = set()
        self.pages_scanned = 0

    async def crawl(self, start_urls: List[str]):
        for u in start_urls:
            await self.queue.put(u)
            self.seen_pages.add(u)

        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        ) as client:

            workers = [
                asyncio.create_task(self.worker(client, start_urls[0]))
                for _ in range(CONCURRENCY)
            ]
            await asyncio.gather(*workers)

    async def worker(self, client: httpx.AsyncClient, base: str):
        while not self.queue.empty() and self.pages_scanned < MAX_PAGES:
            url = await self.queue.get()

            try:
                r = await client.get(url)
                html = r.text or ""
            except httpx.HTTPError as e:
                print(f"[!] HTTP error en {url}: {e}")
                continue
            except Exception as e:
                print(f"[!] Error inesperado en {url}: {e}")
                continue

            self.pages_scanned += 1
            soup = BeautifulSoup(html, "html.parser")

            # -------- JS FILES --------
            for script in soup.find_all("script", src=True):
                js = normalize(url, script["src"])
                if js and same_domain(js, base):
                    self.found_js.add(js)

            # -------- LINKS --------
            for a in soup.find_all("a", href=True):
                n = normalize(url, a["href"])
                if n and same_domain(n, base) and n not in self.seen_pages:
                    self.seen_pages.add(n)
                    await self.queue.put(n)

# =========================
# CLI
# =========================

def parse_args():
    ap = argparse.ArgumentParser("endpwn — JS file mapper (bug bounty)")
    ap.add_argument("-u", "--url", required=True, help="Target (ej: example.com)")
    ap.add_argument("--json", help="Guardar JS encontrados en JSON")
    return ap.parse_args()

async def main():
    args = parse_args()
    base = args.url if args.url.startswith("http") else "https://" + args.url
    base = base.rstrip("/")

    crawler = Crawler()
    await crawler.crawl([base])

    print(f"\n[+] Páginas escaneadas: {crawler.pages_scanned}")
    print(f"[+] Archivos JS encontrados: {len(crawler.found_js)}\n")

    for js in sorted(crawler.found_js):
        print(js)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(sorted(crawler.found_js), f, indent=2)
        print(f"\n[+] JSON guardado en {args.json}")

if __name__ == "__main__":
    asyncio.run(main())
