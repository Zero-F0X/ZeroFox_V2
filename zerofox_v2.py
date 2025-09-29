#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fast async XSS scanner (authorized use only).
- Uses asyncio + httpx.AsyncClient for high throughput.
- Reuses connections, supports optional rotating proxies.
- Two-stage approach: quick smoke test (small payload list) then full fuzz on positives.
- Batch writes evidence to disk.
"""

import asyncio
import os
import re
import sys
import time
import random
import argparse
import urllib.parse
from itertools import cycle
from typing import List, Optional, Tuple, Dict, Set

import httpx
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init
import aiofiles

colorama_init(autoreset=True)

# -------------------------
# Config (tweak)
# -------------------------
XSS_PAYLOAD_FILE = "xss.txt"       # full payload list
SMOKE_PAYLOAD_FILE = None          # optional separate smoke payload file (if None, use top N from xss.txt)
SMOKE_PAYLOAD_COUNT = 30          # number of quick payloads to test first
OUTDIR = "output_async"
CONCURRENCY = 150                 # total simultaneous requests
RATE_LIMIT_PER_HOST = 0.02       # minimal delay per-host between requests (seconds)
MAX_REQUESTS_PER_SECOND = 300    # global throttle (safety)
REQUEST_TIMEOUT = 6.0
VERIFY_TLS = False               # set True if you want verification
SAVE_EVIDENCE = True
BATCH_EVIDENCE_FLUSH = 20        # write evidence to disk in batches

# Optional proxy list (round-robin). Put proxies as "http://user:pass@ip:port" or "http://ip:port"
proxies_list: List[str] = []


# -------------------------
# Helpers
# -------------------------
def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)
    return path

def load_payloads(path: str) -> List[str]:
    if not os.path.exists(path):
        print(Fore.YELLOW + f"[!] Payload file not found: {path}" + Style.RESET_ALL)
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()]
    print(Fore.GREEN + f"[i] Loaded {len(lines)} payloads from {path}" + Style.RESET_ALL)
    return lines

def inject_payload(url: str, payload: str) -> str:
    # inject the url-encoded payload into each param value (fast)
    if "?" not in url:
        return url
    base, qs = url.split("?", 1)
    parts = []
    for p in qs.split("&"):
        if "=" in p:
            k, v = p.split("=", 1)
            parts.append(f"{k}={urllib.parse.quote(payload)}")
        else:
            parts.append(f"{p}={urllib.parse.quote(payload)}")
    return f"{base}?{'&'.join(parts)}"

def safe_name_for_file(s: str) -> str:
    return re.sub(r'[^0-9A-Za-z\-_\.]', '_', s)[:200]

# Basic filter for wayback / crawl results: keep only parameterized URLs
def filter_parameterized(urls: List[str], limit: Optional[int]=None) -> List[str]:
    out = [u for u in urls if "?" in u or "=" in u]
    # dedupe preserve order
    seen = set()
    dedup = []
    for u in out:
        if u not in seen:
            seen.add(u)
            dedup.append(u)
    if limit:
        return dedup[:limit]
    return dedup

# -------------------------
# Async HTTP utilities
# -------------------------
class HostRateLimiter:
    """Simple per-host rate limiter using last request timestamps."""
    def __init__(self, min_delay: float):
        self.min_delay = min_delay
        self._last: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def wait(self, host: str):
        async with self._lock:
            now = time.monotonic()
            last = self._last.get(host, 0.0)
            wait_for = self.min_delay - (now - last)
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last[host] = time.monotonic()

# Global rate manager (simple token bucket)
class GlobalRateLimiter:
    def __init__(self, rps: int):
        self._interval = 1.0 / max(1, rps)
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self._interval:
                await asyncio.sleep(self._interval - elapsed)
            self._last = time.monotonic()

# -------------------------
# Scanner core (async)
# -------------------------
async def fetch_text(client: httpx.AsyncClient, url: str, timeout: float) -> Optional[str]:
    try:
        r = await client.get(url, timeout=timeout)
        return r.text or ""
    except Exception:
        return None

async def test_payloads_on_url(client: httpx.AsyncClient, url: str, payloads: List[str], timeout: float) -> Optional[Tuple[str, str, str]]:
    """
    Try payloads on a single URL. Return first successful (test_url, payload, raw_text).
    """
    for p in payloads:
        test_url = inject_payload(url, p)
        text = await fetch_text(client, test_url, timeout)
        if text is None:
            continue
        dec = urllib.parse.unquote_plus(p)
        if p in text or dec in text:
            return (test_url, p, text)
    return None

async def worker_job(url: str,
                     smoke_payloads: List[str],
                     full_payloads: Optional[List[str]],
                     session_factory,
                     host_rl: HostRateLimiter,
                     global_rl: GlobalRateLimiter,
                     found_queue: asyncio.Queue,
                     timeout: float):
    """
    2-stage: quick smoke test (smoke_payloads). If positive and full_payloads provided, run full fuzzing (full_payloads).
    session_factory -> returns httpx.AsyncClient (preconfigured) for this job (for proxy rotation).
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    # respect small delays
    await host_rl.wait(host)
    await global_rl.wait()

    client: httpx.AsyncClient = session_factory()
    try:
        # smoke stage
        res = await test_payloads_on_url(client, url, smoke_payloads, timeout)
        if res:
            test_url, p, text = res
            await found_queue.put((test_url, p, text))
            # run full fuzz only if full_payloads provided
            if full_payloads:
                # small delay before heavy fuzz to avoid burst
                await asyncio.sleep(0.01)
                full_res = await test_payloads_on_url(client, url, full_payloads, timeout)
                if full_res:
                    await found_queue.put(full_res)
    finally:
        await client.aclose()

# -------------------------
# Session factory (for proxy rotation)
# -------------------------
def make_session_factory(proxies_cycle: Optional[cycle], verify_tls: bool, limits: Optional[httpx.Limits]=None):
    """
    Returns a function that creates AsyncClient instances.
    If proxies_cycle is provided, it's used round-robin per client.
    """
    def factory():
        proxy = None
        if proxies_cycle:
            proxy = next(proxies_cycle)
        client = httpx.AsyncClient(http2=True,
                                   verify=verify_tls,
                                   timeout=REQUEST_TIMEOUT,
                                   limits=limits)
        if proxy:
            client._transport._pool.max_keepalive = 5  # small tweak if underlying transport is available
            client._proxies = {"all://": proxy}  # httpx low-level proxies; works for simple rotation
        return client
    return factory

# -------------------------
# Simple crawler / wayback loader (sync, light)
# -------------------------
def load_wayback(domain: str, limit: int = 1000) -> List[str]:
    # keep this small / fast by limiting results
    try:
        import requests
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
        r = requests.get(url, timeout=12)
        lines = [l.strip() for l in r.text.splitlines() if l.strip()]
        return lines[:limit]
    except Exception:
        return []

def crawl_site(start_url: str, max_depth: int = 1, max_pages: int = 300) -> List[str]:
    from urllib.parse import urljoin
    domain = urllib.parse.urlparse(start_url).netloc
    visited = set()
    q = [(start_url, 0)]
    found = []
    while q and len(visited) < max_pages:
        url, depth = q.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            import requests
            r = requests.get(url, timeout=6, verify=False)
            soup = BeautifulSoup(r.text or "", "html.parser")
            for link in soup.find_all("a", href=True):
                full = urljoin(url, link['href'])
                if domain in full and full not in visited:
                    if "?" in full or "=" in full:
                        found.append(full)
                    q.append((full, depth + 1))
        except Exception:
            continue
    return sorted(set(found))

# -------------------------
# Orchestration
# -------------------------
async def run_scan(urls: List[str],
                   smoke_payloads: List[str],
                   full_payloads: Optional[List[str]],
                   concurrency: int,
                   proxies: List[str]):
    ensure_dir(OUTDIR)
    # limits for httpx AsyncClient (connections)
    limits = httpx.Limits(max_keepalive_connections=concurrency//2 or 10,
                          max_connections=concurrency*2 or 100)

    proxies_cycle = cycle(proxies) if proxies else None
    session_factory = make_session_factory(proxies_cycle, verify_tls=VERIFY_TLS, limits=limits)

    host_rl = HostRateLimiter(RATE_LIMIT_PER_HOST)
    global_rl = GlobalRateLimiter(MAX_REQUESTS_PER_SECOND)

    sem = asyncio.Semaphore(concurrency)
    found_queue: asyncio.Queue = asyncio.Queue()
    tasks = []

    async def sem_job(u):
        async with sem:
            await worker_job(u, smoke_payloads, full_payloads, session_factory, host_rl, global_rl, found_queue, REQUEST_TIMEOUT)

    # spawn tasks
    for u in urls:
        tasks.append(asyncio.create_task(sem_job(u)))

    # consumer for found_queue: batch write evidence
    hits_set: Set[str] = set()
    evidence_batch = []

    async def consumer():
        nonlocal evidence_batch
        while True:
            try:
                item = await asyncio.wait_for(found_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                # stop condition: if all tasks done and queue empty
                if all(t.done() for t in tasks) and found_queue.empty():
                    break
                else:
                    continue
            if not item:
                continue
            test_url, payload, text = item
            if test_url not in hits_set:
                hits_set.add(test_url)
                evidence_batch.append((test_url, payload, text))
            # flush in batch
            if len(evidence_batch) >= BATCH_EVIDENCE_FLUSH:
                await flush_evidence(evidence_batch)
                evidence_batch = []
    # run producer and consumer
    consumer_task = asyncio.create_task(consumer())
    await asyncio.gather(*tasks)
    # ensure consumer finishes
    await consumer_task
    # final flush
    if evidence_batch:
        await flush_evidence(evidence_batch)

    # save hits
    hits_file = os.path.join(OUTDIR, "xss_found_urls.txt")
    async with aiofiles.open(hits_file, "w", encoding="utf-8") as f:
        for h in sorted(hits_set):
            await f.write(h + "\n")

    print(Fore.GREEN + f"[✓] Done. Found {len(hits_set)} unique hits. Results in {hits_file}" + Style.RESET_ALL)
    return sorted(hits_set)

async def flush_evidence(batch):
    ev_dir = ensure_dir(os.path.join(OUTDIR, "evidence"))
    for test_url, payload, text in batch:
        safe = safe_name_for_file(test_url)
        fn = os.path.join(ev_dir, f"{safe}__resp.html")
        try:
            async with aiofiles.open(fn, "w", encoding="utf-8") as f:
                await f.write(f"<!-- payload: {payload} -->\n")
                await f.write(text or "")
        except Exception:
            pass

# -------------------------
# CLI + runner
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Fast Async XSS Scanner (authorized only)")
    p.add_argument("--targets", "-t", required=False, help="Single domain (domain.com) or path to file with URLs (one per line)")
    p.add_argument("--workers", type=int, default=CONCURRENCY, help="Concurrency (default configured)")
    p.add_argument("--proxies", help="Optional file with proxies (one per line)")
    p.add_argument("--limit-urls", type=int, default=0, help="Limit number of parameterized URLs to scan (0 = no limit)")
    return p.parse_args()

def gather_target_urls(arg_target: Optional[str], limit: int=0) -> List[str]:
    # if arg_target is a file => read URLs; if domain => query wayback and crawl; else error
    if not arg_target:
        print(Fore.RED + "[!] No target provided." + Style.RESET_ALL)
        sys.exit(1)
    if os.path.exists(arg_target):
        with open(arg_target, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
        return filter_parameterized(urls, limit if limit>0 else None)
    # treat as domain (domain.com)
    domain = arg_target.strip()
    print(Fore.CYAN + f"[~] Gathering URLs from Wayback + quick crawl for {domain} ..." + Style.RESET_ALL)
    wayback = load_wayback(domain, limit=1000)
    crawled = crawl_site(f"http://{domain}", max_depth=1, max_pages=200)
    combined = list(dict.fromkeys(wayback + crawled))  # dedupe preserving order
    return filter_parameterized(combined, limit if limit>0 else None)

def load_proxies_from_file(path: Optional[str]) -> List[str]:
    if not path:
        return []
    if not os.path.exists(path):
        print(Fore.YELLOW + f"[!] Proxy file not found: {path}" + Style.RESET_ALL)
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip()]

def chunk_smoke_payloads(payloads: List[str], count: int) -> List[str]:
    if not payloads:
        return []
    # pick top N unique payloads (common ones)
    return payloads[:count]

def main():
    args = parse_args()
    proxies = load_proxies_from_file(args.proxies) if args.proxies else proxies_list
    targets = gather_target_urls(args.targets, limit=args.limit_urls)
    if not targets:
        print(Fore.YELLOW + "[!] No parameterized URLs found to scan." + Style.RESET_ALL)
        return

    # load payloads
    full_payloads = load_payloads(XSS_PAYLOAD_FILE)
    if SMOKE_PAYLOAD_FILE:
        smoke_payloads = load_payloads(SMOKE_PAYLOAD_FILE)
    else:
        smoke_payloads = chunk_smoke_payloads(full_payloads, SMOKE_PAYLOAD_COUNT)

    print(Fore.GREEN + f"[i] Targets to scan: {len(targets)} URLs" + Style.RESET_ALL)
    print(Fore.GREEN + f"[i] Concurrency: {args.workers}, Proxies: {len(proxies)}" + Style.RESET_ALL)
    # run
    asyncio.run(run_scan(targets, smoke_payloads, full_payloads, args.workers, proxies))

if __name__ == "__main__":
    main()
