#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xrayxss_cli.py — xray-like XSS scanner (single-file)
Use only on authorized targets.

Subcommands:
  webscan (alias xray webscan)  - like xray
  scan                         - run full pipeline (wayback+crawl+scan)
  crawl                        - just crawl + wayback gather
  proxy-check                  - test proxies in proxies.txt and write proxies_good.txt
  report                       - generate standalone HTML report from hits file

Example:
  python xrayxss_cli.py webscan --basic-crawler http://example.com --html-output vuln.html
  python xrayxss_cli.py scan --targets example.com --workers 150 --proxies proxies.txt --outdir output --html vuln.html --playwright
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
import urllib.parse
from itertools import cycle
from typing import List, Optional, Tuple, Dict, Set

import httpx
import requests
from bs4 import BeautifulSoup
import aiofiles

# optional Playwright
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

# optional colorama
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    class _C: 
        def __getattr__(self, k): return ""
    Fore = Style = _C()

# ---------------------
# Defaults & tuning
# ---------------------
SMOKE_DEFAULT = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]
XSS_PAYLOAD_FILE = "xss.txt"
OUTDIR_DEFAULT = "output_xrayxss"
DEFAULT_TEMPLATE = "dashboard_template.html"
CONCURRENCY_DEFAULT = 150
RATE_LIMIT_PER_HOST = 0.02
GLOBAL_RPS = 400
REQUEST_TIMEOUT = 8.0
SAVE_EVIDENCE = True

# ---------------------
# small helpers
# ---------------------
def ensure_dir(p): os.makedirs(p, exist_ok=True); return p
def safe_name_for_file(s: str) -> str:
    return re.sub(r'[^0-9A-Za-z\-_\.]', '_', s)[:220]
def load_payloads(path: str) -> List[str]:
    if os.path.exists(path):
        with open(path, encoding='utf-8', errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    return []

# ---------------------
# inject payload into query string (all params)
# ---------------------
def inject_payload(url: str, payload: str) -> str:
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

# ---------------------
# Wayback + crawler
# ---------------------
def load_wayback(domain: str, limit: int = 500) -> List[str]:
    out = []
    try:
        q = urllib.parse.quote(f"*.{domain}/*")
        url = f"http://web.archive.org/cdx/search/cdx?url={q}&output=json&fl=original&collapse=urlkey&limit={limit}"
        r = requests.get(url, timeout=12, headers={"User-Agent":"xrayxss/1.0"})
        r.raise_for_status()
        data = r.json()
        for item in data[1:]:
            cand = item[0] if isinstance(item, list) else item
            if cand and cand not in out:
                out.append(cand)
            if len(out) >= limit:
                break
    except Exception:
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

def extract_param_urls_from_html(text: str, base_url: str) -> List[str]:
    out = []
    try:
        soup = BeautifulSoup(text, "html.parser")
        for a in soup.find_all("a", href=True):
            full = urllib.parse.urljoin(base_url, a['href'])
            if "?" in full or "=" in full:
                out.append(full)
        for form in soup.find_all("form", action=True):
            act = urllib.parse.urljoin(base_url, form['action'])
            if "?" in act or "=" in act:
                out.append(act)
            else:
                inputs = [i.get("name") for i in form.find_all("input", attrs={"name": True})]
                if inputs:
                    qs = "&".join(f"{n}=1" for n in inputs)
                    out.append(act + ("?" + qs if "?" not in act else "&" + qs))
    except Exception:
        pass
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
            soup = BeautifulSoup(r.text or "", "html.parser")
            for link in soup.find_all("a", href=True):
                full = urljoin(url, link['href'])
                if domain in urllib.parse.urlparse(full).netloc and full not in visited:
                    q.append((full, depth+1))
        except Exception:
            continue
    return sorted(set(found))

# ---------------------
# rate limiters + httpx helpers
# ---------------------
class HostRateLimiter:
    def __init__(self, min_delay: float):
        self.min_delay = min_delay
        self._last: Dict[str, float] = {}
        self._lock = asyncio.Lock()
    async def wait(self, host: str):
        async with self._lock:
            now = time.monotonic(); last = self._last.get(host, 0.0)
            wait_for = self.min_delay - (now - last)
            if wait_for > 0: await asyncio.sleep(wait_for)
            self._last[host] = time.monotonic()

class GlobalRateLimiter:
    def __init__(self, rps: int):
        self._interval = 1.0 / max(1, rps); self._lock = asyncio.Lock(); self._last = 0.0
    async def wait(self):
        async with self._lock:
            now = time.monotonic(); elapsed = now - self._last
            if elapsed < self._interval: await asyncio.sleep(self._interval - elapsed)
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
        if text is None: continue
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

# ---------------------
# Playwright verification
# ---------------------
async def playwright_verify(url: str, payload: str, timeout=12.0) -> bool:
    if not PLAYWRIGHT_AVAILABLE: return False
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(url, timeout=timeout*1000)
            await asyncio.sleep(1.0)
            content = await page.content()
            await browser.close()
            return payload in content
    except Exception:
        return False

# ---------------------
# Dashboard helpers (inject receiveReport into template)
# ---------------------
async def write_dashboard_initial(outdir: str, html_filename: str, template_path: Optional[str]=None):
    ensure_dir(outdir)
    path = os.path.join(outdir, html_filename)
    if template_path and os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8", errors="ignore") as f:
            tpl = f.read()
        if "function receiveReport" not in tpl:
            insert = """
<script>
function receiveReport(obj){
  try{
    if(typeof receiveReportFallback === 'function'){ receiveReportFallback(obj); return; }
    const t = document.getElementById('reports');
    if(t){
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>-</td><td title=\"${obj.url}\">${obj.url}</td><td><code>${(obj.payload||'')}</code></td><td><span class='tag vuln'>${obj.status||'vulnerable'}</span></td><td>${obj.ts||''}</td><td><a class='btn ghost' href='./evidence/${obj.safe || ''}__resp.html' target='_blank'>Open</a></td>`;
      t.prepend(tr);
    }
  }catch(e){console.error('receiveReport error',e)}
}
</script>
</body>"""
            tpl = tpl.replace("</body>", insert)
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(tpl)
    else:
        simple = """<!doctype html><html><head><meta charset="utf-8"><title>xrayxss live</title></head><body><h1>xrayxss live</h1><table><thead><tr><th>#</th><th>URL</th><th>Payload</th><th>Status</th><th>Timestamp</th><th>Evidence</th></tr></thead><tbody id='reports'></tbody></table><script>function receiveReport(o){const t=document.getElementById('reports');const tr=document.createElement('tr');tr.innerHTML=`<td>-</td><td>${o.url}</td><td><code>${o.payload}</code></td><td>${o.status}</td><td>${o.ts}</td><td><a target='_blank' href='./evidence/${o.safe}__resp.html'>Open</a></td>`;t.prepend(tr);}</script></body></html>"""
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(simple)
    return path

async def append_to_dashboard(outdir: str, html_filename: str, url: str, payload: str, status: str='vulnerable', safe_name: str=""):
    path = os.path.join(outdir, html_filename)
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    obj = {'url': url, 'payload': payload, 'status': status, 'ts': ts, 'safe': safe_name}
    js = f"<script>try{{ if(typeof receiveReport==='function') receiveReport({json.dumps(obj)}); else console.warn('no receiveReport'); }}catch(e){{console.error(e)}}</script>\n"
    async with aiofiles.open(path, "a", encoding="utf-8") as f:
        await f.write(js)

# ---------------------
# proxy health-check helper (sync simple)
# ---------------------
def proxy_health_check_sync(proxy: str, test_url="https://httpbin.org/ip", timeout=8.0):
    try:
        r = requests.get(test_url, proxies={"http": proxy, "https": proxy}, timeout=timeout)
        if r.status_code == 200:
            return True, r.text.strip()
    except Exception as e:
        return False, str(e)
    return False, "unknown"

# ---------------------
# Orchestration
# ---------------------
async def worker_job(url: str, smoke_payloads: List[str], full_payloads: Optional[List[str]], session_factory, host_rl: HostRateLimiter, global_rl: GlobalRateLimiter, found_q: asyncio.Queue, timeout: float):
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    await host_rl.wait(host)
    await global_rl.wait()
    client: httpx.AsyncClient = session_factory()
    try:
        res = await test_payloads_on_url(client, url, smoke_payloads, timeout)
        if res:
            test_url, p, text = res
            await found_q.put((test_url, p, text, url))
            if full_payloads:
                await asyncio.sleep(0.01)
                full_res = await test_payloads_on_url(client, url, full_payloads, timeout)
                if full_res:
                    await found_q.put((full_res[0], full_res[1], full_res[2], url))
    finally:
        await client.aclose()

async def run_scan(urls: List[str], smoke_payloads: List[str], full_payloads: Optional[List[str]], concurrency: int, proxies: List[str], outdir: str, html_filename: str, verify_with_playwright: bool, template_path: Optional[str]=None):
    ensure_dir(outdir)
    await write_dashboard_initial(outdir, html_filename, template_path)
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

    async def consumer():
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
                verified = False
                if verify_with_playwright:
                    verified = await playwright_verify(test_url, payload, timeout=12.0)
                status = 'vulnerable' if (verified or not verify_with_playwright) else 'suspect'
                safe_name = safe_name_for_file(test_url)
                await append_to_dashboard(outdir, html_filename, test_url if (verified or not verify_with_playwright) else original, payload, status, safe_name)
                print(Fore.MAGENTA + Style.BRIGHT + f"[>>> FOUND] {test_url} payload={payload} verified={verified}" + Style.RESET_ALL)
    consumer_task = asyncio.create_task(consumer())
    await asyncio.gather(*tasks)
    await consumer_task

    hits_file = os.path.join(outdir, "xss_found_urls.txt")
    async with aiofiles.open(hits_file, "w", encoding="utf-8") as f:
        for h in sorted(hits_set):
            await f.write(h + "\n")

    print(Fore.GREEN + f"[✓] Scan finished. {len(hits_set)} hits. Report: {os.path.join(outdir, html_filename)} and {hits_file}" + Style.RESET_ALL)

# ---------------------
# CLI: subcommands
# ---------------------
def cmd_proxy_check(args):
    if not args.proxies or not os.path.exists(args.proxies):
        print(Fore.YELLOW + "[!] proxies file not found" + Style.RESET_ALL); return
    with open(args.proxies, encoding='utf-8') as f:
        proxies = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
    good = []
    print(f"[i] Testing {len(proxies)} proxies...")
    for p in proxies:
        ok, info = proxy_health_check_sync(p)
        print(f" - {p} -> ok={ok}")
        if ok: good.append(p)
    out = args.out or "proxies_good.txt"
    with open(out, "w", encoding='utf-8') as f:
        for g in good: f.write(g + "\n")
    print(Fore.GREEN + f"[✓] good proxies saved to {out}" + Style.RESET_ALL)

def cmd_crawl(args):
    t = args.target
    limit = args.limit or 500
    print(Fore.CYAN + f"[~] Wayback + crawl for {t} (limit={limit})" + Style.RESET_ALL)
    wayback = load_wayback(t, limit=limit)
    crawled = crawl_site(f"http://{t}", max_depth=args.depth or 1, max_pages=args.max or 200)
    combined = list(dict.fromkeys(wayback + crawled))
    paramed = [u for u in combined if ("?" in u or "=" in u)]
    out = args.out or "crawled_urls.txt"
    with open(out, "w", encoding='utf-8') as f:
        for u in paramed: f.write(u + "\n")
    print(Fore.GREEN + f"[✓] saved {len(paramed)} parameterized urls to {out}" + Style.RESET_ALL)

def cmd_report(args):
    outdir = args.outdir or OUTDIR_DEFAULT
    hits = []
    hits_file = os.path.join(outdir, "xss_found_urls.txt")
    if os.path.exists(hits_file):
        with open(hits_file, encoding='utf-8') as f:
            hits = [l.strip() for l in f if l.strip()]
    if not hits:
        print(Fore.YELLOW + "[!] no hits file found" + Style.RESET_ALL); return
    # build simple HTML (or reuse template)
    template = args.template if args.template and os.path.exists(args.template) else None
    async def build():
        await write_dashboard_initial(outdir, args.html or "report.html", template)
        # optionally append rows from evidence
        for h in hits:
            safe = safe_name_for_file(h)
            await append_to_dashboard(outdir, args.html or "report.html", h, "(payload unknown)", "vulnerable", safe)
    asyncio.run(build())
    print(Fore.GREEN + f"[✓] report ready: {os.path.join(outdir, args.html or 'report.html')}" + Style.RESET_ALL)

def cmd_webscan(argv):
    # emulate `xray webscan --basic-crawler target --html-output file`
    parser = argparse.ArgumentParser(prog="xray webscan")
    parser.add_argument("--basic-crawler", required=True)
    parser.add_argument("--html-output", default="vuln.html")
    parser.add_argument("--workers", type=int, default=CONCURRENCY_DEFAULT)
    parser.add_argument("--proxies")
    parser.add_argument("--limit-urls", type=int, default=0)
    parser.add_argument("--playwright", action="store_true")
    ns = parser.parse_args(argv)
    # map to main scan
    args = argparse.Namespace(
        targets=ns.basic_crawler,
        workers=ns.workers,
        proxies=ns.proxies,
        outdir=OUTDIR_DEFAULT,
        html_output=ns.html_output,
        template=None,
        limit_urls=ns.limit_urls,
        playwright=ns.playwright
    )
    # call scan flow
    asyncio.run(flow_scan(args))

async def flow_scan(ns):
    # gather targets
    targets_arg = ns.targets
    workers = ns.workers
    proxies_path = ns.proxies
    outdir = ns.outdir
    html_output = ns.html_output
    limit_urls = ns.limit_urls
    template = ns.template
    verify_play = ns.playwright

    proxies = []
    if proxies_path and os.path.exists(proxies_path):
        with open(proxies_path, encoding='utf-8') as f:
            proxies = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]

    # gather urls
    print(Fore.CYAN + f"[~] gathering urls for {targets_arg}" + Style.RESET_ALL)
    urls = []
    if os.path.exists(targets_arg):
        with open(targets_arg, encoding='utf-8') as f:
            urls = [l.strip() for l in f if l.strip()]
        urls = [u for u in urls if ("?" in u or "=" in u)]
    else:
        domain = targets_arg.strip()
        wayback = load_wayback(domain, limit=limit_urls if limit_urls>0 else 500)
        crawled = crawl_site(f"http://{domain}", max_depth=1, max_pages=200)
        combined = list(dict.fromkeys(wayback + crawled))
        urls = [u for u in combined if ("?" in u or "=" in u)]
        if limit_urls and limit_urls>0:
            urls = urls[:limit_urls]

    if not urls:
        print(Fore.YELLOW + "[!] no parameterized urls found, exiting" + Style.RESET_ALL); return

    full_payloads = load_payloads(XSS_PAYLOAD_FILE)
    smoke = SMOKE_DEFAULT.copy()
    if full_payloads:
        smoke = full_payloads[:min(len(full_payloads), 30)]

    print(Fore.GREEN + f"[i] scanning {len(urls)} urls | workers={workers} | proxies={len(proxies)}" + Style.RESET_ALL)
    await run_scan(urls, smoke, full_payloads, workers, proxies, outdir, html_output, verify_play, template)

def cmd_scan(args):
    asyncio.run(flow_scan(args))

# ---------------------
# main entrypoint
# ---------------------
def main():
    parser = argparse.ArgumentParser(prog="xrayxss", description="xray-like XSS scanner")
    sub = parser.add_subparsers(dest="cmd", required=False)

    p_scan = sub.add_parser("scan", help="gather and scan a target (wayback+crawl+scan)")
    p_scan.add_argument("--targets","-t", required=True)
    p_scan.add_argument("--workers", type=int, default=CONCURRENCY_DEFAULT)
    p_scan.add_argument("--proxies")
    p_scan.add_argument("--outdir", default=OUTDIR_DEFAULT)
    p_scan.add_argument("--html-output", default="vuln.html")
    p_scan.add_argument("--template")
    p_scan.add_argument("--limit-urls", type=int, default=0)
    p_scan.add_argument("--playwright", action="store_true")

    p_crawl = sub.add_parser("crawl", help="just crawl and wayback")
    p_crawl.add_argument("--target", required=True)
    p_crawl.add_argument("--limit", type=int, default=500)
    p_crawl.add_argument("--depth", type=int, default=1)
    p_crawl.add_argument("--max", type=int, default=200)
    p_crawl.add_argument("--out")

    p_pcheck = sub.add_parser("proxy-check", help="test proxies list")
    p_pcheck.add_argument("--proxies", required=True)
    p_pcheck.add_argument("--out", default="proxies_good.txt")

    p_report = sub.add_parser("report", help="build report from existing hits")
    p_report.add_argument("--outdir", default=OUTDIR_DEFAULT)
    p_report.add_argument("--html", default="report.html")
    p_report.add_argument("--template")

    # accept xray-style (webscan) too
    p_web = sub.add_parser("webscan", help="xray webscan alias")
    p_web.add_argument("--basic-crawler", required=True)
    p_web.add_argument("--html-output", default="vuln.html")
    p_web.add_argument("--workers", type=int, default=CONCURRENCY_DEFAULT)
    p_web.add_argument("--proxies")
    p_web.add_argument("--limit-urls", type=int, default=0)
    p_web.add_argument("--playwright", action="store_true")

    # if no subcommand, print help
    if len(sys.argv) <= 1:
        parser.print_help(); return

    args = parser.parse_args()

    if args.cmd == "proxy-check":
        cmd_proxy_check(args); return
    if args.cmd == "crawl":
        cmd_crawl(args); return
    if args.cmd == "report":
        cmd_report(args); return
    if args.cmd == "webscan":
        # map webscan to flow_scan
        ns = argparse.Namespace(
            targets=args.basic_crawler,
            workers=args.workers,
            proxies=args.proxies,
            outdir=OUTDIR_DEFAULT,
            html_output=args.html_output,
            template=None,
            limit_urls=args.limit_urls,
            playwright=args.playwright
        )
        asyncio.run(flow_scan(ns)); return
    if args.cmd == "scan":
        cmd_scan(args); return

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Aborted by user." + Style.RESET_ALL)
