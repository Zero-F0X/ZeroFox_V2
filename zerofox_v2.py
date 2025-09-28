#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ZeroFox v2 - Fast + Realtime XSS Reporting + Spooky UI
# Use ONLY on authorized targets.

import os
import sys
import time
import random
import re
import urllib.parse
import subprocess
import requests
import urllib3
import threading
import queue
import argparse
from functools import partial
import concurrent.futures

# Third-party
try:
    from colorama import Fore, Back, Style, init as colorama_init
    from bs4 import BeautifulSoup
except Exception as e:
    print("Missing dependencies. Install with: pip install requests beautifulsoup4 colorama")
    raise e

# Optional playwright
HEADLESS_ENABLED = True
_playwright_available = False
if HEADLESS_ENABLED:
    try:
        from playwright.sync_api import sync_playwright
        _playwright_available = True
    except Exception:
        _playwright_available = False

colorama_init(autoreset=True)
urllib3.disable_warnings()

# -------------------------
# CONFIG (default values, can be overridden by CLI)
# -------------------------
XSS_PAYLOAD_FILE = "xss.txt"
RATE_LIMIT = 0.10
REQUEST_TIMEOUT = 8
SHORT_TIMEOUT = 3
SAVE_EVIDENCE = True
PLAYWRIGHT_LAUNCH_OPTIONS = {"headless": True, "timeout": 15000}
MAX_WORKERS = 8
UI_UPDATE_INTERVAL = 0.06

# -------------------------
# Fancy UI elements
# -------------------------
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(text, delay=0.005, end="\n"):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(end)
    sys.stdout.flush()

def typing_effect(lines, w_delay=0.01, between=0.12):
    for line in lines:
        slow_print(line, delay=w_delay)
        time.sleep(between)

def big_banner():
    banner = r"""
 ███████████ ██████████ ███████████      ███████       ███████████    ███████    █████ █████   
░█░░░░░░███ ░░███░░░░░█░░███░░░░░███   ███░░░░░███    ░░███░░░░░░█  ███░░░░░███ ░░███ ░░███    
░     ███░   ░███  █ ░  ░███    ░███  ███     ░░███    ░███   █ ░  ███     ░░███ ░░███ ███     
     ███     ░██████    ░██████████  ░███      ░███    ░███████   ░███      ░███  ░░█████      
    ███      ░███░░█    ░███░░░░░███ ░███      ░███    ░███░░░█   ░███      ░███   ███░███     
  ████     █ ░███ ░   █ ░███    ░███ ░░███     ███     ░███  ░    ░░███     ███   ███ ░░███    
 ███████████ ██████████ █████   █████ ░░░███████░      █████       ░░░███████░   █████ █████   
░░░░░░░░░░░ ░░░░░░░░░░ ░░░░░   ░░░░░    ░░░░░░░       ░░░░░          ░░░░░░░    ░░░░░ ░░░░░                                                            
    """
    print(Fore.RED + Style.BRIGHT + banner + Style.RESET_ALL)
    intro = [
        Fore.LIGHTBLACK_EX + "ZeroFox v2" + Style.RESET_ALL + " — Http Recon & XSS Scanner (authorized use only).",
        Fore.YELLOW + "Initializing modules..." + Style.RESET_ALL
    ]
    typing_effect(intro, w_delay=0.01, between=0.12)

def matrix_rain(lines=6, width=72, delay=0.015):
    charset = "01"
    for _ in range(lines):
        line = ''.join(random.choice(charset) for _ in range(width))
        print(Fore.GREEN + line + Style.RESET_ALL)
        time.sleep(delay)

def killer_startup_animation():
    clear_screen()
    big_banner()
    matrix_rain(lines=6, width=72, delay=0.015)
    print()

# -------------------------
# Helpers
# -------------------------
def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path

def save_list(path, items):
    ensure_dir(os.path.dirname(path) if os.path.dirname(path) else ".")
    with open(path, "w", encoding="utf-8") as f:
        for it in items:
            f.write(it + "\n")

def load_xss_payloads(path=XSS_PAYLOAD_FILE):
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="ignore") as f:
            payloads = [line.rstrip("\n") for line in f if line.strip()]
        print(Fore.GREEN + f"[i] Loaded {len(payloads)} payload(s) from {path}." + Style.RESET_ALL)
        return payloads
    else:
        print(Fore.YELLOW + f"[!] {path} not found — no XSS payloads loaded." + Style.RESET_ALL)
        return []

def inject_payload(url, payload):
    try:
        base, params = url.split("?", 1)
        new_params = "&".join(f"{p.split('=')[0]}={urllib.parse.quote(payload)}" for p in params.split("&"))
        return f"{base}?{new_params}"
    except Exception:
        return url

# -------------------------
# XSS Scanning (simplified)
# -------------------------
def _scan_url_worker(url, payloads, outdir, rate_limit, request_timeout):
    session = requests.Session()
    session.headers.update({"User-Agent": "ZeroFox-v2/1.0"})
    try:
        for payload in payloads:
            test_url = inject_payload(url, payload)
            try:
                r = session.get(test_url, timeout=request_timeout, verify=False)
                resp = r.text or ""
                if payload in resp or urllib.parse.unquote_plus(payload) in resp:
                    print(Fore.RED + f"[FOUND] {test_url}" + Style.RESET_ALL)
                    return test_url
            except Exception:
                pass
            finally:
                time.sleep(rate_limit)
    finally:
        session.close()
    return None

def optimized_scan_xss(urls, outdir, payloads):
    hits = []
    if not payloads:
        return hits

    target_urls = [u for u in urls if "?" in u]
    total_urls = len(target_urls)
    print(Fore.CYAN + f"[i] Starting XSS scan: {total_urls} parameterized URL(s)" + Style.RESET_ALL)

    workers = min(MAX_WORKERS, max(1, total_urls))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_scan_url_worker, u, payloads, outdir, RATE_LIMIT, SHORT_TIMEOUT): u for u in target_urls}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                hits.append(res)

    save_list(os.path.join(outdir, "xss_found_urls.txt"), hits)
    return hits

# -------------------------
# Other scans
# -------------------------
def find_urls(domain, outdir):
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey", timeout=15)
        urls = sorted(set(r.text.splitlines()))
        save_list(os.path.join(outdir, "urls.txt"), urls)
        return urls
    except Exception:
        return []

def crawl_site(start_url, outdir, max_depth=2):
    from urllib.parse import urljoin
    domain = urllib.parse.urlparse(start_url).netloc
    visited, queue_, found = set(), [(start_url, 0)], []
    while queue_:
        url, depth = queue_.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                full_url = urljoin(url, link['href'])
                if domain in full_url and full_url not in visited:
                    if "?" in full_url or "=" in full_url:
                        found.append(full_url)
                    queue_.append((full_url, depth + 1))
        except Exception:
            continue
    save_list(os.path.join(outdir, "crawled_urls.txt"), sorted(set(found)))
    return found

# -------------------------
# Flow
# -------------------------
def scan_all(urls, domain):
    outdir = f"output/{domain}"
    ensure_dir(outdir)
    payloads = load_xss_payloads(XSS_PAYLOAD_FILE)
    hits = optimized_scan_xss(urls, outdir, payloads)
    print(Fore.GREEN + f"[✓] Scan selesai — {len(hits)} bug ditemukan." + Style.RESET_ALL)

def scan_domain(domain):
    outdir = f"output/{domain}"
    ensure_dir(outdir)
    wayback = find_urls(domain, outdir)
    crawled = crawl_site(f"http://{domain}", outdir)
    urls = list(set(wayback + crawled))
    save_list(os.path.join(outdir, "all_urls.txt"), urls)
    scan_all(urls, domain)

# -------------------------
# CLI
# -------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="ZeroFox v2 — XSS Scanner (authorized use only)")
    parser.add_argument("--workers", type=int, default=8, help="Jumlah worker paralel (default: 8)")
    parser.add_argument("--rate-limit", type=float, default=0.10, help="Delay antar request (detik, default: 0.10)")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout request singkat (detik, default: 3)")
    return parser.parse_args()

def main():
    global MAX_WORKERS, RATE_LIMIT, SHORT_TIMEOUT
    args = parse_args()
    MAX_WORKERS = args.workers
    RATE_LIMIT = args.rate_limit
    SHORT_TIMEOUT = args.timeout

    killer_startup_animation()
    print(Fore.GREEN + f"\n[CFG] Workers={MAX_WORKERS}, RateLimit={RATE_LIMIT}s, ShortTimeout={SHORT_TIMEOUT}s" + Style.RESET_ALL)
    print(Fore.GREEN + "\n[MODE] 1 = Scan 1 domain | 2 = Multi scan (bulk.txt)\n" + Style.RESET_ALL)
    mode = input("Pilih mode (1/2): ").strip()
    if mode == '2':
        filepath = input("Masukkan path file list domain (contoh: targets.txt): ").strip()
        if not os.path.exists(filepath):
            print(Fore.RED + "[!] File tidak ditemukan." + Style.RESET_ALL)
            return
        with open(filepath) as f:
            targets = [line.strip() for line in f if line.strip()]
        for domain in targets:
            scan_domain(domain)
    else:
        domain = input(Fore.YELLOW + "[>] Masukkan domain target: " + Style.RESET_ALL).strip()
        scan_domain(domain)
    print(Fore.CYAN + "\n[✓] Semua proses selesai. Hasil ada di folder output/." + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Dibatalkan oleh user." + Style.RESET_ALL)
