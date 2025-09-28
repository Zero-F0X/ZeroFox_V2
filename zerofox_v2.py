#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ZeroFox v2 - XSS Scanner with scan-time loading animation
# Use ONLY on authorized targets.

import os
import sys
import time
import random
import re
import urllib.parse
import requests
import urllib3
import threading
import queue
import argparse
from functools import partial
import concurrent.futures

# Third-party
try:
    from colorama import Fore, Style, init as colorama_init
    from bs4 import BeautifulSoup
except Exception as e:
    print("Missing dependencies. Install with: pip install requests beautifulsoup4 colorama")
    raise e

# Optional Playwright (kept optional)
HEADLESS_ENABLED = False
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
# Defaults (override via CLI)
# -------------------------
XSS_PAYLOAD_FILE = "xss.txt"
RATE_LIMIT = 0.10
REQUEST_TIMEOUT = 8
SHORT_TIMEOUT = 3
SAVE_EVIDENCE = True
MAX_WORKERS = 8
UI_UPDATE_INTERVAL = 0.06

# -------------------------
# UI helpers
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

def typing_effect(lines, w_delay=0.01, between=0.10):
    for line in lines:
        slow_print(line, delay=w_delay)
        time.sleep(between)

def banner():
    b = r"""
 ███████████ ██████████ ███████████      ███████       ███████████
░█░░░░░░███ ░░███░░░░░█░░███░░░░░███   ███░░░░░███    ░░███░░░░░░█
░     ███░   ░███  █ ░  ░███    ░███  ███     ░░███    ░███   █ ░
     ███     ░██████    ░██████████  ░███      ░███    ░███████
    ███      ░███░░█    ░███░░░░░███ ░███      ░███    ░███░░░█
  ████     █ ░███ ░   █ ░███    ░███ ░░███     ███     ░███  ░
 ███████████ ██████████ █████   █████ ░░░███████░      █████
"""
    print(Fore.RED + Style.BRIGHT + b + Style.RESET_ALL)
    intro = [
        Fore.LIGHTBLACK_EX + "ZeroFox v2" + Style.RESET_ALL + " — XSS Scanner (authorized use only).",
        Fore.YELLOW + "Starting modules..." + Style.RESET_ALL
    ]
    typing_effect(intro, w_delay=0.01, between=0.08)

def startup_animation():
    clear_screen()
    banner()
    # small matrix
    for _ in range(4):
        line = "".join(random.choice("01") for _ in range(60))
        print(Fore.GREEN + line + Style.RESET_ALL)
        time.sleep(0.03)
    print()

# -------------------------
# File / payload helpers
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

def save_evidence_html(outdir, safe_name, payload, resp_text):
    ev_dir = ensure_dir(os.path.join(outdir, "evidence"))
    fn = os.path.join(ev_dir, f"{safe_name}.html")
    try:
        with open(fn, "w", encoding="utf-8") as f:
            f.write(f"<!-- payload: {payload} -->\n")
            f.write(resp_text)
    except Exception:
        pass
    return fn

# -------------------------
# Scan animation (spinner + progress + immediate found)
# -------------------------
def scan_animation(stop_event, counters, total, found_q):
    spinner = ["|", "/", "-", "\\"]
    width = 36
    idx = 0
    try:
        while not stop_event.is_set():
            scanned = counters.get("scanned", 0)
            found = counters.get("found", 0)
            pct = int((scanned / total) * 100) if total else 0
            filled = int((pct / 100) * width)
            bar = "█" * filled + "-" * (width - filled)
            spin = spinner[idx % len(spinner)]
            # clear small area
            sys.stdout.write("\x1b[2J\x1b[H")
            sys.stdout.write(Fore.CYAN + f" ZeroFox v2 — SCANNING\n" + Style.RESET_ALL)
            sys.stdout.write(Fore.YELLOW + f" [{spin}] {scanned}/{total} URLs scanned | Found: {found}\n" + Style.RESET_ALL)
            sys.stdout.write(Fore.RED + f" Progress: [{bar}] {pct}%\n" + Style.RESET_ALL)
            # show up to 4 immediate founds
            try:
                for _ in range(4):
                    u = found_q.get_nowait()
                    sys.stdout.write(Fore.MAGENTA + Style.BRIGHT + f" >>> FOUND: {u}\n" + Style.RESET_ALL)
            except queue.Empty:
                pass
            sys.stdout.flush()
            time.sleep(UI_UPDATE_INTERVAL * 6)
            idx += 1
    finally:
        sys.stdout.write("\x1b[2J\x1b[H")
        sys.stdout.flush()

# -------------------------
# Worker (fast checks)
# -------------------------
def _scan_url_worker(url, payloads, outdir, rate_limit, timeout, found_q):
    session = requests.Session()
    session.headers.update({"User-Agent": "ZeroFox-v2/1.0"})
    try:
        for p in payloads:
            test = inject_payload(url, p)
            try:
                r = session.get(test, timeout=timeout, verify=False)
                text = r.text or ""
                dec = urllib.parse.unquote_plus(p)
                if p in text or dec in text:
                    # save evidence quickly
                    safe = re.sub(r'[^0-9A-Za-z\-_\.]', '_', test)[:160]
                    if SAVE_EVIDENCE:
                        save_evidence_html(outdir, safe + "__resp", p, text)
                    found_q.put(test)
                    return test
            except Exception:
                pass
            finally:
                if rate_limit:
                    time.sleep(rate_limit)
    finally:
        try:
            session.close()
        except:
            pass
    return None

# -------------------------
# Optimized scan with animation + immediate reporting
# -------------------------
def optimized_scan_xss(urls, outdir, payloads, workers, rate_limit, timeout):
    hits = []
    target = [u for u in urls if "?" in u]
    total = len(target)
    print(Fore.CYAN + f"[i] Scanning {total} parameterized URLs with {workers} workers..." + Style.RESET_ALL)
    if total == 0 or not payloads:
        print(Fore.YELLOW + "[!] Nothing to scan (no parameterized URLs or no payloads)." + Style.RESET_ALL)
        return hits

    counters = {"scanned": 0, "found": 0}
    counters_lock = threading.Lock()
    found_q = queue.Queue()
    stop_anim = threading.Event()
    anim_thread = threading.Thread(target=scan_animation, args=(stop_anim, counters, total, found_q), daemon=True)
    anim_thread.start()

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    futures = []

    def _cb(fut, url):
        nonlocal counters
        try:
            res = fut.result()
            with counters_lock:
                counters["scanned"] += 1
                if res:
                    counters["found"] += 1
        except Exception as e:
            with counters_lock:
                counters["scanned"] += 1
            with open("scan_errors.log", "a", encoding="utf-8") as ef:
                ef.write(f"{time.asctime()} - error scanning {url}: {e}\n")

    try:
        for u in target:
            fut = executor.submit(_scan_url_worker, u, payloads, outdir, rate_limit, timeout, found_q)
            fut.add_done_callback(lambda f, url=u: _cb(f, url))
            futures.append(fut)

        # wait for completion; founds are printed via animation (from queue)
        concurrent.futures.wait(futures)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Aborted by user. Waiting for threads to finish..." + Style.RESET_ALL)
        executor.shutdown(wait=False)
    finally:
        try:
            executor.shutdown(wait=True)
        except:
            pass

    # stop animation and drain found queue
    stop_anim.set()
    anim_thread.join()
    while not found_q.empty():
        try:
            hits.append(found_q.get_nowait())
        except queue.Empty:
            break

    hits = sorted(set(hits))
    save_list(os.path.join(outdir, "xss_found_urls.txt"), hits)
    print(Fore.GREEN + f"[✓] Scan finished. {len(hits)} vulnerable endpoints found. Results saved to {outdir}/xss_found_urls.txt" + Style.RESET_ALL)
    return hits

# -------------------------
# Crawling helpers (simple)
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
    visited, q, found = set(), [(start_url, 0)], []
    while q:
        url, depth = q.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                full = urljoin(url, link['href'])
                if domain in full and full not in visited:
                    if "?" in full or "=" in full:
                        found.append(full)
                    q.append((full, depth + 1))
        except Exception:
            continue
    save_list(os.path.join(outdir, "crawled_urls.txt"), sorted(set(found)))
    return found

# -------------------------
# Flow
# -------------------------
def scan_domain(domain, workers, rate_limit, timeout):
    outdir = f"output/{domain}"
    ensure_dir(outdir)
    print(Fore.CYAN + f"[~] Gathering URLs for {domain}..." + Style.RESET_ALL)
    wayback = find_urls(domain, outdir)
    crawled = crawl_site(f"http://{domain}", outdir)
    urls = list(set(wayback + crawled))
    save_list(os.path.join(outdir, "all_urls.txt"), urls)
    payloads = load_xss_payloads(XSS_PAYLOAD_FILE)
    optimized_scan_xss(urls, outdir, payloads, workers, rate_limit, timeout)

# -------------------------
# CLI
# -------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="ZeroFox v2 — XSS Scanner (authorized use only)")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help="Jumlah worker paralel (default: 8)")
    parser.add_argument("--rate-limit", type=float, default=RATE_LIMIT, help="Delay antar request (detik, default: 0.10)")
    parser.add_argument("--timeout", type=int, default=SHORT_TIMEOUT, help="Timeout singkat request (detik, default: 3)")
    return parser.parse_args()

def main():
    args = parse_args()
    global MAX_WORKERS, RATE_LIMIT, SHORT_TIMEOUT
    MAX_WORKERS = max(1, int(args.workers))
    RATE_LIMIT = max(0.0, float(args.rate_limit))
    SHORT_TIMEOUT = max(1, int(args.timeout))

    startup_animation()
    print(Fore.GREEN + f"[CFG] workers={MAX_WORKERS}, rate_limit={RATE_LIMIT}s, timeout={SHORT_TIMEOUT}s" + Style.RESET_ALL)
    print(Fore.GREEN + "\n[MODE] 1 = Scan 1 domain | 2 = Multi scan (bulk.txt)\n" + Style.RESET_ALL)
    mode = input("Pilih mode (1/2): ").strip()
    if mode == "2":
        filepath = input("Masukkan path file list domain (contoh: targets.txt): ").strip()
        if not os.path.exists(filepath):
            print(Fore.RED + "[!] File tidak ditemukan." + Style.RESET_ALL)
            return
        with open(filepath) as f:
            targets = [l.strip() for l in f if l.strip()]
        for t in targets:
            scan_domain(t, MAX_WORKERS, RATE_LIMIT, SHORT_TIMEOUT)
    else:
        domain = input(Fore.YELLOW + "[>] Masukkan domain target: " + Style.RESET_ALL).strip()
        scan_domain(domain, MAX_WORKERS, RATE_LIMIT, SHORT_TIMEOUT)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Dibatalkan oleh user." + Style.RESET_ALL)
