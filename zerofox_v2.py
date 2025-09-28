#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ZeroFox v2 - Fast + Spooky UI
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
from functools import partial
import concurrent.futures

# Third-party
try:
    from colorama import Fore, Back, Style, init as colorama_init
    from bs4 import BeautifulSoup
    from tqdm import tqdm
except Exception as e:
    print("Missing dependencies. Install with: pip install requests beautifulsoup4 colorama tqdm")
    raise e

# Optional playwright
HEADLESS_ENABLED = True
_playwright_available = False
if HEADLESS_ENABLED:
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
        _playwright_available = True
    except Exception:
        _playwright_available = False

colorama_init(autoreset=True)
urllib3.disable_warnings()

# -------------------------
# CONFIG
# -------------------------
XSS_PAYLOAD_FILE = "xss.txt"
RATE_LIMIT = 0.12            # seconds between requests
REQUEST_TIMEOUT = 8          # fallback timeout
SHORT_TIMEOUT = 4            # faster initial check
SAVE_EVIDENCE = True
PLAYWRIGHT_LAUNCH_OPTIONS = {"headless": True, "timeout": 15000}
MAX_WORKERS = 6              # tune this (4-12 typical)
UI_UPDATE_INTERVAL = 0.05    # for spinner animations

# -------------------------
# Fancy UI elements (hacker-y)
# -------------------------
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(text, delay=0.01, end="\n"):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(end)
    sys.stdout.flush()

def typing_effect(lines, w_delay=0.01, between=0.25):
    for line in lines:
        slow_print(line, delay=w_delay)
        time.sleep(between)

def big_banner():
    banner = r"""
 ████████╗███████╗███████╗ ██████╗  ██████╗ ██╗  ██╗██╗  ██╗
 ╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔═══██╗██║ ██╔╝██║  ██║
    ██║   █████╗  ███████╗██║   ██║██║   ██║█████╔╝ ███████║
    ██║   ██╔══╝  ╚════██║██║   ██║██║   ██║██╔═██╗ ██╔══██║
    ██║   ███████╗███████║╚██████╔╝╚██████╔╝██║  ██╗██║  ██║
    ╚═╝   ╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    """
    print(Fore.RED + Style.BRIGHT + banner + Style.RESET_ALL)
    intro = [
        Fore.LIGHTBLACK_EX + "ZeroFox v2" + Style.RESET_ALL + " — Http Recon & XSS Scanner (authorized use only).",
        Fore.YELLOW + "Initializing modules..." + Style.RESET_ALL
    ]
    typing_effect(intro, w_delay=0.02, between=0.15)

def spinner_task(stop_event, text="booting"):
    chars = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{Fore.CYAN}[{chars[i%len(chars)]}] {text}{' ' * 20}{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(UI_UPDATE_INTERVAL)
        i += 1
    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()

def matrix_rain(lines=10, width=60, delay=0.02):
    charset = "01"
    for _ in range(lines):
        line = ''.join(random.choice(charset) for _ in range(width))
        print(Fore.GREEN + line + Style.RESET_ALL)
        time.sleep(delay)

def spooky_console(lines=6, delay_between=0.18):
    # fake logs that look scary but are non-destructive / harmless
    templates = [
        "[init] kernel modules loaded",
        "[net] sniffing interfaces: eth0 wlan0",
        "[auth] keys fetched from memory (simulated)",
        "[scan] starting passive recon",
        "[payload] queue prepared (non-destructive markers only)",
        "[xss] headless engine primed"
    ]
    for i in range(lines):
        line = templates[i % len(templates)]
        slow_print(Fore.LIGHTBLACK_EX + line + Style.RESET_ALL, delay=0.01)
        time.sleep(delay_between)

def killer_startup_animation():
    clear_screen()
    big_banner()
    stop = threading.Event()
    s = threading.Thread(target=spinner_task, args=(stop, "initializing subsystems..."))
    s.start()
    time.sleep(1.1)
    stop.set()
    s.join()
    matrix_rain(lines=8, width=72, delay=0.02)
    spooky_console(lines=6, delay_between=0.18)
    print()

# -------------------------
# Helpers for scanning
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

def save_screenshot(outdir, safe_name, image_bytes):
    ev_dir = ensure_dir(os.path.join(outdir, "evidence"))
    fn = os.path.join(ev_dir, f"{safe_name}.png")
    try:
        with open(fn, "wb") as f:
            f.write(image_bytes)
    except Exception:
        pass
    return fn

# -------------------------
# Headless reuse helper
# -------------------------
def play_authorized_check_with_browser(browser, test_url, marker, outdir, timeout=8000):
    """
    Reuse an existing Playwright browser instance to detect console logs/DOM markers.
    Returns (detected: bool, details: dict)
    """
    details = {"console": [], "screenshot": None, "html": None}
    try:
        context = browser.new_context()
        page = context.new_page()
        def on_console(msg):
            try:
                details["console"].append(msg.text())
            except Exception:
                pass
        page.on("console", on_console)
        try:
            page.goto(test_url, wait_until="networkidle", timeout=timeout)
        except Exception:
            pass
        try:
            page.wait_for_timeout(200)
        except Exception:
            pass

        # console messages
        for m in details["console"]:
            if marker in m:
                try:
                    ss = page.screenshot(type="png")
                    details["screenshot"] = save_screenshot(outdir, re.sub(r'[^0-9A-Za-z\-_\.]', '_', test_url)[:200], ss)
                    html = page.content()
                    details["html"] = save_evidence_html(outdir, re.sub(r'[^0-9A-Za-z\-_\.]', '_', test_url)[:200] + "_rendered", marker, html)
                except Exception:
                    pass
                try:
                    context.close()
                except:
                    pass
                return True, details

        # DOM check
        try:
            content = page.content()
            if marker in content:
                details["html"] = save_evidence_html(outdir, re.sub(r'[^0-9A-Za-z\-_\.]', '_', test_url)[:200] + "_rendered", marker, content)
                try:
                    ss = page.screenshot(type="png")
                    details["screenshot"] = save_screenshot(outdir, re.sub(r'[^0-9A-Za-z\-_\.]', '_', test_url)[:200], ss)
                except Exception:
                    pass
                try:
                    context.close()
                except:
                    pass
                return True, details
        except Exception:
            pass

        try:
            context.close()
        except:
            pass
    except Exception as e:
        return False, {"reason": f"playwright_error:{e}"}
    return False, details

# -------------------------
# Optimized XSS scanning (parallel per-URL)
# -------------------------
def _scan_url_worker(url, payloads, outdir, rate_limit, request_timeout, playwright_enabled, browser):
    """
    Worker scans one URL (all payloads sequentially). Returns first found test_url or None.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "ZeroFox-v2-Scanner/1.0"})
    try:
        for payload in payloads:
            test_url = inject_payload(url, payload)
            try:
                r = session.get(test_url, timeout=request_timeout, verify=False)
                resp = r.text or ""
                decoded_payload = urllib.parse.unquote_plus(payload)
                # quick reflection detection
                if payload in resp or decoded_payload in resp:
                    safe = re.sub(r'[^0-9A-Za-z\-_\.]', '_', test_url)[:200]
                    if SAVE_EVIDENCE:
                        save_evidence_html(outdir, safe + "__resp", payload, resp)
                    return test_url
                # headers check
                for hk, hv in r.headers.items():
                    if payload in hv or decoded_payload in hv:
                        safe = re.sub(r'[^0-9A-Za-z\-_\.]', '_', test_url)[:200]
                        if SAVE_EVIDENCE:
                            save_evidence_html(outdir, safe + "__header", payload, f"{hk}: {hv}\n\n{resp}")
                        return test_url
            except Exception:
                pass
            finally:
                if rate_limit:
                    time.sleep(rate_limit)

        # fallback headless detect
        if playwright_enabled and browser:
            marker_m = re.search(r"[A-Za-z0-9_]{6,}", payload)
            if marker_m:
                marker = marker_m.group(0)
            else:
                marker = "ZF" + str(random.randint(100000, 999999))
            try:
                detected, details = play_authorized_check_with_browser(browser, test_url, marker, outdir)
                if detected:
                    return test_url
            except Exception:
                pass
    finally:
        try:
            session.close()
        except:
            pass
    return None

def optimized_scan_xss(urls, outdir, payloads):
    hits = []
    if not payloads:
        print(Fore.YELLOW + "[!] No payloads loaded, skipping XSS scan." + Style.RESET_ALL)
        return hits

    print(Fore.CYAN + f"[i] Starting optimized XSS scan: {len([u for u in urls if '?' in u])} parameterized URL(s), {len(payloads)} payload(s), workers={MAX_WORKERS}." + Style.RESET_ALL)

    # prepare playwright once
    browser = None
    pw_controller = None
    if _playwright_available:
        try:
            pw_controller = sync_playwright().start()
            browser = pw_controller.chromium.launch(**PLAYWRIGHT_LAUNCH_OPTIONS)
            print(Fore.CYAN + "[i] Playwright browser launched for reuse." + Style.RESET_ALL)
        except Exception as e:
            browser = None
            try:
                if pw_controller:
                    pw_controller.stop()
            except:
                pass
            print(Fore.YELLOW + f"[!] Playwright launch failed: {e}" + Style.RESET_ALL)

    target_urls = [u for u in urls if "?" in u]
    if not target_urls:
        print(Fore.YELLOW + "[!] No parameterized URLs to scan." + Style.RESET_ALL)
        return hits

    workers = min(MAX_WORKERS, max(1, len(target_urls)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        func = partial(_scan_url_worker, payloads=payloads, outdir=outdir, rate_limit=RATE_LIMIT,
                       request_timeout=SHORT_TIMEOUT, playwright_enabled=bool(browser), browser=browser)
        future_to_url = {ex.submit(func, url): url for url in target_urls}
        # nice progress reporting
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                res = future.result()
                if res:
                    print(Fore.RED + f"[FOUND] {res}" + Style.RESET_ALL)
                    hits.append(res)
                else:
                    # friendly small console output
                    print(Fore.LIGHTBLACK_EX + f"[OK] {url} scanned." + Style.RESET_ALL)
            except Exception as e:
                print(Fore.YELLOW + f"[!] Worker error for {url}: {e}" + Style.RESET_ALL)

    # cleanup browser
    if browser:
        try:
            browser.close()
        except:
            pass
        try:
            pw_controller.stop()
        except:
            pass

    hits = sorted(set(hits))
    save_list(os.path.join(outdir, "xss_found_urls.txt"), hits)
    return hits

# -------------------------
# Other scans (kept simple)
# -------------------------
def find_subdomains(domain, outdir):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        data = r.json()
        subs = sorted(set(entry['name_value'] for entry in data if domain in entry['name_value']))
        save_list(os.path.join(outdir, "subdomains.txt"), subs)
        return subs
    except Exception:
        return []

def find_urls(domain, outdir):
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey", timeout=15)
        urls = sorted(set(r.text.splitlines()))
        save_list(os.path.join(outdir, "urls.txt"), urls)
        return urls
    except Exception:
        return []

def crawl_site(start_url, outdir, max_depth=2):
    domain = urllib.parse.urlparse(start_url).netloc
    visited, queue, found = set(), [(start_url, 0)], []
    while queue:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                full_url = urljoin(url, link['href'])
                if domain in full_url and full_url not in visited:
                    if any(x in full_url for x in ["?", "=", "php"]):
                        found.append(full_url)
                    queue.append((full_url, depth + 1))
        except Exception:
            continue
    save_list(os.path.join(outdir, "crawled_urls.txt"), sorted(set(found)))
    return found

# -------------------------
# Top-level flows (simplified)
# -------------------------
def scan_all(urls, domain):
    outdir = f"output/{domain}"
    ensure_dir(outdir)
    payloads = load_xss_payloads(XSS_PAYLOAD_FILE)
    # quick UI
    print(Fore.MAGENTA + f"[+] Running XSS scan for {domain}..." + Style.RESET_ALL)
    found = optimized_scan_xss(urls, outdir, payloads)
    print(Fore.GREEN + f"[✓] XSS scan done — {len(found)} vulnerable endpoints found." + Style.RESET_ALL)

def scan_domain(domain):
    outdir = f"output/{domain}"
    ensure_dir(outdir)
    print(Fore.CYAN + f"[~] Collecting URLs for {domain}..." + Style.RESET_ALL)
    wayback = find_urls(domain, outdir)
    crawled = crawl_site(f"http://{domain}", outdir)
    urls = list(set(wayback + crawled))
    save_list(os.path.join(outdir, "all_urls.txt"), urls)
    scan_all(urls, domain)

# -------------------------
# Entry/CLI
# -------------------------
def main():
    killer_startup_animation()
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
            print(Fore.CYAN + f"[~] Scanning: {domain}" + Style.RESET_ALL)
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
