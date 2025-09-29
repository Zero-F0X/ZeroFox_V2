# ZeroFox v2 (modified)
ZeroFox v2 is a recon and XSS scanning framework (modified). This package includes:
- `zerofox_v2.py` — main script (XSS detection with optional Playwright headless checks)
- `xss.txt` — XSS payload list (one per line). Replace with your own payload file.
- `requirements.txt` — Python dependencies.

## IMPORTANT
Only use this tool on targets where you have **explicit written authorization**. Misuse is illegal.

## Quick setup (Ubuntu)
1. Create Python venv:
```bash
pip install "httpx[http2]" beautifulsoup4 colorama aiofiles requests
pip install websockets
pip install httpx-cache
sudo apt update && sudo apt install -y git
git clone https://github.com/Zero-F0X/ZeroFox_V2.git
pip install --upgrade pip
python3 -m playwright install chromium
cd ZeroFox_V2
pip install -r requirements.txt


```
One line:
```bash

python3 -m venv venv && source venv/bin/activate && pip install --upgrade pip && pip install "httpx[http2]" beautifulsoup4 colorama aiofiles requests

```

2. Edit `xss.txt` (place your payloads). The repository includes a small sample; replace with your approved list.

3. Run:
```bash

python3 zerofox_v2.py --targets example.com --workers 120 --outdir output_report --html-output vuln.html

```

## Notes
- Playwright is optional. If not installed, script will run without headless checks.
- Be careful with rate limits and concurrency to avoid disrupting the target.
