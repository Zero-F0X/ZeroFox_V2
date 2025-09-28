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
sudo apt update && sudo apt install -y git
git clone https://github.com/Zero-F0X/ZeroFox_V2.git
pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
cd ZeroFox-V2
```

2. Edit `xss.txt` (place your payloads). The repository includes a small sample; replace with your approved list.

3. Run:
```bash
python3 zerofox_v2.py
```

## Notes
- Playwright is optional. If not installed, script will run without headless checks.
- Be careful with rate limits and concurrency to avoid disrupting the target.
