# Homoglyph Hunter — CLI Edition

*A lightweight Python CLI tool to generate Unicode homoglyph (look-alike) domain variants with punycode, optionally check DNS resolution, and run WHOIS — for phishing detection, typosquatting research, and brand protection.*

---

## ✨ Features
- Generate look-alike domains from Unicode **confusables** (Cyrillic, Greek, Latin-extended).
- Validate output with **IDNA/punycode** (only encodable domains are returned).
- **DNS check** (A/AAAA) to flag variants that resolve (proxy for “likely registered”).
- **WHOIS** (optional): system `whois`, `python-whois`, or direct TCP to common WHOIS servers.
- Export results to **CSV** and **TXT**.
- Pure Python, no required third-party dependencies for generation/DNS.

> ⚠️ Notes  
> - DNS “resolves” is a *signal*, not proof of registration (wildcards/CDNs can resolve).  
> - WHOIS availability & rate limits vary by TLD; fallback WHOIS covers popular ones (`.com/.net/.org/.io/.ai/.in`) and uses generic servers as last resort.  

---

## 📦 Installation

**Recommended: use a virtual environment**

macOS / Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows (PowerShell):
```powershell
python -m venv .venv
.\venv\Scripts\activate
```

Clone or download the repo and you’re ready — no extra installs needed for generation/DNS.

### Optional (for richer WHOIS support)
- **macOS (Homebrew):**
  ```bash
  brew install whois
  ```
- **Python package (alternative WHOIS backend):**
  ```bash
  pip install python-whois
  ```

---

## 🖥️ Usage

### Basic generation
```bash
python homoglyph_cli.py paypal.com
```

### With DNS check (which variants resolve)
```bash
python homoglyph_cli.py paypal.com --check
```

### Only show / export resolving (likely registered) variants
```bash
python homoglyph_cli.py paypal.com --check --only-registered
```

### WHOIS (default: for resolving domains when --check is used)
```bash
python homoglyph_cli.py paypal.com --check --whois --csv results.csv
```

### WHOIS for **all** variants (slow; mind rate limits)
```bash
python homoglyph_cli.py paypal.com --whois --whois-all --csv all_whois.csv
```

### Exports
```bash
# CSV with punycode (+ resolves/WHOIS columns if enabled)
python homoglyph_cli.py paypal.com --check --whois --csv out.csv

# TXT (one domain per line; respects --only-registered)
python homoglyph_cli.py paypal.com --check --only-registered --txt out.txt
```

### Performance tuning
```bash
# Faster DNS: more workers, shorter timeout
python homoglyph_cli.py paypal.com --check --workers 64 --timeout 1.5

# WHOIS concurrency & timeout
python homoglyph_cli.py paypal.com --check --whois --whois-workers 16 --whois-timeout 5
```

---

## 📂 Output columns (CSV)

- `unicode_domain` — the prettified Unicode form (what a user would see).
- `punycode` — ASCII/IDNA form (what DNS actually uses).
- `resolves` — `1` if DNS A/AAAA resolved, else `0` (only when `--check`).
- `whois_available` — `1` if WHOIS text was retrieved, else `0` (only when `--whois`).
- `whois_text` — raw WHOIS text (large; included when `--whois`).

---

## 🔍 Examples

```bash
# Typical workflow for a brand:
python homoglyph_cli.py mybrand.com --max-edits 1 --limit 5000 --check --only-registered --whois --csv mybrand_watch.csv
```

---

## ⚠️ Legal & Ethical Use
This project is for **defensive security** and **research**.  
Do **not** use it to register or abuse look-alike domains. Respect laws, policies, and TLD rate limits.

---

## 📜 License
MIT License.

---

## ✍️ Credits
Created with ❤️ by **Ishan Anand**
