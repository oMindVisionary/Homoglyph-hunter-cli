# Homoglyph Hunter — CLI Edition

*A lightweight Python CLI tool to generate homoglyph domain variants with punycode, for phishing detection and brand protection.*

---

## 🚀 Features
- Generate homoglyph look-alike domains using Unicode confusables (Cyrillic, Greek, Latin extended).
- Validate each domain with IDNA (punycode encoding).
- Export results as **CSV** or **TXT**.
- No external dependencies — pure Python standard library.

---

## 📦 Installation

### 1️⃣ Clone the repo
```bash
git clone https://github.com/<your-username>/homoglyph-hunter-cli.git
cd homoglyph-hunter-cli
```

### 2️⃣ (Optional) Create a virtual environment
**macOS / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

No additional dependencies required.

---

## 🖥️ Usage

```bash
# Show help
python homoglyph_cli.py -h

# Generate variants for paypal.com (prints preview of first 50)
python homoglyph_cli.py paypal.com

# Generate with 2 swaps, limit 5000, and save to CSV
python homoglyph_cli.py paypal.com --max-edits 2 --limit 5000 --csv paypal_variants.csv

# Save to TXT
python homoglyph_cli.py paypal.com --txt paypal_variants.txt
```

---

## 📂 Project Structure
```
├── homoglyph_cli.py   # CLI tool script
├── README.md          # Documentation
└── LICENSE            # MIT License
```

---

## ⚠️ Disclaimer
This tool is for **educational and defensive cybersecurity purposes only**.  
Do not use it for malicious activities. Always follow responsible security practices.

---

## 📜 License
Licensed under the **MIT License**.

---

## ✨ Credits
Created with ❤️ by **Ishan Aannd**
