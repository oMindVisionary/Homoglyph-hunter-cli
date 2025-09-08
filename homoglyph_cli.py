#!/usr/bin/env python3
"""
Homoglyph Hunter (CLI Edition)
Generate homoglyph domain variants with punycode, optionally check DNS, and run WHOIS.
Created with ❤️ by Ishan Anand
"""
import argparse
import csv
import itertools
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Set, Dict, Optional

# ---------------- Confusables ----------------
CONFUSABLES: Dict[str, List[str]] = {
    "a": ["а", "α", "à", "á", "â", "ä", "ã", "å"],
    "b": ["Ь", "ь", "β"],
    "c": ["с", "ϲ", "ç"],
    "d": ["ԁ"],
    "e": ["е", "ε", "é", "è", "ê", "ë"],
    "f": ["Ϝ"],
    "g": ["ɡ"],
    "h": ["һ", "ḥ"],
    "i": ["і", "í", "ì", "î", "ï", "ı"],
    "j": ["ј"],
    "k": ["κ", "к"],
    "l": ["ⅼ", "ɫ", "Ɩ", "|", "1"],
    "m": ["м"],
    "n": ["п", "ṇ"],
    "o": ["ο", "о", "օ", "º", "0", "ö", "ó", "ò", "ô", "ø", "õ"],
    "p": ["ρ", "р"],
    "q": ["զ"],
    "r": ["г", "ṛ"],
    "s": ["ѕ", "ʂ", "ś", "ş", "ṣ"],
    "t": ["τ", "ť", "ṭ"],
    "u": ["υ", "ư", "ú", "ù", "û", "ü"],
    "v": ["ѵ", "ν"],
    "w": ["ѡ", "ɯ"],
    "x": ["х", "χ"],
    "y": ["у", "γ", "ý", "ÿ"],
    "z": ["ʐ", "ż", "ź", "ẓ"],
    "0": ["o", "ο", "о", "օ"],
    "1": ["l", "I", "ⅼ"],
    "3": ["ε"],
    "5": ["ѕ"],
    "-": ["—", "–"],  # filtered by IDNA later if invalid
}
# ---------------------------------------------

def normalize_domain(domain: str) -> str:
    return domain.strip().strip(".").lower()

def split_domain(domain: str) -> Tuple[str, str]:
    parts = domain.split(".")
    if len(parts) < 2: return parts[0], ""
    return parts[0], ".".join(parts[1:])

def idna_safe(label: str) -> Tuple[bool, str]:
    try:
        puny = label.encode("idna").decode("ascii")
        restored = puny.encode("ascii").decode("idna")
        return restored == label, puny
    except Exception:
        return False, ""

def generate_variants_for_label(label: str, max_edits: int = 1, limit: int = 10000) -> Set[str]:
    results: Set[str] = set()
    n = len(label)
    idxs = list(range(n))
    for edits in range(1, max_edits + 1):
        for positions in itertools.combinations(idxs, edits):
            pools: List[List[str]] = []
            for i, ch in enumerate(label):
                if i in positions and ch in CONFUSABLES:
                    pools.append([a for a in CONFUSABLES[ch] if a != ch])
                else:
                    pools.append([ch])
            for combo in itertools.product(*pools):
                variant = "".join(combo)
                if variant != label:
                    ok, _ = idna_safe(variant)
                    if ok:
                        results.add(variant)
                        if len(results) >= limit:
                            return results
    return results

def generate_domain_variants(domain: str, max_edits: int = 1, limit: int = 10000) -> List[Tuple[str, str]]:
    domain = normalize_domain(domain)
    sld, rest = split_domain(domain)
    variants = generate_variants_for_label(sld, max_edits=max_edits, limit=limit)
    out: List[Tuple[str, str]] = []
    for v in sorted(variants):
        full = v if not rest else f"{v}.{rest}"
        ok, puny = idna_safe(full)
        if ok:
            out.append((full, puny))
    return out

# ---------- DNS resolution ----------
def resolves(domain_ascii: str, timeout: float = 2.0) -> bool:
    try:
        socket.setdefaulttimeout(timeout)
        info = socket.getaddrinfo(domain_ascii, None)
        return len(info) > 0
    except Exception:
        return False

def check_registered(pairs: List[Tuple[str, str]], timeout: float, workers: int) -> List[Tuple[str, str, bool]]:
    results: List[Tuple[str, str, bool]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = {ex.submit(resolves, puny, timeout): (u, puny) for (u, puny) in pairs}
        for fut in as_completed(futures):
            u, puny = futures[fut]
            ok = False
            try:
                ok = fut.result()
            except Exception:
                ok = False
            results.append((u, puny, ok))
    results.sort(key=lambda x: x[0])
    return results
# ------------------------------------

# ---------- WHOIS helpers ----------
WHOIS_TLDS = {
    # Common TLDs with known WHOIS servers
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io":  "whois.nic.io",
    "ai":  "whois.nic.ai",
    "in":  "whois.registry.in",
}

def run_system_whois(domain_ascii: str, timeout: float) -> Optional[str]:
    """Use the system 'whois' command if available."""
    try:
        out = subprocess.check_output(
            ["whois", domain_ascii],
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
        )
        return out.strip()
    except Exception:
        return None

def run_python_whois(domain_ascii: str, timeout: float) -> Optional[str]:
    """Try python-whois if installed: pip install python-whois"""
    try:
        import whois  # type: ignore
        # python-whois can be slow; wrap with a crude timeout using threads if needed
        data = whois.whois(domain_ascii)
        return str(data)
    except Exception:
        return None

def whois_tcp_query(server: str, query: str, timeout: float) -> Optional[str]:
    """Lightweight TCP 43 WHOIS query."""
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode("utf-8"))
            chunks = []
            s.settimeout(timeout)
            while True:
                buf = s.recv(4096)
                if not buf:
                    break
                chunks.append(buf)
        return b"".join(chunks).decode("utf-8", errors="replace").strip()
    except Exception:
        return None

def run_basic_whois(domain_ascii: str, timeout: float) -> Optional[str]:
    """Fallback WHOIS using TCP to a best-guess server based on TLD."""
    tld = domain_ascii.rsplit(".", 1)[-1].lower() if "." in domain_ascii else ""
    server = WHOIS_TLDS.get(tld, None)
    if server:
        return whois_tcp_query(server, domain_ascii, timeout)
    # Last-resort generic servers (may not work for all TLDs)
    for srv in ("whois.iana.org", "whois.arin.net"):
        resp = whois_tcp_query(srv, domain_ascii, timeout)
        if resp:
            return resp
    return None

def whois_lookup(domain_ascii: str, timeout: float = 5.0) -> Optional[str]:
    """
    Multi-strategy WHOIS:
      1) system 'whois' if available
      2) python-whois if installed
      3) direct TCP query to a known TLD server (limited set)
    """
    # Strategy 1
    txt = run_system_whois(domain_ascii, timeout=timeout)
    if txt: return txt
    # Strategy 2
    txt = run_python_whois(domain_ascii, timeout=timeout)
    if txt: return txt
    # Strategy 3
    txt = run_basic_whois(domain_ascii, timeout=timeout)
    return txt
# ------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Homoglyph Hunter (CLI Edition)")
    ap.add_argument("domain", help="Base domain (e.g. paypal.com)")
    ap.add_argument("--max-edits", type=int, default=1, help="Max characters to swap (default: 1)")
    ap.add_argument("--limit", type=int, default=2000, help="Cap total variants (default: 2000)")
    ap.add_argument("--csv", type=str, help="Export results to CSV file")
    ap.add_argument("--txt", type=str, help="Export results to TXT file")
    ap.add_argument("--check", action="store_true", help="Check which variants resolve via DNS (A/AAAA).")
    ap.add_argument("--only-registered", dest="only_registered", action="store_true",
                    help="When used with --check, only show/export domains that resolve.")
    # WHOIS options
    ap.add_argument("--whois", action="store_true",
                    help="Run WHOIS lookups (slower). Defaults to only run on resolving domains if --check is used.")
    ap.add_argument("--whois-all", action="store_true",
                    help="Run WHOIS for all variants (ignores --only-registered).")
    ap.add_argument("--whois-timeout", type=float, default=5.0, help="Timeout per WHOIS (seconds).")
    ap.add_argument("--whois-workers", type=int, default=8, help="Concurrent WHOIS lookups.")
    # DNS tuning
    ap.add_argument("--timeout", type=float, default=2.0, help="DNS timeout per domain (seconds).")
    ap.add_argument("--workers", type=int, default=32, help="Concurrent DNS lookups.")
    args = ap.parse_args()

    pairs = generate_domain_variants(args.domain, max_edits=args.max_edits, limit=args.limit)

    # If no DNS check and no whois: simple output/export
    if not args.check and not args.whois:
        print(f"Generated {len(pairs)} variants for {args.domain}:")
        for u, p in pairs[:50]:
            print(f"{u:30}  {p}")
        if args.csv:
            with open(args.csv, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["unicode_domain", "punycode"])
                writer.writerows(pairs)
            print(f"[+] Saved CSV to {args.csv}")
        if args.txt:
            with open(args.txt, "w", encoding="utf-8") as f:
                for u, _ in pairs:
                    f.write(u + "\n")
            print(f"[+] Saved TXT to {args.txt}")
        return

    # DNS check (optional)
    checked: List[Tuple[str, str, bool]]
    if args.check:
        checked = check_registered(pairs, timeout=args.timeout, workers=args.workers)
        if args.only_registered:
            checked = [t for t in checked if t[2]]
    else:
        checked = [(u, p, False) for (u, p) in pairs]

    # WHOIS phase (optional)
    whois_rows: List[Tuple[str, str, bool, Optional[str]]] = []
    if args.whois:
        # Choose targets for WHOIS
        if args.whois_all:
            targets = [(u, p) for (u, p, _) in checked]
        else:
            # Default: WHOIS only resolving domains if DNS check used; else WHOIS all
            if args.check:
                targets = [(u, p) for (u, p, ok) in checked if ok]
            else:
                targets = [(u, p) for (u, p, _) in checked]

        # Run WHOIS concurrently
        def _w(u_p):
            u, p = u_p
            txt = whois_lookup(p, timeout=args.whois_timeout)
            return u, p, txt

        print(f"[WHOIS] Querying {len(targets)} domains (workers={args.whois_workers})...")
        start = time.time()
        with ThreadPoolExecutor(max_workers=max(1, args.whois_workers)) as ex:
            futures = {ex.submit(_w, t): t for t in targets}
            for fut in as_completed(futures):
                u, p, txt = fut.result()
                whois_rows.append((u, p, True if txt else False, txt))
        dur = time.time() - start
        print(f"[WHOIS] Done in {dur:.1f}s")

    # Console preview
    print(f"Generated {len(pairs)} variants for {args.domain} (showing up to 50):")
    shown = 0
    for rec in checked:
        u, p, ok = rec
        whois_ok = None
        if args.whois:
            match = next((w for w in whois_rows if w[0] == u and w[1] == p), None)
            whois_ok = (match[2] if match else False)
        status = "RESOLVES" if ok else "—"
        if args.whois:
            status += " • WHOIS" + ("✓" if whois_ok else "×")
        print(f"{u:30}  {p:35}  {status}")
        shown += 1
        if shown >= 50:
            break

    # Exports
    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            header = ["unicode_domain", "punycode", "resolves"]
            if args.whois:
                header += ["whois_available", "whois_text"]
            writer.writerow(header)

            if args.whois:
                # Prefer WHOIS rows for joined data; fall back to DNS-only rows
                wmap = {(u, p): (ok, txt) for (u, p, ok, txt) in whois_rows}
                for (u, p, ok) in checked:
                    w = wmap.get((u, p))
                    if w:
                        writer.writerow([u, p, int(ok), int(bool(w[1])), w[1]])
                    else:
                        writer.writerow([u, p, int(ok), 0, ""])
            else:
                for (u, p, ok) in checked:
                    writer.writerow([u, p, int(ok)])
        print(f"[+] Saved CSV to {args.csv}")

    if args.txt:
        with open(args.txt, "w", encoding="utf-8") as f:
            for (u, p, ok) in checked:
                if args.check and args.only_registered and not ok:
                    continue
                f.write(u + "\n")
        print(f"[+] Saved TXT to {args.txt}")

if __name__ == "__main__":
    main()
