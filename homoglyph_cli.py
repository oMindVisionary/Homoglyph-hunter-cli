#!/usr/bin/env python3
"""
Homoglyph Hunter (CLI Edition)
Generate homoglyph domain variants with punycode.
Created with ❤️ by Ishan Aannd
"""
import argparse
import csv
import itertools
from typing import List, Tuple, Set, Dict

# Confusable lookalikes (Latin→Cyrillic/Greek/Latin-extended)
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

def normalize_domain(domain: str) -> str:
    return domain.strip().strip(".").lower()

def split_domain(domain: str) -> Tuple[str, str]:
    parts = domain.split(".")
    if len(parts) < 2:
        return parts[0], ""
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
    indices = list(range(n))
    for edits in range(1, max_edits + 1):
        for positions in itertools.combinations(indices, edits):
            pools: List[List[str]] = []
            for idx, ch in enumerate(label):
                if idx in positions and ch in CONFUSABLES:
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

def generate_domain_variants(domain: str, max_edits: int = 1, limit: int = 10000):
    domain = normalize_domain(domain)
    sld, rest = split_domain(domain)
    variants = generate_variants_for_label(sld, max_edits=max_edits, limit=limit)
    out = []
    for v in sorted(variants):
        full = v if not rest else f"{v}.{rest}"
        ok, puny = idna_safe(full)
        if ok:
            out.append((full, puny))
    return out

def main():
    ap = argparse.ArgumentParser(description="Homoglyph Hunter (CLI Edition)")
    ap.add_argument("domain", help="Base domain (e.g. paypal.com)")
    ap.add_argument("--max-edits", type=int, default=1, help="Max characters to swap (default: 1)")
    ap.add_argument("--limit", type=int, default=2000, help="Cap total variants (default: 2000)")
    ap.add_argument("--csv", type=str, help="Export results to CSV file")
    ap.add_argument("--txt", type=str, help="Export results to TXT file")
    args = ap.parse_args()

    pairs = generate_domain_variants(args.domain, max_edits=args.max_edits, limit=args.limit)

    print(f"Generated {len(pairs)} variants for {args.domain}:")
    for u, p in pairs[:50]:  # preview first 50
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

if __name__ == "__main__":
    main()
