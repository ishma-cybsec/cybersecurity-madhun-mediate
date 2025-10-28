#File: password_leak_checker_full.py
#Author: ishmacybsec

#!/usr/bin/env python3
"""
password_leak_checker_full.py

Features:
 - Offline mode: load a (possibly large) leaked SHA256 file into memory (set) for O(1) checks.
 - Online mode: query HaveIBeenPwned (HIBP) using k-anonymity (SHA1 prefix) safely.
 - Single password interactive check or batch mode (passwords from file).
 - Nicely formatted output with leading-zero case numbers (e.g., #001).
 - No external libraries required.

Usage:
    python password_leak_checker_full.py           # interactive single-check
    python password_leak_checker_full.py --batch pwlist.txt
    python password_leak_checker_full.py --leaks leaked_hashes.txt --batch pwlist.txt --online

Notes:
 - offline leaks file should contain lowercase SHA256 hashes, one per line.
 - online mode uses the public HIBP pwned-passwords API (k-anonymity). Only the first 5 chars of SHA1 are sent.
 - if checking a large leak file, make sure your machine has memory for it (loading into set).
"""

from __future__ import annotations
import hashlib
import os
import sys
import urllib.request
import urllib.error
import argparse
from typing import Optional, Set, Iterable

DEFAULT_LEAKS_FILE = "leaked_hashes.txt"   # expected: lowercase sha256 per line
DEFAULT_BATCH_OUTPUT = "pw_check_results.txt"

def sha256_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def sha1_hash_upper(s: str) -> str:
    # HIBP expects uppercase SHA1 hex
    return hashlib.sha1(s.encode("utf-8")).hexdigest().upper()

# ------------------ Offline: load leaks into set ------------------
def load_leak_hashes(leaks_path: str) -> Set[str]:
    """
    Load SHA256 leaks into a set. Expects one hash per line (lowercase or uppercase).
    Returns a set of lowercase hashes.
    """
    if not os.path.exists(leaks_path):
        raise FileNotFoundError(f"Leaks file not found: {leaks_path}")
    leaks = set()
    with open(leaks_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            h = line.strip().lower()
            if not h:
                continue
            # Basic validation: line length for SHA256 hex is 64
            if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                leaks.add(h)
            else:
                # skip or accept if you prefer; here we skip malformed lines
                continue
    return leaks

def check_offline(password: str, leaks_set: Set[str]) -> bool:
    """Return True if password found in local leak set (sha256)."""
    phash = sha256_hash(password).lower()
    return phash in leaks_set

# ------------------ Online: HIBP k-anonymity check ------------------
def check_hibp(password: str, timeout: float = 10.0) -> Optional[int]:
    """
    Query HIBP Pwned Passwords using k-anonymity.
    Returns:
      - integer count > 0 if found (occurrence count),
      - 0 if not found,
      - None on network/API error.
    """
    try:
        sha1 = sha1_hash_upper(password)
        prefix = sha1[:5]
        suffix = sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "Katsuo-Password-Checker"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8", errors="replace")
        # Data lines: "HASHSUFFIX:COUNT" where HASHSUFFIX is uppercase SHA1 suffix
        for line in data.splitlines():
            if not line:
                continue
            parts = line.split(":")
            if len(parts) != 2:
                continue
            suf, cnt = parts[0].strip(), parts[1].strip()
            if suf.upper() == suffix.upper():
                try:
                    return int(cnt)
                except ValueError:
                    return None
        return 0
    except urllib.error.HTTPError as he:
        # e.g., 403/429 etc.
        print("HIBP HTTP error:", he)
        return None
    except Exception as e:
        print("HIBP/network error:", e)
        return None

# ------------------ Utilities ------------------
def mask_password(pw: str, show_chars: int = 1) -> str:
    """Return a masked version of password for printing: e.g., p****** (keeps first char)."""
    if not pw:
        return ""
    if len(pw) <= show_chars:
        return "*" * len(pw)
    return pw[:show_chars] + "*" * (len(pw) - show_chars)

def read_passwords_from_file(path: str) -> Iterable[str]:
    """Yield passwords (one per line) from a file; strips whitespace; ignores empty lines."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.rstrip("\n")
            if pw:
                yield pw

# ------------------ Main interactive / batch logic ------------------
def check_single_interactive(leaks_set: Optional[Set[str]], use_online: bool) -> None:
    pw = input("Enter password to test (or type 'quit' to exit): ").strip()
    if not pw or pw.lower() == "quit":
        print("Exiting.")
        return
    # Basic strength hint
    print("\n[Hint] Basic strength check:")
    if len(pw) < 8:
        print("  - Weak: less than 8 characters.")
    else:
        print("  - Length OK (>= 8).")

    offline_found = False
    online_count = None

    if leaks_set is not None:
        offline_found = check_offline(pw, leaks_set)

    if use_online:
        print("\nQuerying HIBP (k-anonymity) ...")
        online_count = check_hibp(pw)

    print("\n=== Results ===")
    print(f"Password: {mask_password(pw)}")
    if leaks_set is not None:
        if offline_found:
            print("⚠️  Offline: FOUND in local leak set.")
        else:
            print("✅ Offline: Not found in local leak set.")
    else:
        print("Offline check: skipped (no leaks file loaded).")

    if use_online:
        if online_count is None:
            print("Online check: Could not complete (network/API error).")
        elif online_count == 0:
            print("✅ Online: Not found in HIBP.")
        else:
            print(f"⚠️  Online: Found {online_count} occurrences in HIBP data.")
    else:
        print("Online check: skipped.")

    # Advice
    print("\nAdvice:")
    if (leaks_set is not None and offline_found) or (isinstance(online_count, int) and online_count > 0) or (len(pw) < 8):
        print(" - Do NOT reuse this password. Change it immediately on any service that used it.")
        print(" - Use a password manager and unique passwords per site.")
    else:
        print(" - Password appears not found by current checks. Still use a unique, strong password.")

def check_batch_file(batch_path: str, leaks_set: Optional[Set[str]], use_online: bool, out_path: Optional[str]) -> None:
    if not os.path.exists(batch_path):
        print("Batch password file not found:", batch_path)
        return
    passwords = list(read_passwords_from_file(batch_path))
    if not passwords:
        print("No passwords found in batch file.")
        return

    # Prepare offline lookup if leaks_set None
    if leaks_set is None:
        print("Note: offline leak checks will be skipped (no leaks file loaded).")

    # Output header
    total = len(passwords)
    width = 3
    # dynamically adjust width if many
    if total >= 1000:
        width = 4
    elif total >= 100:
        width = 3
    # Prepare output file if requested
    outf = None
    if out_path:
        try:
            outf = open(out_path, "w", encoding="utf-8")
            outf.write("CaseID\tMaskedPassword\tOfflineFound\tHIBPCount\n")
        except Exception as e:
            print("Could not open output file for writing:", e)
            outf = None

    # Iterate and check
    for idx, pw in enumerate(passwords, start=1):
        case_id = f"#{idx:0{width}d}"   # leading zeros in printed case ID
        masked = mask_password(pw, show_chars=1)
        offline_found = False
        hibp_count = None

        if leaks_set is not None:
            offline_found = check_offline(pw, leaks_set)

        if use_online:
            hibp_count = check_hibp(pw)

        # Print one-line summary
        offline_str = "YES" if offline_found else "NO"
        if hibp_count is None and use_online:
            online_str = "ERR"
        else:
            online_str = str(hibp_count) if isinstance(hibp_count, int) else "SKIP"
        print(f"{case_id} {masked} | offline: {offline_str} | HIBP: {online_str}")

        # Write to output file if present
        if outf:
            outf.write(f"{case_id}\t{masked}\t{offline_str}\t{online_str}\n")

    if outf:
        outf.close()
        print("\nBatch check complete. Results written to:", out_path)
    else:
        print("\nBatch check complete. (No output file)")

# ------------------ Argument parsing and entry ------------------
def parse_args():
    p = argparse.ArgumentParser(description="Password Leak Checker (offline set + optional HIBP k-anonymity).")
    p.add_argument("--leaks", "-l", default=DEFAULT_LEAKS_FILE, help=f"Offline leaks file (SHA256 per line). Default: {DEFAULT_LEAKS_FILE}")
    p.add_argument("--batch", "-b", help="Batch file with passwords (one per line). If omitted, interactive single password mode runs.")
    p.add_argument("--online", action="store_true", help="Use online HIBP k-anonymity check (requires internet).")
    p.add_argument("--out", "-o", help="Output file path for batch results (optional). Default: pw_check_results.txt if omitted and --batch used.")
    p.add_argument("--no-offline", action="store_true", help="Skip loading offline leaks even if leaks file exists.")
    return p.parse_args()

def main():
    args = parse_args()

    leaks_set = None
    if not args.no_offline:
        # try to load leaks file if present
        if os.path.exists(args.leaks):
            print("Loading offline leaks file (this may take memory for large files)...")
            try:
                leaks_set = load_leak_hashes(args.leaks)
                print(f"Loaded {len(leaks_set)} unique SHA256 hashes from {args.leaks}.")
            except Exception as e:
                print("Could not load leaks file:", e)
                leaks_set = None
        else:
            print(f"Offline leaks file '{args.leaks}' not found. You can create a sample file or pass --no-offline to skip offline checks.")

    # If batch mode
    if args.batch:
        outpath = args.out or DEFAULT_BATCH_OUTPUT
        check_batch_file(args.batch, leaks_set, args.online, outpath)
    else:
        check_single_interactive(leaks_set, args.online)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(0)
