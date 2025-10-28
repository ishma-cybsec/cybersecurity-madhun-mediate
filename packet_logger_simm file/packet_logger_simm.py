#!/usr/bin/env python3
"""
packet_logger_full.py

- Tries to capture live packets with Scapy and logs parsed fields.
- If scapy is not available or capture is not allowed, falls back to parsing a simple text file 'packets.txt'.
- Writes results to 'packet_log.txt' (raw) and 'packet_summary.csv' (structured).
- Safe to run in a Python IDE. Handles KeyboardInterrupt cleanly.

Usage:
    python packet_logger_full.py
Then follow prompts:
- Choose "live" capture (requires scapy + root) or "file" fallback.
- If file fallback and file missing, you can create a sample automatically.

Author: Katsuo helper
"""

import csv
import os
import sys
import time
from collections import Counter, defaultdict

# --- Try to import scapy (optional) ---
USE_SCAPY = False
try:
    from scapy.all import sniff, Raw, IP, TCP, UDP
    USE_SCAPY = True
except Exception:
    USE_SCAPY = False

# --- Helpers for parsing text-lines (fallback) ---
import re
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
PORT_RE = re.compile(r"\b(port|dport|sport)[:= ]?(\d{1,5})\b", re.IGNORECASE)

def parse_text_packet_line(line):
    """Parse a simple packet-like text line into structured fields."""
    rec = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
           "src": None, "dst": None, "sport": None, "dport": None,
           "proto": None, "status": None, "raw": line.strip()}
    ips = IP_RE.findall(line)
    if ips:
        if len(ips) >= 1:
            rec["src"] = ips[0]
        if len(ips) >= 2:
            rec["dst"] = ips[1]

    # find ports (store last occurrence of each named port)
    for m in PORT_RE.findall(line):
        name = m[0].lower()
        number = m[1]
        if name.startswith("d"):
            rec["dport"] = number
        elif name.startswith("s"):
            rec["sport"] = number
        else:
            # generic 'port' token -> assume destination port
            rec["dport"] = number

    if "tcp" in line.lower():
        rec["proto"] = "TCP"
    elif "udp" in line.lower():
        rec["proto"] = "UDP"

    if "failed" in line.lower():
        rec["status"] = "Failed"
    elif "success" in line.lower() or "accepted" in line.lower():
        rec["status"] = "Success"

    return rec

# --- CSV logging helpers ---
CSV_FILE = "packet_summary.csv"
RAW_LOG = "packet_log.txt"
CSV_FIELDS = ["timestamp", "src", "dst", "sport", "dport", "proto", "status", "raw"]

def ensure_csv_header(path=CSV_FILE):
    exists = os.path.exists(path)
    if not exists:
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                writer.writeheader()
        except Exception as e:
            print("Error creating CSV header:", e)

def append_record_csv(record, path=CSV_FILE):
    try:
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writerow({k: record.get(k, "") for k in CSV_FIELDS})
    except Exception as e:
        print("Error writing CSV record:", e)

def append_raw_log(line, path=RAW_LOG):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line.rstrip("\n") + "\n")
    except Exception as e:
        print("Error writing raw log:", e)

# --- Live capture callback using scapy ---
def scapy_packet_to_record(pkt):
    """Convert a Scapy packet to our record dict (best-effort extraction)."""
    rec = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "src": None, "dst": None,
           "sport": None, "dport": None, "proto": None, "status": None, "raw": None}
    try:
        # basic IP layer
        if IP in pkt:
            rec["src"] = pkt[IP].src
            rec["dst"] = pkt[IP].dst
        # transport
        if TCP in pkt:
            rec["proto"] = "TCP"
            rec["sport"] = getattr(pkt[TCP], "sport", None)
            rec["dport"] = getattr(pkt[TCP], "dport", None)
        elif UDP in pkt:
            rec["proto"] = "UDP"
            rec["sport"] = getattr(pkt[UDP], "sport", None)
            rec["dport"] = getattr(pkt[UDP], "dport", None)
        # payload snippet if present
        payload_snip = ""
        if Raw in pkt:
            try:
                raw_bytes = bytes(pkt[Raw].load)
                # limit snippet and decode safely
                payload_snip = raw_bytes[:80].decode("utf-8", errors="replace")
            except Exception:
                payload_snip = "<binary>"
        rec["raw"] = pkt.summary() + " | " + payload_snip
    except Exception as e:
        rec["raw"] = repr(pkt)
    return rec

def scapy_packet_callback(pkt):
    rec = scapy_packet_to_record(pkt)
    # Print concise line
    src = rec.get("src") or "?"
    dst = rec.get("dst") or "?"
    dp = rec.get("dport") or "?"
    proto = rec.get("proto") or "?"
    print(f"[{rec['timestamp']}] {src} -> {dst} proto={proto} dport={dp}")
    append_raw_log(rec["raw"])
    append_record_csv(rec)

# --- Analysis / alerting utilities (run after capture or on-demand) ---
def analyze_csv(path=CSV_FILE, scan_threshold=12, ssh_failed_threshold=5):
    """Read CSV and produce a summary and simple alerts."""
    if not os.path.exists(path):
        print("CSV file not found:", path)
        return None

    src_counter = Counter()
    dst_port_counter = Counter()
    ip_set = set()
    src_to_ports = defaultdict(set)
    src_to_failed22 = Counter()
    total = 0

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                total += 1
                src = row.get("src") or ""
                dst = row.get("dst") or ""
                dport = row.get("dport") or ""
                status = row.get("status") or ""

                if src:
                    src_counter[src] += 1
                    ip_set.add(src)
                if dst:
                    ip_set.add(dst)
                if dport:
                    try:
                        dp_int = int(dport)
                        dst_port_counter[dp_int] += 1
                        if src:
                            src_to_ports[src].add(dp_int)
                    except Exception:
                        pass
                if dport == "22" and status.lower() == "failed":
                    src_to_failed22[src] += 1
    except Exception as e:
        print("Error analyzing CSV:", e)
        return None

    port_scan_alerts = [(s, len(p)) for s, p in src_to_ports.items() if len(p) >= scan_threshold]
    ssh_alerts = [(s, cnt) for s, cnt in src_to_failed22.items() if cnt >= ssh_failed_threshold]

    print("\n=== Analysis Summary ===")
    print(f"Total records: {total}")
    print(f"Unique IPs: {len(ip_set)}")
    print("\nTop source IPs:")
    for ip, cnt in src_counter.most_common(8):
        print(f"  {ip} -> {cnt}")

    print("\nTop destination ports:")
    for p, cnt in dst_port_counter.most_common(8):
        print(f"  {p} -> {cnt}")

    if port_scan_alerts:
        print("\n⚠️ Port-scan suspects:")
        for s, n in port_scan_alerts:
            print(f"  {s} -> {n} distinct dest ports")

    if ssh_alerts:
        print("\n⚠️ SSH brute-force suspects (failed attempts to port 22):")
        for s, n in ssh_alerts:
            print(f"  {s} -> {n} failed attempts")

    return {
        "total": total,
        "unique_ips": len(ip_set),
        "top_sources": src_counter.most_common(8),
        "top_ports": dst_port_counter.most_common(8),
        "port_scan_alerts": port_scan_alerts,
        "ssh_alerts": ssh_alerts
    }

# --- Fallback / sample generator ---
SAMPLE_FILE = "packets.txt"
SAMPLE_CONTENT = """Packet: src 192.168.1.5 dest 10.0.0.1 port 80 proto TCP
Packet: src 192.168.1.9 dest 10.0.0.5 port 22 proto TCP status=Failed
2025-10-29 12:00 src=45.33.22.1 dst=10.0.0.1 dport=22 status=Failed
Packet: src 45.33.22.1 dest 10.0.0.2 port 23
Packet: src 45.33.22.1 dest 10.0.0.3 port 25
Packet: src 45.33.22.1 dest 10.0.0.4 port 53
Packet: src 45.33.22.1 dest 10.0.0.5 port 80
Packet: src 45.33.22.1 dest 10.0.0.6 port 443
Packet: src 45.33.22.1 dest 10.0.0.7 port 21
Packet: src 45.33.22.1 dest 10.0.0.8 port 8080
Packet: src 45.33.22.1 dest 10.0.0.9 port 110
Packet: src 45.33.22.1 dest 10.0.0.10 port 995
Packet: src 8.8.8.8 dest 10.0.0.1 port 53 proto UDP
Packet: src 192.168.1.5 dest 10.0.0.1 port 80 proto TCP
"""

def create_sample_packets_file(path=SAMPLE_FILE):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_CONTENT)
        print("Sample packets file created at:", path)
        return True
    except Exception as e:
        print("Could not create sample file:", e)
        return False

# --- Interactive run flow ---
def run_interactive():
    print("Packet Logger — interactive mode\n")
    # ensure CSV header exists
    ensure_csv_header()

    mode = ""
    if USE_SCAPY:
        print("Scapy detected. Live capture is available (requires root/administrator).")
        choice = input("Choose mode: (L)ive capture or (F)ile parse [L/f]: ").strip().lower()
        if choice == "" or choice == "l":
            mode = "live"
        else:
            mode = "file"
    else:
        print("Scapy not available — falling back to file parse mode.")
        mode = "file"

    if mode == "live":
        print("Starting live capture. Press Ctrl+C to stop.")
        try:
            # sniff on all interfaces; store=False to avoid memory growth
            sniff(prn=lambda pkt: (append_raw_log(pkt.summary()), append_record_csv(scapy_packet_to_record(pkt)), print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {pkt.summary()}")), store=False)
        except PermissionError:
            print("Permission error: live capture requires administrator/root privileges.")
            print("Switching to file parse mode.")
            mode = "file"
        except Exception as e:
            print("Live capture error:", e)
            mode = "file"

    if mode == "file":
        path = input(f"Enter packet text file path (press Enter for '{SAMPLE_FILE}'): ").strip() or SAMPLE_FILE
        if not os.path.exists(path):
            create = input(f"File '{path}' not found. Create sample file? [Y/n]: ").strip().lower()
            if create == "" or create == "y" or create == "yes":
                ok = create_sample_packets_file(path)
                if not ok:
                    print("Cannot create sample file. Exiting.")
                    return
            else:
                print("Please create a packet-like file and re-run. Exiting.")
                return

        # parse file and append records
        ensure_csv_header()
        total = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line.strip():
                        continue
                    total += 1
                    rec = parse_text_packet_line(line)
                    append_raw_log(rec["raw"])
                    append_record_csv(rec)
            print(f"Parsed {total} lines from {path} and appended to CSV/log.")
        except Exception as e:
            print("Error reading/parsing file:", e)
            return

    # after capture/parse, run quick analysis
    analyze_csv()

# --- Entry point ---
if __name__ == "__main__":
    try:
        run_interactive()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting cleanly.")
    except Exception as e:
        print("Unexpected error:", e)
        sys.exit(1)

