# ishma-cybsec intermediate tools

**Packet Logger (sim)** · **Password Length Checker**
*Intermediate, lightweight Python tools for digital forensics & app security — built for TalTech projects, SOC/IR labs, and portfolio demos.*

Hey — this repo bundles two compact, no-friction projects you can run in any Python 3 IDE (IDLE / Thonny / VS Code). They’re designed to teach forensic thinking and app security basics without heavy installs or admin privileges. Perfect for TalTech coursework or internship demos.

---

## Projects included

### 1) Packet Logger — Simulator / Analyzer (`packet_logger_safe.py`)

A plain-Python packet *log parser* and lightweight analyzer that:

* Parses simple packet-like text files (`packets.txt`) so you can simulate network traffic without capturing live packets or needing root.
* Produces a CSV summary (`packet_summary.csv`) and raw log (`packet_log.txt`).
* Summarizes: total packets, unique IPs, top source IPs, top destination ports.
* Flags simple suspicious behaviours:

  * **Port scan** — same source probing many distinct destination ports.
  * **SSH brute-force** — repeated failed attempts to port 22.
* IDE-friendly: interactive prompts, auto-creates a sample `packets.txt` if missing, graceful error handling.

**Why useful:** demonstrates network-level forensics and SOC detection logic without root/Scapy. Good for IR labs, detection engineering, and showing pipeline automation.

---

### 2) Password Length Checker (`password_length_checker.py`)

A tiny CLI tool that:

* Reads single password input or a batch file (one password per line).
* Reports simple strength hints focused on **length** and basic character variety.
* Outputs formatted case IDs with leading zeros (e.g., `#001`) for clear reporting.
* Designed as a minimal, safe audit tool — ideal for teaching password policy basics and for integration into bigger audits.

**Why useful:** password hygiene is a core security control. This lightweight tool shows automated checks, logging style, and how to present results to reviewers or as part of an intake pipeline.

---

## Tech stack & requirements

* Language: **Python 3.8+** (works on any Python 3 interpreter)
* No external libraries required for the default modes. (Optional: Scapy for live capture — not recommended for TalTech classroom demos unless you have admin privileges.)
* Files: the tools rely on small text files (e.g., `packets.txt`, optional `pwlist.txt`) — no DBs.

---

## Quick start (run locally, no installs)

1. Clone the repo (or copy files into a folder).
2. Open your Python IDE and run the script you want.

**Packet Logger (safe, interactive)**

```bash
# from terminal or run in IDE
python packet_logger_safe.py
# follow prompts; press Enter to use default 'packets.txt' sample
```

**Password Length Checker (single or batch)**

```bash
python password_length_checker.py
# or for batch:
python password_length_checker.py --batch pwlist.txt --out pw_report.txt
```

---

## Example usage & sample output

**Packet Logger (console excerpt)**

```
Packet Logger — interactive mode
Scapy not available — falling back to file parse mode.
Enter packet text file path (press Enter for 'packets.txt'):

Parsed 14 lines from packets.txt and appended to CSV/log.

=== Packet Logger Summary ===
Total packet-like lines: 14
Unique IPs seen: 6

Top 5 source IPs:
  45.33.22.1 -> 10 packets
  192.168.1.5 -> 2 packets

Top 5 destination ports:
  80 -> 4 hits
  22 -> 3 hits

⚠️ Port-scan suspects (source IP, distinct dest ports):
  45.33.22.1 -> 11 distinct ports

CSV saved to: packet_summary.csv
```

**Password Length Checker (console excerpt)**

```
Enter password (or path to batch file): hunter2
Case #001: hunter* | Length: 7 -> Weak (less than 8 chars)
Advice: Use >= 12 chars and a password manager.
```

---

## Safety & ethics

* **Do not** capture or analyze network traffic you are not authorized to access. Use the text-based simulator or lab networks only.
* The packet logger falls back to a safe, *local* text file approach by default. Only use Scapy/live capture on systems where you have permission and with instructor approval.
* Password tools are for **testing & auditing owned data only**. Never attempt to test passwords on live accounts without explicit permission.

---

## How these help with TalTech / forensic-heavy applications

* Both projects teach **core forensic concepts**: evidence collection (logs/hashes), timeline/aggregation (packet summaries), detection heuristics (brute force / port scans), and secure reporting.
* Lightweight & reproducible — easy to include in coursework, demo in labs, or expand into bigger IR projects (memory parsing, YARA scanning, SIEM rule testing).
* The formats (CSV, plain text) are compatible with further processing in research projects or TalTech assignments.

---

## Extend & next steps (ideas)

* Packet Logger: add time-window heuristics, sliding window port-scan detection, GeoIP enrichment, or simple HTML dashboard export.
* Password Checker: add offline leak checking (SHA256 set matching), HIBP k-anonymity integration, complexity scoring, or integrate into a mock registration form.
* Wrap both in a small CLI wrapper or a `Makefile` for reproducible lab runs.

---

## Contributing

Want to add features or improve docs? PRs welcome. Keep changes:

* lightweight (no heavy deps unless optional),
* privacy-preserving, and
* accompanied by a brief README update and usage example.

---

## License

MIT — feel free to reuse for learning, coursework, and portfolio demos. If you publish a public demo, **remove vulnerable live capture code** and include the safety note prominently.

---

If you want, I’ll:

* create a polished `README.md` file ready to commit, or
* generate example `packets.txt` and `pwlist.txt` sample files you can drop into the repo and run immediately.

Which of those would you like next?
