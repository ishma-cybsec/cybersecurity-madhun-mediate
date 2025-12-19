Intermediate Python Tools for Cybersecurity & Digital Forensics

This repository contains two lightweight Python tools developed for practicing digital forensics, basic SOC detection logic, and application security concepts. The projects are intentionally designed to be safe, auditable, and runnable in standard Python environments without administrative privileges or external dependencies.

The focus is on methodology and analysis, not offensive exploitation.


---

Projects Included

1. Packet Logger – Simulator & Analyzer

packet_logger_safe.py

A plain-Python packet log parser and analyzer that simulates network traffic analysis using text-based packet records.

Key functionality:

Parses packet-like log files (packets.txt) to simulate traffic without live capture

Generates structured outputs:

packet_log.txt (raw processed logs)

packet_summary.csv (aggregated analysis)


Computes:

Total packet count

Unique IP addresses

Most frequent source IPs

Most targeted destination ports


Detects simple suspicious patterns:

Port scanning behaviour (single source → multiple ports)

Repeated SSH attempts on port 22


Includes input validation, error handling, and sample data auto-generation


Learning focus:
Network forensics, log analysis, detection logic, reporting discipline


---

2. Password Length Checker

password_length_checker.py

A minimal command-line utility for basic password policy auditing.

Key functionality:

Accepts single password input or batch input from a file

Evaluates passwords based on:

Length

Basic character diversity


Outputs clearly formatted audit results with case IDs

Designed for safe, non-invasive analysis


Learning focus:
Password hygiene, automation, structured reporting


---

Technical Details

Language: Python 3.8+

Dependencies: None (standard library only)

Environment: Works in any Python IDE (IDLE, Thonny, VS Code)

Data handling: Text-based input files (no databases)
