ishma-cybsec      cybersecurity madhun mediate level

Packet Logger (sim) · Password Length Checker
Intermediate, lightweight Python tools for digital forensics & app security — built for TalTech projects, SOC/IR labs, and portfolio demos.

Hey — this repo bundles two compact, no-friction projects you can run in any Python 3 IDE (IDLE / Thonny / VS Code). They’re designed to teach forensic thinking and app security basics without heavy installs or admin privileges. Perfect for TalTech coursework or internship demos.

Projects included
1) Packet Logger — Simulator / Analyzer (packet_logger_safe.py)

A plain-Python packet log parser and lightweight analyzer that:

Parses simple packet-like text files (packets.txt) so you can simulate network traffic without capturing live packets or needing root.

Produces a CSV summary (packet_summary.csv) and raw log (packet_log.txt).

Summarizes: total packets, unique IPs, top source IPs, top destination ports.

Flags simple suspicious behaviours:

Port scan — same source probing many distinct destination ports.

SSH brute-force — repeated failed attempts to port 22.

IDE-friendly: interactive prompts, auto-creates a sample packets.txt if missing, graceful error handling.

Why useful: demonstrates network-level forensics and SOC detection logic without root/Scapy. Good for IR labs, detection engineering, and showing pipeline automation.

2) Password Length Checker (password_length_checker.py)

A tiny CLI tool that:

Reads single password input or a batch file (one password per line).

Reports simple strength hints focused on length and basic character variety.

Outputs formatted case IDs with leading zeros (e.g., #001) for clear reporting.

Designed as a minimal, safe audit tool — ideal for teaching password policy basics and for integration into bigger audits.

Why useful: password hygiene is a core security control. This lightweight tool shows automated checks, logging style, and how to present results to reviewers or as part of an intake pipeline.

Tech stack & requirements

Language: Python 3.8+ (works on any Python 3 interpreter)

No external libraries required for the default modes. (Optional: Scapy for live capture — not recommended for TalTech classroom demos unless you have admin privileges.)
