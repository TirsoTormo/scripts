<div align="center">

# ARGOS v1
### Network Intelligence & Packet Factory

[![Version](https://img.shields.io/badge/version-v1.0.0-purple.svg)](https://github.com/TirsoTormo/argos-net-intelligence)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

*CLI network intelligence suite for system administrators and network engineers.*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Architecture](#architecture) • [Disclaimer](#disclaimer)

</div>

---

## Overview

**ARGOS** is a high-performance, CLI-only network auditing tool built in Python. It integrates active network discovery, synthetic packet injection (Packet Factory), LAN speed testing, and report exporting into a clean terminal interface with Rich formatting.

> [!IMPORTANT]
> Requires **administrator/root** privileges for Layer 2 operations (ARP scan, raw sockets).

## Features

- **Resilient Auto-Discovery (L2/L3)**: ARP scans and ICMP ping sweeps with concurrent Vendor MAC lookup (local JSON cache + online fallback).
- **OS Fingerprinting**: Heuristic OS detection from TTL, TCP Window, and MSS values.
- **Packet Factory (L2/L3/L4)**: Modular packet construction and sending.
  - Custom TCP segments with specific flags (`SYN`, `ACK`, `FIN`, `RST`).
  - TCP SYN port probing with port groups (`web`, `top20`, `mikrotik`).
  - UDP probing and custom ICMP ping with TTL/payload control.
  - Manual ICMP traceroute with incremental TTL.
  - Auto-Installer: Npcap silent installer for Windows.
- **LAN Speed Test**: TCP throughput measurement between two hosts on the same network.
- **Audit Persistence**: All scans archived into SQLite and exportable to JSON, Markdown, or CSV.
- **Rich Terminal Output**: Corporate purple palette with animated tables and colored panels.

---

## Installation

### Using uv (recommended)
```bash
# Install uv
# Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and sync
git clone https://github.com/YOUR_USERNAME/argos-net-intelligence.git
cd argos-net-intelligence
make sync
```

### Using pip
```bash
pip install -e .
```

After installation via pip, the `argos` command is available globally.

---

## Usage

```bash
# Network Discovery
argos --scan
argos --scan --export-json report.json
argos --interfaces

# Packet Factory (Requires Admin/Root)
argos --probe 192.168.1.1 --ports web
argos --dst 192.168.1.1 --flags S --port 443
argos --traceroute 8.8.8.8
argos --ping 192.168.1.1 --count 10 --ttl 128

# LAN Speed Test
argos --server
argos --client <SERVER_IP>
```

Platform wrappers:
- **Windows**: `.\argos.ps1 --scan`
- **Linux/macOS**: `./argos.sh --scan`

---

## Architecture

```
src/argos/
├── __init__.py
├── __main__.py          # python -m argos entry point
├── main.py              # CLI argument parsing and command dispatch
├── core/
│   ├── discovery.py     # ARP/ICMP network scanner
│   ├── fingerprint.py   # OS fingerprinting heuristics
│   ├── models.py        # Pydantic data models
│   ├── net_utils.py     # Network utility functions
│   ├── packet_factory/  # L2/L3/L4 packet construction
│   ├── speed_test.py    # TCP throughput measurement
│   ├── terminal.py      # Rich terminal formatting (tables, panels, theme)
│   ├── updater.py       # Auto-update from GitHub
│   └── vendor_manager.py # MAC vendor resolution
└── storage/
    ├── database.py      # SQLite persistence
    └── exporter.py      # JSON/Markdown/CSV export
```

---

## Disclaimer

ARGOS is intended strictly for **authorized network auditing**, educational purposes, and systems administration tasks. The creators are **not responsible** for any misuse or illegal activities. Always ensure you have explicit permission to audit the target network.

---
<div align="center">
  <i>ARGOS v1 — Built for Network Engineers.</i>
</div>
