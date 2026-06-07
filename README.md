# MNet — Mapping Network Tool

<div align="center">

```
███╗   ███╗███╗   ██╗███████╗████████╗
████╗ ████║████╗  ██║██╔════╝╚══██╔══╝
██╔████╔██║██╔██╗ ██║█████╗     ██║
██║╚██╔╝██║██║╚██╗██║██╔══╝     ██║
██║ ╚═╝ ██║██║ ╚████║███████╗   ██║
╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝
```

**Mapping Network Tool — v2.0.26**

[![Python](https://img.shields.io/badge/Python-3.6+-green?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20macOS-blue?style=flat-square)](https://github.com/brainrotshiva/mnet)
[![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-brainrotshiva-cyan?style=flat-square)](https://github.com/brainrotshiva)

*Next-generation network mapper built for 2026 infrastructure*

</div>

---

## What is MNet?

**MNet** (Mapping Network) is a modern, Python-based network reconnaissance tool inspired by Nmap — but designed for today's infrastructure. While traditional scanners focus on ports and services, MNet understands **cloud environments**, **containerized workloads**, **Kubernetes clusters**, and **IPv6 networks** — with built-in **AI-powered risk analysis**.

> "Nmap maps networks. MNet maps *modern* networks."

---

## Features

| Feature | Description |
|---|---|
| **TCP / SYN / UDP Scanning** | Full scan mode support |
| **IPv6 Support** | Native IPv6 host and port scanning |
| **Cloud Awareness** | Detects AWS, Azure, GCP by IP fingerprint |
| **Kubernetes Detection** | Identifies exposed K8s API, Kubelet, etcd |
| **Container Port Intelligence** | Recognizes Docker, Kubernetes, service mesh ports |
| **AI Risk Analysis** | Claude-powered (or offline rule-based) threat prioritization |
| **CVE / Vuln Hints** | Maps open ports to known CVEs automatically |
| **OS Fingerprinting** | TTL-based OS detection |
| **Banner Grabbing** | Service version identification |
| **Ping Sweep** | CIDR-based host discovery |
| **HTML / JSON / CSV Reports** | Professional exportable reports |
| **Progress Bar** | Real-time live scan progress |
| **Kali Linux Installer** | One-command install script |

---

## Quick Install (Kali Linux)

**One-line install:**
```bash
git clone https://github.com/brainrotshiva/Mnet && cd Mnet && chmod +x install.sh && sudo ./install.sh
```

Then run from anywhere:
```bash
mnet 192.168.1.1
```

---

## Manual Install

```bash
git clone https://github.com/brainrotshiva/mnet
cd mnet
python3 mnet.py --help
```

No external dependencies — runs on Python 3.6+ standard library only.

---

## Usage

After install, use `mnet` just like `nmap` — short and simple:

```bash
# Basic scan
mnet 192.168.1.1

# Full recon
mnet 192.168.1.1 --vuln --os

# Specific ports
mnet 192.168.1.1 -p 22,80,443

# All ports
mnet 192.168.1.1 -p all

# Top 100 ports
mnet 192.168.1.1 --top100

# UDP scan
mnet 192.168.1.1 -sU

# Stealth SYN scan
sudo mnet 192.168.1.1 -sS

# IPv6 scan
mnet 2001:db8::1

# Ping sweep
mnet 192.168.1.0/24 --sweep

# Save HTML report
mnet 192.168.1.1 --vuln --html report.html

# Save JSON + CSV
mnet 192.168.1.1 --json scan.json --csv scan.csv
```

> Without install, use `python3 mnet.py` instead of `mnet`

---

## All Options

```
Scan Modes:
  -sT, --tcp        TCP Connect scan (default)
  -sS, --stealth    SYN scan (requires root)
  -sU, --udp        UDP scan (requires root)
  --sweep           Ping sweep for CIDR blocks

Port Options:
  -p, --ports       Port range: 1-1000 | 22,80,443 | all
  --top100          Top 100 common ports
  --top1000         Top 1000 common ports

Detection:
  --banner          Grab service banners
  --os              OS fingerprinting
  --vuln            CVE hints + AI risk analysis

Performance:
  -t, --threads     Thread count (default: 150)
  --timeout         Per-port timeout in seconds (default: 1.0)

Output:
  --json FILE       JSON report
  --csv  FILE       CSV report
  --html FILE       HTML report
  -v, --verbose     Show all ports including closed/filtered
  -q, --quiet       Suppress progress bar
```

---

## AI-Powered Analysis

MNet integrates with **Claude (Anthropic)** for intelligent risk analysis:

```bash
export ANTHROPIC_API_KEY="your-key-here"
mnet 10.0.0.1 --vuln
```

Without an API key, MNet automatically falls back to built-in rule-based analysis covering 30+ critical vulnerability patterns.

---

## Cloud & Container Awareness

MNet recognizes cloud-native services automatically:

| Port | Service | Risk |
|---|---|---|
| 2375 | Docker Engine API | CRITICAL |
| 6443 | Kubernetes API Server | CRITICAL |
| 10250 | Kubelet API | CRITICAL |
| 2379 | etcd | CRITICAL |
| 9200 | Elasticsearch | HIGH |
| 8500 | Consul | HIGH |
| 8200 | Vault | HIGH |

When multiple Kubernetes ports are found open, MNet triggers a dedicated **Kubernetes Cluster Alert** with remediation steps.

---

## CVE Mapping

MNet maps open ports to known CVEs automatically:

| Port | CVE | Severity |
|---|---|---|
| 445/SMB | CVE-2017-0144 (EternalBlue) | CRITICAL |
| 3389/RDP | CVE-2019-0708 (BlueKeep) | CRITICAL |
| 22/SSH | CVE-2023-38408 | CRITICAL |
| 80/HTTP | CVE-2021-41773 (Apache) | CRITICAL |
| 6379/Redis | CVE-2022-0543 | CRITICAL |
| 2375/Docker | CVE-2019-5736 | CRITICAL |

---

## Report Examples

### Terminal Output
```
  OPEN      22/tcp        SSH                   SSH-2.0-OpenSSH_8.9
           ⚠  [CRITICAL] CVE-2023-38408 — OpenSSH Remote Code Execution

  OPEN      6443/tcp      Kubernetes            
           ↳ Cloud/Container: Kubernetes API Server

  OPEN      10250/tcp     Kubelet               
           ⚠  [CRITICAL] Kubelet API exposed = container exec + secret read

☸  KUBERNETES CLUSTER DETECTED
  confidence          : 80%
  risk                : CRITICAL — Kubernetes internals exposed to network
  recommendation      : Restrict 6443, 10250, 2379 with firewall/RBAC immediately
```

### HTML Report
A dark-themed, professional HTML report is generated with:
- Stats dashboard
- AI risk analysis block
- Full port table with CVE highlights
- Cloud/K8s indicators

---

## Project Structure

```
mnet/
├── mnet.py              # Entry point & CLI
├── install.sh           # Kali Linux installer
├── requirements.txt
├── core/
│   ├── engine.py        # Scan orchestration
│   ├── display.py       # Terminal UI
│   └── utils.py         # Port lists, helpers, CVE data
├── modules/
│   ├── scanners.py      # TCP/UDP/SYN/IPv6/Banner/OS scanners
│   └── ai_analysis.py   # Claude API + offline rule-based AI
└── output/
    └── exporters.py     # JSON, CSV, HTML exporters
```

---

## Tested On

- Kali Linux 2024+
- Ubuntu 22.04 / 24.04
- macOS 13+
- Python 3.8 — 3.12

---

## Legal Disclaimer

This tool is for **authorized security testing and educational use only**.

Do not scan systems without explicit permission. Unauthorized port scanning may violate laws in your jurisdiction. The author is not responsible for misuse.

Use on:
- Your own systems
- Lab environments (TryHackMe, HackTheBox, VulnHub)
- Systems where you have written authorization

---

## Author

**brainrotshiva** — Cybersecurity fresher, CTF player, SOC enthusiast

- GitHub: [@brainrotshiva](https://github.com/brainrotshiva)
- Certifications: HSCCSP
- Based in Hyderabad, India

---

## Related MITRE ATT&CK Techniques

- [T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1590 — Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)

---

<div align="center">
Built with Python — No dependencies — Works on Kali out of the box
</div>
