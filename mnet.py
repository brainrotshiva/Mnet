#!/usr/bin/env python3
"""
MNet — Mapping Network Tool v2.0.26
Author  : brainrotshiva
GitHub  : https://github.com/brainrotshiva
License : MIT

Usage:
  python mnet.py <target> [options]
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
from core.engine import ScanEngine
from core.display import Display
from core.utils import validate_target, parse_ports, check_root, TOP_100_PORTS, TOP_1000_PORTS


def main():
    Display.banner()

    parser = argparse.ArgumentParser(
        prog="mnet",
        description="MNet — Mapping Network Tool by brainrotshiva",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
\033[38;5;46mExamples:\033[0m
  python mnet.py 192.168.1.1
  python mnet.py scanme.nmap.org -p 1-1000 --banner
  python mnet.py 10.0.0.1 -p 22,80,443,2375,6443 --vuln --os
  python mnet.py 192.168.1.0/24 --sweep
  python mnet.py 10.0.0.1 -p 1-65535 -t 500 --html report.html
  python mnet.py 2001:db8::1 --top100              # IPv6 scan
  python mnet.py 10.0.0.1 --stealth --vuln --os    # Full recon

\033[38;5;245mAI Analysis: set ANTHROPIC_API_KEY env var for Claude-powered risk reports\033[0m
        """
    )

    # Target
    parser.add_argument("target", help="IP, hostname, IPv6, or CIDR (e.g. 192.168.1.0/24)")

    # Scan modes
    scan_group = parser.add_argument_group("Scan Modes")
    scan_group.add_argument("-sT", "--tcp",     action="store_true", help="TCP Connect scan (default)")
    scan_group.add_argument("-sS", "--stealth", action="store_true", help="Stealth SYN scan (requires root)")
    scan_group.add_argument("-sU", "--udp",     action="store_true", help="UDP scan (requires root)")
    scan_group.add_argument("--sweep",          action="store_true", help="Ping sweep — host discovery on CIDR")

    # Port options
    port_group = parser.add_argument_group("Port Options")
    port_group.add_argument("-p", "--ports",  default="1-1024", help="Ports: 1-1000 | 22,80,443 | 'all' (default: 1-1024)")
    port_group.add_argument("--top100",  action="store_true", help="Scan top 100 common ports")
    port_group.add_argument("--top1000", action="store_true", help="Scan top 1000 common ports")

    # Detection modules
    detect_group = parser.add_argument_group("Detection Modules")
    detect_group.add_argument("--banner", action="store_true", help="Grab service banners")
    detect_group.add_argument("--os",     action="store_true", help="OS fingerprinting (TTL-based)")
    detect_group.add_argument("--vuln",   action="store_true", help="Vuln hints + CVE mapping + AI analysis")

    # Performance
    perf_group = parser.add_argument_group("Performance")
    perf_group.add_argument("-t", "--threads", type=int,   default=150, help="Threads (default: 150)")
    perf_group.add_argument("--timeout",       type=float, default=1.0, help="Timeout per port in seconds (default: 1.0)")

    # Output
    out_group = parser.add_argument_group("Output")
    out_group.add_argument("--json", metavar="FILE", help="Export JSON report")
    out_group.add_argument("--csv",  metavar="FILE", help="Export CSV report")
    out_group.add_argument("--html", metavar="FILE", help="Export HTML report (beautiful)")
    out_group.add_argument("-v", "--verbose", action="store_true", help="Show closed/filtered ports too")
    out_group.add_argument("-q", "--quiet",   action="store_true", help="Suppress progress bar")

    args = parser.parse_args()

    # Root check
    if (args.stealth or args.udp) and not check_root():
        Display.warn("Stealth/UDP scan requires root. Falling back to TCP Connect.")
        args.stealth = False
        args.udp = False

    # Port resolution
    if args.top100:
        ports = TOP_100_PORTS
    elif args.top1000:
        ports = TOP_1000_PORTS
    elif args.ports == "all":
        ports = list(range(1, 65536))
        Display.warn("Full port scan (1-65535) selected. This will take a while.")
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            Display.error("Invalid port specification. Use: 1-1024 or 22,80,443")
            sys.exit(1)

    # Scan type
    if args.stealth:   scan_type = "syn"
    elif args.udp:     scan_type = "udp"
    else:              scan_type = "tcp"

    # Config
    config = {
        "target":     args.target,
        "ports":      ports,
        "scan_type":  scan_type,
        "threads":    args.threads,
        "timeout":    args.timeout,
        "banner":     args.banner,
        "os_detect":  args.os,
        "vuln_check": args.vuln,
        "verbose":    args.verbose,
        "quiet":      args.quiet,
        "sweep":      args.sweep,
        "json_out":   args.json,
        "csv_out":    args.csv,
        "html_out":   args.html,
    }

    engine = ScanEngine(config)
    engine.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  \033[38;5;196m[!] Scan aborted.\033[0m\n")
        sys.exit(0)
