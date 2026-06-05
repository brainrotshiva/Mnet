"""
MNet Scan Engine
Author: brainrotshiva
"""

import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

from core.utils import (
    resolve_host, validate_target, get_cidr_hosts,
    detect_cloud_provider, is_ipv6, SERVICES
)
from core.display import Display
from modules.scanners import (
    tcp_scan, udp_scan, syn_scan, ipv6_scan,
    grab_banner, os_fingerprint, ping_host,
    detect_kubernetes, enrich_result
)
from modules.ai_analysis import ai_risk_analysis
from output.exporters import export_json, export_csv, export_html


class ScanEngine:

    def __init__(self, config: dict):
        self.config = config
        self.results: List[Dict] = []
        self.start_time = datetime.now()
        self._lock = threading.Lock()
        self._completed = 0

    def run(self):
        config = self.config
        target = config["target"]
        target_type = validate_target(target)

        # ── Ping Sweep Mode ───────────────────────────────────
        if config.get("sweep") and target_type == "cidr":
            self._sweep(target)
            return

        # ── Resolve target ────────────────────────────────────
        if target_type in ("ipv4", "hostname"):
            ip = resolve_host(target)
            if not ip:
                Display.error(f"Cannot resolve: {target}")
                return
        elif target_type == "ipv6":
            ip = target
        elif target_type == "cidr":
            # Scan first host in CIDR
            hosts = get_cidr_hosts(target)
            if not hosts:
                Display.error("Invalid or too-large CIDR. Use /16 or smaller.")
                return
            Display.warn(f"CIDR detected. Scanning {len(hosts)} hosts. Use --sweep for host discovery.")
            for host in hosts[:5]:  # limit to 5 for demo
                self._scan_single_host(host, host, "ipv4")
            return
        else:
            ip = resolve_host(target)
            if not ip:
                Display.error(f"Cannot resolve: {target}")
                return

        self._scan_single_host(target, ip, target_type)

    # ─────────────────────────────────────────────────────────
    # SINGLE HOST SCAN
    # ─────────────────────────────────────────────────────────

    def _scan_single_host(self, target: str, ip: str, target_type: str):
        config = self.config
        config["target"] = target

        # Cloud detection
        cloud_provider = detect_cloud_provider(ip)

        Display.print_scan_header(config, ip, target_type)
        Display.section("LIVE RESULTS")

        # OS fingerprint (upfront if requested)
        os_info = ""
        if config.get("os_detect"):
            Display.info("Running OS fingerprint...")
            os_info = os_fingerprint(ip)
            Display.info(f"OS Hint: {os_info}")

        # Choose scanner
        if target_type == "ipv6" or is_ipv6(ip):
            scanner = lambda port: ipv6_scan(ip, port, config["timeout"])
        elif config["scan_type"] == "udp":
            scanner = lambda port: udp_scan(ip, port, config["timeout"])
        elif config["scan_type"] == "syn":
            scanner = lambda port: syn_scan(ip, port, config["timeout"])
        else:
            scanner = lambda port: tcp_scan(ip, port, config["timeout"])

        ports = config["ports"]
        results = []
        completed = [0]

        def worker(port):
            result = scanner(port)
            result = enrich_result(result, config)
            with self._lock:
                results.append(result)
                completed[0] += 1
                if result["state"] == "open":
                    Display.print_open_port(result)
                if not config.get("quiet"):
                    Display.progress(completed[0], len(ports))
            return result

        with ThreadPoolExecutor(max_workers=config["threads"]) as executor:
            futures = [executor.submit(worker, p) for p in ports]
            for f in as_completed(futures):
                pass  # results collected in worker

        print()  # newline after progress bar

        # Kubernetes detection
        k8s_info = detect_kubernetes(results)

        # AI Analysis
        open_ports = [r for r in results if r["state"] == "open"]
        ai_summary = ""
        if config.get("vuln_check") or len(open_ports) > 0:
            Display.info("Running AI risk analysis...")
            ai_summary = ai_risk_analysis(
                target=target,
                open_ports=open_ports,
                os_hint=os_info,
                cloud_provider=cloud_provider or "",
                k8s_detected=k8s_info.get("detected", False)
            )

        # Summary
        Display.print_summary(
            results=results,
            config=config,
            start_time=self.start_time,
            os_info=os_info,
            cloud_provider=cloud_provider or "",
            k8s_info=k8s_info,
            ai_summary=ai_summary
        )

        # Exports
        if config.get("json_out"):
            export_json(results, config, config["json_out"], os_info, cloud_provider or "", ai_summary)
        if config.get("csv_out"):
            export_csv(results, config["csv_out"])
        if config.get("html_out"):
            export_html(results, config, config["html_out"], os_info, cloud_provider or "", ai_summary)

    # ─────────────────────────────────────────────────────────
    # PING SWEEP
    # ─────────────────────────────────────────────────────────

    def _sweep(self, cidr: str):
        hosts = get_cidr_hosts(cidr)
        if not hosts:
            Display.error("Invalid CIDR or network too large.")
            return

        Display.section(f"PING SWEEP — {cidr}  ({len(hosts)} hosts)")
        up_count = 0

        def check_host(ip):
            is_up, latency = ping_host(ip)
            if is_up:
                cloud = detect_cloud_provider(ip)
                return ip, latency, cloud
            return None

        with ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
            futures = {executor.submit(check_host, h): h for h in hosts}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    ip, lat, cloud = result
                    Display.print_host_up(ip, lat, cloud=cloud or "")
                    up_count += 1

        Display.section(f"SWEEP COMPLETE — {up_count}/{len(hosts)} hosts up")
