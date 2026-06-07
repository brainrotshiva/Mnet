"""
MNet Display Module
Author: brainrotshiva
"""
import sys
from datetime import datetime
from core.utils import severity_color, CLOUD_PORT_HINTS

RESET  = "\033[0m"
GREEN  = "\033[38;5;46m"
RED    = "\033[38;5;196m"
YELLOW = "\033[38;5;220m"
ORANGE = "\033[38;5;208m"
BLUE   = "\033[38;5;39m"
CYAN   = "\033[38;5;87m"
GRAY   = "\033[38;5;245m"
WHITE  = "\033[38;5;255m"
BOLD   = "\033[1m"

class Display:
    @staticmethod
    def banner():
        print(f"{GREEN}MNet — Mapping Network Tool v2.0.26{RESET}")
    @staticmethod
    def info(msg): print(f"  {BLUE}[*]{RESET} {msg}")
    @staticmethod
    def success(msg): print(f"  {GREEN}[+]{RESET} {msg}")
    @staticmethod
    def warn(msg): print(f"  {YELLOW}[!]{RESET} {msg}")
    @staticmethod
    def error(msg): print(f"  {RED}[-]{RESET} {msg}")
    @staticmethod
    def section(title):
        print(f"\n{CYAN}{'─'*62}{RESET}")
        print(f"{CYAN}  {title}{RESET}")
        print(f"{CYAN}{'─'*62}{RESET}")
    @staticmethod
    def print_open_port(p):
        port=p["port"]; service=p.get("service") or "unknown"
        banner=p.get("banner") or ""; proto=p.get("proto","tcp")
        cloud=p.get("cloud_hint") or ""; vulns=p.get("vulns") or []
        crit=[21,22,23,445,3389,6379,2375,10250,5900,8888]
        color=ORANGE if port in crit else GREEN
        print(f"  {color}{'OPEN':<8}{RESET}  {WHITE}{port}/{proto:<12}{RESET}  {CYAN}{service:<22}{RESET}  {GRAY}{banner[:40]}{RESET}")
        if cloud: print(f"           {YELLOW}↳ {cloud}{RESET}")
        for cve,desc,sev in vulns:
            print(f"           {severity_color(sev)}⚠  [{sev}] {cve} — {desc}{RESET}")
    @staticmethod
    def print_host_up(ip,latency,os_hint="",cloud=""):
        cloud_tag=f" {YELLOW}[{cloud}]{RESET}" if cloud else ""
        print(f"  {GREEN}[UP]{RESET}  {WHITE}{ip:<20}{RESET}  {GRAY}{latency:.1f}ms{RESET}{cloud_tag}")
    @staticmethod
    def print_scan_header(config,ip,target_type):
        Display.section("SCAN CONFIGURATION")
        print(f"  {GRAY}Target   :{RESET} {WHITE}{config['target']}{RESET} -> {ip}")
        print(f"  {GRAY}Mode     :{RESET} {WHITE}{config['scan_type'].upper()}{RESET}")
        print(f"  {GRAY}Ports    :{RESET} {WHITE}{len(config['ports'])} ports{RESET}")
        print(f"  {GRAY}Threads  :{RESET} {WHITE}{config['threads']}{RESET}")
        print(f"  {GRAY}Started  :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    @staticmethod
    def print_summary(results,config,start_time,os_info="",cloud_provider="",k8s_info=None,ai_summary=""):
        elapsed=(datetime.now()-start_time).total_seconds()
        open_ports=[r for r in results if r["state"]=="open"]
        vuln_count=sum(len(r.get("vulns",[])) for r in open_ports)
        crit_count=sum(1 for r in open_ports for v in r.get("vulns",[]) if v[2]=="CRITICAL")
        Display.section("SCAN RESULTS SUMMARY")
        print(f"  {GRAY}Target     :{RESET} {WHITE}{config['target']}{RESET}")
        if os_info: print(f"  {GRAY}OS Hint    :{RESET} {WHITE}{os_info}{RESET}")
        if cloud_provider: print(f"  {GRAY}Cloud      :{RESET} {YELLOW}{cloud_provider}{RESET}")
        print(f"  {GRAY}Open Ports :{RESET} {GREEN}{len(open_ports)}{RESET}/{len(results)}")
        print(f"  {GRAY}Duration   :{RESET} {elapsed:.2f}s")
        if ai_summary:
            Display.section("AI RISK ANALYSIS")
            for line in ai_summary.strip().split("\n"): print(f"  {line}")
        risk="CRITICAL" if crit_count>=3 else "HIGH" if crit_count>=1 else "MEDIUM" if vuln_count>=3 else "LOW"
        Display.section("RISK SCORE")
        print(f"  {severity_color(risk)}{BOLD}{risk}{RESET}")
        print()
    @staticmethod
    def progress(current,total,label="Scanning"):
        pct=int((current/total)*40)
        bar=f"{GREEN}{'█'*pct}{GRAY}{'░'*(40-pct)}{RESET}"
        sys.stdout.write(f"\r  [{bar}] {current}/{total}")
        sys.stdout.flush()
        if current==total: print()
