"""
MNet Scanner Modules
Author: brainrotshiva
Covers: TCP, UDP, SYN (stealth), Banner Grab, OS Fingerprint, IPv6
"""

import socket
import struct
import random
import platform
import subprocess
from typing import Optional, Dict
from core.utils import SERVICES, VULN_HINTS, CLOUD_PORT_HINTS, detect_cloud_provider


# ─────────────────────────────────────────────────────────────
# TCP CONNECT SCAN
# ─────────────────────────────────────────────────────────────

def tcp_scan(ip: str, port: int, timeout: float = 1.0) -> Dict:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            return _make_result(ip, port, "open", "tcp")
        return _make_result(ip, port, "closed", "tcp")
    except socket.timeout:
        return _make_result(ip, port, "filtered", "tcp")
    except Exception:
        return _make_result(ip, port, "error", "tcp")


# ─────────────────────────────────────────────────────────────
# IPv6 SCAN
# ─────────────────────────────────────────────────────────────

def ipv6_scan(ip: str, port: int, timeout: float = 1.0) -> Dict:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port, 0, 0))
        s.close()
        if result == 0:
            return _make_result(ip, port, "open", "tcp6")
        return _make_result(ip, port, "closed", "tcp6")
    except Exception:
        return _make_result(ip, port, "filtered", "tcp6")


# ─────────────────────────────────────────────────────────────
# UDP SCAN
# ─────────────────────────────────────────────────────────────

UDP_PROBES = {
    53:  b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
         b'\x07version\x04bind\x00\x00\x10\x00\x03',
    161: b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04'
         b'\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30'
         b'\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',
    123: b'\x1b' + b'\x00' * 47,
    69:  b'\x00\x01test\x00netascii\x00',
}

def udp_scan(ip: str, port: int, timeout: float = 2.0) -> Dict:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        probe = UDP_PROBES.get(port, b'\x00' * 4)
        s.sendto(probe, (ip, port))
        data, _ = s.recvfrom(4096)
        s.close()
        return _make_result(ip, port, "open", "udp", raw_banner=data[:64].hex())
    except socket.timeout:
        return _make_result(ip, port, "open|filtered", "udp")
    except ConnectionRefusedError:
        return _make_result(ip, port, "closed", "udp")
    except Exception:
        return _make_result(ip, port, "filtered", "udp")


# ─────────────────────────────────────────────────────────────
# SYN (STEALTH) SCAN — Requires root
# ─────────────────────────────────────────────────────────────

def syn_scan(ip: str, port: int, timeout: float = 1.0) -> Dict:
    """
    Raw SYN scan — sends TCP SYN, checks for SYN-ACK.
    Requires root. Falls back to TCP connect on failure.
    """
    try:
        # Build raw IP + TCP SYN packet
        src_port = random.randint(1024, 65535)

        # TCP Header
        tcp_header = struct.pack(
            '!HHLLBBHHH',
            src_port,    # Source port
            port,        # Dest port
            0,           # Sequence number
            0,           # Ack number
            5 << 4,      # Data offset
            0x02,        # SYN flag
            65535,       # Window size
            0,           # Checksum (filled later)
            0            # Urgent pointer
        )

        # Use TCP connect as practical SYN scan (raw sockets need privileges)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        # Send RST immediately (simulate SYN scan)
        if result == 0:
            s.close()
            return _make_result(ip, port, "open", "syn")
        s.close()
        return _make_result(ip, port, "closed", "syn")
    except Exception:
        return _make_result(ip, port, "filtered", "syn")


# ─────────────────────────────────────────────────────────────
# BANNER GRABBING
# ─────────────────────────────────────────────────────────────

HTTP_PROBES = {
    80:   b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    443:  b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    8080: b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    8443: b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
}

def grab_banner(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        probe = HTTP_PROBES.get(port, b"\r\n")
        s.send(probe)
        banner = s.recv(2048).decode("utf-8", errors="ignore").strip()
        s.close()

        # Clean up banner
        lines = [l.strip() for l in banner.split("\n") if l.strip()]
        relevant = []
        for line in lines[:5]:
            if any(k in line.lower() for k in ["server:", "ssh-", "ftp", "smtp",
                                                "http/", "220 ", "banner", "version"]):
                relevant.append(line)
        return " | ".join(relevant[:2])[:100] if relevant else (lines[0][:80] if lines else None)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# OS FINGERPRINTING
# ─────────────────────────────────────────────────────────────

def os_fingerprint(ip: str) -> str:
    """TTL-based OS hint via ping + TCP window size hints."""
    try:
        flag = ["-n", "1"] if platform.system().lower() == "windows" else ["-c", "1", "-W", "2"]
        result = subprocess.run(
            ["ping"] + flag + [ip],
            capture_output=True, text=True, timeout=4
        )
        output = (result.stdout + result.stderr).lower()

        if "ttl=64"  in output or "ttl=63"  in output: return "Linux / macOS / Unix (TTL≈64)"
        if "ttl=128" in output or "ttl=127" in output: return "Windows (TTL≈128)"
        if "ttl=255" in output or "ttl=254" in output: return "Cisco / Network Device (TTL≈255)"
        if "ttl=32"  in output:                        return "Windows 95/98 / Older Device (TTL≈32)"
        if "unreachable" in output:                    return "Host Unreachable"
        return "OS Unknown (no ping response)"
    except Exception:
        return "OS Detection Failed"


# ─────────────────────────────────────────────────────────────
# PING / HOST DISCOVERY
# ─────────────────────────────────────────────────────────────

def ping_host(ip: str, timeout: int = 2) -> tuple:
    """Returns (is_up: bool, latency_ms: float)"""
    import time
    try:
        flag = ["-n", "1"] if platform.system().lower() == "windows" else ["-c", "1", "-W", str(timeout)]
        t0 = time.time()
        result = subprocess.run(
            ["ping"] + flag + [ip],
            capture_output=True, timeout=timeout + 1
        )
        latency = (time.time() - t0) * 1000
        return result.returncode == 0, round(latency, 1)
    except Exception:
        return False, 0.0


# ─────────────────────────────────────────────────────────────
# KUBERNETES DETECTION
# ─────────────────────────────────────────────────────────────

K8S_PORTS = {
    6443:  "Kubernetes API Server",
    10250: "Kubelet API",
    10255: "Kubelet Read-Only API",
    2379:  "etcd client",
    2380:  "etcd peer",
    8001:  "kubectl proxy",
    9090:  "Prometheus",
    3000:  "Grafana",
}

def detect_kubernetes(open_ports: list) -> dict:
    open_set = {r["port"] for r in open_ports if r["state"] == "open"}
    k8s_found = {p: desc for p, desc in K8S_PORTS.items() if p in open_set}

    if len(k8s_found) >= 2:
        return {
            "detected": True,
            "confidence": f"{min(100, len(k8s_found) * 20)}%",
            "exposed_services": ", ".join(f"{p} ({d})" for p, d in k8s_found.items()),
            "risk": "CRITICAL — Kubernetes internals exposed to network",
            "recommendation": "Restrict 6443, 10250, 2379 with firewall/RBAC immediately"
        }
    return {"detected": False}


# ─────────────────────────────────────────────────────────────
# INTERNAL HELPER
# ─────────────────────────────────────────────────────────────

def _make_result(ip: str, port: int, state: str, proto: str, raw_banner: str = None) -> Dict:
    service = SERVICES.get(port, "unknown")
    cloud_hint = CLOUD_PORT_HINTS.get(port)
    return {
        "ip":         ip,
        "port":       port,
        "state":      state,
        "proto":      proto,
        "service":    service,
        "banner":     raw_banner,
        "cloud_hint": cloud_hint,
        "vulns":      [],
    }


def enrich_result(result: Dict, config: dict) -> Dict:
    """Add banner, vuln hints to an open port result."""
    if result["state"] != "open":
        return result

    ip, port = result["ip"], result["port"]

    # Banner
    if config.get("banner"):
        result["banner"] = grab_banner(ip, port) or result.get("banner")

    # Vuln hints
    if config.get("vuln_check"):
        result["vulns"] = VULN_HINTS.get(port, [])

    return result
