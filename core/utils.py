"""
MNet Core Utilities
Author: brainrotshiva
"""

import os
import re
import socket
import ipaddress
from typing import List, Optional

# ─────────────────────────────────────────────────────────────
# TOP PORT LISTS
# ─────────────────────────────────────────────────────────────

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 123,
    135, 139, 143, 161, 194, 389, 443, 445, 465, 514,
    515, 587, 631, 636, 993, 995, 1080, 1194, 1433, 1521,
    1723, 2049, 2181, 2375, 2376, 3000, 3306, 3389, 3690, 4443,
    4444, 5000, 5432, 5672, 5900, 5985, 5986, 6379, 6443, 7001,
    7077, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300,
    9418, 9999, 10250, 10255, 11211, 15672, 27017, 27018, 28015, 50000,
    50070, 50075, 61616, 2222, 4040, 4848, 6000, 7000, 7474, 7687,
    8008, 8009, 8161, 8500, 8983, 9042, 9092, 9160, 9600, 27443,
    32768, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 65535
]

TOP_1000_PORTS = list(range(1, 1025)) + [
    1080, 1194, 1433, 1521, 1723, 2049, 2181, 2375, 2376,
    3000, 3306, 3389, 4444, 5000, 5432, 5672, 5900, 5985,
    6379, 6443, 7001, 8000, 8080, 8443, 8888, 9000, 9200,
    9300, 10250, 11211, 15672, 27017, 50070
]
TOP_1000_PORTS = sorted(set(TOP_1000_PORTS))

# ─────────────────────────────────────────────────────────────
# COMMON SERVICES
# ─────────────────────────────────────────────────────────────

SERVICES = {
    20: "FTP-Data",       21: "FTP",            22: "SSH",
    23: "Telnet",         25: "SMTP",            53: "DNS",
    67: "DHCP",           68: "DHCP",            69: "TFTP",
    80: "HTTP",           110: "POP3",           111: "RPCBind",
    119: "NNTP",          123: "NTP",            135: "MS-RPC",
    137: "NetBIOS-NS",    138: "NetBIOS-DGM",    139: "NetBIOS-SSN",
    143: "IMAP",          161: "SNMP",           194: "IRC",
    389: "LDAP",          443: "HTTPS",          445: "SMB",
    465: "SMTPS",         514: "Syslog",         515: "LPD",
    587: "SMTP-Sub",      631: "IPP",            636: "LDAPS",
    993: "IMAPS",         995: "POP3S",          1080: "SOCKS",
    1194: "OpenVPN",      1433: "MSSQL",         1521: "Oracle",
    1723: "PPTP",         2049: "NFS",           2181: "ZooKeeper",
    2375: "Docker",       2376: "Docker-TLS",    3000: "Grafana",
    3306: "MySQL",        3389: "RDP",           3690: "SVN",
    4443: "HTTPS-Alt",    4444: "Metasploit",    5000: "Flask/Dev",
    5432: "PostgreSQL",   5672: "RabbitMQ",      5900: "VNC",
    5985: "WinRM-HTTP",   5986: "WinRM-HTTPS",   6379: "Redis",
    6443: "Kubernetes",   7001: "WebLogic",      7077: "Spark",
    8000: "HTTP-Dev",     8080: "HTTP-Proxy",    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",    8888: "Jupyter",       9000: "SonarQube",
    9090: "Prometheus",   9092: "Kafka",         9200: "Elasticsearch",
    9300: "ES-Cluster",   9418: "Git",           9999: "Ambari",
    10250: "Kubelet",     10255: "Kubelet-RO",   11211: "Memcached",
    15672: "RabbitMQ-UI", 27017: "MongoDB",      27018: "MongoDB",
    50070: "HDFS-NN",     50075: "HDFS-DN",      61616: "ActiveMQ",
    7474: "Neo4j",        7687: "Neo4j-Bolt",    9042: "Cassandra",
    9160: "Cassandra-RPC",8500: "Consul",        8983: "Solr",
    15433: "PgBouncer",   27443: "MongoDB-TLS",
}

# ─────────────────────────────────────────────────────────────
# VULNERABILITY HINTS (CVE mapping)
# ─────────────────────────────────────────────────────────────

VULN_HINTS = {
    21:    [("CVE-2011-2523", "vsftpd 2.3.4 Backdoor", "CRITICAL"),
            ("CVE-2010-4221",  "ProFTPD 1.3.3c Heap Overflow", "HIGH")],
    22:    [("CVE-2023-38408", "OpenSSH Remote Code Execution", "CRITICAL"),
            ("CVE-2018-15473", "OpenSSH Username Enumeration", "MEDIUM")],
    23:    [("CVE-2020-10188", "Telnet Remote Code Exec", "CRITICAL"),
            ("INFO",           "Telnet sends credentials in plaintext", "HIGH")],
    80:    [("CVE-2021-41773", "Apache Path Traversal", "CRITICAL"),
            ("CVE-2017-5638",  "Apache Struts RCE", "CRITICAL")],
    443:   [("CVE-2022-22965", "Spring4Shell RCE", "CRITICAL"),
            ("CVE-2021-44228", "Log4Shell via HTTPS", "CRITICAL")],
    445:   [("CVE-2017-0144",  "EternalBlue / WannaCry SMB", "CRITICAL"),
            ("CVE-2020-0796",  "SMBGhost RCE", "CRITICAL")],
    3389:  [("CVE-2019-0708",  "BlueKeep RDP RCE", "CRITICAL"),
            ("CVE-2019-1182",  "DejaBlue RDP RCE", "CRITICAL")],
    6379:  [("CVE-2022-0543",  "Redis Lua Sandbox Escape", "CRITICAL"),
            ("INFO",           "Redis open without auth = full server takeover", "CRITICAL")],
    2375:  [("CVE-2019-5736",  "Docker runc Container Escape", "CRITICAL"),
            ("INFO",           "Unauthenticated Docker API = full host access", "CRITICAL")],
    27017: [("CVE-2019-2389",  "MongoDB Unauthorized Access", "HIGH"),
            ("INFO",           "MongoDB open without auth = data exposure", "HIGH")],
    9200:  [("CVE-2021-44228", "Log4Shell in Elasticsearch", "CRITICAL"),
            ("INFO",           "Elasticsearch open = full data read/write", "HIGH")],
    5432:  [("CVE-2019-9193",  "PostgreSQL COPY FROM PROGRAM RCE", "HIGH")],
    3306:  [("CVE-2012-2122",  "MySQL Auth Bypass", "HIGH")],
    10250: [("INFO",           "Kubelet API exposed = container exec + secret read", "CRITICAL")],
    5900:  [("CVE-2006-2369",  "VNC Auth Bypass", "CRITICAL"),
            ("INFO",           "VNC without password = full desktop access", "CRITICAL")],
    11211: [("CVE-2018-1000115","Memcached UDP Amplification DDoS", "HIGH"),
            ("INFO",           "Memcached open = cache poisoning + data read", "HIGH")],
    7001:  [("CVE-2020-14882", "WebLogic RCE Unauth", "CRITICAL")],
    8888:  [("INFO",           "Jupyter Notebook open = arbitrary code execution", "CRITICAL")],
    5672:  [("CVE-2021-22116", "RabbitMQ AMQP SSRF", "HIGH")],
    9092:  [("INFO",           "Kafka open = message read/write without auth", "HIGH")],
    1433:  [("CVE-2020-0618",  "MSSQL Reporting Services RCE", "HIGH")],
}

# ─────────────────────────────────────────────────────────────
# CLOUD SERVICE FINGERPRINTS
# ─────────────────────────────────────────────────────────────

CLOUD_IP_RANGES = {
    "AWS":   ["13.", "18.", "34.", "35.", "52.", "54.", "3.", "15.", "16."],
    "Azure": ["20.", "40.", "51.", "52.", "104.", "137.", "138.", "168."],
    "GCP":   ["34.", "35.", "104.", "130.", "142.", "146.", "147.", "216."],
}

CLOUD_PORT_HINTS = {
    2375:  "Docker Engine API",
    2376:  "Docker Engine API (TLS)",
    6443:  "Kubernetes API Server",
    10250: "Kubernetes Kubelet",
    10255: "Kubernetes Kubelet (RO)",
    2379:  "etcd (Kubernetes datastore)",
    2380:  "etcd peer",
    8001:  "kubectl proxy",
    9090:  "Prometheus metrics",
    3000:  "Grafana dashboard",
    9093:  "Alertmanager",
    8500:  "Consul HTTP API",
    8600:  "Consul DNS",
    4646:  "Nomad HTTP API",
    8200:  "Vault HTTP API",
    8201:  "Vault cluster",
    5601:  "Kibana",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch cluster",
    15672: "RabbitMQ Management",
    8161: "ActiveMQ Web Console",
}

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def check_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

def resolve_host(target: str) -> Optional[str]:
    try:
        # IPv6
        if ":" in target:
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def parse_ports(port_str: str) -> List[int]:
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            s, e = part.split("-", 1)
            ports.extend(range(int(s), int(e) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def validate_target(target: str) -> str:
    """Returns 'cidr', 'ipv4', 'ipv6', or 'hostname'"""
    try:
        ipaddress.ip_network(target, strict=False)
        if "/" in target:
            return "cidr"
        return "ipv6" if ":" in target else "ipv4"
    except ValueError:
        return "hostname"

def detect_cloud_provider(ip: str) -> Optional[str]:
    for provider, prefixes in CLOUD_IP_RANGES.items():
        for prefix in prefixes:
            if ip.startswith(prefix):
                return provider
    return None

def is_ipv6(target: str) -> bool:
    try:
        ipaddress.IPv6Address(target)
        return True
    except ValueError:
        return False

def get_cidr_hosts(cidr: str) -> List[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        # Limit to /16 for safety
        if net.prefixlen < 16:
            raise ValueError("CIDR too large. Use /16 or smaller.")
        return [str(h) for h in net.hosts()]
    except Exception as e:
        return []

def severity_color(severity: str) -> str:
    colors = {
        "CRITICAL": "\033[38;5;196m",
        "HIGH":     "\033[38;5;208m",
        "MEDIUM":   "\033[38;5;220m",
        "LOW":      "\033[38;5;39m",
        "INFO":     "\033[38;5;245m",
    }
    return colors.get(severity, "\033[0m")
