"""
MNet AI Analysis Module
Author: brainrotshiva
"""
import json
import urllib.request
import os
from typing import List, Dict, Optional


def _call_claude(prompt, max_tokens=600):
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None
    payload = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
            return data["content"][0]["text"].strip()
    except Exception:
        return None


def ai_risk_analysis(target, open_ports, os_hint="", cloud_provider="", k8s_detected=False):
    return _rule_based_analysis(open_ports, os_hint, cloud_provider, k8s_detected)


def _rule_based_analysis(open_ports, os_hint, cloud_provider, k8s_detected):
    risks = []
    actions = []
    score = 0
    open_set = {r["port"] for r in open_ports if r["state"] == "open"}

    if 23 in open_set:
        risks.append("Telnet open — credentials in plaintext")
        actions.append("Disable Telnet, use SSH instead")
        score += 40
    if 445 in open_set:
        risks.append("SMB exposed — EternalBlue risk")
        actions.append("Patch MS17-010, block port 445")
        score += 35
    if 3389 in open_set:
        risks.append("RDP exposed — BlueKeep risk")
        actions.append("Restrict RDP to VPN only")
        score += 35
    if 2375 in open_set:
        risks.append("Docker API exposed — full host takeover possible")
        actions.append("Close port 2375 immediately")
        score += 50
    if 6379 in open_set:
        risks.append("Redis exposed — no auth = RCE possible")
        actions.append("Bind Redis to 127.0.0.1")
        score += 40
    if 10250 in open_set:
        risks.append("Kubelet API exposed — CRITICAL")
        actions.append("Restrict 10250 to control-plane only")
        score += 50
    if not risks:
        risks.append("No critical vulnerabilities detected")

    if k8s_detected:
        risks.append("Kubernetes cluster internals exposed")
        actions.append("Apply Network Policies and RBAC")
        score += 60

    rating = "CRITICAL" if score>=80 else "HIGH" if score>=50 else "MEDIUM" if score>=25 else "LOW"

    lines = [f"Attack Surface Rating: {rating}\n"]
    lines.append("Top Risks:")
    for r in risks[:5]:
        lines.append(f"  ⚠ {r}")
    lines.append("\nImmediate Actions:")
    for a in (actions or ["No critical actions required"])[:4]:
        lines.append(f"  → {a}")
    return "\n".join(lines)
