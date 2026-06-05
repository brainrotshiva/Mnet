"""
MNet Output Exporters — JSON, CSV, HTML
Author: brainrotshiva
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict


def export_json(results: List[Dict], config: dict, filepath: str,
                os_info: str = "", cloud: str = "", ai_summary: str = ""):
    report = {
        "mnet_version": "2.0.26",
        "author":       "brainrotshiva",
        "scan_time":    datetime.now().isoformat(),
        "target":       config["target"],
        "scan_type":    config["scan_type"],
        "os_hint":      os_info,
        "cloud":        cloud,
        "ai_analysis":  ai_summary,
        "open_ports":   [r for r in results if r["state"] == "open"],
        "all_results":  results,
        "stats": {
            "total_scanned": len(results),
            "open":          sum(1 for r in results if r["state"] == "open"),
            "closed":        sum(1 for r in results if r["state"] == "closed"),
            "filtered":      sum(1 for r in results if r["state"] == "filtered"),
        }
    }
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  [\033[38;5;46m+\033[0m] JSON report saved → {filepath}")


def export_csv(results: List[Dict], filepath: str):
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "port", "proto", "state", "service", "banner", "cloud_hint"])
        writer.writeheader()
        for r in results:
            writer.writerow({
                "ip":         r.get("ip", ""),
                "port":       r.get("port", ""),
                "proto":      r.get("proto", "tcp"),
                "state":      r.get("state", ""),
                "service":    r.get("service", ""),
                "banner":     r.get("banner") or "",
                "cloud_hint": r.get("cloud_hint") or "",
            })
    print(f"  [\033[38;5;46m+\033[0m] CSV report saved → {filepath}")


def export_html(results: List[Dict], config: dict, filepath: str,
                os_info: str = "", cloud: str = "", ai_summary: str = ""):
    open_ports = [r for r in results if r["state"] == "open"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = ""
    for r in open_ports:
        vulns = r.get("vulns") or []
        vuln_html = ""
        for cve, desc, sev in vulns:
            colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44aaff"}
            c = colors.get(sev, "#aaa")
            vuln_html += f'<span class="vuln" style="color:{c}">⚠ [{sev}] {cve} — {desc}</span><br>'

        cloud_tag = f'<span class="cloud-tag">{r["cloud_hint"]}</span>' if r.get("cloud_hint") else ""
        banner = r.get("banner") or ""

        rows += f"""
        <tr>
          <td class="port">{r['port']}/{r['proto']}</td>
          <td class="state open">OPEN</td>
          <td>{r['service']}</td>
          <td class="mono">{banner[:60]}</td>
          <td>{cloud_tag}</td>
          <td>{vuln_html or '<span class="ok">No hints</span>'}</td>
        </tr>"""

    ai_block = f"""
    <div class="card ai-card">
      <div class="card-title">🤖 AI Risk Analysis</div>
      <pre class="ai-text">{ai_summary}</pre>
    </div>""" if ai_summary else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MNet Scan Report — {config['target']}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@300;400;600;700&display=swap');

  :root {{
    --bg:     #0a0e1a;
    --bg2:    #0f1528;
    --card:   #131929;
    --border: #1e2d4a;
    --green:  #00ff88;
    --red:    #ff4444;
    --orange: #ff8800;
    --blue:   #0088ff;
    --cyan:   #00ddff;
    --text:   #c8d8f0;
    --dim:    #4a6080;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Space Grotesk', sans-serif;
    min-height: 100vh;
    padding: 2rem;
  }}

  header {{
    display: flex;
    align-items: center;
    gap: 1.5rem;
    margin-bottom: 2.5rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
  }}
  .logo {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 2.2rem;
    font-weight: 700;
    background: linear-gradient(135deg, var(--green), var(--cyan));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -1px;
  }}
  .meta {{ color: var(--dim); font-size: 0.85rem; line-height: 1.8; }}
  .meta strong {{ color: var(--text); }}

  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.2rem;
    text-align: center;
  }}
  .stat-value {{ font-size: 2rem; font-weight: 700; color: var(--green); font-family: 'JetBrains Mono', monospace; }}
  .stat-label {{ font-size: 0.75rem; color: var(--dim); margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }}

  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }}
  .card-title {{
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--dim);
    margin-bottom: 1rem;
  }}
  .ai-card {{ border-color: #1e3a5f; background: #0c1825; }}
  .ai-text {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    line-height: 1.7;
    color: var(--cyan);
    white-space: pre-wrap;
  }}

  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    text-align: left;
    padding: 0.7rem 1rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--dim);
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 0.75rem 1rem;
    border-bottom: 1px solid #0f1828;
    font-size: 0.85rem;
    vertical-align: top;
  }}
  tr:hover td {{ background: #111e35; }}
  .port {{ font-family: 'JetBrains Mono', monospace; color: var(--cyan); font-weight: 700; }}
  .state.open {{ color: var(--green); font-weight: 700; font-family: 'JetBrains Mono', monospace; }}
  .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: var(--dim); }}
  .vuln {{ display: block; font-size: 0.78rem; margin-bottom: 2px; }}
  .ok {{ color: var(--dim); font-size: 0.78rem; }}
  .cloud-tag {{
    background: #1a2a4a;
    color: var(--blue);
    font-size: 0.72rem;
    padding: 2px 8px;
    border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
  }}

  footer {{
    text-align: center;
    color: var(--dim);
    font-size: 0.78rem;
    margin-top: 3rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
  }}
  footer a {{ color: var(--green); text-decoration: none; }}
</style>
</head>
<body>

<header>
  <div>
    <div class="logo">MNet</div>
    <div style="color:var(--dim); font-size:0.8rem; margin-top:2px;">Mapping Network Tool v2.0.26</div>
  </div>
  <div class="meta">
    <strong>Target:</strong> {config['target']}<br>
    <strong>Scan Type:</strong> {config['scan_type'].upper()}<br>
    <strong>OS Hint:</strong> {os_info or "—"}<br>
    <strong>Cloud:</strong> {cloud or "—"}<br>
    <strong>Scanned:</strong> {now}
  </div>
</header>

<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-value">{len(open_ports)}</div>
    <div class="stat-label">Open Ports</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{len(results)}</div>
    <div class="stat-label">Total Scanned</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:var(--orange)">{sum(len(r.get('vulns',[]))for r in open_ports)}</div>
    <div class="stat-label">Vuln Hints</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:var(--cyan)">{cloud or '—'}</div>
    <div class="stat-label">Cloud Provider</div>
  </div>
</div>

{ai_block}

<div class="card">
  <div class="card-title">Open Ports & Services</div>
  <table>
    <thead>
      <tr>
        <th>Port/Proto</th>
        <th>State</th>
        <th>Service</th>
        <th>Banner</th>
        <th>Cloud/K8s</th>
        <th>Vulnerability Hints</th>
      </tr>
    </thead>
    <tbody>
      {rows if rows else '<tr><td colspan="6" style="text-align:center;color:var(--dim)">No open ports found</td></tr>'}
    </tbody>
  </table>
</div>

<footer>
  Generated by <a href="https://github.com/brainrotshiva">MNet v2.0.26 — @brainrotshiva</a> &nbsp;|&nbsp; {now}
</footer>

</body>
</html>"""

    with open(filepath, "w") as f:
        f.write(html)
    print(f"  [\033[38;5;46m+\033[0m] HTML report saved → {filepath}")
