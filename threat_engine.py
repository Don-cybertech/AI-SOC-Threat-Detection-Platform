"""
threat_engine.py — Unified Threat Engine + HTML Report Generator
=================================================================
Combines outputs from all detection modules into a unified
threat summary and generates a professional HTML report.
"""

from datetime import datetime
from pathlib import Path


# ── Severity ordering ──────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def build_summary(phishing_results, log_threats, honeypot_alerts) -> dict:
    """Build a unified summary dict from all module outputs."""
    phishing_hits = [r for r in phishing_results if r.verdict in ("PHISHING", "SUSPICIOUS")]
    total_threats = len(phishing_hits) + len(log_threats) + len(honeypot_alerts)

    critical = (
        sum(1 for r in phishing_results if r.verdict == "PHISHING") +
        sum(1 for t in log_threats if t.severity == "CRITICAL") +
        sum(1 for a in honeypot_alerts if a.severity == "CRITICAL")
    )

    return {
        "total_threats":    total_threats,
        "critical":         critical,
        "phishing_scanned": len(phishing_results),
        "phishing_hits":    len(phishing_hits),
        "log_threats":      len(log_threats),
        "honeypot_alerts":  len(honeypot_alerts),
        "generated_at":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_level":       "CRITICAL" if critical >= 3 else
                            "HIGH"     if critical >= 1 else
                            "MEDIUM"   if total_threats >= 3 else "LOW",
    }


# ── HTML Report ────────────────────────────────────────────────────────────────

def _color(sev: str) -> str:
    return {
        "CRITICAL":  "#ff4c4c", "HIGH":     "#ff8c00",
        "MEDIUM":    "#ffd700", "LOW":      "#4fc3f7",
        "PHISHING":  "#ff4c4c", "SUSPICIOUS":"#ff8c00",
        "CLEAN":     "#4caf50", "INFO":     "#9e9e9e",
    }.get(sev, "#ffffff")


def generate_html_report(
    phishing_results,
    log_threats,
    honeypot_alerts,
    summary: dict,
    output_path: str = "soc_report.html",
) -> str:

    # ── Phishing rows ──────────────────────────────────────────────────────────
    phishing_rows = ""
    for r in phishing_results:
        c = _color(r.verdict)
        triggers_html = "<br>".join(r.triggers) if r.triggers else "—"
        phishing_rows += f"""
        <tr>
          <td>{r.id}</td>
          <td style="max-width:200px;word-break:break-all">{r.sender}</td>
          <td>{r.subject[:60]}{'…' if len(r.subject)>60 else ''}</td>
          <td><span class="badge" style="background:{c}22;color:{c};border:1px solid {c}66">{r.verdict}</span></td>
          <td>{r.score}/100</td>
          <td style="font-size:11px;color:#7d8590">{triggers_html}</td>
        </tr>"""

    # ── Log threat rows ────────────────────────────────────────────────────────
    log_rows = ""
    for t in log_threats:
        c = _color(t.severity)
        log_rows += f"""
        <tr>
          <td><span class="badge" style="background:{c}22;color:{c};border:1px solid {c}66">{t.severity}</span></td>
          <td>{t.threat_type}</td>
          <td style="font-family:monospace">{t.ip}</td>
          <td>{t.detail}</td>
          <td>{t.count}</td>
          <td style="font-size:11px;color:#7d8590">{t.timestamp}</td>
        </tr>"""

    # ── Honeypot rows ──────────────────────────────────────────────────────────
    hp_rows = ""
    for a in honeypot_alerts:
        c = _color(a.severity)
        hp_rows += f"""
        <tr>
          <td>{a.id}</td>
          <td style="font-family:monospace">{a.ip}</td>
          <td>{a.country}</td>
          <td>{a.port} / {a.service}</td>
          <td>{a.attack_type}</td>
          <td><span class="badge" style="background:{c}22;color:{c};border:1px solid {c}66">{a.severity}</span></td>
          <td>{a.attempts}</td>
          <td style="font-size:11px;color:#7d8590">{a.timestamp}</td>
        </tr>"""

    risk_color = _color(summary["risk_level"])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>AI-SOC Threat Detection Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;padding:24px}}
  h1{{font-size:24px;color:#58a6ff;margin-bottom:4px}}
  .subtitle{{color:#7d8590;font-size:12px;margin-bottom:24px}}
  .stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:24px}}
  .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;border-left:4px solid}}
  .stat-label{{font-size:10px;font-weight:700;letter-spacing:1px;color:#7d8590;margin-bottom:6px}}
  .stat-value{{font-size:28px;font-weight:800;font-family:monospace}}
  .section{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:20px;overflow:hidden}}
  .section-header{{background:#1c2128;padding:12px 16px;font-size:13px;font-weight:600;border-bottom:1px solid #30363d}}
  table{{width:100%;border-collapse:collapse;font-size:12px}}
  th{{background:#1c2128;color:#7d8590;font-size:10px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;padding:8px 12px;text-align:left;border-bottom:1px solid #30363d}}
  td{{padding:8px 12px;border-bottom:1px solid #21262d;font-family:monospace}}
  tr:hover td{{background:#1c2128}}
  .badge{{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px}}
  .risk-banner{{background:{risk_color}15;border:1px solid {risk_color}44;border-radius:8px;padding:16px 20px;margin-bottom:24px;display:flex;align-items:center;gap:16px}}
  .risk-level{{font-size:28px;font-weight:900;color:{risk_color}}}
  .risk-detail{{color:#e6edf3;font-size:13px}}
  footer{{text-align:center;padding:20px;color:#7d8590;font-size:12px;border-top:1px solid #30363d;margin-top:24px}}
  @media(max-width:900px){{.stats{{grid-template-columns:repeat(3,1fr)}}}}
</style>
</head>
<body>

<h1>🛡️ AI-SOC Threat Detection Report</h1>
<p class="subtitle">Generated: {summary['generated_at']} &nbsp;|&nbsp; Portfolio Project &nbsp;|&nbsp; Don Achema (@Don-cybertech)</p>

<div class="risk-banner">
  <div class="risk-level">⚠ {summary['risk_level']}</div>
  <div class="risk-detail">
    <strong>Overall Risk Level: {summary['risk_level']}</strong><br>
    {summary['total_threats']} threats detected across {summary['phishing_scanned']} emails,
    log analysis, and honeypot monitoring.
    {summary['critical']} critical threat(s) require immediate attention.
  </div>
</div>

<div class="stats">
  <div class="stat" style="border-left-color:#ff4c4c">
    <div class="stat-label">TOTAL THREATS</div>
    <div class="stat-value" style="color:#ff4c4c">{summary['total_threats']}</div>
  </div>
  <div class="stat" style="border-left-color:#ff4c4c">
    <div class="stat-label">CRITICAL</div>
    <div class="stat-value" style="color:#ff4c4c">{summary['critical']}</div>
  </div>
  <div class="stat" style="border-left-color:#ff8c00">
    <div class="stat-label">PHISHING HITS</div>
    <div class="stat-value" style="color:#ff8c00">{summary['phishing_hits']}</div>
  </div>
  <div class="stat" style="border-left-color:#ffd700">
    <div class="stat-label">LOG THREATS</div>
    <div class="stat-value" style="color:#ffd700">{summary['log_threats']}</div>
  </div>
  <div class="stat" style="border-left-color:#c792ea">
    <div class="stat-label">HONEYPOT ALERTS</div>
    <div class="stat-value" style="color:#c792ea">{summary['honeypot_alerts']}</div>
  </div>
  <div class="stat" style="border-left-color:#58a6ff">
    <div class="stat-label">EMAILS SCANNED</div>
    <div class="stat-value" style="color:#58a6ff">{summary['phishing_scanned']}</div>
  </div>
</div>

<div class="section">
  <div class="section-header">📧 Phishing Detection Results</div>
  <table>
    <thead><tr><th>ID</th><th>Sender</th><th>Subject</th><th>Verdict</th><th>Score</th><th>Triggers</th></tr></thead>
    <tbody>{phishing_rows}</tbody>
  </table>
</div>

<div class="section">
  <div class="section-header">📋 Log Analysis — Threats Detected</div>
  <table>
    <thead><tr><th>Severity</th><th>Threat Type</th><th>Source IP</th><th>Detail</th><th>Count</th><th>Timestamp</th></tr></thead>
    <tbody>{log_rows if log_rows else '<tr><td colspan="6" style="text-align:center;padding:20px;color:#7d8590">No threats detected in logs</td></tr>'}</tbody>
  </table>
</div>

<div class="section">
  <div class="section-header">🍯 Honeypot Monitor — Connection Attempts</div>
  <table>
    <thead><tr><th>Alert ID</th><th>Source IP</th><th>Country</th><th>Port / Service</th><th>Attack Type</th><th>Severity</th><th>Attempts</th><th>Timestamp</th></tr></thead>
    <tbody>{hp_rows if hp_rows else '<tr><td colspan="8" style="text-align:center;padding:20px;color:#7d8590">No honeypot alerts</td></tr>'}</tbody>
  </table>
</div>

<footer>
  AI-SOC Threat Detection Platform &nbsp;|&nbsp; Cybersecurity Portfolio &nbsp;|&nbsp;
  <a href="https://github.com/Don-cybertech" style="color:#58a6ff">@Don-cybertech</a>
</footer>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
