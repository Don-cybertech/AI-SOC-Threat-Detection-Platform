"""
honeypot_monitor.py — Honeypot Alert Monitor
=============================================
Simulates a multi-service honeypot and generates alerts
for suspicious connection attempts.

Services monitored:
  - SSH (port 22)    — password spray, key attempts
  - HTTP (port 80)   — web scanners, path traversal
  - FTP (port 21)    — anonymous login attempts
  - Telnet (port 23) — legacy protocol abuse
  - SMB (port 445)   — ransomware/worm propagation
  - RDP (port 3389)  — remote desktop attacks
"""

import random
from datetime import datetime, timedelta
from dataclasses import dataclass, field


# ── Services ───────────────────────────────────────────────────────────────────

HONEYPOT_SERVICES = {
    22:   "SSH",
    21:   "FTP",
    23:   "Telnet",
    80:   "HTTP",
    443:  "HTTPS",
    445:  "SMB",
    3389: "RDP",
    8080: "HTTP-Alt",
}

ATTACK_TYPES = {
    22:   ["Password spray", "SSH key brute force", "User enumeration"],
    21:   ["Anonymous login attempt", "FTP bounce attack", "Directory traversal"],
    23:   ["Default credential attempt", "Telnet scan", "Banner grabbing"],
    80:   ["Web scanner", "Path traversal", "SQLi probe", "XSS probe"],
    443:  ["SSL scan", "Certificate probing", "Web scanner"],
    445:  ["EternalBlue probe", "SMB relay attempt", "Ransomware propagation"],
    3389: ["RDP brute force", "BlueKeep probe", "Credential stuffing"],
    8080: ["Web scanner", "Proxy abuse attempt", "API fuzzing"],
}

DEMO_IPS = [
    "185.220.101.5", "45.155.205.10", "91.108.4.55",
    "194.165.16.11", "77.247.181.165", "162.247.74.200",
    "198.54.117.200", "199.87.154.255",
]

COUNTRIES = {
    "185.220.101.5":  ("Germany", "DE"),
    "45.155.205.10":  ("Russia",  "RU"),
    "91.108.4.55":    ("China",   "CN"),
    "194.165.16.11":  ("Ukraine", "UA"),
    "77.247.181.165": ("Netherlands", "NL"),
    "162.247.74.200": ("United States", "US"),
    "198.54.117.200": ("Brazil",  "BR"),
    "199.87.154.255": ("Iran",    "IR"),
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class HoneypotAlert:
    id:          str
    ip:          str
    country:     str
    port:        int
    service:     str
    attack_type: str
    severity:    str
    timestamp:   str
    attempts:    int
    color:       str = "#ff4c4c"


def _ts(minutes_ago: float) -> str:
    dt = datetime.now() - timedelta(minutes=minutes_ago)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _severity(port: int, attempts: int) -> tuple[str, str]:
    if port in (445, 3389) or attempts >= 50:
        return "CRITICAL", "#ff4c4c"
    elif port in (22, 23) or attempts >= 20:
        return "HIGH",     "#ff8c00"
    elif attempts >= 5:
        return "MEDIUM",   "#ffd700"
    else:
        return "LOW",      "#4fc3f7"


# ── Demo generator ─────────────────────────────────────────────────────────────

def run_demo() -> list[HoneypotAlert]:
    """Generate realistic honeypot alerts for demo mode."""
    alerts = []
    counter = 1

    scenarios = [
        ("185.220.101.5",  22,   65,  5),
        ("45.155.205.10",  445,  12,  20),
        ("91.108.4.55",    3389, 38,  35),
        ("194.165.16.11",  80,   9,   60),
        ("77.247.181.165", 23,   7,   80),
        ("162.247.74.200", 21,   4,   90),
        ("198.54.117.200", 22,   25,  110),
        ("199.87.154.255", 8080, 6,   130),
    ]

    for ip, port, attempts, mins_ago in scenarios:
        country, _ = COUNTRIES.get(ip, ("Unknown", "??"))
        attack_type = random.choice(ATTACK_TYPES.get(port, ["Unknown attack"]))
        sev, color  = _severity(port, attempts)

        alerts.append(HoneypotAlert(
            id          = f"HP-{counter:04d}",
            ip          = ip,
            country     = country,
            port        = port,
            service     = HONEYPOT_SERVICES.get(port, "Unknown"),
            attack_type = attack_type,
            severity    = sev,
            timestamp   = _ts(mins_ago),
            attempts    = attempts,
            color       = color,
        ))
        counter += 1

    return sorted(alerts, key=lambda a: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(a.severity, 4))
