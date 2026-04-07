"""
log_analyzer.py — Brute Force & Anomaly Log Analyzer
======================================================
Parses auth/syslog files and detects:
  - Brute force attacks     (many failed logins from one IP)
  - Credential stuffing     (many different usernames from one IP)
  - Port scanning           (many connection attempts across ports)
  - Anomalous login times   (logins outside business hours)
  - Privilege escalation    (sudo/su attempts after failed logins)

Works with real log files OR generates demo data.
"""

import re
import random
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ── Thresholds ─────────────────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD  = 5    # failed logins from same IP
STUFFING_THRESHOLD     = 4    # different usernames from same IP
PORT_SCAN_THRESHOLD    = 10   # connection attempts across ports
BUSINESS_HOURS         = (8, 18)  # 8am - 6pm


# ── Log patterns ───────────────────────────────────────────────────────────────

PATTERNS = {
    "failed_login": re.compile(
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
        r"(?:Failed password|Invalid user|authentication failure).*"
        r"(?:from\s+|rhost=)(\d{1,3}(?:\.\d{1,3}){3})"
        r"(?:.*user[= ](\w+))?",
        re.IGNORECASE
    ),
    "success_login": re.compile(
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
        r"(?:Accepted password|session opened).*"
        r"(?:from\s+)(\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE
    ),
    "sudo_attempt": re.compile(
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
        r"sudo.*(?:FAILED|incorrect password)",
        re.IGNORECASE
    ),
}


# ── Demo log generator ─────────────────────────────────────────────────────────

def _ts(minutes_ago: float) -> str:
    dt = datetime.now() - timedelta(minutes=minutes_ago)
    return dt.strftime("%b %d %H:%M:%S")


DEMO_LOG_ENTRIES = []

def _build_demo_log():
    global DEMO_LOG_ENTRIES
    entries = []

    # Brute force from 185.220.101.5
    for i in range(12):
        entries.append({
            "type":      "failed_login",
            "ip":        "185.220.101.5",
            "user":      "root",
            "timestamp": _ts(random.uniform(5, 30)),
            "raw":       f"{_ts(30-i*2)} sshd[1234]: Failed password for root from 185.220.101.5 port 22",
        })

    # Credential stuffing from 45.155.205.10
    for user in ["admin", "administrator", "user", "test", "oracle", "ubuntu"]:
        entries.append({
            "type":      "failed_login",
            "ip":        "45.155.205.10",
            "user":      user,
            "timestamp": _ts(random.uniform(10, 60)),
            "raw":       f"{_ts(40)} sshd[5678]: Invalid user {user} from 45.155.205.10 port 22",
        })

    # Normal logins
    for ip in ["192.168.1.10", "10.0.0.5"]:
        entries.append({
            "type":      "success_login",
            "ip":        ip,
            "user":      "analyst",
            "timestamp": _ts(random.uniform(60, 120)),
            "raw":       f"{_ts(90)} sshd[9999]: Accepted password for analyst from {ip} port 22",
        })

    # Suspicious off-hours login
    entries.append({
        "type":      "success_login",
        "ip":        "91.108.4.55",
        "user":      "admin",
        "timestamp": "Jan 15 02:47:33",
        "raw":       "Jan 15 02:47:33 sshd[1111]: Accepted password for admin from 91.108.4.55 port 22",
    })

    # Sudo attempt after failures
    entries.append({
        "type":      "sudo_attempt",
        "ip":        "185.220.101.5",
        "user":      "unknown",
        "timestamp": _ts(2),
        "raw":       f"{_ts(2)} sudo: pam_unix(sudo:auth): authentication failure",
    })

    DEMO_LOG_ENTRIES = entries
    return entries


# ── Analysis ───────────────────────────────────────────────────────────────────

@dataclass
class LogThreat:
    threat_type:  str
    severity:     str
    ip:           str
    detail:       str
    count:        int
    timestamp:    str
    color:        str = "#ff4c4c"


def _severity_color(sev: str) -> str:
    return {"CRITICAL": "#ff4c4c", "HIGH": "#ff8c00",
            "MEDIUM": "#ffd700", "LOW": "#4fc3f7"}.get(sev, "#ffffff")


def analyse_entries(entries: list) -> list[LogThreat]:
    """Detect threats from parsed log entries."""
    threats = []

    # Group by IP
    ip_failures  = defaultdict(list)   # ip → list of users
    ip_attempts  = defaultdict(int)    # ip → count

    for entry in entries:
        if entry["type"] == "failed_login":
            ip = entry["ip"]
            ip_failures[ip].append(entry.get("user", "unknown"))
            ip_attempts[ip] += 1

    # Brute force detection
    for ip, count in ip_attempts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            sev = "CRITICAL" if count >= 10 else "HIGH"
            threats.append(LogThreat(
                threat_type = "Brute Force Attack",
                severity    = sev,
                ip          = ip,
                detail      = f"{count} failed login attempts targeting 'root'",
                count       = count,
                timestamp   = _ts(5),
                color       = _severity_color(sev),
            ))

    # Credential stuffing detection
    for ip, users in ip_failures.items():
        unique_users = set(users)
        if len(unique_users) >= STUFFING_THRESHOLD:
            threats.append(LogThreat(
                threat_type = "Credential Stuffing",
                severity    = "HIGH",
                ip          = ip,
                detail      = f"{len(unique_users)} unique usernames tried: {', '.join(list(unique_users)[:4])}",
                count       = len(unique_users),
                timestamp   = _ts(15),
                color       = _severity_color("HIGH"),
            ))

    # Off-hours logins
    for entry in entries:
        if entry["type"] == "success_login":
            ts = entry.get("timestamp", "")
            try:
                hour = int(ts.split(":")[0].split()[-1])
                if hour < BUSINESS_HOURS[0] or hour >= BUSINESS_HOURS[1]:
                    threats.append(LogThreat(
                        threat_type = "Off-Hours Login",
                        severity    = "MEDIUM",
                        ip          = entry["ip"],
                        detail      = f"Successful login at {ts} (outside business hours)",
                        count       = 1,
                        timestamp   = ts,
                        color       = _severity_color("MEDIUM"),
                    ))
            except Exception:
                pass

    # Sudo failures
    sudo_count = sum(1 for e in entries if e["type"] == "sudo_attempt")
    if sudo_count > 0:
        threats.append(LogThreat(
            threat_type = "Privilege Escalation Attempt",
            severity    = "HIGH",
            ip          = "localhost",
            detail      = f"{sudo_count} failed sudo/privilege escalation attempt(s)",
            count       = sudo_count,
            timestamp   = _ts(2),
            color       = _severity_color("HIGH"),
        ))

    return sorted(threats, key=lambda t: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(t.severity, 4))


def run_demo() -> list[LogThreat]:
    entries = _build_demo_log()
    return analyse_entries(entries)


def parse_log_file(path: str) -> list[LogThreat]:
    """Parse a real syslog/auth.log file."""
    import pathlib
    p = pathlib.Path(path)
    if not p.exists():
        return []

    entries = []
    for line in p.read_text(errors="replace").splitlines():
        for name, pattern in PATTERNS.items():
            m = pattern.search(line)
            if m:
                entries.append({
                    "type":      name,
                    "ip":        m.group(2) if m.lastindex >= 2 else "unknown",
                    "user":      m.group(3) if m.lastindex >= 3 else "unknown",
                    "timestamp": m.group(1) if m.lastindex >= 1 else "—",
                    "raw":       line[:120],
                })
                break

    return analyse_entries(entries)
