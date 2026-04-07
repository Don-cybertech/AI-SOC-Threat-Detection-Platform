"""
soc_console.py — AI-SOC Threat Detection Platform
===================================================
Portfolio Project | Don Achema (@Don-cybertech)

Commands:
  scan     – Run full threat scan (phishing + logs + honeypot)
  phishing – Scan emails for phishing only
  logs     – Analyse log file for brute force / anomalies
  honeypot – View honeypot alerts

Examples:
  python soc_console.py scan --demo
  python soc_console.py scan --log auth.log
  python soc_console.py phishing --demo
  python soc_console.py logs --demo
  python soc_console.py honeypot
"""

import argparse
import sys
import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.columns import Columns
from rich import box

import phishing_detector as pd_
import log_analyzer       as la_
import honeypot_monitor   as hm_
import threat_engine      as te_


console = Console()

BANNER = """[bold cyan]
  █████╗ ██╗      ███████╗ ██████╗  ██████╗
 ██╔══██╗██║      ██╔════╝██╔═══██╗██╔════╝
 ███████║██║█████╗███████╗██║   ██║██║
 ██╔══██║██║╚════╝╚════██║██║   ██║██║
 ██║  ██║██║      ███████║╚██████╔╝╚██████╗
 ╚═╝  ╚═╝╚═╝      ╚══════╝ ╚═════╝  ╚═════╝[/bold cyan]
[bold cyan]████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗[/bold cyan]
[bold cyan]╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝[/bold cyan]
[bold cyan]   ██║   ███████║██████╔╝█████╗  ███████║   ██║   [/bold cyan]
[bold cyan]   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   [/bold cyan]
[bold cyan]   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   [/bold cyan]
[bold cyan]   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝  [/bold cyan]
[bold cyan]██████╗ ███████╗████████╗███████╗ ██████╗████████╗[/bold cyan]
[bold cyan]██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝[/bold cyan]
[bold cyan]██║  ██║█████╗     ██║   █████╗  ██║        ██║   [/bold cyan]
[bold cyan]██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   [/bold cyan]
[bold cyan]██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   [/bold cyan]
[bold cyan]╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   [/bold cyan]
[dim]AI-SOC Threat Detection Platform  |  Portfolio Project  |  Don Achema[/dim]"""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _sev_style(sev: str) -> str:
    return {
        "CRITICAL":  "bold red",
        "HIGH":      "bold dark_orange",
        "MEDIUM":    "bold yellow",
        "LOW":       "bold cyan",
        "PHISHING":  "bold red",
        "SUSPICIOUS":"bold dark_orange",
        "CLEAN":     "bold green",
    }.get(sev, "white")


def _risk_panel(risk_level: str, summary: dict):
    color = {"CRITICAL":"red","HIGH":"dark_orange","MEDIUM":"yellow","LOW":"green"}.get(risk_level,"white")
    cards = [
        Panel(f"[bold]{summary['total_threats']}[/bold]\n[dim]Total Threats[/dim]",  border_style="red"),
        Panel(f"[bold red]{summary['critical']}[/bold red]\n[dim]Critical[/dim]",    border_style="red"),
        Panel(f"[bold yellow]{summary['phishing_hits']}[/bold yellow]\n[dim]Phishing[/dim]", border_style="yellow"),
        Panel(f"[bold orange3]{summary['log_threats']}[/bold orange3]\n[dim]Log Threats[/dim]", border_style="dark_orange"),
        Panel(f"[bold magenta]{summary['honeypot_alerts']}[/bold magenta]\n[dim]Honeypot[/dim]", border_style="magenta"),
        Panel(f"[bold cyan]{summary['phishing_scanned']}[/bold cyan]\n[dim]Emails Scanned[/dim]", border_style="cyan"),
    ]
    console.print(Panel(
        f"[bold {color}]  OVERALL RISK: {risk_level}[/bold {color}]\n"
        f"[dim]  {summary['total_threats']} threats detected  |  "
        f"{summary['critical']} critical  |  {summary['generated_at']}[/dim]",
        border_style=color, padding=(0, 1)
    ))
    console.print(Columns(cards, equal=True, expand=True))
    console.print()


# ── Phishing display ───────────────────────────────────────────────────────────

def display_phishing(results):
    console.print(Rule("[bold cyan]📧 PHISHING DETECTION[/bold cyan]"))

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold dim")
    table.add_column("ID",      width=8)
    table.add_column("Sender",  min_width=22)
    table.add_column("Subject", min_width=30)
    table.add_column("Verdict", width=12)
    table.add_column("Score",   justify="right", width=7)
    table.add_column("Key Trigger", min_width=30)

    for r in results:
        style   = _sev_style(r.verdict)
        trigger = r.triggers[0] if r.triggers else "—"
        table.add_row(
            r.id,
            f"[dim]{r.sender[:28]}[/dim]",
            r.subject[:42] + ("…" if len(r.subject) > 42 else ""),
            f"[{style}]{r.verdict}[/{style}]",
            f"[bold]{r.score}[/bold]",
            f"[dim]{trigger[:45]}[/dim]",
        )

    console.print(table)

    phishing = sum(1 for r in results if r.verdict == "PHISHING")
    suspicious = sum(1 for r in results if r.verdict == "SUSPICIOUS")
    console.print(f"\n  [red]PHISHING: {phishing}[/red]  "
                  f"[yellow]SUSPICIOUS: {suspicious}[/yellow]  "
                  f"[green]CLEAN: {len(results)-phishing-suspicious}[/green]\n")


# ── Log threats display ────────────────────────────────────────────────────────

def display_log_threats(threats):
    console.print(Rule("[bold cyan]📋 LOG ANALYSIS[/bold cyan]"))

    if not threats:
        console.print("[dim]  No threats detected in logs.[/dim]\n")
        return

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold dim")
    table.add_column("Severity",   width=10)
    table.add_column("Threat",     min_width=26)
    table.add_column("Source IP",  min_width=16)
    table.add_column("Detail",     min_width=38)
    table.add_column("Count", justify="right", width=7)
    table.add_column("Timestamp",  min_width=19)

    for t in threats:
        style = _sev_style(t.severity)
        table.add_row(
            f"[{style}]{t.severity}[/{style}]",
            t.threat_type,
            f"[cyan]{t.ip}[/cyan]",
            t.detail[:55] + ("…" if len(t.detail) > 55 else ""),
            str(t.count),
            f"[dim]{t.timestamp}[/dim]",
        )

    console.print(table)
    console.print()


# ── Honeypot display ───────────────────────────────────────────────────────────

def display_honeypot(alerts):
    console.print(Rule("[bold cyan]🍯 HONEYPOT MONITOR[/bold cyan]"))

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold dim")
    table.add_column("ID",       width=8)
    table.add_column("IP",       min_width=16)
    table.add_column("Country",  min_width=14)
    table.add_column("Port/Svc", min_width=12)
    table.add_column("Attack",   min_width=24)
    table.add_column("Severity", width=10)
    table.add_column("Hits",     justify="right", width=6)
    table.add_column("Time",     min_width=19)

    for a in alerts:
        style = _sev_style(a.severity)
        table.add_row(
            a.id,
            f"[cyan]{a.ip}[/cyan]",
            a.country,
            f"{a.port}/{a.service}",
            a.attack_type,
            f"[{style}]{a.severity}[/{style}]",
            str(a.attempts),
            f"[dim]{a.timestamp}[/dim]",
        )

    console.print(table)
    console.print()


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_scan(args):
    console.print(Rule("[bold cyan]FULL SOC SCAN[/bold cyan]"))

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}[/cyan]"),
                  console=console, transient=True) as p:
        t1 = p.add_task("Scanning emails for phishing...", total=None)
        phishing = pd_.run_demo()
        p.update(t1, description="✓ Phishing scan complete")

        t2 = p.add_task("Analysing logs for anomalies...", total=None)
        log_threats = la_.run_demo() if not args.log else la_.parse_log_file(args.log)
        p.update(t2, description="✓ Log analysis complete")

        t3 = p.add_task("Checking honeypot alerts...", total=None)
        honeypot = hm_.run_demo()
        p.update(t3, description="✓ Honeypot scan complete")

    summary = te_.build_summary(phishing, log_threats, honeypot)
    _risk_panel(summary["risk_level"], summary)

    display_phishing(phishing)
    display_log_threats(log_threats)
    display_honeypot(honeypot)

    # HTML report
    report_path = args.output or "soc_report.html"
    with Progress(SpinnerColumn(), TextColumn("[cyan]Generating HTML report...[/cyan]"),
                  console=console, transient=True) as p:
        p.add_task("report", total=None)
        te_.generate_html_report(phishing, log_threats, honeypot, summary, report_path)

    console.print(Panel(
        f"[bold green]✓  HTML report saved:[/bold green] [cyan]{report_path}[/cyan]\n"
        f"[dim]Open in your browser to view the full formatted report.[/dim]",
        border_style="green", padding=(0, 2)
    ))


def cmd_phishing(args):
    with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning emails...[/cyan]"),
                  console=console, transient=True) as p:
        p.add_task("scan", total=None)
        results = pd_.run_demo()
    display_phishing(results)


def cmd_logs(args):
    with Progress(SpinnerColumn(), TextColumn("[cyan]Analysing logs...[/cyan]"),
                  console=console, transient=True) as p:
        p.add_task("scan", total=None)
        threats = la_.run_demo() if args.demo else la_.parse_log_file(args.file or "auth.log")
    display_log_threats(threats)


def cmd_honeypot(args):
    with Progress(SpinnerColumn(), TextColumn("[cyan]Loading honeypot alerts...[/cyan]"),
                  console=console, transient=True) as p:
        p.add_task("scan", total=None)
        alerts = hm_.run_demo()
    display_honeypot(alerts)


# ── CLI Setup ──────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="soc_console",
        description="AI-SOC Threat Detection Platform",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="Run full threat scan")
    sc.add_argument("--demo",   action="store_true", default=True, help="Use demo data (default)")
    sc.add_argument("--log",    metavar="FILE",  help="Path to real log file")
    sc.add_argument("--output", metavar="FILE",  help="HTML report output path (default: soc_report.html)")

    ph = sub.add_parser("phishing", help="Scan emails for phishing")
    ph.add_argument("--demo", action="store_true", default=True)

    lg = sub.add_parser("logs", help="Analyse log file")
    lg.add_argument("--demo", action="store_true", default=True)
    lg.add_argument("--file", metavar="FILE", help="Log file path")

    hp = sub.add_parser("honeypot", help="View honeypot alerts")

    return parser


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    console.print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()

    try:
        if args.command == "scan":     cmd_scan(args)
        elif args.command == "phishing": cmd_phishing(args)
        elif args.command == "logs":     cmd_logs(args)
        elif args.command == "honeypot": cmd_honeypot(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
