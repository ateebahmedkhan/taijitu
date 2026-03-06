#!/usr/bin/env python3
# taijitu/red/cli.py
# TAIJITU RED — Professional CLI
# Autonomous Security Research Platform

import sys
import time
from datetime import datetime

from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich.rule import Rule
from rich.panel import Panel
from rich import box
import questionary
from questionary import Style

# ── BRAND COLORS ─────────────────────────────────────
BLUE   = "#00C2FF"
PURPLE = "#7B2FBE"
RED    = "#E53E3E"
GREEN  = "#38A169"
WHITE  = "#FFFFFF"
DIM    = "#3A3A4A"
MID    = "#6A6A7A"

console = Console()

STYLE = Style([
    ("qmark",       f"fg:{BLUE} bold"),
    ("question",    "fg:#FFFFFF bold"),
    ("answer",      f"fg:{PURPLE} bold"),
    ("pointer",     f"fg:{BLUE} bold"),
    ("highlighted", f"fg:{BLUE} bold"),
    ("selected",    f"fg:{PURPLE}"),
    ("separator",   f"fg:{DIM}"),
    ("instruction", f"fg:{DIM}"),
])

# ── LOGO ─────────────────────────────────────────────
# Neural spiral — two overlapping orbital rings
# Blue = Guardian   Purple = Adversary   White dot = Verdict

LOGO_LINES = [
    ("        ·  ·  ·                    ", BLUE),
    ("     ·           ·                 ", BLUE),
    ("   ·    ◯◯◯◯◯◯     ·              ", BLUE),
    ("  ·   ◯◯      ◯◯    ·             ", BLUE),
    (" ·   ◯◯  ◯◯◯◯  ◯◯   ·            ", BLUE),
    (" ·  ◯◯ ◯◯    ◯◯ ◯◯  ·            ", BLUE),
    (" ·  ◯◯ ◯  ●  ◯ ◯◯  ·            ", None),   # center dot
    (" ·  ◯◯ ◯◯    ◯◯ ◯◯  ·            ", PURPLE),
    (" ·   ◯◯  ◯◯◯◯  ◯◯   ·            ", PURPLE),
    ("  ·   ◯◯      ◯◯    ·             ", PURPLE),
    ("   ·    ◯◯◯◯◯◯     ·              ", PURPLE),
    ("     ·           ·                 ", PURPLE),
    ("        ·  ·  ·                    ", PURPLE),
]


def render_logo():
    """Render the neural spiral logo in terminal"""
    # Two orbital rings side by side with shared center
    lines = [
        f"{'':>8}{'·  ' * 3}{'':>12}{'·  ' * 2}",
    ]

    # Simplified clean version that looks good in terminal
    logo = [
        ("    ", "◯◯◯◯◯◯◯◯", "    ", "◯◯◯◯◯◯◯◯"),
        ("  ", "◯◯", "        ", "◯◯", "  ", "◯◯", "        ", "◯◯"),
        (" ", "◯", "   ", "◯◯◯◯◯◯", "   ", "◯", "   ", "◯◯◯◯◯◯", "  "),
        (" ", "◯", "  ", "◯◯", "  ", "●", "  ", "◯◯", "  ", "◯◯", "  "),
        (" ", "◯", "   ", "◯◯◯◯◯◯", "   ", "◯", "   ", "◯◯◯◯◯◯", "  "),
        ("  ", "◯◯", "        ", "◯◯", "  ", "◯◯", "        ", "◯◯"),
        ("    ", "◯◯◯◯◯◯◯◯", "    ", "◯◯◯◯◯◯◯◯"),
    ]


def print_banner():
    from taijitu.red.logo import print_logo
    print_logo(console)

def animate_startup():
    """TAIJITU neural spiral loading animation"""
    from taijitu.red.logo import animate_startup as logo_animate
    logo_animate(console)


def phase_line(label: str, status: str, detail: str = ""):
    """Single phase status line"""
    icons = {
        "done":    f"[{BLUE}]✓[/{BLUE}]",
        "fail":    f"[{RED}]✗[/{RED}]",
        "skip":    f"[{DIM}]–[/{DIM}]",
        "run":     f"[{BLUE}]·[/{BLUE}]",
    }
    icon = icons.get(status, "·")
    detail_str = f"  [{DIM}]{detail}[/{DIM}]" if detail else ""
    console.print(f"  {icon}  [{DIM}]{label}[/{DIM}]{detail_str}")


def findings_table(findings: list):
    """Professional findings table"""
    if not findings:
        console.print(f"\n  [{DIM}]No findings.[/{DIM}]\n")
        return

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_color = {
        "critical": RED,
        "high":     "#FF6B35",
        "medium":   "#C0A020",
        "low":      MID,
        "info":     DIM,
    }

    sorted_f = sorted(
        findings,
        key=lambda x: sev_order.get(x.get("severity", "info"), 9),
    )

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style=f"dim",
        border_style=DIM,
        padding=(0, 2),
        show_edge=False,
    )

    table.add_column("SEV", width=10, no_wrap=True)
    table.add_column("TYPE", width=32, no_wrap=True)
    table.add_column("LOCATION", width=40, no_wrap=True)

    for f in sorted_f:
        sev = f.get("severity", "info")
        color = sev_color.get(sev, DIM)
        url = f.get("url", "")
        if len(url) > 38:
            url = url[:35] + "..."

        table.add_row(
            Text(sev.upper(), style=f"bold {color}"),
            Text(f.get("type", "Unknown"), style=WHITE),
            Text(url, style=MID),
        )

    console.print()
    console.print(table)
    console.print()


def summary_block(result):
    """Clean engagement summary"""
    console.print(f"  [dim]{'─' * 60}[/dim]")
    console.print()

    sev_color = {
        "critical": RED,
        "high":     "#FF6B35",
        "medium":   "#C0A020",
        "low":      MID,
    }

    counts = [
        ("critical", result.critical_count),
        ("high",     result.high_count),
        ("medium",   result.medium_count),
        ("low",      result.low_count),
    ]

    t = Text("  ")
    for sev, count in counts:
        if count:
            t.append(
                f"{count} {sev.upper()}  ",
                style=f"bold {sev_color[sev]}",
            )

    console.print(t)
    console.print()
    console.print(
        f"  [{DIM}]Duration  "
        f"{result.duration_seconds:.0f}s[/{DIM}]"
    )

    if result.consensus:
        console.print()
        console.print(
            f"  [{BLUE}]Guardian[/{BLUE}] "
            f"[{DIM}]·[/{DIM}] "
            f"[{PURPLE}]Adversary[/{PURPLE}]"
        )
        consensus = (
            result.consensus
            .replace("NEXT ACTION:", "")
            .strip()
        )
        console.print(
            f"  [{DIM}]{consensus[:220]}[/{DIM}]"
        )

    console.print()
    console.print(f"  [dim]{'─' * 60}[/dim]")
    console.print()


# ── SCAN EXECUTION ────────────────────────────────────

def run_scan(
    target: str,
    depth: str = "full",
    credentials=None,
    report_fmt: str = None,
):
    """Execute pipeline with live output"""
    from taijitu.red.pipeline import pipeline
    from taijitu.red.scope_manager import scope_manager

    scope = scope_manager.check(target)

    if not scope.safe_to_test:
        console.print(
            f"  [{RED}]✗[/{RED}]  [{RED}]Out of scope[/{RED}]"
            f"  [{DIM}]{scope.reason}[/{DIM}]"
        )
        console.print()
        console.print(
            f"  [{DIM}]Add this target to a program first.[/{DIM}]"
        )
        console.print(
            f"  [{DIM}]Run: taijitu-red → Load bug bounty program[/{DIM}]"
        )
        return None

    console.print(
        f"  [{BLUE}]✓[/{BLUE}]  [{DIM}]Scope verified"
        f"  {scope.program}[/{DIM}]"
    )
    console.print()

    result = pipeline.run(
        target_url=target,
        credentials=credentials,
        skip_crawl=(depth != "full"),
        skip_brain=(depth == "recon"),
        verbose=True,
    )

    findings_table(result.all_findings)
    summary_block(result)

    if report_fmt and result.all_findings:
        content = pipeline.generate_full_report(
            result, format=report_fmt
        )
        ext = "json" if report_fmt == "json" else "md"
        fname = (
            f"taijitu_report_"
            f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{ext}"
        )
        with open(fname, "w") as fh:
            fh.write(content)
        console.print(
            f"  [{BLUE}]✓[/{BLUE}]  [{DIM}]Report — {fname}[/{DIM}]"
        )
        console.print()

    return result


# ── INTERACTIVE FLOWS ─────────────────────────────────

def flow_scan():
    """Interactive scan flow"""
    console.print()

    target = questionary.text(
        "Target URL or bug bounty program URL:",
        style=STYLE,
    ).ask()

    if not target:
        return

    # Bug bounty platform URL detected
    if any(p in target for p in [
        "hackerone.com", "bugcrowd.com",
        "intigriti.com", "yeswehack.com",
    ]):
        console.print()
        console.print(
            f"  [{BLUE}]✓[/{BLUE}]  [{DIM}]Bug bounty URL detected[/{DIM}]"
        )
        flow_load_program(target)
        return

    depth = questionary.select(
        "Scan depth:",
        choices=[
            questionary.Choice(
                "Full  —  recon + crawl + scan + brain",
                value="full",
            ),
            questionary.Choice(
                "Quick  —  scan only",
                value="quick",
            ),
            questionary.Choice(
                "Recon  —  passive only, zero touch",
                value="recon",
            ),
        ],
        style=STYLE,
    ).ask()

    if not depth:
        return

    use_creds = questionary.confirm(
        "Authenticated scan? (test credentials required)",
        default=False,
        style=STYLE,
    ).ask()

    credentials = None
    if use_creds:
        from taijitu.red.scanner.auth_scanner import AuthCredentials
        credentials = AuthCredentials(
            username=questionary.text(
                "Username:", style=STYLE
            ).ask() or "",
            password=questionary.password(
                "Password:", style=STYLE
            ).ask() or "",
            login_url=questionary.text(
                "Login URL (blank = auto-detect):",
                style=STYLE,
            ).ask() or "",
        )

    report_fmt = questionary.select(
        "Report format:",
        choices=[
            questionary.Choice("Markdown", value="markdown"),
            questionary.Choice("HackerOne format", value="hackerone"),
            questionary.Choice("JSON", value="json"),
            questionary.Choice("None", value=None),
        ],
        style=STYLE,
    ).ask()

    console.print()
    console.print(f"  [dim]{'─' * 60}[/dim]")
    console.print()

    run_scan(
        target=target,
        depth=depth,
        credentials=credentials,
        report_fmt=report_fmt,
    )


def flow_load_program(url: str = None):
    """Load bug bounty program from platform URL or manually"""
    from taijitu.red.scope_manager import scope_manager, BugBountyProgram
    from taijitu.red.platforms import load_program_from_url, hackerone

    console.print()

    if not url:
        url = questionary.text(
            "Paste bug bounty program URL:",
            style=STYLE,
        ).ask()

    if not url:
        url = "manual"

    # Detect if it is a platform URL
    is_platform = any(p in url for p in [
        "hackerone.com", "bugcrowd.com",
        "intigriti.com", "yeswehack.com",
    ])

    if is_platform:
        console.print()
        console.print(
            f"  [{BLUE}]⠋[/{BLUE}]  [dim]Reading program from API...[/dim]"
        )

        program_data = load_program_from_url(url)

        if not program_data:
            console.print(
                f"  [{RED}]✗[/{RED}]  [{RED}]Could not fetch program. "
                f"Check your API credentials.[/{RED}]"
            )
            return

        # Display what was found
        console.print(
            f"  [{BLUE}]✓[/{BLUE}]  [dim]Program: "
            f"{program_data.name}[/dim]"
        )
        console.print()

        # Show scope table
        from rich.table import Table
        from rich import box

        if program_data.in_scope:
            table = Table(
                box=box.SIMPLE,
                border_style=DIM,
                show_edge=False,
                padding=(0, 2),
            )
            table.add_column("TYPE", style=DIM, width=12)
            table.add_column("ASSET", style=WHITE, width=45)
            table.add_column("BOUNTY", style=BLUE, width=8)

            for s in program_data.in_scope[:20]:
                table.add_row(
                    s["type"],
                    s["asset"],
                    "✓" if s["bounty"] else "–",
                )

            console.print(f"  [dim]IN SCOPE ({len(program_data.in_scope)}):[/dim]")
            console.print(table)

        if program_data.out_of_scope:
            console.print(
                f"  [dim]OUT OF SCOPE: "
                + ", ".join(
                    s["asset"] for s in program_data.out_of_scope[:5]
                )
                + "[/dim]"
            )

        console.print()

        # Account requirement warning
        if program_data.requires_account:
            console.print(
                f"  [{PURPLE}]![/{PURPLE}]  "
                f"[dim]This program has web targets.[/dim]"
            )
            console.print(
                f"       [dim]Create a dedicated test account "
                f"on the target before scanning.[/dim]"
            )
            console.print(
                f"       [dim]Never use real user accounts.[/dim]"
            )
            console.print()

        # Confirm and load into scope manager
        confirm = questionary.confirm(
            f"Load '{program_data.name}' into TAIJITU and start engagement?",
            default=True,
            style=STYLE,
        ).ask()

        if not confirm:
            return

        # Extract URL/domain assets for scope manager
        url_types = {"URL", "WILDCARD", "DOMAIN"}
        in_scope_domains = [
            s["asset"] for s in program_data.in_scope
            if s["type"] in url_types or s["type"] == "OTHER"
        ]
        out_of_scope_domains = [
            s["asset"] for s in program_data.out_of_scope
            if s["type"] in url_types or s["type"] == "OTHER"
        ]

        scope_manager.add_program(BugBountyProgram(
            name=program_data.name,
            platform=program_data.platform,
            in_scope=in_scope_domains,
            out_of_scope=out_of_scope_domains,
            vulnerability_types=program_data.vulnerability_types,
            max_severity="critical",
            notes=program_data.testing_notes,
        ))

        console.print(
            f"  [{BLUE}]✓[/{BLUE}]  [dim]Program loaded — "
            f"{len(in_scope_domains)} targets[/dim]"
        )
        console.print()

        # Ask which target to scan
        if in_scope_domains:
            url_targets = [
                s["asset"] for s in program_data.in_scope
                if s["type"] == "URL" and s.get("bounty")
            ]
            if not url_targets:
                url_targets = [
                    s["asset"] for s in program_data.in_scope
                    if s["type"] == "URL"
                ]

            if url_targets:
                choices = [
                    questionary.Choice(f"  {t}", value=t)
                    for t in url_targets[:8]
                ]
                choices.append(
                    questionary.Choice("  Enter manually", value="manual")
                )
                choices.append(
                    questionary.Choice("  Not now", value=None)
                )

                target = questionary.select(
                    "Which target to scan first?",
                    choices=choices,
                    style=STYLE,
                ).ask()

                if target == "manual":
                    target = questionary.text(
                        "Enter target URL:",
                        style=STYLE,
                    ).ask()

                if target and target != "manual":
                    # Ask about test account
                    has_account = False
                    if program_data.requires_account:
                        has_account = questionary.confirm(
                            "Do you have a test account on this target?",
                            default=False,
                            style=STYLE,
                        ).ask()

                    credentials = None
                    if has_account:
                        from taijitu.red.scanner.auth_scanner import AuthCredentials
                        console.print(
                            f"\n  [dim]Enter your test account credentials.[/dim]"
                        )
                        console.print(
                            f"  [{RED}]Never use real user credentials.[/{RED}]\n"
                        )
                        credentials = AuthCredentials(
                            username=questionary.text(
                                "  Username:", style=STYLE
                            ).ask() or "",
                            password=questionary.password(
                                "  Password:", style=STYLE
                            ).ask() or "",
                            login_url=questionary.text(
                                "  Login URL (blank = auto-detect):",
                                style=STYLE,
                            ).ask() or "",
                        )

                    report_fmt = questionary.select(
                        "Report format:",
                        choices=[
                            questionary.Choice("Markdown", value="markdown"),
                            questionary.Choice("HackerOne format", value="hackerone"),
                            questionary.Choice("JSON", value="json"),
                            questionary.Choice("None", value=None),
                        ],
                        style=STYLE,
                    ).ask()

                    if not target.startswith("http"):
                        target = f"https://{target}"

                    console.print()
                    console.print(f"  [dim]{'─' * 56}[/dim]")
                    console.print()

                    run_scan(
                        target=target,
                        depth="full",
                        credentials=credentials,
                        report_fmt=report_fmt,
                    )

    else:
        # Manual entry fallback
        platform = questionary.select(
            "Platform:",
            choices=[
                "hackerone", "bugcrowd",
                "intigriti", "yeswehack", "other",
            ],
            style=STYLE,
        ).ask() or "other"

        program_name = questionary.text(
            "Program name:", style=STYLE
        ).ask() or "Unnamed"

        console.print(f"\n  [dim]Enter in-scope domains:[/dim]")
        in_scope = []
        while True:
            d = questionary.text(
                f"  Domain {len(in_scope)+1} (empty to finish):",
                style=STYLE,
            ).ask()
            if not d:
                break
            in_scope.append(d.strip())

        scope_manager.add_program(BugBountyProgram(
            name=program_name,
            platform=platform,
            in_scope=in_scope,
            out_of_scope=[],
            vulnerability_types=[],
            max_severity="critical",
            notes="",
        ))

        console.print(
            f"\n  [{BLUE}]✓[/{BLUE}]  [dim]Program added — "
            f"{len(in_scope)} targets[/dim]"
        )


def flow_guide():
    """Interactive dual-mind guidance"""
    from taijitu.red.brain.hacking_brain import hacking_brain

    console.print()
    console.print(
        f"  [{DIM}]Describe your situation — "
        f"what you found, where you are stuck.[/{DIM}]"
    )
    console.print()

    situation = questionary.text(
        "Situation:",
        style=STYLE,
    ).ask()

    if not situation:
        return

    console.print()
    console.print(
        f"  [{BLUE}]Guardian[/{BLUE}]  [{DIM}]·[/{DIM}]  "
        f"[{PURPLE}]Adversary[/{PURPLE}]  [{DIM}]analyzing...[/{DIM}]"
    )
    console.print()

    guidance = hacking_brain.guide(situation)

    console.print(
        Rule(f"[{BLUE}]Guardian[/{BLUE}]", style=DIM)
    )
    console.print(f"\n  [{DIM}]{guidance.guardian_guidance}[/{DIM}]\n")

    console.print(
        Rule(f"[{PURPLE}]Adversary[/{PURPLE}]", style=DIM)
    )
    console.print(f"\n  [{DIM}]{guidance.adversary_guidance}[/{DIM}]\n")

    console.print(Rule("Consensus", style=DIM))
    console.print(
        f"\n  [{WHITE}]{guidance.consensus_next_step}[/{WHITE}]\n"
    )


def flow_reports():
    """View previous reports"""
    import glob

    console.print()
    reports = sorted(
        glob.glob("taijitu_report_*.md") +
        glob.glob("taijitu_report_*.json"),
        reverse=True,
    )

    if not reports:
        console.print(
            f"  [{DIM}]No reports found.[/{DIM}]"
        )
        return

    choices = [
        questionary.Choice(f"  {r}", value=r)
        for r in reports[:10]
    ]
    choices.append(questionary.Choice("  Back", value=None))

    selected = questionary.select(
        "Reports:", choices=choices, style=STYLE
    ).ask()

    if selected:
        from rich.markdown import Markdown
        console.print()
        with open(selected) as f:
            console.print(Markdown(f.read()[:4000]))


def flow_programs():
    """Program management"""
    from taijitu.red.scope_manager import scope_manager

    console.print()
    action = questionary.select(
        "Programs:",
        choices=[
            questionary.Choice("  Add new program", value="add"),
            questionary.Choice("  List programs", value="list"),
            questionary.Choice("  Check scope", value="check"),
            questionary.Choice("  Back", value=None),
        ],
        style=STYLE,
    ).ask()

    if action == "list":
        programs = scope_manager.list_programs()
        console.print()
        if not programs:
            console.print(f"  [{DIM}]No programs.[/{DIM}]")
            return
        table = Table(
            box=box.SIMPLE,
            border_style=DIM,
            show_edge=False,
            padding=(0, 2),
        )
        table.add_column("PROGRAM", style=WHITE)
        table.add_column("PLATFORM", style=DIM)
        table.add_column("TARGETS", style=BLUE)
        for p in programs:
            table.add_row(
                p["name"],
                p["platform"],
                str(p["in_scope_count"]),
            )
        console.print(table)

    elif action == "add":
        flow_load_program()

    elif action == "check":
        target = questionary.text(
            "Target URL:", style=STYLE
        ).ask()
        if target:
            result = scope_manager.check(target)
            console.print()
            if result.safe_to_test:
                console.print(
                    f"  [{BLUE}]✓[/{BLUE}]  [{DIM}]In scope"
                    f"  {result.program}[/{DIM}]"
                )
            else:
                console.print(
                    f"  [{RED}]✗[/{RED}]  [{RED}]Out of scope[/{RED}]"
                    f"  [{DIM}]{result.reason}[/{DIM}]"
                )


# ── MAIN ─────────────────────────────────────────────

def cmd_interactive():
    """Interactive mode"""
    print_banner()
    animate_startup()

    while True:
        action = questionary.select(
            "Select:",
            choices=[
                questionary.Choice(
                    "  New engagement", value="scan"
                ),
                questionary.Choice(
                    "  Load bug bounty program", value="program_load"
                ),
                questionary.Choice(
                    "  Manage programs", value="programs"
                ),
                questionary.Choice(
                    "  Get guidance", value="guide"
                ),
                questionary.Choice(
                    "  Reports", value="reports"
                ),
                questionary.Choice(
                    "  Exit", value="exit"
                ),
            ],
            style=STYLE,
        ).ask()

        if not action or action == "exit":
            console.print(
                f"\n  [{DIM}]Closing.[/{DIM}]\n"
            )
            sys.exit(0)
        elif action == "scan":
            flow_scan()
        elif action == "program_load":
            flow_load_program()
        elif action == "programs":
            flow_programs()
        elif action == "guide":
            flow_guide()
        elif action == "reports":
            flow_reports()

        console.print()


def cmd_scan(args):
    print_banner()
    run_scan(
        target=args.target,
        depth="quick" if args.fast else "full",
        report_fmt=args.report,
    )


def cmd_recon(args):
    from taijitu.red.recon.osint import osint_engine
    from urllib.parse import urlparse

    print_banner()
    domain = urlparse(args.target).netloc or args.target
    result = osint_engine.investigate(domain)
    report = osint_engine.generate_report(result)

    table = Table(
        box=box.SIMPLE, border_style=DIM,
        show_edge=False, padding=(0, 2),
    )
    table.add_column("", style=DIM, width=20)
    table.add_column("", style=WHITE)

    table.add_row("Target", domain)
    table.add_row("IPs", str(report["summary"]["ip_count"]))
    table.add_row(
        "Subdomains",
        str(report["summary"]["subdomain_count"]),
    )
    table.add_row(
        "Attack Surface",
        f"{report['summary']['attack_surface_score']}/100",
    )
    table.add_row("Assessment", report["recommendation"])
    console.print()
    console.print(table)

    if report["subdomains"]:
        console.print()
        for sub in report["subdomains"]:
            console.print(
                f"  [{BLUE}]·[/{BLUE}]  [{DIM}]{sub['subdomain']}"
                f"  {sub['ip']}[/{DIM}]"
            )
    console.print()


def cmd_guide(args):
    from taijitu.red.brain.hacking_brain import hacking_brain
    print_banner()
    guidance = hacking_brain.guide(args.situation)
    console.print(Rule(f"[{BLUE}]Guardian[/{BLUE}]", style=DIM))
    console.print(f"\n  [{DIM}]{guidance.guardian_guidance}[/{DIM}]\n")
    console.print(Rule(f"[{PURPLE}]Adversary[/{PURPLE}]", style=DIM))
    console.print(f"\n  [{DIM}]{guidance.adversary_guidance}[/{DIM}]\n")
    console.print(Rule("Consensus", style=DIM))
    console.print(f"\n  [{WHITE}]{guidance.consensus_next_step}[/{WHITE}]\n")


def cmd_program(args):
    from taijitu.red.scope_manager import scope_manager
    print_banner()
    if args.action == "list":
        programs = scope_manager.list_programs()
        table = Table(
            box=box.SIMPLE, border_style=DIM,
            show_edge=False, padding=(0, 2),
        )
        table.add_column("PROGRAM", style=WHITE)
        table.add_column("PLATFORM", style=DIM)
        table.add_column("TARGETS", style=BLUE)
        for p in programs:
            table.add_row(
                p["name"], p["platform"],
                str(p["in_scope_count"]),
            )
        console.print()
        console.print(table)
    elif args.action == "check" and args.target:
        result = scope_manager.check(args.target)
        console.print()
        if result.safe_to_test:
            console.print(
                f"  [{BLUE}]✓[/{BLUE}]  [{DIM}]In scope"
                f"  {result.program}[/{DIM}]"
            )
        else:
            console.print(
                f"  [{RED}]✗[/{RED}]  [{RED}]Out of scope[/{RED}]"
                f"  [{DIM}]{result.reason}[/{DIM}]"
            )
    elif args.action == "add":
        flow_load_program()
    console.print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="taijitu-red",
        add_help=False,
    )
    parser.add_argument("--help", "-h", action="store_true")
    sub = parser.add_subparsers(dest="command")

    sp = sub.add_parser("scan")
    sp.add_argument("target")
    sp.add_argument(
        "--report",
        choices=["hackerone", "markdown", "json"],
    )
    sp.add_argument("--fast", action="store_true")

    rp = sub.add_parser("recon")
    rp.add_argument("target")

    gp = sub.add_parser("guide")
    gp.add_argument("situation")

    pp = sub.add_parser("program")
    pp.add_argument("action", choices=["list", "add", "check"])
    pp.add_argument("--target")

    args = parser.parse_args()

    if not args.command:
        cmd_interactive()
        return

    dispatch = {
        "scan":    cmd_scan,
        "recon":   cmd_recon,
        "guide":   cmd_guide,
        "program": cmd_program,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()