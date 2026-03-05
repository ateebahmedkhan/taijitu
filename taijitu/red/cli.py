#!/usr/bin/env python3
# taijitu/red/cli.py
# TAIJITU RED Command Line Interface
# Run scans, get guidance, generate reports from terminal
# Use only on authorized targets

import argparse
import json
import sys
import structlog
from datetime import datetime

log = structlog.get_logger()


def cmd_scan(args):
    """Run full vulnerability scan on target"""
    from taijitu.red.scope_manager import scope_manager
    from taijitu.red.scanner.vuln_scanner import vuln_scanner
    from taijitu.red.scanner.web_scanner import web_scanner
    from taijitu.red.brain.report_generator import report_generator

    target = args.target

    print(f"\n☯  TAIJITU RED — Scanning {target}")
    print("=" * 60)

    # Scope check first — always
    scope = scope_manager.check(target)
    if not scope.safe_to_test:
        print(f"\n❌ BLOCKED — {scope.reason}")
        print("\nAdd this target to a program scope first:")
        print("  taijitu-red program add --help")
        sys.exit(1)

    print(f"✅ Scope check passed — {scope.program}")
    print()

    # Run vulnerability scanner
    print("🔍 Running vulnerability scanner...")
    vuln_result = vuln_scanner.scan(target)
    vuln_report = vuln_scanner.generate_report(vuln_result)

    # Run web scanner
    print("🕷  Running web scanner...")
    web_result = web_scanner.scan(target)
    web_report = web_scanner.generate_report(web_result)

    # Combine results
    all_vulns = {}
    for k, v in vuln_report.get("vulnerabilities_by_severity", {}).items():
        all_vulns[k] = v
    for k, v in web_report.get("vulnerabilities", {}).items():
        if k in all_vulns:
            all_vulns[k].extend(v)
        else:
            all_vulns[k] = v

    combined_report = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "total_vulnerabilities": (
            vuln_report["total_vulnerabilities"] +
            web_report["total_vulnerabilities"]
        ),
        "risk_score": max(
            vuln_report.get("total_score", 0),
            web_report.get("total_vulnerabilities", 0) * 10,
        ),
        "vulnerabilities": all_vulns,
        "interesting_files": vuln_report.get("interesting_files", []),
    }

    # Print summary
    print()
    print(f"📊 SCAN COMPLETE")
    print(f"   Target:          {target}")
    print(f"   Total vulns:     {combined_report['total_vulnerabilities']}")
    print(f"   Risk score:      {combined_report['risk_score']}/100")
    print()

    for severity in ["critical", "high", "medium", "low"]:
        vulns = all_vulns.get(severity, [])
        if vulns:
            emoji = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡"}
            print(f"{emoji.get(severity, '⚪')} {severity.upper()} ({len(vulns)}):")
            for v in vulns:
                name = v.get("name", v.get("vuln_type", "Unknown"))
                bounty = v.get("bounty_estimate", "")
                print(f"   → {name}")
                if bounty:
                    print(f"     Bounty: {bounty}")
            print()

    # Generate reports if requested
    if args.report:
        reports = report_generator.generate_from_scan(
            combined_report,
            target=target,
        )
        if args.report == "hackerone":
            print("\n" + "=" * 60)
            print("HACKERONE SUBMISSION FORMAT")
            print("=" * 60)
            for r in reports[:3]:  # First 3 findings
                print(report_generator.format_hackerone(r))
                print()
        elif args.report == "markdown":
            output = report_generator.format_markdown(reports)
            filename = f"taijitu_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
            with open(filename, "w") as f:
                f.write(output)
            print(f"📄 Report saved to {filename}")
        elif args.report == "json":
            filename = f"taijitu_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, "w") as f:
                json.dump(combined_report, f, indent=2)
            print(f"📄 Report saved to {filename}")

    return combined_report


def cmd_recon(args):
    """Run passive OSINT recon on target"""
    from taijitu.red.recon.osint import osint_engine

    target = args.target
    print(f"\n☯  TAIJITU RED — Recon on {target}")
    print("=" * 60)

    result = osint_engine.investigate(target)
    report = osint_engine.generate_report(result)

    print(f"\n📡 RECON COMPLETE")
    print(f"   Target:          {report['target']}")
    print(f"   IPs found:       {report['summary']['ip_count']}")
    print(f"   Subdomains:      {report['summary']['subdomain_count']}")
    print(f"   Attack surface:  {report['summary']['attack_surface_score']}/100")
    print(f"   Recommendation:  {report['recommendation']}")
    print()

    if report["ip_addresses"]:
        print("🌐 IP Addresses:")
        for ip in report["ip_addresses"]:
            print(f"   {ip}")
        print()

    if report["subdomains"]:
        print("🔗 Subdomains Found:")
        for sub in report["subdomains"]:
            print(f"   {sub['subdomain']} → {sub['ip']}")
        print()

    if report["risk_indicators"]:
        print("⚠️  Risk Indicators:")
        for risk in report["risk_indicators"]:
            emoji = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡"}
            print(f"   {emoji.get(risk['severity'], '⚪')} {risk['description']}")
        print()


def cmd_guide(args):
    """Get dual-mind guidance on current situation"""
    from taijitu.red.brain.hacking_brain import hacking_brain

    situation = args.situation
    print(f"\n☯  TAIJITU RED — Dual-Mind Guidance")
    print("=" * 60)
    print(f"Situation: {situation[:100]}...")
    print()
    print("Asking Guardian and Adversary minds...")
    print("This takes 30-60 seconds...")
    print()

    guidance = hacking_brain.guide(situation)

    print("🛡  GUARDIAN SAYS:")
    print(guidance.guardian_guidance)
    print()
    print("⚔️  ADVERSARY SAYS:")
    print(guidance.adversary_guidance)
    print()
    print("🎯 CONSENSUS NEXT STEP:")
    print(guidance.consensus_next_step)
    print()
    print(f"💰 BOUNTY POTENTIAL: {guidance.bounty_potential}")
    print(f"⏱  Duration: {guidance.duration_seconds:.1f} seconds")


def cmd_program(args):
    """Manage bug bounty programs"""
    from taijitu.red.scope_manager import scope_manager, BugBountyProgram

    if args.action == "list":
        programs = scope_manager.list_programs()
        print(f"\n☯  TAIJITU RED — Registered Programs ({len(programs)})")
        print("=" * 60)
        for p in programs:
            print(f"  📋 {p['name']} ({p['platform']})")
            print(f"     In scope: {p['in_scope_count']} targets")
            print()

    elif args.action == "add":
        print("\n☯  TAIJITU RED — Add Bug Bounty Program")
        print("=" * 60)
        name = input("Program name: ")
        platform = input("Platform (hackerone/bugcrowd/intigriti): ")
        print("In-scope domains (one per line, empty line to finish):")
        in_scope = []
        while True:
            domain = input("  > ")
            if not domain:
                break
            in_scope.append(domain)

        print("Out-of-scope domains (one per line, empty line to finish):")
        out_of_scope = []
        while True:
            domain = input("  > ")
            if not domain:
                break
            out_of_scope.append(domain)

        notes = input("Notes (testing restrictions etc): ")

        program = BugBountyProgram(
            name=name,
            platform=platform,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            vulnerability_types=[],
            max_severity="critical",
            notes=notes,
        )
        scope_manager.add_program(program)
        print(f"\n✅ Program '{name}' added with {len(in_scope)} in-scope targets")

    elif args.action == "check":
        result = scope_manager.check(args.target)
        status = "✅ IN SCOPE" if result.is_in_scope else "❌ OUT OF SCOPE"
        print(f"\n{status}")
        print(f"Target:  {args.target}")
        print(f"Reason:  {result.reason}")
        print(f"Program: {result.program}")


def main():
    parser = argparse.ArgumentParser(
        prog="taijitu-red",
        description="☯  TAIJITU RED — Authorized Security Testing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  taijitu-red scan http://testphp.vulnweb.com
  taijitu-red scan https://target.com --report hackerone
  taijitu-red recon example.com
  taijitu-red guide "I found SQLi on /search.php, what next?"
  taijitu-red program list
  taijitu-red program add
  taijitu-red program check https://target.com

Use only on authorized targets.
        """,
    )

    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run full vulnerability scan",
    )
    scan_parser.add_argument("target", help="Target URL to scan")
    scan_parser.add_argument(
        "--report",
        choices=["hackerone", "markdown", "json"],
        help="Generate report in specified format",
    )

    # recon command
    recon_parser = subparsers.add_parser(
        "recon",
        help="Run passive OSINT reconnaissance",
    )
    recon_parser.add_argument("target", help="Target domain")

    # guide command
    guide_parser = subparsers.add_parser(
        "guide",
        help="Get dual-mind guidance when stuck",
    )
    guide_parser.add_argument(
        "situation",
        help="Describe your current situation",
    )

    # program command
    program_parser = subparsers.add_parser(
        "program",
        help="Manage bug bounty programs",
    )
    program_parser.add_argument(
        "action",
        choices=["list", "add", "check"],
        help="Action to perform",
    )
    program_parser.add_argument(
        "--target",
        help="Target URL for scope check",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "recon":
        cmd_recon(args)
    elif args.command == "guide":
        cmd_guide(args)
    elif args.command == "program":
        cmd_program(args)


if __name__ == "__main__":
    main()