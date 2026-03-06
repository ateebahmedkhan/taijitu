# taijitu/red/pipeline.py
# Autonomous Bug Bounty Pipeline
# One command — full engagement — professional report
# Chains: recon → crawl → scan → auth → takeover → brain → report
# Use only on authorized targets

import structlog
from datetime import datetime
from dataclasses import dataclass, field

log = structlog.get_logger()


@dataclass
class PipelineResult:
    """Complete autonomous engagement result"""
    target: str
    domain: str
    timestamp: datetime
    duration_seconds: float = 0.0

    # Module results
    recon_report: dict = field(default_factory=dict)
    crawl_report: dict = field(default_factory=dict)
    vuln_report: dict = field(default_factory=dict)
    web_report: dict = field(default_factory=dict)
    takeover_report: dict = field(default_factory=dict)
    auth_report: dict = field(default_factory=dict)
    brain_guidance: str = ""
    adversary_guidance: str = ""
    consensus: str = ""
    cortex_report: str = ""

    # Aggregated findings
    all_findings: list = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_bounty_low: int = 0
    total_bounty_high: int = 0


class AutonomousPipeline:
    """
    Autonomous Bug Bounty Pipeline

    Runs a complete security engagement automatically:

    Phase 1 — RECON
              Passive OSINT — IPs, subdomains, surface mapping

    Phase 2 — CRAWL
              JS-aware browser crawl — finds hidden endpoints
              Forms, API calls, parameters, secrets

    Phase 3 — SCAN
              Vulnerability scanner — headers, SSL, files
              Web scanner — SQLi, XSS, SSRF, traversal
              PayloadsAllTheThings powered

    Phase 4 — TAKEOVER
              Subdomain takeover detection
              13 cloud service fingerprints

    Phase 5 — BRAIN
              Dual-mind analysis of all findings
              Guardian + Adversary guidance
              Attack chain identification

    Phase 6 — REPORT
              Professional report generation
              HackerOne / Bugcrowd / PDF format
              CVSS scores, PoC steps, bounty estimates

    Use only on authorized targets.
    """

    def __init__(self):
        self._load_modules()
        log.info("autonomous_pipeline_initialized")

    def _load_modules(self):
        """Lazy load all RED modules"""
        from taijitu.red.scope_manager import scope_manager
        from taijitu.red.recon.osint import osint_engine
        from taijitu.red.recon.js_crawler import js_crawler
        from taijitu.red.scanner.vuln_scanner import vuln_scanner
        from taijitu.red.scanner.web_scanner import web_scanner
        from taijitu.red.scanner.takeover import takeover_scanner
        from taijitu.red.brain.hacking_brain import hacking_brain
        from taijitu.red.brain.report_generator import report_generator

        self.scope_manager = scope_manager
        self.osint = osint_engine
        self.crawler = js_crawler
        self.vuln_scanner = vuln_scanner
        self.web_scanner = web_scanner
        self.takeover = takeover_scanner
        self.brain = hacking_brain
        self.reporter = report_generator

    def run(
        self,
        target_url: str,
        credentials=None,
        skip_crawl: bool = False,
        skip_brain: bool = False,
        verbose: bool = True,
    ) -> PipelineResult:
        """
        Run full autonomous engagement pipeline

        target_url:  Full URL of target
        credentials: AuthCredentials for authenticated scan
        skip_crawl:  Skip JS crawling (faster but less thorough)
        skip_brain:  Skip AI guidance (faster)
        verbose:     Print progress to console
        """
        from urllib.parse import urlparse

        start_time = datetime.utcnow()

        parsed = urlparse(target_url)
        domain = parsed.netloc or target_url
        domain = domain.split(":")[0]

        result = PipelineResult(
            target=target_url,
            domain=domain,
            timestamp=start_time,
        )

        def log_phase(phase: str, status: str = "starting"):
            if verbose:
                icons = {
                    "starting": "🔄",
                    "complete": "✅",
                    "skipped": "⏭ ",
                    "failed": "❌",
                }
                icon = icons.get(status, "•")
                print(f"  {icon} {phase}")
            log.info(f"pipeline_{status}", phase=phase)

        if verbose:
            print()
            print("☯  TAIJITU RED — AUTONOMOUS PIPELINE")
            print("=" * 60)
            print(f"  Target: {target_url}")
            print(f"  Domain: {domain}")
            print(f"  Started: {start_time.strftime('%H:%M:%S')}")
            print("=" * 60)
            print()

        # ── SCOPE CHECK ──────────────────────────────────────
        scope = self.scope_manager.check(target_url)
        if not scope.safe_to_test:
            if verbose:
                print(f"❌ BLOCKED — {scope.reason}")
                print()
                print("Add this target to a program first:")
                print("  taijitu-red program add")
            return result

        if verbose:
            print(f"✅ Scope: {scope.program}")
            print()
            print("Running pipeline phases:")
            print()

        # ── PHASE 1 — RECON ──────────────────────────────────
        log_phase("Phase 1 — Passive Recon")
        try:
            recon = self.osint.investigate(domain)
            result.recon_report = self.osint.generate_report(recon)
            log_phase(
                f"         {len(recon.ip_addresses)} IPs, "
                f"{len(recon.subdomains)} subdomains, "
                f"surface score {recon.attack_surface_score}/100",
                "complete",
            )
        except Exception as e:
            log_phase(f"Phase 1 failed: {str(e)[:50]}", "failed")

        # ── PHASE 2 — JS CRAWL ───────────────────────────────
        if not skip_crawl:
            log_phase("Phase 2 — JS Browser Crawl")
            try:
                crawl = self.crawler.crawl(target_url, max_pages=15)
                result.crawl_report = self.crawler.generate_report(crawl)
                log_phase(
                    f"         {crawl.total_pages_crawled} pages, "
                    f"{len(crawl.forms)} forms, "
                    f"{len(crawl.endpoints)} endpoints, "
                    f"{len(crawl.secrets_found)} secrets",
                    "complete",
                )
            except Exception as e:
                log_phase(f"Phase 2 failed: {str(e)[:50]}", "failed")
        else:
            log_phase("Phase 2 — JS Crawl", "skipped")

        # ── PHASE 3 — VULNERABILITY SCAN ─────────────────────
        log_phase("Phase 3 — Vulnerability Scan")
        try:
            vuln = self.vuln_scanner.scan(target_url)
            result.vuln_report = self.vuln_scanner.generate_report(vuln)
            log_phase(
                f"         {result.vuln_report['total_vulnerabilities']} "
                f"findings, score {result.vuln_report.get('total_score', 0)}/100",
                "complete",
            )
        except Exception as e:
            log_phase(f"Phase 3 failed: {str(e)[:50]}", "failed")

        # ── PHASE 4 — WEB SCANNER ────────────────────────────
        log_phase("Phase 4 — Web Application Scan")
        try:
            web = self.web_scanner.scan(target_url)
            result.web_report = self.web_scanner.generate_report(web)
            log_phase(
                f"         {result.web_report['total_vulnerabilities']} "
                f"findings, {result.web_report['total_requests']} requests",
                "complete",
            )
        except Exception as e:
            log_phase(f"Phase 4 failed: {str(e)[:50]}", "failed")

        # ── PHASE 5 — SUBDOMAIN TAKEOVER ─────────────────────
        log_phase("Phase 5 — Subdomain Takeover")
        try:
            takeover = self.takeover.scan(domain)
            result.takeover_report = self.takeover.generate_report(takeover)
            log_phase(
                f"         {result.takeover_report['subdomains_found']} "
                f"subdomains, {result.takeover_report['vulnerable_count']} vulnerable",
                "complete",
            )
        except Exception as e:
            log_phase(f"Phase 5 failed: {str(e)[:50]}", "failed")

        # ── PHASE 6 — AUTH SCAN ──────────────────────────────
        if credentials:
            log_phase("Phase 6 — Authenticated Scan")
            try:
                from taijitu.red.scanner.auth_scanner import auth_scanner
                auth = auth_scanner.scan(target_url, credentials)
                result.auth_report = auth_scanner.generate_report(auth)
                log_phase(
                    f"         Login: {auth.login_successful}, "
                    f"{len(auth.findings)} findings",
                    "complete",
                )
            except Exception as e:
                log_phase(f"Phase 6 failed: {str(e)[:50]}", "failed")
        else:
            log_phase("Phase 6 — Authenticated Scan (no credentials)", "skipped")

        # ── AGGREGATE ALL FINDINGS ───────────────────────────
        result.all_findings = self._aggregate_findings(result)
        result.critical_count = sum(
            1 for f in result.all_findings
            if f.get("severity") == "critical"
        )
        result.high_count = sum(
            1 for f in result.all_findings
            if f.get("severity") == "high"
        )
        result.medium_count = sum(
            1 for f in result.all_findings
            if f.get("severity") == "medium"
        )
        result.low_count = sum(
            1 for f in result.all_findings
            if f.get("severity") == "low"
        )

        # Calculate bounty range
        result.total_bounty_low, result.total_bounty_high = (
            self._estimate_bounty(result.all_findings)
        )

        # ── PHASE 7 — DUAL MIND BRAIN ────────────────────────
        if not skip_brain and result.all_findings:
            log_phase("Phase 7 — Dual-Mind Analysis")
            try:
                situation = self._build_situation(result)
                combined_report = {
                    "vulnerabilities": self._group_findings(
                        result.all_findings
                    ),
                }
                guidance = self.brain.guide(situation, combined_report)
                result.brain_guidance = guidance.guardian_guidance
                result.adversary_guidance = guidance.adversary_guidance
                result.consensus = guidance.consensus_next_step
                log_phase(
                    f"         Analysis complete "
                    f"({guidance.duration_seconds:.0f}s)",
                    "complete",
                )
            except Exception as e:
                log_phase(f"Phase 7 failed: {str(e)[:50]}", "failed")
        elif not result.all_findings:
            log_phase("Phase 7 — Brain (no findings to analyze)", "skipped")
        else:
            log_phase("Phase 7 — Brain", "skipped")
        # ── PHASE 8 — CORTEX VALIDATION ──────────────────────
        if result.all_findings:
            log_phase("Phase 8 — CORTEX Validation")
            try:
                from taijitu.red.cortex import cortex

                # Get policy intel if program is loaded
                policy_intel = None
                if self.scope_manager.current_program:
                    prog = self.scope_manager.current_program
                    if hasattr(prog, "policy_text") and prog.policy_text:
                        policy_intel = cortex.read_policy(
                            prog.policy_text, prog.name
                        )

                # Validate all findings — remove false positives
                validated = cortex.validate_all_findings(
                    result.all_findings,
                    program_name=getattr(
                        self.scope_manager.current_program,
                        "name", "Unknown"
                    ),
                    policy_intel=policy_intel,
                )

                before = len(result.all_findings)
                result.all_findings = validated
                removed = before - len(validated)

                log_phase(
                    f"         {len(validated)} confirmed "
                    f"({removed} false positives removed)",
                    "complete",
                )

                # Write full submission if reportable findings exist
                reportable = [
                    f for f in validated
                    if f.get("cortex_verdict", {}).get("is_reportable")
                ]
                if reportable:
                    result.cortex_report = cortex.write_full_submission(
                        reportable,
                        program_name=getattr(
                            self.scope_manager.current_program,
                            "name", "Unknown"
                        ),
                        target=target,
                    )
                    log_phase(
                        f"         Report written "
                        f"({len(reportable)} reportable findings)",
                        "complete",
                    )

            except Exception as e:
                log_phase(f"Phase 8 failed: {str(e)[:80]}", "failed")
        else:
            log_phase("Phase 8 — CORTEX Validation", "skipped")
        # ── CALCULATE DURATION ───────────────────────────────
        result.duration_seconds = (
            datetime.utcnow() - start_time
        ).total_seconds()

        # ── PRINT SUMMARY ────────────────────────────────────
        if verbose:
            self._print_summary(result)

        return result

    def generate_full_report(
        self,
        result: PipelineResult,
        format: str = "markdown",
    ) -> str:
        """
        Generate complete engagement report

        format: markdown, hackerone, json
        """
        from taijitu.red.brain.report_generator import report_generator

        # Combine all findings into report format
        combined = {
            "target": result.target,
            "timestamp": result.timestamp.isoformat(),
            "total_vulnerabilities": len(result.all_findings),
            "risk_score": min(
                result.critical_count * 40 +
                result.high_count * 20 +
                result.medium_count * 10 +
                result.low_count * 5,
                100,
            ),
            "vulnerabilities": self._group_findings(result.all_findings),
            "interesting_files": result.vuln_report.get(
                "interesting_files", []
            ),
        }

        reports = report_generator.generate_from_scan(
            combined, result.target
        )

        if format == "markdown":
            header = f"""# TAIJITU RED — Engagement Report
**Target:** {result.target}
**Date:** {result.timestamp.strftime('%Y-%m-%d %H:%M')} UTC
**Duration:** {result.duration_seconds:.0f} seconds
**Total Findings:** {len(result.all_findings)}
**Estimated Bounty:** ${result.total_bounty_low:,} - ${result.total_bounty_high:,}

## Attack Surface
- IPs: {result.recon_report.get('summary', {}).get('ip_count', 0)}
- Subdomains: {result.recon_report.get('summary', {}).get('subdomain_count', 0)}
- Pages Crawled: {result.crawl_report.get('summary', {}).get('pages_crawled', 0)}
- Parameters Found: {result.crawl_report.get('summary', {}).get('parameters_found', 0)}
- Forms: {result.crawl_report.get('summary', {}).get('forms_found', 0)}

## AI Guidance
### Guardian
{result.brain_guidance[:500] if result.brain_guidance else 'Not run'}

### Adversary
{result.adversary_guidance[:500] if result.adversary_guidance else 'Not run'}

### Consensus Next Step
{result.consensus if result.consensus else 'Not run'}

---

"""
            return header + report_generator.format_markdown(reports)

        elif format == "hackerone":
            if reports:
                return report_generator.format_hackerone(reports[0])
            return "No findings to report"

        elif format == "json":
            import json
            return json.dumps({
                "target": result.target,
                "duration": result.duration_seconds,
                "findings": result.all_findings,
                "recon": result.recon_report,
                "guidance": {
                    "guardian": result.brain_guidance,
                    "adversary": result.adversary_guidance,
                    "consensus": result.consensus,
                },
                "bounty_estimate": {
                    "low": result.total_bounty_low,
                    "high": result.total_bounty_high,
                },
            }, indent=2)

        return ""

    def _aggregate_findings(self, result: PipelineResult) -> list:
        """Aggregate findings from all modules"""
        findings = []

        # Vuln scanner findings
        for sev, vulns in result.vuln_report.get(
            "vulnerabilities_by_severity", {}
        ).items():
            for v in vulns:
                findings.append({
                    "severity": sev,
                    "type": v.get("name", "Unknown"),
                    "url": v.get("url", result.target),
                    "description": v.get("description", ""),
                    "evidence": v.get("evidence", ""),
                    "remediation": v.get("remediation", ""),
                    "bounty_estimate": "",
                    "source": "vuln_scanner",
                })

        # Web scanner findings
        for vuln_type, vulns in result.web_report.get(
            "vulnerabilities", {}
        ).items():
            for v in vulns:
                findings.append({
                    "severity": v.get("severity", "medium"),
                    "type": vuln_type,
                    "url": v.get("url", result.target),
                    "parameter": v.get("parameter", ""),
                    "description": v.get("description", ""),
                    "evidence": v.get("evidence", ""),
                    "remediation": v.get("remediation", ""),
                    "bounty_estimate": v.get("bounty_estimate", ""),
                    "source": "web_scanner",
                })

        # Takeover findings
        for v in result.takeover_report.get("vulnerable_subdomains", []):
            findings.append({
                "severity": v.get("severity", "high"),
                "type": "Subdomain Takeover",
                "url": v.get("subdomain", ""),
                "description": v.get("description", ""),
                "evidence": f"CNAME: {v.get('cname', '')}",
                "remediation": "Remove dangling DNS record",
                "bounty_estimate": v.get("bounty_estimate", ""),
                "source": "takeover_scanner",
            })

        # Auth scanner findings
        for sev, vulns in result.auth_report.get(
            "findings_by_severity", {}
        ).items():
            for v in vulns:
                findings.append({
                    "severity": sev,
                    "type": v.get("type", "Unknown"),
                    "url": v.get("url", result.target),
                    "description": v.get("description", ""),
                    "evidence": v.get("evidence", ""),
                    "remediation": v.get("remediation", ""),
                    "bounty_estimate": v.get("bounty_estimate", ""),
                    "source": "auth_scanner",
                })

        # Secrets from crawler
        for secret in result.crawl_report.get("secrets", []):
            findings.append({
                "severity": "critical",
                "type": f"Secret Exposed: {secret.get('type')}",
                "url": secret.get("source", result.target),
                "description": f"Secret found in client-side code",
                "evidence": f"Type: {secret.get('type')}, Value: {secret.get('value')}",
                "remediation": "Remove secrets from client-side code immediately",
                "bounty_estimate": "$500 - $5,000",
                "source": "js_crawler",
            })

        return findings

    def _group_findings(self, findings: list) -> dict:
        """Group findings by type for report generator"""
        grouped = {}
        for f in findings:
            vuln_type = f.get("type", "Unknown")
            if vuln_type not in grouped:
                grouped[vuln_type] = []
            grouped[vuln_type].append(f)
        return grouped

    def _estimate_bounty(self, findings: list) -> tuple:
        """Estimate total bounty range from all findings"""
        total_low = 0
        total_high = 0

        for finding in findings:
            estimate = finding.get("bounty_estimate", "")
            if not estimate:
                continue
            try:
                # Parse "$500 - $10,000+" format
                parts = estimate.replace("$", "").replace("+", "")
                parts = parts.replace(",", "").split("-")
                if len(parts) >= 2:
                    total_low += int(parts[0].strip())
                    total_high += int(parts[1].strip())
            except Exception:
                continue

        return total_low, total_high

    def _build_situation(self, result: PipelineResult) -> str:
        """Build situation description for brain analysis"""
        lines = [
            f"I am testing {result.target} on an authorized bug bounty program.",
            f"",
            f"FINDINGS SUMMARY:",
            f"- Critical: {result.critical_count}",
            f"- High: {result.high_count}",
            f"- Medium: {result.medium_count}",
            f"- Low: {result.low_count}",
            f"",
        ]

        # Add top findings
        critical = [
            f for f in result.all_findings
            if f.get("severity") == "critical"
        ]
        if critical:
            lines.append("CRITICAL FINDINGS:")
            for f in critical[:5]:
                lines.append(
                    f"- {f['type']} at {f['url'][:50]}"
                )
            lines.append("")

        high = [
            f for f in result.all_findings
            if f.get("severity") == "high"
        ]
        if high:
            lines.append("HIGH FINDINGS:")
            for f in high[:5]:
                lines.append(
                    f"- {f['type']} at {f['url'][:50]}"
                )

        lines.append("")
        lines.append(
            "What should I focus on to maximize impact and bounty?"
        )

        return "\n".join(lines)

    def _print_summary(self, result: PipelineResult):
        """Suppressed — CLI handles its own output"""
        pass

# ── GLOBAL INSTANCE ───────────────────────────────────
pipeline = AutonomousPipeline()