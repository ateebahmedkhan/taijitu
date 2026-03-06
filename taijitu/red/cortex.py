# taijitu/red/cortex.py
# TAIJITU CORTEX — Intelligence Layer
# Powered by Groq (free, fast, llama3-70b)
# Reads program policies, validates findings,
# writes reports, learns from engagements

import os
import json
import re
import structlog
from dataclasses import dataclass, field
from typing import Optional

log = structlog.get_logger()

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"
MODEL         = "moonshotai/kimi-k2-instruct"   # CORTEX — precision tasks
MODEL_FAST    = "llama-3.3-70b-versatile"        # Brain — fast debate tasks


def _ask(system: str, user: str, max_tokens: int = 1024, model: str = None) -> str:
    """Single Groq API call — returns text response"""
    try:
        import requests
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model":       model or MODEL,
            "max_tokens":  max_tokens,
            "temperature": 0.3,
            "messages": [
                {"role": "system",  "content": system},
                {"role": "user",    "content": user},
            ],
        }
        resp = requests.post(
            GROQ_URL, headers=headers,
            json=payload, timeout=30,
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip()
        else:
            log.error("groq_api_error", status=resp.status_code)
            return ""
    except Exception as e:
        log.error("groq_request_failed", error=str(e)[:100])
        return ""


@dataclass
class PolicyIntelligence:
    """Extracted intelligence from a bug bounty program policy"""
    program_name:       str   = ""
    what_they_want:     list  = field(default_factory=list)
    what_they_ignore:   list  = field(default_factory=list)
    testing_rules:      list  = field(default_factory=list)
    needs_account:      bool  = False
    account_guidance:   str   = ""
    top_priority:       str   = ""
    avoid:              list  = field(default_factory=list)
    summary:            str   = ""


@dataclass
class FindingVerdict:
    """CORTEX verdict on a single finding"""
    is_real:        bool  = False
    is_reportable:  bool  = False
    severity:       str   = "info"
    confidence:     float = 0.0
    reason:         str   = ""
    next_step:      str   = ""


@dataclass
class ReportSection:
    """A single finding written for HackerOne submission"""
    title:          str = ""
    severity:       str = ""
    summary:        str = ""
    steps:          str = ""
    impact:         str = ""
    remediation:    str = ""
    cvss:           str = ""


class Cortex:
    """
    TAIJITU CORTEX — The Intelligence Layer

    Three core capabilities:
    1. Policy Reader    — understands program rules
    2. Finding Validator — confirms real vs false positive
    3. Report Writer    — writes submission-ready reports
    """

    def __init__(self):
        if not GROQ_API_KEY:
            log.warning("cortex_no_api_key",
                        msg="Set GROQ_API_KEY in ~/.zshrc")
        else:
            log.info("cortex_initialized", model=MODEL)

    # ── 1. POLICY READER ─────────────────────────────────

    def read_policy(
        self,
        policy_text: str,
        program_name: str = "",
    ) -> PolicyIntelligence:
        """
        Read and understand a bug bounty program policy.
        Extract what they want, what to avoid, testing rules.

        Usage:
            policy = cortex.read_policy(policy_page_text, "Google VRP")
        """
        log.info("cortex_reading_policy", program=program_name)

        system = """You are a senior bug bounty researcher.
        Analyze bug bounty program policies and extract actionable intelligence.
        Always respond in valid JSON only. No explanation, no markdown, just JSON."""

        user = f"""Analyze this bug bounty program policy for {program_name}.
        
Extract and return this JSON structure:
{{
  "what_they_want": ["list of vulnerability types they prioritize and pay well for"],
  "what_they_ignore": ["list of issues they explicitly do not pay for"],
  "testing_rules": ["list of testing restrictions or requirements"],
  "needs_account": true or false,
  "account_guidance": "instructions for creating test account if needed",
  "top_priority": "single most important thing to test first",
  "avoid": ["list of things that will get you banned or rejected"],
  "summary": "2 sentence summary of what this program is about"
}}

Policy text:
{policy_text[:4000]}"""

        response = _ask(system, user, max_tokens=1024)

        intel = PolicyIntelligence(program_name=program_name)

        try:
            # Strip any markdown if present
            clean = re.sub(r'```json|```', '', response).strip()
            data  = json.loads(clean)

            intel.what_they_want   = data.get("what_they_want",   [])
            intel.what_they_ignore = data.get("what_they_ignore", [])
            intel.testing_rules    = data.get("testing_rules",    [])
            intel.needs_account    = data.get("needs_account",    False)
            intel.account_guidance = data.get("account_guidance", "")
            intel.top_priority     = data.get("top_priority",     "")
            intel.avoid            = data.get("avoid",            [])
            intel.summary          = data.get("summary",          "")

            log.info("cortex_policy_read",
                     program=program_name,
                     priorities=len(intel.what_they_want),
                     rules=len(intel.testing_rules))

        except Exception as e:
            log.error("cortex_policy_parse_error", error=str(e)[:100])

        return intel

    # ── 2. FINDING VALIDATOR ──────────────────────────────

    def validate_finding(
        self,
        finding: dict,
        program_name: str = "",
        policy_intel: Optional[PolicyIntelligence] = None,
    ) -> FindingVerdict:
        """
        Validate a single finding.
        Is it real? Is it reportable? What severity?

        Usage:
            verdict = cortex.validate_finding(finding, "Google VRP", intel)
        """
        log.info("cortex_validating_finding",
                 type=finding.get("type", ""),
                 severity=finding.get("severity", ""))

        policy_context = ""
        if policy_intel:
            policy_context = f"""
Program priorities: {', '.join(policy_intel.what_they_want[:5])}
Program ignores: {', '.join(policy_intel.what_they_ignore[:5])}
Program rules: {', '.join(policy_intel.testing_rules[:3])}
"""

        system = """You are a senior bug bounty triager with 10 years experience.
        Evaluate security findings for validity and reportability.
        Be skeptical — most automated scanner findings are false positives.
        Respond in valid JSON only."""

        user = f"""Evaluate this security finding for the {program_name} bug bounty program.

Finding:
- Type: {finding.get('type', '')}
- Severity claimed: {finding.get('severity', '')}
- URL: {finding.get('url', '')}
- Evidence: {finding.get('evidence', '')}
- Description: {finding.get('description', '')}

{policy_context}

Return this JSON:
{{
  "is_real": true or false,
  "is_reportable": true or false,
  "severity": "critical/high/medium/low/info",
  "confidence": 0.0 to 1.0,
  "reason": "one sentence explaining your verdict",
  "next_step": "specific action to verify or exploit this finding"
}}

Be harsh on false positives. Missing headers alone are rarely reportable.
Only mark is_real=true if there is strong evidence of an actual vulnerability."""

        response = _ask(system, user, max_tokens=512)

        verdict = FindingVerdict()

        try:
            clean = re.sub(r'```json|```', '', response).strip()
            data  = json.loads(clean)

            verdict.is_real       = data.get("is_real",       False)
            verdict.is_reportable = data.get("is_reportable", False)
            verdict.severity      = data.get("severity",      "info")
            verdict.confidence    = float(data.get("confidence", 0.0))
            verdict.reason        = data.get("reason",        "")
            verdict.next_step     = data.get("next_step",     "")

            log.info("cortex_finding_verdict",
                     real=verdict.is_real,
                     reportable=verdict.is_reportable,
                     confidence=verdict.confidence)

        except Exception as e:
            log.error("cortex_verdict_parse_error", error=str(e)[:100])

        return verdict

    def validate_all_findings(
        self,
        findings: list,
        program_name: str = "",
        policy_intel: Optional[PolicyIntelligence] = None,
    ) -> list:
        """Validate all findings concurrently — one API call per finding in parallel"""
        import concurrent.futures

        log.info("cortex_validating_all",
                 count=len(findings), program=program_name)

        def validate_one(finding):
            verdict = self.validate_finding(finding, program_name, policy_intel)
            if verdict.is_real:
                finding["cortex_verdict"] = {
                    "is_reportable": verdict.is_reportable,
                    "severity":      verdict.severity,
                    "confidence":    verdict.confidence,
                    "reason":        verdict.reason,
                    "next_step":     verdict.next_step,
                }
                finding["severity"] = verdict.severity
                return finding
            return None

        validated = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
            results = list(pool.map(validate_one, findings))
            validated = [r for r in results if r is not None]

        log.info("cortex_validation_complete",
                 original=len(findings),
                 validated=len(validated),
                 filtered=len(findings) - len(validated))

        return validated

    # ── 3. REPORT WRITER ─────────────────────────────────

    def write_report(
        self,
        finding: dict,
        program_name: str = "",
        target: str = "",
    ) -> ReportSection:
        """
        Write a submission-ready HackerOne report for a finding.
        Professional, concise, follows HackerOne best practices.

        Usage:
            report = cortex.write_report(finding, "Google VRP", "accounts.google.com")
        """
        log.info("cortex_writing_report",
                 type=finding.get("type", ""))

        system = """You are a professional bug bounty report writer.
        Write clear, concise, professional vulnerability reports for HackerOne.
        Keep reports factual and to the point. No fluff. No exaggeration.
        Respond in valid JSON only."""

        user = f"""Write a professional HackerOne bug bounty report for this finding.

Program: {program_name}
Target: {target}
Vulnerability type: {finding.get('type', '')}
Severity: {finding.get('severity', '')}
URL: {finding.get('url', '')}
Evidence: {finding.get('evidence', '')}
Description: {finding.get('description', '')}

Return this JSON:
{{
  "title": "concise vulnerability title (under 80 chars)",
  "severity": "critical/high/medium/low",
  "summary": "2-3 sentence description of the vulnerability and its impact",
  "steps": "numbered steps to reproduce, starting from unauthenticated state",
  "impact": "what an attacker could do with this vulnerability",
  "remediation": "specific technical fix recommendation",
  "cvss": "CVSS 3.1 score estimate like 8.1 (High)"
}}"""

        response = _ask(system, user, max_tokens=1024)

        section = ReportSection()

        try:
            clean = re.sub(r'```json|```', '', response).strip()
            data  = json.loads(clean)

            section.title       = data.get("title",       "")
            section.severity    = data.get("severity",    "")
            section.summary     = data.get("summary",     "")
            section.steps       = data.get("steps",       "")
            section.impact      = data.get("impact",      "")
            section.remediation = data.get("remediation", "")
            section.cvss        = data.get("cvss",        "")

            log.info("cortex_report_written",
                     title=section.title[:50])

        except Exception as e:
            log.error("cortex_report_parse_error", error=str(e)[:100])

        return section

    def write_full_submission(
        self,
        findings: list,
        program_name: str = "",
        target: str = "",
    ) -> str:
        """
        Write complete HackerOne submission for all validated findings.
        Returns formatted markdown ready to paste into HackerOne.
        """
        if not findings:
            return "No validated findings to report."

        lines = []
        lines.append(f"# Security Research Report — {target}")
        lines.append(f"**Program:** {program_name}")
        lines.append(f"**Researcher:** TAIJITU RED Autonomous Pipeline")
        lines.append("")

        for i, finding in enumerate(findings, 1):
            report = self.write_report(finding, program_name, target)

            lines.append(f"---")
            lines.append(f"## Finding {i} — {report.title}")
            lines.append(f"**Severity:** {report.severity.upper()}")
            if report.cvss:
                lines.append(f"**CVSS:** {report.cvss}")
            lines.append("")
            lines.append(f"### Summary")
            lines.append(report.summary)
            lines.append("")
            lines.append(f"### Steps to Reproduce")
            lines.append(report.steps)
            lines.append("")
            lines.append(f"### Impact")
            lines.append(report.impact)
            lines.append("")
            lines.append(f"### Remediation")
            lines.append(report.remediation)
            lines.append("")

        return "\n".join(lines)

    # ── 4. STRATEGY ENGINE ───────────────────────────────

    def get_strategy(
        self,
        target: str,
        tech_stack: list = None,
        policy_intel: Optional[PolicyIntelligence] = None,
        previous_findings: list = None,
    ) -> str:
        """
        Get specific hunting strategy for a target.
        Based on tech stack, program priorities, and what was already found.
        """
        log.info("cortex_strategy_request", target=target)

        context_parts = [f"Target: {target}"]

        if tech_stack:
            context_parts.append(
                f"Technology stack: {', '.join(tech_stack)}"
            )

        if policy_intel:
            context_parts.append(
                f"Program wants: {', '.join(policy_intel.what_they_want[:3])}"
            )
            context_parts.append(
                f"Top priority: {policy_intel.top_priority}"
            )

        if previous_findings:
            types = [f.get("type", "") for f in previous_findings[:5]]
            context_parts.append(
                f"Already found: {', '.join(types)}"
            )

        context = "\n".join(context_parts)

        system = """You are a senior bug bounty researcher with a track record of
        finding critical vulnerabilities. Give specific, actionable hunting advice.
        Be direct. No generic advice. Specific to this target and context."""

        user = f"""Give me a specific bug hunting strategy for this engagement.

{context}

Tell me:
1. Exactly what to test first and why
2. Which endpoints are highest value
3. What vulnerability type is most likely given the tech stack
4. One specific test to run right now

Keep it under 200 words. Be specific, not generic."""

        return _ask(system, user, max_tokens=400)


# ── GLOBAL INSTANCE ───────────────────────────────────
cortex = Cortex()