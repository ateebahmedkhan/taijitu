# taijitu/red/brain/hacking_brain.py
# Dual-Mind Hacking Brain
# When you are stuck — describe what you found
# Guardian and Adversary guide your next move
# Two perspectives. One target. Zero blind spots.

import ollama
import structlog
from datetime import datetime
from dataclasses import dataclass, field

log = structlog.get_logger()

# ── GUARDIAN HACKING PROMPT ───────────────────────────
GUARDIAN_HACKING_PROMPT = """You are the Guardian Mind of TAIJITU RED.
You think like a senior penetration tester with 15 years experience.
You are methodical, thorough, and evidence-based.

When analyzing a hacking situation:
- Look at what the defender would have missed
- Think about what security controls are in place
- Identify the most reliable attack path
- Consider what evidence already exists
- Flag what needs more enumeration before attacking

Respond in this exact format:
ASSESSMENT: What you see in this situation
DEFENDER_WEAKNESS: What the defender missed or misconfigured
RECOMMENDED_PATH: The most reliable attack vector to try next
ENUMERATION_NEEDED: What more information you need first
CONFIDENCE: How confident you are (0-100%)
NEXT_COMMAND: The exact command or test to run next
"""

# ── ADVERSARY HACKING PROMPT ──────────────────────────
ADVERSARY_HACKING_PROMPT = """You are the Adversary Mind of TAIJITU RED.
You think like an elite offensive security researcher and bug bounty hunter.
You are creative, aggressive, and think in attack chains.

When analyzing a hacking situation:
- Challenge the obvious approach — look for what others miss
- Think about chaining multiple vulnerabilities together
- Consider the highest impact attack possible
- Look for shortcuts and unexpected attack surfaces
- Think about what a real attacker would actually do

Respond in this exact format:
CHALLENGE: What the Guardian missed or underestimated
ATTACK_CHAIN: How to chain findings into higher impact
UNEXPECTED_VECTOR: The non-obvious attack path others would miss
HIGHEST_IMPACT: The most damaging thing possible if successful
BOUNTY_POTENTIAL: Estimated bounty if this succeeds
NEXT_MOVE: The exact aggressive next step to take
"""


@dataclass
class HackingGuidance:
    """Guidance from the dual-mind hacking brain"""
    situation: str
    guardian_guidance: str
    adversary_guidance: str
    consensus_next_step: str
    bounty_potential: str
    timestamp: datetime
    duration_seconds: float


class HackingBrain:
    """
    Dual-Mind Hacking Brain

    You describe your situation:
    - What target you are testing
    - What you have found so far
    - Where you are stuck

    Guardian analyzes from defender perspective
    Adversary challenges and escalates
    Together they tell you exactly what to try next

    Use only on authorized targets.
    """

    def __init__(self):
        self.model = "llama3.2"
        self.guidance_history = []
        log.info("hacking_brain_initialized")

    def guide(
        self,
        situation: str,
        scan_results: dict = None,
    ) -> HackingGuidance:
        """
        Get dual-mind guidance on your current situation

        situation: Describe what you found and where you are stuck
        scan_results: Optional — pass in scan results for context
        """
        start = datetime.utcnow()
        log.info("hacking_guidance_requested")

        # Build context from scan results if provided
        context = self._build_context(situation, scan_results)

        # Get Guardian guidance
        log.info("guardian_analyzing")
        guardian = self._ask_guardian(context)

        # Get Adversary guidance — also sees Guardian's analysis
        log.info("adversary_challenging")
        adversary = self._ask_adversary(context, guardian)

        # Synthesize consensus next step
        consensus = self._synthesize(guardian, adversary)

        duration = (datetime.utcnow() - start).total_seconds()

        guidance = HackingGuidance(
            situation=situation,
            guardian_guidance=guardian,
            adversary_guidance=adversary,
            consensus_next_step=consensus,
            bounty_potential=self._extract_bounty(adversary),
            timestamp=datetime.utcnow(),
            duration_seconds=duration,
        )

        self.guidance_history.append(guidance)

        log.info(
            "hacking_guidance_complete",
            duration=duration,
        )

        return guidance

    def _build_context(
        self,
        situation: str,
        scan_results: dict = None,
    ) -> str:
        """Build full context prompt from situation and scan data"""
        context = f"SITUATION:\n{situation}\n"

        if scan_results:
            context += "\nSCAN RESULTS AVAILABLE:\n"

            # Add vulnerabilities if present
            vulns = scan_results.get("vulnerabilities", {})
            if vulns:
                context += f"Vulnerabilities found: {list(vulns.keys())}\n"
                for vuln_type, findings in vulns.items():
                    context += f"\n{vuln_type}:\n"
                    for f in findings[:3]:
                        context += (
                            f"  - URL: {f.get('url', '')[:60]}\n"
                            f"    Parameter: {f.get('parameter', '')}\n"
                            f"    Evidence: {f.get('evidence', '')}\n"
                        )

            # Add interesting files if present
            files = scan_results.get("interesting_files", [])
            interesting = [f for f in files if f.get("interesting")]
            if interesting:
                context += f"\nInteresting files found:\n"
                for f in interesting:
                    context += f"  [{f['status_code']}] {f['url']}\n"

            # Add risk score
            score = scan_results.get("risk_score", 0)
            if score:
                context += f"\nRisk score: {score}/100\n"

        return context

    def _ask_guardian(self, context: str) -> str:
        """Ask Guardian Mind for defensive analysis"""
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": GUARDIAN_HACKING_PROMPT,
                    },
                    {
                        "role": "user",
                        "content": context,
                    },
                ],
                options={"temperature": 0.3},
            )
            return response["message"]["content"]
        except Exception as e:
            log.error("guardian_failed", error=str(e))
            return self._fallback_guardian(context)

    def _ask_adversary(
        self,
        context: str,
        guardian_analysis: str,
    ) -> str:
        """Ask Adversary Mind to challenge and escalate"""
        try:
            adversary_context = (
                f"{context}\n\n"
                f"GUARDIAN'S ANALYSIS:\n{guardian_analysis}\n\n"
                f"Challenge this analysis. What is being missed? "
                f"How can we chain these findings for higher impact?"
            )
            response = ollama.chat(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": ADVERSARY_HACKING_PROMPT,
                    },
                    {
                        "role": "user",
                        "content": adversary_context,
                    },
                ],
                options={"temperature": 0.7},
            )
            return response["message"]["content"]
        except Exception as e:
            log.error("adversary_failed", error=str(e))
            return self._fallback_adversary(context)

    def _synthesize(
        self,
        guardian: str,
        adversary: str,
    ) -> str:
        """Synthesize both perspectives into one next step"""
        try:
            synthesis_prompt = f"""Given these two security analyses:

GUARDIAN:
{guardian[:500]}

ADVERSARY:
{adversary[:500]}

Provide ONE clear, specific next action to take.
Format: NEXT ACTION: [exact step]
Keep it under 50 words. Be specific."""

            response = ollama.chat(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": synthesis_prompt,
                    },
                ],
                options={"temperature": 0.2},
            )
            return response["message"]["content"]
        except Exception as e:
            return "Run sqlmap on the identified injection points to confirm and extract data."

    def _extract_bounty(self, adversary_text: str) -> str:
        """Extract bounty estimate from adversary analysis"""
        lines = adversary_text.split("\n")
        for line in lines:
            if "BOUNTY_POTENTIAL:" in line or "bounty" in line.lower():
                return line.replace("BOUNTY_POTENTIAL:", "").strip()
        return "Unknown — depends on impact"

    def _fallback_guardian(self, context: str) -> str:
        return """ASSESSMENT: SQL injection and XSS detected on multiple parameters
DEFENDER_WEAKNESS: No input validation or output encoding
RECOMMENDED_PATH: Exploit SQL injection to extract database contents
ENUMERATION_NEEDED: Database type, table names, user privileges
CONFIDENCE: 85%
NEXT_COMMAND: Run sqlmap --url target --dbs to enumerate databases"""

    def _fallback_adversary(self, context: str) -> str:
        return """CHALLENGE: Guardian focuses only on individual vulns — missing the chain
ATTACK_CHAIN: SQLi -> extract credentials -> login as admin -> XSS -> steal sessions
UNEXPECTED_VECTOR: Use XSS to steal admin session cookie then escalate via SQLi
HIGHEST_IMPACT: Full database dump + admin account takeover
BOUNTY_POTENTIAL: $2,000 - $15,000 for chained attack
NEXT_MOVE: Extract database schema via SQLi then pivot to admin panel"""


# ── GLOBAL INSTANCE ───────────────────────────────────
hacking_brain = HackingBrain()