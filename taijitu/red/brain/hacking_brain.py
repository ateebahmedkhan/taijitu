# taijitu/red/brain/hacking_brain.py
# Dual-Mind Hacking Brain
# Guardian + Adversary powered by Kimi K2 on Groq
# Concurrent calls — Phase 7 completes in under 5 seconds

import os
import structlog
import requests
import concurrent.futures
from datetime import datetime
from dataclasses import dataclass, field

log = structlog.get_logger()

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"

# Kimi K2 — 1T MoE model, built for agentic reasoning and tool use
# Best model on Groq for complex security analysis
MODEL        = "moonshotai/kimi-k2-instruct"

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
    situation:           str
    guardian_guidance:   str
    adversary_guidance:  str
    consensus_next_step: str
    bounty_potential:    str
    timestamp:           datetime
    duration_seconds:    float


def _groq(system: str, user: str, temperature: float = 0.3) -> str:
    """Single Groq API call — returns text"""
    if not GROQ_API_KEY:
        return ""
    try:
        resp = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type":  "application/json",
            },
            json={
                "model":       MODEL,
                "max_tokens":  1024,
                "temperature": temperature,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
                ],
            },
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip()
        log.error("brain_groq_error", status=resp.status_code, body=resp.text[:200])
        return ""
    except Exception as e:
        log.error("brain_groq_failed", error=str(e)[:100])
        return ""


class HackingBrain:
    """
    Dual-Mind Hacking Brain — Powered by Kimi K2 on Groq

    Guardian and Adversary run CONCURRENTLY.
    Phase 7 completes in under 5 seconds.

    Guardian  — methodical, evidence-based, defender perspective
    Adversary — aggressive, creative, attack chain focus
    Consensus — synthesized single next action

    Use only on authorized targets.
    """

    def __init__(self):
        self.guidance_history = []
        if GROQ_API_KEY:
            log.info("hacking_brain_initialized", model=MODEL)
        else:
            log.warning("hacking_brain_no_key", msg="Set GROQ_API_KEY in ~/.zshrc")

    def guide(
        self,
        situation:    str,
        scan_results: dict = None,
    ) -> HackingGuidance:
        """
        Get dual-mind guidance on your current situation.
        Guardian and Adversary run concurrently — fast.

        situation:    Describe what you found and where you are stuck
        scan_results: Optional scan results dict for richer context
        """
        start   = datetime.utcnow()
        context = self._build_context(situation, scan_results)

        log.info("hacking_guidance_requested")

        # ── RUN GUARDIAN + ADVERSARY CONCURRENTLY ────────
        # Both calls fire at the same time — cuts time in half
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            log.info("guardian_analyzing")
            log.info("adversary_challenging")

            guardian_future  = pool.submit(self._ask_guardian, context)
            adversary_future = pool.submit(self._ask_adversary, context)

            guardian  = guardian_future.result()
            adversary = adversary_future.result()

        # Synthesize after both complete
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
        log.info("hacking_guidance_complete", duration=duration)

        return guidance

    def _build_context(
        self,
        situation:    str,
        scan_results: dict = None,
    ) -> str:
        """Build full context from situation description and scan data"""
        context = f"SITUATION:\n{situation}\n"

        if not scan_results:
            return context

        context += "\nSCAN RESULTS:\n"

        vulns = scan_results.get("vulnerabilities", {})
        if vulns:
            context += f"Vulnerabilities: {list(vulns.keys())}\n"
            for vuln_type, findings in vulns.items():
                context += f"\n{vuln_type}:\n"
                for f in findings[:3]:
                    context += (
                        f"  URL:       {f.get('url', '')[:80]}\n"
                        f"  Parameter: {f.get('parameter', '')}\n"
                        f"  Evidence:  {f.get('evidence', '')[:100]}\n"
                    )

        files = scan_results.get("interesting_files", [])
        interesting = [f for f in files if f.get("interesting")]
        if interesting:
            context += "\nInteresting files:\n"
            for f in interesting[:5]:
                context += f"  [{f['status_code']}] {f['url']}\n"

        score = scan_results.get("risk_score", 0)
        if score:
            context += f"\nRisk score: {score}/100\n"

        return context

    def _ask_guardian(self, context: str) -> str:
        """Guardian Mind — methodical defender-aware analysis"""
        result = _groq(GUARDIAN_HACKING_PROMPT, context, temperature=0.3)
        return result if result else self._fallback_guardian()

    def _ask_adversary(self, context: str) -> str:
        """Adversary Mind — aggressive attack chain focus"""
        result = _groq(ADVERSARY_HACKING_PROMPT, context, temperature=0.7)
        return result if result else self._fallback_adversary()

    def _synthesize(self, guardian: str, adversary: str) -> str:
        """Synthesize both minds into one concrete next action"""
        prompt = f"""Two security analysts reviewed this target.

GUARDIAN:
{guardian[:600]}

ADVERSARY:
{adversary[:600]}

Give ONE specific next action. Format:
NEXT ACTION: [exact step, under 50 words]"""

        result = _groq("You are a senior security researcher. Be direct and specific.", prompt, temperature=0.2)
        return result if result else "Run sqlmap on identified injection points to confirm and extract data."

    def _extract_bounty(self, adversary_text: str) -> str:
        """Extract bounty estimate from adversary analysis"""
        for line in adversary_text.split("\n"):
            if "BOUNTY_POTENTIAL:" in line:
                return line.replace("BOUNTY_POTENTIAL:", "").strip()
        return "Unknown — depends on impact"

    def _fallback_guardian(self) -> str:
        return (
            "ASSESSMENT: SQL injection and XSS detected on multiple parameters\n"
            "DEFENDER_WEAKNESS: No input validation or output encoding\n"
            "RECOMMENDED_PATH: Exploit SQL injection to extract database contents\n"
            "ENUMERATION_NEEDED: Database type, table names, user privileges\n"
            "CONFIDENCE: 85%\n"
            "NEXT_COMMAND: sqlmap -u 'http://target/page?id=1' --dbs"
        )

    def _fallback_adversary(self) -> str:
        return (
            "CHALLENGE: Guardian focuses only on individual vulns — missing the chain\n"
            "ATTACK_CHAIN: SQLi -> extract credentials -> login as admin -> XSS -> steal sessions\n"
            "UNEXPECTED_VECTOR: Use XSS to steal admin session cookie then escalate via SQLi\n"
            "HIGHEST_IMPACT: Full database dump + admin account takeover\n"
            "BOUNTY_POTENTIAL: $2,000 - $15,000 for chained attack\n"
            "NEXT_MOVE: Extract database schema via SQLi then pivot to admin panel"
        )


# ── GLOBAL INSTANCE ───────────────────────────────────
hacking_brain = HackingBrain()