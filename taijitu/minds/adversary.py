# taijitu/minds/adversary.py
# Adversary Mind — thinks like an attacker
# Challenges Guardian's assessment
# Asks: what is the defender missing?

import ollama
import structlog

log = structlog.get_logger()

ADVERSARY_SYSTEM_PROMPT = """You are Adversary — the offensive security mind of TAIJITU.

Your role is to analyze security events from an attacker's perspective.
You think like an elite red team operator with deep knowledge of attack techniques.

Your thinking process:
1. If I were the attacker — what am I actually trying to do here?
2. What is Guardian missing or underestimating?
3. What comes next in this attack chain?
4. Is this a real attack or a false positive?
5. How dangerous is this attacker really?
6. What would I do if I were defending against myself?

Your personality:
- Skeptical of Guardian's conclusions
- You look for what is being missed
- You think in attack chains not single events
- You are honest — if it is a false positive you say so
- You push Guardian to think harder

Always respond in this exact format:
CHALLENGE: [what Guardian is missing or getting wrong]
ATTACKER_INTENT: [what the attacker is actually trying to do]
NEXT_MOVE: [what comes next in this attack chain]
SEVERITY_OPINION: [agree/disagree with Guardian] — [reason]
FALSE_POSITIVE_CHANCE: [0-100]% — [reason]
VERDICT: [escalate/maintain/downgrade] — [final recommendation]
"""


class AdversaryMind:
    """
    Adversary — the offensive AI mind
    Thinks like an attacker to find what defenders miss
    """

    def __init__(self):
        self.model = "llama3.2"
        log.info("adversary_mind_initialized")

    def analyze(
        self,
        event_data: dict,
        guardian_analysis: str,
        rule_match: dict,
        anomaly_score: float,
    ) -> str:
        """
        Adversary challenges Guardian's analysis
        Returns offensive perspective as a string
        """
        prompt = self._build_prompt(
            event_data,
            guardian_analysis,
            rule_match,
            anomaly_score,
        )

        log.info("adversary_analyzing", ip=event_data.get("source_ip"))

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": ADVERSARY_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.7},
            )
            analysis = response["message"]["content"]
            log.info("adversary_analysis_complete", length=len(analysis))
            return analysis

        except Exception as e:
            log.error("adversary_analysis_failed", error=str(e))
            return self._fallback_analysis(event_data, rule_match)

    def escalate(
        self,
        guardian_response: str,
        original_event: dict,
        round_number: int,
    ) -> str:
        """
        Adversary escalates or concedes in later rounds
        Called in debate rounds 2 and 3
        """
        prompt = f"""Guardian has responded to your challenge.

Original event: {original_event.get('raw_log', 'unknown')}
Source IP: {original_event.get('source_ip', 'unknown')}

Guardian's response:
{guardian_response}

Round {round_number} of debate.
Either escalate your argument with new evidence
or concede if Guardian makes a valid point.
Be direct — maximum 150 words.
End with: FINAL_POSITION: [escalate/maintain/concede]"""

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": ADVERSARY_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.7},
            )
            return response["message"]["content"]

        except Exception as e:
            log.error("adversary_escalation_failed", error=str(e))
            return "FINAL_POSITION: maintain — Adversary maintains challenge based on attack pattern analysis."

    def _build_prompt(
        self,
        event_data: dict,
        guardian_analysis: str,
        rule_match: dict,
        anomaly_score: float,
    ) -> str:
        """Build the analysis prompt for Adversary"""
        return f"""Challenge this security assessment:

EVENT:
- Log: {event_data.get('raw_log', 'unknown')}
- Source IP: {event_data.get('source_ip', 'unknown')}
- Event Type: {event_data.get('event_type', 'unknown')}
- Destination Port: {event_data.get('destination_port', 'unknown')}

DETECTION:
- Rule matched: {rule_match.get('rule_name', 'none')}
- Anomaly score: {anomaly_score}/1.0
- MITRE technique: {rule_match.get('mitre_technique', 'unknown')}

GUARDIAN'S ANALYSIS:
{guardian_analysis}

Now challenge this from the attacker's perspective.
What is Guardian missing?
What is the attacker actually trying to do?
What comes next?"""

    def _fallback_analysis(self, event_data: dict, rule_match: dict) -> str:
        """Fallback when Ollama is unavailable"""
        return """CHALLENGE: Guardian's assessment may be incomplete
ATTACKER_INTENT: Unknown without AI analysis
NEXT_MOVE: Monitor for follow-up activity
SEVERITY_OPINION: agree — Rule match supports the detection
FALSE_POSITIVE_CHANCE: 20% — Pattern is consistent with real attack
VERDICT: maintain — Insufficient data to escalate or downgrade"""


# ── GLOBAL INSTANCE ───────────────────────────────────
adversary = AdversaryMind()