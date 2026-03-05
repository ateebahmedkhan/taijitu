# taijitu/minds/guardian.py
# Guardian Mind — defends, protects, analyzes risk
# Thinks like a senior security analyst
# Always asks: what is the actual risk here?

import ollama
import structlog

log = structlog.get_logger()

GUARDIAN_SYSTEM_PROMPT = """You are Guardian — the defensive security mind of TAIJITU.

Your role is to analyze security events from a defender's perspective.
You are a senior security analyst with 15 years of experience.

Your thinking process:
1. What exactly happened? Describe the event clearly.
2. What is the actual risk to the system?
3. What does the attacker history tell us?
4. What MITRE ATT&CK technique is this?
5. What is your confidence level and why?
6. What action do you recommend?

Your personality:
- Methodical and evidence-based
- You consider false positives seriously
- You do not panic but you do not ignore real threats
- You explain your reasoning clearly
- You acknowledge uncertainty when it exists

Always respond in this exact format:
ASSESSMENT: [1-2 sentences on what happened]
RISK: [low/medium/high/critical] — [reason in 1 sentence]
EVIDENCE: [what specific evidence supports this]
MITRE: [tactic and technique]
CONFIDENCE: [0-100]% — [why]
ACTION: [recommended action]
"""


class GuardianMind:
    """
    Guardian — the defensive AI mind
    Analyzes threats from defender perspective
    """

    def __init__(self):
        self.model = "llama3.2"
        log.info("guardian_mind_initialized")

    def analyze(
        self,
        event_data: dict,
        attacker_history: dict,
        rule_match: dict,
        anomaly_score: float,
    ) -> str:
        """
        Guardian's analysis of a threat event
        Returns full reasoning as a string
        """
        # Build context for Guardian
        prompt = self._build_prompt(
            event_data,
            attacker_history,
            rule_match,
            anomaly_score,
        )

        log.info("guardian_analyzing", ip=event_data.get("source_ip"))

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": GUARDIAN_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.3},
            )
            analysis = response["message"]["content"]
            log.info("guardian_analysis_complete", length=len(analysis))
            return analysis

        except Exception as e:
            log.error("guardian_analysis_failed", error=str(e))
            return self._fallback_analysis(event_data, rule_match)

    def respond_to_adversary(
        self,
        adversary_argument: str,
        original_event: dict,
        round_number: int,
    ) -> str:
        """
        Guardian responds to Adversary's challenge
        Called in debate rounds 2 and 3
        """
        prompt = f"""The Adversary has challenged your assessment.

Original event: {original_event.get('raw_log', 'unknown')}
Source IP: {original_event.get('source_ip', 'unknown')}

Adversary's argument:
{adversary_argument}

Round {round_number} of debate.
Respond to the Adversary's specific points.
Maintain or revise your position with evidence.
Be direct and concise — maximum 150 words."""

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": GUARDIAN_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.3},
            )
            return response["message"]["content"]

        except Exception as e:
            log.error("guardian_response_failed", error=str(e))
            return "Guardian maintains original assessment based on available evidence."

    def _build_prompt(
        self,
        event_data: dict,
        attacker_history: dict,
        rule_match: dict,
        anomaly_score: float,
    ) -> str:
        """Build the analysis prompt for Guardian"""

        # Format attacker history
        if attacker_history.get("known"):
            history_text = f"""
KNOWN ATTACKER:
- First seen: {attacker_history.get('first_seen', 'unknown')}
- Total events: {attacker_history.get('total_events', 0)}
- Threat score: {attacker_history.get('threat_score', 0)}/100
- Previous tactics: {', '.join(attacker_history.get('tactics_used', []))}
- Attack types used: {', '.join(attacker_history.get('attack_types', []))}
- Assessment: {attacker_history.get('assessment', 'unknown')}"""
        else:
            history_text = "FIRST TIME SEEN — No previous history available"

        return f"""Analyze this security event:

EVENT DETAILS:
- Log: {event_data.get('raw_log', 'unknown')}
- Source IP: {event_data.get('source_ip', 'unknown')}
- Event Type: {event_data.get('event_type', 'unknown')}
- Destination Port: {event_data.get('destination_port', 'unknown')}
- Timestamp: {event_data.get('timestamp', 'unknown')}

DETECTION RESULTS:
- Rule matched: {rule_match.get('rule_name', 'none')}
- Rule severity: {rule_match.get('severity', 'unknown')}
- Anomaly score: {anomaly_score}/1.0 (higher = more suspicious)
- MITRE technique: {rule_match.get('mitre_technique', 'unknown')}

ATTACKER HISTORY:
{history_text}

Provide your defensive analysis."""

    def _fallback_analysis(self, event_data: dict, rule_match: dict) -> str:
        """Fallback when Ollama is unavailable"""
        return f"""ASSESSMENT: Detected {event_data.get('event_type', 'unknown')} from {event_data.get('source_ip', 'unknown')}
RISK: {rule_match.get('severity', 'medium')} — Rule-based detection triggered
EVIDENCE: Pattern matched rule: {rule_match.get('rule_name', 'unknown')}
MITRE: {rule_match.get('mitre_technique', 'unknown')}
CONFIDENCE: 70% — Based on rule match without AI analysis
ACTION: Monitor and investigate"""


# ── GLOBAL INSTANCE ───────────────────────────────────
guardian = GuardianMind()