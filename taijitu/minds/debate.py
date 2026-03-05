# taijitu/minds/debate.py
# Debate orchestrator — runs Guardian vs Adversary
# Three rounds — verdict produced at the end
# This is the heart of TAIJITU

import time
import structlog
from datetime import datetime
from dataclasses import dataclass

from taijitu.minds.guardian import guardian
from taijitu.minds.adversary import adversary

log = structlog.get_logger()


@dataclass
class DebateVerdict:
    """Final verdict after full debate"""
    # Verdict
    verdict: str                    # threat / false_positive / unknown
    final_severity: str             # low / medium / high / critical
    final_confidence: float         # 0.0 to 1.0
    recommended_action: str         # block / monitor / ignore

    # Transcript
    round_1_guardian: str
    round_1_adversary: str
    round_2_guardian: str
    round_2_adversary: str
    round_3_guardian: str
    round_3_adversary: str

    # Metadata
    debate_rounds: int
    duration_seconds: float
    timestamp: datetime
    event_id: int = 0

    # Summary
    guardian_summary: str = ""
    adversary_summary: str = ""
    explanation: str = ""


class DebateEngine:
    """
    Orchestrates the three-round debate
    between Guardian and Adversary minds

    Round 1: Both minds give opening analysis
    Round 2: Both minds respond to each other
    Round 3: Both minds give final position
    Verdict: Engine produces final decision
    """

    def __init__(self):
        self.guardian = guardian
        self.adversary = adversary
        log.info("debate_engine_initialized")

    def run(
        self,
        event_data: dict,
        attacker_history: dict,
        rule_match: dict,
        anomaly_score: float,
        event_id: int = 0,
    ) -> DebateVerdict:
        """
        Run the full three-round debate
        Returns complete verdict with transcript
        """
        start_time = time.time()
        timestamp = datetime.utcnow()

        log.info(
            "debate_starting",
            event_id=event_id,
            ip=event_data.get("source_ip"),
            event_type=event_data.get("event_type"),
        )

        # ── ROUND 1 — Opening Analysis ─────────────────
        log.info("debate_round_1")

        r1_guardian = self.guardian.analyze(
            event_data=event_data,
            attacker_history=attacker_history,
            rule_match=rule_match,
            anomaly_score=anomaly_score,
        )

        r1_adversary = self.adversary.analyze(
            event_data=event_data,
            guardian_analysis=r1_guardian,
            rule_match=rule_match,
            anomaly_score=anomaly_score,
        )

        # ── ROUND 2 — Challenge and Response ───────────
        log.info("debate_round_2")

        r2_guardian = self.guardian.respond_to_adversary(
            adversary_argument=r1_adversary,
            original_event=event_data,
            round_number=2,
        )

        r2_adversary = self.adversary.escalate(
            guardian_response=r2_guardian,
            original_event=event_data,
            round_number=2,
        )

        # ── ROUND 3 — Final Positions ───────────────────
        log.info("debate_round_3")

        r3_guardian = self.guardian.respond_to_adversary(
            adversary_argument=r2_adversary,
            original_event=event_data,
            round_number=3,
        )

        r3_adversary = self.adversary.escalate(
            guardian_response=r3_guardian,
            original_event=event_data,
            round_number=3,
        )

        # ── VERDICT ────────────────────────────────────
        log.info("debate_producing_verdict")

        verdict = self._produce_verdict(
            event_data=event_data,
            rule_match=rule_match,
            anomaly_score=anomaly_score,
            r1_guardian=r1_guardian,
            r1_adversary=r1_adversary,
            r3_adversary=r3_adversary,
        )

        duration = time.time() - start_time

        log.info(
            "debate_complete",
            event_id=event_id,
            verdict=verdict["verdict"],
            severity=verdict["severity"],
            confidence=verdict["confidence"],
            duration=round(duration, 2),
        )

        return DebateVerdict(
            verdict=verdict["verdict"],
            final_severity=verdict["severity"],
            final_confidence=verdict["confidence"],
            recommended_action=verdict["action"],
            round_1_guardian=r1_guardian,
            round_1_adversary=r1_adversary,
            round_2_guardian=r2_guardian,
            round_2_adversary=r2_adversary,
            round_3_guardian=r3_guardian,
            round_3_adversary=r3_adversary,
            debate_rounds=3,
            duration_seconds=round(duration, 2),
            timestamp=timestamp,
            event_id=event_id,
            guardian_summary=self._extract_summary(r3_guardian),
            adversary_summary=self._extract_summary(r3_adversary),
            explanation=self._build_explanation(verdict, r1_guardian, r1_adversary),
        )

    def _produce_verdict(
        self,
        event_data: dict,
        rule_match: dict,
        anomaly_score: float,
        r1_guardian: str,
        r1_adversary: str,
        r3_adversary: str,
    ) -> dict:
        """
        Produce final verdict from debate
        Uses rule match + anomaly score + debate content
        """
        # Start with rule-based severity
        severity = rule_match.get("severity", "medium")
        confidence = rule_match.get("confidence", 0.5)

        # Adjust based on anomaly score
        if anomaly_score > 0.8:
            confidence = min(confidence + 0.15, 1.0)

        # Check if Adversary conceded
        adversary_conceded = "concede" in r3_adversary.lower()
        adversary_escalated = "escalate" in r3_adversary.lower()

        # Check if Guardian is confident
        guardian_confident = any(word in r1_guardian.lower() for word in [
            "high confidence", "clearly", "definitely", "certain"
        ])

        # Determine verdict
        if adversary_conceded and guardian_confident:
            verdict = "threat"
            confidence = min(confidence + 0.1, 1.0)
        elif adversary_escalated:
            verdict = "threat"
            severity = self._upgrade_severity(severity)
            confidence = min(confidence + 0.05, 1.0)
        elif "false positive" in r1_adversary.lower() and not guardian_confident:
            verdict = "false_positive"
            confidence = max(confidence - 0.2, 0.1)
        else:
            verdict = "threat"

        # Determine action
        action = self._determine_action(verdict, severity, confidence)

        return {
            "verdict": verdict,
            "severity": severity,
            "confidence": round(confidence, 2),
            "action": action,
        }

    def _upgrade_severity(self, current: str) -> str:
        """Upgrade severity one level"""
        levels = ["low", "medium", "high", "critical"]
        idx = levels.index(current) if current in levels else 1
        return levels[min(idx + 1, 3)]

    def _determine_action(
        self,
        verdict: str,
        severity: str,
        confidence: float,
    ) -> str:
        """Determine recommended action from verdict"""
        if verdict == "false_positive":
            return "ignore"
        if severity == "critical" and confidence > 0.7:
            return "block_immediately"
        if severity == "high" and confidence > 0.6:
            return "block_and_alert"
        if severity == "medium":
            return "alert_and_monitor"
        return "monitor"

    def _extract_summary(self, text: str) -> str:
        """Extract first 200 characters as summary"""
        if not text:
            return ""
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        return lines[0][:200] if lines else text[:200]

    def _build_explanation(
        self,
        verdict: dict,
        guardian_text: str,
        adversary_text: str,
    ) -> str:
        """Build plain English explanation of verdict"""
        return (
            f"Verdict: {verdict['verdict'].upper()} | "
            f"Severity: {verdict['severity'].upper()} | "
            f"Confidence: {int(verdict['confidence'] * 100)}% | "
            f"Action: {verdict['action']}"
        )


# ── GLOBAL INSTANCE ───────────────────────────────────
debate_engine = DebateEngine()