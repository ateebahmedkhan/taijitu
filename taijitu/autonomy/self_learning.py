# taijitu/autonomy/self_learning.py
# Self-learning engine
# TAIJITU learns from every confirmed threat
# Retrains its own model without human help

import json
import structlog
from datetime import datetime
from dataclasses import dataclass

log = structlog.get_logger()


@dataclass
class LearningResult:
    """Result of a learning cycle"""
    learned: bool
    lesson_type: str        # new_pattern, false_positive, confirmed_threat
    description: str        # What was learned
    confidence_change: float  # How much confidence changed
    timestamp: datetime


class SelfLearningEngine:
    """
    TAIJITU's self-learning system

    What it learns from:
    1. Confirmed threats — strengthens detection rules
    2. False positives — reduces false alarm rate
    3. New attack patterns — creates new rules
    4. Human feedback — highest trust signal

    How it learns:
    - Maintains a lesson log
    - Adjusts rule confidence scores
    - Feeds new patterns to anomaly detector
    - Generates new detection rules from patterns
    """

    def __init__(self):
        self.lessons: list = []
        self.rule_adjustments: dict = {}
        self.new_patterns: list = []
        log.info("self_learning_engine_initialized")

    def learn_from_verdict(
        self,
        verdict,
        event_data: dict,
        rule_match: dict,
    ) -> LearningResult:
        """
        Learn from a completed debate verdict
        Called automatically after every debate
        """
        event_type = event_data.get("event_type", "unknown")
        rule_name = rule_match.get("rule_name", "unknown")
        verdict_type = verdict.verdict

        if verdict_type == "threat":
            return self._learn_confirmed_threat(
                event_type, rule_name, verdict
            )
        elif verdict_type == "false_positive":
            return self._learn_false_positive(
                event_type, rule_name, verdict
            )
        else:
            return self._learn_unknown(event_type, rule_name)

    def learn_from_feedback(
        self,
        ip: str,
        event_type: str,
        human_verdict: str,
        original_verdict: str,
    ) -> LearningResult:
        """
        Learn from human feedback
        When human confirms or overrides TAIJITU's verdict
        Human feedback is the highest trust signal
        """
        if human_verdict == original_verdict:
            # Human agreed — reinforce
            lesson = LearningResult(
                learned=True,
                lesson_type="human_confirmed",
                description=f"Human confirmed {original_verdict} for {event_type} — reinforcing",
                confidence_change=+0.05,
                timestamp=datetime.utcnow(),
            )
            log.info(
                "human_confirmed_verdict",
                event_type=event_type,
                verdict=original_verdict,
            )
        else:
            # Human disagreed — correct
            lesson = LearningResult(
                learned=True,
                lesson_type="human_correction",
                description=f"Human corrected {original_verdict} to {human_verdict} for {event_type}",
                confidence_change=-0.15,
                timestamp=datetime.utcnow(),
            )
            log.info(
                "human_corrected_verdict",
                event_type=event_type,
                original=original_verdict,
                correction=human_verdict,
            )

        self.lessons.append(lesson)
        self._adjust_rule_confidence(event_type, lesson.confidence_change)
        return lesson

    def generate_new_rule(
        self,
        pattern: str,
        event_type: str,
        severity: str,
        mitre_tactic: str,
        mitre_technique: str,
    ) -> dict:
        """
        Generate a new detection rule from a novel pattern
        Called when TAIJITU sees something new
        that no existing rule covers
        """
        new_rule = {
            "name": f"auto_{event_type}_{len(self.new_patterns)}",
            "description": f"Auto-generated rule from confirmed {event_type}",
            "pattern_type": "keyword",
            "keywords": [pattern],
            "severity": severity,
            "confidence": 0.70,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "auto_generated": True,
            "generated_at": datetime.utcnow().isoformat(),
        }

        self.new_patterns.append(new_rule)

        log.info(
            "new_rule_generated",
            rule_name=new_rule["name"],
            event_type=event_type,
            severity=severity,
        )

        return new_rule

    def retrain_anomaly_detector(self, confirmed_events: list) -> bool:
        """
        Retrain Isolation Forest on confirmed threat data
        Makes anomaly detector more accurate over time
        Called weekly or after 100 new confirmed threats
        """
        if len(confirmed_events) < 10:
            log.info(
                "retrain_skipped",
                reason="insufficient_data",
                count=len(confirmed_events),
            )
            return False

        try:
            from taijitu.detection.anomaly_detector import anomaly_detector

            # Convert confirmed events to training format
            training_data = []
            for event in confirmed_events:
                training_data.append({
                    "timestamp": event.get("timestamp", datetime.utcnow()),
                    "destination_port": event.get("destination_port", 0),
                    "source_port": event.get("source_port", 0),
                    "event_type": event.get("event_type", "unknown"),
                    "log_source": event.get("log_source", "unknown"),
                })

            anomaly_detector.train(training_data)

            log.info(
                "anomaly_detector_retrained",
                samples=len(training_data),
            )
            return True

        except Exception as e:
            log.error("retrain_failed", error=str(e))
            return False

    def get_learning_summary(self) -> dict:
        """Summary of everything TAIJITU has learned"""
        confirmed = sum(
            1 for l in self.lessons
            if l.lesson_type == "confirmed_threat"
        )
        false_positives = sum(
            1 for l in self.lessons
            if l.lesson_type == "false_positive"
        )
        corrections = sum(
            1 for l in self.lessons
            if l.lesson_type == "human_correction"
        )

        return {
            "total_lessons": len(self.lessons),
            "confirmed_threats": confirmed,
            "false_positives_learned": false_positives,
            "human_corrections": corrections,
            "new_rules_generated": len(self.new_patterns),
            "rule_adjustments": len(self.rule_adjustments),
        }

    def _learn_confirmed_threat(
        self,
        event_type: str,
        rule_name: str,
        verdict,
    ) -> LearningResult:
        """Learn from a confirmed threat"""
        lesson = LearningResult(
            learned=True,
            lesson_type="confirmed_threat",
            description=f"Confirmed {event_type} threat — strengthening rule {rule_name}",
            confidence_change=+0.02,
            timestamp=datetime.utcnow(),
        )
        self.lessons.append(lesson)
        self._adjust_rule_confidence(rule_name, +0.02)
        log.info(
            "learned_confirmed_threat",
            event_type=event_type,
            rule=rule_name,
        )
        return lesson

    def _learn_false_positive(
        self,
        event_type: str,
        rule_name: str,
        verdict,
    ) -> LearningResult:
        """Learn from a false positive"""
        lesson = LearningResult(
            learned=True,
            lesson_type="false_positive",
            description=f"False positive on {event_type} — reducing rule {rule_name} confidence",
            confidence_change=-0.05,
            timestamp=datetime.utcnow(),
        )
        self.lessons.append(lesson)
        self._adjust_rule_confidence(rule_name, -0.05)
        log.info(
            "learned_false_positive",
            event_type=event_type,
            rule=rule_name,
        )
        return lesson

    def _learn_unknown(
        self,
        event_type: str,
        rule_name: str,
    ) -> LearningResult:
        """Learn from an uncertain verdict"""
        lesson = LearningResult(
            learned=False,
            lesson_type="uncertain",
            description=f"Uncertain verdict on {event_type} — no adjustment",
            confidence_change=0.0,
            timestamp=datetime.utcnow(),
        )
        self.lessons.append(lesson)
        return lesson

    def _adjust_rule_confidence(
        self,
        rule_name: str,
        delta: float,
    ) -> None:
        """Adjust a rule's confidence score"""
        current = self.rule_adjustments.get(rule_name, 0.0)
        self.rule_adjustments[rule_name] = round(current + delta, 3)


# ── GLOBAL INSTANCE ───────────────────────────────────
self_learning = SelfLearningEngine()