# taijitu/autonomy/night_probe.py
# Adversarial night probe
# TAIJITU attacks itself at 3am
# Finds weaknesses before real attackers do

import structlog
from datetime import datetime
from dataclasses import dataclass, field

log = structlog.get_logger()


@dataclass
class ProbeResult:
    """Result of a night probe run"""
    started_at: datetime
    completed_at: datetime
    total_probes: int
    weaknesses_found: int
    rules_triggered: int
    missed_attacks: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    security_score_before: float = 50.0
    security_score_after: float = 50.0


class NightProbe:
    """
    Adversarial self-testing system

    What it does at 3am:
    1. Generates attack simulations against own detection
    2. Checks which attacks were missed
    3. Identifies weak detection rules
    4. Generates hardening recommendations
    5. Updates security posture score
    6. Sends report via Telegram

    Why this matters:
    Real attackers probe your defenses constantly
    TAIJITU probes itself first
    Finds gaps before attackers exploit them
    """

    def __init__(self):
        self.probe_history: list = []
        self.last_run: datetime = None
        log.info("night_probe_initialized")

    def run(self, security_score: float = 50.0) -> ProbeResult:
        """
        Run the full adversarial night probe
        Tests all detection rules against simulated attacks
        """
        started_at = datetime.utcnow()
        log.info("night_probe_starting", time=started_at.isoformat())

        from taijitu.ingestion.log_sources import simulator
        from taijitu.detection.rule_engine import rule_engine

        missed_attacks = []
        rules_triggered = 0
        total_probes = 0

        # ── PROBE 1 — Test all attack types ───────────
        attack_types = [
            "ssh_brute_force",
            "port_scan",
            "sql_injection",
            "xss_attempt",
            "c2_beacon",
            "ransomware_activity",
            "credential_dumping",
        ]

        for attack_type in attack_types:
            for _ in range(3):
                event = simulator.generate_attack(attack_type)
                result = rule_engine.check(event.raw_log)
                total_probes += 1

                if result.matched:
                    rules_triggered += 1
                else:
                    missed_attacks.append({
                        "attack_type": attack_type,
                        "log": event.raw_log[:100],
                        "reason": "No rule matched this variant",
                    })

        # ── PROBE 2 — Test evasion variants ───────────
        evasion_attempts = [
            "FAILED PASSWORD for root",           # uppercase evasion
            "f a i l e d   p a s s w o r d",     # spacing evasion
            "SELECT/**/username/**/FROM/**/users", # SQL comment evasion
            "<ScRiPt>alert(1)</sCrIpT>",          # XSS case evasion
        ]

        for attempt in evasion_attempts:
            result = rule_engine.check(attempt)
            total_probes += 1
            if result.matched:
                rules_triggered += 1
            else:
                missed_attacks.append({
                    "attack_type": "evasion_attempt",
                    "log": attempt,
                    "reason": "Evasion technique bypassed detection",
                })

        # ── GENERATE RECOMMENDATIONS ──────────────────
        recommendations = self._generate_recommendations(
            missed_attacks, total_probes, rules_triggered
        )

        # ── CALCULATE NEW SECURITY SCORE ──────────────
        detection_rate = rules_triggered / total_probes if total_probes > 0 else 0
        score_after = self._calculate_score(
            security_score, detection_rate, len(missed_attacks)
        )

        completed_at = datetime.utcnow()
        weaknesses_found = len(missed_attacks)

        result = ProbeResult(
            started_at=started_at,
            completed_at=completed_at,
            total_probes=total_probes,
            weaknesses_found=weaknesses_found,
            rules_triggered=rules_triggered,
            missed_attacks=missed_attacks,
            recommendations=recommendations,
            security_score_before=security_score,
            security_score_after=score_after,
        )

        self.probe_history.append(result)
        self.last_run = completed_at

        duration = (completed_at - started_at).seconds

        log.info(
            "night_probe_complete",
            total_probes=total_probes,
            rules_triggered=rules_triggered,
            weaknesses_found=weaknesses_found,
            score_before=security_score,
            score_after=score_after,
            duration_seconds=duration,
        )

        return result

    def _generate_recommendations(
        self,
        missed_attacks: list,
        total_probes: int,
        rules_triggered: int,
    ) -> list:
        """Generate actionable hardening recommendations"""
        recommendations = []
        detection_rate = rules_triggered / total_probes if total_probes > 0 else 0

        if detection_rate < 0.7:
            recommendations.append(
                "CRITICAL: Detection rate below 70% — add more rules immediately"
            )

        if detection_rate < 0.85:
            recommendations.append(
                "WARNING: Detection rate below 85% — review missed attack patterns"
            )

        # Check for missed attack types
        missed_types = set(m["attack_type"] for m in missed_attacks)

        if "evasion_attempt" in missed_types:
            recommendations.append(
                "Add case-insensitive matching to detection rules"
            )

        if "sql_injection" in missed_types:
            recommendations.append(
                "Strengthen SQL injection patterns — comment and encoding evasion detected"
            )

        if "ssh_brute_force" in missed_types:
            recommendations.append(
                "SSH brute force variants bypassing detection — add more patterns"
            )

        if not recommendations:
            recommendations.append(
                "Detection coverage is strong — no critical gaps found"
            )

        return recommendations

    def _calculate_score(
        self,
        current_score: float,
        detection_rate: float,
        weaknesses: int,
    ) -> float:
        """Calculate new security posture score"""
        # Base score from detection rate
        base = detection_rate * 100

        # Penalty for weaknesses
        penalty = weaknesses * 2

        # Blend with current score
        new_score = (base * 0.6) + (current_score * 0.4) - penalty

        return round(max(0.0, min(100.0, new_score)), 1)

    def get_last_report(self) -> dict:
        """Get the most recent probe report"""
        if not self.probe_history:
            return {"status": "no_probe_run_yet"}

        last = self.probe_history[-1]
        duration = (last.completed_at - last.started_at).seconds

        return {
            "ran_at": last.started_at.isoformat(),
            "duration_seconds": duration,
            "total_probes": last.total_probes,
            "rules_triggered": last.rules_triggered,
            "weaknesses_found": last.weaknesses_found,
            "detection_rate": round(
                last.rules_triggered / last.total_probes, 3
            ) if last.total_probes > 0 else 0,
            "security_score_before": last.security_score_before,
            "security_score_after": last.security_score_after,
            "recommendations": last.recommendations,
            "missed_attacks": last.missed_attacks,
        }


# ── GLOBAL INSTANCE ───────────────────────────────────
night_probe = NightProbe()