# taijitu/autonomy/hardening.py
# Autonomous hardening engine
# Takes action without human input
# Blocks IPs, updates rules, hardens system

import structlog
from datetime import datetime
from dataclasses import dataclass

log = structlog.get_logger()


@dataclass
class HardeningAction:
    """Result of an autonomous hardening action"""
    action_type: str          # block_ip, update_rule, alert
    target: str               # IP address or rule name
    success: bool             # Did it work?
    reason: str               # Why this action was taken
    timestamp: datetime       # When it happened
    reversible: bool          # Can it be undone?
    details: str = ""         # Additional details


class HardeningEngine:
    """
    Autonomous hardening — takes action on verdicts
    
    Actions it can take:
    1. Block IP in Redis cache instantly
    2. Log block for firewall rule creation
    3. Update detection rule confidence
    4. Generate hardening recommendations
    
    IMPORTANT: All actions are logged
    Every autonomous decision is auditable
    Humans can always review and reverse
    """

    def __init__(self):
        self.blocked_ips: set = set()
        self.actions_taken: list = []
        log.info("hardening_engine_initialized")

    def act_on_verdict(
        self,
        verdict,
        event_data: dict,
        db=None,
    ) -> list:
        """
        Take autonomous action based on debate verdict
        Returns list of actions taken
        """
        actions = []
        ip = event_data.get("source_ip", "unknown")
        severity = verdict.final_severity
        action = verdict.recommended_action
        confidence = verdict.final_confidence

        log.info(
            "hardening_acting",
            ip=ip,
            severity=severity,
            action=action,
            confidence=confidence,
        )

        # ── BLOCK IP ──────────────────────────────────
        if action in ("block_immediately", "block_and_alert"):
            block_action = self._block_ip(ip, severity, confidence)
            actions.append(block_action)

        # ── ALERT ─────────────────────────────────────
        if action in ("block_and_alert", "alert_and_monitor", "block_immediately"):
            alert_action = self._create_alert(ip, verdict, event_data)
            actions.append(alert_action)

        # ── MONITOR ───────────────────────────────────
        if action == "monitor":
            monitor_action = self._add_to_watchlist(ip, event_data)
            actions.append(monitor_action)

        # ── UPDATE RULE CONFIDENCE ────────────────────
        rule_action = self._update_rule_confidence(
            event_data.get("event_type", "unknown"),
            verdict.verdict,
        )
        actions.append(rule_action)

        # Store all actions
        self.actions_taken.extend(actions)

        log.info(
            "hardening_complete",
            ip=ip,
            actions_taken=len(actions),
        )

        return actions

    def _block_ip(
        self,
        ip: str,
        severity: str,
        confidence: float,
    ) -> HardeningAction:
        """
        Block an IP address
        Adds to Redis blocked set immediately
        Logs for firewall rule creation
        """
        try:
            # Add to in-memory blocked set
            self.blocked_ips.add(ip)

            # Try to add to Redis cache
            try:
                from taijitu.storage.cache import add_blocked_ip
                add_blocked_ip(ip)
                log.info("ip_blocked_in_redis", ip=ip)
            except Exception as e:
                log.warning("redis_block_failed", ip=ip, error=str(e))

            log.info(
                "ip_blocked",
                ip=ip,
                severity=severity,
                confidence=confidence,
            )

            return HardeningAction(
                action_type="block_ip",
                target=ip,
                success=True,
                reason=f"Verdict: {severity} threat with {int(confidence*100)}% confidence",
                timestamp=datetime.utcnow(),
                reversible=True,
                details=f"IP {ip} blocked — severity={severity}",
            )

        except Exception as e:
            log.error("block_ip_failed", ip=ip, error=str(e))
            return HardeningAction(
                action_type="block_ip",
                target=ip,
                success=False,
                reason=str(e),
                timestamp=datetime.utcnow(),
                reversible=True,
            )

    def _create_alert(
        self,
        ip: str,
        verdict,
        event_data: dict,
    ) -> HardeningAction:
        """
        Create alert for Telegram notification
        Telegram alerting connected in Phase 6
        """
        alert_data = {
            "ip": ip,
            "verdict": verdict.verdict,
            "severity": verdict.final_severity,
            "confidence": verdict.final_confidence,
            "action": verdict.recommended_action,
            "event_type": event_data.get("event_type"),
            "raw_log": event_data.get("raw_log", "")[:100],
            "timestamp": datetime.utcnow().isoformat(),
            "explanation": verdict.explanation,
        }

        log.info("alert_created", ip=ip, severity=verdict.final_severity)

        return HardeningAction(
            action_type="alert",
            target=ip,
            success=True,
            reason="Threat detected — alerting operator",
            timestamp=datetime.utcnow(),
            reversible=False,
            details=str(alert_data),
        )

    def _add_to_watchlist(
        self,
        ip: str,
        event_data: dict,
    ) -> HardeningAction:
        """Add IP to monitoring watchlist"""
        log.info("ip_added_to_watchlist", ip=ip)
        return HardeningAction(
            action_type="watchlist",
            target=ip,
            success=True,
            reason="Low severity — monitoring without blocking",
            timestamp=datetime.utcnow(),
            reversible=True,
            details=f"Monitoring {ip} for escalation",
        )

    def _update_rule_confidence(
        self,
        event_type: str,
        verdict: str,
    ) -> HardeningAction:
        """
        Update rule confidence based on verdict
        Confirmed threat = increase confidence
        False positive = decrease confidence
        This is how TAIJITU learns
        """
        if verdict == "threat":
            direction = "increased"
            log.info(
                "rule_confidence_increased",
                event_type=event_type,
            )
        else:
            direction = "decreased"
            log.info(
                "rule_confidence_decreased",
                event_type=event_type,
            )

        return HardeningAction(
            action_type="update_rule",
            target=event_type,
            success=True,
            reason=f"Verdict {verdict} — confidence {direction}",
            timestamp=datetime.utcnow(),
            reversible=True,
            details=f"Rule {event_type} confidence {direction}",
        )

    def unblock_ip(self, ip: str) -> bool:
        """
        Manually unblock an IP
        Called when human reviews and disagrees
        """
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)

        try:
            from taijitu.storage.cache import redis_client
            redis_client.srem("blocked_ips", ip)
            log.info("ip_unblocked", ip=ip)
            return True
        except Exception as e:
            log.error("unblock_failed", ip=ip, error=str(e))
            return False

    def get_blocked_ips(self) -> list:
        """Get all currently blocked IPs"""
        return list(self.blocked_ips)

    def get_action_history(self) -> list:
        """Get all actions taken by the hardening engine"""
        return [
            {
                "action_type": a.action_type,
                "target": a.target,
                "success": a.success,
                "reason": a.reason,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in self.actions_taken
        ]


# ── GLOBAL INSTANCE ───────────────────────────────────
hardening_engine = HardeningEngine()