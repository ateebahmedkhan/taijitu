# taijitu/detection/correlator.py
# Event correlation engine
# Groups related events together
# Upgrades severity when patterns connect
# Same IP attacking multiple times = escalation

import structlog
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict

log = structlog.get_logger()


@dataclass
class CorrelationResult:
    """Result after correlating an event with history"""
    original_severity: str
    final_severity: str
    severity_upgraded: bool
    event_count: int          # How many events from this IP
    unique_attack_types: int  # How many different attack types
    time_window_minutes: int  # Over what time period
    pattern_detected: str     # What pattern was found
    recommendation: str       # What to do


@dataclass
class IPHistory:
    """Tracks event history per IP address"""
    ip: str
    events: list = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)


# Severity levels for upgrading
SEVERITY_LEVELS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_NAMES = {v: k for k, v in SEVERITY_LEVELS.items()}


class Correlator:
    """
    Correlates events across time and IPs
    
    What it detects:
    - Same IP attacking multiple times (brute force)
    - Same IP using multiple attack types (advanced attacker)
    - Rapid succession attacks (automated tools)
    - Port scanning followed by exploitation (kill chain)
    """

    def __init__(self, window_minutes: int = 60):
        # How far back to look for related events
        self.window_minutes = window_minutes
        # In-memory history per IP
        self.ip_history: dict[str, IPHistory] = defaultdict(
            lambda: IPHistory(ip="unknown")
        )
        log.info("correlator_initialized", window_minutes=window_minutes)

    def correlate(self, event: dict) -> CorrelationResult:
        """
        Correlate incoming event with history
        Returns upgraded severity if pattern detected
        """
        ip = event.get("source_ip", "unknown")
        event_type = event.get("event_type", "unknown")
        severity = event.get("severity", "low")
        timestamp = event.get("timestamp", datetime.utcnow())

        # Get or create history for this IP
        history = self.ip_history[ip]
        history.ip = ip
        history.last_seen = timestamp

        # Add current event to history
        history.events.append({
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": severity,
        })

        # Only look at events within the time window
        cutoff = datetime.utcnow() - timedelta(minutes=self.window_minutes)
        recent_events = [
            e for e in history.events
            if e["timestamp"] >= cutoff
        ]

        # Update history with only recent events
        history.events = recent_events

        # Analyze patterns
        event_count = len(recent_events)
        unique_types = len(set(e["event_type"] for e in recent_events))
        original_severity = severity

        # ── PATTERN DETECTION ─────────────────────────
        pattern = "single_event"
        final_severity = severity
        recommendation = "monitor"

        # Pattern 1 — Brute force (same type 5+ times)
        same_type_count = sum(
            1 for e in recent_events
            if e["event_type"] == event_type
        )
        if same_type_count >= 5:
            pattern = "brute_force_detected"
            final_severity = self._upgrade_severity(severity, levels=1)
            recommendation = "block_ip"
            log.info(
                "pattern_brute_force",
                ip=ip,
                count=same_type_count,
                severity=final_severity,
            )

        # Pattern 2 — Multi-vector attack (3+ different attack types)
        if unique_types >= 3:
            pattern = "multi_vector_attack"
            final_severity = self._upgrade_severity(severity, levels=2)
            recommendation = "block_ip_and_alert"
            log.info(
                "pattern_multi_vector",
                ip=ip,
                unique_types=unique_types,
                severity=final_severity,
            )

        # Pattern 3 — Rapid succession (10+ events in window)
        if event_count >= 10:
            pattern = "rapid_succession_attack"
            final_severity = self._upgrade_severity(severity, levels=1)
            recommendation = "block_ip"
            log.info(
                "pattern_rapid_succession",
                ip=ip,
                event_count=event_count,
                severity=final_severity,
            )

        # Pattern 4 — Kill chain (recon followed by exploitation)
        event_types_seen = [e["event_type"] for e in recent_events]
        has_recon = "port_scan" in event_types_seen
        has_exploit = any(t in event_types_seen for t in [
            "sql_injection", "xss_attempt",
            "command_injection", "ssh_brute_force"
        ])
        if has_recon and has_exploit:
            pattern = "kill_chain_detected"
            final_severity = "critical"
            recommendation = "block_ip_immediately_and_alert"
            log.info(
                "pattern_kill_chain",
                ip=ip,
                severity=final_severity,
            )

        severity_upgraded = final_severity != original_severity

        if severity_upgraded:
            log.info(
                "severity_upgraded",
                ip=ip,
                from_severity=original_severity,
                to_severity=final_severity,
                pattern=pattern,
            )

        return CorrelationResult(
            original_severity=original_severity,
            final_severity=final_severity,
            severity_upgraded=severity_upgraded,
            event_count=event_count,
            unique_attack_types=unique_types,
            time_window_minutes=self.window_minutes,
            pattern_detected=pattern,
            recommendation=recommendation,
        )

    def _upgrade_severity(self, current: str, levels: int = 1) -> str:
        """
        Upgrade severity by N levels
        low -> medium -> high -> critical
        Cannot go above critical
        """
        current_level = SEVERITY_LEVELS.get(current, 1)
        new_level = min(current_level + levels, 4)
        return SEVERITY_NAMES[new_level]

    def get_ip_summary(self, ip: str) -> dict:
        """Get summary of all activity from an IP"""
        if ip not in self.ip_history:
            return {"ip": ip, "known": False}

        history = self.ip_history[ip]
        event_types = [e["event_type"] for e in history.events]

        return {
            "ip": ip,
            "known": True,
            "total_events": len(history.events),
            "first_seen": history.first_seen,
            "last_seen": history.last_seen,
            "attack_types": list(set(event_types)),
            "unique_attack_types": len(set(event_types)),
        }

    def clear_old_history(self) -> None:
        """Remove IPs with no recent activity"""
        cutoff = datetime.utcnow() - timedelta(minutes=self.window_minutes)
        inactive = [
            ip for ip, h in self.ip_history.items()
            if h.last_seen < cutoff
        ]
        for ip in inactive:
            del self.ip_history[ip]
        if inactive:
            log.info("cleared_inactive_ips", count=len(inactive))


# ── GLOBAL INSTANCE ───────────────────────────────────
correlator = Correlator(window_minutes=60)