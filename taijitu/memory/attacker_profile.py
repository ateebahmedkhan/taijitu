# taijitu/memory/attacker_profile.py
# Persistent attacker memory
# Every IP TAIJITU has ever seen is stored here forever
# This is what makes TAIJITU remember across restarts

import structlog
from datetime import datetime
from sqlalchemy.orm import Session

from taijitu.storage.models import AttackerProfile
from taijitu.storage.cache import (
    get_attacker_profile,
    set_attacker_profile,
    delete_attacker_profile,
)

log = structlog.get_logger()


class AttackerMemory:
    """
    Manages persistent memory of every attacker
    
    Flow:
    1. Event arrives from IP X
    2. Check Redis cache for IP X profile
    3. If not in cache — check PostgreSQL
    4. If not in database — create new profile
    5. Update profile with new event data
    6. Save back to PostgreSQL and Redis
    
    Result: Every attacker remembered forever
    Even after restart — profile is in PostgreSQL
    """

    def get_or_create(self, db: Session, ip: str) -> AttackerProfile:
        """
        Get existing profile or create new one
        Checks cache first then database
        """
        # Check cache first — fastest path
        cached = get_attacker_profile(ip)
        if cached:
            log.info("profile_from_cache", ip=ip)
            # Still need DB object for updates
            profile = db.query(AttackerProfile).filter(
                AttackerProfile.ip_address == ip
            ).first()
            if profile:
                return profile

        # Check database
        profile = db.query(AttackerProfile).filter(
            AttackerProfile.ip_address == ip
        ).first()

        if profile:
            log.info("profile_from_database", ip=ip, events=profile.total_events)
            # Update cache
            self._cache_profile(profile)
            return profile

        # Create new profile
        profile = AttackerProfile(
            ip_address=ip,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            total_events=0,
            total_blocked=0,
            tactics_used=[],
            techniques_used=[],
            target_ports=[],
            event_types=[],
            threat_score=0.0,
            is_blocked=False,
            block_count=0,
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)

        log.info("profile_created", ip=ip)
        return profile

    def update(
        self,
        db: Session,
        ip: str,
        event_type: str,
        severity: str,
        mitre_tactic: str,
        mitre_technique: str,
        destination_port: int,
        anomaly_score: float,
    ) -> AttackerProfile:
        """
        Update attacker profile with new event data
        Called every time a threat is detected from this IP
        """
        profile = self.get_or_create(db, ip)

        # Update timestamps
        profile.last_seen = datetime.utcnow()
        profile.total_events += 1

        # Update tactics list — no duplicates
        tactics = profile.tactics_used or []
        if mitre_tactic and mitre_tactic not in tactics:
            tactics.append(mitre_tactic)
        profile.tactics_used = tactics

        # Update techniques list — no duplicates
        techniques = profile.techniques_used or []
        if mitre_technique and mitre_technique not in techniques:
            techniques.append(mitre_technique)
        profile.techniques_used = techniques

        # Update target ports — no duplicates
        ports = profile.target_ports or []
        if destination_port and destination_port not in ports:
            ports.append(destination_port)
        profile.target_ports = ports

        # Update event types — no duplicates
        types = profile.event_types or []
        if event_type and event_type not in types:
            types.append(event_type)
        profile.event_types = types

        # Update threat score
        profile.threat_score = self._calculate_threat_score(
            profile, severity, anomaly_score
        )

        # Save to database
        db.commit()
        db.refresh(profile)

        # Update cache
        self._cache_profile(profile)

        log.info(
            "profile_updated",
            ip=ip,
            total_events=profile.total_events,
            threat_score=round(profile.threat_score, 1),
            tactics=len(profile.tactics_used),
        )

        return profile

    def mark_blocked(self, db: Session, ip: str) -> AttackerProfile:
        """Mark an IP as blocked"""
        profile = self.get_or_create(db, ip)
        profile.is_blocked = True
        profile.block_count += 1
        profile.total_blocked += 1
        db.commit()
        db.refresh(profile)

        # Invalidate cache
        delete_attacker_profile(ip)
        self._cache_profile(profile)

        log.info(
            "attacker_blocked",
            ip=ip,
            block_count=profile.block_count,
            threat_score=profile.threat_score,
        )
        return profile

    def get_summary(self, db: Session, ip: str) -> dict:
        """
        Get a complete summary of an attacker
        Used by Guardian mind before debate
        """
        profile = db.query(AttackerProfile).filter(
            AttackerProfile.ip_address == ip
        ).first()

        if not profile:
            return {
                "ip": ip,
                "known": False,
                "message": "First time seen — no history available",
            }

        # Calculate days since first seen
        days_known = (datetime.utcnow() - profile.first_seen).days

        return {
            "ip": ip,
            "known": True,
            "first_seen": profile.first_seen.isoformat(),
            "last_seen": profile.last_seen.isoformat(),
            "days_tracked": days_known,
            "total_events": profile.total_events,
            "total_blocked": profile.total_blocked,
            "is_currently_blocked": profile.is_blocked,
            "threat_score": round(profile.threat_score, 1),
            "tactics_used": profile.tactics_used or [],
            "techniques_used": profile.techniques_used or [],
            "target_ports": profile.target_ports or [],
            "attack_types": profile.event_types or [],
            "assessment": self._threat_assessment(profile.threat_score),
        }

    def _calculate_threat_score(
        self,
        profile: AttackerProfile,
        new_severity: str,
        anomaly_score: float,
    ) -> float:
        """
        Calculate overall threat score 0-100
        Based on history, severity, and anomaly score
        """
        score = profile.threat_score

        # Add points based on severity
        severity_points = {
            "low": 2,
            "medium": 5,
            "high": 10,
            "critical": 20,
        }
        score += severity_points.get(new_severity, 2)

        # Add points for anomaly score
        score += anomaly_score * 10

        # Add points for diversity of tactics
        tactic_count = len(profile.tactics_used or [])
        score += tactic_count * 3

        # Cap at 100
        return min(score, 100.0)

    def _threat_assessment(self, score: float) -> str:
        """Convert threat score to plain English assessment"""
        if score >= 80:
            return "CRITICAL THREAT — Known highly active attacker"
        elif score >= 60:
            return "HIGH THREAT — Persistent attacker with multiple tactics"
        elif score >= 40:
            return "MEDIUM THREAT — Repeat offender showing pattern"
        elif score >= 20:
            return "LOW THREAT — Early stage activity"
        else:
            return "MINIMAL THREAT — New or infrequent activity"

    def _cache_profile(self, profile: AttackerProfile) -> None:
        """Save profile to Redis cache"""
        set_attacker_profile(profile.ip_address, {
            "ip": profile.ip_address,
            "threat_score": profile.threat_score,
            "total_events": profile.total_events,
            "is_blocked": profile.is_blocked,
            "tactics_used": profile.tactics_used,
            "last_seen": profile.last_seen.isoformat(),
        })


# ── GLOBAL INSTANCE ───────────────────────────────────
attacker_memory = AttackerMemory()