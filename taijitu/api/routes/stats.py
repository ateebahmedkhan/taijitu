# taijitu/api/routes/stats.py
# Live statistics endpoints
# Powers Grafana dashboard and attack map

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from taijitu.storage.database import get_db
from taijitu.storage.models import ThreatEvent, AttackerProfile, SystemHealth
from taijitu.detection.rule_engine import rule_engine
from taijitu.autonomy.hardening import hardening_engine
from taijitu.autonomy.night_probe import night_probe

import structlog
log = structlog.get_logger()

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/overview")
async def get_overview(db: Session = Depends(get_db)):
    """
    Main dashboard overview
    Called every 30 seconds by Grafana
    """
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_1h = now - timedelta(hours=1)

    # Event counts
    total_events = db.query(ThreatEvent).count()
    events_24h = db.query(ThreatEvent).filter(
        ThreatEvent.timestamp >= last_24h
    ).count()
    events_1h = db.query(ThreatEvent).filter(
        ThreatEvent.timestamp >= last_1h
    ).count()

    # Severity breakdown
    critical = db.query(ThreatEvent).filter(
        ThreatEvent.severity == "critical",
        ThreatEvent.timestamp >= last_24h,
    ).count()
    high = db.query(ThreatEvent).filter(
        ThreatEvent.severity == "high",
        ThreatEvent.timestamp >= last_24h,
    ).count()

    # Attacker counts
    total_attackers = db.query(AttackerProfile).count()
    blocked_attackers = db.query(AttackerProfile).filter(
        AttackerProfile.is_blocked == True
    ).count()

    # Rule engine stats
    rule_stats = rule_engine.get_stats()

    # Night probe
    probe_report = night_probe.get_last_report()
    security_score = probe_report.get(
        "security_score_after", 50.0
    ) if probe_report.get("status") != "no_probe_run_yet" else 50.0

    return {
        "timestamp": now.isoformat(),
        "events": {
            "total": total_events,
            "last_24h": events_24h,
            "last_1h": events_1h,
        },
        "severity": {
            "critical_24h": critical,
            "high_24h": high,
        },
        "attackers": {
            "total_known": total_attackers,
            "currently_blocked": blocked_attackers,
            "in_memory": len(hardening_engine.get_blocked_ips()),
        },
        "detection": {
            "total_rules": rule_stats["total_rules"],
            "tactics_covered": rule_stats["tactics_covered"],
        },
        "security_score": security_score,
        "status": "operational",
    }


@router.get("/timeline")
async def get_timeline(
    hours: int = 24,
    db: Session = Depends(get_db),
):
    """
    Event timeline for Grafana time series chart
    Returns event counts per hour
    """
    now = datetime.utcnow()
    since = now - timedelta(hours=hours)

    events = db.query(ThreatEvent).filter(
        ThreatEvent.timestamp >= since
    ).all()

    # Group by hour
    timeline = {}
    for event in events:
        hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
        if hour_key not in timeline:
            timeline[hour_key] = {
                "hour": hour_key,
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
        timeline[hour_key]["total"] += 1
        severity = event.severity or "low"
        if severity in timeline[hour_key]:
            timeline[hour_key][severity] += 1

    return {
        "hours": hours,
        "data_points": len(timeline),
        "timeline": sorted(timeline.values(), key=lambda x: x["hour"]),
    }


@router.get("/tactics")
async def get_tactics(db: Session = Depends(get_db)):
    """
    MITRE ATT&CK tactic breakdown
    Powers the tactics chart in Grafana
    """
    events = db.query(ThreatEvent).filter(
        ThreatEvent.mitre_tactic.isnot(None)
    ).all()

    tactics = {}
    for event in events:
        tactic = event.mitre_tactic or "Unknown"
        tactics[tactic] = tactics.get(tactic, 0) + 1

    return {
        "total_events_with_tactic": len(events),
        "tactics": [
            {"tactic": k, "count": v}
            for k, v in sorted(
                tactics.items(),
                key=lambda x: x[1],
                reverse=True,
            )
        ],
    }


@router.get("/top-attackers")
async def get_top_attackers(
    limit: int = 10,
    db: Session = Depends(get_db),
):
    """Top attackers by threat score for leaderboard"""
    attackers = db.query(AttackerProfile).order_by(
        AttackerProfile.threat_score.desc()
    ).limit(limit).all()

    return {
        "count": len(attackers),
        "attackers": [
            {
                "rank": i + 1,
                "ip": a.ip_address,
                "threat_score": round(a.threat_score, 1),
                "total_events": a.total_events,
                "is_blocked": a.is_blocked,
                "days_tracked": (
                    datetime.utcnow() - a.first_seen
                ).days,
            }
            for i, a in enumerate(attackers)
        ],
    }


@router.get("/night-probe")
async def get_night_probe():
    """Latest night probe report"""
    return night_probe.get_last_report()


@router.get("/blocked-ips")
async def get_blocked_ips():
    """Currently blocked IPs"""
    blocked = hardening_engine.get_blocked_ips()
    return {
        "count": len(blocked),
        "ips": blocked,
    }