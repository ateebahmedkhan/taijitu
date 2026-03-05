# taijitu/api/routes/events.py
# Threat event API endpoints
# Powers the live dashboard and external integrations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from pydantic import BaseModel

from taijitu.storage.database import get_db
from taijitu.storage.models import ThreatEvent, AttackerProfile
from taijitu.detection.rule_engine import rule_engine
from taijitu.detection.correlator import correlator
from taijitu.detection.anomaly_detector import anomaly_detector
from taijitu.memory.attacker_profile import attacker_memory
from taijitu.memory.threat_dna import threat_dna

import structlog
log = structlog.get_logger()

router = APIRouter(prefix="/events", tags=["events"])


# ── REQUEST MODELS ────────────────────────────────────

class IngestEventRequest(BaseModel):
    source_ip: str
    raw_log: str
    log_source: str = "api"
    destination_port: int = 0
    source_port: int = 0
    event_type: str = "unknown"


class HumanFeedbackRequest(BaseModel):
    event_id: int
    verdict: str       # threat / false_positive
    notes: str = ""


# ── ENDPOINTS ─────────────────────────────────────────

@router.post("/ingest")
async def ingest_event(
    request: IngestEventRequest,
    db: Session = Depends(get_db),
):
    """
    Ingest a raw log event into TAIJITU
    Runs through full detection pipeline
    Returns verdict immediately
    """
    log.info("event_ingested", ip=request.source_ip)

    event_dict = {
        "source_ip": request.source_ip,
        "raw_log": request.raw_log,
        "log_source": request.log_source,
        "destination_port": request.destination_port,
        "source_port": request.source_port,
        "event_type": request.event_type,
        "timestamp": datetime.utcnow(),
    }

    # Stage 1 — Rule engine
    rule_result = rule_engine.check(request.raw_log)

    # Stage 2 — Anomaly detector
    if not anomaly_detector.is_trained:
        anomaly_detector.train()
    anomaly_result = anomaly_detector.score(event_dict)

    # Stage 3 — Correlator
    event_dict["severity"] = rule_result.severity
    correlation = correlator.correlate(event_dict)

    return {
        "status": "processed",
        "source_ip": request.source_ip,
        "rule_matched": rule_result.matched,
        "rule_name": rule_result.rule_name,
        "severity": correlation.final_severity,
        "anomaly_score": anomaly_result.anomaly_score,
        "pattern_detected": correlation.pattern_detected,
        "recommendation": correlation.recommendation,
        "mitre_technique": rule_result.mitre_technique,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/recent")
async def get_recent_events(
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Get most recent threat events"""
    events = db.query(ThreatEvent).order_by(
        ThreatEvent.timestamp.desc()
    ).limit(limit).all()

    return {
        "count": len(events),
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "source_ip": e.source_ip,
                "event_type": e.event_type,
                "severity": e.severity,
                "verdict": e.verdict,
                "action_taken": e.action_taken,
                "mitre_tactic": e.mitre_tactic,
            }
            for e in events
        ],
    }


@router.get("/attackers")
async def get_attackers(
    limit: int = 20,
    db: Session = Depends(get_db),
):
    """Get top attackers by threat score"""
    attackers = db.query(AttackerProfile).order_by(
        AttackerProfile.threat_score.desc()
    ).limit(limit).all()

    return {
        "count": len(attackers),
        "attackers": [
            {
                "ip": a.ip_address,
                "threat_score": round(a.threat_score, 1),
                "total_events": a.total_events,
                "is_blocked": a.is_blocked,
                "tactics_used": a.tactics_used,
                "last_seen": a.last_seen.isoformat(),
                "first_seen": a.first_seen.isoformat(),
            }
            for a in attackers
        ],
    }


@router.get("/attacker/{ip}")
async def get_attacker_profile(
    ip: str,
    db: Session = Depends(get_db),
):
    """Get full profile of a specific attacker IP"""
    summary = attacker_memory.get_summary(db, ip)
    if not summary.get("known"):
        raise HTTPException(status_code=404, detail=f"IP {ip} not found")

    # Generate DNA analysis
    profile = db.query(AttackerProfile).filter(
        AttackerProfile.ip_address == ip
    ).first()

    dna_analysis = {}
    if profile:
        profile_data = {
            "event_types": profile.event_types or [],
            "tactics_used": profile.tactics_used or [],
            "target_ports": profile.target_ports or [],
        }
        dna_analysis = threat_dna.analyze(profile_data)

    return {
        **summary,
        "dna": dna_analysis,
    }


@router.post("/feedback")
async def submit_feedback(
    request: HumanFeedbackRequest,
    db: Session = Depends(get_db),
):
    """
    Submit human feedback on a verdict
    Used to correct TAIJITU and improve accuracy
    """
    event = db.query(ThreatEvent).filter(
        ThreatEvent.id == request.event_id
    ).first()

    if not event:
        raise HTTPException(
            status_code=404,
            detail=f"Event {request.event_id} not found"
        )

    event.human_verdict = request.verdict
    db.commit()

    log.info(
        "human_feedback_received",
        event_id=request.event_id,
        verdict=request.verdict,
    )

    return {
        "status": "feedback_recorded",
        "event_id": request.event_id,
        "verdict": request.verdict,
    }