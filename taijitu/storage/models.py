# taijitu/storage/models.py
# Every database table TAIJITU uses
# Think of each class as one table in the database

from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float,
    DateTime, Text, Boolean, JSON
)
from sqlalchemy.orm import declarative_base

# Base class — all models inherit from this
Base = declarative_base()


class ThreatEvent(Base):
    """
    Every suspicious event detected by TAIJITU
    One row = one threat event
    """
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # When and where
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True)       # Attacker IP
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)

    # What happened
    event_type = Column(String(100), index=True)     # ssh_brute_force, port_scan etc
    raw_log = Column(Text, nullable=True)            # Original log line
    log_source = Column(String(50))                  # which source: system, network, wazuh

    # Detection results
    rule_matched = Column(String(200), nullable=True)  # Which rule fired
    anomaly_score = Column(Float, default=0.0)          # Isolation Forest score 0-1
    mitre_tactic = Column(String(100), nullable=True)   # MITRE ATT&CK tactic
    mitre_technique = Column(String(100), nullable=True) # MITRE ATT&CK technique

    # Severity
    severity = Column(String(20), default="low")     # low, medium, high, critical
    confidence = Column(Float, default=0.0)          # How confident 0-1

    # Debate results
    debate_id = Column(Integer, nullable=True)       # Links to DebateTranscript
    verdict = Column(String(20), nullable=True)      # threat, false_positive, unknown
    guardian_summary = Column(Text, nullable=True)   # Guardian's final position
    adversary_summary = Column(Text, nullable=True)  # Adversary's final position

    # Actions taken
    action_taken = Column(String(100), nullable=True) # blocked, alerted, ignored
    auto_blocked = Column(Boolean, default=False)

    # Human feedback
    human_verdict = Column(String(20), nullable=True) # confirmed, false_positive
    feedback_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<ThreatEvent {self.event_type} from {self.source_ip} severity={self.severity}>"


class AttackerProfile(Base):
    """
    Persistent memory of every attacker TAIJITU has seen
    One row = one unique IP address
    This is TAIJITU's long-term memory
    """
    __tablename__ = "attacker_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), unique=True, index=True)

    # History
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    total_events = Column(Integer, default=0)
    total_blocked = Column(Integer, default=0)

    # Behavior
    tactics_used = Column(JSON, default=list)        # List of MITRE tactics seen
    techniques_used = Column(JSON, default=list)     # List of MITRE techniques seen
    target_ports = Column(JSON, default=list)        # Ports they probe
    event_types = Column(JSON, default=list)         # Types of attacks attempted

    # Scoring
    threat_score = Column(Float, default=0.0)        # Overall danger score 0-100
    is_blocked = Column(Boolean, default=False)      # Currently blocked?
    block_count = Column(Integer, default=0)         # Times blocked

    # Behavioral DNA
    dna_hash = Column(String(64), nullable=True)     # Behavioral fingerprint
    dna_features = Column(JSON, nullable=True)       # Raw features for DNA

    # Geo
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    isp = Column(String(200), nullable=True)

    def __repr__(self):
        return f"<AttackerProfile {self.ip_address} score={self.threat_score} events={self.total_events}>"


class DebateTranscript(Base):
    """
    Full Guardian vs Adversary debate for every threat
    One row = one complete debate
    """
    __tablename__ = "debate_transcripts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, index=True)           # Links to ThreatEvent
    timestamp = Column(DateTime, default=datetime.utcnow)

    # The debate
    round_1_guardian = Column(Text, nullable=True)   # Guardian's opening analysis
    round_1_adversary = Column(Text, nullable=True)  # Adversary's opening analysis
    round_2_guardian = Column(Text, nullable=True)   # Guardian responds to Adversary
    round_2_adversary = Column(Text, nullable=True)  # Adversary escalates or concedes
    round_3_guardian = Column(Text, nullable=True)   # Final Guardian position
    round_3_adversary = Column(Text, nullable=True)  # Final Adversary position

    # Verdict
    final_severity = Column(String(20))              # low, medium, high, critical
    final_confidence = Column(Float)                 # 0.0 to 1.0
    final_verdict = Column(String(20))               # threat, false_positive, unknown
    recommended_action = Column(String(100))         # block, monitor, ignore

    # Metadata
    debate_rounds = Column(Integer, default=0)       # How many rounds happened
    duration_seconds = Column(Float, nullable=True)  # How long the debate took

    def __repr__(self):
        return f"<DebateTranscript event={self.event_id} verdict={self.final_verdict}>"


class DetectionRule(Base):
    """
    TAIJITU's rule engine — MITRE ATT&CK mapped signatures
    One row = one detection rule
    These grow automatically as TAIJITU learns
    """
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), unique=True)
    description = Column(Text, nullable=True)

    # Pattern
    pattern = Column(Text)                           # What to look for
    pattern_type = Column(String(50))                # regex, keyword, threshold

    # MITRE mapping
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(100), nullable=True)

    # Severity
    severity = Column(String(20), default="medium")
    confidence = Column(Float, default=0.8)

    # Status
    is_active = Column(Boolean, default=True)
    auto_generated = Column(Boolean, default=False)  # True if TAIJITU created it
    hit_count = Column(Integer, default=0)           # Times this rule fired

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<DetectionRule {self.name} severity={self.severity}>"


class SystemHealth(Base):
    """
    TAIJITU's own health metrics
    One row = one health snapshot
    """
    __tablename__ = "system_health"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Metrics
    events_processed = Column(Integer, default=0)
    debates_completed = Column(Integer, default=0)
    threats_detected = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    ips_blocked = Column(Integer, default=0)

    # Performance
    avg_debate_duration = Column(Float, nullable=True)
    events_per_minute = Column(Float, nullable=True)

    # Posture score
    security_posture_score = Column(Float, default=50.0)  # 0-100

    def __repr__(self):
        return f"<SystemHealth score={self.security_posture_score} at {self.timestamp}>"