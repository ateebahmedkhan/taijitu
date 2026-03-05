# tests/test_detection.py
# Core detection pipeline tests
# Verifies TAIJITU detects real attacks correctly

import pytest
from datetime import datetime
from taijitu.detection.rule_engine import RuleEngine
from taijitu.detection.correlator import Correlator
from taijitu.memory.threat_dna import ThreatDNA


# ── RULE ENGINE TESTS ─────────────────────────────────

class TestRuleEngine:

    def setup_method(self):
        self.engine = RuleEngine()

    def test_detects_ssh_brute_force(self):
        result = self.engine.check(
            "Failed password for root from 185.220.101.45 port 22 ssh2"
        )
        assert result.matched is True
        assert result.rule_name == "ssh_brute_force"
        assert result.severity == "high"

    def test_detects_sql_injection(self):
        result = self.engine.check(
            "GET /login?id=1 UNION SELECT username,password FROM users--"
        )
        assert result.matched is True
        assert result.rule_name == "sql_injection"
        assert result.severity == "critical"

    def test_ignores_normal_traffic(self):
        result = self.engine.check(
            "User admin logged in successfully from 192.168.1.1"
        )
        assert result.matched is False
        assert result.severity == "low"

    def test_detects_ransomware(self):
        result = self.engine.check(
            "ransomware activity YOUR FILES ARE ENCRYPTED"
        )
        assert result.matched is True
        assert result.severity == "critical"

    def test_rule_count(self):
        stats = self.engine.get_stats()
        assert stats["total_rules"] >= 15
        assert stats["tactics_covered"] >= 8


# ── CORRELATOR TESTS ──────────────────────────────────

class TestCorrelator:

    def setup_method(self):
        self.correlator = Correlator(window_minutes=60)

    def test_single_event_no_upgrade(self):
        result = self.correlator.correlate({
            "source_ip": "10.0.0.1",
            "event_type": "ssh_brute_force",
            "severity": "high",
            "timestamp": datetime.utcnow(),
        })
        assert result.final_severity == "high"
        assert result.severity_upgraded is False

    def test_brute_force_upgrades_to_critical(self):
        ip = "192.168.99.99"
        for _ in range(5):
            result = self.correlator.correlate({
                "source_ip": ip,
                "event_type": "ssh_brute_force",
                "severity": "high",
                "timestamp": datetime.utcnow(),
            })
        assert result.final_severity == "critical"
        assert result.severity_upgraded is True
        assert result.pattern_detected == "brute_force_detected"

    def test_kill_chain_detected(self):
        ip = "192.168.88.88"
        self.correlator.correlate({
            "source_ip": ip,
            "event_type": "port_scan",
            "severity": "medium",
            "timestamp": datetime.utcnow(),
        })
        result = self.correlator.correlate({
            "source_ip": ip,
            "event_type": "sql_injection",
            "severity": "critical",
            "timestamp": datetime.utcnow(),
        })
        assert result.pattern_detected == "kill_chain_detected"
        assert result.final_severity == "critical"


# ── THREAT DNA TESTS ──────────────────────────────────

class TestThreatDNA:

    def setup_method(self):
        self.dna = ThreatDNA()

    def test_same_behavior_same_dna(self):
        profile1 = {
            "event_types": ["ssh_brute_force", "port_scan"],
            "tactics_used": ["Initial Access"],
            "target_ports": [22, 80],
        }
        profile2 = {
            "event_types": ["ssh_brute_force", "port_scan"],
            "tactics_used": ["Initial Access"],
            "target_ports": [22, 80],
        }
        dna1 = self.dna.generate_dna(profile1)
        dna2 = self.dna.generate_dna(profile2)
        assert dna1 == dna2

    def test_different_behavior_different_dna(self):
        profile1 = {
            "event_types": ["ssh_brute_force"],
            "tactics_used": ["Initial Access"],
            "target_ports": [22],
        }
        profile2 = {
            "event_types": ["ransomware_activity"],
            "tactics_used": ["Impact"],
            "target_ports": [445],
        }
        dna1 = self.dna.generate_dna(profile1)
        dna2 = self.dna.generate_dna(profile2)
        assert dna1 != dna2

    def test_attacker_type_classification(self):
        profile = {
            "event_types": ["ransomware_activity"],
            "tactics_used": ["Impact"],
            "target_ports": [445],
        }
        analysis = self.dna.analyze(profile)
        assert analysis["attacker_type"] == "ransomware_operator"