# tests/conftest.py
# Pytest configuration and shared fixtures

import pytest
from datetime import datetime


@pytest.fixture
def sample_event():
    """Sample threat event for testing"""
    return {
        "source_ip": "185.220.101.45",
        "event_type": "ssh_brute_force",
        "raw_log": "Failed password for root from 185.220.101.45 port 22 ssh2",
        "destination_port": 22,
        "source_port": 54321,
        "timestamp": datetime.utcnow(),
        "log_source": "system",
        "severity": "high",
    }


@pytest.fixture
def sample_attacker_history():
    """Sample attacker history for testing"""
    return {
        "known": True,
        "first_seen": "2026-01-15",
        "total_events": 47,
        "threat_score": 72.0,
        "tactics_used": ["Initial Access", "Reconnaissance"],
        "attack_types": ["ssh_brute_force", "port_scan"],
        "assessment": "HIGH THREAT",
    }