# taijitu/detection/rule_engine.py
# MITRE ATT&CK mapped rule engine

import re
import structlog
from dataclasses import dataclass

log = structlog.get_logger()


@dataclass
class RuleMatch:
    matched: bool
    rule_name: str
    severity: str
    confidence: float
    mitre_tactic: str
    mitre_technique: str
    description: str


RULES = [
    {
        "name": "ssh_brute_force",
        "description": "Multiple failed SSH login attempts",
        "pattern_type": "keyword",
        "keywords": ["Failed password", "Invalid user", "authentication failure"],
        "severity": "high",
        "confidence": 0.90,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1110.001 - Brute Force: Password Guessing",
    },
    {
        "name": "ftp_brute_force",
        "description": "Multiple failed FTP login attempts",
        "pattern_type": "keyword",
        "keywords": ["FTP login failed", "530 Login incorrect"],
        "severity": "high",
        "confidence": 0.85,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1110.001 - Brute Force: Password Guessing",
    },
    {
        "name": "rdp_brute_force",
        "description": "Multiple failed RDP login attempts",
        "pattern_type": "keyword",
        "keywords": ["RDP login failed", "NLA authentication failed"],
        "severity": "high",
        "confidence": 0.85,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1110.001 - Brute Force: Password Guessing",
    },
    {
        "name": "port_scan_detected",
        "description": "Systematic port scanning activity",
        "pattern_type": "keyword",
        "keywords": ["port scan", "nmap", "masscan", "SYN scan"],
        "severity": "medium",
        "confidence": 0.80,
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1046 - Network Service Discovery",
    },
    {
        "name": "ping_sweep",
        "description": "ICMP ping sweep to discover live hosts",
        "pattern_type": "keyword",
        "keywords": ["ICMP echo", "ping sweep", "host discovery"],
        "severity": "low",
        "confidence": 0.70,
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1018 - Remote System Discovery",
    },
    {
        "name": "sql_injection",
        "description": "SQL injection attempt in web request",
        "pattern_type": "regex",
        "pattern": r"(union.*select|select.*from|drop.*table|or.*1=1|xp_cmdshell)",
        "severity": "critical",
        "confidence": 0.92,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
    },
    {
        "name": "xss_attempt",
        "description": "Cross-site scripting attempt",
        "pattern_type": "regex",
        "pattern": r"(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)",
        "severity": "high",
        "confidence": 0.88,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
    },
    {
        "name": "path_traversal",
        "description": "Directory traversal attempt",
        "pattern_type": "regex",
        "pattern": r"(\.\./|\.\.\\|%2e%2e%2f)",
        "severity": "high",
        "confidence": 0.85,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
    },
    {
        "name": "command_injection",
        "description": "Command injection attempt",
        "pattern_type": "regex",
        "pattern": r"(;.*whoami|\|.*cat|`.*`|\$\(.*\))",
        "severity": "critical",
        "confidence": 0.90,
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059 - Command and Scripting Interpreter",
    },
    {
        "name": "credential_dumping",
        "description": "Possible credential dumping activity",
        "pattern_type": "keyword",
        "keywords": ["mimikatz", "lsass", "hashdump", "SAM database"],
        "severity": "critical",
        "confidence": 0.95,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003 - OS Credential Dumping",
    },
    {
        "name": "password_spray",
        "description": "Password spraying attack",
        "pattern_type": "keyword",
        "keywords": ["password spray", "account lockout"],
        "severity": "high",
        "confidence": 0.85,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.003 - Brute Force: Password Spraying",
    },
    {
        "name": "lateral_movement_smb",
        "description": "SMB lateral movement attempt",
        "pattern_type": "keyword",
        "keywords": ["IPC$ share", "admin$ share", "psexec"],
        "severity": "critical",
        "confidence": 0.88,
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021.002 - SMB/Windows Admin Shares",
    },
    {
        "name": "data_exfiltration_dns",
        "description": "Possible data exfiltration via DNS",
        "pattern_type": "keyword",
        "keywords": ["DNS tunnel", "long DNS query", "base64 DNS"],
        "severity": "critical",
        "confidence": 0.85,
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048.003 - Exfiltration Over Alternative Protocol",
    },
    {
        "name": "cron_modification",
        "description": "Cron job modification for persistence",
        "pattern_type": "keyword",
        "keywords": ["crontab", "cron.d", "scheduled task"],
        "severity": "high",
        "confidence": 0.80,
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053.003 - Scheduled Task/Job: Cron",
    },
    {
        "name": "log_clearing",
        "description": "System logs being cleared",
        "pattern_type": "keyword",
        "keywords": ["log cleared", "event log cleared", "history cleared"],
        "severity": "critical",
        "confidence": 0.95,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.001 - Clear Windows Event Logs",
    },
    {
        "name": "firewall_disabled",
        "description": "Firewall disabled or rules modified",
        "pattern_type": "keyword",
        "keywords": ["firewall disabled", "iptables flush", "ufw disable"],
        "severity": "critical",
        "confidence": 0.92,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.004 - Disable or Modify System Firewall",
    },
    {
        "name": "c2_beacon",
        "description": "Command and control beacon detected",
        "pattern_type": "keyword",
        "keywords": ["reverse shell", "netcat", "nc -e", "bash -i"],
        "severity": "critical",
        "confidence": 0.93,
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071 - Application Layer Protocol",
    },
    {
        "name": "ransomware_activity",
        "description": "Ransomware-like file encryption activity",
        "pattern_type": "keyword",
        "keywords": ["ransomware", "file encrypted", ".locked", "decrypt"],
        "severity": "critical",
        "confidence": 0.96,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1486 - Data Encrypted for Impact",
    },
    {
        "name": "dos_attack",
        "description": "Denial of service attack detected",
        "pattern_type": "keyword",
        "keywords": ["DoS attack", "DDoS", "SYN flood", "UDP flood"],
        "severity": "critical",
        "confidence": 0.90,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498 - Network Denial of Service",
    },
    {
        "name": "tor_usage",
        "description": "Tor network usage detected",
        "pattern_type": "keyword",
        "keywords": ["tor exit", "onion routing", ".onion"],
        "severity": "high",
        "confidence": 0.85,
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1090.003 - Multi-hop Proxy",
    },
]


class RuleEngine:

    def __init__(self):
        self.rules = RULES
        log.info("rule_engine_loaded", total_rules=len(self.rules))

    def check(self, event_text: str) -> RuleMatch:
        event_lower = event_text.lower()

        for rule in self.rules:
            if rule["pattern_type"] in ("keyword", "threshold"):
                for keyword in rule.get("keywords", []):
                    if keyword.lower() in event_lower:
                        log.info("rule_matched", rule=rule["name"], severity=rule["severity"])
                        return RuleMatch(
                            matched=True,
                            rule_name=rule["name"],
                            severity=rule["severity"],
                            confidence=rule["confidence"],
                            mitre_tactic=rule["mitre_tactic"],
                            mitre_technique=rule["mitre_technique"],
                            description=rule["description"],
                        )

            elif rule["pattern_type"] == "regex":
                pattern = rule.get("pattern", "")
                if pattern and re.search(pattern, event_lower, re.IGNORECASE):
                    log.info("rule_matched", rule=rule["name"], severity=rule["severity"])
                    return RuleMatch(
                        matched=True,
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        description=rule["description"],
                    )

        return RuleMatch(
            matched=False,
            rule_name="none",
            severity="low",
            confidence=0.0,
            mitre_tactic="unknown",
            mitre_technique="unknown",
            description="No rule matched",
        )

    def get_stats(self) -> dict:
        tactics = {}
        for rule in self.rules:
            tactic = rule["mitre_tactic"]
            tactics[tactic] = tactics.get(tactic, 0) + 1
        return {
            "total_rules": len(self.rules),
            "tactics_covered": len(tactics),
            "tactics": tactics,
        }


rule_engine = RuleEngine()