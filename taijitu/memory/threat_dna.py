# taijitu/memory/threat_dna.py
# Behavioral DNA fingerprinting
# Identifies the same attacker across IP changes
# Attackers have habits — TAIJITU remembers them

import hashlib
import json
import structlog
from datetime import datetime

log = structlog.get_logger()


class ThreatDNA:
    """
    Behavioral fingerprinting system
    
    The problem it solves:
    Attacker uses IP 185.220.101.45 today
    TAIJITU blocks it
    Attacker comes back tomorrow with IP 193.32.162.157
    Without DNA — looks like a new attacker
    With DNA — TAIJITU recognizes the same behavior pattern
    
    How it works:
    Extract behavioral features from attack pattern
    Hash them into a DNA fingerprint
    Compare new attackers against known DNA
    Match = same actor, different IP
    """

    def extract_features(self, profile_data: dict) -> dict:
        """
        Extract behavioral features from attacker profile
        These features survive IP changes
        Only uses WHAT they do — not how many times
        """
        return {
            # What attack types they use
            "attack_types": sorted(profile_data.get("event_types", [])),

            # What MITRE tactics they use
            "tactics": sorted(profile_data.get("tactics_used", [])),

            # What ports they target
            "target_ports": sorted(profile_data.get("target_ports", [])),
        }

    def generate_dna(self, profile_data: dict) -> str:
        """
        Generate a DNA hash from behavioral features
        Same behavior pattern = same hash
        
        Returns a 16-character hex string
        """
        features = self.extract_features(profile_data)

        # Create a stable string from features
        # sorted() ensures same order every time
        dna_string = json.dumps(features, sort_keys=True)

        # Hash it to a short fingerprint
        full_hash = hashlib.sha256(dna_string.encode()).hexdigest()
        dna_hash = full_hash[:16]

        log.info(
            "dna_generated",
            dna=dna_hash,
            attack_types=features["attack_types"],
            tactics=features["tactics"],
        )

        return dna_hash

    def compare(self, dna1: str, dna2: str) -> bool:
        """
        Compare two DNA hashes
        Returns True if they match — same attacker behavior
        """
        if not dna1 or not dna2:
            return False
        match = dna1 == dna2
        if match:
            log.info("dna_match_found", dna=dna1)
        return match

    def similarity_score(
        self,
        features1: dict,
        features2: dict
    ) -> float:
        """
        Calculate how similar two behavioral profiles are
        Returns 0.0 to 1.0
        1.0 = identical behavior
        0.0 = completely different
        
        Used when exact DNA match fails
        Catches attackers who slightly changed tactics
        """
        score = 0.0
        total_weight = 0.0

        # Compare attack types — highest weight
        types1 = set(features1.get("attack_types", []))
        types2 = set(features2.get("attack_types", []))
        if types1 or types2:
            overlap = len(types1 & types2)
            total = len(types1 | types2)
            type_similarity = overlap / total if total > 0 else 0
            score += type_similarity * 0.4
            total_weight += 0.4

        # Compare tactics
        tactics1 = set(features1.get("tactics", []))
        tactics2 = set(features2.get("tactics", []))
        if tactics1 or tactics2:
            overlap = len(tactics1 & tactics2)
            total = len(tactics1 | tactics2)
            tactic_similarity = overlap / total if total > 0 else 0
            score += tactic_similarity * 0.3
            total_weight += 0.3

        # Compare target ports
        ports1 = set(features1.get("target_ports", []))
        ports2 = set(features2.get("target_ports", []))
        if ports1 or ports2:
            overlap = len(ports1 & ports2)
            total = len(ports1 | ports2)
            port_similarity = overlap / total if total > 0 else 0
            score += port_similarity * 0.2
            total_weight += 0.2

        # Compare persistence behavior
        if features1.get("is_persistent") == features2.get("is_persistent"):
            score += 0.1
        total_weight += 0.1

        # Normalize
        final_score = score / total_weight if total_weight > 0 else 0.0

        log.info(
            "similarity_calculated",
            score=round(final_score, 3),
        )

        return round(final_score, 3)

    def analyze(self, profile_data: dict) -> dict:
        """
        Full DNA analysis of an attacker profile
        Returns complete behavioral analysis
        """
        features = self.extract_features(profile_data)
        dna_hash = self.generate_dna(profile_data)

        # Determine attacker sophistication
        sophistication = "unknown"
        attack_count = len(features["attack_types"])
        tactic_count = len(features["tactics"])

        if attack_count >= 4 or tactic_count >= 3:
            sophistication = "advanced"
        elif attack_count >= 2 or tactic_count >= 2:
            sophistication = "intermediate"
        elif attack_count >= 1:
            sophistication = "basic"

        # Determine likely attacker type
        attacker_type = "unknown"
        attack_types = set(features["attack_types"])

        if "ransomware_activity" in attack_types:
            attacker_type = "ransomware_operator"
        elif "credential_dumping" in attack_types:
            attacker_type = "advanced_persistent_threat"
        elif "c2_beacon" in attack_types:
            attacker_type = "malware_operator"
        elif "sql_injection" in attack_types or "xss_attempt" in attack_types:
            attacker_type = "web_application_attacker"
        elif "ssh_brute_force" in attack_types or "port_scan" in attack_types:
            attacker_type = "opportunistic_scanner"

        return {
            "dna_hash": dna_hash,
            "features": features,
            "sophistication": sophistication,
            "attacker_type": attacker_type,
            "generated_at": datetime.utcnow().isoformat(),
        }


# ── GLOBAL INSTANCE ───────────────────────────────────
threat_dna = ThreatDNA()