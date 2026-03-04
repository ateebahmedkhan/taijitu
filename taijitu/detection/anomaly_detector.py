# taijitu/detection/anomaly_detector.py
# Isolation Forest anomaly detector
# Catches attacks no rule has ever seen before
# Trained on normal traffic — flags anything abnormal

import numpy as np
import structlog
from dataclasses import dataclass
from sklearn.ensemble import IsolationForest
from datetime import datetime

log = structlog.get_logger()


@dataclass
class AnomalyResult:
    """Result from anomaly detection"""
    is_anomaly: bool
    anomaly_score: float      # 0.0 to 1.0 — higher = more suspicious
    confidence: float         # How confident we are
    reason: str               # Plain English explanation


class AnomalyDetector:
    """
    Isolation Forest based anomaly detector
    Learns what normal traffic looks like
    Flags anything that deviates from normal
    
    How Isolation Forest works:
    - Normal points need many splits to isolate
    - Anomalies are isolated with very few splits
    - Anomalies = suspicious = potential threats
    """

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,      # Number of trees
            contamination=0.1,     # Expect 10% anomalies
            random_state=42,       # Reproducible results
            max_samples="auto",
        )
        self.is_trained = False
        self.training_samples = 0
        log.info("anomaly_detector_initialized")

    def extract_features(self, event: dict) -> list:
        """
        Convert raw event into numerical features
        Isolation Forest only understands numbers
        
        Features we extract:
        1. Hour of day — attacks cluster at night
        2. Destination port — common attack ports
        3. Source port range — high ports are suspicious
        4. Event type encoded — each type gets a number
        5. Log source encoded — system vs network vs web
        """
        # Feature 1 — hour of day (0-23)
        timestamp = event.get("timestamp", datetime.utcnow())
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except Exception:
                timestamp = datetime.utcnow()
        hour = timestamp.hour

        # Feature 2 — destination port
        dest_port = event.get("destination_port", 0)

        # Feature 3 — source port (high ports more suspicious)
        src_port = event.get("source_port", 0)
        src_port_range = min(src_port // 1000, 65)  # Normalize to 0-65

        # Feature 4 — event type encoded
        event_type_map = {
            "ssh_brute_force": 8,
            "port_scan": 7,
            "sql_injection": 9,
            "xss_attempt": 7,
            "c2_beacon": 10,
            "ransomware_activity": 10,
            "credential_dumping": 9,
            "data_exfiltration": 9,
            "lateral_movement": 8,
            "normal_traffic": 1,
            "unknown": 3,
        }
        event_type = event.get("event_type", "unknown")
        event_encoded = event_type_map.get(event_type, 3)

        # Feature 5 — log source encoded
        source_map = {
            "system": 1,
            "network": 2,
            "web": 3,
            "wazuh": 4,
            "unknown": 0,
        }
        log_source = event.get("log_source", "unknown")
        source_encoded = source_map.get(log_source, 0)

        # Feature 6 — is known attack port
        attack_ports = {22, 23, 3389, 445, 139, 21, 3306, 5432, 6379, 27017}
        is_attack_port = 1 if dest_port in attack_ports else 0

        return [
            hour,
            dest_port,
            src_port_range,
            event_encoded,
            source_encoded,
            is_attack_port,
        ]

    def train(self, events: list = None) -> None:
        """
        Train on normal traffic patterns
        If no events provided — generates synthetic normal traffic
        """
        if not events:
            events = self._generate_training_data()

        # Extract features from all events
        features = [self.extract_features(e) for e in events]
        X = np.array(features)

        # Train the model
        self.model.fit(X)
        self.is_trained = True
        self.training_samples = len(events)

        log.info(
            "anomaly_detector_trained",
            samples=self.training_samples,
        )

    def _generate_training_data(self) -> list:
        """
        Generate synthetic normal traffic for initial training
        Used when no real training data is available yet
        """
        import random
        training_data = []

        # Normal business hours web traffic
        for _ in range(300):
            training_data.append({
                "timestamp": datetime.utcnow().replace(
                    hour=random.randint(9, 18)
                ),
                "destination_port": random.choice([80, 443, 8080]),
                "source_port": random.randint(40000, 65535),
                "event_type": "normal_traffic",
                "log_source": "web",
            })

        # Normal SSH logins during business hours
        for _ in range(100):
            training_data.append({
                "timestamp": datetime.utcnow().replace(
                    hour=random.randint(8, 18)
                ),
                "destination_port": 22,
                "source_port": random.randint(40000, 65535),
                "event_type": "normal_traffic",
                "log_source": "system",
            })

        # Normal database connections
        for _ in range(100):
            training_data.append({
                "timestamp": datetime.utcnow().replace(
                    hour=random.randint(6, 22)
                ),
                "destination_port": random.choice([5432, 3306]),
                "source_port": random.randint(40000, 65535),
                "event_type": "normal_traffic",
                "log_source": "system",
            })

        log.info(
            "training_data_generated",
            samples=len(training_data)
        )
        return training_data

    def score(self, event: dict) -> AnomalyResult:
        """
        Score a single event for anomaly
        Returns AnomalyResult with score 0.0 to 1.0
        Higher score = more suspicious
        """
        # Auto-train if not trained yet
        if not self.is_trained:
            log.info("auto_training_on_first_event")
            self.train()

        # Extract features
        features = self.extract_features(event)
        X = np.array([features])

        # Get raw score from Isolation Forest
        # Raw score is negative — more negative = more anomalous
        raw_score = self.model.score_samples(X)[0]

        # Convert to 0.0-1.0 range
        # Typical range is -0.5 to 0.5
        # We normalize so -0.5 becomes 1.0 (very anomalous)
        # and 0.5 becomes 0.0 (very normal)
        anomaly_score = max(0.0, min(1.0, (-raw_score - 0.1) * 2))

        # Determine if this is an anomaly
        prediction = self.model.predict(X)[0]
        is_anomaly = prediction == -1  # -1 means anomaly in sklearn

        # Build human readable reason
        hour = features[0]
        dest_port = features[1]
        event_type = event.get("event_type", "unknown")

        reasons = []
        if hour < 6 or hour > 22:
            reasons.append(f"unusual hour ({hour:02d}:00)")
        if dest_port in {22, 3389, 445, 23}:
            reasons.append(f"sensitive port ({dest_port})")
        if anomaly_score > 0.7:
            reasons.append("behavior deviates significantly from baseline")
        if not reasons:
            reasons.append("statistical deviation from normal patterns")

        reason = " | ".join(reasons) if reasons else "normal pattern"

        log.info(
            "anomaly_scored",
            event_type=event_type,
            score=round(anomaly_score, 3),
            is_anomaly=is_anomaly,
        )

        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=round(anomaly_score, 3),
            confidence=round(min(anomaly_score + 0.2, 1.0), 3),
            reason=reason,
        )


# ── GLOBAL INSTANCE ───────────────────────────────────
anomaly_detector = AnomalyDetector()