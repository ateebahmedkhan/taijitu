# taijitu/query/natural_language.py
# Natural language query engine
# Ask TAIJITU questions in plain English
# It understands and answers using real data

import ollama
import structlog
from datetime import datetime, timedelta
from dataclasses import dataclass

log = structlog.get_logger()

NL_SYSTEM_PROMPT = """You are TAIJITU's query engine.
You answer security questions in plain English using data provided to you.

Rules:
- Answer directly and concisely
- Use the data provided — do not make up numbers
- If data is empty say so honestly
- Format IPs in code blocks like `192.168.1.1`
- Keep answers under 150 words
- Be direct — no fluff
"""


@dataclass
class QueryResult:
    """Result of a natural language query"""
    question: str
    answer: str
    data_used: dict
    timestamp: datetime


class NaturalLanguageQuery:
    """
    Ask TAIJITU questions in plain English

    Examples:
    - "What are the top threats right now?"
    - "Which IP is most dangerous?"
    - "What happened in the last hour?"
    - "Are there any critical alerts?"
    - "What attack types have been detected?"
    """

    def __init__(self):
        self.model = "llama3.2"
        self.query_history = []
        log.info("natural_language_query_initialized")

    def ask(self, question: str, db=None) -> QueryResult:
        """
        Ask a question in plain English
        TAIJITU answers using real data
        """
        log.info("query_received", question=question[:50])

        # Gather relevant data based on question
        data = self._gather_data(question, db)

        # Build prompt with data context
        prompt = self._build_prompt(question, data)

        # Ask Ollama
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": NL_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.2},
            )
            answer = response["message"]["content"]

        except Exception as e:
            log.error("query_failed", error=str(e))
            answer = self._fallback_answer(question, data)

        result = QueryResult(
            question=question,
            answer=answer,
            data_used=data,
            timestamp=datetime.utcnow(),
        )

        self.query_history.append(result)
        log.info("query_answered", length=len(answer))
        return result

    def ask_without_db(self, question: str, mock_data: dict) -> QueryResult:
        """
        Ask a question with manually provided data
        Used for testing without database
        """
        prompt = self._build_prompt(question, mock_data)

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": NL_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.2},
            )
            answer = response["message"]["content"]

        except Exception as e:
            log.error("query_failed", error=str(e))
            answer = self._fallback_answer(question, mock_data)

        result = QueryResult(
            question=question,
            answer=answer,
            data_used=mock_data,
            timestamp=datetime.utcnow(),
        )
        self.query_history.append(result)
        return result

    def _gather_data(self, question: str, db) -> dict:
        """
        Gather relevant data based on question keywords
        Only fetches what is needed for efficiency
        """
        data = {}
        question_lower = question.lower()

        if not db:
            return data

        try:
            from taijitu.storage.models import ThreatEvent, AttackerProfile

            # Always include basic counts
            data["total_events"] = db.query(ThreatEvent).count()
            data["total_attackers"] = db.query(AttackerProfile).count()

            # Recent events
            if any(word in question_lower for word in [
                "recent", "latest", "last", "hour", "today", "now"
            ]):
                last_hour = datetime.utcnow() - timedelta(hours=1)
                recent = db.query(ThreatEvent).filter(
                    ThreatEvent.timestamp >= last_hour
                ).order_by(ThreatEvent.timestamp.desc()).limit(10).all()
                data["recent_events"] = [
                    {
                        "ip": e.source_ip,
                        "type": e.event_type,
                        "severity": e.severity,
                        "time": e.timestamp.isoformat(),
                    }
                    for e in recent
                ]

            # Top attackers
            if any(word in question_lower for word in [
                "attacker", "ip", "dangerous", "threat", "top", "worst"
            ]):
                top = db.query(AttackerProfile).order_by(
                    AttackerProfile.threat_score.desc()
                ).limit(5).all()
                data["top_attackers"] = [
                    {
                        "ip": a.ip_address,
                        "threat_score": round(a.threat_score, 1),
                        "total_events": a.total_events,
                        "is_blocked": a.is_blocked,
                        "tactics": a.tactics_used,
                    }
                    for a in top
                ]

            # Critical events
            if any(word in question_lower for word in [
                "critical", "severe", "urgent", "dangerous"
            ]):
                critical = db.query(ThreatEvent).filter(
                    ThreatEvent.severity == "critical"
                ).order_by(
                    ThreatEvent.timestamp.desc()
                ).limit(5).all()
                data["critical_events"] = [
                    {
                        "ip": e.source_ip,
                        "type": e.event_type,
                        "time": e.timestamp.isoformat(),
                        "verdict": e.verdict,
                    }
                    for e in critical
                ]

            # Blocked IPs
            if any(word in question_lower for word in [
                "blocked", "block", "banned"
            ]):
                blocked = db.query(AttackerProfile).filter(
                    AttackerProfile.is_blocked.is_(True)
                ).all()
                data["blocked_ips"] = [a.ip_address for a in blocked]

        except Exception as e:
            log.error("data_gathering_failed", error=str(e))

        return data

    def _build_prompt(self, question: str, data: dict) -> str:
        """Build prompt with data context"""
        data_text = "\n".join(
            f"{k}: {v}" for k, v in data.items()
        ) if data else "No data available yet"

        return f"""Security data from TAIJITU:

{data_text}

Question: {question}

Answer based only on the data above."""

    def _fallback_answer(self, question: str, data: dict) -> str:
        """Fallback answer when Ollama is unavailable"""
        total = data.get("total_events", 0)
        attackers = data.get("total_attackers", 0)
        return (
            f"Based on available data: "
            f"{total} total events detected, "
            f"{attackers} unique attackers tracked. "
            f"AI analysis unavailable — Ollama offline."
        )


# ── GLOBAL INSTANCE ───────────────────────────────────
nl_query = NaturalLanguageQuery()