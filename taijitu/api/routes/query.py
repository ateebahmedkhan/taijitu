# taijitu/api/routes/query.py
# Natural language query endpoint
# Ask TAIJITU questions via HTTP

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from taijitu.storage.database import get_db
from taijitu.query.natural_language import nl_query

import structlog
log = structlog.get_logger()

router = APIRouter(prefix="/query", tags=["query"])


class QueryRequest(BaseModel):
    question: str


@router.post("/ask")
async def ask_question(
    request: QueryRequest,
    db: Session = Depends(get_db),
):
    """
    Ask TAIJITU a question in plain English
    Returns answer based on real database data

    Examples:
    - "Which IP is most dangerous?"
    - "Any critical threats in the last hour?"
    - "Which attackers should be blocked?"
    """
    result = nl_query.ask(request.question, db)

    return {
        "question": result.question,
        "answer": result.answer,
        "timestamp": result.timestamp.isoformat(),
    }


@router.get("/history")
async def get_query_history():
    """Get history of all questions asked"""
    return {
        "count": len(nl_query.query_history),
        "history": [
            {
                "question": r.question,
                "answer": r.answer[:200],
                "timestamp": r.timestamp.isoformat(),
            }
            for r in nl_query.query_history[-20:]
        ],
    }