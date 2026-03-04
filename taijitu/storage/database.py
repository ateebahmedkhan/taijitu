# taijitu/storage/database.py
# Database connection and session management
# Every part of TAIJITU uses this to talk to PostgreSQL

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError
import structlog

from taijitu.config import settings
from taijitu.storage.models import Base

# ── LOGGING ───────────────────────────────────────────
log = structlog.get_logger()

# ── ENGINE ────────────────────────────────────────────
# The engine is the actual connection to PostgreSQL
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,       # Check connection is alive before using
    pool_size=10,             # Keep 10 connections ready
    max_overflow=20,          # Allow 20 extra if needed
    echo=settings.is_development,  # Log SQL in development only
)

# ── SESSION FACTORY ───────────────────────────────────
# SessionLocal creates database sessions
# A session is one conversation with the database
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


def get_db() -> Session:
    """
    Get a database session
    Use this in FastAPI routes like:

    def my_route(db: Session = Depends(get_db)):
        events = db.query(ThreatEvent).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables() -> None:
    """
    Create all database tables if they don't exist
    Called once when TAIJITU starts up
    """
    try:
        Base.metadata.create_all(bind=engine)
        log.info("database_tables_created")
    except OperationalError as e:
        log.error("database_connection_failed", error=str(e))
        raise


def check_connection() -> bool:
    """
    Test if database is reachable
    Returns True if connected, False if not
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        log.info("database_connection_ok")
        return True
    except OperationalError as e:
        log.error("database_unreachable", error=str(e))
        return False