# main.py
# TAIJITU entry point
# This is the first file that runs when you start TAIJITU

import structlog
import uvicorn

from taijitu.config import settings
from taijitu.storage.database import create_tables, check_connection as check_db
from taijitu.storage.cache import check_connection as check_cache

# ── LOGGING SETUP ─────────────────────────────────────
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ]
)

log = structlog.get_logger()


def startup_checks() -> bool:
    """
    Run all checks before starting TAIJITU
    Returns True if everything is ready
    Returns False if something is missing
    """
    log.info("taijitu_starting", version="1.0.0")
    log.info("two_minds_one_system_zero_blind_spots")

    all_good = True

    # Check database
    log.info("checking_database")
    if check_db():
        log.info("database_ready")
    else:
        log.error("database_not_ready", hint="Is PostgreSQL running? Check docker-compose up")
        all_good = False

    # Check Redis
    log.info("checking_redis")
    if check_cache():
        log.info("redis_ready")
    else:
        log.error("redis_not_ready", hint="Is Redis running? Check docker-compose up")
        all_good = False

    return all_good


def main():
    """
    Start TAIJITU
    """
    log.info("=" * 50)
    log.info("TAIJITU — Autonomous Security Platform")
    log.info("Guardian Mind + Adversary Mind = Zero Blind Spots")
    log.info("=" * 50)

    # Run startup checks
    ready = startup_checks()

    if not ready:
        log.error("startup_failed", message="Fix the errors above then try again")
        return

    # Create database tables if they don't exist
    log.info("creating_database_tables")
    create_tables()
    log.info("database_tables_ready")

    # Start the API server
    log.info("starting_api_server", host="0.0.0.0", port=8000)
    log.info("dashboard_will_be_at", url="http://localhost:8000")
    log.info("api_docs_will_be_at", url="http://localhost:8000/docs")

    uvicorn.run(
        "taijitu.api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.is_development,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()