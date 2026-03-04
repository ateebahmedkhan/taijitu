# taijitu/api/server.py
# FastAPI application — the front door of TAIJITU
# Every API request comes through here

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from taijitu.config import settings

# ── LOGGING ───────────────────────────────────────────
log = structlog.get_logger()

# ── APP ───────────────────────────────────────────────
app = FastAPI(
    title="TAIJITU",
    description="Two Minds. One System. Zero Blind Spots. — Autonomous Security Platform",
    version="1.0.0",
    docs_url="/docs",       # API documentation at /docs
    redoc_url="/redoc",     # Alternative docs at /redoc
)

# ── CORS ──────────────────────────────────────────────
# Allows the dashboard to talk to the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── STARTUP ───────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    """Runs when TAIJITU API starts"""
    log.info("taijitu_api_started")
    log.info("api_docs_available", url="http://localhost:8000/docs")


# ── HEALTH CHECK ──────────────────────────────────────
@app.get("/health")
async def health_check():
    """
    Health check endpoint
    Visit http://localhost:8000/health to verify TAIJITU is running
    Returns status of all components
    """
    return {
        "status": "online",
        "system": "TAIJITU",
        "version": "1.0.0",
        "tagline": "Two Minds. One System. Zero Blind Spots.",
        "components": {
            "api": "online",
            "guardian_mind": "ready",
            "adversary_mind": "ready",
        }
    }


# ── ROOT ──────────────────────────────────────────────
@app.get("/")
async def root():
    """
    Root endpoint
    Visit http://localhost:8000 to see TAIJITU is alive
    """
    return {
        "system": "TAIJITU",
        "tagline": "Two Minds. One System. Zero Blind Spots.",
        "docs": "http://localhost:8000/docs",
        "health": "http://localhost:8000/health",
        "status": "operational",
        "author": "Ateeb Ahmed Khan",
        "github": "https://github.com/ateebahmedkhan",
    }