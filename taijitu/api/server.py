# taijitu/api/server.py
# FastAPI application — main API server
# All routes registered here

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from taijitu.api.routes.events import router as events_router
from taijitu.api.routes.stats import router as stats_router
from taijitu.api.routes.query import router as query_router

log = structlog.get_logger()

# ── FASTAPI APP ───────────────────────────────────────
app = FastAPI(
    title="TAIJITU",
    description="Two Minds. One System. Zero Blind Spots.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── ROUTES ────────────────────────────────────────────
app.include_router(events_router)
app.include_router(query_router)
app.include_router(stats_router)


# ── ROOT ──────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "system": "TAIJITU",
        "tagline": "Two Minds. One System. Zero Blind Spots.",
        "docs": "http://localhost:8000/docs",
        "health": "http://localhost:8000/health",
        "status": "operational",
        "author": "Ateeb Ahmed Khan",
        "github": "https://github.com/ateebahmedkhan",
    }


# ── HEALTH ────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "online",
        "system": "TAIJITU",
        "version": "1.0.0",
        "tagline": "Two Minds. One System. Zero Blind Spots.",
        "components": {
            "api": "online",
            "guardian_mind": "ready",
            "adversary_mind": "ready",
        },
    }