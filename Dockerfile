# Dockerfile
# Builds the TAIJITU application container
# Used by docker-compose for the api and worker services

# ── BASE IMAGE ────────────────────────────────────────
# Python 3.11 on slim Debian — small and fast
FROM python:3.11-slim

# ── LABELS ───────────────────────────────────────────
LABEL maintainer="Ateeb Ahmed Khan"
LABEL description="TAIJITU — Two Minds. One System. Zero Blind Spots."
LABEL version="1.0.0"

# ── SYSTEM DEPENDENCIES ───────────────────────────────
# Install system packages needed by Python libraries
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    nmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── WORKING DIRECTORY ─────────────────────────────────
# All TAIJITU code lives at /app inside the container
WORKDIR /app

# ── PYTHON DEPENDENCIES ───────────────────────────────
# Copy requirements first — Docker caches this layer
# Only rebuilds when requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── APPLICATION CODE ──────────────────────────────────
# Copy the entire project into the container
COPY . .

# ── PORT ──────────────────────────────────────────────
# TAIJITU API runs on port 8000
EXPOSE 8000

# ── HEALTHCHECK ───────────────────────────────────────
# Docker checks if TAIJITU is healthy every 30 seconds
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ── START COMMAND ─────────────────────────────────────
# Default command — can be overridden in docker-compose
CMD ["python", "main.py"]