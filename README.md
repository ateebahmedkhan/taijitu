# ☯ TAIJITU

<div align="center">

**Two Minds. One System. Zero Blind Spots.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](https://www.docker.com)
[![Ollama](https://img.shields.io/badge/Ollama-local%20AI-orange.svg)](https://ollama.ai)
[![Tests](https://img.shields.io/badge/tests-15%20passing-brightgreen.svg)]()

</div>

---

## What Is TAIJITU?

TAIJITU is an autonomous cybersecurity platform where two AI minds debate every threat in real time.

**Guardian** analyzes from the defender's perspective. **Adversary** challenges from the attacker's perspective. Together they reach a verdict — block, alert, or monitor — with zero human input required.

Every decision is explainable. Every action is auditable. Everything runs locally with no API costs.

---

## The Seven Pillars

| Pillar | Description |
|--------|-------------|
| 🧠 Dual-Mind Debate | Guardian vs Adversary argue every threat |
| 🔍 Detection Engine | 20 MITRE ATT&CK mapped signatures |
| 🧬 Threat DNA | Identifies same attacker across IP changes |
| 🤖 Autonomy | Blocks IPs, learns, self-tests at 3am |
| 📱 Telegram War Room | Real-time alerts on your phone |
| 🌐 Network Intelligence | Real packet capture via Scapy |
| 💬 Natural Language | Ask questions in plain English |

---

## Quick Start
```bash
git clone https://github.com/ateebahmedkhan/taijitu
cd taijitu
cp .env.example .env
docker-compose up -d
```

Visit `http://localhost:8000/docs` for full API documentation.

---

## Architecture
```
Raw Log / Network Packet
        ↓
   Rule Engine (MITRE ATT&CK)
        ↓
  Anomaly Detector (Isolation Forest)
        ↓
    Correlator (Pattern Detection)
        ↓
  ┌─────────────────────┐
  │   DEBATE ENGINE     │
  │  Guardian vs        │
  │  Adversary          │
  │  3 rounds           │
  └─────────────────────┘
        ↓
    Verdict + Action
        ↓
  ┌─────┬──────┬────────┐
  │Block│Alert │ Learn  │
  │ IP  │Phone │& Adapt │
  └─────┴──────┴────────┘
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI + Uvicorn |
| AI Minds | Ollama + Llama 3.2 (local) |
| Database | PostgreSQL + TimescaleDB |
| Cache | Redis |
| Queue | Celery |
| Detection | scikit-learn Isolation Forest |
| Packets | Scapy |
| Alerts | python-telegram-bot |
| Monitoring | Prometheus + Grafana |
| Container | Docker Compose |

---

## API Endpoints
```
POST /events/ingest          — Ingest raw log event
GET  /events/recent          — Recent threat events
GET  /events/attackers       — Top attackers by score
GET  /events/attacker/{ip}   — Full attacker profile
POST /events/feedback        — Submit human feedback
GET  /stats/overview         — Dashboard statistics
GET  /stats/timeline         — Hourly event chart
GET  /stats/tactics          — MITRE tactic breakdown
GET  /stats/top-attackers    — Threat leaderboard
POST /query/ask              — Natural language query
GET  /health                 — System health check
```

---

## vs Existing Tools

| Feature | TAIJITU | Splunk | Wazuh | CrowdStrike |
|---------|---------|--------|-------|-------------|
| Dual-Mind Debate | ✅ | ❌ | ❌ | ❌ |
| Local AI (no API cost) | ✅ | ❌ | ❌ | ❌ |
| Behavioral DNA | ✅ | ❌ | ❌ | ✅ |
| Self-Testing at 3am | ✅ | ❌ | ❌ | ❌ |
| Natural Language Query | ✅ | ✅ | ❌ | ✅ |
| Free & Open Source | ✅ | ❌ | ✅ | ❌ |
| Runs on MacBook | ✅ | ❌ | ✅ | ❌ |

---

## Project Status
```
✅ Phase 1  — Foundation (7 Docker services)
✅ Phase 2  — Detection Engine (20 MITRE signatures)
✅ Phase 3  — Memory Engine (attacker profiles + DNA)
✅ Phase 4  — Dual-Mind Debate (Guardian vs Adversary)
✅ Phase 5  — Autonomy Engine (block, learn, self-test)
✅ Phase 6  — Telegram War Room (real-time alerts)
✅ Phase 7  — Network Intelligence (packet capture)
✅ Phase 8  — Dashboard API (17 endpoints)
✅ Phase 9  — Natural Language Query
✅ Phase 10 — Polish and Launch
```

---

## Author

**Ateeb Ahmed Khan**
B.Tech Metallurgical Engineering → Self-taught Cybersecurity

[![GitHub](https://img.shields.io/badge/GitHub-ateebahmedkhan-black.svg)](https://github.com/ateebahmedkhan)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-ateebahmedkhan-blue.svg)](https://linkedin.com/in/ateebahmedkhan)

---

## License

MIT License — free to use, modify, and distribute.