<div align="center">

# ☯ TAIJITU

### Two Minds. One System. Zero Blind Spots.

**The world's first dual-mind autonomous cybersecurity platform.**
Guardian and Adversary — two AI minds debating every threat in real time.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](docker-compose.yml)
[![Ollama](https://img.shields.io/badge/AI-Local%20%26%20Free-purple.svg)](https://ollama.ai)

</div>

---

## What Is TAIJITU?

TAIJITU is a free, local, autonomous cybersecurity platform that thinks like an attacker to protect like a defender.

Instead of just detecting threats — TAIJITU debates them.

Every suspicious event triggers a real-time argument between two AI minds:

- **Guardian Mind** — analyzes from the defender's perspective. What do I know? What rules apply? What is the risk?
- **Adversary Mind** — analyzes from the attacker's perspective. How would I exploit this? What comes next? What is the defender missing?

Their debate produces a verdict — with full reasoning in plain English. No black boxes. No unexplained scores. Every decision is transparent and auditable.

---

## The Four Products

| Product | Purpose |
|---------|---------|
| **TAIJITU BLUE** | Autonomous SOC — real-time threat detection and response |
| **TAIJITU RED** | Autonomous Red Team — penetration testing and bug bounty |
| **TAIJITU PURPLE** | Intelligence Bridge — continuous Blue/Red feedback loop |
| **TAIJITU GRC** | Compliance Engine — automatic governance and audit reporting |

---

## The Seven Pillars

1. **Dual-Mind Debate** — Guardian defends, Adversary attacks, debate IS the analysis
2. **Perpetual Attacker Memory** — every IP stored forever, full history retrieved instantly
3. **Explainable AI Verdicts** — full reasoning chain in plain English, not just scores
4. **Autonomous Self-Learning** — corrects own mistakes, no human retraining needed
5. **Behavioral Threat DNA** — fingerprints attackers by behavior, survives IP changes
6. **Adversarial Night Probe** — attacks itself at 3am to find weaknesses first
7. **100% Free and Offline** — Ollama local LLM, no API costs, data never leaves machine

---

## Quick Start
```bash
# 1. Clone the repository
git clone https://github.com/ateebahmedkhan/taijitu.git
cd taijitu

# 2. Copy environment template
cp .env.example .env

# 3. Start everything
docker-compose up -d

# 4. Open TAIJITU
open http://localhost:8000
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| AI | Ollama + Llama 3.2 — local, free, private |
| Backend | FastAPI + Celery + Redis |
| Database | PostgreSQL + TimescaleDB |
| Detection | Scikit-learn Isolation Forest + MITRE ATT&CK |
| Network | Scapy + PyShark |
| Dashboard | Grafana + Prometheus |
| Alerting | Telegram Bot |

---

## Architecture
```
Internet Traffic
      ↓
TAIJITU Ingestion Engine
      ↓
Rule Engine + Anomaly Detector
      ↓
┌─────────────────────────┐
│   DUAL-MIND DEBATE      │
│                         │
│  Guardian  ←→  Adversary│
│  (Defender)   (Attacker)│
└─────────────────────────┘
      ↓
Verdict + Full Transcript
      ↓
Autonomous Action + Alert
```

---

## Comparison

| Capability | Splunk | CrowdStrike | Wazuh | TAIJITU |
|-----------|--------|-------------|-------|---------|
| Dual-mind AI debate | ✗ | ✗ | ✗ | ✅ |
| Perpetual attacker memory | Partial | Partial | ✗ | ✅ |
| Explains its reasoning | ✗ | ✗ | ✗ | ✅ |
| Red + Blue + Purple + GRC | ✗ | ✗ | ✗ | ✅ |
| 100% free and offline | ✗ | ✗ | ✅ | ✅ |
| Cost | $150k+/yr | $15/endpoint | Free | **Free** |

---

## Status

🔴 Currently in active development — Phase 1 Foundation

Follow the build journey on [LinkedIn](https://linkedin.com/in/ateebahmedkhan)

---

## Author

**Ateeb Ahmed Khan**
Self-taught cybersecurity, building autonomous security systems.

- GitHub: [@ateebahmedkhan](https://github.com/ateebahmedkhan)
- LinkedIn: [ateebahmedkhan](https://linkedin.com/in/ateebahmedkhan)

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

<div align="center">
☯ <strong>TAIJITU</strong> — Two Minds. One System. Zero Blind Spots.
</div>