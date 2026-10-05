"""
ThreatFusion – AI-powered cyber-threat intelligence aggregator.

This package contains the FastAPI backend application that orchestrates
threat-intelligence lookups across VirusTotal, Shodan, and NVD, then
fuses the results through an ML risk-scoring pipeline.

Architecture
------------
app/
├── api/          ← FastAPI routers (health, scan)
├── core/         ← Configuration, logging, database bootstrap
├── models/       ← Pydantic schemas & SQLAlchemy / raw-SQL models
├── services/     ← Business logic: enrichment, ML scoring, caching
└── main.py       ← Application entry-point & lifespan setup
"""

APP_VERSION = "0.1.0"
