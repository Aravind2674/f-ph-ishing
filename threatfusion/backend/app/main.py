"""ThreatFusion API — Main Application Entry Point

This is the FastAPI application that orchestrates all components:
- Ingestion layer (VirusTotal, Shodan, CVE, tech fingerprinting)
- Feature engineering pipeline
- Dual scoring (baseline heuristic + ML fusion model)
- SHAP-based risk explanations

The app supports two modes controlled by USE_MOCK_DATA in .env:
- true (default): Returns realistic mocked responses — no API keys needed
- false: Makes real HTTP calls to external threat intelligence APIs
"""

from contextlib import asynccontextmanager
import aiosqlite
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings, startup_warnings
from app.core.logging import setup_logging, get_logger

logger = get_logger(__name__)

# SQL schema for scan history persistence.
# Using SQLite for development simplicity — PostgreSQL migration is a
# documented TODO (see docs/ARCHITECTURE.md). The schema stores serialized
# JSON for flexibility during rapid iteration; a normalized schema would
# be appropriate for production.
CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    result_json TEXT NOT NULL,
    baseline_score REAL,
    ml_score REAL,
    ml_label TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager.
    
    Handles startup initialization and shutdown cleanup:
    1. Configure structured logging
    2. Display mock/live mode warning
    3. Initialize SQLite database tables
    4. Signal readiness
    """
    settings = get_settings()
    
    # Step 1: Set up logging before anything else so all startup messages
    # are properly formatted
    setup_logging(settings.LOG_LEVEL)
    
    # Step 2: Make it loud and clear which mode we're running in —
    # this prevents confusion during demos and development
    startup_warnings()
    
    # Step 3: Initialize the database — create tables if they don't exist.
    # aiosqlite gives us async SQLite access without blocking the event loop.
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(CREATE_TABLES_SQL)
        await db.commit()
    logger.info("Database initialized: %s", db_path)
    
    logger.info("🚀 ThreatFusion API ready (mock_mode=%s)", settings.USE_MOCK_DATA)
    
    yield  # Application runs here
    
    # Shutdown cleanup (if needed in the future)
    logger.info("ThreatFusion API shutting down")


# Create the FastAPI application with metadata for auto-generated OpenAPI docs.
# FastAPI generates interactive Swagger UI at /docs automatically — this is
# invaluable for demos and viva presentations.
app = FastAPI(
    title="ThreatFusion API",
    description=(
        "ML-based risk fusion for web & network attack surface analysis. "
        "Aggregates signals from VirusTotal, Shodan/InternetDB, NVD/CVE, "
        "and web technology fingerprinting, then uses a trained ML model "
        "to produce a single explainable risk score."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware — allow all origins during development.
# In production, this should be restricted to the frontend's domain.
# We need CORS because the React frontend (localhost:5173) calls the
# API (localhost:8000) from a different origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route handlers
from app.api.health import router as health_router
from app.api.scan import router as scan_router

app.include_router(health_router)
app.include_router(scan_router)
