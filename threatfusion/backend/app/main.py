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

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings, log_provider_table, startup_warnings
from app.core.auth import get_api_token, log_token_location
from app.core.db import init_db
from app.core.security import SecurityMiddleware
from app.core.logging import setup_logging, get_logger

logger = get_logger(__name__)

_RETENTION_INTERVAL_SECONDS = 6 * 3600


async def _retention_loop(service) -> None:
    """Purge network data older than NETWORK_RETENTION_DAYS (at startup, then periodically)."""
    while True:
        try:
            days = get_settings().NETWORK_RETENTION_DAYS
            counts = await service.purge(days)
            if any(counts.values()):
                logger.info("Retention purge (%d days): removed %s", days, counts)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Retention purge failed")
        await asyncio.sleep(_RETENTION_INTERVAL_SECONDS)


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
    # Which providers can actually be called (configured / placeholder / missing) — never values.
    log_provider_table(settings)
    
    # Step 2b: make sure an API token exists (generated once, stored outside the repo) and tell the
    # operator WHERE it is — never what it is.
    get_api_token()
    log_token_location()

    # Step 3: Initialize the database — create/upgrade the schema with versioned, in-place
    # migrations (core/db.py). The path is absolute (see Settings.database_path).
    db_path = settings.database_path
    await init_db(db_path)
    logger.info("Database ready: %s", db_path)

    # Step 4: Initialize the Network Layer (baseline store + alert tables).
    # This is always initialised so the API can serve status/history even
    # before live capture is started. Capture itself only begins when
    # NETWORK_AUTO_START is true (needs Npcap + an elevated process) or when
    # the operator calls POST /network/monitor/start.
    from app.network.service import get_service
    net_service = get_service()
    await net_service.init()
    # Retention (A0-10): purge old per-device browsing history now and every few hours.
    retention_task = asyncio.create_task(_retention_loop(net_service), name="net-retention")

    if settings.NETWORK_AUTO_START:
        logger.info("NETWORK_AUTO_START=true — starting capture")
        await net_service.start()

    logger.info("🚀 ThreatFusion API ready (mock_mode=%s)", settings.USE_MOCK_DATA)

    yield  # Application runs here

    # Shutdown cleanup — stop capture threads if running.
    retention_task.cancel()
    try:
        await net_service.stop()
    except Exception:
        logger.exception("Error stopping network monitor during shutdown")
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

# Request guards (Host allow-list, JSON-only mutations) — added BEFORE CORS so that CORS is the outermost
# layer and its headers are present on 400/415 responses too.
app.add_middleware(SecurityMiddleware)

# CORS middleware — allow Vite/React dev origins.
# Note: allow_origins=["*"] is incompatible with allow_credentials=True
# in browsers, which surfaces as a CORS failure on fetch.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    # No cookies/credentials are used: access is by Bearer token, so credentialed CORS is off.
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Register route handlers
from app.api.health import router as health_router
from app.api.scan import router as scan_router
from app.api.analyze import router as analyze_router
from app.api.traffic import router as traffic_router
from app.api.verify import router as verify_router
from app.api.network import router as network_router, stream_router

app.include_router(health_router)
app.include_router(scan_router)
app.include_router(analyze_router)
app.include_router(traffic_router)
app.include_router(verify_router)
app.include_router(network_router)
app.include_router(stream_router)
