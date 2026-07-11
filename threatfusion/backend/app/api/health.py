"""
Health-check endpoint.

This is intentionally the simplest router in the project — it exists so
that monitoring tools, Docker HEALTHCHECK directives, and the front-end
can verify the API is alive without authentication or heavy logic.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.config import get_settings

router = APIRouter(tags=["ops"])


# ── Response model ──────────────────────────────────────────────────────
class HealthResponse(BaseModel):
    """Schema returned by ``GET /health``.

    Exposing ``mock_mode`` in the health payload lets the dashboard UI
    display a banner to the user so they know they're looking at
    synthetic data.
    """

    status: str = Field(
        ...,
        examples=["healthy"],
        description="Simple liveness indicator.",
    )
    version: str = Field(
        ...,
        examples=["0.1.0"],
        description="Semantic version of the running API.",
    )
    mock_mode: bool = Field(
        ...,
        description="True when the API is returning mock/synthetic data.",
    )


# ── Endpoint ────────────────────────────────────────────────────────────
@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness probe",
    description="Returns the API status, version, and whether mock mode is active.",
)
async def health_check() -> HealthResponse:
    """Lightweight health check — no DB or external calls."""
    settings = get_settings()
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        mock_mode=settings.USE_MOCK_DATA,
    )
