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
class ProviderHealth(BaseModel):
    """Readiness of one data provider. Labels and booleans only — never credential values."""

    configured: bool = Field(..., description="True if the provider can be called")
    mock: bool = Field(..., description="True if served by the mock layer")
    state: str = Field(
        ...,
        description="configured | placeholder | missing | keyless | local | mock",
    )


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
    providers: dict[str, ProviderHealth] = Field(
        default_factory=dict,
        description="Per-provider readiness (A0-5). A provider that is not configured is "
                    "never called; scans list it under data_sources_skipped.",
    )
    models: dict[str, dict] = Field(
        default_factory=dict,
        description="ML model health (A2-6): status ok | disabled with the reason (integrity, missing card, schema "
                    "mismatch), plus the card's headline metrics and limitations.",
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
    from app.ml import model_cards
    from app.ml.runtime import url_risk_service

    settings = get_settings()
    models = url_risk_service().health()
    try:                                                         # the HTTP attack classifier's card (A2-4 / A2-6)
        card = model_cards.load_card("vuln_classifier")
        models["payload_classifier"] = ({**model_cards.summary(card, None), "held_out": (card.get("metrics") or {}).get("held_out_recall_correct_class")}
                                        if card else {"status": "no model card"})
    except Exception as exc:                                     # integrity failure etc.: reported, never swallowed
        models["payload_classifier"] = {"status": "disabled", "reason": f"{type(exc).__name__}"}
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        mock_mode=settings.USE_MOCK_DATA,
        providers={
            name: ProviderHealth(configured=st.configured, mock=st.mock, state=st.state)
            for name, st in settings.provider_statuses().items()
        },
        models=models,
    )
