"""
ThreatFusion – Active Verification API  (Phase 4)
==================================================

``POST /verify`` actively confirms suspected injection points on a target URL
using **non-destructive** probes (reflection canary, error and boolean SQLi
signals). It is **scope-gated**: it only probes localhost or a host the caller
explicitly authorises via ``authorized_hosts``; anything else is refused before
any request leaves the server.

This is the "simulate the attack and check" step — it verifies, it does not
exploit. See :mod:`app.verify.active` for the safety guarantees.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

from app.models.schemas import ProbeResultModel, VerifyRequest, VerifyResponse
from app.verify.active import ActiveVerifier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/verify", tags=["verify"])


@router.post("", response_model=VerifyResponse,
             summary="Actively confirm injection points on an authorised target")
async def verify(request: VerifyRequest) -> VerifyResponse:
    """Run scope-gated, non-destructive active confirmation on a target URL."""
    verifier = ActiveVerifier(authorized_hosts=set(request.authorized_hosts))
    report = await verifier.verify(request.target)

    if not report.authorized:
        return VerifyResponse(
            success=False, authorized=False, target=report.target,
            summary="Out of scope — target host not authorised for active testing.",
            error=report.error,
        )

    probes = [ProbeResultModel(**vars(p)) for p in report.probes]
    confirmed = [p for p in probes if p.confirmed]

    if confirmed:
        techniques = sorted({p.technique for p in confirmed})
        summary = (
            f"Confirmed {len(confirmed)} vulnerability(ies) across "
            f"{len({p.param for p in confirmed})} parameter(s): {', '.join(techniques)}."
        )
    elif report.error:
        summary = report.error
    else:
        summary = f"No vulnerabilities confirmed across {len(report.tested_params)} parameter(s)."

    return VerifyResponse(
        success=True, authorized=True, target=report.target,
        tested_params=report.tested_params,
        confirmed_count=len(confirmed), probes=probes,
        summary=summary, error=report.error,
    )
