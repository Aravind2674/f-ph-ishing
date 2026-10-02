"""
ThreatFusion – Traffic Analysis API  (Phase 3)
===============================================

``POST /traffic/analyze`` runs the neural HTTP attack classifier over a batch of
**captured** HTTP requests and returns risk-scored flows. Capture sources:

- a **HAR** export from Burp Suite / Chrome DevTools / OWASP ZAP (``har`` field);
- a normalised batch from the **mitmproxy** live-capture addon (``requests`` field).

The endpoint is passive: it scores traffic that was already captured and handed
to it. It never issues a request against a target.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter

from app.core.artifacts import model_path
from app.ml.vuln_classifier import VulnClassifier
from app.models.schemas import (
    RequestFindingModel,
    TrafficAnalyzeRequest,
    TrafficAnalyzeResponse,
    ValueFindingModel,
)
from app.recon.traffic import CapturedRequest, analyze_request, parse_har

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/traffic", tags=["traffic"])

# Reuse the same classifier the /analyze endpoint uses (graceful if untrained).
_clf = VulnClassifier()
_p = model_path("vuln_classifier.pt")  # configured model dir (absolute), not the CWD
if _p is not None:
    try:
        _clf.load(_p)
        logger.info("Traffic analyzer loaded classifier from %s", _p)
    except Exception as exc:  # incl. ArtifactIntegrityError  # pragma: no cover - defensive
        logger.warning("Failed to load vuln classifier: %s", exc)


@router.post("/analyze", response_model=TrafficAnalyzeResponse,
             summary="Score captured HTTP traffic (HAR or batch) for injection attacks")
async def analyze_traffic(request: TrafficAnalyzeRequest) -> TrafficAnalyzeResponse:
    """Classify every attacker-controlled value across a batch of captured requests."""
    if not _clf.is_loaded:
        return TrafficAnalyzeResponse(
            success=False, model_loaded=False,
            summary="Neural HTTP attack classifier is not loaded (train ml/train_vuln.py).",
            error="model_not_loaded",
        )

    # Normalise both input shapes to CapturedRequest.
    captured: list[CapturedRequest] = [
        CapturedRequest(method=r.method, url=r.url, headers=r.headers, body=r.body)
        for r in request.requests
    ]
    if request.har:
        captured.extend(parse_har(request.har))

    if not captured:
        return TrafficAnalyzeResponse(
            success=True, analyzed=0, flagged=0,
            summary="No requests supplied. Provide 'requests' or a 'har' export.",
        )

    findings: list[RequestFindingModel] = []
    for req in captured:
        rf = analyze_request(_clf, req)
        findings.append(
            RequestFindingModel(
                method=rf.method,
                url=rf.url,
                is_attack=rf.is_attack,
                worst_label=rf.worst_label,
                worst_location=rf.worst_location,
                worst_confidence=rf.worst_confidence,
                suspicious_span=rf.suspicious_span,
                values_analyzed=rf.values_analyzed,
                attack_values=rf.attack_values,
                details=[ValueFindingModel(**vars(d)) for d in rf.details],
            )
        )

    # Most severe requests first.
    from app.recon.traffic import SEVERITY
    findings.sort(key=lambda f: (SEVERITY.get(f.worst_label, 0), f.worst_confidence), reverse=True)

    flagged = sum(1 for f in findings if f.is_attack)
    if flagged:
        top = findings[0]
        summary = (
            f"{flagged} of {len(findings)} requests contain injection attempts. "
            f"Most severe: {top.worst_label.upper()} in {top.method} {top.url} "
            f"({top.worst_location}, {top.worst_confidence:.0%})."
        )
    else:
        summary = f"Analysed {len(findings)} requests — no injection patterns detected."

    return TrafficAnalyzeResponse(
        success=True, model_loaded=True,
        analyzed=len(findings), flagged=flagged,
        findings=findings, summary=summary,
    )
