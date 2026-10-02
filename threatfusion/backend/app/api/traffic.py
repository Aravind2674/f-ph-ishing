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

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool

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

from app.core.auth import require_token  # noqa: E402
from app.core import privacy
from app.core.config import get_settings

router = APIRouter(prefix="/traffic", tags=["traffic"], dependencies=[Depends(require_token)])

# Reuse the same classifier the /analyze endpoint uses (graceful if untrained).
_clf = VulnClassifier()
_p = model_path("vuln_classifier.pt")  # configured model dir (absolute), not the CWD
if _p is not None:
    try:
        _clf.load(_p)
        logger.info("Traffic analyzer loaded classifier from %s", _p)
    except Exception as exc:  # incl. ArtifactIntegrityError  # pragma: no cover - defensive
        logger.warning("Failed to load vuln classifier: %s", exc)


def _analyze_all(captured: list[CapturedRequest]) -> list[RequestFindingModel]:
    """Classify every captured request (blocking; call via ``run_in_threadpool``)."""
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
    return findings


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

    # Cap the amount of work BEFORE parsing/classifying anything (A0-9): a single call could otherwise
    # queue unbounded CNN inference. Requests in the batch and HAR entries count together.
    limit = get_settings().MAX_TRAFFIC_REQUESTS
    har_entries = []
    if isinstance(request.har, dict):
        log = request.har.get("log")
        har_entries = (log.get("entries") if isinstance(log, dict) else None) or []
    total = len(request.requests) + (len(har_entries) if isinstance(har_entries, list) else 0)
    if total > limit:
        raise HTTPException(
            status_code=413,
            detail=f"Too many requests in one call ({total}); the limit is {limit} (MAX_TRAFFIC_REQUESTS).",
        )

    # Normalise both input shapes to CapturedRequest.
    captured: list[CapturedRequest] = [
        CapturedRequest(method=r.method, url=r.url, headers=privacy.redact_headers(r.headers), body=r.body)
        for r in request.requests
    ]
    if request.har:
        captured.extend(parse_har(request.har))
    # Cookies / Authorization / API-key headers are never needed for classification: drop their values
    # before anything else touches the requests (A0-10; the mitm addon redacts them at the source too).
    for c in captured:
        c.headers = privacy.redact_headers(c.headers)

    if not captured:
        return TrafficAnalyzeResponse(
            success=True, analyzed=0, flagged=0,
            summary="No requests supplied. Provide 'requests' or a 'har' export.",
        )

    # CNN inference is CPU-bound and synchronous: run the whole batch in a worker thread so the event
    # loop (SSE heartbeat, other requests) is not stalled.
    findings = await run_in_threadpool(_analyze_all, captured)

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
