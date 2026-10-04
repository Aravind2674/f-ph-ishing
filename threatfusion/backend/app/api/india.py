"""
India-specific citizen endpoints (B16)

``POST /india/analyze-text``   — read a pasted message (SMS / WhatsApp / call script) and say which known scam patterns it resembles
``POST /india/report-kit``     — a pre-filled report and the right official channels (nothing is submitted for the user)
``GET  /scan/{id}/report-kit`` — the same, prepared from a stored scan (lives in this router for tidiness: ``/india/scan/{id}/report-kit``)

Everything here is local: the text is analysed in this process and is neither stored nor sent anywhere.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.auth import require_token
from app.core.hub import hub
from app.core.ratelimit import scan_rate_limit
from app.core.scan_store import ScanStore
from app.india.report_kit import ReportKind, ReportKit, build_report_kit
from app.india.scam_patterns import TextAnalysis, analyze_text

router = APIRouter(prefix="/india", tags=["india"], dependencies=[Depends(require_token)])
_store = ScanStore()


class AnalyzeTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000, description="The message or page text to read")
    language: str = Field("en", description="Only 'en' today; other values are answered in English with a note")


class AnalyzeTextResponse(BaseModel):
    success: bool = True
    analysis: TextAnalysis
    notes: list[str] = Field(default_factory=list)


class ReportKitRequest(BaseModel):
    kind: ReportKind = "website"
    host: Optional[str] = Field(None, max_length=253)
    url: Optional[str] = Field(None, max_length=2048)
    reasons: list[str] = Field(default_factory=list, max_length=10)
    brand: Optional[str] = Field(None, max_length=100)
    brand_domain: Optional[str] = Field(None, max_length=253)
    message_excerpt: Optional[str] = Field(None, max_length=2000)
    lost_money: bool = False


@router.post("/analyze-text", response_model=AnalyzeTextResponse, summary="Which known scam patterns does this message resemble?",
             dependencies=[Depends(scan_rate_limit)])
async def analyze_message(body: AnalyzeTextRequest) -> AnalyzeTextResponse:
    index = await hub.brands()
    notes = [] if body.language == "en" else ["Only English is available today; this answer is in English."]
    return AnalyzeTextResponse(analysis=analyze_text(body.text, index), notes=notes)


@router.post("/report-kit", response_model=ReportKit, summary="Prepare a report and list the right channels (submits nothing)")
async def report_kit(body: ReportKitRequest) -> ReportKit:
    return build_report_kit(body.kind, host=body.host, url=body.url, reasons=body.reasons, brand=body.brand, brand_domain=body.brand_domain,
                            message_excerpt=body.message_excerpt, lost_money=body.lost_money)


@router.get("/scan/{scan_id}/report-kit", response_model=ReportKit, summary="Report kit prepared from a stored scan")
async def report_kit_for_scan(scan_id: str, lost_money: bool = False) -> ReportKit:
    result = await _store.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    reasons: list[str] = []
    brand = domain = None
    check = result.brand_check
    if check is not None and check.match is not None:
        brand, domain = check.match.brand, check.match.brand_domain
        reasons.append(f"The domain imitates {brand} ({check.match.kind.replace('_', ' ')}).")
    if result.reputation and result.reputation.listed_by:
        reasons.append("Listed by: " + ", ".join(result.reputation.listed_by) + ".")
    if result.url_risk and result.url_risk.flagged:
        reasons.append("The URL text looks like phishing to the URL model.")
    if result.rdap and result.rdap.registered_at:
        reasons.append(f"The domain was registered on {result.rdap.registered_at.date().isoformat()}.")
    host = result.canonical.host if result.canonical else None
    return build_report_kit("website", host=host, url=result.canonical.url if result.canonical else None, reasons=reasons or ["Flagged by a ThreatFusion scan."],
                            brand=brand, brand_domain=domain, scan_id=scan_id, lost_money=lost_money)
