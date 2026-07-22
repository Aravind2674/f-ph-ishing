"""
ThreatFusion – Request Analysis API  (Phase 2)
===============================================

``POST /analyze`` runs the neural HTTP attack classifier over a submitted value
— a single parameter, a raw query string, or a full URL — and returns a per-value
verdict (benign / sqli / xss / path-traversal / cmdi) with confidence and the
suspicious substring that drove an attack verdict.

This is deliberately **passive**: it only classifies text the caller hands it and
never makes a network request against a target. Active, scope-gated probing of a
live target is a later phase.
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter

from app.ml.vuln_classifier import VulnClassifier
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, PayloadFinding

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analyze", tags=["analyze"])

# ── Model init (graceful — endpoint still responds if checkpoint is missing) ──
_clf = VulnClassifier()
for _p in (Path("ml/models/vuln_classifier.pt"), Path("../ml/models/vuln_classifier.pt")):
    if _p.exists():
        try:
            _clf.load(_p)
            logger.info("Vuln classifier loaded from %s", _p)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to load vuln classifier: %s", exc)
        break


def _candidates(text: str) -> list[tuple[str, str]]:
    """Extract ``(location, value)`` pairs to classify from the input.

    Always includes the whole string ('full'); if it parses as a URL/query with
    parameters, each parameter value is added as ``param:<name>``. A path with
    ``/`` segments beyond the host is also surfaced so path-traversal in the path
    itself is caught.
    """
    out: list[tuple[str, str]] = [("full", text)]
    seen = {text}

    parts = urlsplit(text if "://" in text else f"//{text}", scheme="http")
    for key, val in parse_qsl(parts.query, keep_blank_values=True):
        if val and val not in seen:
            out.append((f"param:{key}", val))
            seen.add(val)
    if parts.path and parts.path not in ("/", "") and parts.path not in seen:
        out.append(("path", parts.path))
        seen.add(parts.path)
    return out


# Severity ordering for sorting findings (higher = worse).
_SEVERITY = {"cmdi": 4, "sqli": 3, "xss": 2, "path-traversal": 1, "benign": 0}


@router.post("", response_model=AnalyzeResponse, summary="Classify request text for injection attacks")
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """Classify a payload / query string / URL for injection patterns."""
    if not _clf.is_loaded:
        return AnalyzeResponse(
            success=False,
            model_loaded=False,
            findings=[],
            summary="Neural HTTP attack classifier is not loaded (train ml/train_vuln.py).",
            error="model_not_loaded",
        )

    findings: list[PayloadFinding] = []
    for location, value in _candidates(request.text):
        result = _clf.classify(value)
        is_attack = result["class_id"] != 0
        span = None
        if is_attack:
            spans = _clf.suspicious_span(value, result["class_id"])
            span = spans[0] if spans else None
        findings.append(
            PayloadFinding(
                input=value,
                location=location,
                label=result["label"],
                is_attack=is_attack,
                confidence=round(result["confidence"], 4),
                suspicious_span=span,
                probs={k: round(v, 4) for k, v in result["probs"].items()},
            )
        )

    # Most severe first, then by confidence.
    findings.sort(key=lambda f: (_SEVERITY.get(f.label, 0), f.confidence), reverse=True)

    worst = findings[0] if findings else None
    if worst and worst.is_attack:
        summary = (
            f"Detected {worst.label.upper()} in {worst.location} "
            f"({worst.confidence:.0%} confidence)"
            + (f" — token '{worst.suspicious_span}'." if worst.suspicious_span else ".")
        )
    else:
        summary = "No injection patterns detected."

    return AnalyzeResponse(success=True, model_loaded=True, findings=findings, summary=summary)
