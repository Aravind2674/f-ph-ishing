"""
ThreatFusion – Traffic Capture & Analysis  (Phase 3)
=====================================================

Turns captured HTTP traffic into risk-scored flows by running the Phase 2 neural
attack classifier over every request. This is the "the model reads the request
packets" layer: whatever the capture source — a **HAR export** (Burp / Chrome
DevTools / OWASP ZAP all speak HAR), a **mitmproxy** live stream, or a manual
batch — it is normalised into :class:`CapturedRequest` and each attacker-controlled
value (query params, URL path, body params) is classified.

Nothing here makes an outbound request against a target. It analyses traffic that
has already been captured and handed to it. Active, scope-gated probing is a
later phase.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from app.ml.vuln_classifier import VulnClassifier

# Severity ranking shared with the /analyze endpoint semantics.
SEVERITY = {"cmdi": 4, "sqli": 3, "xss": 2, "path-traversal": 1, "benign": 0}


@dataclass
class CapturedRequest:
    """A single captured HTTP request, normalised across capture sources."""

    method: str = "GET"
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None

    @property
    def content_type(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                return v.lower()
        return ""


@dataclass
class ValueFinding:
    """Classifier verdict for one attacker-controlled value within a request."""

    location: str
    value: str
    label: str
    is_attack: bool
    confidence: float
    suspicious_span: Optional[str]


@dataclass
class RequestFinding:
    """Aggregated verdict for a whole request (its worst value)."""

    method: str
    url: str
    is_attack: bool
    worst_label: str
    worst_location: str
    worst_confidence: float
    suspicious_span: Optional[str]
    values_analyzed: int
    attack_values: int
    details: List[ValueFinding]


# ── HAR parsing ─────────────────────────────────────────────────────────────
def parse_har(har: dict) -> List[CapturedRequest]:
    """Extract :class:`CapturedRequest` objects from a HAR document.

    HAR (HTTP Archive) is the JSON format exported by Chrome/Firefox DevTools,
    Burp Suite, and OWASP ZAP, so this single parser accepts traffic from any of
    them. Malformed entries are skipped rather than aborting the whole batch.
    """
    out: List[CapturedRequest] = []
    entries = (har or {}).get("log", {}).get("entries", [])
    for entry in entries:
        req = entry.get("request") or {}
        url = req.get("url")
        if not url:
            continue
        headers = {h.get("name", ""): h.get("value", "") for h in req.get("headers", [])}
        body = None
        post = req.get("postData")
        if isinstance(post, dict):
            body = post.get("text")
            if body is None and post.get("params"):
                # Reconstruct a form body from HAR's structured params.
                body = "&".join(
                    f"{p.get('name','')}={p.get('value','')}" for p in post["params"]
                )
        out.append(
            CapturedRequest(
                method=(req.get("method") or "GET").upper(),
                url=url,
                headers=headers,
                body=body,
            )
        )
    return out


# ── Value extraction ────────────────────────────────────────────────────────
def _iter_form_pairs(text: str) -> Iterable[Tuple[str, str]]:
    yield from parse_qsl(text, keep_blank_values=True)


def _iter_json_values(obj, prefix: str = "") -> Iterable[Tuple[str, str]]:
    """Yield ``(json-path, value)`` for every scalar in a decoded JSON body."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _iter_json_values(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _iter_json_values(v, f"{prefix}[{i}]")
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        yield prefix or "value", str(obj)


def extract_values(req: CapturedRequest) -> List[Tuple[str, str]]:
    """Return ``(location, value)`` pairs of attacker-controlled inputs.

    Covers URL query parameters, the URL path, and the request body (form-encoded
    or JSON). These are the surfaces an injection attack rides in on.
    """
    out: List[Tuple[str, str]] = []
    seen: set = set()

    def add(location: str, value: str) -> None:
        if value and value not in seen:
            out.append((location, value))
            seen.add(value)

    parts = urlsplit(req.url)
    for key, val in parse_qsl(parts.query, keep_blank_values=True):
        add(f"query:{key}", val)
    if parts.path and parts.path not in ("/", ""):
        add("path", parts.path)

    if req.body:
        ctype = req.content_type
        if "application/json" in ctype:
            try:
                for path, val in _iter_json_values(json.loads(req.body)):
                    add(f"body:{path}", val)
            except (ValueError, TypeError):
                add("body", req.body)
        elif "application/x-www-form-urlencoded" in ctype or "=" in req.body:
            for key, val in _iter_form_pairs(req.body):
                add(f"body:{key}", val)
        else:
            add("body", req.body)

    return out


# ── Analysis ────────────────────────────────────────────────────────────────
def analyze_request(clf: VulnClassifier, req: CapturedRequest) -> RequestFinding:
    """Classify every value in a request and aggregate to a request-level verdict."""
    details: List[ValueFinding] = []
    for location, value in extract_values(req):
        result = clf.classify(value)
        is_attack = result["class_id"] != 0
        span = None
        if is_attack:
            spans = clf.suspicious_span(value, result["class_id"])
            span = spans[0] if spans else None
        details.append(
            ValueFinding(
                location=location,
                value=value,
                label=result["label"],
                is_attack=is_attack,
                confidence=round(result["confidence"], 4),
                suspicious_span=span,
            )
        )

    details.sort(key=lambda d: (SEVERITY.get(d.label, 0), d.confidence), reverse=True)
    worst = details[0] if details else None
    attack_values = sum(1 for d in details if d.is_attack)

    return RequestFinding(
        method=req.method,
        url=req.url,
        is_attack=bool(worst and worst.is_attack),
        worst_label=worst.label if worst else "benign",
        worst_location=worst.location if worst else "",
        worst_confidence=worst.confidence if worst else 0.0,
        suspicious_span=worst.suspicious_span if worst else None,
        values_analyzed=len(details),
        attack_values=attack_values,
        details=details,
    )
