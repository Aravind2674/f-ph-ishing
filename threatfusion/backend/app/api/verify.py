"""
ThreatFusion – Active Verification API  (Phase 4, hardened in A0-3)
====================================================================

``POST /verify`` actively confirms suspected injection points on a target URL using
**non-destructive** probes (reflection canary, error and boolean SQLi signals).

Scope and safety are **server-side**:

* ``VERIFY_ENABLED`` (default **false**) is the master switch;
* the allowlist is ``VERIFY_ALLOWED_HOSTS`` — ``authorized_hosts`` in the request body is **ignored**
  (it used to let the caller authorise themselves; audit §H1);
* every request leaves through the SSRF-safe fetcher (validated, pinned IP; no redirects; TLS verified);
* runs are rate-limited per host (``VERIFY_RATE_PER_MINUTE``);
* every call — including refused ones — appends a row to ``verify_audit``.

This is the "simulate the attack and check" step: it verifies, it does not exploit.
See :mod:`app.verify.active` for the safety guarantees.
"""

from __future__ import annotations

import logging
import math
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Depends

from app.core.audit import ensure_verify_audit_schema, record_verify_call
from app.core.auth import require_token
from app.core.config import get_settings
from app.core.ratelimit import SlidingWindowLimiter
from app.models.schemas import ProbeResultModel, VerifyRequest, VerifyResponse
from app.verify.active import ActiveVerifier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/verify", tags=["verify"], dependencies=[Depends(require_token)])

# Per-target-host run limiter (process-local).
RATE_LIMITER = SlidingWindowLimiter(window_seconds=60.0)

_IGNORED_NOTICE = (
    "`authorized_hosts` in the request is ignored: the scope of active verification is "
    "configured on the server (VERIFY_ALLOWED_HOSTS), never by the caller."
)


@router.post("", response_model=VerifyResponse,
             summary="Actively confirm injection points on a server-authorised target")
async def verify(request: VerifyRequest) -> VerifyResponse:
    """Run scope-gated, non-destructive active confirmation on a target URL."""
    settings = get_settings()
    target = request.target

    notice = None
    if request.authorized_hosts:
        logger.warning("Ignoring caller-supplied authorized_hosts %s for /verify (scope is server config)",
                       request.authorized_hosts)
        notice = _IGNORED_NOTICE

    parts = urlsplit(target)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        port = None

    # ── 1. Master switch ────────────────────────────────────────────────
    if not settings.VERIFY_ENABLED:
        await record_verify_call(target=target, host=host, outcome="disabled",
                                 detail="VERIFY_ENABLED is false")
        return VerifyResponse(
            success=False, authorized=False, target=target, notice=notice,
            summary="Active verification is disabled on this server.",
            error="verify_disabled",
        )

    verifier = ActiveVerifier(allowed_hosts=settings.verify_allowed_hosts,
                              verify_tls=settings.VERIFY_TLS)

    # ── 2. Scope (server-configured allowlist) ──────────────────────────
    if not verifier.in_scope(host, port):
        await record_verify_call(target=target, host=host, outcome="refused_scope",
                                 detail="host not in VERIFY_ALLOWED_HOSTS")
        return VerifyResponse(
            success=False, authorized=False, target=target, notice=notice,
            summary="Out of scope — target host not authorised for active testing on this server.",
            error=f"Refusing to probe '{host}': not listed in VERIFY_ALLOWED_HOSTS.",
        )

    # ── 3. Rate limit (per target host) ─────────────────────────────────
    allowed, retry_after = RATE_LIMITER.check(host, settings.VERIFY_RATE_PER_MINUTE)
    if not allowed:
        await record_verify_call(target=target, host=host, outcome="rate_limited",
                                 detail=f"retry in {retry_after:.0f}s")
        raise HTTPException(
            status_code=429,
            detail=f"Too many verification runs against {host}; retry in {math.ceil(retry_after)}s.",
            headers={"Retry-After": str(math.ceil(retry_after))},
        )

    # ── 4. Fail closed if the audit log cannot be written ───────────────
    try:
        await ensure_verify_audit_schema()
    except Exception:
        logger.exception("verify_audit unavailable — refusing to run active probes")
        raise HTTPException(status_code=503, detail="Audit log unavailable; refusing to run active probes.")

    # ── 5. Probe ────────────────────────────────────────────────────────
    report = await verifier.verify(target)
    probes = [ProbeResultModel(**vars(p)) for p in report.probes]
    confirmed = [p for p in probes if p.confirmed]

    if report.blocked:
        outcome = "blocked"
    elif report.error and not report.probes and not report.tested_params:
        outcome = "error"
    else:
        outcome = "completed"
    await record_verify_call(
        target=target, host=host, outcome=outcome,
        checks_run=report.checks_run,
        resolved_ip=report.resolved_ip, confirmed_count=len(confirmed),
        detail=report.error,
    )

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
        success=True, authorized=True, target=report.target, notice=notice,
        tested_params=report.tested_params,
        confirmed_count=len(confirmed), probes=probes,
        summary=summary, error=report.error,
    )
