"""
The fast tier (B1)
==================

PhishIntel (arXiv 2412.09057) made heavy, reference-based phishing detection deployable by answering most URLs from local
blocklists and a cache and queueing only the unknown ones for slow analysis.  This module is that first answer: everything it
reads is **local** — nothing about the target is sent anywhere, no provider is called, no page is fetched:

1. the **canonical target** (``core/targets``), refusing private / local names;
2. the **local blocklist feeds** (OpenPhish, PhishTank) and the Tranco popularity prior (``ingestion/blocklists``);
3. the **brand-impersonation check** (B4: confusables, brand + keyword, brand in a subdomain);
4. the **URL-text models** (calibrated tree model + character CNN + fusion, ``ml/url_risk``) — without the SHAP evidence, which
   belongs to the slow tier;
5. a **recent full scan** of the same canonical target, if one is stored (the "cache").

The verdict is a transparent rule over those parts, never a hidden score:

=========  ================================================================================================
``block``  the exact URL / page is on a local phishing blocklist (a hit on the *host* only is a ``warn``)
``warn``   a look-alike of a protected brand, or the URL text is flagged at the FPR ≤ 1 % operating point,
           or the host serves other blocklisted pages
``info``   a protected brand's own domain (official) — or nothing found *and* a recent full scan exists
``none``   nothing found locally: **not** a clean bill of health — the slow tier may still find something
=========  ================================================================================================

Latency is measured and returned (``latency_ms``); the acceptance target is a p95 under 300 ms for listed or cached targets.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.core import privacy
from app.core.hub import hub
from app.core.targets import Target, canonicalize
from app.ingestion.reputation import Subject
from app.ml.lookalike import assess_lookalike
from app.ml.runtime import url_risk_service
from app.models.schemas import BrandCheck, FastVerdict, ReputationVerdict, TargetType

logger = logging.getLogger(__name__)

LOCAL_LISTS = ("openphish", "phishtank")
RECENT_SCAN_HOURS = 24


def _subject(target: Target, url: Optional[str]) -> Subject:
    kind = "url" if target.kind == TargetType.URL else "domain"
    return Subject(kind=kind, host=target.host, registered_domain=target.registered_domain, url=url if kind == "url" else None)


async def fast_check(raw: str, declared: Optional[TargetType] = None, *, send_full_url: bool = False,
                     recent_scan_lookup=None) -> FastVerdict:
    """Answer from local data only. ``recent_scan_lookup(canonical_key) -> Optional[dict]`` finds a stored full scan."""
    t0 = time.perf_counter()
    target = canonicalize(raw, declared)

    def done(**kw) -> FastVerdict:
        return FastVerdict(latency_ms=round((time.perf_counter() - t0) * 1000, 1), **kw)

    if not target.valid:
        return done(status="invalid", level="none", reasons=[target.problem or "not a valid target"], target_type=declared)
    if target.kind not in (TargetType.URL, TargetType.DOMAIN):
        return done(status="not_applicable", level="none", target_type=target.kind,
                    reasons=["The fast tier checks URLs and domains; IPs and hashes need the full scan."])
    blocked = privacy.provider_block_reason(target.host or "")
    if blocked:
        return done(status="not_assessable", level="none", target_type=target.kind,
                    reasons=["Private or local names are never checked against outside lists."], canonical_host=target.host)

    url = (target.url_full if send_full_url else target.url_public) or ""
    reasons: list[str] = []
    level = "none"
    listed: list[ReputationVerdict] = []

    # ── local lists (offline) ──
    rep = hub.reputation()
    subject = _subject(target, url)
    lookups = await asyncio.gather(*(rep.clients[s].lookup(subject) for s in (*LOCAL_LISTS, "tranco") if s in rep.clients))
    feed_gaps: list[str] = []
    rank: Optional[int] = None
    for res in lookups:
        if res.ok and res.data is not None:
            if res.source == "tranco":
                rank = (res.data.extra or {}).get("rank")
            elif res.data.listed:
                listed.append(res.data)
        elif res.source in LOCAL_LISTS and res.status.value == "error":
            feed_gaps.append(res.source)
    exact = [v for v in listed if v.match in ("exact_url", "url_path")]
    if exact:
        level = "block"
        reasons += [f"Listed by {', '.join(sorted(v.source for v in exact))} ({exact[0].match.replace('_', ' ')})."]
    elif listed:
        level = "warn"
        reasons += [f"The host serves other pages listed by {', '.join(sorted(v.source for v in listed))}."]

    # ── brand impersonation (B4) ──
    brand: Optional[BrandCheck] = None
    try:
        brand = assess_lookalike(target.host or "", await hub.brands())
    except Exception:
        logger.exception("fast tier: brand check failed")
    if brand is not None and brand.status == "lookalike" and brand.match is not None:
        level = level if level == "block" else "warn"
        reasons.append(f"Imitates {brand.match.brand} ({brand.match.kind.replace('_', ' ')}); the real site is {brand.match.brand_domain}.")

    # ── URL-text models (no SHAP here) ──
    risk = None
    ml = url_risk_service()
    if ml.loaded:
        try:
            risk, _, _ = await asyncio.to_thread(ml.assess, raw, False)
            if risk.flagged:
                level = level if level == "block" else "warn"
                reasons.append(f"The URL text looks like phishing ({round((risk.headline_score or 0) * 100)} %, flagged at "
                               f"the false-positive ≤ 1 % operating point).")
        except Exception:
            logger.exception("fast tier: URL model failed")

    # ── a recent full scan ──
    cached = None
    if recent_scan_lookup is not None:
        try:
            cached = await recent_scan_lookup(target)
        except Exception:
            logger.exception("fast tier: cache lookup failed")

    official = brand is not None and brand.status == "official"
    if level == "none" and official:
        level = "info"
        reasons.append(f"{brand.official_of}'s own domain.")
    if level == "none" and not reasons:
        reasons.append("Nothing found in the local checks. That is not a clean bill of health: the full scan may still find something.")
    status = {"block": "listed", "warn": "suspicious", "info": "official" if official else "info", "none": "nothing_found"}[level]
    return done(status=status, level=level, reasons=reasons, target_type=target.kind, canonical_host=target.host,
                registered_domain=target.registered_domain, listed_by=sorted({v.source for v in listed}), popularity_rank=rank,
                brand_check=brand, url_risk_score=None if risk is None else risk.headline_score,
                url_risk_flagged=None if risk is None else risk.flagged, list_gaps=feed_gaps, cached_scan=cached)


async def recent_scan_summary(store, target: Target, hours: int = RECENT_SCAN_HOURS) -> Optional[dict]:
    """The newest stored full scan of the same canonical target within ``hours`` (its id and headline), or ``None``."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    return await store.latest_for_target(target.host or "", since)
