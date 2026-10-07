"""
The reputation gate (revamp T2c, A3-4)
======================================

A busy network looks up thousands of names an hour.  VirusTotal's free tier answers four a minute, and user scans share that
quota.  Anything that may cost a third-party call therefore goes through this gate, in this order, and **stops at the first stage that
can decide**:

1. **private / local filter** (``core/privacy``) — printer.local, single-label names, reverse DNS, private addresses are never sent
   anywhere (and IP literals are not looked up passively at all);
2. **TTL cache by registered domain** (eTLD+1) — ``cdn1.example.com`` and ``cdn2.example.com`` are one question;
3. **in-flight de-duplication** — fifty concurrent queries for one domain run one evaluation;
4. **local lists** — Tranco top-N = popular, *skip* (a prior, never a verdict); OpenPhish / PhishTank host listing = flagged, no
   third-party call needed;
5. **the local URL-text model** (free, ~1 ms) — below its flag threshold the name is left alone;
6. **VirusTotal**, only when the model flags the name **and** the network's own budget has room (``NETWORK_VT_PER_MINUTE``, default 1,
   a sub-budget of the shared VirusTotal limiter, so monitoring cannot starve a user's scans).  A cached VirusTotal answer costs
   nothing and gives the budget back.

What the verdict means (``AppLayerSubScore.corroborated``): a **cross-layer alert needs corroboration** — a list hit or at least two
VirusTotal engines.  A URL-text score alone is reported and never raises an alert by itself: at ~1 % false positives per name, thousands
of names a day would otherwise be thousands of false alarms.  When the budget is used up the result says so (``budget_exhausted``)
instead of pretending VirusTotal was asked.

``stats`` counts what each stage saved, so "1,000 queries → one VirusTotal call" is something the status page can show.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections import Counter, OrderedDict, deque
from typing import Any, Callable, Optional

from app.core import privacy
from app.core.config import get_settings
from app.ingestion.reputation import Subject
from app.ml.baseline import baseline_score
from app.ml.features import extract_features
from app.network.models import AppLayerSubScore

logger = logging.getLogger(__name__)

MIN_CORROBORATING_ENGINES = 2
MAX_CACHE = 20_000

_PRIVACY_REASON = {
    "private_name": "Private/local name",
    "single_label": "Single-label (local) name",
    "private_address": "Private IP address",
    "invalid_name": "Malformed name",
}


def unavailable_reason(name: str, res: Any) -> str:
    """Human-readable 'why there is no score' from a non-ok ProviderResult."""
    if res.status.value == "not_found":
        return f"{name} has no record of this target"
    detail = res.reason or res.status.value
    http = f" (HTTP {res.http_status})" if res.http_status else ""
    retry = f", retry in {int(res.retry_after)}s" if getattr(res, "retry_after", None) else ""
    return f"{name} lookup unavailable: {detail}{http}{retry}"


class VtBudget:
    """At most ``per_minute`` *uncached* VirusTotal lookups per rolling minute for the network layer (0 = none at all)."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic) -> None:
        self.per_minute = max(0, int(per_minute))
        self._clock = clock
        self._used: deque[float] = deque()

    def try_acquire(self) -> bool:
        now = self._clock()
        while self._used and now - self._used[0] >= 60.0:
            self._used.popleft()
        if len(self._used) >= self.per_minute:
            return False
        self._used.append(now)
        return True

    def refund(self) -> None:
        """A lookup answered from VirusTotal's own cache used no quota: give the slot back."""
        if self._used:
            self._used.pop()


def registered_domain_of(host: str) -> str:
    from app.core.targets import _extractor

    try:
        ext = _extractor()(host)
        return (ext.registered_domain or host).lower()
    except Exception:
        return host.lower()


class ReputationGate:
    def __init__(self, *, settings: Any = None, hub: Any = None, ml_provider: Optional[Callable[[], Any]] = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._settings = settings
        self._hub = hub
        self._ml_provider = ml_provider
        self._clock = clock
        self._cache: "OrderedDict[str, tuple[float, AppLayerSubScore]]" = OrderedDict()
        self._inflight: dict[str, "asyncio.Future[AppLayerSubScore]"] = {}
        self._budget: Optional[VtBudget] = None
        self.stats: Counter[str] = Counter()

    # ── lazily bound collaborators (the hub / settings can be rebuilt by tests) ──
    def _s(self) -> Any:
        return self._settings or get_settings()

    def _h(self) -> Any:
        if self._hub is not None:
            return self._hub
        from app.core.hub import hub

        return hub

    def _ml(self) -> Any:
        if self._ml_provider is not None:
            return self._ml_provider()
        from app.ml.runtime import url_risk_service

        return url_risk_service()

    def budget(self) -> VtBudget:
        per_minute = self._s().NETWORK_VT_PER_MINUTE
        if self._budget is None or self._budget.per_minute != max(0, int(per_minute)):
            self._budget = VtBudget(per_minute, self._clock)
        return self._budget

    def summary(self) -> dict[str, Any]:
        """What the stages saved — shown in /network/status."""
        s = self._s()
        return {**{k: self.stats[k] for k in ("names", "private", "cache_hits", "dedup_joins", "popular", "listed", "model_clear",
                                               "vt_calls", "budget_exhausted", "unavailable")},
                "vt_budget_per_minute": s.NETWORK_VT_PER_MINUTE, "cache_size": len(self._cache)}

    # ── public ──────────────────────────────────────────────────────────
    async def assess(self, name: str) -> AppLayerSubScore:
        s = self._s()
        self.stats["names"] += 1
        raw = (name or "").strip()
        use_mock = s.USE_MOCK_DATA
        base = dict(target=raw[:255], target_type="domain", live=not use_mock)

        blocked = privacy.provider_block_reason(raw)
        if blocked:
            self.stats["private"] += 1
            return AppLayerSubScore(available=False, source="private",
                                    reason=f"{_PRIVACY_REASON.get(blocked, blocked)} — not sent to third-party services", **base)
        if _is_ip(raw):
            self.stats["private"] += 1
            return AppLayerSubScore(available=False, source="private", reason="IP addresses are not looked up passively", **{**base, "target_type": "ip"})

        key = registered_domain_of(privacy.normalise_name(raw))
        now = self._clock()
        hit = self._cache.get(key)
        if hit is not None and hit[0] > now:
            self._cache.move_to_end(key)
            self.stats["cache_hits"] += 1
            cached = hit[1]
            return cached.model_copy(update={"target": raw[:255], "source": "cache", "cached_from": cached.cached_from or cached.source})

        pending = self._inflight.get(key)
        if pending is not None:
            self.stats["dedup_joins"] += 1
            result = await asyncio.shield(pending)
            return result.model_copy(update={"target": raw[:255]})

        loop = asyncio.get_running_loop()
        fut: "asyncio.Future[AppLayerSubScore]" = loop.create_future()
        self._inflight[key] = fut
        try:
            try:
                result = await self._assess_uncached(privacy.normalise_name(raw), key, base)
            except asyncio.CancelledError:
                raise
            except Exception as exc:                              # a bug must be a labelled gap, never a made-up verdict or a crash
                logger.exception("Reputation gate failed for %s", raw)
                result = AppLayerSubScore(available=False, source="unavailable", reason=f"reputation check failed: {type(exc).__name__}", **base)
                self.stats["unavailable"] += 1
            ttl = s.NETWORK_GATE_CACHE_SECONDS if result.available and result.source != "budget_exhausted" else s.NETWORK_GATE_RETRY_SECONDS
            self._cache[key] = (self._clock() + ttl, result)
            self._cache.move_to_end(key)
            while len(self._cache) > MAX_CACHE:
                self._cache.popitem(last=False)
            if not fut.done():
                fut.set_result(result)
            return result
        finally:
            self._inflight.pop(key, None)
            if not fut.done():
                fut.cancel()

    # ── the stages ──────────────────────────────────────────────────────
    async def _assess_uncached(self, name: str, key: str, base: dict) -> AppLayerSubScore:
        s, h = self._s(), self._h()
        use_mock = s.USE_MOCK_DATA
        rep = h.reputation()
        subject = Subject(kind="domain", host=name, registered_domain=key)

        # 4a. popular?  (Tranco is a prior: a popular name is skipped, never "cleared")
        rank: Optional[int] = None
        tranco = rep.clients.get("tranco")
        if tranco is not None and (use_mock or s.TRANCO_ENABLED):
            res = await tranco.lookup(subject)
            if res.ok and res.data is not None:
                rank = (res.data.extra or {}).get("rank")
                if rank is not None:
                    self.stats["popular"] += 1
                    return AppLayerSubScore(available=True, source="popular_domain", popularity_rank=int(rank),
                                            reason=f"ranked #{int(rank):,} in the Tranco popularity list — not checked further", **base)

        # 4b. a local blocklist names the host: flagged without any third-party call
        enabled = {"openphish": s.OPENPHISH_ENABLED, "phishtank": s.PHISHTANK_ENABLED}
        listed: list[str] = []
        for source in ("openphish", "phishtank"):
            client = rep.clients.get(source)
            if client is None or not (use_mock or enabled[source]):
                continue
            res = await client.lookup(subject)
            if res.ok and res.data is not None and res.data.listed:
                listed.append(source)
        if listed:
            self.stats["listed"] += 1
            return AppLayerSubScore(available=True, source="local_blocklist", flagged=True, corroborated=True, blocklists=listed,
                                    popularity_rank=rank, reason="a local blocklist lists this host", **base)

        # 5. the local URL-text model
        ml = self._ml()
        if not getattr(ml, "loaded", False):
            self.stats["unavailable"] += 1
            return AppLayerSubScore(available=False, source="unavailable", reason="the URL model is not loaded, so nothing is spent on this name", **base)
        assessment, _, _ = await asyncio.to_thread(ml.assess, name, False)
        url_fields = dict(ml_score=round(float(assessment.headline_score), 4), ml_label=ml.band(assessment.headline_score))
        if not assessment.flagged:
            self.stats["model_clear"] += 1
            return AppLayerSubScore(available=True, source="url_model_only", **url_fields, **base)

        # 6. flagged by the model: VirusTotal, if configured and the network's own budget allows
        _, explanations, _ = await asyncio.to_thread(ml.assess, name, True)
        top = [e.human_readable for e in explanations[:4]]
        if not s.provider_statuses()["virustotal"].configured:
            return AppLayerSubScore(available=True, source="url_model_only", top_explanations=top,
                                    reason="VirusTotal is not configured (set VIRUSTOTAL_API_KEY): URL model score only", **url_fields, **base)
        budget = self.budget()
        if not budget.try_acquire():
            self.stats["budget_exhausted"] += 1
            return AppLayerSubScore(available=True, source="budget_exhausted", top_explanations=top,
                                    reason=f"the network's VirusTotal budget ({budget.per_minute}/min) is used up: URL model score only",
                                    **url_fields, **base)
        try:
            vt_res = await asyncio.wait_for(h.virustotal().lookup_domain(name), timeout=float(s.NETWORK_VT_TIMEOUT_SECONDS))
        except asyncio.TimeoutError:
            self.stats["unavailable"] += 1
            return AppLayerSubScore(available=False, source="unavailable", top_explanations=top, reason="VirusTotal lookup timed out",
                                    **url_fields, **base)
        if getattr(vt_res, "cached", False):
            budget.refund()                                       # served from VirusTotal's cache: no quota was used
        else:
            self.stats["vt_calls"] += 1
        if not vt_res.ok:
            self.stats["unavailable"] += 1
            return AppLayerSubScore(available=False, source="unavailable", top_explanations=top,
                                    reason=unavailable_reason("VirusTotal", vt_res), **url_fields, **base)
        vt = vt_res.data
        malicious = getattr(vt, "malicious_count", 0) or 0
        suspicious = getattr(vt, "suspicious_count", 0) or 0
        corroborated = (malicious + suspicious) >= MIN_CORROBORATING_ENGINES
        return AppLayerSubScore(
            available=True, source="virustotal", baseline_score=round(float(baseline_score(extract_features(vt, None, None, None))), 4),
            vt_malicious_count=malicious, vt_total_engines=getattr(vt, "total_engines", 0) or 0, flagged=corroborated,
            corroborated=corroborated, top_explanations=top, popularity_rank=rank, **url_fields, **base)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False
