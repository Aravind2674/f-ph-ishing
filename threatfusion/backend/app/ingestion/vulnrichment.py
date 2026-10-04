"""
ThreatFusion – CISA Vulnrichment (SSVC decision points) client (B11)
====================================================================

CISA's **Vulnrichment** program adds an *ADP container* (``providerMetadata.shortName == "CISA-ADP"``) to CVE JSON 5
records.  Its ``ssvc`` metric carries the decision points CISA assigned:

* **Exploitation** — ``none`` | ``poc`` | ``active``
* **Automatable** — ``yes`` | ``no``
* **Technical Impact** — ``partial`` | ``total``

We read them from the CVE Services API (``GET https://cveawg.mitre.org/api/cve/{CVE}``; only the CVE id is sent), one
request per CVE, bounded in concurrency and count (``max_concurrency`` / ``max_cves``) and cached (a week for an answer, a
day for "not enriched"; a failure never).

Three-state: a CVE CISA has not enriched (no CISA-ADP container, or 404) is **absent** from the result — it is *not* "no
exploitation".  ``ok`` (≥ 1 row, ``partial:answered/asked`` if some requests failed) · ``not_found`` (every CVE answered, none
enriched) · ``error`` · ``skipped``.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

import httpx
from pydantic import BaseModel, Field

from app.core import providers as prov
from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.models.schemas import ProviderResult, ProviderStatus, SsvcRow

logger = logging.getLogger(__name__)

SOURCE = "vulnrichment"
DEFAULT_BASE_URL = "https://cveawg.mitre.org/api/cve"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class VulnrichmentResult(BaseModel):
    rows: dict[str, SsvcRow] = Field(default_factory=dict)


def parse_ssvc(record: dict) -> Optional[SsvcRow]:
    """The SSVC decision points of the CISA-ADP container, or ``None`` if CISA has not enriched this CVE."""
    for adp in (record.get("containers") or {}).get("adp") or []:
        if (adp.get("providerMetadata") or {}).get("shortName") != "CISA-ADP":
            continue
        for metric in adp.get("metrics") or []:
            other = metric.get("other") or {}
            if other.get("type") != "ssvc":
                continue
            content = other.get("content") or {}
            points: dict[str, str] = {}
            for option in content.get("options") or []:
                if isinstance(option, dict):
                    for key, value in option.items():
                        points[str(key).lower().replace(" ", "_")] = str(value).lower()
            if points:
                return SsvcRow(exploitation=points.get("exploitation"), automatable=points.get("automatable"),
                               technical_impact=points.get("technical_impact"), timestamp=content.get("timestamp"))
    return None


_MOCK = {
    "CVE-2021-44228": SsvcRow(exploitation="active", automatable="yes", technical_impact="total", timestamp="2026-09-30T12:00:00Z"),
    "CVE-2021-41773": SsvcRow(exploitation="active", automatable="yes", technical_impact="partial", timestamp="2026-09-30T12:00:00Z"),
    "CVE-2014-0160": SsvcRow(exploitation="active", automatable="yes", technical_impact="partial", timestamp="2026-09-30T12:00:00Z"),
}


class VulnrichmentClient:
    def __init__(
        self,
        use_mock: bool = True,
        *,
        base_url: str = DEFAULT_BASE_URL,
        cache: Optional[ProviderCache] = None,
        limiter: Optional[QuotaLimiter] = None,
        cache_ttl: float = 7 * 24 * 3600.0,
        not_found_ttl: float = 24 * 3600.0,
        max_concurrency: int = 5,
        max_cves: int = 25,
        max_queue_seconds: float = 10.0,
        timeout: float = 15.0,
    ) -> None:
        self._use_mock = use_mock
        self._base_url = base_url.rstrip("/")
        self._cache = cache if cache is not None else ProviderCache()
        self._limiter = limiter if limiter is not None else QuotaLimiter(0, 0)
        self._ttl = cache_ttl
        self._not_found_ttl = not_found_ttl
        self._max_concurrency = max(1, max_concurrency)
        self._max_cves = max(1, max_cves)
        self._max_queue = max_queue_seconds
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._client_loop: Optional[asyncio.AbstractEventLoop] = None

    async def _get_client(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is None or self._client_loop is not loop:
            self._client = httpx.AsyncClient(timeout=self._timeout, headers={"Accept": "application/json"})
            self._client_loop = loop
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except RuntimeError:
                pass
            self._client = None
            self._client_loop = None

    async def _one(self, cve: str) -> ProviderResult[SsvcRow]:
        key = f"cve:{cve}"
        try:
            cached = await self._cache.get(SOURCE, key, SsvcRow)
        except Exception:
            logger.exception("provider cache read failed; continuing without it")
            cached = None
        if cached is not None:
            return cached
        wait = await self._limiter.acquire(max_wait=self._max_queue)
        if wait is not None:
            return prov.error(SOURCE, "rate_limited", retry_after=wait)
        started = prov.start_timer()
        client = await self._get_client()
        try:
            response = await client.get(f"{self._base_url}/{cve}")
        except Exception as exc:
            logger.warning("Vulnrichment request failed for %s: %s", cve, exc)
            return prov.from_exception(SOURCE, exc, started=started)
        failure = prov.from_http_status(SOURCE, response.status_code, started=started)
        if failure is not None:
            if response.status_code == 429:
                seconds = prov.parse_retry_after(response.headers.get("retry-after"))
                self._limiter.penalize(seconds)
                failure = failure.model_copy(update={"retry_after": round(seconds, 1)})
                return failure
            result = failure
        else:
            try:
                row = parse_ssvc(response.json())
            except (ValueError, TypeError, AttributeError):
                return prov.error(SOURCE, "parse_error", http_status=response.status_code, started=started)
            result = (prov.ok(SOURCE, row, http_status=response.status_code, started=started) if row is not None
                      else prov.not_found(SOURCE, http_status=response.status_code, started=started))
        try:
            await self._cache.put(SOURCE, key, result, ttl_ok=self._ttl, ttl_not_found=self._not_found_ttl)
        except Exception:
            logger.exception("provider cache write failed; continuing without it")
        return result

    async def lookup(self, cve_ids: list[str]) -> ProviderResult[VulnrichmentResult]:
        ids = list(dict.fromkeys(c.strip().upper() for c in cve_ids if c and _CVE.match(c.strip().upper())))
        if not ids:
            return prov.skipped(SOURCE, "no_cve_ids")
        if self._use_mock:
            rows = {c: _MOCK[c] for c in ids if c in _MOCK}
            return prov.ok(SOURCE, VulnrichmentResult(rows=rows), http_status=None, mock=True)

        ids = ids[: self._max_cves]
        started = prov.start_timer()
        gate = asyncio.Semaphore(self._max_concurrency)

        async def bounded(cve: str) -> ProviderResult[SsvcRow]:
            async with gate:
                return await self._one(cve)

        results = await asyncio.gather(*(bounded(c) for c in ids))
        rows = {c: r.data for c, r in zip(ids, results) if r.ok}
        failures = [r for r in results if r.status == ProviderStatus.ERROR]
        answered = len(ids) - len(failures)
        if rows:
            reason = f"partial:{answered}/{len(ids)}" if failures else None
            out = prov.ok(SOURCE, VulnrichmentResult(rows=rows), http_status=200, started=started, reason=reason)
            return out.model_copy(update={"cached": True}) if all(r.cached for r in results if not r.status == ProviderStatus.ERROR) and not failures else out
        if failures:
            return failures[0].model_copy(update={"latency_ms": prov._latency_ms(started)})
        return prov.not_found(SOURCE, http_status=200, started=started)
