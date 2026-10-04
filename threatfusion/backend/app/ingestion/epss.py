"""
ThreatFusion – EPSS (Exploit Prediction Scoring System) client (B11)
====================================================================

EPSS (FIRST.org) estimates the **probability that a CVE is exploited in the wild in the next 30 days** and the CVE's
percentile among all scored CVEs.  It is the *likelihood* half of the picture CVSS lacks (CVSS = severity).

* ``GET https://api.first.org/data/v1/epss?cve=A,B,C`` — batched (``batch_size`` ids per request), only CVE ids are sent.
* Scores refresh daily, so answers are cached for a day (per CVE; a CVE EPSS has no row for is cached as ``not_found``
  too — brand-new CVEs get a score within a day or two).  A failure is never cached.
* Three-state: a CVE with no row is **absent** from the result — never ``0.0`` (an unscored CVE is not a harmless one).
  Status: ``ok`` (≥ 1 row; ``partial:ok/total`` if some batches failed) · ``not_found`` (answered, no rows) · ``error``
  (rate-limited / server error / timeout / unparseable) · ``skipped`` (no valid CVE ids).
* A 429's ``Retry-After`` is honoured through the shared limiter (like VirusTotal and NVD).
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
from app.models.schemas import EpssRow, ProviderResult, ProviderStatus

logger = logging.getLogger(__name__)

SOURCE = "epss"
DEFAULT_BASE_URL = "https://api.first.org/data/v1/epss"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class EpssResult(BaseModel):
    rows: dict[str, EpssRow] = Field(default_factory=dict)


def _mock_row(cve: str) -> Optional[EpssRow]:
    known = {"CVE-2021-44228": (0.94358, 0.99991), "CVE-2021-41773": (0.9421, 0.9998), "CVE-2014-0160": (0.9438, 0.9999)}
    if cve in known:
        e, p = known[cve]
    else:
        seed = sum(ord(c) for c in cve)
        e = round(((seed * 37) % 400) / 10000.0, 5)                 # 0 – 0.04: most CVEs are rarely exploited
        p = round(min(0.95, 0.15 + e * 15), 5)
    return EpssRow(epss=e, percentile=p, date="2026-10-03")


class EpssClient:
    def __init__(
        self,
        use_mock: bool = True,
        *,
        base_url: str = DEFAULT_BASE_URL,
        cache: Optional[ProviderCache] = None,
        limiter: Optional[QuotaLimiter] = None,
        batch_size: int = 100,
        cache_ttl: float = 24 * 3600.0,
        max_queue_seconds: float = 10.0,
        max_concurrency: int = 2,
        timeout: float = 15.0,
    ) -> None:
        self._use_mock = use_mock
        self._base_url = base_url
        self._cache = cache if cache is not None else ProviderCache()
        self._limiter = limiter if limiter is not None else QuotaLimiter(0, 0)
        self._batch = max(1, batch_size)
        self._ttl = cache_ttl
        self._max_queue = max_queue_seconds
        self._max_concurrency = max(1, max_concurrency)
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

    async def _fetch_batch(self, batch: list[str]) -> tuple[Optional[dict[str, EpssRow]], Optional[ProviderResult]]:
        """One request → ``(rows, None)`` (rows may be empty) or ``(None, failure)``."""
        wait = await self._limiter.acquire(max_wait=self._max_queue)
        if wait is not None:
            return None, prov.error(SOURCE, "rate_limited", retry_after=wait)
        started = prov.start_timer()
        client = await self._get_client()
        try:
            response = await client.get(self._base_url, params={"cve": ",".join(batch)})
        except Exception as exc:
            logger.warning("EPSS request failed: %s", exc)
            return None, prov.from_exception(SOURCE, exc, started=started)
        failure = prov.from_http_status(SOURCE, response.status_code, started=started)
        if failure is not None:
            if response.status_code == 429:
                seconds = prov.parse_retry_after(response.headers.get("retry-after"))
                self._limiter.penalize(seconds)
                failure = failure.model_copy(update={"retry_after": round(seconds, 1)})
            return None, failure
        try:
            rows: dict[str, EpssRow] = {}
            for item in response.json()["data"]:
                rows[str(item["cve"]).upper()] = EpssRow(
                    epss=float(item["epss"]), percentile=float(item["percentile"]), date=item.get("date"))
        except (ValueError, KeyError, TypeError):
            return None, prov.error(SOURCE, "parse_error", http_status=response.status_code, started=started)
        return rows, None

    async def lookup(self, cve_ids: list[str]) -> ProviderResult[EpssResult]:
        ids = list(dict.fromkeys(c.strip().upper() for c in cve_ids if c and _CVE.match(c.strip().upper())))
        if not ids:
            return prov.skipped(SOURCE, "no_cve_ids")
        if self._use_mock:
            rows = {c: r for c in ids if (r := _mock_row(c)) is not None}
            return prov.ok(SOURCE, EpssResult(rows=rows), http_status=None, mock=True)

        started = prov.start_timer()
        rows: dict[str, EpssRow] = {}
        misses: list[str] = []
        answered_absent = 0
        for cve in ids:
            try:
                cached = await self._cache.get(SOURCE, f"cve:{cve}", EpssRow)
            except Exception:
                logger.exception("provider cache read failed; continuing without it")
                cached = None
            if cached is None:
                misses.append(cve)
            elif cached.ok:
                rows[cve] = cached.data
            else:
                answered_absent += 1                              # cached "no row"
        from_cache = len(ids) - len(misses)

        batches = [misses[i:i + self._batch] for i in range(0, len(misses), self._batch)]
        gate = asyncio.Semaphore(self._max_concurrency)

        async def one(batch: list[str]):
            async with gate:
                return await self._fetch_batch(batch)

        outcomes = await asyncio.gather(*(one(b) for b in batches)) if batches else []
        failures: list[ProviderResult] = []
        for batch, (got, failure) in zip(batches, outcomes):
            if failure is not None:
                failures.append(failure)
                continue
            for cve in batch:
                if cve in got:
                    rows[cve] = got[cve]
                    await self._remember(cve, prov.ok(SOURCE, got[cve], http_status=200))
                else:
                    answered_absent += 1
                    await self._remember(cve, prov.not_found(SOURCE, http_status=200))

        if failures and not rows and not answered_absent:
            return failures[0].model_copy(update={"latency_ms": prov._latency_ms(started)})
        if failures:
            reason = f"partial:{len(batches) - len(failures)}/{len(batches)}"
        else:
            reason = None
        if not rows:
            return prov.not_found(SOURCE, http_status=None if not batches else 200, started=started)
        out = prov.ok(SOURCE, EpssResult(rows=rows), http_status=None if not batches else 200, started=started, reason=reason)
        return out.model_copy(update={"cached": True}) if not batches and from_cache else out

    async def _remember(self, cve: str, result: ProviderResult) -> None:
        try:
            await self._cache.put(SOURCE, f"cve:{cve}", result, ttl_ok=self._ttl, ttl_not_found=self._ttl)
        except Exception:
            logger.exception("provider cache write failed; continuing without it")
