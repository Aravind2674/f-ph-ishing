"""
ThreatFusion – VirusTotal Ingestion Client
==========================================

Wraps the **VirusTotal v3 REST API** behind a clean async interface that
returns ``ProviderResult[VirusTotalResult]`` (A0-1): the normalised data *plus* an explicit
status (ok / not_found / error …), HTTP status, reason code, timestamp, cached flag and
latency.  A failed lookup is **never** turned into an empty ``VirusTotalResult`` — that
was the audit's root cause of "an outage looks like a clean target".

Key endpoints used
------------------
* ``GET /api/v3/domains/{domain}``      – domain reputation & last analysis.
* ``GET /api/v3/ip_addresses/{ip}``    – IP reputation (IPs used to be sent to ``/domains/``; A1-1).
* ``GET /api/v3/urls/{url_id}``         – URL reputation (url_id = base64).
* ``GET /api/v3/files/{hash}``          – file‑hash lookup (MD5/SHA‑1/SHA‑256).

Quota, cache, lifetime (A1-1)
-----------------------------
The free VT tier allows **4 requests / minute and 500 / day**.  One process-wide client (``core/hub.py``) is
shared by every scan *and* the network layer, together with one :class:`~app.core.quota.QuotaLimiter`:

* every network call first takes a slot; a caller that would have to wait longer than ``max_queue_seconds`` gets
  ``error / rate_limited`` (+ ``retry_after``) immediately instead of hanging until the scan deadline;
* a 429 is surfaced the same way and its ``Retry-After`` is *honoured* — the limiter blocks every later caller
  for that long, so a burst can't keep hammering a provider that just said "stop";
* answers (ok / not_found) are cached in SQLite (``core/cache.py``) and cost no quota; failures never are.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional, Any

import httpx

from app.core import privacy
from app.core import providers as prov
from app.core.cache import ProviderCache, url_key
from app.core.quota import QuotaLimiter
from app.models.schemas import ProviderResult, ProviderStatus, VirusTotalResult

logger = logging.getLogger(__name__)

SOURCE = "virustotal"


DEFAULT_RETRY_AFTER = 60.0          # used when a 429 carries no (usable) Retry-After
MAX_RETRY_AFTER = 24 * 3600.0


class _NoAnalysis(Exception):
    """VT knows the object but has no AV analysis for it (empty/missing last_analysis_stats)."""


def parse_retry_after(value: Optional[str], *, now: Optional[datetime] = None) -> float:
    """Seconds to back off from a ``Retry-After`` header (delta-seconds or an HTTP-date, RFC 9110 §10.2.3).

    A missing, negative, zero or unparseable value yields a conservative default rather than "retry now":
    the provider just told us to stop, and guessing 0 would hammer it again immediately.
    """
    if value:
        value = value.strip()
        try:
            seconds = float(value)
        except ValueError:
            try:
                when = parsedate_to_datetime(value)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                seconds = (when - (now or datetime.now(timezone.utc))).total_seconds()
                seconds = max(seconds, 1.0)
            except (TypeError, ValueError):
                return DEFAULT_RETRY_AFTER
        if seconds > 0:
            return min(seconds, MAX_RETRY_AFTER)
    return DEFAULT_RETRY_AFTER


class VirusTotalClient:
    """Async client for the VirusTotal v3 API.

    Parameters
    ----------
    api_key : str
        VirusTotal API key. Read from environment / config – never hard‑coded.
    use_mock : bool
        When True, return deterministic synthetic data instead of making real HTTP calls.
    """

    def __init__(
        self,
        api_key: str,
        use_mock: bool = True,
        *,
        limiter: Optional[QuotaLimiter] = None,
        cache: Optional[ProviderCache] = None,
        cache_ttl: float = 3600.0,
        not_found_ttl: float = 900.0,
        max_queue_seconds: float = 15.0,
    ) -> None:
        self._api_key: str = api_key
        self._use_mock: bool = use_mock
        self._base_url: str = "https://www.virustotal.com/api/v3"

        # No limiter given = unlimited windows (a limiter with 0/0), which still carries Retry-After blocks.
        self._limiter = limiter if limiter is not None else QuotaLimiter(0, 0)
        self._max_queue = max_queue_seconds
        # Only *answers* are cached (ok / not_found) — never failures (the old client cached the empty result of
        # a failed call for an hour). The default is an in-memory store; the shared hub injects the SQLite one.
        self._cache = cache if cache is not None else ProviderCache()
        self._cache_ttl = cache_ttl
        self._not_found_ttl = not_found_ttl

        # httpx clients and semaphores belong to the event loop that created them: rebuilt if the loop changes
        # (one loop in production; each TestClient request has its own).
        self._client: Optional[httpx.AsyncClient] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._client_loop: Optional[asyncio.AbstractEventLoop] = None
        logger.info("VirusTotalClient initialised (mock_mode=%s)", self._use_mock)

    async def _get_client(self) -> tuple[httpx.AsyncClient, asyncio.Semaphore]:
        """Lazy-initialize the HTTP client (connection reuse) and the concurrency bound for this event loop."""
        loop = asyncio.get_running_loop()
        if self._client is None or self._client_loop is not loop:
            self._client = httpx.AsyncClient(timeout=15.0, headers={"x-apikey": self._api_key})
            self._semaphore = asyncio.Semaphore(4)       # bounds concurrent connections (the quota is the limiter's)
            self._client_loop = loop
        return self._client, self._semaphore

    async def close(self) -> None:
        """Close the HTTP client and release connections (process shutdown — not per scan)."""
        if self._client:
            try:
                await self._client.aclose()
            except RuntimeError:           # its loop is already closed
                pass
            self._client = None
            self._semaphore = None
            self._client_loop = None

    async def _cache_get(self, key: str) -> Optional[ProviderResult[VirusTotalResult]]:
        try:
            return await self._cache.get(SOURCE, key, VirusTotalResult)
        except Exception:                  # a cache problem must never fail a scan
            logger.exception("provider cache read failed; continuing without it")
            return None

    async def _cache_put(self, key: str, result: ProviderResult[VirusTotalResult]) -> None:
        try:
            await self._cache.put(SOURCE, key, result, ttl_ok=self._cache_ttl, ttl_not_found=self._not_found_ttl)
        except Exception:
            logger.exception("provider cache write failed; continuing without it")

    async def _fetch(self, url: str) -> ProviderResult[VirusTotalResult]:
        """Take a quota slot, GET ``url`` and classify the outcome (see ``core/providers.py``)."""
        retry_after = await self._limiter.acquire(max_wait=self._max_queue)
        if retry_after is not None:
            logger.info("VirusTotal quota: next slot in %.0fs (> %.0fs queue limit) — not calling", retry_after, self._max_queue)
            return prov.error(SOURCE, "rate_limited", retry_after=retry_after)
        client, semaphore = await self._get_client()
        async with semaphore:
            started = prov.start_timer()
            try:
                response = await client.get(url)
            except Exception as exc:  # httpx transport errors (timeout, connect, …)
                logger.warning("VirusTotal request failed for %s: %s", url, exc)
                return prov.from_exception(SOURCE, exc, started=started)

        failure = prov.from_http_status(SOURCE, response.status_code, started=started)
        if failure is not None:
            logger.warning("VirusTotal returned HTTP %s for %s", response.status_code, url)
            if response.status_code == 429:
                seconds = parse_retry_after(response.headers.get("retry-after"))
                self._limiter.penalize(seconds)       # every later caller (scans, network layer) backs off too
                failure = failure.model_copy(update={"retry_after": round(seconds, 1)})
            return failure
        try:
            data = self._parse_response(response.json())
        except _NoAnalysis:
            # 200 but no AV verdicts yet: a real answer, yet it carries no evidence.
            return ProviderResult(source=SOURCE, status=ProviderStatus.NOT_FOUND, reason="no_analysis",
                                  http_status=response.status_code, latency_ms=prov._latency_ms(started))
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("VirusTotal payload unusable for %s: %s", url, exc)
            return prov.error(SOURCE, "parse_error", http_status=response.status_code, started=started)
        return prov.ok(SOURCE, data, http_status=response.status_code, started=started)

    def _generate_mock(self, target: str) -> VirusTotalResult:
        """Generate deterministic mock data based on the target string."""
        import hashlib
        import random
        from datetime import datetime, timezone, timedelta

        target_lower = target.lower()
        if "malicious" in target_lower or "evil" in target_lower:
            return VirusTotalResult(
                malicious_count=15,
                harmless_count=50,
                suspicious_count=3,
                undetected_count=5,
                total_engines=73,
                reputation_score=-47,
                last_analysis_date=datetime.now(timezone.utc),
                categories={'Fortinet': 'malware', 'Sophos': 'malware'}
            )
        elif "google" in target_lower or "microsoft" in target_lower:
            return VirusTotalResult(
                malicious_count=0,
                harmless_count=70,
                suspicious_count=0,
                undetected_count=3,
                total_engines=73,
                reputation_score=85,
                last_analysis_date=datetime.now(timezone.utc),
                categories={'Fortinet': 'business', 'Sophos': 'business'}
            )
        else:
            # Seed based on target domain to generate unique but deterministic scores
            seed_val = int(hashlib.md5(target.encode('utf-8')).hexdigest(), 16)
            rng = random.Random(seed_val)

            malicious = rng.randint(0, 8)
            suspicious = rng.randint(0, 3)
            undetected = rng.randint(2, 10)
            total = 73
            harmless = total - malicious - suspicious - undetected
            reputation = rng.randint(-30, 90)

            cats = ['business', 'technology', 'education', 'news', 'suspicious', 'shopping']
            cat = rng.choice(cats)

            # Deterministic last seen days
            days_ago = rng.randint(0, 100)
            last_date = datetime.now(timezone.utc) - timedelta(days=days_ago)

            return VirusTotalResult(
                malicious_count=malicious,
                harmless_count=harmless,
                suspicious_count=suspicious,
                undetected_count=undetected,
                total_engines=total,
                reputation_score=reputation,
                last_analysis_date=last_date,
                categories={'Fortinet': cat}
            )

    def _parse_response(self, data: dict[str, Any]) -> VirusTotalResult:
        """Parse raw VT v3 JSON into a VirusTotalResult.

        Raises ``ValueError`` for a payload that is not a VT object at all (→ ``parse_error``)
        and ``_NoAnalysis`` when the object exists but has no analysis stats yet.
        """
        if (not isinstance(data, dict) or not isinstance(data.get("data"), dict)
                or "attributes" not in data["data"]):
            raise ValueError("response is not a VirusTotal object")

        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats") or {}
        if not stats or not sum(stats.values()):
            raise _NoAnalysis()

        last_date = None
        if "last_analysis_date" in attrs:
            last_date = datetime.fromtimestamp(attrs["last_analysis_date"], tz=timezone.utc)

        categories = {}
        if "categories" in attrs:
            # Take a sample of categories
            categories = dict(list(attrs["categories"].items())[:5])

        return VirusTotalResult(
            malicious_count=stats.get("malicious", 0),
            harmless_count=stats.get("harmless", 0),
            suspicious_count=stats.get("suspicious", 0),
            undetected_count=stats.get("undetected", 0),
            total_engines=sum(stats.values()),
            reputation_score=attrs.get("reputation", 0),
            last_analysis_date=last_date,
            categories=categories
        )

    # ------------------------------------------------------------------
    # Public async methods
    # ------------------------------------------------------------------

    async def _lookup(self, kind: str, key: str, subject: Optional[str], mock_target: str,
                      url: str) -> ProviderResult[VirusTotalResult]:
        if self._use_mock:
            return prov.ok(SOURCE, self._generate_mock(mock_target), http_status=None, mock=True)
        # Never send private/local/malformed names (or private IPs) to VirusTotal (A0-10) — and a refused
        # lookup costs no quota and touches no cache.
        if subject is not None:
            blocked = privacy.provider_block_reason(subject)
            if blocked:
                return prov.skipped(SOURCE, blocked)
        cached = await self._cache_get(key)
        if cached is not None:
            return cached
        result = await self._fetch(url)
        await self._cache_put(key, result)
        return result

    async def lookup_domain(self, domain: str) -> ProviderResult[VirusTotalResult]:
        """Fetch the reputation and last‑analysis stats for a domain."""
        return await self._lookup("domain", f"domain:{domain.lower()}", domain, domain,
                                  f"{self._base_url}/domains/{domain}")

    async def lookup_ip(self, ip: str) -> ProviderResult[VirusTotalResult]:
        """Fetch the reputation and last‑analysis stats for an IPv4/IPv6 address."""
        return await self._lookup("ip", f"ip:{ip.lower()}", ip, ip, f"{self._base_url}/ip_addresses/{ip}")

    async def lookup_url(self, url: str) -> ProviderResult[VirusTotalResult]:
        """Fetch the reputation and last‑analysis stats for a URL."""
        # VT v3 API requires the URL to be base64url encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._lookup("url", url_key(url), privacy.hostname_of(url) or "", url,
                                  f"{self._base_url}/urls/{url_id}")

    async def lookup_file_hash(self, file_hash: str) -> ProviderResult[VirusTotalResult]:
        """Fetch the analysis report for a file hash."""
        return await self._lookup("hash", f"hash:{file_hash.lower()}", None, file_hash,
                                  f"{self._base_url}/files/{file_hash}")
