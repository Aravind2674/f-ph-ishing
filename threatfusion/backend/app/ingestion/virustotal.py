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
* ``GET /api/v3/urls/{url_id}``         – URL reputation (url_id = base64).
* ``GET /api/v3/files/{hash}``          – file‑hash lookup (MD5/SHA‑1/SHA‑256).

Rate limits
-----------
The free VT API tier allows **4 requests / minute (500/day)**.  A real, process-wide
token bucket is part of A1-1; until then a semaphore only bounds *concurrency*.  A 429
from VirusTotal is surfaced as ``error / rate_limited`` instead of being swallowed.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Tuple, Any

import httpx

from app.core import providers as prov
from app.models.schemas import ProviderResult, ProviderStatus, VirusTotalResult

logger = logging.getLogger(__name__)

SOURCE = "virustotal"


class _NoAnalysis(Exception):
    """VT knows the object but has no AV analysis for it (empty/missing last_analysis_stats)."""


class VirusTotalClient:
    """Async client for the VirusTotal v3 API.

    Parameters
    ----------
    api_key : str
        VirusTotal API key. Read from environment / config – never hard‑coded.
    use_mock : bool
        When True, return deterministic synthetic data instead of making real HTTP calls.
    """

    def __init__(self, api_key: str, use_mock: bool = True) -> None:
        self._api_key: str = api_key
        self._use_mock: bool = use_mock
        self._base_url: str = "https://www.virustotal.com/api/v3"

        # Bounds concurrency only (real rate limiting arrives with the shared client in A1-1).
        self._semaphore = asyncio.Semaphore(4)

        # In-memory cache. Only *answers* are cached (ok / not_found) — never failures:
        # the previous client cached the empty result of a failed call for an hour.
        self._cache: Dict[Tuple[str, str], Tuple[ProviderResult[VirusTotalResult], float]] = {}
        self._cache_ttl = 3600  # 1 hour

        self._client: Optional[httpx.AsyncClient] = None
        logger.info("VirusTotalClient initialised (mock_mode=%s)", self._use_mock)

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-initialize the HTTP client for connection reuse."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=15.0,
                headers={"x-apikey": self._api_key}
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client and release connections."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _check_cache(self, method: str, target: str) -> Optional[ProviderResult[VirusTotalResult]]:
        """Return a fresh cached *answer* (marked ``cached=True``), else None."""
        if self._use_mock:
            return None  # Skip cache in mock mode so tests are predictable

        key = (method, target)
        if key in self._cache:
            result, timestamp = self._cache[key]
            if time.time() - timestamp < self._cache_ttl:
                logger.debug("Cache hit for %s %s", method, target)
                return result.model_copy(update={"cached": True})
            del self._cache[key]
        return None

    def _set_cache(self, method: str, target: str, result: ProviderResult[VirusTotalResult]) -> None:
        """Cache answers only; an error must be retried, not remembered."""
        if not self._use_mock and result.status in (ProviderStatus.OK, ProviderStatus.NOT_FOUND):
            self._cache[(method, target)] = (result, time.time())

    async def _fetch(self, url: str) -> ProviderResult[VirusTotalResult]:
        """GET ``url`` and classify the outcome (see ``core/providers.py`` for the mapping)."""
        async with self._semaphore:
            client = await self._get_client()
            started = prov.start_timer()
            try:
                response = await client.get(url)
            except Exception as exc:  # httpx transport errors (timeout, connect, …)
                logger.warning("VirusTotal request failed for %s: %s", url, exc)
                return prov.from_exception(SOURCE, exc, started=started)

        failure = prov.from_http_status(SOURCE, response.status_code, started=started)
        if failure is not None:
            logger.warning("VirusTotal returned HTTP %s for %s", response.status_code, url)
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

    async def _lookup(self, kind: str, target: str, url: str) -> ProviderResult[VirusTotalResult]:
        if self._use_mock:
            return prov.ok(SOURCE, self._generate_mock(target), http_status=None, mock=True)
        cached = self._check_cache(kind, target)
        if cached is not None:
            return cached
        result = await self._fetch(url)
        self._set_cache(kind, target, result)
        return result

    async def lookup_domain(self, domain: str) -> ProviderResult[VirusTotalResult]:
        """Fetch the reputation and last‑analysis stats for a domain."""
        return await self._lookup("domain", domain, f"{self._base_url}/domains/{domain}")

    async def lookup_url(self, url: str) -> ProviderResult[VirusTotalResult]:
        """Fetch the reputation and last‑analysis stats for a URL."""
        # VT v3 API requires the URL to be base64url encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._lookup("url", url, f"{self._base_url}/urls/{url_id}")

    async def lookup_file_hash(self, file_hash: str) -> ProviderResult[VirusTotalResult]:
        """Fetch the analysis report for a file hash."""
        return await self._lookup("hash", file_hash, f"{self._base_url}/files/{file_hash}")
