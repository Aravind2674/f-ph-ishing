"""
ThreatFusion – CVE / NVD Ingestion Client
==========================================

Wraps the **NIST National Vulnerability Database (NVD) API v2** to
hydrate bare CVE IDs (e.g. from Shodan) into full vulnerability records
with descriptions, CVSS scores, and severity labels.

Architecture
------------
The client operates in two modes controlled by ``use_mock``:

* **Mock mode** (default): Returns deterministic, realistic data for
  well-known CVEs (Log4Shell, Heartbleed, etc.) without any network I/O.
  This is essential for local development, demos, viva presentations, and
  integration tests that must be fast and hermetic.

* **Live mode**: Calls the real NVD REST API v2.  Requires an active
  internet connection.  An API key lifts the rate limit from
  5 → 50 requests per 30-second window.

Rate-limit compliance, fan-out and deadline (A1-2)
--------------------------------------------------
NVD throttles aggressively (with HTTP 403, not only 429).  Every request first takes a slot from a shared
:class:`~app.core.quota.QuotaLimiter` configured from ``NVD_REQUESTS_PER_WINDOW`` / ``NVD_WINDOW_SECONDS`` (the
published window, not a hard-coded one).  A 403/429/503 is *retried* with exponential backoff (or the server's
``Retry-After``) and the wait is registered with the limiter so concurrent lookups back off together — never past the
deadline.  CVE IDs are fetched concurrently (bounded) under one hard deadline; if it expires, the lookups that
*finished* are returned as ``partial:n/m`` instead of the whole result being lost to a timeout.

Caching
-------
CVE records and CPE result sets are cached in SQLite (``core/cache.py``; CVE data changes rarely, so the default TTL
is a week).  Only answers are cached — a failed lookup is retried, never remembered.

CPE lookups
-----------
InternetDB reports CPEs as CPE 2.2 URIs; :func:`cpe22_to_cpe23` converts them to the 2.3 names NVD's ``cpeName``
parameter wants, queries are paginated (``startIndex`` / ``resultsPerPage``), and CPEs without a version are skipped
(they match every release of a product — noise, not evidence about this host).

Design decision — why httpx?
-----------------------------
``httpx`` is used instead of ``aiohttp`` because:
1. Its API is nearly identical to ``requests``, lowering the learning curve.
2. It supports both sync and async with the same library.
3. ``httpx.AsyncClient`` supports connection pooling and HTTP/2 out of the
   box, which is beneficial for batch CVE lookups.
"""

from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import unquote

import httpx

from app.core import providers as prov
from app.core.cache import ProviderCache
from app.core.logging import get_logger
from app.core.quota import QuotaLimiter
from app.models.schemas import CVEDetail, CVEResult, ProviderResult, ProviderStatus

logger = get_logger(__name__)

SOURCE = "nvd"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex for validating CVE identifiers (e.g. CVE-2021-44228).
# The year must be 4 digits and the sequence number must be at least 4 digits.
_CVE_ID_PATTERN: re.Pattern[str] = re.compile(
    r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE
)

# NVD API v2 base URL — centralised so it's easy to override in tests.
_NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Default cache TTL for a CVE record (a week): descriptions and CVSS scores change rarely.
_DEFAULT_CACHE_TTL_SECONDS: int = 7 * 24 * 3600

# Request timeout for NVD API calls.
_REQUEST_TIMEOUT_SECONDS: float = 15.0


# ---------------------------------------------------------------------------
# Mock Data
# ---------------------------------------------------------------------------

def _build_mock_cve_database() -> dict[str, CVEDetail]:
    """Build a lookup table of well-known CVEs with realistic data.

    These entries mirror the actual NVD response structure so that the
    mock path exercises the same Pydantic models as the live path.  This
    ensures the frontend sees a consistent data shape regardless of mode.

    Why these specific CVEs?
    - Log4Shell (CVE-2021-44228): The most impactful CVE in recent history.
      CVSS 10.0 makes it ideal for testing critical-severity rendering.
    - Apache path traversal (CVE-2021-41773): A classic web-server vuln
      that Shodan frequently surfaces.
    - HTTP/2 Rapid Reset (CVE-2023-44487): A protocol-level DoS attack
      that demonstrates how modern CVEs can affect infrastructure.
    - Heartbleed (CVE-2014-0160): An iconic TLS vulnerability.  Its age
      tests that the client handles older CVEs gracefully.
    """
    return {
        "CVE-2021-44228": CVEDetail(
            cve_id="CVE-2021-44228",
            description=(
                "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security "
                "releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in "
                "configuration, log messages, and parameters do not protect "
                "against attacker controlled LDAP and other JNDI related "
                "endpoints. An attacker who can control log messages or log "
                "message parameters can execute arbitrary code loaded from "
                "LDAP servers when message lookup substitution is enabled."
            ),
            cvss_v3_score=10.0,
            severity="CRITICAL",
            published_date=datetime(2021, 12, 10, 0, 0, 0, tzinfo=timezone.utc),
        ),
        "CVE-2021-41773": CVEDetail(
            cve_id="CVE-2021-41773",
            description=(
                "A flaw was found in a change made to path normalization in "
                "Apache HTTP Server 2.4.49. An attacker could use a path "
                "traversal attack to map URLs to files outside the "
                "directories configured by Alias-like directives. If files "
                "outside of these directories are not protected by the usual "
                "default configuration 'require all denied', these requests "
                "can succeed. If CGI scripts are also enabled for these "
                "aliased paths, this could allow for remote code execution."
            ),
            cvss_v3_score=7.5,
            severity="HIGH",
            published_date=datetime(2021, 10, 5, 0, 0, 0, tzinfo=timezone.utc),
        ),
        "CVE-2023-44487": CVEDetail(
            cve_id="CVE-2023-44487",
            description=(
                "The HTTP/2 protocol allows a denial of service (server "
                "resource consumption) because request cancellation can reset "
                "many streams quickly, as exploited in the wild in August "
                "through October 2023. Also known as Rapid Reset Attack."
            ),
            cvss_v3_score=7.5,
            severity="HIGH",
            published_date=datetime(2023, 10, 10, 0, 0, 0, tzinfo=timezone.utc),
        ),
        "CVE-2014-0160": CVEDetail(
            cve_id="CVE-2014-0160",
            description=(
                "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 "
                "before 1.0.1g do not properly handle Heartbeat Extension "
                "packets, which allows remote attackers to obtain sensitive "
                "information from process memory via crafted packets that "
                "trigger a buffer over-read, as demonstrated by reading "
                "private keys, aka the Heartbleed bug."
            ),
            cvss_v3_score=7.5,
            severity="HIGH",
            published_date=datetime(2014, 4, 7, 0, 0, 0, tzinfo=timezone.utc),
        ),
    }


# Module-level singleton — built once at import time.
_MOCK_CVE_DB: dict[str, CVEDetail] = _build_mock_cve_database()


def _generate_unknown_mock_cve(cve_id: str) -> CVEDetail:
    """Generate a plausible mock entry for a CVE ID not in our database.

    For unknown CVEs we default to MEDIUM severity (5.0).  This is a
    deliberate design choice: it sits in the middle of the CVSS scale and
    avoids inflating or deflating overall risk scores during demos.
    """
    return CVEDetail(
        cve_id=cve_id,
        description=(
            f"This is a simulated vulnerability entry for {cve_id}. "
            f"In production, full details would be fetched from the NVD API."
        ),
        cvss_v3_score=5.0,
        severity="MEDIUM",
        published_date=datetime(2023, 1, 15, 0, 0, 0, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# CPE helpers
# ---------------------------------------------------------------------------

def cpe22_to_cpe23(cpe: str) -> str | None:
    """Convert an InternetDB-style CPE 2.2 URI to the CPE 2.3 *formatted string* NVD's ``cpeName`` expects.

    ``cpe:/a:apache:http_server:2.4.49`` → ``cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*``.
    A 2.3 string passes through unchanged; anything that is not a CPE with at least ``part:vendor:product``
    returns ``None``.  Percent-escapes of 2.2 are decoded and re-escaped the 2.3 way (``%2f`` → ``\\/``).
    """
    if not isinstance(cpe, str):
        return None
    cpe = cpe.strip()
    if cpe.lower().startswith("cpe:2.3:"):
        return cpe if len(cpe.split(":")) >= 6 else None
    if not cpe.lower().startswith("cpe:/"):
        return None
    parts = cpe[5:].split(":")                        # part, vendor, product, version, update, edition, language
    if len(parts) < 3 or not all(parts[:3]):
        return None
    fields: list[str] = []
    for raw in parts[:7]:
        value = unquote(raw)
        if value in ("", "-") and raw == "":
            value = "*"
        elif value != "-":
            value = re.sub(r"([^A-Za-z0-9_\-.*?])", r"\\\1", value)     # CPE 2.3 escaping of punctuation
        fields.append(value)
    fields += ["*"] * (7 - len(fields))
    return "cpe:2.3:" + ":".join(fields) + ":*:*:*:*"


def _cpe_version(cpe23: str) -> str:
    parts = cpe23.split(":")
    return parts[5] if len(parts) > 5 else "*"


def specific_cpe_names(cpes: list[str]) -> list[str]:
    """CPE 2.3 names worth looking up: valid, deduplicated, and **with a version**.

    A versionless CPE (``cpe:/o:microsoft:windows``) matches thousands of CVEs across every release, which is
    noise rather than evidence about *this* host.
    """
    out: list[str] = []
    for raw in cpes or []:
        std = cpe22_to_cpe23(raw)
        if std and _cpe_version(std) not in ("*", "-", "") and std not in out:
            out.append(std)
    return out


_RETRYABLE_STATUS = (403, 429, 503)      # NVD throttles with 403 (and 429); 503 when overloaded
_CACHE_SOURCE = SOURCE


# ---------------------------------------------------------------------------
# CVEClient
# ---------------------------------------------------------------------------

class CVEClient:
    """Async client for the NIST NVD v2 API with mock fallback.

    This is the primary interface the orchestrator uses to hydrate bare CVE IDs (e.g. ``"CVE-2021-44228"``) into
    full ``CVEDetail`` records and to look up CVEs by CPE.

    Parameters
    ----------
    api_key : str
        NVD API key, sent in the ``apiKey`` *header* (never the URL). Without one NVD allows only 5 requests per
        30 s; the app treats a missing key as "not configured" (A0-5).
    use_mock : bool
        When ``True``, return deterministic synthetic data instead of making real HTTP calls.
    limiter : QuotaLimiter, optional
        Shared rate gate (the hub builds it from ``NVD_REQUESTS_PER_WINDOW`` / ``NVD_WINDOW_SECONDS``). It also
        carries ``Retry-After``/backoff blocks so concurrent lookups slow down *together*.
    cache : ProviderCache, optional
        Persistent CVE/CPE cache (SQLite in production). Default: in-memory, same semantics.
    max_concurrency, deadline_seconds
        At most this many lookups in flight, and a hard time budget for one ``lookup_*`` call. When the budget is
        spent the *finished* lookups are returned (``partial:n/m``) instead of all of them being lost.
    max_retries, backoff_base
        403/429/503 are retried up to ``max_retries`` times with exponential backoff (``base × 2^attempt``), or
        the server's ``Retry-After`` when it sends one — never past the deadline.
    max_pages, results_per_page, max_cpes, max_cpe_cves
        CPE queries are paginated (``startIndex``/``resultsPerPage``); at most ``max_pages`` pages per CPE, at most
        ``max_cpes`` CPEs per host, and at most ``max_cpe_cves`` (highest CVSS first) CPE-derived CVEs are merged
        into a scan.
    """

    def __init__(
        self,
        api_key: str = "",
        use_mock: bool = True,
        *,
        cache_ttl_seconds: int = _DEFAULT_CACHE_TTL_SECONDS,
        not_found_ttl_seconds: int = 3600,
        cpe_cache_ttl_seconds: int = 24 * 3600,
        limiter: QuotaLimiter | None = None,
        cache: ProviderCache | None = None,
        max_concurrency: int = 5,
        deadline_seconds: float = 15.0,
        max_retries: int = 3,
        backoff_base: float = 1.0,
        max_pages: int = 3,
        results_per_page: int = 2000,
        max_cpes: int = 5,
        max_cpe_cves: int = 25,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._api_key: str = api_key
        self._use_mock: bool = use_mock
        self._base_url: str = _NVD_BASE_URL
        self._cache_ttl = cache_ttl_seconds
        self._not_found_ttl = not_found_ttl_seconds
        self._cpe_cache_ttl = cpe_cache_ttl_seconds
        # No limiter given = no windows (0/0) — which still carries Retry-After/backoff blocks.
        self._limiter = limiter if limiter is not None else QuotaLimiter(0, 0)
        self._cache = cache if cache is not None else ProviderCache()
        self._max_concurrency = max(1, int(max_concurrency))
        self._deadline = float(deadline_seconds)
        self._max_retries = max(0, int(max_retries))
        self._backoff_base = float(backoff_base)
        self._max_pages = max(1, int(max_pages))
        self._per_page = max(1, int(results_per_page))
        self._max_cpes = max(0, int(max_cpes))
        self._max_cpe_cves = max(1, int(max_cpe_cves))
        self._clock = clock

        # httpx clients belong to the event loop that created them (rebuilt if the loop changes).
        self._http_client: httpx.AsyncClient | None = None
        self._client_loop: asyncio.AbstractEventLoop | None = None

        logger.info(
            "CVEClient initialised (mock_mode=%s, has_api_key=%s, concurrency=%d, deadline=%.0fs, retries=%d)",
            self._use_mock, bool(self._api_key), self._max_concurrency, self._deadline, self._max_retries,
        )

    # ------------------------------------------------------------------
    # Async context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> CVEClient:
        """Allow ``async with CVEClient(...) as client:`` usage."""
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None,
                        exc_tb: Any) -> None:
        """Ensure the HTTP client is closed when exiting the context."""
        await self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_http_client(self) -> httpx.AsyncClient:
        """Lazily create the shared ``httpx.AsyncClient`` for the running event loop."""
        loop = asyncio.get_running_loop()
        if self._http_client is None or self._http_client.is_closed or self._client_loop is not loop:
            headers: dict[str, str] = {
                "Accept": "application/json",
                "User-Agent": "ThreatFusion/0.1.0 (university-project)",
            }
            if self._api_key:
                # NVD expects the API key in a custom header, NOT as a query parameter.
                headers["apiKey"] = self._api_key
            self._http_client = httpx.AsyncClient(headers=headers, timeout=httpx.Timeout(_REQUEST_TIMEOUT_SECONDS),
                                                  http2=False)
            self._client_loop = loop
        return self._http_client

    async def _cache_get(self, key: str, model):
        try:
            return await self._cache.get(_CACHE_SOURCE, key, model)
        except Exception:                     # a cache problem must never fail a scan
            logger.exception("provider cache read failed; continuing without it")
            return None

    async def _cache_put(self, key: str, result: ProviderResult, ttl_ok: float) -> None:
        try:
            await self._cache.put(_CACHE_SOURCE, key, result, ttl_ok=ttl_ok, ttl_not_found=self._not_found_ttl)
        except Exception:
            logger.exception("provider cache write failed; continuing without it")

    async def _request(self, params: dict[str, str]) -> tuple[httpx.Response | None, ProviderResult | None, float | None]:
        """One GET against NVD → ``(response, None, None)`` or ``(None, failure, retry_after_header)``.

        A non-200 answer is classified, not swallowed (A0-1): 404 → ``not_found``; 403 → ``auth_or_rate_limited``
        (NVD uses 403 for throttling); 429 → ``rate_limited``; 5xx → ``server_error``; transport errors →
        ``timeout`` / ``network``.  The rate *gate* is applied by the caller (``_fetch_json``).
        """
        client = self._get_http_client()
        started = prov.start_timer()
        try:
            logger.debug("NVD API request: params=%s", params)
            response = await client.get(self._base_url, params=params)
        except Exception as exc:
            logger.error("NVD API request failed for params=%s: %s", params, exc)
            return None, prov.from_exception(SOURCE, exc, started=started), None
        failure = prov.from_http_status(
            SOURCE, response.status_code, started=started, forbidden_reason="auth_or_rate_limited",
        )
        if failure is not None:
            logger.warning("NVD API returned HTTP %d for params=%s", response.status_code, params)
            header = response.headers.get("retry-after")
            return None, failure, (prov.parse_retry_after(header, default=None) if header else None)
        return response, None, None

    async def _fetch_json(self, params: dict[str, str], deadline_at: float) -> tuple[dict | None, ProviderResult | None]:
        """Rate-gated GET with retry/backoff → ``(payload, None)`` or ``(None, failure)``.

        403/429/503 are retried (exponential backoff, or the server's ``Retry-After``) as long as the wait still
        fits before ``deadline_at``.  The wait is registered with the shared limiter (``penalize``) so every other
        in-flight lookup backs off with us instead of hammering a provider that just said "slow down".
        """
        last_failure: ProviderResult | None = None
        for attempt in range(self._max_retries + 1):
            wait = await self._limiter.acquire(max_wait=max(0.0, deadline_at - self._clock()))
            if wait is not None:                    # the next slot is beyond our time budget
                base = last_failure or prov.error(SOURCE, "rate_limited")
                return None, base.model_copy(update={"retry_after": round(wait, 1)})
            response, failure, header_delay = await self._request(params)
            if failure is None:
                try:
                    return response.json(), None
                except ValueError:
                    return None, prov.error(SOURCE, "parse_error", http_status=response.status_code)
            if failure.http_status in _RETRYABLE_STATUS and attempt < self._max_retries:
                delay = header_delay if header_delay is not None else self._backoff_base * (2 ** attempt)
                if self._clock() + delay > deadline_at:
                    return None, failure.model_copy(update={"retry_after": round(delay, 1)})
                self._limiter.penalize(delay)       # acquire() above sleeps for it
                last_failure = failure
                continue
            return None, failure
        return None, last_failure or prov.error(SOURCE, "unknown")        # pragma: no cover

    @staticmethod
    def _parse_nvd_cve_item(cve_item: dict[str, Any]) -> CVEDetail:
        """Parse a single CVE item from the NVD v2 response into a ``CVEDetail``.

        NVD v2 Response Structure (abbreviated)::

            {"vulnerabilities": [{"cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"lang": "en", "value": "..."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
                "published": "2021-12-10T10:15:00.000"}}]}

        We prefer CVSS v3.1 metrics.  If unavailable, we fall back to v3.0, then to v2 (with a severity mapping).
        This graceful degradation handles the ~20% of CVEs that lack v3 scores.
        """
        cve_data: dict[str, Any] = cve_item.get("cve", {})
        cve_id: str = cve_data.get("id", "UNKNOWN")

        # ── Extract English description ──────────────────────────────
        descriptions: list[dict[str, str]] = cve_data.get("descriptions", [])
        description: str = ""
        for desc in descriptions:
            if desc.get("lang", "") == "en":
                description = desc.get("value", "")
                break
        # Fallback: use the first description if no English one is found.
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # ── Extract CVSS v3.x score and severity ─────────────────────
        metrics: dict[str, Any] = cve_data.get("metrics", {})
        cvss_score: float | None = None
        severity: str | None = None

        # Try CVSS v3.1 first (preferred), then v3.0.
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list: list[dict[str, Any]] = metrics.get(metric_key, [])
            if metric_list:
                cvss_data: dict[str, Any] = metric_list[0].get("cvssData", {})
                raw_score = cvss_data.get("baseScore")
                if raw_score is not None:
                    cvss_score = float(raw_score)
                    severity = cvss_data.get("baseSeverity", "").upper() or None
                break

        # Fallback to CVSS v2 if no v3 metrics exist.
        if cvss_score is None:
            v2_metrics: list[dict[str, Any]] = metrics.get("cvssMetricV2", [])
            if v2_metrics:
                cvss_data_v2: dict[str, Any] = v2_metrics[0].get("cvssData", {})
                raw_score_v2 = cvss_data_v2.get("baseScore")
                if raw_score_v2 is not None:
                    cvss_score = float(raw_score_v2)
                    # CVSS v2 doesn't have baseSeverity in the same format, so we derive it from the score.
                    severity = _cvss_v2_score_to_severity(cvss_score)

        # ── Extract published date ───────────────────────────────────
        published_str: str = cve_data.get("published", "")
        published_date: datetime | None = None
        if published_str:
            try:
                # NVD uses ISO 8601, sometimes with a trailing 'Z' or '.000' fractional seconds.
                published_date = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
            except ValueError:
                logger.warning("Could not parse published date '%s' for %s", published_str, cve_id)

        return CVEDetail(
            cve_id=cve_id,
            description=description,
            cvss_v3_score=cvss_score,
            severity=severity,
            published_date=published_date,
        )

    # ------------------------------------------------------------------
    # Mock helpers
    # ------------------------------------------------------------------

    async def _mock_lookup_single(self, cve_id: str) -> CVEDetail:
        """Return mock data for a single CVE ID (known CVEs: curated; unknown: a MEDIUM placeholder)."""
        await asyncio.sleep(0.01)          # a tiny network delay, so tests exercise the same concurrency patterns

        normalised_id: str = cve_id.upper().strip()
        if normalised_id in _MOCK_CVE_DB:
            logger.debug("Mock hit for known CVE: %s", normalised_id)
            return _MOCK_CVE_DB[normalised_id]
        logger.debug("Mock fallback: generating plausible entry for unknown CVE %s", normalised_id)
        return _generate_unknown_mock_cve(normalised_id)

    async def _mock_lookup_by_cpe(self, cpe: str) -> list[CVEDetail]:
        """Return mock CVEs matching a CPE string (a fixed set for 'apache'/'openssl', one generic otherwise)."""
        await asyncio.sleep(0.02)

        cpe_lower = cpe.lower()
        if "apache" in cpe_lower:
            results: list[CVEDetail] = [_MOCK_CVE_DB["CVE-2021-41773"]]
            if "log4j" in cpe_lower:
                results.append(_MOCK_CVE_DB["CVE-2021-44228"])
            return results
        if "openssl" in cpe_lower:
            return [_MOCK_CVE_DB["CVE-2014-0160"]]
        return [_generate_unknown_mock_cve("CVE-2023-99999")]

    # ------------------------------------------------------------------
    # Live API helpers
    # ------------------------------------------------------------------

    async def _live_lookup_single(self, cve_id: str, deadline_at: float) -> tuple[CVEDetail | None, ProviderResult | None]:
        """Fetch one CVE → ``(detail, None)`` or ``(None, why-not)`` ("no such CVE" ≠ "the request failed")."""
        payload, failure = await self._fetch_json({"cveId": cve_id}, deadline_at)
        if failure is not None:
            return None, failure
        try:
            vulnerabilities: list[dict[str, Any]] = payload.get("vulnerabilities", [])
            if not vulnerabilities:
                logger.warning("NVD returned empty vulnerabilities array for %s", cve_id)
                return None, prov.not_found(SOURCE, http_status=200)
            return self._parse_nvd_cve_item(vulnerabilities[0]), None
        except (KeyError, IndexError, ValueError, TypeError, AttributeError) as exc:
            logger.error("Failed to parse NVD response for %s: %s", cve_id, exc)
            return None, prov.error(SOURCE, "parse_error", http_status=200)

    async def _resolve_cves(self, valid_ids: list[str]) -> tuple[list[CVEDetail], list[ProviderResult], int]:
        """Look the IDs up concurrently (bounded) within the deadline → ``(details, failures, served_from_cache)``.

        Whatever finished by the deadline is returned; the rest are reported as ``error/timeout`` failures.
        """
        deadline_at = self._clock() + self._deadline
        gate = asyncio.Semaphore(self._max_concurrency)

        async def one(cve_id: str) -> tuple[CVEDetail | None, ProviderResult | None, bool]:
            if self._use_mock:
                return await self._mock_lookup_single(cve_id), None, False
            key = f"cve:{cve_id}"
            cached = await self._cache_get(key, CVEDetail)
            if cached is not None:
                return (cached.data, None, True) if cached.ok else (None, cached, True)
            async with gate:
                if self._clock() >= deadline_at:
                    return None, prov.error(SOURCE, "timeout"), False
                detail, failure = await self._live_lookup_single(cve_id, deadline_at)
            if detail is not None:
                await self._cache_put(key, prov.ok(SOURCE, detail), self._cache_ttl)
            elif failure is not None and failure.status == ProviderStatus.NOT_FOUND:
                await self._cache_put(key, failure, self._cache_ttl)
            return detail, failure, False

        tasks = {cve_id: asyncio.ensure_future(one(cve_id)) for cve_id in valid_ids}
        done, pending = await asyncio.wait(tasks.values(), timeout=max(0.0, deadline_at - self._clock()))
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        details: list[CVEDetail] = []
        failures: list[ProviderResult] = []
        from_cache = 0
        for cve_id, task in tasks.items():
            if task in pending or task.cancelled():
                failures.append(prov.error(SOURCE, "timeout"))
                continue
            try:
                detail, failure, was_cached = task.result()
            except Exception:                                    # never let one lookup sink the others
                logger.exception("Unexpected error looking up %s", cve_id)
                failures.append(prov.error(SOURCE, "unexpected"))
                continue
            if detail is not None:
                details.append(detail)
                from_cache += 1 if was_cached else 0
            else:
                failure = failure or prov.error(SOURCE, "unknown")
                logger.warning("No data for %s (%s)", cve_id, failure.reason or failure.status.value)
                failures.append(failure)
        return details, failures, from_cache

    @staticmethod
    def _valid_ids(cve_ids: list[str]) -> list[str]:
        seen: set[str] = set()
        valid_ids: list[str] = []
        for raw_id in cve_ids or []:
            normalised: str = str(raw_id).upper().strip()
            if normalised in seen:
                continue
            seen.add(normalised)
            if not _CVE_ID_PATTERN.match(normalised):
                logger.warning("Skipping invalid CVE ID format: '%s'", raw_id)
                continue
            valid_ids.append(normalised)
        return valid_ids

    @staticmethod
    def _best_failure(failures: list[ProviderResult], started: float) -> ProviderResult:
        """The most informative failure (errors outrank not_found)."""
        errors = [f for f in failures if f.status == ProviderStatus.ERROR]
        chosen = errors[0] if errors else failures[0]
        return chosen.model_copy(update={"latency_ms": prov._latency_ms(started)})

    # ------------------------------------------------------------------
    # Public async methods
    # ------------------------------------------------------------------

    async def lookup_cves(self, cve_ids: list[str]) -> ProviderResult[CVEResult]:
        """Fetch full details for a list of CVE IDs.

        Lookups run concurrently (bounded by ``max_concurrency``) under one deadline.  Returns a
        ``ProviderResult[CVEResult]``:

        * ``ok`` – at least one CVE was retrieved (``reason="partial:n/m"`` if some failed or ran out of time);
        * ``not_found`` – NVD answered but knows none of the IDs;
        * ``error`` – nothing could be retrieved because requests failed (reason says why);
        * ``skipped`` – no valid CVE IDs were supplied.

        Crucially, "NVD failed" is **never** reported as ``CVEResult(max_cvss_score=0.0)`` — that made an
        unreachable NVD look like "no critical vulnerabilities".
        """
        if not cve_ids:
            logger.debug("lookup_cves called with empty list")
            return prov.skipped(SOURCE, "no_cve_ids")
        valid_ids = self._valid_ids(cve_ids)
        if not valid_ids:
            logger.warning("No valid CVE IDs after filtering")
            return prov.skipped(SOURCE, "no_valid_cve_ids")

        logger.info("Looking up %d CVE(s) (mode=%s): %s", len(valid_ids), "mock" if self._use_mock else "live",
                    ", ".join(valid_ids[:5]) + ("..." if len(valid_ids) > 5 else ""))
        started = prov.start_timer()
        details, failures, from_cache = await self._resolve_cves(valid_ids)

        if details:
            max_score = max((d.cvss_v3_score for d in details if d.cvss_v3_score is not None), default=None)
            result = CVEResult(cves=details, total_cves=len(details), max_cvss_score=max_score)
            logger.info("CVE lookup complete: %d/%d succeeded, max_cvss=%s", len(details), len(valid_ids), "unscored" if max_score is None else f"{max_score:.1f}")
            partial = f"partial:{len(details)}/{len(valid_ids)}" if len(details) < len(valid_ids) else None
            all_cached = from_cache == len(details) and not self._use_mock
            out = prov.ok(SOURCE, result, http_status=None if (self._use_mock or all_cached) else 200,
                          started=None if all_cached else started, reason=partial, mock=self._use_mock)
            return out.model_copy(update={"cached": True}) if all_cached else out
        return self._best_failure(failures, started)

    async def lookup_by_cpe(self, cpe: str) -> ProviderResult[CVEResult]:
        """Find the CVEs NVD associates with a **CPE** (paginated).

        Accepts a CPE 2.3 name or an InternetDB-style 2.2 URI.  An empty list from NVD is a genuine ``ok`` answer
        ("no known CVEs"); a failed request is an ``error`` — never an empty ``CVEResult``.  At most ``max_pages``
        pages are fetched: if NVD has more, the result is ``ok`` with ``reason="truncated:got/total"``.  If a
        later page fails, the pages already retrieved are kept (also ``truncated:``).
        """
        std = cpe22_to_cpe23(cpe)
        if std is None:
            logger.warning("lookup_by_cpe called with an unusable CPE")
            return prov.skipped(SOURCE, "no_cpe" if not (cpe or "").strip() else "invalid_cpe")
        logger.info("Looking up CVEs for CPE=%s (mode=%s)", std, "mock" if self._use_mock else "live")

        started = prov.start_timer()
        if self._use_mock:
            details = await self._mock_lookup_by_cpe(std)
            max_score = max((d.cvss_v3_score for d in details if d.cvss_v3_score is not None), default=None)
            return prov.ok(SOURCE, CVEResult(cves=details, total_cves=len(details), max_cvss_score=max_score),
                           http_status=None, started=started, mock=True)

        key = f"cpe:{std.lower()}"
        cached = await self._cache_get(key, CVEResult)
        if cached is not None:
            return cached

        deadline_at = self._clock() + self._deadline
        collected: list[CVEDetail] = []
        total: int | None = None
        start_index = 0
        for _page in range(self._max_pages):
            payload, failure = await self._fetch_json(
                {"cpeName": std, "startIndex": str(start_index), "resultsPerPage": str(self._per_page)}, deadline_at)
            if failure is not None:
                if not collected:
                    return failure
                break                                       # keep the pages we already have
            try:
                items: list[dict[str, Any]] = payload.get("vulnerabilities", [])
                collected.extend(self._parse_nvd_cve_item(v) for v in items)
                total = int(payload.get("totalResults", len(collected)))
            except (KeyError, IndexError, ValueError, TypeError, AttributeError) as exc:
                logger.error("Failed to parse NVD CPE response for %s: %s", std, exc)
                if not collected:
                    return prov.error(SOURCE, "parse_error", http_status=200)
                break
            start_index += len(items)
            if not items or start_index >= total:
                break

        max_score = max((d.cvss_v3_score for d in collected if d.cvss_v3_score is not None), default=None)
        result = CVEResult(cves=collected, total_cves=len(collected), max_cvss_score=max_score)
        truncated = total is not None and len(collected) < total
        reason = f"truncated:{len(collected)}/{total}" if truncated else None
        logger.info("CPE lookup complete for %s: %d CVEs (total %s)", std, len(collected), total)
        out = prov.ok(SOURCE, result, http_status=200, started=started, reason=reason)
        await self._cache_put(key, out, self._cpe_cache_ttl)
        return out

    async def lookup_for_host(self, cve_ids: list[str], cpes: list[str] | None = None) -> ProviderResult[CVEResult]:
        """The scan's single NVD entry point: the CVE IDs InternetDB listed **plus** its (versioned) CPEs.

        Both kinds of lookup run concurrently and are merged into one ``ProviderResult`` — one ``nvd`` outcome per
        scan.  CVEs are deduplicated; CPE-derived ones (which can number in the hundreds for a popular product) are
        capped to the ``max_cpe_cves`` highest-CVSS entries.  ``reason="partial:ok/total"`` counts lookup units
        (each CVE ID and each CPE) and says so when something failed or timed out.  CPE lookups are live-only:
        mock mode keeps the original ID-only behaviour.
        """
        valid_ids = self._valid_ids(cve_ids)
        cpe_names = [] if self._use_mock else specific_cpe_names(cpes or [])[: self._max_cpes]
        if not valid_ids and not cpe_names:
            return prov.skipped(SOURCE, "no_cve_ids")
        started = prov.start_timer()

        async def ids_part():
            return await self._resolve_cves(valid_ids) if valid_ids else ([], [], 0)

        (details, failures, from_cache), *cpe_results = await asyncio.gather(
            ids_part(), *(self.lookup_by_cpe(c) for c in cpe_names))

        units_total = len(valid_ids) + len(cpe_names)
        units_ok = len(details)
        merged: dict[str, CVEDetail] = {d.cve_id.upper(): d for d in details}
        cpe_failures: list[ProviderResult] = []
        cpe_cached = 0
        for res in cpe_results:
            if not res.ok:
                cpe_failures.append(res)
                continue
            units_ok += 1
            cpe_cached += 1 if res.cached else 0
            ranked = sorted(res.data.cves, key=lambda d: d.cvss_v3_score if d.cvss_v3_score is not None else -1.0,
                            reverse=True)
            for d in ranked[: self._max_cpe_cves]:
                merged.setdefault(d.cve_id.upper(), d)
        all_failures = failures + cpe_failures

        if units_ok == 0:
            return self._best_failure(all_failures, started)
        cves = list(merged.values())
        max_score = max((d.cvss_v3_score for d in cves if d.cvss_v3_score is not None), default=None)
        result = CVEResult(cves=cves, total_cves=len(cves), max_cvss_score=max_score)
        reason = f"partial:{units_ok}/{units_total}" if units_ok < units_total else None
        all_cached = not self._use_mock and from_cache == len(details) and cpe_cached == len(cpe_results) - len(cpe_failures)
        out = prov.ok(SOURCE, result, http_status=None if (self._use_mock or all_cached) else 200,
                      started=None if all_cached else started, reason=reason, mock=self._use_mock)
        return out.model_copy(update={"cached": True}) if all_cached else out

    async def close(self) -> None:
        """Close the underlying HTTP client (process shutdown). Safe to call repeatedly."""
        if self._http_client is not None and not self._http_client.is_closed:
            try:
                await self._http_client.aclose()
            except RuntimeError:               # its loop is already closed
                pass
            logger.debug("HTTP client closed")
        self._http_client = None
        self._client_loop = None


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _cvss_v2_score_to_severity(score: float) -> str:
    """Map a CVSS v2 numeric score to a qualitative severity label.

    CVSS v2 ranges (from NIST documentation):
    - 0.0–3.9 : LOW
    - 4.0–6.9 : MEDIUM
    - 7.0–10.0: HIGH

    Note: CVSS v2 does not have a CRITICAL tier.  We add one at 9.0+ for consistency with v3 labelling in the UI,
    which always shows four severity tiers.
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"
