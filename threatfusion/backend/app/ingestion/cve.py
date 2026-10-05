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
  internet connection.  An optional API key lifts the rate limit from
  5 → 50 requests per 30-second window.

Rate-limit compliance
---------------------
NVD is aggressive about rate-limiting.  Rather than retrying after a 403,
we **proactively** throttle with an ``asyncio.Semaphore`` that replenishes
on a 30-second rolling window.  This keeps the client well-behaved and
avoids IP-level bans during batch scans.

Caching
-------
A simple in-memory dict cache with configurable TTL avoids redundant API
calls when the same CVE is referenced by multiple hosts in one scan
session.  We intentionally avoid external cache stores (Redis, etc.) to
keep the deployment footprint minimal for a university project.

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
from typing import Any

import httpx

from app.core import providers as prov
from app.core.logging import get_logger
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

# Default cache TTL in seconds (1 hour).  CVE data rarely changes within
# a single analysis session, so aggressive caching is safe.
_DEFAULT_CACHE_TTL_SECONDS: int = 3600

# Rate-limit window in seconds (NVD uses a 30-second rolling window).
_RATE_LIMIT_WINDOW_SECONDS: float = 30.0

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
# Cache entry
# ---------------------------------------------------------------------------

class _CacheEntry:
    """Timestamped cache entry for CVE details.

    We wrap the data with an insertion timestamp rather than using a
    background eviction thread because the cache is small (tens of
    entries per scan) and TTL checks on read are simpler and thread-safe.
    """

    __slots__ = ("data", "created_at")

    def __init__(self, data: CVEDetail) -> None:
        self.data: CVEDetail = data
        self.created_at: float = time.monotonic()

    def is_expired(self, ttl_seconds: float) -> bool:
        """Return ``True`` if the entry is older than ``ttl_seconds``."""
        return (time.monotonic() - self.created_at) > ttl_seconds


# ---------------------------------------------------------------------------
# CVEClient
# ---------------------------------------------------------------------------

class CVEClient:
    """Async client for the NIST NVD v2 API with mock fallback.

    This is the primary interface the orchestrator uses to hydrate bare
    CVE IDs (e.g. ``"CVE-2021-44228"``) into full ``CVEDetail`` records
    with descriptions, CVSS scores, and severity labels.

    Parameters
    ----------
    api_key : str
        NVD API key (optional but strongly recommended to raise the rate
        limit from 5 → 50 req / 30 s).  Empty string means "no key".
        **Never hardcode keys** — pass from environment variables via
        ``settings.nvd_api_key``.
    use_mock : bool
        When ``True``, return deterministic synthetic data instead of
        making real HTTP calls.  Defaults to ``True`` so that the project
        works out of the box with zero configuration.

    Usage
    -----
    ::

        async with CVEClient(api_key=settings.nvd_api_key) as client:
            result = await client.lookup_cves(["CVE-2021-44228"])
            print(result.max_cvss_score)  # 10.0

    The client is an async context manager — ``__aenter__`` / ``__aexit__``
    handle httpx lifetime.  You can also call ``close()`` manually.
    """

    def __init__(
        self,
        api_key: str = "",
        use_mock: bool = True,
        *,
        cache_ttl_seconds: int = _DEFAULT_CACHE_TTL_SECONDS,
    ) -> None:
        self._api_key: str = api_key
        self._use_mock: bool = use_mock
        self._base_url: str = _NVD_BASE_URL
        self._cache_ttl: int = cache_ttl_seconds

        # ── In-memory cache ──────────────────────────────────────────
        # Keyed by cache key (CVE ID or CPE string) → _CacheEntry.
        self._cache: dict[str, _CacheEntry] = {}

        # ── Rate limiter ─────────────────────────────────────────────
        # We use an asyncio.Semaphore to cap concurrent in-flight
        # requests.  The semaphore size matches NVD's published limits.
        # After each request we schedule a delayed release so the
        # semaphore replenishes on the 30-second rolling window.
        max_concurrent: int = 50 if self._api_key else 5
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(max_concurrent)
        self._rate_limit_window: float = _RATE_LIMIT_WINDOW_SECONDS

        # ── HTTP client ──────────────────────────────────────────────
        # Initialised lazily (only when live mode is actually used) to
        # avoid creating event-loop-bound resources at import time.
        # In mock mode this stays None and is never touched.
        self._http_client: httpx.AsyncClient | None = None

        logger.info(
            "CVEClient initialised (mock_mode=%s, has_api_key=%s, "
            "rate_limit=%d req/%ds, cache_ttl=%ds)",
            self._use_mock,
            bool(self._api_key),
            max_concurrent,
            int(self._rate_limit_window),
            self._cache_ttl,
        )

    # ------------------------------------------------------------------
    # Async context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> CVEClient:
        """Allow ``async with CVEClient(...) as client:`` usage."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Ensure the HTTP client is closed when exiting the context."""
        await self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_http_client(self) -> httpx.AsyncClient:
        """Lazily create and return the shared ``httpx.AsyncClient``.

        Lazy initialisation avoids binding to an event loop at
        construction time, which would fail if the client is instantiated
        outside of an async context (e.g. during module import or in
        FastAPI's dependency-injection wiring).
        """
        if self._http_client is None or self._http_client.is_closed:
            headers: dict[str, str] = {
                "Accept": "application/json",
                "User-Agent": "ThreatFusion/0.1.0 (university-project)",
            }
            if self._api_key:
                # NVD expects the API key in a custom header, NOT as a
                # query parameter.  This is a common mistake in tutorials.
                headers["apiKey"] = self._api_key
            self._http_client = httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(_REQUEST_TIMEOUT_SECONDS),
                # Enable HTTP/2 for potentially better throughput on
                # batch lookups (NVD supports it).
                http2=False,  # Set to True if h2 is installed
            )
        return self._http_client

    def _cache_get(self, key: str) -> CVEDetail | None:
        """Retrieve a cached CVE detail if it exists and hasn't expired.

        Returns ``None`` on cache miss or expiry (which also evicts the
        stale entry to reclaim memory).
        """
        entry = self._cache.get(key)
        if entry is None:
            return None
        if entry.is_expired(self._cache_ttl):
            # Evict expired entry eagerly.
            del self._cache[key]
            logger.debug("Cache expired for key=%s", key)
            return None
        logger.debug("Cache hit for key=%s", key)
        return entry.data

    def _cache_set(self, key: str, detail: CVEDetail) -> None:
        """Store a CVE detail in the cache."""
        self._cache[key] = _CacheEntry(detail)

    async def _rate_limited_request(
        self,
        params: dict[str, str],
    ) -> tuple[httpx.Response | None, ProviderResult | None]:
        """Execute a rate-limited GET against NVD → ``(response, None)`` or ``(None, failure)``.

        The semaphore ensures we never exceed NVD's published rate limits.  After acquiring
        it we schedule a delayed release (after ``_rate_limit_window`` seconds) so the slot
        becomes available again once the rolling window has elapsed.

        A non-200 answer is classified, not swallowed (A0-1): 404 → ``not_found``;
        403 → ``error/auth_or_rate_limited`` (NVD uses 403 for an invalid key *and* for
        throttling); 429 → ``rate_limited``; 5xx → ``server_error``; timeout/connect errors
        → ``timeout`` / ``network``.
        """
        await self._semaphore.acquire()

        # Hold the slot for the full rate-limit window so that at most N requests can be
        # in flight within any 30-second period.
        loop = asyncio.get_running_loop()
        loop.call_later(self._rate_limit_window, self._semaphore.release)

        client = self._get_http_client()
        started = prov.start_timer()

        try:
            logger.debug("NVD API request: params=%s", params)
            response = await client.get(self._base_url, params=params)
        except Exception as exc:
            logger.error("NVD API request failed for params=%s: %s", params, exc)
            return None, prov.from_exception(SOURCE, exc, started=started)

        failure = prov.from_http_status(
            SOURCE, response.status_code, started=started, forbidden_reason="auth_or_rate_limited",
        )
        if failure is not None:
            logger.warning("NVD API returned HTTP %d for params=%s", response.status_code, params)
            return None, failure
        return response, None

    @staticmethod
    def _parse_nvd_cve_item(cve_item: dict[str, Any]) -> CVEDetail:
        """Parse a single CVE item from the NVD v2 response into a ``CVEDetail``.

        NVD v2 Response Structure (abbreviated)::

            {
              "vulnerabilities": [
                {
                  "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                      {"lang": "en", "value": "..."}
                    ],
                    "metrics": {
                      "cvssMetricV31": [
                        {
                          "cvssData": {
                            "baseScore": 10.0,
                            "baseSeverity": "CRITICAL"
                          }
                        }
                      ]
                    },
                    "published": "2021-12-10T10:15:00.000"
                  }
                }
              ]
            }

        We prefer CVSS v3.1 metrics.  If unavailable, we fall back to
        v3.0, then to v2 (with a severity mapping).  This graceful
        degradation handles the ~20% of CVEs that lack v3 scores.
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
                    # CVSS v2 doesn't have baseSeverity in the same format,
                    # so we derive it from the numeric score.
                    severity = _cvss_v2_score_to_severity(cvss_score)

        # ── Extract published date ───────────────────────────────────
        published_str: str = cve_data.get("published", "")
        published_date: datetime | None = None
        if published_str:
            try:
                # NVD uses ISO 8601 format, sometimes with trailing 'Z'
                # or '.000' fractional seconds.
                published_date = datetime.fromisoformat(
                    published_str.replace("Z", "+00:00")
                )
            except ValueError:
                logger.warning(
                    "Could not parse published date '%s' for %s",
                    published_str,
                    cve_id,
                )

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
        """Return mock data for a single CVE ID.

        Known CVEs return curated realistic data; unknown IDs get a
        plausible MEDIUM-severity placeholder.  The ``await asyncio.sleep``
        simulates network latency so that integration tests exercise the
        same concurrency patterns as live mode.
        """
        # Simulate a tiny network delay (10ms) for realism.
        await asyncio.sleep(0.01)

        normalised_id: str = cve_id.upper().strip()
        if normalised_id in _MOCK_CVE_DB:
            logger.debug("Mock hit for known CVE: %s", normalised_id)
            return _MOCK_CVE_DB[normalised_id]

        logger.debug(
            "Mock fallback: generating plausible entry for unknown CVE %s",
            normalised_id,
        )
        return _generate_unknown_mock_cve(normalised_id)

    async def _mock_lookup_by_cpe(self, cpe: str) -> list[CVEDetail]:
        """Return mock CVEs matching a CPE string.

        In mock mode we return a fixed set of CVEs for any CPE that
        contains 'apache', and a single generic CVE for everything else.
        This gives the frontend something meaningful to display.
        """
        await asyncio.sleep(0.02)

        cpe_lower = cpe.lower()
        if "apache" in cpe_lower:
            # Return the two Apache-related CVEs from our mock database.
            results: list[CVEDetail] = [
                _MOCK_CVE_DB["CVE-2021-41773"],
            ]
            # If the CPE mentions log4j, also include Log4Shell.
            if "log4j" in cpe_lower:
                results.append(_MOCK_CVE_DB["CVE-2021-44228"])
            return results

        if "openssl" in cpe_lower:
            return [_MOCK_CVE_DB["CVE-2014-0160"]]

        # Generic fallback — return one plausible CVE.
        return [_generate_unknown_mock_cve("CVE-2023-99999")]

    # ------------------------------------------------------------------
    # Live API helpers
    # ------------------------------------------------------------------

    async def _live_lookup_single(self, cve_id: str) -> tuple[CVEDetail | None, ProviderResult | None]:
        """Fetch one CVE → ``(detail, None)`` or ``(None, why-not)``.

        The failure result lets the caller tell "NVD has no such CVE" from "the request failed"
        — the old code returned a bare ``None`` for both.
        """
        response, failure = await self._rate_limited_request({"cveId": cve_id})
        if failure is not None:
            return None, failure

        try:
            payload: dict[str, Any] = response.json()
            vulnerabilities: list[dict[str, Any]] = payload.get("vulnerabilities", [])
            if not vulnerabilities:
                logger.warning("NVD returned empty vulnerabilities array for %s", cve_id)
                return None, prov.not_found(SOURCE, http_status=response.status_code)
            return self._parse_nvd_cve_item(vulnerabilities[0]), None
        except (KeyError, IndexError, ValueError, TypeError, AttributeError) as exc:
            logger.error("Failed to parse NVD response for %s: %s", cve_id, exc)
            return None, prov.error(SOURCE, "parse_error", http_status=response.status_code)

    async def _live_lookup_by_cpe(self, cpe: str) -> tuple[list[CVEDetail], ProviderResult | None]:
        """Fetch all CVEs matching a CPE → ``(details, None)`` or ``([], failure)``.

        NVD paginates (default 2000/page); only the first page is fetched (pagination: A1-2).
        An empty list with no failure is a genuine answer ("no CVEs for this CPE").
        """
        response, failure = await self._rate_limited_request({"cpeName": cpe})
        if failure is not None:
            return [], failure

        try:
            payload: dict[str, Any] = response.json()
            vulnerabilities: list[dict[str, Any]] = payload.get("vulnerabilities", [])
            results = [self._parse_nvd_cve_item(v) for v in vulnerabilities]
            total = payload.get("totalResults", len(results))
            if total > len(results):
                logger.info(
                    "NVD reported %d total CVEs for CPE=%s, but only fetched first page (%d results).",
                    total, cpe, len(results),
                )
            return results, None
        except (KeyError, IndexError, ValueError, TypeError, AttributeError) as exc:
            logger.error("Failed to parse NVD CPE response for %s: %s", cpe, exc)
            return [], prov.error(SOURCE, "parse_error", http_status=response.status_code)

    # ------------------------------------------------------------------
    # Public async methods
    # ------------------------------------------------------------------

    async def lookup_cves(self, cve_ids: list[str]) -> ProviderResult[CVEResult]:
        """Fetch full details for a list of CVE IDs.

        Each ID (e.g. ``"CVE-2021-44228"``) is looked up individually against NVD (or the
        mock database).  Returns a ``ProviderResult[CVEResult]``:

        * ``ok`` – at least one CVE was retrieved (``reason="partial:n/m"`` if some failed);
        * ``not_found`` – NVD answered but knows none of the IDs;
        * ``error`` – nothing could be retrieved because requests failed (reason says why);
        * ``skipped`` – no valid CVE IDs were supplied.

        Crucially, "NVD failed" is **never** reported as ``CVEResult(max_cvss_score=0.0)`` —
        that made an unreachable NVD look like "no critical vulnerabilities".
        """
        if not cve_ids:
            logger.debug("lookup_cves called with empty list")
            return prov.skipped(SOURCE, "no_cve_ids")

        # ── Deduplicate and validate ─────────────────────────────────
        seen: set[str] = set()
        valid_ids: list[str] = []
        for raw_id in cve_ids:
            normalised: str = raw_id.upper().strip()
            if normalised in seen:
                continue
            seen.add(normalised)
            if not _CVE_ID_PATTERN.match(normalised):
                logger.warning("Skipping invalid CVE ID format: '%s'", raw_id)
                continue
            valid_ids.append(normalised)

        if not valid_ids:
            logger.warning("No valid CVE IDs after filtering")
            return prov.skipped(SOURCE, "no_valid_cve_ids")

        logger.info(
            "Looking up %d CVE(s) (mode=%s): %s",
            len(valid_ids),
            "mock" if self._use_mock else "live",
            ", ".join(valid_ids[:5]) + ("..." if len(valid_ids) > 5 else ""),
        )

        # ── Perform lookups (with cache) ─────────────────────────────
        started = prov.start_timer()
        details: list[CVEDetail] = []
        failures: list[ProviderResult] = []
        from_cache = 0

        for cve_id in valid_ids:
            cached = self._cache_get(cve_id)
            if cached is not None:
                details.append(cached)
                from_cache += 1
                continue

            if self._use_mock:
                detail, failure = await self._mock_lookup_single(cve_id), None
            else:
                detail, failure = await self._live_lookup_single(cve_id)

            if detail is not None:
                self._cache_set(cve_id, detail)
                details.append(detail)
            else:
                failure = failure or prov.error(SOURCE, "unknown")
                logger.warning("No data for %s (%s)", cve_id, failure.reason or failure.status.value)
                failures.append(failure)

        # ── Aggregate ────────────────────────────────────────────────
        if details:
            max_score = max((d.cvss_v3_score for d in details if d.cvss_v3_score is not None), default=0.0)
            result = CVEResult(cves=details, total_cves=len(details), max_cvss_score=max_score)
            logger.info("CVE lookup complete: %d/%d succeeded, max_cvss=%.1f",
                        len(details), len(valid_ids), max_score)
            partial = f"partial:{len(details)}/{len(valid_ids)}" if len(details) < len(valid_ids) else None
            all_cached = from_cache == len(details) and not self._use_mock
            out = prov.ok(SOURCE, result, http_status=None if (self._use_mock or all_cached) else 200,
                          started=None if all_cached else started, reason=partial, mock=self._use_mock)
            return out.model_copy(update={"cached": True}) if all_cached else out

        # Nothing retrieved: report the most informative failure (errors outrank not_found).
        errors = [f for f in failures if f.status == ProviderStatus.ERROR]
        chosen = errors[0] if errors else failures[0]
        return chosen.model_copy(update={"latency_ms": prov._latency_ms(started)})

    async def lookup_by_cpe(self, cpe: str) -> ProviderResult[CVEResult]:
        """Find all CVEs associated with a **CPE** string.

        Useful for discovering vulnerabilities in a specific software product/version detected
        by Shodan or the tech fingerprinter.  An empty list from NVD is a genuine ``ok`` answer
        ("no known CVEs"); a failed request is an ``error`` — never an empty ``CVEResult``.

        Parameters
        ----------
        cpe : str
            CPE 2.3 formatted string
            (e.g. ``"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"``).
        """
        if not cpe or not cpe.strip():
            logger.warning("lookup_by_cpe called with empty CPE")
            return prov.skipped(SOURCE, "no_cpe")

        cpe = cpe.strip()
        logger.info("Looking up CVEs for CPE=%s (mode=%s)", cpe, "mock" if self._use_mock else "live")

        # CPE lookups return many CVEs; the cache holds single CVEDetail objects, so CPE
        # results are not cached yet (A1-2 adds a persistent provider cache).
        started = prov.start_timer()
        if self._use_mock:
            cve_details, failure = await self._mock_lookup_by_cpe(cpe), None
        else:
            cve_details, failure = await self._live_lookup_by_cpe(cpe)

        if failure is not None:
            return failure

        max_score = max((d.cvss_v3_score for d in cve_details if d.cvss_v3_score is not None), default=0.0)
        result = CVEResult(cves=cve_details, total_cves=len(cve_details), max_cvss_score=max_score)
        logger.info("CPE lookup complete for %s: %d CVEs found, max_cvss=%.1f", cpe, len(cve_details), max_score)
        return prov.ok(SOURCE, result, http_status=None if self._use_mock else 200,
                       started=started, mock=self._use_mock)

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources.

        Safe to call multiple times.  After closing, any subsequent API
        calls will lazily create a new client.
        """
        if self._http_client is not None and not self._http_client.is_closed:
            await self._http_client.aclose()
            logger.debug("HTTP client closed")
        self._http_client = None

    def clear_cache(self) -> None:
        """Purge all cached CVE entries.

        Useful in tests or when the operator knows NVD data has been
        updated (e.g. after a coordinated disclosure).
        """
        count = len(self._cache)
        self._cache.clear()
        logger.info("Cleared %d entries from CVE cache", count)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _cvss_v2_score_to_severity(score: float) -> str:
    """Map a CVSS v2 numeric score to a qualitative severity label.

    CVSS v2 ranges (from NIST documentation):
    - 0.0–3.9 : LOW
    - 4.0–6.9 : MEDIUM
    - 7.0–10.0: HIGH

    Note: CVSS v2 does not have a CRITICAL tier.  We add one at 9.0+
    for consistency with v3 labelling in the UI, which always shows
    four severity tiers.
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"
