"""
ThreatFusion – CISA Known Exploited Vulnerabilities (KEV) feed (B11)
====================================================================

KEV is CISA's catalogue of vulnerabilities **confirmed exploited in the wild** — an observation, not a prediction
(that is EPSS's job), and the strongest "patch this now" signal there is.  ``knownRansomwareCampaignUse`` marks the ones
ransomware crews use.

The catalogue is downloaded (``KEV_FEED_URL``, through the SSRF-safe fetcher), kept in the local feed store and refreshed
at most every ``KEV_MAX_AGE_HOURS``; lookups are then free and offline, and every answer carries the feed's **age**.

Honesty rules
-------------
* A feed that has *never* been downloaded is **unknown** (``error / feed_unavailable``) — never "not listed".
* A failed refresh keeps the previous copy; the answer is ``ok`` but flagged ``stale`` (``reason = "stale_feed"``).
* A download that is unparseable, or that shrinks a ≥ 100-entry catalogue to under half, is refused
  (``parse_error`` / ``suspicious_shrink``): KEV only ever grows, so a tiny file is a truncated or poisoned one.
* "Not in KEV" is *absence of evidence* (the catalogue is deliberately incomplete): callers must not read it as safe.
"""

from __future__ import annotations

import asyncio
import json
import logging
import weakref
from typing import Optional

from pydantic import BaseModel, Field

from app.core import providers as prov
from app.core.feeds import FeedStore
from app.core.safe_http import FetchPolicy, SafeFetcher
from app.models.schemas import KevRow, ProviderResult

logger = logging.getLogger(__name__)

SOURCE = "kev"
FEED = "kev"
DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevMeta(BaseModel):
    """What a refresh obtained."""

    count: int
    catalog_version: Optional[str] = None


class KevResult(BaseModel):
    """The KEV entries among the requested CVEs (unlisted CVEs are simply absent) plus the feed's age."""

    entries: dict[str, KevRow] = Field(default_factory=dict)
    age_days: Optional[float] = None
    catalog_version: Optional[str] = None
    stale: bool = False


_MOCK_CATALOGUE = {
    "CVE-2021-44228": KevRow(date_added="2021-12-10", due_date="2021-12-24", ransomware=True, vendor="Apache",
                             product="Log4j2", name="Apache Log4j2 Remote Code Execution"),
    "CVE-2021-41773": KevRow(date_added="2021-11-03", due_date="2021-11-17", ransomware=False, vendor="Apache",
                             product="HTTP Server", name="Apache HTTP Server Path Traversal"),
    "CVE-2014-0160": KevRow(date_added="2022-05-04", due_date="2022-05-25", ransomware=False, vendor="OpenSSL",
                            product="OpenSSL", name="OpenSSL Heartbleed"),
}


class KevFeed:
    def __init__(
        self,
        use_mock: bool = True,
        *,
        store: FeedStore,
        policy: Optional[FetchPolicy] = None,
        url: str = DEFAULT_URL,
        max_age_hours: float = 24.0,
    ) -> None:
        self._use_mock = use_mock
        self._store = store
        self._policy = policy
        self._fetcher: Optional[SafeFetcher] = None
        self._url = url
        self._max_age_days = max_age_hours / 24.0
        # One refresh at a time per event loop; concurrent lookups wait for it and then share the result.
        self._locks: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = weakref.WeakKeyDictionary()

    def _get_fetcher(self) -> SafeFetcher:
        if self._fetcher is None:
            policy = self._policy or FetchPolicy.from_settings(max_bytes=12 * 1024 * 1024, total_timeout=60.0, request_timeout=30.0)
            self._fetcher = SafeFetcher(policy)
        return self._fetcher

    def _lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        lock = self._locks.get(loop)
        if lock is None:
            lock = self._locks[loop] = asyncio.Lock()
        return lock

    async def close(self) -> None:
        return None

    # ── refresh ────────────────────────────────────────────────────────
    async def refresh(self) -> ProviderResult[KevMeta]:
        """Download the catalogue now. On any failure the previous copy is left untouched."""
        started = prov.start_timer()
        try:
            res = await self._get_fetcher().fetch(self._url, headers={"Accept": "application/json"})
        except Exception as exc:                                   # blocked / timeout / network
            return prov.from_exception(SOURCE, exc, started=started)
        if res.status_code == 404:
            return prov.error(SOURCE, "not_found_upstream", http_status=404, started=started)
        failure = prov.from_http_status(SOURCE, res.status_code, started=started)
        if failure is not None:
            return failure
        try:
            doc = json.loads(res.body.decode("utf-8", errors="replace"))
            rows = doc["vulnerabilities"]
            if not isinstance(rows, list):
                raise ValueError("vulnerabilities is not a list")
            entries: dict[str, dict] = {}
            for v in rows:
                cve = str(v["cveID"]).strip().upper()
                entries[cve] = KevRow(
                    date_added=v.get("dateAdded"), due_date=v.get("dueDate"),
                    ransomware=str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                    vendor=v.get("vendorProject"), product=v.get("product"), name=v.get("vulnerabilityName"),
                ).model_dump()
            if not entries:
                raise ValueError("empty catalogue")
            version = doc.get("catalogVersion")
        except (ValueError, KeyError, TypeError, AttributeError):
            return prov.error(SOURCE, "parse_error", http_status=res.status_code, started=started)

        previous = await self._store.count(FEED)
        if previous >= 100 and len(entries) < previous * 0.5:      # KEV only grows: this is truncated or poisoned
            logger.warning("KEV download has %d entries but the local copy has %d: refused", len(entries), previous)
            return prov.error(SOURCE, "suspicious_shrink", http_status=res.status_code, started=started)

        await self._store.replace(FEED, entries, source_url=self._url, version=version)
        logger.info("KEV catalogue refreshed: %d entries (version %s)", len(entries), version)
        return prov.ok(SOURCE, KevMeta(count=len(entries), catalog_version=version), http_status=res.status_code, started=started)

    async def ensure_fresh(self) -> Optional[ProviderResult[KevMeta]]:
        """Refresh if the local copy is missing or older than ``max_age``. ``None`` when it was already fresh."""
        age = await self._store.age_days(FEED)
        if age is not None and age <= self._max_age_days:
            return None
        async with self._lock():
            age = await self._store.age_days(FEED)                  # another lookup may have refreshed meanwhile
            if age is not None and age <= self._max_age_days:
                return None
            return await self.refresh()

    # ── lookup ─────────────────────────────────────────────────────────
    async def lookup(self, cve_ids: list[str]) -> ProviderResult[KevResult]:
        ids = [c.strip().upper() for c in cve_ids if c and c.strip()]
        if self._use_mock:
            found = {c: _MOCK_CATALOGUE[c] for c in ids if c in _MOCK_CATALOGUE}
            return prov.ok(SOURCE, KevResult(entries=found, age_days=0.0, catalog_version="mock"), http_status=None, mock=True)

        await self.ensure_fresh()                                   # a failure is visible below as "stale"/"unavailable"
        meta = await self._store.meta(FEED)
        if meta is None:
            return prov.error(SOURCE, "feed_unavailable")           # never downloaded: UNKNOWN, not "not listed"
        age = await self._store.age_days(FEED)
        stale = age is not None and age > self._max_age_days
        rows = await self._store.get_many(FEED, ids)
        result = KevResult(entries={k: KevRow.model_validate(v) for k, v in rows.items()},
                           age_days=None if age is None else round(age, 3), catalog_version=meta.version, stale=stale)
        return prov.ok(SOURCE, result, http_status=None, reason="stale_feed" if stale else None)
