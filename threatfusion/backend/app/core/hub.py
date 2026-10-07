"""
Process-wide provider clients (A1-1, A1-2)
=========================================

Before this module ``/scan`` built a fresh ``VirusTotalClient`` / ``CVEClient`` per request and the network layer
built another per DNS event, so no cache ever hit and nothing could enforce a shared quota.  :data:`hub` owns **one**
client per provider (each with its own :class:`~app.core.quota.QuotaLimiter`, all sharing one SQLite-backed
:class:`~app.core.cache.ProviderCache`) for the whole process; scans and the network layer both go through it.  ``main.py``'s lifespan warms it at start-up and closes it
at shutdown — request handlers never close it.

It is rebuilt only when the relevant settings change (tests flip them; production never does), so the limiter's
window survives for as long as the configuration does.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.core.cache import ProviderCache
from app.core.config import get_settings
from app.core.quota import QuotaLimiter
from app.ingestion.cve import CVEClient
from app.ingestion.dns_records import DnsClient
from app.core.feeds import FeedStore
from app.ingestion.eol import EolClient
from app.ingestion.epss import EpssClient
from app.ingestion.kev import KevFeed
from app.ingestion.vulnrichment import VulnrichmentClient
from app.ingestion.blocklists import Ja3BlacklistFeed, OpenPhishFeed, PhishTankFeed, TrancoFeed
from app.ingestion.ct import CtClient
from app.ingestion.reputation import (AbuseIpdbChannel, GreyNoiseChannel, OtxChannel, SafeBrowsingChannel, ThreatFoxChannel,
                                      UrlhausChannel, UrlscanChannel)
from app.ingestion.reputation_set import ReputationSet
from app.ingestion.rdap import RdapClient
from app.ingestion.tls import TlsClient
from app.ingestion.virustotal import VirusTotalClient
from app.ml.brands import BrandIndex

logger = logging.getLogger(__name__)

TRANCO_FEED = "tranco"        # filled by the B2 reputation feeds: ``{domain: rank}``


class ProviderHub:
    def __init__(self) -> None:
        # The cache reads the DB path from settings on every call, like ScanStore.
        self.cache = ProviderCache(path_provider=lambda: get_settings().database_path)
        self.feeds = FeedStore(path_provider=lambda: get_settings().database_path)      # bulk feeds (KEV, B2 feeds)
        self._vt: Optional[VirusTotalClient] = None
        self._vt_key: Optional[tuple] = None
        self._nvd: Optional[CVEClient] = None
        self._nvd_key: Optional[tuple] = None
        self._tls: Optional[TlsClient] = None
        self._tls_key: Optional[tuple] = None
        self._reputation: Optional[ReputationSet] = None
        self._reputation_key: Optional[tuple] = None
        self._ct: Optional[CtClient] = None
        self._ct_key: Optional[tuple] = None
        self._rdap: Optional[RdapClient] = None
        self._rdap_key: Optional[tuple] = None
        self._dns: Optional[DnsClient] = None
        self._dns_key: Optional[tuple] = None
        self._eol: Optional[EolClient] = None
        self._eol_key: Optional[tuple] = None
        self._brands: Optional[BrandIndex] = None
        self._brands_key: Optional[tuple] = None
        self._epss: Optional[EpssClient] = None
        self._epss_key: Optional[tuple] = None
        self._kev: Optional[KevFeed] = None
        self._kev_key: Optional[tuple] = None
        self._vuln: Optional[VulnrichmentClient] = None
        self._vuln_key: Optional[tuple] = None
        self._ja3: Optional[Ja3BlacklistFeed] = None
        self._ja3_key: Optional[tuple] = None

    def virustotal(self) -> VirusTotalClient:
        s = get_settings()
        key = (
            s.VIRUSTOTAL_API_KEY, s.USE_MOCK_DATA, s.VIRUSTOTAL_REQUESTS_PER_MINUTE, s.VIRUSTOTAL_REQUESTS_PER_DAY,
            s.VIRUSTOTAL_MAX_QUEUE_SECONDS, s.VIRUSTOTAL_CACHE_TTL_SECONDS, s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS,
        )
        if self._vt is None or key != self._vt_key:
            self._vt = VirusTotalClient(
                api_key=s.VIRUSTOTAL_API_KEY,
                use_mock=s.USE_MOCK_DATA,
                limiter=QuotaLimiter(s.VIRUSTOTAL_REQUESTS_PER_MINUTE, s.VIRUSTOTAL_REQUESTS_PER_DAY),
                cache=self.cache,
                cache_ttl=s.VIRUSTOTAL_CACHE_TTL_SECONDS,
                not_found_ttl=s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS,
                max_queue_seconds=s.VIRUSTOTAL_MAX_QUEUE_SECONDS,
            )
            self._vt_key = key
        return self._vt

    def nvd(self) -> CVEClient:
        s = get_settings()
        key = (
            s.NVD_API_KEY, s.USE_MOCK_DATA, s.NVD_REQUESTS_PER_WINDOW, s.NVD_WINDOW_SECONDS, s.NVD_MAX_CONCURRENCY,
            s.NVD_DEADLINE_SECONDS, s.NVD_MAX_RETRIES, s.NVD_BACKOFF_BASE_SECONDS, s.NVD_CACHE_TTL_SECONDS,
            s.NVD_MAX_CPES, s.NVD_MAX_PAGES, s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS,
        )
        if self._nvd is None or key != self._nvd_key:
            self._nvd = CVEClient(
                api_key=s.NVD_API_KEY,
                use_mock=s.USE_MOCK_DATA,
                limiter=QuotaLimiter(windows=[(s.NVD_REQUESTS_PER_WINDOW, s.NVD_WINDOW_SECONDS)]),
                cache=self.cache,
                cache_ttl_seconds=s.NVD_CACHE_TTL_SECONDS,
                not_found_ttl_seconds=s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS,
                max_concurrency=s.NVD_MAX_CONCURRENCY,
                deadline_seconds=s.NVD_DEADLINE_SECONDS,
                max_retries=s.NVD_MAX_RETRIES,
                backoff_base=s.NVD_BACKOFF_BASE_SECONDS,
                max_pages=s.NVD_MAX_PAGES,
                max_cpes=s.NVD_MAX_CPES,
            )
            self._nvd_key = key
        return self._nvd

    def tls(self) -> TlsClient:
        s = get_settings()
        key = (s.USE_MOCK_DATA, s.TLS_TIMEOUT_SECONDS, s.TLS_CACHE_TTL_SECONDS, s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS)
        if self._tls is None or key != self._tls_key:
            self._tls = TlsClient(use_mock=s.USE_MOCK_DATA, cache=self.cache, cache_ttl=s.TLS_CACHE_TTL_SECONDS,
                                  not_found_ttl=s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS, timeout=s.TLS_TIMEOUT_SECONDS)
            self._tls_key = key
        return self._tls

    def ct(self) -> CtClient:
        s = get_settings()
        key = (s.USE_MOCK_DATA, s.CT_BASE_URL, s.CT_REQUESTS_PER_MINUTE, s.CT_CACHE_TTL_SECONDS, s.CT_MAX_BYTES,
               s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS)
        if self._ct is None or key != self._ct_key:
            self._ct = CtClient(use_mock=s.USE_MOCK_DATA, base_url=s.CT_BASE_URL, cache=self.cache,
                                cache_ttl=s.CT_CACHE_TTL_SECONDS, not_found_ttl=s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS,
                                limiter=QuotaLimiter(s.CT_REQUESTS_PER_MINUTE, 0), max_bytes=s.CT_MAX_BYTES)
            self._ct_key = key
        return self._ct

    def rdap(self) -> RdapClient:
        s = get_settings()
        key = (s.USE_MOCK_DATA, s.RDAP_REQUESTS_PER_MINUTE, s.RDAP_CACHE_TTL_SECONDS, s.RDAP_WHOIS_FALLBACK,
               s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS)
        if self._rdap is None or key != self._rdap_key:
            self._rdap = RdapClient(use_mock=s.USE_MOCK_DATA, cache=self.cache, cache_ttl=s.RDAP_CACHE_TTL_SECONDS,
                                    not_found_ttl=s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS,
                                    limiter=QuotaLimiter(s.RDAP_REQUESTS_PER_MINUTE, 0),
                                    whois_fallback=s.RDAP_WHOIS_FALLBACK)
            self._rdap_key = key
        return self._rdap

    def dns(self) -> DnsClient:
        s = get_settings()
        key = (s.USE_MOCK_DATA, s.DNS_TIMEOUT_SECONDS, s.DNS_CACHE_TTL_SECONDS, s.DNS_NAMESERVERS,
               s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS)
        if self._dns is None or key != self._dns_key:
            servers = [x.strip() for x in s.DNS_NAMESERVERS.split(",") if x.strip()] or None
            self._dns = DnsClient(use_mock=s.USE_MOCK_DATA, cache=self.cache, cache_ttl=s.DNS_CACHE_TTL_SECONDS,
                                  not_found_ttl=s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS, timeout=s.DNS_TIMEOUT_SECONDS,
                                  nameservers=servers)
            self._dns_key = key
        return self._dns

    def eol(self) -> EolClient:
        s = get_settings()
        key = (s.USE_MOCK_DATA, s.EOL_API_BASE, s.EOL_CACHE_TTL_SECONDS, s.EOL_REQUESTS_PER_MINUTE)
        if self._eol is None or key != self._eol_key:
            self._eol = EolClient(use_mock=s.USE_MOCK_DATA, cache=self.cache, base_url=s.EOL_API_BASE,
                                  cache_ttl=s.EOL_CACHE_TTL_SECONDS,
                                  limiter=QuotaLimiter(s.EOL_REQUESTS_PER_MINUTE, 0))
            self._eol_key = key
        return self._eol

    def epss(self) -> EpssClient:
        s = get_settings()
        key = (s.USE_MOCK_DATA, s.EPSS_API_BASE, s.EPSS_REQUESTS_PER_MINUTE, s.EPSS_CACHE_TTL_SECONDS)
        if self._epss is None or key != self._epss_key:
            self._epss = EpssClient(use_mock=s.USE_MOCK_DATA, base_url=s.EPSS_API_BASE, cache=self.cache,
                                    cache_ttl=s.EPSS_CACHE_TTL_SECONDS, limiter=QuotaLimiter(s.EPSS_REQUESTS_PER_MINUTE, 0))
            self._epss_key = key
        return self._epss

    def kev(self) -> KevFeed:
        s = get_settings()
        key = (s.USE_MOCK_DATA, s.KEV_FEED_URL, s.KEV_MAX_AGE_HOURS)
        if self._kev is None or key != self._kev_key:
            self._kev = KevFeed(use_mock=s.USE_MOCK_DATA, store=self.feeds, url=s.KEV_FEED_URL, max_age_hours=s.KEV_MAX_AGE_HOURS)
            self._kev_key = key
        return self._kev

    def vulnrichment(self) -> VulnrichmentClient:
        s = get_settings()
        key = (s.USE_MOCK_DATA, s.VULNRICHMENT_API_BASE, s.VULNRICHMENT_REQUESTS_PER_MINUTE, s.VULNRICHMENT_MAX_CVES)
        if self._vuln is None or key != self._vuln_key:
            self._vuln = VulnrichmentClient(use_mock=s.USE_MOCK_DATA, base_url=s.VULNRICHMENT_API_BASE, cache=self.cache,
                                            limiter=QuotaLimiter(s.VULNRICHMENT_REQUESTS_PER_MINUTE, 0),
                                            max_cves=s.VULNRICHMENT_MAX_CVES)
            self._vuln_key = key
        return self._vuln

    def ja3(self) -> Ja3BlacklistFeed:
        """The SSLBL JA3 blacklist (local feed; the network layer's TLS fingerprint check)."""
        s = get_settings()
        key = (s.USE_MOCK_DATA, s.SSLBL_JA3_FEED_URL, s.SSLBL_JA3_MAX_AGE_HOURS)
        if self._ja3 is None or key != self._ja3_key:
            self._ja3 = Ja3BlacklistFeed(s.USE_MOCK_DATA, store=self.feeds, url=s.SSLBL_JA3_FEED_URL, max_age_hours=s.SSLBL_JA3_MAX_AGE_HOURS)
            self._ja3_key = key
        return self._ja3

    def reputation(self) -> ReputationSet:
        """One client per independent reputation source (B2), rebuilt only when their settings change."""
        import app as _app_pkg

        s = get_settings()
        key = (
            s.USE_MOCK_DATA, s.ABUSECH_AUTH_KEY, s.GOOGLE_SAFE_BROWSING_API_KEY, s.ABUSEIPDB_API_KEY, s.OTX_API_KEY,
            s.URLSCAN_API_KEY, s.GREYNOISE_API_KEY, s.PHISHTANK_APP_KEY, s.ABUSEIPDB_MIN_CONFIDENCE,
            s.REPUTATION_CACHE_TTL_SECONDS, s.REPUTATION_REQUESTS_PER_MINUTE, s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS,
            s.OPENPHISH_FEED_URL, s.OPENPHISH_MAX_AGE_HOURS, s.PHISHTANK_FEED_URL, s.PHISHTANK_MAX_AGE_HOURS,
            s.TRANCO_FEED_URL, s.TRANCO_MAX_AGE_HOURS, s.TRANCO_TOP_N,
        )
        if self._reputation is None or key != self._reputation_key:
            common = dict(use_mock=s.USE_MOCK_DATA, cache=self.cache, cache_ttl=s.REPUTATION_CACHE_TTL_SECONDS,
                          not_found_ttl=s.PROVIDER_CACHE_NOT_FOUND_TTL_SECONDS)

            def channel(cls, api_key="", **opts):
                return cls(api_key=api_key, limiter=QuotaLimiter(s.REPUTATION_REQUESTS_PER_MINUTE, 0), **common, **opts)

            phishtank_url = s.PHISHTANK_FEED_URL
            if s.PHISHTANK_APP_KEY and "/data/online" in phishtank_url:
                phishtank_url = phishtank_url.replace("/data/online", f"/data/{s.PHISHTANK_APP_KEY}/online", 1)
            clients = {
                "openphish": OpenPhishFeed(s.USE_MOCK_DATA, store=self.feeds, url=s.OPENPHISH_FEED_URL,
                                           max_age_hours=s.OPENPHISH_MAX_AGE_HOURS),
                "phishtank": PhishTankFeed(s.USE_MOCK_DATA, store=self.feeds, url=phishtank_url,
                                           max_age_hours=s.PHISHTANK_MAX_AGE_HOURS),
                "tranco": TrancoFeed(s.USE_MOCK_DATA, store=self.feeds, url=s.TRANCO_FEED_URL,
                                     max_age_hours=s.TRANCO_MAX_AGE_HOURS, top_n=s.TRANCO_TOP_N),
                "urlhaus": channel(UrlhausChannel, s.ABUSECH_AUTH_KEY),
                "threatfox": channel(ThreatFoxChannel, s.ABUSECH_AUTH_KEY),
                "safebrowsing": channel(SafeBrowsingChannel, s.GOOGLE_SAFE_BROWSING_API_KEY, client_version=_app_pkg.APP_VERSION),
                "urlscan": channel(UrlscanChannel, s.URLSCAN_API_KEY),
                "otx": channel(OtxChannel, s.OTX_API_KEY),
                "abuseipdb": channel(AbuseIpdbChannel, s.ABUSEIPDB_API_KEY, min_confidence=s.ABUSEIPDB_MIN_CONFIDENCE),
                "greynoise": channel(GreyNoiseChannel, s.GREYNOISE_API_KEY),
            }
            self._reputation = ReputationSet(clients)
            self._reputation_key = key
        return self._reputation

    async def brands(self) -> BrandIndex:
        """The protected-brand index: the curated list, plus the top of the Tranco feed once B2 has downloaded it.

        Rebuilt only when the feed was re-fetched (its ``fetched_at`` changes); a missing feed is not an error — the
        check then runs on the curated list alone and reports ``popular_checked: 0``.
        """
        s = get_settings()
        meta = await self.feeds.meta(TRANCO_FEED)
        key = (meta.fetched_at if meta else None, s.LOOKALIKE_POPULAR_LIMIT)
        if self._brands is None or key != self._brands_key:
            popular: list[tuple[str, int]] = []
            if meta is not None:
                rows = await self.feeds.items(TRANCO_FEED, s.LOOKALIKE_POPULAR_LIMIT)
                popular = sorted(((d, int(r)) for d, r in rows if isinstance(r, (int, float))), key=lambda x: x[1])
            self._brands = await asyncio.to_thread(BrandIndex.build, popular, s.LOOKALIKE_POPULAR_LIMIT)
            self._brands_key = key
        return self._brands

    async def close(self) -> None:
        """Release connections (process shutdown)."""
        if self._vt is not None:
            await self._vt.close()
        if self._nvd is not None:
            await self._nvd.close()
        for client in (self._epss, self._vuln, self._reputation):
            if client is not None:
                await client.close()

    def reset(self) -> None:
        """Forget the clients (tests): the next access builds fresh ones with a fresh quota window."""
        self._vt = None
        self._vt_key = None
        self._nvd = None
        self._nvd_key = None
        self._tls = self._rdap = self._dns = self._eol = self._ct = None
        self._tls_key = self._rdap_key = self._dns_key = self._eol_key = self._ct_key = None
        self._epss = self._kev = self._vuln = self._ja3 = None
        self._epss_key = self._kev_key = self._vuln_key = self._ja3_key = None
        self._brands = None
        self._brands_key = None
        self._reputation = None
        self._reputation_key = None


hub = ProviderHub()
