"""
Process-wide provider clients (A1-1)
====================================

Before this module ``/scan`` built a fresh ``VirusTotalClient`` per request and the network layer built another per
DNS event, so no cache ever hit and nothing could enforce a shared quota.  :data:`hub` owns **one** client (and one
:class:`~app.core.quota.QuotaLimiter`, and one SQLite-backed :class:`~app.core.cache.ProviderCache`) for the whole
process; scans and the network layer both go through it.  ``main.py``'s lifespan warms it at start-up and closes it
at shutdown — request handlers never close it.

It is rebuilt only when the relevant settings change (tests flip them; production never does), so the limiter's
window survives for as long as the configuration does.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.core.cache import ProviderCache
from app.core.config import get_settings
from app.core.quota import QuotaLimiter
from app.ingestion.virustotal import VirusTotalClient

logger = logging.getLogger(__name__)


class ProviderHub:
    def __init__(self) -> None:
        # The cache reads the DB path from settings on every call, like ScanStore.
        self.cache = ProviderCache(path_provider=lambda: get_settings().database_path)
        self._vt: Optional[VirusTotalClient] = None
        self._vt_key: Optional[tuple] = None

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

    async def close(self) -> None:
        """Release connections (process shutdown)."""
        if self._vt is not None:
            await self._vt.close()

    def reset(self) -> None:
        """Forget the clients (tests): the next access builds fresh ones with a fresh quota window."""
        self._vt = None
        self._vt_key = None


hub = ProviderHub()
