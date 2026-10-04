"""
Provider response cache (A1-1)
==============================

A TTL cache for third-party lookups, kept in SQLite (``provider_cache``, schema v3) so it survives restarts and is
shared by every request — the per-scan client's in-memory dict never hit, which is why a repeated scan burnt
VirusTotal quota again.

What is cached — and what is not
--------------------------------
* ``ok`` and ``not_found`` are *answers* and are cached (``not_found`` for a shorter time: a brand-new phishing
  page may be submitted to a provider minutes later).
* ``error``, ``skipped`` and ``not_configured`` are **never** stored.  Audit §F: the old client cached the empty
  result of a failed call for an hour, turning an outage into a clean verdict.  A failure must be retried.
* A cached result keeps its **original** ``fetched_at`` (the UI shows how old the evidence is) and is flagged
  ``cached=True``.

Privacy: the key identifies the looked-up object, and URLs are keyed by a SHA-256 of the string — never the URL
itself, which can carry tokens.  Domain/IP keys are plain (they are what the user looked up) and are covered by
``DELETE /network/data``.

``ProviderCache()`` with no path is an in-memory store with identical semantics (tests, ephemeral clients).
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Callable, Optional, Type, TypeVar

import aiosqlite
from pydantic import BaseModel

from app.core.db import ensure_db
from app.models.schemas import ProviderResult, ProviderStatus

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_CACHEABLE = (ProviderStatus.OK, ProviderStatus.NOT_FOUND)


def url_key(url: str) -> str:
    """Cache key component for a URL: a digest, never the URL (it may contain tokens)."""
    return "url:" + hashlib.sha256(url.encode("utf-8")).hexdigest()


class ProviderCache:
    def __init__(
        self,
        path_provider: Optional[Callable[[], Path]] = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path_provider = path_provider
        self._clock = clock                      # wall clock: expiry must survive a restart
        self._mem: dict[tuple[str, str], tuple[str, str, float]] = {}   # (payload, status, expires_at)

    # ── helpers ────────────────────────────────────────────────────────
    async def _connect(self) -> aiosqlite.Connection:
        """The (not yet started) connection — use as ``async with await self._connect() as db``."""
        path = self._path_provider()
        await ensure_db(path)
        return aiosqlite.connect(path)

    # ── API ────────────────────────────────────────────────────────────
    async def get(self, source: str, key: str, data_model: Type[T]) -> Optional[ProviderResult[T]]:
        """A fresh cached answer (``cached=True``, original ``fetched_at``), or ``None``."""
        now = self._clock()
        if self._path_provider is None:
            row = self._mem.get((source, key))
            if row is None:
                return None
            if row[2] <= now:
                del self._mem[(source, key)]
                return None
            payload = row[0]
        else:
            async with await self._connect() as db:
                async with db.execute(
                    "SELECT payload FROM provider_cache WHERE source=? AND cache_key=? AND expires_at>?",
                    (source, key, now),
                ) as cur:
                    found = await cur.fetchone()
            if found is None:
                return None
            payload = found[0]
        try:
            result = ProviderResult[data_model].model_validate_json(payload)
        except Exception:                          # a row written by an older shape: treat as a miss
            logger.warning("Ignoring unreadable provider_cache row for %s", source)
            return None
        return result.model_copy(update={"cached": True})

    async def put(self, source: str, key: str, result: ProviderResult, *, ttl_ok: float,
                  ttl_not_found: float) -> bool:
        """Store ``result`` if (and only if) it is an answer. Returns whether it was stored."""
        if result.status not in _CACHEABLE:
            return False
        ttl = ttl_ok if result.status == ProviderStatus.OK else ttl_not_found
        if ttl <= 0:
            return False
        payload = result.model_copy(update={"cached": False}).model_dump_json()
        expires = self._clock() + ttl
        if self._path_provider is None:
            self._mem[(source, key)] = (payload, result.status.value, expires)
            return True
        async with await self._connect() as db:
            await db.execute(
                "INSERT OR REPLACE INTO provider_cache (source, cache_key, status, payload, fetched_at, expires_at) "
                "VALUES (?,?,?,?,?,?)",
                (source, key, result.status.value, payload, result.fetched_at.isoformat(), expires),
            )
            await db.commit()
        return True

    async def purge_expired(self) -> int:
        now = self._clock()
        if self._path_provider is None:
            stale = [k for k, v in self._mem.items() if v[2] <= now]
            for k in stale:
                del self._mem[k]
            return len(stale)
        async with await self._connect() as db:
            cur = await db.execute("DELETE FROM provider_cache WHERE expires_at<=?", (now,))
            await db.commit()
            return cur.rowcount

    async def clear(self, source: Optional[str] = None) -> int:
        """Drop every cached lookup (optionally just one source). Used by the user's 'erase data' action."""
        if self._path_provider is None:
            keys = [k for k in self._mem if source is None or k[0] == source]
            for k in keys:
                del self._mem[k]
            return len(keys)
        async with await self._connect() as db:
            if source is None:
                cur = await db.execute("DELETE FROM provider_cache")
            else:
                cur = await db.execute("DELETE FROM provider_cache WHERE source=?", (source,))
            await db.commit()
            return cur.rowcount

    async def count(self) -> int:
        """Rows currently stored (including not-yet-purged expired ones)."""
        if self._path_provider is None:
            return len(self._mem)
        async with await self._connect() as db:
            async with db.execute("SELECT count(*) FROM provider_cache") as cur:
                return (await cur.fetchone())[0]
