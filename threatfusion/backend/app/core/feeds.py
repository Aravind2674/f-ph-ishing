"""
Local feed store (B11 / B2, schema v4)
======================================

A **feed** is a bulk list that is downloaded and kept locally: CISA KEV today; OpenPhish, PhishTank and Tranco in B2.
Looking a target up in a feed costs no quota and makes no network call, and — the point of this module — every feed
remembers *when it was fetched*, so the UI can show its age and the scan can say "KEV data is 3 days old" instead of
pretending the list is current.

Rules shared by every feed
--------------------------
* A refresh **replaces** the feed atomically (one transaction): readers see the old list or the new one, never half.
* A refresh that fails leaves the previous list in place; the caller reports the feed as *stale*.
* A feed that was never downloaded has no :class:`FeedMeta` — callers treat that as **unknown**, never as "not listed".

``FeedStore()`` with no path is an in-memory store with identical semantics (tests, ephemeral use).
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import aiosqlite

from app.core.db import ensure_db

logger = logging.getLogger(__name__)

_CHUNK = 500          # SQLite's variable limit is 999; stay well under it for IN (...) lookups


@dataclass(frozen=True)
class FeedMeta:
    feed: str
    fetched_at: float            # epoch seconds
    source_url: str
    record_count: int
    version: Optional[str]


class FeedStore:
    def __init__(self, path_provider: Optional[Callable[[], Path]] = None, *, clock: Callable[[], float] = time.time) -> None:
        self._path_provider = path_provider
        self._clock = clock
        self._mem_entries: dict[str, dict[str, str]] = {}
        self._mem_meta: dict[str, FeedMeta] = {}

    async def _connect(self) -> aiosqlite.Connection:
        path = self._path_provider()
        await ensure_db(path)
        return aiosqlite.connect(path)

    # ── writes ─────────────────────────────────────────────────────────
    async def replace(self, feed: str, entries: dict[str, Any], *, source_url: str, version: Optional[str] = None) -> FeedMeta:
        """Atomically replace the whole feed (values are JSON-serialisable) and stamp it as fetched now."""
        meta = FeedMeta(feed=feed, fetched_at=self._clock(), source_url=source_url, record_count=len(entries), version=version)
        encoded = {k: json.dumps(v, separators=(",", ":")) for k, v in entries.items()}
        if self._path_provider is None:
            self._mem_entries[feed] = encoded
            self._mem_meta[feed] = meta
            return meta
        async with await self._connect() as db:
            await db.execute("DELETE FROM feed_entries WHERE feed=?", (feed,))
            await db.executemany("INSERT INTO feed_entries (feed, key, value) VALUES (?,?,?)",
                                 ((feed, k, v) for k, v in encoded.items()))
            await db.execute(
                "INSERT OR REPLACE INTO feed_meta (feed, fetched_at, source_url, record_count, version) VALUES (?,?,?,?,?)",
                (feed, meta.fetched_at, source_url, meta.record_count, version))
            await db.commit()                         # one transaction: readers never see a half-written feed
        return meta

    async def clear(self, feed: Optional[str] = None) -> int:
        """Forget a feed (or all of them). Used by the user's 'erase data' action. Returns entries removed."""
        if self._path_provider is None:
            feeds = [feed] if feed else list(self._mem_entries)
            removed = sum(len(self._mem_entries.pop(f, {})) for f in feeds)
            for f in feeds:
                self._mem_meta.pop(f, None)
            return removed
        async with await self._connect() as db:
            if feed:
                cur = await db.execute("DELETE FROM feed_entries WHERE feed=?", (feed,))
                await db.execute("DELETE FROM feed_meta WHERE feed=?", (feed,))
            else:
                cur = await db.execute("DELETE FROM feed_entries")
                await db.execute("DELETE FROM feed_meta")
            await db.commit()
            return cur.rowcount

    # ── reads ──────────────────────────────────────────────────────────
    async def meta(self, feed: str) -> Optional[FeedMeta]:
        if self._path_provider is None:
            return self._mem_meta.get(feed)
        async with await self._connect() as db:
            async with db.execute(
                "SELECT feed, fetched_at, source_url, record_count, version FROM feed_meta WHERE feed=?", (feed,)
            ) as cur:
                row = await cur.fetchone()
        return FeedMeta(*row) if row else None

    async def age_days(self, feed: str) -> Optional[float]:
        """Days since the feed was last fetched; ``None`` if it never was (unknown, not "fresh")."""
        meta = await self.meta(feed)
        return None if meta is None else max(0.0, (self._clock() - meta.fetched_at) / 86400.0)

    async def count(self, feed: str) -> int:
        if self._path_provider is None:
            return len(self._mem_entries.get(feed, {}))
        async with await self._connect() as db:
            async with db.execute("SELECT count(*) FROM feed_entries WHERE feed=?", (feed,)) as cur:
                return (await cur.fetchone())[0]

    async def items(self, feed: str, limit: int = 10_000) -> list[tuple[str, Any]]:
        """Up to ``limit`` ``(key, value)`` pairs of a feed (e.g. the top of a ranked list); ``[]`` if it was never fetched."""
        if self._path_provider is None:
            table = self._mem_entries.get(feed, {})
            return [(k, json.loads(v)) for k, v in list(table.items())[:limit]]
        async with await self._connect() as db:
            async with db.execute("SELECT key, value FROM feed_entries WHERE feed=? LIMIT ?", (feed, limit)) as cur:
                return [(k, json.loads(v)) for k, v in await cur.fetchall()]

    async def get(self, feed: str, key: str) -> Optional[Any]:
        return (await self.get_many(feed, [key])).get(key)

    async def get_many(self, feed: str, keys: Iterable[str]) -> dict[str, Any]:
        keys = list(dict.fromkeys(keys))
        if self._path_provider is None:
            table = self._mem_entries.get(feed, {})
            return {k: json.loads(table[k]) for k in keys if k in table}
        found: dict[str, Any] = {}
        async with await self._connect() as db:
            for i in range(0, len(keys), _CHUNK):
                chunk = keys[i:i + _CHUNK]
                marks = ",".join("?" * len(chunk))
                async with db.execute(f"SELECT key, value FROM feed_entries WHERE feed=? AND key IN ({marks})",
                                      (feed, *chunk)) as cur:
                    for key, value in await cur.fetchall():
                        found[key] = json.loads(value)
        return found
