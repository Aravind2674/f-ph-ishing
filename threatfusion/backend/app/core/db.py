"""
SQLite bootstrap with versioned, in-place migrations (A0-6)
============================================================

``PRAGMA user_version`` records the schema version, so an existing database (for example the
developer's, which already holds network alerts and an empty ``scans`` table) is upgraded **in place
and idempotently** — rows are never dropped.  Running :func:`init_db` twice changes nothing.

Version history
---------------
* v1 – baseline ``scans`` table (the shape the original ``main.py`` created; it was never written to).
* v2 – scan provenance: ``mock``, ``verdict_status``, ``baseline_label``, ``model_versions``,
  ``feature_schema_version``, ``provenance`` (per-provider outcomes), ``status``/``error`` (failed
  scans are recorded too), ``app_version``.
* v3 – ``provider_cache``: persistent TTL cache of third-party answers (A1-1; see ``core/cache.py``).
* v4 – ``feed_meta`` / ``feed_entries``: bulk feeds kept locally with their fetch time (KEV, later OpenPhish/PhishTank/
  Tranco; B11/B2 — see ``core/feeds.py``).
* v5 – ``feedback``: user reports of false positives / negatives with provenance, reviewed before they can reach any
  training data (B20 — see ``api/feedback.py``).

The network layer's tables (``net_*``) and ``verify_audit`` create themselves; they share this file but
not this version counter.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Awaitable, Callable

import aiosqlite

logger = logging.getLogger(__name__)

_V1_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    result_json TEXT NOT NULL,
    baseline_score REAL,
    ml_score REAL,
    ml_label TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
"""

# (column, DDL fragment) added by v2. NOT NULL columns carry defaults so old rows stay valid.
_V2_COLUMNS: list[tuple[str, str]] = [
    ("mock", "INTEGER NOT NULL DEFAULT 0"),
    ("verdict_status", "TEXT"),
    ("baseline_label", "TEXT"),
    ("model_versions", "TEXT"),          # JSON: {"xgboost_fusion": "<sha12>", ...}
    ("feature_schema_version", "INTEGER"),
    ("provenance", "TEXT"),              # JSON list of per-provider outcomes
    ("status", "TEXT NOT NULL DEFAULT 'ok'"),   # 'ok' | 'error'
    ("error", "TEXT"),
    ("app_version", "TEXT"),
]


async def _migrate_v1(db: aiosqlite.Connection) -> None:
    await db.executescript(_V1_SCANS)


async def _migrate_v2(db: aiosqlite.Connection) -> None:
    async with db.execute("PRAGMA table_info(scans)") as cur:
        existing = {row[1] for row in await cur.fetchall()}
    for name, ddl in _V2_COLUMNS:
        if name not in existing:  # idempotent: safe if a previous run died half-way
            await db.execute(f"ALTER TABLE scans ADD COLUMN {name} {ddl}")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_scans_status_ts ON scans(status, timestamp)")


_V3_PROVIDER_CACHE = """
CREATE TABLE IF NOT EXISTS provider_cache (
    source TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    status TEXT NOT NULL,            -- 'ok' | 'not_found' (failures are never cached)
    payload TEXT NOT NULL,           -- the ProviderResult as JSON (keeps its original fetched_at)
    fetched_at TEXT NOT NULL,
    expires_at REAL NOT NULL,        -- epoch seconds
    PRIMARY KEY (source, cache_key)
);
CREATE INDEX IF NOT EXISTS idx_provider_cache_expires ON provider_cache(expires_at);
"""


async def _migrate_v3(db: aiosqlite.Connection) -> None:
    await db.executescript(_V3_PROVIDER_CACHE)


_V4_FEEDS = """
CREATE TABLE IF NOT EXISTS feed_meta (
    feed TEXT PRIMARY KEY,
    fetched_at REAL NOT NULL,        -- epoch seconds of the last successful download
    source_url TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    version TEXT
);
CREATE TABLE IF NOT EXISTS feed_entries (
    feed TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,             -- JSON
    PRIMARY KEY (feed, key)
);
"""


async def _migrate_v4(db: aiosqlite.Connection) -> None:
    await db.executescript(_V4_FEEDS)


_V5_FEEDBACK = """
CREATE TABLE IF NOT EXISTS feedback (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    target TEXT NOT NULL,              -- host name, or the full URL only if the reporter opted in
    target_type TEXT NOT NULL,
    label TEXT NOT NULL,               -- false_positive | false_negative | confirm_malicious | confirm_benign
    note TEXT,
    source TEXT NOT NULL,              -- extension | ui | api
    scan_id TEXT,
    verdict_snapshot TEXT,             -- JSON: what ThreatFusion said when the report was made
    model_versions TEXT,               -- JSON
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | accepted | rejected: reviewed before entering any training data
    reviewed_at TEXT,
    reviewer TEXT,
    review_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
CREATE INDEX IF NOT EXISTS idx_feedback_target ON feedback(target);
"""


async def _migrate_v5(db: aiosqlite.Connection) -> None:
    await db.executescript(_V5_FEEDBACK)


MIGRATIONS: list[tuple[int, Callable[[aiosqlite.Connection], Awaitable[None]]]] = [
    (1, _migrate_v1),
    (2, _migrate_v2),
    (3, _migrate_v3),
    (4, _migrate_v4),
    (5, _migrate_v5),
]
LATEST_VERSION = MIGRATIONS[-1][0]

_initialised: set[str] = set()


async def init_db(path: Path | str) -> None:
    """Create the database if needed and apply any pending migrations."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(path) as db:
        async with db.execute("PRAGMA user_version") as cur:
            version = (await cur.fetchone())[0]
        for target, migrate in MIGRATIONS:
            if version < target:
                logger.info("Migrating %s: schema v%d -> v%d", path.name, version, target)
                await migrate(db)
                await db.execute(f"PRAGMA user_version = {target}")
                await db.commit()
                version = target
    _initialised.add(str(path))


async def ensure_db(path: Path | str) -> None:
    """``init_db`` once per process per path (used lazily by stores)."""
    if str(path) not in _initialised:
        await init_db(path)
