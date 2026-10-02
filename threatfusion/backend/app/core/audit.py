"""
Append-only audit log for active verification (A0-3)
=====================================================

``POST /verify`` sends probe requests to a target, so every call — allowed or refused — leaves a
record: *when, what target, which resolved IP, which checks ran, what the outcome was*.

The table is **append-only at the database level**: ``BEFORE UPDATE`` / ``BEFORE DELETE`` triggers
abort the statement, so neither a bug nor a casual SQL session can rewrite history (a determined
operator with file access can still drop the triggers — this is an accountability aid, not a
tamper-proof ledger).

Outcomes: ``disabled`` | ``refused_scope`` | ``rate_limited`` | ``completed`` | ``blocked`` | ``error``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from app.core.config import get_settings

logger = logging.getLogger(__name__)

VERIFY_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS verify_audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,
    target          TEXT    NOT NULL,
    host            TEXT,
    resolved_ip     TEXT,
    checks_run      TEXT    NOT NULL,
    outcome         TEXT    NOT NULL,
    confirmed_count INTEGER NOT NULL DEFAULT 0,
    detail          TEXT
);
CREATE TRIGGER IF NOT EXISTS verify_audit_no_update
BEFORE UPDATE ON verify_audit
BEGIN SELECT RAISE(ABORT, 'verify_audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS verify_audit_no_delete
BEFORE DELETE ON verify_audit
BEGIN SELECT RAISE(ABORT, 'verify_audit is append-only'); END;
"""


def _db_path() -> str:
    # NOTE: relative DATABASE_URL paths are resolved against the CWD until A0-6 makes them absolute.
    return get_settings().DATABASE_URL.replace("sqlite:///", "")


async def ensure_verify_audit_schema() -> None:
    """Create the table + triggers if needed. Raises if the database is not writable."""
    async with aiosqlite.connect(_db_path()) as db:
        await db.executescript(VERIFY_AUDIT_SCHEMA)
        await db.commit()


async def record_verify_call(
    *,
    target: str,
    host: Optional[str],
    outcome: str,
    checks_run: Optional[list[str]] = None,
    resolved_ip: Optional[str] = None,
    confirmed_count: int = 0,
    detail: Optional[str] = None,
) -> None:
    """Append one audit row. Never raises into the request path for refused calls (it logs)."""
    try:
        async with aiosqlite.connect(_db_path()) as db:
            await db.executescript(VERIFY_AUDIT_SCHEMA)
            await db.execute(
                "INSERT INTO verify_audit (ts, target, host, resolved_ip, checks_run, outcome, "
                "confirmed_count, detail) VALUES (?,?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), target, host, resolved_ip,
                 json.dumps(sorted(set(checks_run or []))), outcome, confirmed_count, detail),
            )
            await db.commit()
    except Exception:  # an audit failure must be loud, but must not mask the response itself
        logger.exception("FAILED to write verify_audit row (outcome=%s target=%s)", outcome, target)
