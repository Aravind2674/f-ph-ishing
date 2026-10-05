"""
Persistent scan storage (A0-6)
==============================

Replaces the module-level ``_db`` dict in ``api/scan.py`` (history vanished on every restart and the
``scans`` table was never written).  Every scan is stored with its full result JSON *and* the provenance
needed to interpret it later: mock flag, verdict status, model versions, feature-schema version and
per-provider outcomes.  Failed scans are recorded too (``status='error'``) so errors are not lost, but
they are not listed in history.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from app.core.config import get_settings
from app.core.db import ensure_db
from app.models.schemas import ScanHistoryItem, ScanResult

logger = logging.getLogger(__name__)


class ScanStore:
    """Async CRUD over the ``scans`` table. The path is read from settings on every call."""

    @staticmethod
    def _path():
        return get_settings().database_path

    async def save(self, result: ScanResult) -> None:
        path = self._path()
        await ensure_db(path)
        async with aiosqlite.connect(path) as db:
            await db.execute(
                "INSERT INTO scans (scan_id, target, target_type, timestamp, result_json, "
                "baseline_score, ml_score, ml_label, mock, verdict_status, baseline_label, "
                "model_versions, feature_schema_version, provenance, status, error, app_version) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    result.scan_id, result.target, result.target_type.value,
                    result.timestamp.isoformat(), result.model_dump_json(),
                    result.baseline_score, result.ml_score, result.ml_label,
                    1 if result.mock_mode else 0, result.verdict_status, result.baseline_label,
                    json.dumps(result.model_versions), result.feature_schema_version,
                    json.dumps([o.model_dump(mode="json") for o in result.provider_results]),
                    "ok", None, result.app_version,
                ),
            )
            await db.commit()

    async def save_failure(self, scan_id: str, target: str, target_type: str, error: str) -> None:
        """Record a scan that raised, so the error is not lost (not listed in history)."""
        path = self._path()
        await ensure_db(path)
        async with aiosqlite.connect(path) as db:
            await db.execute(
                "INSERT INTO scans (scan_id, target, target_type, timestamp, result_json, status, error) "
                "VALUES (?,?,?,?,?,?,?)",
                (scan_id, target, target_type, datetime.now(timezone.utc).isoformat(), "{}", "error", error),
            )
            await db.commit()

    async def get(self, scan_id: str) -> Optional[ScanResult]:
        path = self._path()
        await ensure_db(path)
        async with aiosqlite.connect(path) as db:
            async with db.execute(
                "SELECT result_json FROM scans WHERE scan_id = ? AND status = 'ok'", (scan_id,)
            ) as cur:
                row = await cur.fetchone()
        if row is None:
            return None
        try:
            return ScanResult.model_validate_json(row[0])
        except Exception:  # e.g. a migrated row without a stored result
            logger.warning("Stored scan %s has no readable result", scan_id)
            return None

    async def latest_for_target(self, host: str, since: datetime) -> Optional[dict]:
        """The newest stored OK scan whose canonical host is ``host`` and that is newer than ``since`` (the fast tier's cache)."""
        if not host:
            return None
        path = self._path()
        await ensure_db(path)
        async with aiosqlite.connect(path) as db:
            async with db.execute(
                "SELECT scan_id, timestamp, baseline_label, ml_label, verdict_status, mock FROM scans "
                "WHERE status = 'ok' AND json_extract(result_json,'$.canonical.host') = ? AND timestamp >= ? "
                "ORDER BY timestamp DESC LIMIT 1",
                (host.lower(), since.isoformat()),
            ) as cur:
                row = await cur.fetchone()
        if row is None:
            return None
        return {"scan_id": row[0], "timestamp": row[1], "baseline_label": row[2], "ml_label": row[3],
                "verdict_status": row[4], "mock": bool(row[5])}

    async def history(self, limit: int = 100, offset: int = 0) -> list[ScanHistoryItem]:
        """Newest first. Lightweight columns only (no full result payloads)."""
        path = self._path()
        await ensure_db(path)
        async with aiosqlite.connect(path) as db:
            async with db.execute(
                "SELECT scan_id, target, target_type, timestamp, baseline_score, baseline_label, "
                "ml_score, ml_label, json_extract(result_json,'$.neural_score'), "
                "json_extract(result_json,'$.neural_label') "
                "FROM scans WHERE status = 'ok' ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ) as cur:
                rows = await cur.fetchall()
        return [
            ScanHistoryItem(
                scan_id=r[0], target=r[1], target_type=r[2], timestamp=r[3],
                baseline_score=r[4], baseline_label=r[5], ml_score=r[6], ml_label=r[7],
                neural_score=r[8], neural_label=r[9],
            )
            for r in rows
        ]
