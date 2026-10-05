"""
Feedback loop (B20): users say "this verdict was wrong" — and a human reviews it before it can mean anything
=============================================================================================================

``POST /feedback``            — report a false positive / false negative (or confirm a verdict) for a host or URL;
``GET  /feedback``            — list reports (``?status=pending``);
``POST /feedback/{id}/review``— a person accepts or rejects a report.

Design rules (and why)
----------------------
* **Feedback is never training data on arrival.**  Every report starts ``pending``; only a human ``accepted`` review marks it as
  usable, and ``ml/feedback_export.py`` exports *accepted* rows only.  Anyone who can reach the API could submit a poisoned
  label, so unreviewed feedback must not move a model.
* **Provenance is stored** — what ThreatFusion said at the time (``verdict_snapshot``: fast level, scores, model versions),
  the source (extension / ui / api) and the time — so a later disagreement can be audited.
* **Privacy:** only the canonical *host* is stored unless the reporter ticked "send full URL"; the free-text note is capped,
  stripped of control characters, and never echoed into an event stream.
* **Flood and poisoning guards:** the shared rate limiter applies; an identical report (same target + label) within an hour is
  answered with the existing id instead of a new row.
* Private / local names are refused (nothing about them leaves the machine anyway, and they carry no label value).
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional
from uuid import uuid4

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core import privacy
from app.core.auth import require_token
from app.core.config import get_settings
from app.core.db import ensure_db
from app.core.ratelimit import scan_rate_limit
from app.core.targets import canonicalize
from app.models.schemas import TargetType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/feedback", tags=["feedback"], dependencies=[Depends(require_token)])

Label = Literal["false_positive", "false_negative", "confirm_malicious", "confirm_benign"]
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
DEDUP_WINDOW = timedelta(hours=1)


class FeedbackRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    target_type: Optional[TargetType] = None
    label: Label
    note: Optional[str] = Field(None, max_length=2000)
    scan_id: Optional[str] = Field(None, max_length=64)
    source: Literal["extension", "ui", "api"] = "api"
    send_full_url: bool = False
    verdict_snapshot: Optional[dict] = Field(None, description="What ThreatFusion said when the user reported (fast level, scores)")
    model_versions: Optional[dict] = None


class FeedbackItem(BaseModel):
    id: str
    created_at: str
    target: str
    target_type: str
    label: str
    note: Optional[str] = None
    source: str
    scan_id: Optional[str] = None
    status: str
    verdict_snapshot: Optional[dict] = None
    model_versions: Optional[dict] = None
    reviewed_at: Optional[str] = None
    reviewer: Optional[str] = None
    review_note: Optional[str] = None


class FeedbackReceipt(BaseModel):
    id: str
    status: str
    duplicate: bool = False
    message: str


class ReviewRequest(BaseModel):
    decision: Literal["accepted", "rejected"]
    reviewer: str = Field("local", max_length=64)
    note: Optional[str] = Field(None, max_length=500)


def _clean(text: Optional[str], limit: int) -> Optional[str]:
    if text is None:
        return None
    return _CONTROL.sub("", text).strip()[:limit] or None


def _path():
    return get_settings().database_path


def _item(row) -> FeedbackItem:
    return FeedbackItem(
        id=row[0], created_at=row[1], target=row[2], target_type=row[3], label=row[4], note=row[5], source=row[6], scan_id=row[7],
        status=row[8], verdict_snapshot=json.loads(row[9]) if row[9] else None, model_versions=json.loads(row[10]) if row[10] else None,
        reviewed_at=row[11], reviewer=row[12], review_note=row[13])


_COLUMNS = ("id, created_at, target, target_type, label, note, source, scan_id, status, verdict_snapshot, model_versions, "
            "reviewed_at, reviewer, review_note")


@router.post("", response_model=FeedbackReceipt, summary="Report a wrong verdict (reviewed before it is used for anything)",
             dependencies=[Depends(scan_rate_limit)])
async def submit_feedback(body: FeedbackRequest) -> FeedbackReceipt:
    target = canonicalize(body.target, body.target_type)
    if not target.valid:
        raise HTTPException(status_code=400, detail="That is not a valid URL, domain, IP address or hash.")
    subject = target.host or target.ip or target.hash or ""
    if target.kind in (TargetType.DOMAIN, TargetType.URL, TargetType.IP) and privacy.provider_block_reason(subject):
        raise HTTPException(status_code=400, detail="Private or local names cannot be reported.")
    stored = (target.url_full if (body.send_full_url and target.kind == TargetType.URL) else subject) or subject
    now = datetime.now(timezone.utc)
    await ensure_db(_path())
    async with aiosqlite.connect(_path()) as db:
        async with db.execute("SELECT id, created_at, status FROM feedback WHERE target = ? AND label = ? ORDER BY created_at DESC LIMIT 1",
                              (stored, body.label)) as cur:
            row = await cur.fetchone()
        if row and datetime.fromisoformat(row[1]) > now - DEDUP_WINDOW:
            return FeedbackReceipt(id=row[0], status=row[2], duplicate=True, message="Already reported recently; thank you.")
        fid = str(uuid4())
        await db.execute(
            "INSERT INTO feedback (id, created_at, target, target_type, label, note, source, scan_id, verdict_snapshot, model_versions, status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?, 'pending')",
            (fid, now.isoformat(), stored, target.kind.value, body.label, _clean(body.note, 500), body.source, _clean(body.scan_id, 64),
             json.dumps(body.verdict_snapshot, default=str)[:4000] if body.verdict_snapshot else None,
             json.dumps(body.model_versions, default=str)[:1000] if body.model_versions else None))
        await db.commit()
    return FeedbackReceipt(id=fid, status="pending", message="Recorded. It is reviewed by a person before it can be used for anything.")


@router.get("", response_model=list[FeedbackItem], summary="List feedback reports")
async def list_feedback(status: Optional[Literal["pending", "accepted", "rejected"]] = Query(None),
                        limit: int = Query(100, ge=1, le=1000)) -> list[FeedbackItem]:
    await ensure_db(_path())
    sql = f"SELECT {_COLUMNS} FROM feedback" + (" WHERE status = ?" if status else "") + " ORDER BY created_at DESC LIMIT ?"
    args = ([status] if status else []) + [limit]
    async with aiosqlite.connect(_path()) as db:
        async with db.execute(sql, args) as cur:
            return [_item(r) for r in await cur.fetchall()]


@router.post("/{feedback_id}/review", response_model=FeedbackItem, summary="Accept or reject a report (human review)")
async def review_feedback(feedback_id: str, body: ReviewRequest) -> FeedbackItem:
    await ensure_db(_path())
    async with aiosqlite.connect(_path()) as db:
        cur = await db.execute(
            "UPDATE feedback SET status = ?, reviewed_at = ?, reviewer = ?, review_note = ? WHERE id = ? AND status = 'pending'",
            (body.decision, datetime.now(timezone.utc).isoformat(), _clean(body.reviewer, 64), _clean(body.note, 500), feedback_id))
        await db.commit()
        async with db.execute(f"SELECT {_COLUMNS} FROM feedback WHERE id = ?", (feedback_id,)) as cur2:
            row = await cur2.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="No such report.")
        if cur.rowcount == 0:
            raise HTTPException(status_code=409, detail="That report was already reviewed.")
    return _item(row)
