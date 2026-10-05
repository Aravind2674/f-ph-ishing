"""B20 — the feedback loop: store with provenance, review before use, never train on unreviewed labels.

Reports are ``pending`` until a person accepts them; a flood or a duplicate does not create rows; private names are refused; the
note is sanitised and capped; only the host is stored unless the reporter opted in to the full URL; the exporter writes accepted
rows only.
"""

from __future__ import annotations

import json
import sqlite3

import httpx
import pytest
import pytest_asyncio

AUTH = {"Authorization": "Bearer test-token-0123456789abcdef0123456789abcdef"}


@pytest_asyncio.fixture
async def client(monkeypatch):
    from app.core.config import get_settings
    from app.main import app

    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1000")
    get_settings.cache_clear()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as c:
        yield c
    get_settings.cache_clear()


def body(**over):
    return {"target": "https://www.example-shop.test/checkout?token=SECRET", "label": "false_positive", "note": "this is my bank's own site",
            "source": "extension", "verdict_snapshot": {"level": "warn", "url_risk_score": 0.91}, "model_versions": {"url_xgb": "abc123"}, **over}


@pytest.mark.asyncio
async def test_a_report_is_stored_pending_with_provenance_and_host_only(client) -> None:
    r = await client.post("/feedback", json=body())
    assert r.status_code == 200 and r.json()["status"] == "pending" and r.json()["duplicate"] is False
    items = (await client.get("/feedback", params={"status": "pending"})).json()
    item = next(i for i in items if i["id"] == r.json()["id"])
    assert item["target"] == "www.example-shop.test", "the query string (and its token) is not stored by default"
    assert "SECRET" not in json.dumps(item)
    assert item["source"] == "extension" and item["verdict_snapshot"]["level"] == "warn" and item["model_versions"] == {"url_xgb": "abc123"}
    assert item["reviewed_at"] is None and item["created_at"]


@pytest.mark.asyncio
async def test_the_full_url_is_stored_only_when_the_reporter_opts_in(client) -> None:
    r = await client.post("/feedback", json=body(target="https://opt-in.example.test/a/b?x=1", send_full_url=True, label="false_negative"))
    item = next(i for i in (await client.get("/feedback")).json() if i["id"] == r.json()["id"])
    assert item["target"].startswith("https://opt-in.example.test/a/b")


@pytest.mark.asyncio
async def test_an_identical_report_within_an_hour_is_a_duplicate_not_a_new_row(client) -> None:
    first = (await client.post("/feedback", json=body(target="dup.example.test"))).json()
    second = (await client.post("/feedback", json=body(target="dup.example.test"))).json()
    other = (await client.post("/feedback", json=body(target="dup.example.test", label="false_negative"))).json()
    assert second["duplicate"] is True and second["id"] == first["id"] and other["id"] != first["id"]


@pytest.mark.asyncio
async def test_bad_targets_private_names_and_oversized_notes_are_refused(client) -> None:
    assert (await client.post("/feedback", json=body(target="not a target!!"))).status_code == 400
    assert (await client.post("/feedback", json=body(target="http://printer.local/admin"))).status_code == 400
    assert (await client.post("/feedback", json=body(note="x" * 2001))).status_code == 422
    assert (await client.post("/feedback", json=body(label="made_up"))).status_code == 422


@pytest.mark.asyncio
async def test_the_note_is_sanitised_and_capped(client) -> None:
    r = await client.post("/feedback", json=body(target="note.example.test", note="line\x00one\x07 " + "y" * 900))
    item = next(i for i in (await client.get("/feedback")).json() if i["id"] == r.json()["id"])
    assert "\x00" not in item["note"] and "\x07" not in item["note"] and len(item["note"]) == 500


@pytest.mark.asyncio
async def test_a_person_reviews_a_report_exactly_once(client) -> None:
    rid = (await client.post("/feedback", json=body(target="review.example.test"))).json()["id"]
    ok = await client.post(f"/feedback/{rid}/review", json={"decision": "accepted", "reviewer": "alice", "note": "verified by hand"})
    assert ok.status_code == 200 and ok.json()["status"] == "accepted" and ok.json()["reviewer"] == "alice" and ok.json()["reviewed_at"]
    again = await client.post(f"/feedback/{rid}/review", json={"decision": "rejected"})
    assert again.status_code == 409
    assert (await client.post("/feedback/does-not-exist/review", json={"decision": "accepted"})).status_code == 404
    assert rid not in [i["id"] for i in (await client.get("/feedback", params={"status": "pending"})).json()]
    assert rid in [i["id"] for i in (await client.get("/feedback", params={"status": "accepted"})).json()]


@pytest.mark.asyncio
async def test_feedback_needs_the_api_token(client) -> None:
    assert (await client.post("/feedback", json=body(), headers={"Authorization": ""})).status_code in (401, 403)
    assert (await client.get("/feedback", headers={"Authorization": ""})).status_code in (401, 403)


@pytest.mark.asyncio
async def test_the_exporter_writes_accepted_reports_only_with_provenance(client, tmp_path) -> None:
    from app.core.config import get_settings
    from ml import feedback_export

    pending = (await client.post("/feedback", json=body(target="pending.example.test"))).json()["id"]
    rejected = (await client.post("/feedback", json=body(target="rejected.example.test", label="false_negative"))).json()["id"]
    accepted = (await client.post("/feedback", json=body(target="accepted.example.test", label="false_negative"))).json()["id"]
    await client.post(f"/feedback/{rejected}/review", json={"decision": "rejected"})
    await client.post(f"/feedback/{accepted}/review", json={"decision": "accepted", "reviewer": "bob"})
    out = tmp_path / "accepted.jsonl"
    n = feedback_export.export(get_settings().database_path, out)
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert n == len(rows) and {r["id"] for r in rows} >= {accepted} and pending not in {r["id"] for r in rows} and rejected not in {r["id"] for r in rows}
    row = next(r for r in rows if r["id"] == accepted)
    assert row["label"] == 1 and row["reported_as"] == "false_negative" and row["reviewer"] == "bob" and row["verdict_snapshot"]["level"] == "warn"


def test_the_feedback_table_exists_after_migration(tmp_path) -> None:
    import asyncio
    from app.core.db import LATEST_VERSION, init_db

    db = tmp_path / "m.db"
    asyncio.run(init_db(db))
    con = sqlite3.connect(db)
    assert LATEST_VERSION >= 5
    cols = {r[1] for r in con.execute("PRAGMA table_info(feedback)")}
    assert {"id", "target", "label", "status", "reviewer", "verdict_snapshot", "model_versions"} <= cols
    assert con.execute("PRAGMA user_version").fetchone()[0] == LATEST_VERSION
