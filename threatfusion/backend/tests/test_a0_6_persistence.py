"""A0-6 — persist scans and fix schema drift (AUDIT_REPORT.md §7, §C).

Audit findings:
* the ``scans`` table was created at startup but **never written** — history lived in a Python dict and
  vanished on restart (``scans`` had 0 rows on the developer's machine);
* the computed ``summary`` was dropped by the schema (fixed with A0-1) — it must survive storage too;
* the database path was relative to the working directory, so different launch directories meant
  different databases;
* records did not say which models / feature schema produced them, whether data was mock, or which
  provider answered.

Contract now: every scan (and every failed scan) is stored; history is read from the database; the
schema is versioned with in-place migrations; the path is absolute and shared by all components.
"""

from __future__ import annotations

import importlib
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings

BACKEND = Path(__file__).resolve().parents[1]


# ── Database path ───────────────────────────────────────────────────────────
def test_relative_database_url_resolves_against_the_backend_dir_not_the_cwd(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    p = Settings(_env_file=None, DATABASE_URL="sqlite:///./threatfusion.db").database_path
    assert p.is_absolute() and p == (BACKEND / "threatfusion.db").resolve()


def test_absolute_database_url_is_respected(tmp_path) -> None:
    target = tmp_path / "x.db"
    p = Settings(_env_file=None, DATABASE_URL=f"sqlite:///{target.as_posix()}").database_path
    assert p == target.resolve()


def test_every_component_uses_the_same_resolved_path(tmp_path, monkeypatch) -> None:
    from app.core import audit
    from app.network.service import NetworkMonitorService

    db = tmp_path / "shared.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db.as_posix()}")
    get_settings.cache_clear()
    try:
        assert audit._db_path() == str(db.resolve())
        assert NetworkMonitorService()._db_path == str(db.resolve())
    finally:
        get_settings.cache_clear()


# ── Versioned migrations ────────────────────────────────────────────────────
OLD_SCANS_DDL = """
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY, target TEXT NOT NULL, target_type TEXT NOT NULL, timestamp TEXT NOT NULL,
    result_json TEXT NOT NULL, baseline_score REAL, ml_score REAL, ml_label TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


@pytest.mark.asyncio
async def test_migration_upgrades_an_old_database_in_place_and_is_idempotent(tmp_path) -> None:
    from app.core.db import LATEST_VERSION, init_db

    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript(OLD_SCANS_DDL)
    con.execute("INSERT INTO scans (scan_id,target,target_type,timestamp,result_json) VALUES ('old1','a.example','domain','2026-07-01T00:00:00+00:00','{}')")
    con.commit(); con.close()

    await init_db(db)
    await init_db(db)           # running again must change nothing

    con = sqlite3.connect(db)
    cols = {r[1] for r in con.execute("PRAGMA table_info(scans)")}
    assert {"mock", "verdict_status", "model_versions", "feature_schema_version", "provenance",
            "baseline_label", "status", "error", "app_version"} <= cols
    assert con.execute("PRAGMA user_version").fetchone()[0] == LATEST_VERSION
    assert con.execute("SELECT scan_id, status FROM scans").fetchall() == [("old1", "ok")], "old rows survive"
    con.close()


@pytest.mark.asyncio
async def test_init_db_creates_a_fresh_database(tmp_path) -> None:
    from app.core.db import LATEST_VERSION, init_db

    db = tmp_path / "fresh.db"
    await init_db(db)
    con = sqlite3.connect(db)
    assert con.execute("PRAGMA user_version").fetchone()[0] == LATEST_VERSION
    assert con.execute("SELECT name FROM sqlite_master WHERE name='scans'").fetchone()
    con.close()


# ── Scans are stored, and survive a restart ─────────────────────────────────
@pytest.fixture
def app_with_db(tmp_path, monkeypatch, fake_dns):
    import socket
    import app.core.validation as validation

    db = tmp_path / "scans.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db.as_posix()}")
    monkeypatch.setenv("USE_MOCK_DATA", "true")
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)

    def restart():
        """Simulate a process restart: all module-level state is rebuilt."""
        import app.api.scan as scan_module
        importlib.reload(scan_module)
        from app.main import app
        # routers hold references to the *old* module's functions, so rebuild the route table
        for r in list(app.router.routes):
            if getattr(r, "path", "").startswith("/scan"):
                app.router.routes.remove(r)
        app.include_router(scan_module.router)
        return TestClient(app)

    class Ctx:
        pass
    c = Ctx()
    c.db, c.restart = db, restart
    from app.main import app
    c.client = TestClient(app)
    yield c
    get_settings.cache_clear()
    import app.api.scan as scan_module
    importlib.reload(scan_module)


def _scan(client, target="evil-malicious.com", ttype="domain") -> dict:
    return client.post("/scan", json={"target": target, "target_type": ttype}).json()["result"]


def test_a_scan_is_written_to_the_scans_table_with_provenance(app_with_db) -> None:
    res = _scan(app_with_db.client)
    con = sqlite3.connect(app_with_db.db)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM scans WHERE scan_id=?", (res["scan_id"],)).fetchone()
    con.close()
    assert row is not None, "the scans table must be written"
    assert row["target"] == "evil-malicious.com" and row["target_type"] == "domain"
    assert row["mock"] == 1 and row["status"] == "ok" and row["error"] is None
    assert row["verdict_status"] == res["verdict_status"]
    assert row["baseline_label"] == res["baseline_label"] and row["ml_label"] == res["ml_label"]
    assert row["feature_schema_version"] == res["feature_schema_version"] >= 2
    versions = json.loads(row["model_versions"])
    assert set(versions) >= {"xgboost_fusion", "neural_url"} and all(versions.values())
    prov = json.loads(row["provenance"])
    assert {p["source"] for p in prov} >= {"virustotal", "shodan_internetdb"} and all("status" in p for p in prov)
    assert json.loads(row["result_json"])["scan_id"] == res["scan_id"]


def test_history_and_scan_survive_a_restart_including_the_summary(app_with_db) -> None:
    first = _scan(app_with_db.client)
    assert first["summary"], "the summary is computed and must be stored"
    client2 = app_with_db.restart()                      # new "process": no in-memory state
    items = client2.get("/scan/history").json()
    assert [i["scan_id"] for i in items] == [first["scan_id"]]
    assert items[0]["baseline_label"] == first["baseline_label"]
    again = client2.get(f"/scan/{first['scan_id']}").json()["result"]
    assert again["summary"] == first["summary"]
    assert again["provider_results"] == first["provider_results"]
    assert again["model_versions"] == first["model_versions"] and again["mock_mode"] is True


def test_history_is_newest_first_and_limitable(app_with_db) -> None:
    ids = [_scan(app_with_db.client, f"site{i}.example")["scan_id"] for i in range(4)]
    items = app_with_db.client.get("/scan/history").json()
    assert [i["scan_id"] for i in items] == ids[::-1]
    assert len(app_with_db.client.get("/scan/history?limit=2").json()) == 2


def test_unknown_scan_id_is_404(app_with_db) -> None:
    assert app_with_db.client.get("/scan/does-not-exist").status_code == 404


def test_a_failed_scan_is_recorded_with_its_error_but_not_listed_in_history(app_with_db, monkeypatch) -> None:
    import app.api.scan as scan_module

    def boom(*a, **k):
        raise RuntimeError("feature extraction exploded")

    monkeypatch.setattr(scan_module, "extract_features_with_coverage", boom)
    body = app_with_db.client.post("/scan", json={"target": "broken.example", "target_type": "domain"}).json()
    assert body["success"] is False and "exploded" in body["error"]
    con = sqlite3.connect(app_with_db.db)
    rows = con.execute("SELECT target, status, error FROM scans").fetchall()
    con.close()
    assert rows == [("broken.example", "error", "feature extraction exploded")]
    assert app_with_db.client.get("/scan/history").json() == []
