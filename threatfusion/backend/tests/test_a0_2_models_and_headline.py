"""A0-2 — stop presenting the broken XGBoost score as a result (AUDIT_REPORT.md §A, §B, §E).

Audit findings addressed here:

* Models were loaded from CWD-relative paths (``ml/models/…`` or ``../ml/models/…``).  Starting
  uvicorn from any other directory silently left the model unloaded and ``ml_score`` was then set
  *equal to the baseline* while the UI still said "ML Fusion (XGBoost)".
* The deployed XGBoost model reads only 3 VirusTotal features and outputs one value for virtually
  every target (audit §E).  It must not be the headline; the transparent baseline + the evidence is.

(The "no ML score when the model is missing / has no evidence" half was delivered with A0-1; the
regression tests for it live here so the A0-2 acceptance criteria are checked in one place.)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
MODELS = BACKEND.parent / "ml" / "models"


# ── Model location is independent of the working directory ──────────────────
def test_all_models_load_when_started_from_an_unrelated_directory(tmp_path: Path) -> None:
    """The audit's silent-fallback scenario, run for real in a subprocess with a foreign CWD."""
    code = (
        "import sys; sys.path.insert(0, r'%s');\n"
        "import app.api.scan as s, app.api.analyze as a, app.api.traffic as t\n"
        "import app.network.enrichment.app_layer as l\n"
        "print('LOADED', s._model.is_loaded, s._neural_model.is_loaded, a._clf.is_loaded,"
        " t._clf.is_loaded, l._model.is_loaded)\n" % BACKEND
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=tmp_path, capture_output=True, text=True, timeout=240,
        env={**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert out.returncode == 0, out.stderr[-800:]
    assert "LOADED True True True True True" in out.stdout, out.stdout + out.stderr[-500:]


def test_model_dir_defaults_to_the_repo_models_and_is_overridable(tmp_path: Path) -> None:
    from app.core.config import Settings

    default = Settings(_env_file=None).model_dir
    assert default.is_absolute() and default == MODELS.resolve() and default.is_dir()
    assert Settings(_env_file=None, MODEL_DIR=str(tmp_path)).model_dir == tmp_path.resolve()


# ── No score is invented when the model cannot provide one ──────────────────
@pytest.fixture
def mock_scan_client(monkeypatch: pytest.MonkeyPatch):
    import socket
    import app.core.validation as validation
    from app.core.config import get_settings
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "true")
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "93.184.216.34")
    yield TestClient(app)
    get_settings.cache_clear()


def test_missing_model_yields_null_ml_score_never_the_baseline(mock_scan_client, monkeypatch) -> None:
    import app.api.scan as scan_module
    from app.ml.fusion_model import FusionModel

    monkeypatch.setattr(scan_module, "_model", FusionModel())      # not loaded
    body = mock_scan_client.post("/scan", json={"target": "some-site.example", "target_type": "domain"}).json()
    res = body["result"]
    assert res["ml_score"] is None
    assert res["ml_status"] == "model_not_loaded"
    assert res["ml_label"] == "Unknown"
    assert res["baseline_score"] is not None, "the baseline is computed from evidence; it is NOT copied into ml_score"
    assert res["explanations"] == []


def test_scan_exposes_a_baseline_label_for_the_headline(mock_scan_client) -> None:
    res = mock_scan_client.post("/scan", json={"target": "evil-malicious.com", "target_type": "domain"}).json()["result"]
    assert res["baseline_label"] in {"Low", "Medium", "High", "Critical"}
    # the mock "malicious" target is flagged by 15/73 engines: the transparent baseline sees it,
    # while the VT-threshold XGBoost step function (audit §E) does not — that is why baseline leads.
    assert res["baseline_score"] > 0.4 and res["baseline_label"] in {"Medium", "High", "Critical"}


def test_baseline_label_is_unknown_without_any_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.scan import _baseline_label

    assert _baseline_label(None) == "Unknown"
    assert _baseline_label(0.1) == "Low" and _baseline_label(0.6) == "High" and _baseline_label(0.9) == "Critical"


def test_history_items_carry_the_baseline_label(mock_scan_client) -> None:
    mock_scan_client.post("/scan", json={"target": "google.com", "target_type": "domain"})
    items = mock_scan_client.get("/scan/history").json()
    assert items and all("baseline_label" in i for i in items)
