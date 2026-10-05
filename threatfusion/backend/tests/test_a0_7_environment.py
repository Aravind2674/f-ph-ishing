"""A0-7 — reproducible, safe environment (AUDIT_REPORT.md §F.3, §H7).

What the audit found and what these tests pin down:

* ``core/validation.py`` imported ``aiohttp`` although it was not declared anywhere
  (a clean install could not run ``/scan``).  Rather than patch the requirements we
  removed the import; this test fails if any app module imports an undeclared package.
* ``requirements.txt`` used open ``>=`` ranges, so numba/NumPy drifted apart and two
  of three interpreters could not ``import app.main``.  The lock must be exact pins.
* ``torch.load`` defaulted to the unsafe pickle path on torch < 2.6.  Model files are
  now loaded with ``weights_only=True`` *and* checked against a SHA-256 manifest, so a
  swapped or tampered artifact is refused instead of silently scored.
"""

from __future__ import annotations

import ast
import re
import shutil
import sys
from importlib import metadata
from pathlib import Path

import pytest
import respx
import httpx

BACKEND = Path(__file__).resolve().parents[1]
APP_DIR = BACKEND / "app"
MODELS = BACKEND.parent / "ml" / "models"


# ── Dependency hygiene ──────────────────────────────────────────────────────
def _third_party_imports() -> set[str]:
    """Top-level module names imported anywhere under ``app/`` that are not stdlib/local."""
    found: set[str] = set()
    for py in APP_DIR.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
    return {m for m in found if m not in sys.stdlib_module_names and m not in {"app", "__future__"}}


def _locked_distributions() -> set[str]:
    names: set[str] = set()
    for line in (BACKEND / "requirements.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==", line)
        if m:
            names.add(re.sub(r"[-_.]+", "-", m.group(1)).lower())
    return names


def test_requirements_lock_is_fully_pinned() -> None:
    offenders = []
    for line in (BACKEND / "requirements.txt").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("--"):
            continue
        if not re.match(r"^[A-Za-z0-9_.\-]+(\[[^\]]+\])?==[^\s;]+", stripped):
            offenders.append(stripped)
    assert not offenders, f"unpinned entries in requirements.txt: {offenders}"


def test_every_third_party_import_in_app_is_locked() -> None:
    """Catches the audit's ``aiohttp`` situation: imported, never declared."""
    dist_of = metadata.packages_distributions()
    locked = _locked_distributions()
    missing = []
    for mod in sorted(_third_party_imports()):
        dists = {re.sub(r"[-_.]+", "-", d).lower() for d in dist_of.get(mod, [])}
        if not dists & locked:
            missing.append(mod)
    assert not missing, f"imported by app/ but absent from requirements.txt: {missing}"


def test_app_does_not_import_aiohttp_directly() -> None:
    # aiohttp may still arrive transitively (python-Wappalyzer), but the app must not
    # depend on it: one HTTP client (httpx) keeps timeouts/redirect policy in one place.
    assert "aiohttp" not in _third_party_imports()


@pytest.mark.asyncio
async def test_reachability_check_uses_httpx(fake_dns) -> None:
    from app.core.validation import _check_reachability
    from tests.conftest import mock_site

    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "reachable.test", status=200, scheme="https")
        assert await _check_reachability("reachable.test") is True

    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "down.test", status=500, scheme="https")
        mock_site(router, "down.test", status=503, scheme="http")
        assert await _check_reachability("down.test") is False

    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "flaky.test", side_effect=httpx.ConnectError("boom"), scheme="https")
        mock_site(router, "flaky.test", status=301, scheme="http")
        assert await _check_reachability("flaky.test") is True  # falls back to http


@pytest.mark.asyncio
async def test_reachability_check_refuses_a_host_that_rebinds_to_an_internal_address(fake_dns) -> None:
    """Validation checked the public DNS answer; the fetch must not be steerable to localhost."""
    from app.core.validation import _check_reachability

    fake_dns.set("rebind.test", "127.0.0.1")
    with respx.mock(assert_all_called=False) as router:
        assert await _check_reachability("rebind.test") is False
        assert len(router.calls) == 0   # no packet was sent to the internal address


# ── Model artifact integrity ────────────────────────────────────────────────
def test_manifest_covers_every_runtime_artifact() -> None:
    from app.core.artifacts import ArtifactManifest

    manifest = ArtifactManifest.load(MODELS / "manifest.json")
    for name in ("fusion_model.json", "neural_fusion.pt", "neural_fusion_config.json",
                 "vuln_classifier.pt", "vuln_classifier_config.json"):
        assert name in manifest.files, f"{name} missing from manifest"


def test_verify_artifact_accepts_pristine_files() -> None:
    from app.core.artifacts import verify_artifact

    for name in ("fusion_model.json", "neural_fusion.pt", "vuln_classifier.pt"):
        verify_artifact(MODELS / name)  # must not raise


def _copy_with_manifest(tmp_path: Path, name: str) -> Path:
    shutil.copy(MODELS / "manifest.json", tmp_path / "manifest.json")
    shutil.copy(MODELS / name, tmp_path / name)
    return tmp_path / name


def test_tampered_artifact_is_refused(tmp_path: Path) -> None:
    from app.core.artifacts import ArtifactIntegrityError, verify_artifact

    victim = _copy_with_manifest(tmp_path, "fusion_model.json")
    data = bytearray(victim.read_bytes())
    data[len(data) // 2] ^= 0x01  # flip one bit
    victim.write_bytes(bytes(data))
    with pytest.raises(ArtifactIntegrityError, match="sha256"):
        verify_artifact(victim)


def test_unlisted_artifact_is_refused_in_strict_mode(tmp_path: Path) -> None:
    from app.core.artifacts import ArtifactIntegrityError, verify_artifact

    shutil.copy(MODELS / "manifest.json", tmp_path / "manifest.json")
    stray = tmp_path / "evil_model.json"
    stray.write_text("{}")
    with pytest.raises(ArtifactIntegrityError, match="not listed"):
        verify_artifact(stray)


def test_missing_manifest_is_refused(tmp_path: Path) -> None:
    from app.core.artifacts import ArtifactIntegrityError, verify_artifact

    f = tmp_path / "m.json"
    f.write_text("{}")
    with pytest.raises(ArtifactIntegrityError, match="manifest"):
        verify_artifact(f)


@pytest.mark.parametrize("cls_path,artifact", [
    ("app.ml.fusion_model.FusionModel", "fusion_model.json"),
    ("app.ml.neural_fusion.NeuralFusionModel", "neural_fusion.pt"),
    ("app.ml.vuln_classifier.VulnClassifier", "vuln_classifier.pt"),
])
def test_model_loaders_refuse_tampered_files(tmp_path: Path, cls_path: str, artifact: str) -> None:
    """The integrity check is wired into every loader, not just available."""
    import importlib
    from app.core.artifacts import ArtifactIntegrityError

    mod_name, cls_name = cls_path.rsplit(".", 1)
    cls = getattr(importlib.import_module(mod_name), cls_name)

    # Companion config files must travel with the weights (loaders read them by name).
    for companion in MODELS.glob(f"{Path(artifact).stem}_config.json"):
        shutil.copy(companion, tmp_path / companion.name)
    victim = _copy_with_manifest(tmp_path, artifact)
    victim.write_bytes(victim.read_bytes() + b"\x00")  # append a byte => hash mismatch
    with pytest.raises(ArtifactIntegrityError):
        cls().load(victim)


def test_torch_load_uses_weights_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never allow arbitrary pickle execution when reading ``.pt`` checkpoints."""
    import torch
    from app.ml.neural_fusion import NeuralFusionModel
    from app.ml.vuln_classifier import VulnClassifier

    calls: list[dict] = []
    real_load = torch.load

    def spy(*args, **kwargs):
        calls.append(kwargs)
        return real_load(*args, **kwargs)

    monkeypatch.setattr(torch, "load", spy)
    NeuralFusionModel().load(MODELS / "neural_fusion.pt")
    VulnClassifier().load(MODELS / "vuln_classifier.pt")
    assert len(calls) == 2
    assert all(c.get("weights_only") is True for c in calls), calls
