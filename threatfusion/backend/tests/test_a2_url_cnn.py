"""A2-3 — the text-only URL CNN: encoding, canonical-input invariance, saliency spans and integrity-checked loading.

Structure tests use a tiny *untrained* network (they test plumbing, not quality); quality is measured by ``ml/evaluate.py`` and
asserted on the shipped model in ``test_a2_model_health.py``.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import numpy as np
import pytest
import torch

from app.core.artifacts import ArtifactIntegrityError, ArtifactManifest, default_models_dir, sha256_file
from app.ml.url_cnn import ALPHABET, PAD, UNK, UrlCnn, UrlCnnConfig, UrlCnnModel, encode


def tiny(tmp_path: Path, *, calibration: bool = False) -> Path:
    """A small random network + config (+ calibrator), registered in a manifest next to them."""
    torch.manual_seed(0)
    cfg = UrlCnnConfig(max_len=64, emb_dim=8, num_filters=6, kernel_sizes=[3, 5], hidden=8)
    net = UrlCnn(cfg)
    weights = tmp_path / "url_cnn.pt"
    torch.save(net.state_dict(), weights)
    cfg.to_json(tmp_path / "url_cnn_config.json")
    files = {"url_cnn.pt": sha256_file(weights), "url_cnn_config.json": sha256_file(tmp_path / "url_cnn_config.json")}
    if calibration:
        cal = tmp_path / "url_cnn_calibration.json"
        cal.write_text(json.dumps({"calibrator": {"kind": "platt", "a": 2.0, "b": -0.5}}))
        files[cal.name] = sha256_file(cal)
    (tmp_path / "manifest.json").write_text(ArtifactManifest(files=files).to_json())
    return weights


def test_encoding_pads_truncates_and_maps_unknown_characters() -> None:
    cfg = UrlCnnConfig(max_len=10)
    ids = encode("ab", cfg)
    assert len(ids) == 10 and ids[2:] == [PAD] * 8 and ids[0] != UNK
    assert len(encode("x" * 50, cfg)) == 10
    assert encode("é", cfg)[0] == UNK, "characters outside printable ASCII collapse to UNK (homoglyphs are themselves a signal)"
    assert encode("A", cfg)[0] != encode("a", cfg)[0], "path case is kept: the vocabulary is case-sensitive"
    assert len(ALPHABET) == 94 and cfg.vocab_size == 96


def test_forward_shape_and_saliency(tmp_path) -> None:
    cfg = UrlCnnConfig(max_len=32, emb_dim=8, num_filters=4, kernel_sizes=[3], hidden=8)
    net = UrlCnn(cfg).eval()
    ids = torch.tensor([encode("example.com/login", cfg)])
    assert net(ids).shape == (1, 1)
    sal = net.saliency(ids)
    assert sal.shape == (32,) and (sal >= 0).all()


def test_scores_are_invariant_to_scheme_www_and_host_case_for_any_weights(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MODEL_DIR", str(tmp_path))
    from app.core.config import get_settings
    get_settings.cache_clear()
    try:
        model = UrlCnnModel()
        model.load(tiny(tmp_path))
        base = model.predict_proba("example.com/Login?x=1")
        for variant in ["https://example.com/Login?x=1", "http://www.example.com/Login?x=1", "HTTPS://WWW.EXAMPLE.COM/Login?x=1"]:
            assert model.predict_proba(variant) == pytest.approx(base, abs=1e-9), variant
        assert model.predict_proba("example.com/login?x=1") != base, "path case is information and is kept"
    finally:
        get_settings.cache_clear()


def test_uncalibrated_calibrated_and_explanations(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MODEL_DIR", str(tmp_path))
    from app.core.config import get_settings
    get_settings.cache_clear()
    try:
        plain = UrlCnnModel()
        plain.load(tiny(tmp_path))
        assert not plain.calibrated and plain.predict_calibrated("a.example.com") == plain.predict_proba("a.example.com")
        cal = UrlCnnModel()
        cal.load(tiny(tmp_path, calibration=True))
        assert cal.calibrated and 0.0 < cal.predict_calibrated("a.example.com") < 1.0
        spans = cal.explain_url("https://paypa1-secure-login.example.com/verify", top_k=3)
        text = "paypa1-secure-login.example.com/verify"
        assert len(spans) <= 3 and all(0 <= s.start < s.end <= len(text) and s.substring == text[s.start:s.end] for s in spans)
        assert cal.explain_url("") == []
    finally:
        get_settings.cache_clear()


def test_loading_without_the_weights_or_the_manifest_is_refused(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MODEL_DIR", str(tmp_path))
    from app.core.config import get_settings
    get_settings.cache_clear()
    try:
        with pytest.raises(FileNotFoundError):
            UrlCnnModel().load(tmp_path / "nope.pt")
        weights = tiny(tmp_path)
        weights.write_bytes(weights.read_bytes() + b"\x00")          # one extra byte: the SHA-256 no longer matches
        with pytest.raises(ArtifactIntegrityError):
            UrlCnnModel().load(weights)
        with pytest.raises(RuntimeError):
            UrlCnnModel().predict_proba("example.com")
    finally:
        get_settings.cache_clear()


def test_weights_load_with_weights_only(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MODEL_DIR", str(tmp_path))
    from app.core.config import get_settings
    get_settings.cache_clear()
    calls = []
    real = torch.load

    def spy(*a, **k):
        calls.append(k)
        return real(*a, **k)

    monkeypatch.setattr(torch, "load", spy)
    try:
        UrlCnnModel().load(tiny(tmp_path))
    finally:
        get_settings.cache_clear()
    assert calls and all(c.get("weights_only") is True for c in calls)


def test_the_shipped_cnn_config_declares_its_canonicalisation() -> None:
    cfg = UrlCnnConfig.from_json(default_models_dir() / "url_cnn_config.json")
    assert "canonical_url_text" in cfg.canonicalisation and cfg.alphabet == ALPHABET
