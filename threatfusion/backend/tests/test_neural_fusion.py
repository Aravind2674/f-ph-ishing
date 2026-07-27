"""Tests for the NeuralFusionModel inference wrapper.

These exercise the trained checkpoint produced by ``python -m ml.train_neural``.
If the checkpoint is absent (e.g. a fresh clone before training), the runtime
tests skip rather than fail — matching the API's graceful-degradation contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.schemas import FeatureVector, NeuralExplanation
from app.ml.neural_fusion import NeuralFusionModel

# From backend/tests the trained weights live at ../../ml/models/neural_fusion.pt
MODEL_PATH = Path("../ml/models/neural_fusion.pt")

pytestmark = pytest.mark.skipif(
    not MODEL_PATH.exists(),
    reason="neural_fusion.pt not found — run `python -m ml.train_neural` first",
)


@pytest.fixture
def model() -> NeuralFusionModel:
    m = NeuralFusionModel()
    m.load(MODEL_PATH)
    return m


def test_not_loaded_raises() -> None:
    m = NeuralFusionModel()
    assert not m.is_loaded
    with pytest.raises(RuntimeError):
        m.predict_url_only("http://example.com")


def test_scores_are_probabilities(model: NeuralFusionModel) -> None:
    feats = FeatureVector()
    p = model.predict_proba("http://example.com/login", feats)
    u = model.predict_url_only("http://example.com/login")
    assert 0.0 <= p <= 1.0
    assert 0.0 <= u <= 1.0


def test_phishing_scores_higher_than_benign(model: NeuralFusionModel) -> None:
    """The URL-only branch should rank an obvious phish above a clean domain."""
    phish = model.predict_url_only("http://paypa1-secure-login.tk/verify/account.php")
    benign = model.predict_url_only("https://www.google.com/search?q=weather")
    assert phish > benign
    # And the phish should clear the decision boundary on lexical signal alone.
    assert phish >= 0.5


def test_explain_url_returns_valid_spans(model: NeuralFusionModel) -> None:
    url = "http://paypa1-secure-login.tk/verify/account.php"
    spans = model.explain_url(url, top_k=3)
    assert isinstance(spans, list)
    assert all(isinstance(s, NeuralExplanation) for s in spans)
    for s in spans:
        assert 0 <= s.start < s.end <= len(url.lower())
        assert 0.0 <= s.importance <= 1.0
        assert s.substring == url.lower()[s.start : s.end]


def test_predict_label_binary(model: NeuralFusionModel) -> None:
    feats = FeatureVector()
    label = model.predict("https://www.wikipedia.org", feats)
    assert label in (0, 1)
