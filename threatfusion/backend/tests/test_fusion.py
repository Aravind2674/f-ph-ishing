"""Tests for the ML Fusion Model and SHAP Explainer."""

from __future__ import annotations

from pathlib import Path
import pytest

from app.models.schemas import FeatureVector
from app.ml.fusion_model import FusionModel
from app.ml.explain import explain_prediction

# The training script saves the model here relative to the project root.
# From the backend/tests directory, it's at ../../ml/models/fusion_model.json
MODEL_PATH = Path("../ml/models/fusion_model.json")


@pytest.fixture
def model() -> FusionModel:
    """Fixture to load the trained XGBoost model."""
    m = FusionModel()
    m.load(MODEL_PATH)
    return m


@pytest.fixture
def benign_features() -> FeatureVector:
    """A clean feature vector."""
    return FeatureVector(
        vt_malicious_ratio=0.0,
        vt_suspicious_ratio=0.0,
        vt_reputation_score=1.0,
        vt_last_seen_days_ago=2.0,
        shodan_open_port_count=2.0,
        shodan_has_high_risk_port=0.0,
        shodan_cve_count=0.0,
        shodan_max_cvss_score=0.0,
        tech_count=5.0,
        tech_has_known_eol_component=0.0,
        tech_avg_confidence=1.0,
        ssl_cert_valid=1.0,
        domain_age_days=1000.0
    )


@pytest.fixture
def malicious_features() -> FeatureVector:
    """A highly malicious feature vector."""
    return FeatureVector(
        vt_malicious_ratio=0.8,
        vt_suspicious_ratio=0.5,
        vt_reputation_score=0.1,
        vt_last_seen_days_ago=60.0,
        shodan_open_port_count=8.0,
        shodan_has_high_risk_port=1.0,
        shodan_cve_count=5.0,
        shodan_max_cvss_score=9.8,
        tech_count=15.0,
        tech_has_known_eol_component=1.0,
        tech_avg_confidence=0.9,
        ssl_cert_valid=0.0,
        domain_age_days=5.0
    )


def test_model_loading() -> None:
    """Test that model loading works and fails correctly."""
    m = FusionModel()
    assert not m.is_loaded
    
    with pytest.raises(FileNotFoundError):
        m.load("does_not_exist.json")
        
    with pytest.raises(RuntimeError):
        m.predict(FeatureVector())


def test_model_predict(model: FusionModel, benign_features: FeatureVector, malicious_features: FeatureVector) -> None:
    """Test model predictions on known vectors."""
    assert model.is_loaded
    
    # Benign
    label = model.predict(benign_features)
    assert label == 0
    proba = model.predict_proba(benign_features)
    assert 0.0 <= proba < 0.5
    
    # Malicious
    label2 = model.predict(malicious_features)
    assert label2 == 1
    proba2 = model.predict_proba(malicious_features)
    assert 0.5 <= proba2 <= 1.0


def test_explain_prediction(model: FusionModel, malicious_features: FeatureVector) -> None:
    """Test that SHAP explainability works."""
    explanations = explain_prediction(model, malicious_features)
    
    # Should explain exactly 19 features
    assert len(explanations) == 19
    
    # Should be sorted by absolute SHAP value, descending
    abs_vals = [abs(e.shap_value) for e in explanations]
    assert abs_vals == sorted(abs_vals, reverse=True)
    
    # Check that formatting applied correctly
    top_feature = explanations[0]
    assert top_feature.feature_name in malicious_features.model_fields
    assert "(+" in top_feature.human_readable or "(-" in top_feature.human_readable
