"""Tests for the Baseline Rule-Based Scorer."""

from __future__ import annotations

from app.models.schemas import FeatureVector
from app.ml.baseline import baseline_score


def test_baseline_score_safe() -> None:
    """Test the scorer with perfectly safe features."""
    vec = FeatureVector(
        vt_malicious_ratio=0.0,
        vt_suspicious_ratio=0.0,
        vt_reputation_score=1.0,  # Max good reputation
        vt_last_seen_days_ago=0.0,
        shodan_open_port_count=0.0,
        shodan_has_high_risk_port=0.0,
        shodan_cve_count=0.0,
        shodan_max_cvss_score=0.0,
        tech_count=0.0,
        tech_has_known_eol_component=0.0,
        tech_avg_confidence=1.0,
        ssl_cert_valid=1.0,      # Reduces risk
        domain_age_days=365.0,   # Older domain, no risk
    )
    score = baseline_score(vec)
    assert score == 0.0


def test_baseline_score_critical() -> None:
    """Test the scorer with extremely malicious features."""
    vec = FeatureVector(
        vt_malicious_ratio=1.0,   # +0.25
        vt_suspicious_ratio=1.0,  # +0.10
        vt_reputation_score=0.0,  # +0.05
        vt_last_seen_days_ago=60.0, # +0.03
        shodan_open_port_count=20.0, # +0.05
        shodan_has_high_risk_port=1.0, # +0.08
        shodan_cve_count=20.0,    # +0.07
        shodan_max_cvss_score=10.0, # +0.15
        tech_count=40.0,          # +0.02
        tech_has_known_eol_component=1.0, # +0.08
        tech_avg_confidence=1.0,
        ssl_cert_valid=0.0,       # No reduction
        domain_age_days=0.0,      # +0.05
    )
    # Sum is 0.93. The clamping will keep it at 0.93 or 1.0.
    score = baseline_score(vec)
    assert 0.90 < score <= 1.0


def test_baseline_score_mixed() -> None:
    """Test the scorer with a mix of neutral and risky features."""
    vec = FeatureVector(
        vt_malicious_ratio=0.2,   # 0.2 * 0.25 = 0.05
        vt_suspicious_ratio=0.0,
        vt_reputation_score=0.5,  # 0.5 * 0.05 = 0.025
        vt_last_seen_days_ago=15.0, # 0.5 * 0.03 = 0.015
        shodan_open_port_count=2.0, # 0.2 * 0.05 = 0.01
        shodan_has_high_risk_port=0.0,
        shodan_cve_count=0.0,
        shodan_max_cvss_score=0.0,
        tech_count=5.0,           # 0.25 * 0.02 = 0.005
        tech_has_known_eol_component=0.0,
        tech_avg_confidence=1.0,
        ssl_cert_valid=1.0,       # -0.05
        domain_age_days=365.0,
    )
    score = baseline_score(vec)
    # 0.05 + 0.025 + 0.015 + 0.01 + 0.005 - 0.05 = 0.055
    assert 0.0 < score < 0.2
