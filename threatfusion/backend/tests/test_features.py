"""Tests for the Feature Engineering module."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from app.models.schemas import (
    VirusTotalResult,
    ShodanResult,
    CVEResult,
    TechFingerprintResult,
    DetectedTechnology
)
from app.ml.features import extract_features


def test_extract_features_all_none() -> None:
    """Test that graceful degradation works when all sources fail."""
    vec = extract_features(None, None, None, None)
    # Most values should default to 0.0
    assert vec.vt_malicious_ratio == 0.0
    assert vec.shodan_open_port_count == 0.0
    # Placeholders should have their default values
    assert vec.ssl_cert_valid == 1.0
    assert vec.domain_age_days == 365.0


def test_extract_features_with_data() -> None:
    """Test feature extraction with populated data sources."""
    now = datetime.now(timezone.utc)
    
    vt = VirusTotalResult(
        malicious_count=10, 
        total_engines=50,
        reputation_score=-50,
        last_analysis_date=now - timedelta(days=10)
    )
    
    # 3389 is RDP (High Risk)
    shodan = ShodanResult(open_ports=[80, 443, 3389], vulns=["CVE-123"])
    
    cve = CVEResult(max_cvss_score=9.5)
    
    tech = TechFingerprintResult(
        technologies=[
            # jQuery 1 is in the EOL set
            DetectedTechnology(name="jQuery", version="1.12", categories=["JS"], confidence=90),
            DetectedTechnology(name="Nginx", version="1.21", categories=["Web servers"], confidence=100)
        ]
    )
    
    vec = extract_features(vt, shodan, cve, tech)
    
    # Check VT mapping
    assert vec.vt_malicious_ratio == 0.2  # 10 / 50
    assert vec.vt_reputation_score == 0.25 # (-50 + 100) / 200
    assert 9.9 < vec.vt_last_seen_days_ago < 10.1
    
    # Check Shodan mapping
    assert vec.shodan_open_port_count == 3.0
    assert vec.shodan_has_high_risk_port == 1.0
    assert vec.shodan_max_cvss_score == 9.5
    
    # Check Tech Fingerprint mapping
    assert vec.tech_count == 2.0
    assert vec.tech_has_known_eol_component == 1.0
    assert vec.tech_avg_confidence == 0.95  # (90 + 100) / 2 / 100
