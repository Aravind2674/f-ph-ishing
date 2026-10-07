"""Revamp T3b/T3c — the headline is the higher-risk band of the two channels; no score is ever modified.

* ``ml_score``       the URL model's calibrated probability (the stacked tree + character-CNN fusion);
* ``baseline_score`` the provider-evidence weighted sum.

The headline takes the higher *band*; ``driven_by`` names the channel; ``agreement`` reports whether the scores are within 15
points.  Nothing here may raise, lower or clamp either score.
"""

from __future__ import annotations

import random

import pytest
import respx
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.ml.baseline import baseline_score, baseline_terms
from app.ml.verdict import AGREEMENT_POINTS, Verdict, band_rank, headline_verdict
from app.models.schemas import FeatureVector
from tests.conftest import mock_site


# ── the rule itself ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("provider,url,expected", [
    ("Low", "Critical", Verdict("Critical", "url_model", None)),
    ("Critical", "Low", Verdict("Critical", "provider_evidence", None)),
    ("High", "High", Verdict("High", "both", None)),
    ("Medium", "High", Verdict("High", "url_model", None)),
    ("High", "Medium", Verdict("High", "provider_evidence", None)),
    ("Low", "Low", Verdict("Low", "both", None)),
])
def test_headline_is_the_higher_band(provider: str, url: str, expected: Verdict) -> None:
    got = headline_verdict(None, provider, None, url)
    assert (got.headline_band, got.driven_by) == (expected.headline_band, expected.driven_by)


def test_a_channel_without_a_band_does_not_vote_and_is_never_low() -> None:
    assert headline_verdict(None, "Unknown", 0.9, "High") == Verdict("High", "url_model", None)
    assert headline_verdict(0.8, "Critical", None, None) == Verdict("Critical", "provider_evidence", None)
    assert headline_verdict(None, None, None, "Unknown") == Verdict(None, None, None)
    assert band_rank("Unknown") == 0 and band_rank(None) == 0 and band_rank("Low") == 1


def test_agreement_is_within_fifteen_points_and_only_with_two_scores() -> None:
    assert AGREEMENT_POINTS == 15.0
    assert headline_verdict(0.50, "High", 0.65, "High").agreement is True          # exactly 15 points apart
    assert headline_verdict(0.50, "High", 0.651, "High").agreement is False
    assert headline_verdict(0.80, "Critical", 0.03, "Low").agreement is False
    assert headline_verdict(None, "Unknown", 0.9, "High").agreement is None
    assert headline_verdict(0.9, "Critical", None, None).agreement is None


# ── the provider-evidence score is unchanged by the refactor into terms ─────
def _reference_baseline(f: FeatureVector) -> float:
    """The original formula, kept here verbatim as the oracle for the refactor."""
    n = lambda x: 0.0 if x is None else x  # noqa: E731
    score = 0.0
    score += n(f.vt_malicious_ratio) * 0.85
    score += n(f.vt_suspicious_ratio) * 0.20
    score += (0.0 if f.vt_reputation_score is None else 1.0 - f.vt_reputation_score) * 0.10
    score += (n(f.shodan_max_cvss_score) / 10.0) * 0.35
    score += n(f.shodan_has_high_risk_port) * 0.15
    score += min(n(f.shodan_open_port_count) / 10.0, 1.0) * 0.05
    score += min(n(f.shodan_cve_count) / 10.0, 1.0) * 0.05
    score += n(f.tech_has_known_eol_component) * 0.15
    score += min(n(f.tech_count) / 20.0, 1.0) * 0.02
    if f.ssl_cert_valid == 1.0:
        score -= 0.05
    if f.domain_age_days is not None and f.domain_age_days < 30.0:
        score += (1.0 - (f.domain_age_days / 30.0)) * 0.05
    return max(0.0, min(1.0, score))


def test_baseline_score_equals_the_original_formula_and_its_terms_add_up() -> None:
    rng = random.Random(7)
    fields = list(FeatureVector.model_fields)
    for _ in range(300):
        values = {}
        for name in fields:
            if rng.random() < 0.25:
                values[name] = None
            elif name.endswith(("ratio", "reputation_score", "confidence")):
                values[name] = rng.random()
            elif name.startswith(("shodan_has", "tech_has", "ssl")):
                values[name] = float(rng.randint(0, 1))
            else:
                values[name] = rng.random() * 40
        vec = FeatureVector(**values)
        assert baseline_score(vec) == _reference_baseline(vec)
        unclamped = sum(points for _, points in baseline_terms(vec))
        assert baseline_score(vec) == pytest.approx(max(0.0, min(1.0, unclamped)), abs=1e-12)


def test_every_term_has_words_and_a_nonzero_value() -> None:
    vec = FeatureVector(vt_malicious_ratio=0.5, shodan_max_cvss_score=9.8, shodan_has_high_risk_port=1.0, ssl_cert_valid=1.0,
                        domain_age_days=3.0)
    terms = baseline_terms(vec)
    assert all(text and points != 0 for text, points in terms)
    assert any("50%" in text for text, _ in terms) and any("9.8" in text for text, _ in terms)
    assert any(points < 0 for _, points in terms), "the valid-certificate bonus is a negative term, shown as such"


# ── end to end: scores are exactly what was computed ────────────────────────
@pytest.fixture
def live_client(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    monkeypatch.setenv("NVD_API_KEY", "nvd-key-for-tests-123456")
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    yield TestClient(app)
    get_settings.cache_clear()


def _vt(malicious: int, harmless: int) -> dict:
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "harmless": harmless, "suspicious": 0, "undetected": 0},
                                    "reputation": -40, "last_analysis_date": 1_700_000_000}}}


def _scan(client: TestClient, target: str, vt_body: dict | None, vt_status: int = 200, site_status: int = 200) -> dict:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(vt_status, json=vt_body or {})
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        mock_site(router, target, status=site_status, text="<html></html>" + "x" * 25000)
        body = client.post("/scan", json={"target": target, "target_type": "domain"}).json()
    assert body["success"] is True, body
    return body["result"]


def test_provider_evidence_can_drive_the_headline_and_no_score_is_changed(live_client: TestClient) -> None:
    res = _scan(live_client, "harmless-looking-shop.example", _vt(malicious=70, harmless=0))
    # both scores are exactly what their own computation gives
    assert res["ml_score"] == res["url_risk"]["headline_score"]
    assert res["baseline_score"] == baseline_score(FeatureVector(**res["features"]))
    assert sum(t["weight"] for t in res["baseline_terms"]) == pytest.approx(res["baseline_score"], abs=1e-3 * len(res["baseline_terms"]))
    # the headline follows the rule from the two bands that were computed
    expected = headline_verdict(res["baseline_score"], res["baseline_label"], res["ml_score"], res["ml_label"])
    assert (res["headline_band"], res["driven_by"], res["agreement"]) == (expected.headline_band, expected.driven_by, expected.agreement)
    assert res["baseline_label"] == "Critical"
    assert res["headline_band"] == "Critical" and res["driven_by"] in ("provider_evidence", "both")
    assert "critical risk profile" in res["summary"]


def test_url_model_can_drive_the_headline_when_providers_say_nothing_bad(live_client: TestClient) -> None:
    res = _scan(live_client, "paypa1-secure-login.com", _vt(malicious=0, harmless=70))
    assert res["baseline_label"] == "Low" and res["ml_label"] in ("High", "Critical")
    assert res["headline_band"] == res["ml_label"] and res["driven_by"] == "url_model"
    assert res["agreement"] is False
    assert res["ml_score"] == res["url_risk"]["headline_score"], "the URL score is not lowered to match the providers"
    assert res["baseline_score"] == baseline_score(FeatureVector(**res["features"])), "nor the provider score raised to match the URL model"


def test_when_every_provider_fails_the_url_model_still_names_the_headline(live_client: TestClient) -> None:
    res = _scan(live_client, "paypa1-secure-login.com", None, vt_status=500, site_status=500)
    assert res["verdict_status"] == "unknown" and res["baseline_score"] is None and res["baseline_terms"] == []
    assert res["headline_band"] in ("High", "Critical") and res["driven_by"] == "url_model"
    assert res["agreement"] is None
    assert "URL text itself looks like phishing" in res["summary"]


def test_history_carries_the_headline(live_client: TestClient) -> None:
    _scan(live_client, "paypa1-secure-login.com", _vt(malicious=0, harmless=70))
    first = live_client.get("/scan/history").json()[0]
    assert first["headline_band"] in ("High", "Critical") and first["driven_by"] == "url_model"
