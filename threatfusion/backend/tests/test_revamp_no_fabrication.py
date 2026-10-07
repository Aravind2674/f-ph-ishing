"""Revamp T3a — no fabricated values in the serving path.

Rule: every number the service reports comes from a provider answer, a local feed, a captured packet or a model inference on
this request.  A value that is unknown is ``None`` (shown as "—"), never a constant, a default or a neutral stand-in.
Nothing here reaches a real provider: httpx is intercepted by respx and DNS / target validation are stubbed.
"""

from __future__ import annotations

import logging
import re
from typing import Iterator

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.core.config import MockModeRefused, Settings, assert_mock_mode_allowed, get_settings
from app.ingestion.cve import CVEClient
from app.ingestion.virustotal import VirusTotalClient
from app.ml.chaining import VulnerabilityChainer, node_probability
from app.ml.features import extract_features_with_coverage
from app.models.schemas import AttackChainNode, CVEDetail, ProviderStatus, VirusTotalResult
from tests.conftest import mock_site

NVD_URL = r"https://services\.nvd\.nist\.gov/rest/json/cves/2\.0.*"


# ── mock mode is for the test-suite only ────────────────────────────────────
def test_mock_mode_defaults_to_off() -> None:
    assert Settings.model_fields["USE_MOCK_DATA"].default is False


def test_service_refuses_mock_mode_outside_pytest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    with pytest.raises(MockModeRefused, match="USE_MOCK_DATA=false"):
        assert_mock_mode_allowed(Settings(_env_file=None, USE_MOCK_DATA=True))


def test_service_starts_with_mock_off_outside_pytest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert_mock_mode_allowed(Settings(_env_file=None, USE_MOCK_DATA=False))


def test_mock_mode_is_allowed_while_a_test_runs() -> None:
    assert_mock_mode_allowed(Settings(_env_file=None, USE_MOCK_DATA=True))      # PYTEST_CURRENT_TEST is set by pytest


def test_lifespan_refuses_to_start_on_mock_data_outside_pytest(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "true")
    get_settings.cache_clear()
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    try:
        with pytest.raises(MockModeRefused):
            with TestClient(app):
                pass
    finally:
        get_settings.cache_clear()


# ── single fields: unknown stays None ───────────────────────────────────────
def test_virustotal_without_a_reputation_field_reports_none_not_zero() -> None:
    client = VirusTotalClient(api_key="k", use_mock=False)
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 60, "suspicious": 0, "undetected": 9}}}}
    parsed = client._parse_response(body)
    assert parsed.reputation_score is None
    vec, _ = extract_features_with_coverage(parsed, None, None, None)
    assert vec.vt_reputation_score is None
    assert vec.vt_malicious_ratio == pytest.approx(1 / 70)         # the counts it did report are still used


def test_virustotal_reputation_zero_is_a_real_value() -> None:
    client = VirusTotalClient(api_key="k", use_mock=False)
    body = {"data": {"attributes": {"reputation": 0, "last_analysis_stats": {"malicious": 0, "harmless": 70}}}}
    assert client._parse_response(body).reputation_score == 0


@pytest.mark.asyncio
async def test_nvd_cves_without_a_cvss_score_have_no_max_cvss(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)            # the lookup logs its max CVSS: an unscored result must not break that line
    unscored = {"vulnerabilities": [{"cve": {"id": "CVE-2024-0001", "descriptions": [{"lang": "en", "value": "Awaiting analysis"}],
                                             "metrics": {}, "published": "2024-01-01T00:00:00.000"}}]}
    nvd = CVEClient(api_key="real-key", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).respond(200, json=unscored)
        res = await nvd.lookup_cves(["CVE-2024-0001"])
    await nvd.close()
    assert res.status == ProviderStatus.OK and res.data.total_cves == 1
    assert res.data.max_cvss_score is None, "an unscored CVE must not become a CVSS of 0.0"
    vec, _ = extract_features_with_coverage(None, None, res.data, None)
    assert vec.shodan_max_cvss_score is None


def _node(cve: str, cvss=None, epss=None, kev=False, pre=("network_access",), post=("remote_code_execution",)) -> AttackChainNode:
    return AttackChainNode(cve_id=cve, cvss_score=cvss, epss_score=epss, is_in_kev=kev, pre_conditions=list(pre),
                           post_conditions=list(post))


def test_node_probability_never_invents_a_cvss() -> None:
    assert node_probability(_node("CVE-1")) is None                              # nothing known
    assert node_probability(_node("CVE-1", epss=0.3)) == pytest.approx(0.3)      # EPSS alone
    assert node_probability(_node("CVE-1", cvss=8.0)) == pytest.approx(0.8)      # CVSS alone (the old code assumed 5.0 when absent)
    assert node_probability(_node("CVE-1", cvss=8.0, epss=0.5)) == pytest.approx(0.8 * 0.7 + 0.5 * 0.3)
    assert node_probability(_node("CVE-1", kev=True)) == pytest.approx(0.99)     # observed exploitation, needs no CVSS


@pytest.mark.asyncio
async def test_attack_path_over_unrated_cves_has_no_risk_score() -> None:
    chainer = VulnerabilityChainer()
    chainer._initialized = chainer._epss_kev_loaded = chainer._exploitdb_loaded = True       # no CSV snapshots in this test
    chainer._ollama_down_until = float("inf")                                                 # rule-based conditions only
    cves = [CVEDetail(cve_id="CVE-2024-1111", description="remote code execution via the web interface"),
            CVEDetail(cve_id="CVE-2024-2222", description="remote code execution in the admin panel", cvss_v3_score=9.0)]
    paths = await chainer.build_and_solve_chain(cves, intel={})
    by_cve = {p.nodes[0].cve_id: p for p in paths}
    assert by_cve["CVE-2024-1111"].total_risk_score is None
    assert by_cve["CVE-2024-1111"].unrated_cves == ["CVE-2024-1111"]
    assert by_cve["CVE-2024-2222"].total_risk_score == pytest.approx(0.9)
    assert by_cve["CVE-2024-2222"].unrated_cves == []
    assert paths[0].total_risk_score is not None, "rated paths sort before unrated ones"


# ── a scan in which every provider fails ────────────────────────────────────
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


def numeric_leaves(obj, path: str = "") -> Iterator[tuple[str, float]]:
    if isinstance(obj, bool) or obj is None:
        return
    if isinstance(obj, (int, float)):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from numeric_leaves(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for v in obj:
            yield from numeric_leaves(v, f"{path}[]")


# Numbers that are allowed when every provider failed: model inferences on this request, the local rule-based brand check, and
# metadata about the request itself (how long a call took, which HTTP status it got).
ALLOWED = [
    r"url_risk\..*", r"ml_score", r"neural_score", r"neural_url_score", r"explanations\[\]\..*", r"neural_explanations\[\]\..*",
    r"brand_check\..*", r"lookalike_of\..*", r"canonical\.port", r"feature_schema_version",
    r"provider_results\[\]\.(latency_ms|http_status|retry_after)",
]


def test_when_every_provider_fails_no_provider_derived_number_is_reported(live_client: TestClient) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(500)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(503)
        router.get(url__regex=NVD_URL).respond(503)
        mock_site(router, "some-site.example", status=500, text="boom")
        body = live_client.post("/scan", json={"target": "some-site.example", "target_type": "domain"}).json()
    assert body["success"] is True, body
    res = body["result"]

    # every provider-derived block is absent …
    for block in ("virustotal", "shodan", "cve", "tech_fingerprint", "tls", "rdap", "dns", "ct", "exposure"):
        assert res[block] is None, block
    assert res["attack_paths"] == []
    assert res["baseline_score"] is None
    assert all(v is None for v in res["features"].values()), res["features"]

    # … and no other provider-derived number sneaks in anywhere in the response.
    stray = [(p, v) for p, v in numeric_leaves(res) if not any(re.fullmatch(a, p) for a in ALLOWED)]
    assert stray == [], f"numbers that are neither model output nor request metadata: {stray}"
