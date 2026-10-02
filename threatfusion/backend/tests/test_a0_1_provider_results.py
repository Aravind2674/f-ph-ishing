"""A0-1 — three-state provider results (AUDIT_REPORT.md §A, §C, Appendix B).

Audit finding: every HTTP failure was converted to an empty object → zeros → "clean".
A simulated live-mode outage (VT 401, InternetDB 503, target 500) returned
``success=true, sources_failed=[], ml=Low``.  A failed lookup was even *cached* for an hour.

Contract now:
* every provider client returns ``ProviderResult`` with an explicit status
  (ok | not_found | error | skipped | not_configured), http status, reason code,
  timestamp, cached flag and latency — so "no record" and "lookup failed" are never confused;
* failures are never cached and never turned into data;
* features for a provider that did not answer are ``None`` (unknown), not 0 / 0.5;
* if no reputation source answered the verdict is ``unknown`` — never ``Low``.

No test here reaches a real provider: every httpx call is intercepted by respx
(an unmatched request raises), and DNS/target validation are stubbed.
"""

from __future__ import annotations

import numpy as np
from datetime import datetime, timezone

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.ingestion.cve import CVEClient
from app.ingestion.shodan import ShodanClient
from app.ingestion.techfingerprint import TechFingerprintClient
from app.ingestion.virustotal import VirusTotalClient
from app.ml.baseline import baseline_score
from app.ml.features import extract_features, extract_features_with_coverage
from app.ml.fusion_model import FusionModel
from app.models.schemas import (
    CVEResult,
    DetectedTechnology,
    FeatureVector,
    ProviderResult,
    ProviderStatus,
    ShodanResult,
    TechFingerprintResult,
    VirusTotalResult,
)

VT_URL = r"https://www\.virustotal\.com/api/v3/domains/.*"
IDB_URL = r"https://internetdb\.shodan\.io/.*"
NVD_URL = r"https://services\.nvd\.nist\.gov/rest/json/cves/2\.0.*"

VT_OK_JSON = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 2, "harmless": 60, "suspicious": 1, "undetected": 7},
    "reputation": 5, "last_analysis_date": 1_700_000_000, "categories": {"Sophos": "business"}}}}
NVD_OK_JSON = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228",
    "descriptions": [{"lang": "en", "value": "Log4j JNDI remote code execution"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
    "published": "2021-12-10T10:15:00.000"}}]}


# ── ProviderResult itself ───────────────────────────────────────────────────
def test_provider_result_shape_and_helpers() -> None:
    r = ProviderResult[VirusTotalResult](source="virustotal", status=ProviderStatus.OK,
                                         data=VirusTotalResult(), http_status=200)
    assert r.ok and r.fetched_at.tzinfo is not None and r.cached is False and r.mock is False
    bad = ProviderResult[VirusTotalResult](source="virustotal", status=ProviderStatus.ERROR, reason="auth")
    assert not bad.ok and bad.data is None
    # An empty-but-successful model must NOT be mistaken for "no data" by truthiness checks.
    assert bool(VirusTotalResult()) is True
    assert bad.outcome().status == ProviderStatus.ERROR and bad.outcome().reason == "auth"


# ── VirusTotal: status matrix ───────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("code,status,reason", [
    (404, ProviderStatus.NOT_FOUND, None),
    (401, ProviderStatus.ERROR, "auth"),
    (403, ProviderStatus.ERROR, "auth"),
    (429, ProviderStatus.ERROR, "rate_limited"),
    (500, ProviderStatus.ERROR, "server_error"),
    (503, ProviderStatus.ERROR, "server_error"),
    (400, ProviderStatus.ERROR, "bad_request"),
])
async def test_virustotal_http_status_mapping(code: int, status: ProviderStatus, reason: str | None) -> None:
    vt = VirusTotalClient(api_key="k", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_URL).respond(code)
        res = await vt.lookup_domain("example.com")
    await vt.close()
    assert res.status == status
    assert res.http_status == code
    assert res.data is None, "a failed/absent lookup must never be turned into data"
    if reason:
        assert res.reason == reason
    assert res.latency_ms is not None and res.latency_ms >= 0
    assert res.fetched_at.tzinfo is not None and not res.cached


@pytest.mark.asyncio
async def test_virustotal_success_parses_data() -> None:
    vt = VirusTotalClient(api_key="k", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_URL).respond(200, json=VT_OK_JSON)
        res = await vt.lookup_domain("example.com")
    await vt.close()
    assert res.status == ProviderStatus.OK and res.http_status == 200
    assert res.data.malicious_count == 2 and res.data.total_engines == 70
    assert res.data.last_analysis_date == datetime.fromtimestamp(1_700_000_000, tz=timezone.utc)


@pytest.mark.asyncio
@pytest.mark.parametrize("exc,reason", [
    (httpx.ReadTimeout("slow"), "timeout"),
    (httpx.ConnectTimeout("slow"), "timeout"),
    (httpx.ConnectError("refused"), "network"),
])
async def test_virustotal_transport_errors(exc: Exception, reason: str) -> None:
    vt = VirusTotalClient(api_key="k", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_URL).mock(side_effect=exc)
        res = await vt.lookup_domain("example.com")
    await vt.close()
    assert res.status == ProviderStatus.ERROR and res.reason == reason and res.http_status is None


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, {"data": {}}, {"unexpected": 1}, [], "nope"])
async def test_virustotal_malformed_200_is_an_error_not_an_empty_result(body) -> None:
    vt = VirusTotalClient(api_key="k", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_URL).respond(200, json=body)
        res = await vt.lookup_domain("example.com")
    await vt.close()
    assert res.status == ProviderStatus.ERROR and res.reason == "parse_error" and res.data is None


@pytest.mark.asyncio
@pytest.mark.parametrize("attrs", [{}, {"last_analysis_stats": {}}, {"last_analysis_stats": {"malicious": 0}}])
async def test_virustotal_object_without_analysis_is_not_found_not_zero_detections(attrs: dict) -> None:
    """VT knows the object but never analysed it: that is 'no evidence', not '0 engines flagged it'."""
    vt = VirusTotalClient(api_key="k", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_URL).respond(200, json={"data": {"attributes": attrs}})
        res = await vt.lookup_domain("example.com")
    await vt.close()
    assert res.status == ProviderStatus.NOT_FOUND and res.reason == "no_analysis" and res.data is None


@pytest.mark.asyncio
async def test_virustotal_errors_are_never_cached_but_success_is() -> None:
    """The old client cached the empty result of a failed call for an hour."""
    vt = VirusTotalClient(api_key="k", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=VT_URL).mock(side_effect=[
            httpx.Response(401), httpx.Response(200, json=VT_OK_JSON)])
        first = await vt.lookup_domain("cache.example")
        second = await vt.lookup_domain("cache.example")   # must retry, not reuse the failure
        third = await vt.lookup_domain("cache.example")    # now served from cache
        assert route.call_count == 2
    await vt.close()
    assert first.status == ProviderStatus.ERROR
    assert second.status == ProviderStatus.OK and second.cached is False
    assert third.status == ProviderStatus.OK and third.cached is True
    assert third.fetched_at == second.fetched_at, "cached results keep their original timestamp"


@pytest.mark.asyncio
async def test_virustotal_mock_results_are_labelled_mock() -> None:
    vt = VirusTotalClient(api_key="", use_mock=True)
    res = await vt.lookup_domain("google.com")
    assert res.status == ProviderStatus.OK and res.mock is True and res.data.total_engines > 0


# ── Shodan InternetDB ───────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("code,status,reason", [
    (404, ProviderStatus.NOT_FOUND, None),
    (429, ProviderStatus.ERROR, "rate_limited"),
    (503, ProviderStatus.ERROR, "server_error"),
])
async def test_internetdb_status_mapping(code: int, status: ProviderStatus, reason: str | None) -> None:
    sh = ShodanClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=IDB_URL).respond(code)
        res = await sh.lookup_ip("93.184.216.34")
    await sh.close()
    assert res.status == status and res.http_status == code and res.data is None
    if reason:
        assert res.reason == reason


@pytest.mark.asyncio
async def test_internetdb_success_and_timeout() -> None:
    sh = ShodanClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=IDB_URL).respond(
            200, json={"ports": [22, 443], "vulns": ["CVE-2021-44228"], "cpes": [], "hostnames": ["h"], "tags": []})
        ok = await sh.lookup_ip("93.184.216.34")
        router.get(url__regex=IDB_URL).mock(side_effect=httpx.ReadTimeout("slow"))
        slow = await sh.lookup_ip("93.184.216.35")
    await sh.close()
    assert ok.status == ProviderStatus.OK and ok.data.open_ports == [22, 443]
    assert slow.status == ProviderStatus.ERROR and slow.reason == "timeout"


# ── NVD ─────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_nvd_success() -> None:
    nvd = CVEClient(api_key="real-key", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).respond(200, json=NVD_OK_JSON)
        res = await nvd.lookup_cves(["CVE-2021-44228"])
    await nvd.close()
    assert res.status == ProviderStatus.OK
    assert res.data.max_cvss_score == 10.0 and res.data.total_cves == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("code,status,reason", [
    (404, ProviderStatus.NOT_FOUND, None),
    (403, ProviderStatus.ERROR, "auth_or_rate_limited"),   # NVD uses 403 for both
    (429, ProviderStatus.ERROR, "rate_limited"),
    (503, ProviderStatus.ERROR, "server_error"),
])
async def test_nvd_status_mapping(code: int, status: ProviderStatus, reason: str | None) -> None:
    nvd = CVEClient(api_key="real-key", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).respond(code)
        res = await nvd.lookup_cves(["CVE-2021-44228"])
    await nvd.close()
    assert res.status == status and res.http_status == code
    assert res.data is None, "no CVE data was obtained, so there must be no CVEResult(max_cvss=0.0)"
    if reason:
        assert res.reason == reason


@pytest.mark.asyncio
async def test_nvd_partial_success_is_ok_but_says_so() -> None:
    nvd = CVEClient(api_key="real-key", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).mock(side_effect=[
            httpx.Response(200, json=NVD_OK_JSON), httpx.Response(503)])
        res = await nvd.lookup_cves(["CVE-2021-44228", "CVE-2021-41773"])
    await nvd.close()
    assert res.status == ProviderStatus.OK
    assert res.data.total_cves == 1 and res.reason is not None and "partial" in res.reason


@pytest.mark.asyncio
async def test_nvd_timeout() -> None:
    nvd = CVEClient(api_key="real-key", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).mock(side_effect=httpx.ReadTimeout("slow"))
        res = await nvd.lookup_cves(["CVE-2021-44228"])
    await nvd.close()
    assert res.status == ProviderStatus.ERROR and res.reason == "timeout"


# ── Tech fingerprinting ─────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("code,reason", [(500, "server_error"), (503, "server_error")])
async def test_tech_server_errors_are_errors(code: int, reason: str) -> None:
    tf = TechFingerprintClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get("https://site.example/").respond(code, text="boom")
        res = await tf.fingerprint_url("https://site.example/")
    await tf.close()
    assert res.status == ProviderStatus.ERROR and res.reason == reason and res.data is None


@pytest.mark.asyncio
async def test_tech_timeout_and_challenge_page() -> None:
    tf = TechFingerprintClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get("https://slow.example/").mock(side_effect=httpx.ReadTimeout("slow"))
        slow = await tf.fingerprint_url("https://slow.example/")
        router.get("https://cf.example/").respond(200, text="<html>Just a moment... cloudflare</html>")
        blocked = await tf.fingerprint_url("https://cf.example/")
    await tf.close()
    assert slow.status == ProviderStatus.ERROR and slow.reason == "timeout"
    assert blocked.status == ProviderStatus.ERROR and blocked.reason == "bot_challenge"


@pytest.mark.asyncio
async def test_tech_success_with_nothing_detected_is_ok_not_error() -> None:
    tf = TechFingerprintClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get("https://plain.example/").respond(200, text="<html><body>hello</body></html>" + "x" * 25000)
        res = await tf.fingerprint_url("https://plain.example/")
    await tf.close()
    assert res.status == ProviderStatus.OK and isinstance(res.data, TechFingerprintResult)


# ── Features: unknown stays unknown ─────────────────────────────────────────
def test_features_for_missing_providers_are_none_not_zero() -> None:
    vec = extract_features(None, None, None, None)
    assert all(getattr(vec, n) is None for n in FeatureVector.model_fields), vec
    # the hard-coded neutral constants (ssl=1.0, age=365) were fabricated evidence
    assert vec.ssl_cert_valid is None and vec.domain_age_days is None


def test_empty_virustotal_result_is_not_the_same_as_no_virustotal_result() -> None:
    vec, cov = extract_features_with_coverage(VirusTotalResult(), None, None, None)
    assert cov.has_virustotal is True and cov.has_shodan is False
    assert vec.vt_malicious_ratio == 0.0          # provider answered: 0 engines flagged it
    assert vec.shodan_open_port_count is None      # provider did not answer: unknown


def test_coverage_flags_follow_provider_data() -> None:
    _, cov = extract_features_with_coverage(
        VirusTotalResult(total_engines=70), ShodanResult(open_ports=[22]),
        CVEResult(), TechFingerprintResult(technologies=[DetectedTechnology(name="PHP", confidence=90, categories=["x"])]))
    assert (cov.has_virustotal, cov.has_shodan, cov.has_cve, cov.has_tech) == (True, True, True, True)


def test_baseline_ignores_unknown_features_instead_of_treating_them_as_good_or_bad() -> None:
    assert baseline_score(extract_features(None, None, None, None)) == 0.0
    only_vt = baseline_score(extract_features(VirusTotalResult(malicious_count=35, total_engines=70), None, None, None))
    assert only_vt > 0.4  # a clear VT detection still drives the score without other sources


def test_xgboost_input_encodes_unknown_as_nan() -> None:
    arr = FusionModel().feature_vector_to_array(extract_features(None, None, None, None))
    assert arr.shape == (1, 19) and bool(np.isnan(arr).all())


# ── /scan end-to-end behaviour ──────────────────────────────────────────────
@pytest.fixture
def scan_client(monkeypatch: pytest.MonkeyPatch):
    """Live-mode app with every provider *configured*; DNS + target validation stubbed."""
    import socket
    import app.core.validation as validation
    from app.core.config import get_settings
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    monkeypatch.setenv("NVD_API_KEY", "nvd-key-for-tests-123456")
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "93.184.216.34")
    yield TestClient(app)
    get_settings.cache_clear()


def _scan(client: TestClient, target="some-site.example", ttype="domain") -> dict:
    body = client.post("/scan", json={"target": target, "target_type": ttype}).json()
    assert body["success"] is True, body
    return body["result"]


def test_full_provider_outage_is_reported_as_unknown_never_low(scan_client: TestClient) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(401)
        router.get(url__regex=IDB_URL).respond(503)
        router.get(url__regex=r"https://some-site\.example.*").respond(500, text="boom")
        res = _scan(scan_client)

    assert res["data_sources_succeeded"] == []
    assert set(res["data_sources_failed"]) == {"VirusTotal", "Shodan", "TechFingerprint"}
    assert res["mock_mode"] is False
    assert res["verdict_status"] == "unknown"
    assert res["ml_score"] is None and res["ml_label"] == "Unknown" and res["ml_status"] == "insufficient_evidence"
    assert res["baseline_score"] is None, "no evidence at all => no score, not 0.0"
    by_src = {o["source"]: o for o in res["provider_results"]}
    assert by_src["virustotal"]["status"] == "error" and by_src["virustotal"]["reason"] == "auth"
    assert by_src["shodan_internetdb"]["http_status"] == 503
    cov = res["feature_coverage"]
    assert not any([cov["has_virustotal"], cov["has_shodan"], cov["has_cve"], cov["has_tech"]])


def test_partial_outage_is_partial_and_names_the_failed_source(scan_client: TestClient) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(200, json=VT_OK_JSON)
        router.get(url__regex=IDB_URL).respond(503)
        router.get(url__regex=r"https://some-site\.example.*").respond(200, html="<html></html>" + "x" * 25000)
        res = _scan(scan_client)

    assert res["data_sources_succeeded"] == ["VirusTotal", "TechFingerprint"]
    assert res["data_sources_failed"] == ["Shodan"]
    assert res["verdict_status"] == "partial"
    assert res["ml_score"] is not None and res["ml_status"] == "ok"
    assert res["feature_coverage"]["has_virustotal"] is True and res["feature_coverage"]["has_shodan"] is False
    assert res["features"]["shodan_open_port_count"] is None   # unknown, not 0


def test_not_found_is_distinct_from_failed_and_from_success(scan_client: TestClient) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=IDB_URL).respond(404)
        router.get(url__regex=r"https://some-site\.example.*").respond(200, html="<html></html>" + "x" * 25000)
        res = _scan(scan_client)
    assert set(res["data_sources_not_found"]) == {"VirusTotal", "Shodan"}
    assert res["data_sources_failed"] == []
    assert "VirusTotal" not in res["data_sources_succeeded"]
    assert res["ml_score"] is None, "VT has no record: the VT-only model has nothing to score"


def test_nvd_failure_is_not_listed_as_success_and_cvss_is_unknown(scan_client: TestClient) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(200, json=VT_OK_JSON)
        router.get(url__regex=IDB_URL).respond(
            200, json={"ports": [22], "vulns": ["CVE-2021-44228"], "cpes": [], "hostnames": [], "tags": []})
        router.get(url__regex=NVD_URL).respond(403)
        router.get(url__regex=r"https://some-site\.example.*").respond(200, html="<html></html>" + "x" * 25000)
        res = _scan(scan_client)
    assert "NVD" in res["data_sources_failed"] and "NVD" not in res["data_sources_succeeded"]
    assert res["features"]["shodan_cve_count"] == 1.0
    assert res["features"]["shodan_max_cvss_score"] is None   # was silently 0.0 before


def test_mock_mode_scan_keeps_working_and_is_labelled(monkeypatch: pytest.MonkeyPatch) -> None:
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
    res = _scan(TestClient(app), "google.com")
    get_settings.cache_clear()
    assert res["mock_mode"] is True and res["verdict_status"] == "ok"
    assert all(o["mock"] is True for o in res["provider_results"])
    assert set(res["data_sources_succeeded"]) >= {"VirusTotal", "Shodan", "TechFingerprint"}
