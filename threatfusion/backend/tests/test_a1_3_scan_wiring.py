"""A1-3 — the TLS / RDAP / DNS signals wired into ``POST /scan``, the feature vector and ``/health``.

Acceptance (master prompt): *an old domain and a 2-day-old domain produce different ages; an expired certificate
gives* ``ssl_cert_valid=0``.  The three clients are replaced by stubs here (their own behaviour is covered in
``test_a1_3_tls/rdap/dns.py``); what is tested is the wiring: which target kinds trigger them, what they are
given (host / registered domain — never a URL), how results become features, and how failures read.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import respx

from app.ml.features import extract_features_with_coverage
from app.models.schemas import DnsInfo, ProviderResult, ProviderStatus, RdapInfo, TlsInfo
from tests.conftest import mock_site

NOW = datetime.now(timezone.utc)


def tls_ok(host="www.example.com", **kw) -> TlsInfo:
    base = dict(host=host, has_tls=True, chain_valid=True, san_matches_host=True, san_names=[host],
                not_before=NOW - timedelta(days=30), not_after=NOW + timedelta(days=60),
                issuer_org="Let's Encrypt", validation_level="dv", issuer_type="free_dv")
    base.update(kw)
    return TlsInfo(**base)


def rdap_ok(domain="example.com", age_days=4000.0) -> RdapInfo:
    return RdapInfo(domain=domain, registered_at=NOW - timedelta(days=age_days), registrar="R")


def dns_ok(host="www.example.com") -> DnsInfo:
    return DnsInfo(host=host, lookup_domain="example.com", a=["93.184.216.34"], mx=[], spf=False, dmarc=False)


class Stub:
    def __init__(self, result) -> None:
        self.result, self.calls = result, []

    async def lookup(self, *args):
        self.calls.append(args)
        return self.result(*args) if callable(self.result) else self.result

    async def close(self) -> None:
        return None


def _res(source: str, data) -> ProviderResult:
    return ProviderResult(source=source, status=ProviderStatus.OK, data=data, http_status=None)


@pytest.fixture
def stubs(monkeypatch):
    from app.core.hub import hub
    s = type("S", (), {})()
    s.tls, s.rdap, s.dns = Stub(_res("tls", tls_ok())), Stub(_res("rdap", rdap_ok())), Stub(_res("dns", dns_ok()))
    monkeypatch.setattr(hub, "tls", lambda: s.tls)
    monkeypatch.setattr(hub, "rdap", lambda: s.rdap)
    monkeypatch.setattr(hub, "dns", lambda: s.dns)
    return s


@pytest.fixture
def live_scan(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation
    from fastapi.testclient import TestClient
    from app.core.config import get_settings
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1000")
    for name in ("TLS_ENABLED", "RDAP_ENABLED", "DNS_ENABLED"):       # off by default in tests (they open sockets)
        monkeypatch.setenv(name, "true")
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    yield TestClient(app)
    get_settings.cache_clear()


def _scan(client, target="www.example.com", ttype="domain", **extra):
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        mock_site(router, target, text="<html></html>")
        return client.post("/scan", json={"target": target, "target_type": ttype, **extra}).json()


def _outcome(body, source):
    return next((o for o in body["result"]["provider_results"] if o["source"] == source), None)


# ── features ────────────────────────────────────────────────────────────────
def test_features_take_ssl_and_domain_age_from_the_real_signals() -> None:
    vec, cov = extract_features_with_coverage(None, None, None, None, tls=tls_ok(), rdap=rdap_ok(age_days=2.0))
    assert vec.ssl_cert_valid == 1.0 and abs(vec.domain_age_days - 2.0) < 0.01
    assert cov.has_tls and cov.has_rdap and not cov.has_dns


def test_an_expired_certificate_gives_ssl_cert_valid_zero() -> None:
    expired = tls_ok(chain_valid=False, verify_error="expired", not_after=NOW - timedelta(days=1))
    vec, _ = extract_features_with_coverage(None, None, None, None, tls=expired)
    assert vec.ssl_cert_valid == 0.0


def test_no_tls_at_all_is_zero_and_unknown_signals_stay_none() -> None:
    vec, cov = extract_features_with_coverage(None, None, None, None, tls=TlsInfo(host="x.test", has_tls=False))
    assert vec.ssl_cert_valid == 0.0 and vec.domain_age_days is None and cov.has_tls and not cov.has_rdap
    vec2, cov2 = extract_features_with_coverage(None, None, None, None)
    assert vec2.ssl_cert_valid is None and vec2.domain_age_days is None and not (cov2.has_tls or cov2.has_rdap)


def test_a_record_without_a_registration_date_leaves_the_age_unknown_not_zero() -> None:
    vec, cov = extract_features_with_coverage(None, None, None, None, rdap=RdapInfo(domain="x.com"))
    assert vec.domain_age_days is None and cov.has_rdap is True


# ── scan ────────────────────────────────────────────────────────────────────
def test_scan_runs_the_three_signals_with_host_and_registered_domain_only(live_scan, stubs) -> None:
    body = _scan(live_scan)
    r = body["result"]
    assert stubs.tls.calls == [("www.example.com",)]
    assert stubs.rdap.calls == [("example.com",)], "RDAP is asked about the registered domain, not the host"
    assert stubs.dns.calls == [("www.example.com", "example.com")]
    assert r["tls"]["chain_valid"] is True and r["rdap"]["registrar"] == "R" and r["dns"]["a"] == ["93.184.216.34"]
    assert r["features"]["ssl_cert_valid"] == 1.0 and r["features"]["domain_age_days"] > 3999
    assert r["feature_coverage"]["has_tls"] and r["feature_coverage"]["has_rdap"] and r["feature_coverage"]["has_dns"]
    for source in ("tls", "rdap", "dns"):
        assert _outcome(body, source)["status"] == "ok"


def test_an_old_domain_and_a_two_day_old_domain_produce_different_ages(live_scan, stubs) -> None:
    old = _scan(live_scan)["result"]["features"]["domain_age_days"]
    stubs.rdap.result = _res("rdap", rdap_ok(age_days=2.0))
    fresh = _scan(live_scan)["result"]["features"]["domain_age_days"]
    assert old > 3999 and abs(fresh - 2.0) < 0.05


def test_an_expired_certificate_reaches_the_scan_as_ssl_cert_valid_zero(live_scan, stubs) -> None:
    stubs.tls.result = _res("tls", tls_ok(chain_valid=False, verify_error="expired", not_after=NOW - timedelta(days=3)))
    r = _scan(live_scan)["result"]
    assert r["features"]["ssl_cert_valid"] == 0.0 and r["tls"]["verify_error"] == "expired"


def test_url_targets_use_the_canonical_host_and_registered_domain(live_scan, stubs) -> None:
    _scan(live_scan, "https://www.example.com:8443/login?token=SECRET", "url")
    assert stubs.tls.calls == [("www.example.com",)] and stubs.rdap.calls == [("example.com",)]
    assert "SECRET" not in repr(stubs.tls.calls + stubs.rdap.calls + stubs.dns.calls)


def test_failures_are_unknown_features_and_named_in_the_outcomes(live_scan, stubs) -> None:
    stubs.rdap.result = ProviderResult(source="rdap", status=ProviderStatus.ERROR, reason="rate_limited", retry_after=42.0)
    stubs.tls.result = ProviderResult(source="tls", status=ProviderStatus.ERROR, reason="timeout")
    body = _scan(live_scan)
    r = body["result"]
    assert r["features"]["domain_age_days"] is None and r["features"]["ssl_cert_valid"] is None
    assert r["rdap"] is None and r["tls"] is None
    assert _outcome(body, "rdap")["reason"] == "rate_limited" and _outcome(body, "rdap")["retry_after"] == 42.0
    assert not r["feature_coverage"]["has_rdap"] and not r["feature_coverage"]["has_tls"] and r["feature_coverage"]["has_dns"]
    assert "RDAP" in " ".join(r["data_sources_failed"]) or "rdap" in " ".join(r["data_sources_failed"])


@pytest.mark.parametrize("target,ttype", [("8.8.8.8", "ip"), ("d41d8cd98f00b204e9800998ecf8427e", "file_hash")])
def test_ip_and_hash_targets_do_not_trigger_host_signals(live_scan, stubs, target, ttype) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        body = live_scan.post("/scan", json={"target": target, "target_type": ttype}).json()
    assert stubs.tls.calls == stubs.rdap.calls == stubs.dns.calls == []
    assert body["result"]["tls"] is None and _outcome(body, "tls") is None


def test_each_signal_can_be_switched_off(live_scan, stubs, monkeypatch) -> None:
    from app.core.config import get_settings
    monkeypatch.setenv("TLS_ENABLED", "false")
    monkeypatch.setenv("RDAP_ENABLED", "false")
    get_settings.cache_clear()
    body = _scan(live_scan)
    assert stubs.tls.calls == [] and stubs.rdap.calls == [] and len(stubs.dns.calls) == 1
    assert _outcome(body, "tls")["status"] == "skipped" and _outcome(body, "tls")["reason"] == "disabled"
    assert body["result"]["features"]["ssl_cert_valid"] is None and body["result"]["features"]["domain_age_days"] is None


def test_mock_mode_scan_has_all_three_signals_labelled_mock(client, monkeypatch) -> None:
    from app.core.config import get_settings
    for name in ("TLS_ENABLED", "RDAP_ENABLED", "DNS_ENABLED"):
        monkeypatch.setenv(name, "true")
    get_settings.cache_clear()
    from fastapi.testclient import TestClient
    from app.main import app
    import app.core.validation as v

    async def _ok(t):
        return True, {"success": True}, t

    orig = v.validate_domain_target
    v.validate_domain_target = _ok
    try:
        body = TestClient(app).post("/scan", json={"target": "evil-login.com", "target_type": "domain"}).json()
    finally:
        v.validate_domain_target = orig
    r = body["result"]
    assert r["mock_mode"] is True and r["tls"] and r["rdap"] and r["dns"]
    assert r["features"]["domain_age_days"] < 10 and r["features"]["ssl_cert_valid"] == 0.0
    assert all(_outcome(body, s)["mock"] is True for s in ("tls", "rdap", "dns"))
    get_settings.cache_clear()


def test_health_lists_the_new_signals_as_keyless() -> None:
    from app.core.config import Settings
    st = Settings(_env_file=None, USE_MOCK_DATA=False).provider_statuses()
    for name in ("tls", "rdap", "dns"):
        assert st[name].configured and st[name].state == "keyless"
