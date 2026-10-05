"""B3 — Certificate Transparency history (``ingestion/ct.py``, via crt.sh).

A phishing site gets its first certificate days before it goes live; an established one has years of them.  Covered:
parsing and de-duplicating crt.sh rows, the derived fields (first seen, recent issuance, free-DV issuer, brand-like names on
the certificate), the three-state client (ok / not_found / error / skipped; failures never cached), privacy (host only,
no IPs / private names), caching that keeps ageing, the deterministic mock, and the wiring into ``POST /scan`` — a *brand-new
look-alike* versus an *established domain*.  respx / fixtures only: no live crt.sh call.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.core.safe_http import FetchPolicy
from app.ingestion.ct import CtClient, derive, is_free_dv, parse_entries
from app.models.schemas import CtInfo, ProviderStatus
from tests.conftest import mock_site

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


def row(days_ago: float, *, names: str, issuer: str = "C=US, O=Let's Encrypt, CN=R11", serial: str | None = None, now: datetime = NOW) -> dict:
    t = (now - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")
    return {"id": int(days_ago * 1000) + 1, "serial_number": serial or f"{int(days_ago * 1000):x}", "issuer_name": issuer,
            "name_value": names, "entry_timestamp": t + ".123", "not_before": t, "not_after": t}


def _client(**kw) -> CtClient:
    kw.setdefault("limiter", QuotaLimiter(0, 0))
    return CtClient(use_mock=False, clock=lambda: NOW, **kw)


# ── parsing ─────────────────────────────────────────────────────────────────
def test_rows_are_deduplicated_and_names_collected() -> None:
    rows = [row(2, names="shop.example.com\nwww.shop.example.com", serial="aa"),
            row(2, names="shop.example.com\nwww.shop.example.com", serial="aa"),          # the precertificate twin
            row(40, names="*.shop.example.com", serial="bb")]
    info = parse_entries("shop.example.com", rows)
    assert info.certs_total == 2 and len(info.certs) == 2
    assert info.certs[0].logged_at > info.certs[1].logged_at, "newest first"
    assert info.san_names == ["shop.example.com", "www.shop.example.com"], "wildcard prefix stripped, names de-duplicated"
    assert info.first_seen == NOW - timedelta(days=40)


def test_the_issuer_is_reduced_to_its_organisation() -> None:
    info = parse_entries("a.example.com", [row(1, names="a.example.com", issuer="C=US, O=DigiCert Inc, CN=DigiCert TLS RSA")])
    assert info.certs[0].issuer == "DigiCert Inc"


def test_garbage_rows_do_not_break_parsing() -> None:
    info = parse_entries("a.example.com", ["x", 3, None, {"id": 1}, {"serial_number": "z", "entry_timestamp": "not-a-date"}])
    assert info.certs_total == 2 and info.first_seen is None and info.san_names == []


# ── derived fields ──────────────────────────────────────────────────────────
def test_a_brand_new_site_looks_new_and_an_established_one_looks_old() -> None:
    fresh = derive(parse_entries("x.example.com", [row(3, names="x.example.com"), row(1, names="x.example.com")]), NOW)
    old = derive(parse_entries("y.example.com", [row(2000, names="y.example.com", issuer="O=DigiCert Inc"),
                                                 row(900, names="y.example.com", issuer="O=DigiCert Inc"),
                                                 row(20, names="y.example.com", issuer="O=DigiCert Inc")]), NOW)
    assert round(fresh.cert_first_seen_days) == 3 and fresh.cert_count_30d == 2 and fresh.issuer_is_free_dv is True
    assert round(old.cert_first_seen_days) == 2000 and old.cert_count_30d == 1 and old.issuer_is_free_dv is False
    assert old.latest_issuer == "DigiCert Inc"


def test_derive_ages_a_stored_record_and_never_invents_numbers() -> None:
    info = parse_entries("x.example.com", [row(3, names="x.example.com")])
    later = derive(info, NOW + timedelta(days=60))
    assert round(later.cert_first_seen_days) == 63 and later.cert_count_30d == 0, "the 30-day window moved on"
    empty = derive(CtInfo(host="z.example.com"), NOW)
    assert empty.cert_first_seen_days is None and empty.cert_count_30d is None and empty.issuer_is_free_dv is None


@pytest.mark.parametrize("issuer,expected", [("Let's Encrypt", True), ("ZeroSSL", True), ("Google Trust Services", True),
                                             ("DigiCert Inc", False), ("Sectigo Limited", False), (None, None), ("", None)])
def test_free_dv_issuers(issuer, expected) -> None:
    assert is_free_dv(issuer) is expected


def test_other_names_on_the_certificate_that_imitate_a_brand_are_counted() -> None:
    names = "login-update.example.net\npaypa1-secure.example.net\nhdfcbank-login.example.net\nwww.example.net\nexample.net"
    info = derive(parse_entries("example.net", [row(1, names=names)]), NOW)
    assert info.san_brand_keyword_hits == 2
    assert "paypa1-secure.example.net -> PayPal" in info.san_brand_hits and "hdfcbank-login.example.net -> HDFC Bank" in info.san_brand_hits


def test_the_hosts_own_name_is_not_counted_against_it() -> None:
    info = parse_entries("paypa1-secure.com", [row(1, names="paypa1-secure.com\nwww.paypa1-secure.com")])
    assert info.san_brand_hits == [], "the host itself is B4's job (brand_check), not a SAN hit"


# ── the client ──────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_ok_with_certificates(fake_dns) -> None:
    body = json.dumps([row(3, names="new.example.com"), row(1, names="new.example.com")])
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "crt.sh", text=body, headers={"content-type": "application/json"})
        res = await _client().lookup("new.example.com")
    assert res.status == ProviderStatus.OK and res.data.certs_total == 2
    assert round(res.data.cert_first_seen_days) == 3 and res.data.cert_count_30d == 2


@pytest.mark.asyncio
async def test_no_certificates_is_not_found_not_zero(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "crt.sh", text="[]")
        res = await _client().lookup("never-had-a-cert.example.com")
    assert res.status == ProviderStatus.NOT_FOUND and res.data is None


@pytest.mark.asyncio
@pytest.mark.parametrize("status,reason", [(502, "server_error"), (503, "server_error"), (429, "rate_limited")])
async def test_crt_sh_outages_are_errors_and_never_cached(fake_dns, status, reason) -> None:
    cache = ProviderCache()
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(status, text="busy", headers={"retry-after": "7"} if status == 429 else {})

    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "crt.sh", side_effect=handler)
        client = _client(cache=cache)
        first = await client.lookup("busy.example.com")
        second = await client.lookup("busy.example.com")
    assert first.status == ProviderStatus.ERROR and first.reason == reason and first.data is None
    assert calls["n"] == 2, "a failure is retried next time, not served from the cache"
    if status == 429:
        assert first.retry_after == 7.0


@pytest.mark.asyncio
async def test_a_non_json_answer_is_a_parse_error(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "crt.sh", text="<html><body>Gateway Timeout</body></html>")
        res = await _client().lookup("x.example.com")
    assert res.status == ProviderStatus.ERROR and res.reason == "parse_error"


@pytest.mark.asyncio
async def test_line_delimited_json_is_accepted(fake_dns) -> None:
    body = "\n".join(json.dumps(row(d, names="nd.example.com")) for d in (5, 9))
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "crt.sh", text=body)
        res = await _client().lookup("nd.example.com")
    assert res.status == ProviderStatus.OK and res.data.certs_total == 2


@pytest.mark.asyncio
async def test_an_oversized_answer_is_an_error_not_a_partial_parse(fake_dns) -> None:
    body = json.dumps([row(i, names="big.example.com") for i in range(1, 60)])
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "crt.sh", text=body)
        res = await _client(policy=FetchPolicy(max_bytes=2000)).lookup("big.example.com")
    assert res.status == ProviderStatus.ERROR and res.reason == "response_too_large"


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["8.8.8.8", "localhost", "printer.local", "10.0.0.5", "", None])
async def test_ips_and_private_names_are_skipped_without_a_request(fake_dns, host) -> None:
    with respx.mock(assert_all_called=False) as router:
        res = await _client().lookup(host)
        assert not router.calls
    assert res.status == ProviderStatus.SKIPPED


@pytest.mark.asyncio
async def test_only_the_host_name_is_sent(fake_dns) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="[]")

    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "crt.sh", side_effect=handler)
        await _client().lookup("Sub.Example.com.")
    assert len(seen) == 1 and seen[0].url.params["q"] == "sub.example.com" and seen[0].url.params["output"] == "json"
    assert "token" not in str(seen[0].url) and "?" not in str(seen[0].url).split("?q=")[0]


@pytest.mark.asyncio
async def test_cached_answers_keep_ageing(fake_dns) -> None:
    cache = ProviderCache()
    clock = {"now": NOW}
    body = json.dumps([row(3, names="age.example.com")])
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(200, text=body)

    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "crt.sh", side_effect=handler)
        client = CtClient(use_mock=False, cache=cache, limiter=QuotaLimiter(0, 0), clock=lambda: clock["now"])
        first = await client.lookup("age.example.com")
        clock["now"] = NOW + timedelta(days=10)
        second = await client.lookup("age.example.com")
    assert hits["n"] == 1 and second.cached is True
    assert round(first.data.cert_first_seen_days) == 3 and round(second.data.cert_first_seen_days) == 13


# ── the mock ────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_the_mock_is_deterministic_and_labelled() -> None:
    client = CtClient(use_mock=True, clock=lambda: NOW)
    a, b = await client.lookup("evil-login.example.com"), await client.lookup("evil-login.example.com")
    assert a.mock is True and a.data == b.data
    assert a.data.cert_first_seen_days < 10 and a.data.cert_count_30d >= 3
    google = await client.lookup("www.google.com")
    assert google.data.cert_first_seen_days > 1000 and google.data.issuer_is_free_dv is False


# ── scan wiring: a brand-new look-alike vs an established domain ────────────
@pytest.fixture
def live_scan(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation
    from fastapi.testclient import TestClient
    from app.core.config import get_settings
    from app.main import app

    for name, value in {"USE_MOCK_DATA": "false", "VIRUSTOTAL_API_KEY": "vt-key-for-tests-123456",
                        "NVD_API_KEY": "nvd-key-for-tests-123456", "RATE_LIMIT_REQUESTS_PER_MINUTE": "1000",
                        "CT_ENABLED": "true", "CT_REQUESTS_PER_MINUTE": "0"}.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    yield TestClient(app)
    get_settings.cache_clear()


def _scan(client, target, crt_response):
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        mock_site(router, target, text="<html></html>")
        mock_site(router, "crt.sh", **crt_response)
        return client.post("/scan", json={"target": target, "target_type": "domain"}).json()["result"]


def test_scan_reports_a_fresh_certificate_history_for_a_new_lookalike(live_scan) -> None:
    # A scan-level test runs on the real clock (the age is re-derived on read), so the fixture is dated relative to the real "now";
    # with the fixed NOW above it only passed on the day it was written and failed from the next day on.
    now = datetime.now(timezone.utc)
    body = json.dumps([row(2, names="paypa1-secure.com\nwww.paypa1-secure.com\nhdfcbank-login.paypa1-secure.com", now=now),
                       row(1, names="paypa1-secure.com", now=now)])
    r = _scan(live_scan, "paypa1-secure.com", {"text": body})
    ct = r["ct"]
    assert round(ct["cert_first_seen_days"]) == 2 and ct["cert_count_30d"] == 2 and ct["issuer_is_free_dv"] is True
    assert ct["san_brand_keyword_hits"] == 1
    assert r["feature_coverage"]["has_ct"] is True
    out = next(o for o in r["provider_results"] if o["source"] == "ct")
    assert out["status"] == "ok"
    assert r["lookalike_of"]["brand"] == "PayPal", "B4 and B3 agree on this host, from different evidence"


def test_scan_reports_an_old_certificate_history_for_an_established_domain(live_scan) -> None:
    body = json.dumps([row(3000, names="stable.example.org", issuer="O=DigiCert Inc"),
                       row(10, names="stable.example.org", issuer="O=DigiCert Inc")])
    r = _scan(live_scan, "stable.example.org", {"text": body})
    assert r["ct"]["cert_first_seen_days"] > 2900 and r["ct"]["issuer_is_free_dv"] is False


def test_a_crt_sh_outage_leaves_the_certificate_facts_unknown(live_scan) -> None:
    r = _scan(live_scan, "outage.example.org", {"status": 503, "text": "busy"})
    out = next(o for o in r["provider_results"] if o["source"] == "ct")
    assert out["status"] == "error" and out["reason"] == "server_error"
    assert r["ct"] is None and r["feature_coverage"]["has_ct"] is False
    assert r["verdict_status"] in ("ok", "partial", "unknown")


def test_the_switch_skips_ct_in_live_mode(live_scan, monkeypatch) -> None:
    from app.core.config import get_settings
    monkeypatch.setenv("CT_ENABLED", "false")
    get_settings.cache_clear()
    r = _scan(live_scan, "off.example.org", {"text": "[]"})
    out = next(o for o in r["provider_results"] if o["source"] == "ct")
    assert out["status"] == "skipped" and out["reason"] == "disabled" and r["ct"] is None
