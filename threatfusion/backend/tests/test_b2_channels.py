"""B2 (API channels) — URLhaus, ThreatFox, Google Safe Browsing, AbuseIPDB, urlscan (search), AlienVault OTX, GreyNoise.

Independent reputation sources, so the verdict does not hinge on VirusTotal.  Every channel: a positive record, "no record"
(``not_found`` — absence of evidence, never "safe"), every failure status (auth / rate limit with ``Retry-After`` / server
error / unparseable), ``not_configured`` without a key, ``skipped`` when it does not apply or the subject is private, the
cache (answers cached, failures never), the privacy rules (keys only in headers, only the host / public IP / trimmed URL
sent, nothing submitted to urlscan) and the deterministic mock.  respx only: no live call.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.ingestion.reputation import (AbuseIpdbChannel, GreyNoiseChannel, OtxChannel, SafeBrowsingChannel, Subject,
                                      ThreatFoxChannel, UrlhausChannel, UrlscanChannel)
from app.models.schemas import ProviderStatus

KEY = "k-test-0123456789abcdef"
URL_SUBJECT = Subject(kind="url", host="evil.example.com", registered_domain="example.com",
                      url="https://evil.example.com/login", ip="93.184.216.34")
DOMAIN_SUBJECT = Subject(kind="domain", host="evil.example.com", registered_domain="example.com", ip="93.184.216.34")
IP_SUBJECT = Subject(kind="ip", host="93.184.216.34", ip="93.184.216.34")
HASH_SUBJECT = Subject(kind="hash", hash="a" * 64)


def make(cls, **kw):
    kw.setdefault("api_key", KEY)
    kw.setdefault("limiter", QuotaLimiter(0, 0))
    kw.setdefault("cache", ProviderCache())
    return cls(use_mock=False, **kw)


def body_of(request: httpx.Request) -> str:
    return request.content.decode()


# ── URLhaus ─────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_urlhaus_exact_url_hit() -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://urlhaus-api.abuse.ch/v1/url/").respond(200, json={
            "query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": ["elf", "mirai"],
            "date_added": "2026-09-01 10:00:00 UTC", "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/"})
        res = await make(UrlhausChannel).lookup(URL_SUBJECT)
    v = res.data
    assert res.status == ProviderStatus.OK and v.listed and v.category == "malware" and v.match == "exact_url"
    assert v.reference == "https://urlhaus.abuse.ch/url/123/" and v.extra["online"] is True
    req = route.calls[0].request
    assert req.headers["auth-key"] == KEY and KEY not in str(req.url)
    assert "url=https%3A%2F%2Fevil.example.com%2Flogin" in body_of(req)


@pytest.mark.asyncio
async def test_urlhaus_host_lookup_for_a_domain_target() -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://urlhaus-api.abuse.ch/v1/host/").respond(200, json={
            "query_status": "ok", "url_count": "3", "urls": [{"url_status": "online"}, {"url_status": "offline"}, {"url_status": "online"}]})
        res = await make(UrlhausChannel).lookup(DOMAIN_SUBJECT)
    assert res.data.match == "host" and res.data.extra == {"urls": 3, "online": 2}
    assert "host=evil.example.com" in body_of(route.calls[0].request)


@pytest.mark.asyncio
async def test_urlhaus_no_results_is_not_found_and_invalid_is_an_error() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post("https://urlhaus-api.abuse.ch/v1/url/").respond(200, json={"query_status": "no_results"})
        assert (await make(UrlhausChannel).lookup(URL_SUBJECT)).status == ProviderStatus.NOT_FOUND
    with respx.mock(assert_all_called=False) as router:
        router.post("https://urlhaus-api.abuse.ch/v1/url/").respond(200, json={"query_status": "invalid_url"})
        res = await make(UrlhausChannel).lookup(URL_SUBJECT)
    assert res.status == ProviderStatus.ERROR and res.reason == "bad_request"


# ── ThreatFox ───────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_threatfox_ioc_hit_and_miss() -> None:
    hit = {"query_status": "ok", "data": [{"id": "42", "malware_printable": "Cobalt Strike", "threat_type": "botnet_cc",
                                           "confidence_level": 90, "last_seen": "2026-09-30 01:00:00 UTC"}]}
    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://threatfox-api.abuse.ch/api/v1/").respond(200, json=hit)
        res = await make(ThreatFoxChannel).lookup(DOMAIN_SUBJECT)
        assert json.loads(route.calls[0].request.content) == {"query": "search_ioc", "search_term": "evil.example.com"}
        assert route.calls[0].request.headers["auth-key"] == KEY
    assert res.data.listed and res.data.category == "botnet_c2" and res.data.reference == "https://threatfox.abuse.ch/ioc/42/"
    with respx.mock(assert_all_called=False) as router:
        router.post("https://threatfox-api.abuse.ch/api/v1/").respond(200, json={"query_status": "no_result", "data": "nothing"})
        assert (await make(ThreatFoxChannel).lookup(IP_SUBJECT)).status == ProviderStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_threatfox_searches_a_hash_and_rejects_nothing_silently() -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://threatfox-api.abuse.ch/api/v1/").respond(200, json={"query_status": "illegal_search_term"})
        res = await make(ThreatFoxChannel).lookup(HASH_SUBJECT)
    assert json.loads(route.calls[0].request.content)["search_term"] == "a" * 64
    assert res.status == ProviderStatus.ERROR and res.reason == "bad_request"


# ── Google Safe Browsing ────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_safebrowsing_match_and_no_match() -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").respond(200, json={
            "matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://evil.example.com/login"}}]})
        res = await make(SafeBrowsingChannel, client_version="9.9").lookup(URL_SUBJECT)
        req = route.calls[0].request
        sent = json.loads(req.content)
        assert sent["threatInfo"]["threatEntries"] == [{"url": "https://evil.example.com/login"}] and sent["client"]["clientVersion"] == "9.9"
        assert req.headers["x-goog-api-key"] == KEY and KEY not in str(req.url), "the key is a header, never in a URL"
    assert res.data.listed and res.data.category == "social_engineering"
    with respx.mock(assert_all_called=False) as router:
        router.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").respond(200, json={})
        assert (await make(SafeBrowsingChannel).lookup(URL_SUBJECT)).status == ProviderStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_safebrowsing_checks_a_domain_as_its_root_url() -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").respond(200, json={})
        await make(SafeBrowsingChannel).lookup(DOMAIN_SUBJECT)
    assert json.loads(route.calls[0].request.content)["threatInfo"]["threatEntries"] == [{"url": "http://evil.example.com/"}]


# ── AbuseIPDB ───────────────────────────────────────────────────────────────
def abuse(score, reports, **extra):
    return {"data": {"ipAddress": "93.184.216.34", "abuseConfidenceScore": score, "totalReports": reports,
                     "countryCode": "NL", "isp": "Example Hosting", "usageType": "Data Center", "lastReportedAt": "2026-10-01T00:00:00+00:00", **extra}}


@pytest.mark.asyncio
@pytest.mark.parametrize("score,listed", [(87, True), (50, True), (49, False), (10, False)])
async def test_abuseipdb_threshold_decides_listed(score, listed) -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r"https://api\.abuseipdb\.com/api/v2/check.*").respond(200, json=abuse(score, 12))
        res = await make(AbuseIpdbChannel, min_confidence=50).lookup(IP_SUBJECT)
        req = route.calls[0].request
        assert req.url.params["ipAddress"] == "93.184.216.34" and req.headers["key"] == KEY and KEY not in str(req.url)
    assert res.status == ProviderStatus.OK and res.data.listed is listed and res.data.score == float(score) and res.data.category == "abuse"


@pytest.mark.asyncio
async def test_abuseipdb_no_reports_is_no_record_not_a_score_of_zero() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://api\.abuseipdb\.com/.*").respond(200, json=abuse(0, 0))
        res = await make(AbuseIpdbChannel).lookup(IP_SUBJECT)
    assert res.status == ProviderStatus.NOT_FOUND and res.data is None


@pytest.mark.asyncio
async def test_abuseipdb_needs_a_public_ip() -> None:
    ch = make(AbuseIpdbChannel)
    assert (await ch.lookup(Subject(kind="domain", host="x.example.com"))).reason == "no_resolved_ip"
    assert (await ch.lookup(Subject(kind="domain", host="x.example.com", ip="10.0.0.5"))).reason == "private_address"
    assert (await ch.lookup(HASH_SUBJECT)).reason == "not_applicable"


# ── urlscan (search only) ───────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_urlscan_search_finds_malicious_prior_scans_without_a_key() -> None:
    results = {"results": [
        {"_id": "aaa", "task": {"time": "2026-09-01T00:00:00Z"}, "verdicts": {"overall": {"malicious": False}}},
        {"_id": "bbb", "task": {"time": "2026-09-20T00:00:00Z"}, "verdicts": {"overall": {"malicious": True}}}]}
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r"https://urlscan\.io/api/v1/search/.*").respond(200, json=results)
        res = await make(UrlscanChannel, api_key="").lookup(DOMAIN_SUBJECT)
        req = route.calls[0].request
        assert req.method == "GET" and req.url.params["q"] == "domain:evil.example.com" and "api-key" not in req.headers
        assert len(route.calls) == 1, "search only — never a submission"
    v = res.data
    assert v.listed and v.reference == "https://urlscan.io/result/bbb/" and v.extra["scans"] == 2 and v.extra["malicious_scans"] == 1
    assert v.extra["screenshot"] == "https://urlscan.io/screenshots/bbb.png" and v.last_seen == "2026-09-20T00:00:00Z"


@pytest.mark.asyncio
async def test_urlscan_prior_scans_without_a_malicious_verdict_are_not_listed_and_no_scans_is_not_found() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://urlscan\.io/.*").respond(200, json={"results": [{"_id": "c", "task": {"time": "t"}}]})
        res = await make(UrlscanChannel, api_key=KEY).lookup(DOMAIN_SUBJECT)
        assert res.status == ProviderStatus.OK and res.data.listed is False
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r"https://urlscan\.io/.*").respond(200, json={"results": []})
        assert (await make(UrlscanChannel, api_key=KEY).lookup(DOMAIN_SUBJECT)).status == ProviderStatus.NOT_FOUND
        assert route.calls[0].request.headers["api-key"] == KEY


# ── AlienVault OTX ──────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_otx_pulses_and_indicator_types() -> None:
    doc = {"pulse_info": {"count": 3, "pulses": [{"name": "Phish Wave A"}, {"name": "Kit B"}]}}
    with respx.mock(assert_all_called=False) as router:
        host = router.get("https://otx.alienvault.com/api/v1/indicators/hostname/evil.example.com/general").respond(200, json=doc)
        dom = router.get("https://otx.alienvault.com/api/v1/indicators/domain/example.com/general").respond(200, json=doc)
        ip = router.get("https://otx.alienvault.com/api/v1/indicators/IPv4/93.184.216.34/general").respond(200, json=doc)
        file = router.get(f"https://otx.alienvault.com/api/v1/indicators/file/{'a' * 64}/general").respond(200, json=doc)
        a = await make(OtxChannel).lookup(DOMAIN_SUBJECT)
        b = await make(OtxChannel).lookup(Subject(kind="domain", host="example.com", registered_domain="example.com"))
        c = await make(OtxChannel).lookup(IP_SUBJECT)
        d = await make(OtxChannel).lookup(HASH_SUBJECT)
        assert host.called and dom.called and ip.called and file.called
        assert host.calls[0].request.headers["x-otx-api-key"] == KEY
    assert a.data.listed and a.data.category == "threat_intel" and "Phish Wave A" in a.data.detail and a.data.extra["pulses"] == 3
    assert all(r.status == ProviderStatus.OK for r in (b, c, d))


@pytest.mark.asyncio
async def test_otx_zero_pulses_and_404_are_not_found() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://otx\.alienvault\.com/.*").respond(200, json={"pulse_info": {"count": 0, "pulses": []}})
        assert (await make(OtxChannel).lookup(DOMAIN_SUBJECT)).status == ProviderStatus.NOT_FOUND
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://otx\.alienvault\.com/.*").respond(404, json={"detail": "not found"})
        assert (await make(OtxChannel).lookup(DOMAIN_SUBJECT)).status == ProviderStatus.NOT_FOUND


# ── GreyNoise Community ─────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("doc,category,listed", [
    ({"noise": True, "riot": False, "classification": "malicious", "link": "https://viz.greynoise.io/ip/1"}, "scanner", True),
    ({"noise": True, "riot": False, "classification": "unknown"}, "scanner", False),
    ({"noise": False, "riot": True, "classification": "benign", "name": "Cloudflare"}, "benign", False),
])
async def test_greynoise_classifications(doc, category, listed) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get("https://api.greynoise.io/v3/community/93.184.216.34").respond(200, json={"ip": "93.184.216.34", **doc})
        res = await make(GreyNoiseChannel, api_key="").lookup(IP_SUBJECT)
    assert res.status == ProviderStatus.OK and res.data.category == category and res.data.listed is listed


@pytest.mark.asyncio
async def test_greynoise_not_observed_is_not_found_and_the_optional_key_is_a_header() -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.get("https://api.greynoise.io/v3/community/93.184.216.34").respond(404, json={"noise": False, "riot": False})
        res = await make(GreyNoiseChannel, api_key=KEY).lookup(IP_SUBJECT)
        assert route.calls[0].request.headers["key"] == KEY
    assert res.status == ProviderStatus.NOT_FOUND


# ── behaviour shared by every channel ───────────────────────────────────────
CASES = [
    (UrlhausChannel, "POST", r"https://urlhaus-api\.abuse\.ch/.*", URL_SUBJECT),
    (ThreatFoxChannel, "POST", r"https://threatfox-api\.abuse\.ch/.*", DOMAIN_SUBJECT),
    (SafeBrowsingChannel, "POST", r"https://safebrowsing\.googleapis\.com/.*", URL_SUBJECT),
    (AbuseIpdbChannel, "GET", r"https://api\.abuseipdb\.com/.*", IP_SUBJECT),
    (UrlscanChannel, "GET", r"https://urlscan\.io/.*", DOMAIN_SUBJECT),
    (OtxChannel, "GET", r"https://otx\.alienvault\.com/.*", DOMAIN_SUBJECT),
    (GreyNoiseChannel, "GET", r"https://api\.greynoise\.io/.*", IP_SUBJECT),
]


def _route(router, method, pattern):
    return (router.post if method == "POST" else router.get)(url__regex=pattern)


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,method,pattern,subject", CASES)
@pytest.mark.parametrize("status,reason", [(401, "auth"), (403, "auth"), (500, "server_error"), (503, "server_error"), (400, "bad_request")])
async def test_failures_are_errors_never_cached(cls, method, pattern, subject, status, reason) -> None:
    cache = ProviderCache()
    with respx.mock(assert_all_called=False) as router:
        route = _route(router, method, pattern).respond(status, text="nope")
        ch = make(cls, cache=cache)
        first, second = await ch.lookup(subject), await ch.lookup(subject)
    assert first.status == ProviderStatus.ERROR and first.reason == reason and first.data is None
    assert len(route.calls) == 2, "a failure is retried next time, not served from the cache"


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,method,pattern,subject", CASES)
async def test_rate_limit_honours_retry_after_and_throttles_the_next_call(cls, method, pattern, subject) -> None:
    with respx.mock(assert_all_called=False) as router:
        route = _route(router, method, pattern).respond(429, text="slow down", headers={"retry-after": "7"})
        ch = make(cls, limiter=QuotaLimiter(60, 0), max_queue_seconds=0.0)
        first = await ch.lookup(subject)
        second = await ch.lookup(subject)
    assert first.status == ProviderStatus.ERROR and first.reason == "rate_limited" and first.retry_after == 7.0
    assert second.reason == "rate_limited" and len(route.calls) == 1, "the penalty window blocks the second request"


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,method,pattern,subject", CASES)
async def test_unparseable_answers_are_parse_errors(cls, method, pattern, subject) -> None:
    with respx.mock(assert_all_called=False) as router:
        _route(router, method, pattern).respond(200, text="<html>Service Unavailable</html>")
        res = await make(cls).lookup(subject)
    assert res.status == ProviderStatus.ERROR and res.reason == "parse_error"


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [UrlhausChannel, ThreatFoxChannel, SafeBrowsingChannel, AbuseIpdbChannel, OtxChannel])
async def test_a_missing_key_is_not_configured_and_nothing_is_sent(cls) -> None:
    subject = IP_SUBJECT if cls is AbuseIpdbChannel else DOMAIN_SUBJECT
    with respx.mock(assert_all_called=False) as router:
        res = await make(cls, api_key="").lookup(subject)
        assert not router.calls
    assert res.status == ProviderStatus.NOT_CONFIGURED


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [UrlhausChannel, ThreatFoxChannel, SafeBrowsingChannel, UrlscanChannel, OtxChannel])
@pytest.mark.parametrize("host", ["localhost", "printer.local", "intranet", "10.0.0.5", "192.168.1.1"])
async def test_private_and_local_names_never_leave_the_machine(cls, host) -> None:
    kind = "ip" if host[0].isdigit() else "domain"
    subject = Subject(kind=kind, host=host, ip=host if kind == "ip" else None)
    with respx.mock(assert_all_called=False) as router:
        res = await make(cls).lookup(subject)
        assert not router.calls
    assert res.status == ProviderStatus.SKIPPED


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,method,pattern,subject,json_hit", [
    (UrlhausChannel, "POST", r"https://urlhaus-api\.abuse\.ch/.*", URL_SUBJECT, {"query_status": "ok", "url_status": "online"}),
    (AbuseIpdbChannel, "GET", r"https://api\.abuseipdb\.com/.*", IP_SUBJECT, abuse(90, 5)),
    (GreyNoiseChannel, "GET", r"https://api\.greynoise\.io/.*", IP_SUBJECT, {"noise": True, "riot": False, "classification": "malicious"}),
])
async def test_answers_are_cached(cls, method, pattern, subject, json_hit) -> None:
    cache = ProviderCache()
    with respx.mock(assert_all_called=False) as router:
        route = _route(router, method, pattern).respond(200, json=json_hit)
        ch = make(cls, cache=cache)
        first, second = await ch.lookup(subject), await ch.lookup(subject)
    assert len(route.calls) == 1 and second.cached is True and second.data == first.data


@pytest.mark.asyncio
async def test_a_no_record_answer_is_cached_too_but_briefly() -> None:
    cache = ProviderCache()
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r"https://otx\.alienvault\.com/.*").respond(200, json={"pulse_info": {"count": 0}})
        ch = make(OtxChannel, cache=cache)
        a, b = await ch.lookup(DOMAIN_SUBJECT), await ch.lookup(DOMAIN_SUBJECT)
    assert a.status == b.status == ProviderStatus.NOT_FOUND and len(route.calls) == 1


# ── mocks ───────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [UrlhausChannel, ThreatFoxChannel, SafeBrowsingChannel, AbuseIpdbChannel, UrlscanChannel, OtxChannel])
async def test_mock_mode_is_deterministic_labelled_and_offline(cls) -> None:
    subject = Subject(kind="domain", host="evil-login.example.com", registered_domain="example.com", ip="93.184.216.34")
    benign = Subject(kind="domain", host="www.example.org", registered_domain="example.org", ip="93.184.216.34")
    with respx.mock(assert_all_called=False) as router:
        ch = cls(use_mock=True)
        a, b, clean = await ch.lookup(subject), await ch.lookup(subject), await ch.lookup(benign)
        assert not router.calls
    assert a.mock is True and a.status == ProviderStatus.OK and a.data == b.data and a.data.listed
    assert clean.mock is True and clean.status == ProviderStatus.NOT_FOUND
