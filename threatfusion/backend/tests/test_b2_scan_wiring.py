"""B2 (wiring) — the independent reputation channels inside ``POST /scan``.

* ``ScanResult.reputation`` lists who said what side by side — it is *not* a score and is kept apart from the maliciousness
  numbers (fusion is B7's job).
* The verdict no longer hinges on VirusTotal: any reputation source with a record counts as evidence; with none, the
  verdict stays *unknown*.  "No record" from a B2 channel is a normal answer, an error or a missing key is a gap.
* Privacy: the URL sent out is trimmed unless the user opted in; IP channels get a *public* resolved address only.
* Local feeds show their age; switches skip a channel; mock mode touches no network.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.core import providers as prov
from app.ingestion.blocklists import _index
from app.models.schemas import DnsInfo
from tests.conftest import mock_site

SOURCES = ["openphish", "phishtank", "urlhaus", "threatfox", "safebrowsing", "urlscan", "otx", "abuseipdb", "greynoise", "tranco"]
KEYS = {"ABUSECH_AUTH_KEY": "abusech-key-for-tests-123456", "GOOGLE_SAFE_BROWSING_API_KEY": "gsb-key-for-tests-123456",
        "ABUSEIPDB_API_KEY": "abuseipdb-key-for-tests-123456", "OTX_API_KEY": "otx-key-for-tests-123456"}


@pytest.fixture
def live(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation
    from app.core.config import get_settings
    from app.core.hub import hub
    from app.main import app

    env = {"USE_MOCK_DATA": "false", "VIRUSTOTAL_API_KEY": "vt-key-for-tests-123456", "RATE_LIMIT_REQUESTS_PER_MINUTE": "1000",
           "REPUTATION_REQUESTS_PER_MINUTE": "0", "DNS_ENABLED": "true", **KEYS}
    env.update({f"{s.upper()}_ENABLED": "true" for s in SOURCES})
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    hub.reset()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)

    class FakeDns:
        answer = ["93.184.216.34"]

        async def lookup(self, host, registered):
            return prov.ok("dns", DnsInfo(host=host, lookup_domain=registered or host, a=list(self.answer)), http_status=None)

        async def close(self):
            return None

    dns = FakeDns()
    monkeypatch.setattr(hub, "dns", lambda: dns)
    client = TestClient(app)
    client.dns = dns
    client.hub = hub
    yield client
    get_settings.cache_clear()
    hub.reset()


def seed_feed(client, name: str, urls) -> None:
    asyncio.run(client.hub.feeds.replace(name, _index(((u, {}) for u in urls)), source_url="test://feed"))


def seed_tranco(client, ranks: dict[str, int]) -> None:
    asyncio.run(client.hub.feeds.replace("tranco", ranks, source_url="test://tranco"))


def api_routes(router, *, urlhaus_status=200, urlhaus=None, safebrowsing=None, abuseipdb=None, otx=None, threatfox=None, urlscan=None, greynoise=None):
    """Every API channel answers 'no record' unless overridden (first registered route wins)."""
    seen = {}
    seen["urlhaus"] = router.post(url__regex=r"https://urlhaus-api\.abuse\.ch/.*").respond(urlhaus_status, json=urlhaus or {"query_status": "no_results"})
    seen["threatfox"] = router.post(url__regex=r"https://threatfox-api\.abuse\.ch/.*").respond(200, json=threatfox or {"query_status": "no_result", "data": "x"})
    seen["safebrowsing"] = router.post(url__regex=r"https://safebrowsing\.googleapis\.com/.*").respond(200, json=safebrowsing or {})
    seen["abuseipdb"] = router.get(url__regex=r"https://api\.abuseipdb\.com/.*").respond(200, json=abuseipdb or {"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    seen["urlscan"] = router.get(url__regex=r"https://urlscan\.io/.*").respond(200, json=urlscan or {"results": []})
    seen["otx"] = router.get(url__regex=r"https://otx\.alienvault\.com/.*").respond(200, json=otx or {"pulse_info": {"count": 0}})
    seen["greynoise"] = router.get(url__regex=r"https://api\.greynoise\.io/.*").respond(404, json=greynoise or {"noise": False, "riot": False})
    return seen


def scan(client, target, target_type="domain", *, vt=404, routes=None, **body):
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(vt)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        mock_site(router, (target.split("//")[-1].split("/")[0]), text="<html></html>")
        seen = api_routes(router, **(routes or {}))
        resp = client.post("/scan", json={"target": target, "target_type": target_type, **body}).json()
        assert resp["success"], resp
        return resp["result"], seen


def outcome(result, source):
    return next(o for o in result["provider_results"] if o["source"] == source)


# ── listed vs clean ─────────────────────────────────────────────────────────
def test_a_listed_phishing_url_is_reported_by_each_channel_that_knows_it(live) -> None:
    seed_feed(live, "openphish", ["https://evil.example.com/a/b"])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {"google.com": 1})
    r, _ = scan(live, "https://evil.example.com/a/b", "url", routes={
        "urlhaus": {"query_status": "ok", "url_status": "online", "threat": "malware_download", "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}})
    rep = r["reputation"]
    assert sorted(rep["listed_by"]) == ["openphish", "urlhaus"]
    by = {v["source"]: v for v in rep["verdicts"]}
    assert by["openphish"]["match"] == "exact_url" and by["openphish"]["feed_age_days"] is not None
    assert by["urlhaus"]["reference"] == "https://urlhaus.abuse.ch/url/1/"
    assert "listed by OpenPhish, URLhaus" in r["summary"]
    assert set(rep["feed_ages"]) == {"openphish", "phishtank", "tranco"} and rep["feed_ages"]["openphish"] < 0.01
    assert r["verdict_status"] in ("ok", "partial"), "a reputation source had a record, so this is not 'unknown' even though VirusTotal did not"


def test_a_clean_unknown_target_stays_unknown_and_says_so(live) -> None:
    seed_feed(live, "openphish", ["https://elsewhere.example.net/x"])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {"google.com": 1})
    r, _ = scan(live, "brand-new-site.example.org")
    rep = r["reputation"]
    assert rep["listed_by"] == [] and rep["channels_answered"] >= 8
    assert any("absence of evidence" in n for n in rep["notes"])
    assert r["verdict_status"] == "unknown" and "No reputation source answered" in r["verdict_reason"]
    assert "listed by" not in r["summary"]


def test_popularity_is_a_prior_not_a_listing(live) -> None:
    seed_feed(live, "openphish", ["https://elsewhere.example.net/x"])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {"example.org": 321})
    r, _ = scan(live, "www.example.org")
    rep = r["reputation"]
    assert rep["popularity_rank"] == 321 and rep["listed_by"] == []
    assert r["verdict_status"] == "unknown", "popularity is not maliciousness evidence"


def test_the_verdict_does_not_depend_on_virustotal(live) -> None:
    seed_feed(live, "openphish", ["http://evil.example.com/x"])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {})
    r, _ = scan(live, "evil.example.com", vt=500)
    assert outcome(r, "virustotal")["status"] == "error"
    assert r["reputation"]["listed_by"] == ["openphish"] and r["verdict_status"] == "partial"
    assert "VirusTotal" in r["verdict_reason"] or "sources answered" in r["verdict_reason"]


# ── gaps ────────────────────────────────────────────────────────────────────
def test_missing_keys_are_gaps_not_clean_answers(live, monkeypatch) -> None:
    from app.core.config import get_settings
    for name in KEYS:
        monkeypatch.setenv(name, "")
    get_settings.cache_clear()
    live.hub.reset()
    seed_feed(live, "openphish", ["http://evil.example.com/x"])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {})
    r, seen = scan(live, "evil.example.com")
    for source in ("urlhaus", "threatfox", "safebrowsing", "abuseipdb", "otx"):
        assert outcome(r, source)["status"] == "not_configured", source
    assert not seen["urlhaus"].called and not seen["otx"].called, "nothing is sent without a key"
    assert any("gave no answer" in n for n in r["reputation"]["notes"])
    assert r["verdict_status"] == "partial" and "not configured" in r["verdict_reason"]


def test_a_channel_outage_is_an_error_and_never_a_not_listed(live) -> None:
    seed_feed(live, "openphish", [])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {})
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        mock_site(router, "down.example.org", text="<html></html>")
        api_routes(router, urlhaus_status=503)
        r = live.post("/scan", json={"target": "down.example.org", "target_type": "domain"}).json()["result"]
    assert outcome(r, "urlhaus")["status"] == "error" and outcome(r, "urlhaus")["reason"] == "server_error"
    assert "urlhaus" in " ".join(r["reputation"]["notes"])
    assert "URLhaus" in r["data_sources_failed"]


def test_a_never_downloaded_local_feed_is_unknown_not_clean(live) -> None:
    seed_tranco(live, {})
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        mock_site(router, "fresh-install.example.org", text="<html></html>")
        mock_site(router, "openphish.com", path="/feed.txt", status=503, text="")
        mock_site(router, "data.phishtank.com", path="/data/online-valid.json", status=503, text="")
        api_routes(router)
        r = live.post("/scan", json={"target": "fresh-install.example.org", "target_type": "domain"}).json()["result"]
    assert outcome(r, "openphish")["status"] == "error" and outcome(r, "openphish")["reason"] == "feed_unavailable"
    assert outcome(r, "phishtank")["reason"] == "feed_unavailable"


# ── privacy ─────────────────────────────────────────────────────────────────
def test_the_url_sent_to_third_parties_is_trimmed_unless_the_user_opts_in(live) -> None:
    seed_feed(live, "openphish", [])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {})
    target = "https://evil.example.com/a/b?token=SECRET123&email=jane%40example.com"
    r, seen = scan(live, target, "url")
    body = json.dumps(json.loads(seen["safebrowsing"].calls[0].request.content)) + seen["urlhaus"].calls[0].request.content.decode()
    assert "SECRET123" not in body and "jane" not in body and "evil.example.com/a/b" in body
    r2, seen2 = scan(live, target, "url", send_full_url=True)
    assert "SECRET123" in seen2["safebrowsing"].calls[0].request.content.decode()


def test_ip_channels_get_a_public_resolved_address_and_never_an_internal_one(live) -> None:
    seed_feed(live, "openphish", [])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {})
    live.dns.answer = ["10.0.0.5", "93.184.216.34"]
    r, seen = scan(live, "mixed.example.org")
    assert seen["abuseipdb"].calls[0].request.url.params["ipAddress"] == "93.184.216.34"
    assert "93.184.216.34" in str(seen["greynoise"].calls[0].request.url)
    live.dns.answer = ["10.0.0.5"]
    r2, seen2 = scan(live, "internal-only.example.org")
    assert not seen2["abuseipdb"].called and not seen2["greynoise"].called
    assert outcome(r2, "abuseipdb")["status"] == "skipped" and outcome(r2, "abuseipdb")["reason"] == "no_resolved_ip"


# ── switches, order, events ─────────────────────────────────────────────────
def test_a_switched_off_channel_is_skipped_and_nothing_is_sent(live, monkeypatch) -> None:
    from app.core.config import get_settings
    monkeypatch.setenv("URLHAUS_ENABLED", "false")
    monkeypatch.setenv("SAFEBROWSING_ENABLED", "false")
    get_settings.cache_clear()
    seed_feed(live, "openphish", [])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {})
    r, seen = scan(live, "off.example.org")
    assert outcome(r, "urlhaus")["status"] == "skipped" and outcome(r, "urlhaus")["reason"] == "disabled"
    assert not seen["urlhaus"].called and not seen["safebrowsing"].called and seen["otx"].called


def test_outcomes_follow_a_stable_order_and_the_start_event_announces_every_channel(live) -> None:
    from app.core.scan_events import bus
    seed_feed(live, "openphish", [])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {})
    r, _ = scan(live, "order.example.org", scan_id="scan-b2-order-01")
    sources = [o["source"] for o in r["provider_results"] if o["source"] in SOURCES]
    assert sources == SOURCES
    start = bus.events("scan-b2-order-01")[0]
    assert set(SOURCES) <= set(start["providers"])
    blob = json.dumps(bus.events("scan-b2-order-01"))
    assert "order.example.org" not in blob, "events never carry the target"


def test_target_kinds_decide_which_channels_apply(live) -> None:
    seed_feed(live, "openphish", [])
    seed_feed(live, "phishtank", [])
    seed_tranco(live, {})
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        api_routes(router)
        ip = live.post("/scan", json={"target": "93.184.216.34", "target_type": "ip"}).json()["result"]
        digest = "a" * 64
        fh = live.post("/scan", json={"target": digest, "target_type": "file_hash"}).json()["result"]
    ip_sources = {o["source"] for o in ip["provider_results"]}
    assert {"abuseipdb", "greynoise", "urlhaus", "threatfox", "otx"} <= ip_sources and "tranco" not in ip_sources
    assert outcome(ip, "abuseipdb")["status"] == "not_found"
    hash_sources = {o["source"] for o in fh["provider_results"]} & set(SOURCES)
    assert hash_sources == {"threatfox", "otx"}


# ── mock mode ───────────────────────────────────────────────────────────────
def test_mock_mode_reputation_is_synthetic_labelled_and_offline(monkeypatch) -> None:
    import app.core.validation as validation
    from app.core.config import get_settings
    from app.core.hub import hub
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "true")
    get_settings.cache_clear()
    hub.reset()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    with respx.mock(assert_all_called=False) as router:
        r = TestClient(app).post("/scan", json={"target": "evil-login.example.com", "target_type": "domain"}).json()["result"]
        assert not router.calls, "mock mode makes no network call at all"
    rep_outcomes = [o for o in r["provider_results"] if o["source"] in SOURCES]
    assert len(rep_outcomes) == len(SOURCES) and all(o["mock"] for o in rep_outcomes)
    assert {"openphish", "phishtank", "urlhaus", "safebrowsing"} <= set(r["reputation"]["listed_by"])
    assert r["mock_mode"] is True and r["reputation"]["feed_ages"] == {}
    get_settings.cache_clear()
    hub.reset()
