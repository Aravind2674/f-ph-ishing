"""A0-10 — privacy defaults (AUDIT_REPORT.md §H5, §H6).

Audit findings (Medium):
* the extension sent the *full active-tab URL* (paths, query strings, tokens) to the backend, which sent it
  to VirusTotal; the network layer sent every observed DNS name — including internal hostnames — to VirusTotal,
  with attacker-controlled bytes interpolated into the provider URL;
* per-device browsing history (every domain every device asked for) was kept forever, unencrypted;
* the mitmproxy addon forwarded cookies / Authorization headers to the backend.

Contract now:
* private, local, single-label, reverse-DNS and malformed names are NEVER sent to a third party;
* a URL scan sends VirusTotal only scheme://host[:port]/path — no userinfo, query or fragment — unless the user
  opts in (``send_full_url``); the extension sends only the hostname by default;
* sensitive headers are redacted (in the mitm addon and again server-side);
* ``net_*`` data older than ``NETWORK_RETENTION_DAYS`` (default 30) is purged on a schedule, and
  ``DELETE /network/data`` erases everything on demand.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import respx

from app.core import privacy
from app.core.config import Settings, get_settings
from app.ingestion.shodan import ShodanClient
from app.ingestion.virustotal import VirusTotalClient
from app.models.schemas import ProviderStatus
from tests.conftest import mock_site

TOOLS = Path(__file__).resolve().parents[2] / "tools" / "mitm_addon.py"
AUTH = {"Authorization": "Bearer test-token-0123456789abcdef0123456789abcdef"}


# ── Which names may leave the machine ───────────────────────────────────────
@pytest.mark.parametrize("name", [
    "printer.local", "nas.lan", "router.internal", "mac.home.arpa", "host.localdomain", "x.localhost",
    "intranet", "wpad", "DESKTOP-ABC123",                         # single label
    "1.0.168.192.in-addr.arpa", "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.2.ip6.arpa",   # reverse DNS
    "_ipp._tcp.local", "wiki.corp", "server.home",
])
def test_private_and_local_names_are_never_sent_to_third_parties(name: str) -> None:
    assert privacy.provider_block_reason(name) in {"private_name", "single_label"}


@pytest.mark.parametrize("addr", ["10.0.0.5", "192.168.1.20", "127.0.0.1", "169.254.169.254", "100.64.0.9", "::1", "fd00::1"])
def test_private_ip_literals_are_never_sent(addr: str) -> None:
    assert privacy.provider_block_reason(addr) == "private_address"


@pytest.mark.parametrize("name", ["example.com", "Sub.Example.CO.UK.", "xn--bcher-kva.example", "8.8.8.8", "2606:4700:4700::1111", "some-site.example"])
def test_ordinary_public_names_and_addresses_are_allowed(name: str) -> None:
    assert privacy.provider_block_reason(name) is None


@pytest.mark.parametrize("name", [
    "evil.com/../../users/me", "a.com?x=1", "a.com#frag", "user@a.com", "a b.com", "a..com", "-a.com", "a-.com",
    "a.com:8080", "", ".", "a" * 64 + ".com", ("a" * 60 + ".") * 5 + "com", "a%2fb.com", "a\x00b.com", "a\nb.com",
])
def test_malformed_names_are_refused_before_they_reach_a_provider_url(name: str) -> None:
    assert privacy.provider_block_reason(name) == "invalid_name"


def test_unicode_names_are_checked_in_their_punycode_form() -> None:
    assert privacy.provider_block_reason("bücher.example") is None
    assert privacy.provider_block_reason("büro.local") == "private_name"


# ── URLs: strip what identifies the person, not the destination ─────────────
@pytest.mark.parametrize("raw,expected", [
    ("https://user:pw@Example.com:8443/path/a?token=abc#frag", "https://example.com:8443/path/a"),
    ("http://example.com/login?next=/account&sid=1234", "http://example.com/login"),
    ("https://example.com", "https://example.com"),
    ("example.com/reset?token=abc", "example.com/reset"),
])
def test_urls_are_stripped_of_userinfo_query_and_fragment(raw: str, expected: str) -> None:
    assert privacy.strip_url_for_third_parties(raw) == expected


# ── Provider clients enforce it (defence in depth) ──────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("target,reason", [
    ("printer.local", "private_name"), ("nas", "single_label"), ("10.1.2.3", "private_address"),
    ("1.0.168.192.in-addr.arpa", "private_name"), ("evil/../x.com", "invalid_name"),
])
async def test_virustotal_never_receives_private_or_malformed_names(target: str, reason: str) -> None:
    vt = VirusTotalClient(api_key="k", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        res = await vt.lookup_domain(target)
        assert len(router.calls) == 0
    await vt.close()
    assert res.status == ProviderStatus.SKIPPED and res.reason == reason


@pytest.mark.asyncio
async def test_virustotal_url_lookup_is_checked_by_host_too() -> None:
    vt = VirusTotalClient(api_key="k", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        res = await vt.lookup_url("http://intranet.corp/admin?x=1")
        assert len(router.calls) == 0
    await vt.close()
    assert res.status == ProviderStatus.SKIPPED


@pytest.mark.asyncio
async def test_internetdb_never_receives_private_addresses() -> None:
    sh = ShodanClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        res = await sh.lookup_ip("192.168.1.10")
        assert len(router.calls) == 0
    await sh.close()
    assert res.status == ProviderStatus.SKIPPED and res.reason == "private_address"


# ── Network layer: DNS names observed on the LAN ────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("qname", ["printer.local", "nas", "1.0.168.192.in-addr.arpa", "a/b?c=d.example.com"])
async def test_app_layer_scorer_never_sends_observed_private_or_malformed_names(
    monkeypatch: pytest.MonkeyPatch, qname: str
) -> None:
    from app.network.enrichment.app_layer import AppLayerScorer

    monkeypatch.setenv("USE_MOCK_DATA", "false"); monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    get_settings.cache_clear()
    try:
        with respx.mock(assert_all_called=False) as router:
            score = await AppLayerScorer().score(qname, "domain")
            assert len(router.calls) == 0
    finally:
        get_settings.cache_clear()
    assert score.available is False and "third-party" in (score.reason or "")


@pytest.mark.asyncio
async def test_a_private_dns_name_still_feeds_the_local_baseline_but_never_a_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.network.baseline_store import BaselineStore
    from app.network.correlation import CorrelationEngine
    from app.network.enrichment.app_layer import AppLayerScorer
    from app.network.enrichment.wigle import WigleClient
    from app.network.models import EventType, SensorEvent

    monkeypatch.setenv("USE_MOCK_DATA", "false"); monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    get_settings.cache_clear()
    try:
        store = BaselineStore(str(tmp_path / "n.db"), min_observations=3)
        await store.init()
        engine = CorrelationEngine(store, AppLayerScorer(), WigleClient("", ""))
        ev = SensorEvent(event_type=EventType.DNS_QUERY, timestamp=datetime.now(timezone.utc), sensor="dns",
                         mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.50", domain="printer.local")
        with respx.mock(assert_all_called=False) as router:
            await engine.correlate(ev)
            assert len(router.calls) == 0
        profile = await store.get_profile("aa:bb:cc:dd:ee:ff")
        assert profile is not None and profile.dns_observations == 1, "local learning is unaffected"
    finally:
        get_settings.cache_clear()


# ── /scan: URL details are opt-in ───────────────────────────────────────────
@pytest.fixture
def live_scan(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation
    from fastapi.testclient import TestClient
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1000")
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    yield TestClient(app)
    get_settings.cache_clear()


def _vt_requested_url(router_calls) -> str:
    call = next(c for c in router_calls if "virustotal.com/api/v3/urls/" in str(c.request.url))
    url_id = str(call.request.url).rsplit("/", 1)[1]
    return base64.urlsafe_b64decode(url_id + "=" * (-len(url_id) % 4)).decode()


SECRET_URL = "https://some-site.example/reset?token=SECRET123&sid=77#frag"


def test_a_url_scan_sends_virustotal_only_the_stripped_url_by_default(live_scan) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        mock_site(router, "some-site.example", text="<html></html>", path="/reset")
        live_scan.post("/scan", json={"target": SECRET_URL, "target_type": "url"})
        sent = _vt_requested_url(router.calls)
        fetched = [str(c.request.url) for c in router.calls if c.request.url.host == "93.184.216.34"]
    assert sent == "https://some-site.example/reset"
    assert "SECRET123" not in sent
    assert all("SECRET123" not in u and "token=" not in u for u in fetched), "the target itself must not get the token either"


def test_full_url_is_sent_only_when_the_user_opts_in(live_scan) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        mock_site(router, "some-site.example", text="<html></html>", path="/reset")
        live_scan.post("/scan", json={"target": SECRET_URL, "target_type": "url", "send_full_url": True})
        sent = _vt_requested_url(router.calls)
    assert "token=SECRET123" in sent


def test_send_full_url_defaults_to_false() -> None:
    from app.models.schemas import ScanRequest
    assert ScanRequest(target="https://a.example/x?y=1", target_type="url").send_full_url is False


def test_target_validation_refuses_private_and_local_names() -> None:
    import asyncio
    from app.core.validation import validate_domain_target

    for name in ("printer.local", "router.internal", "files.corp.lan", "mac.home.arpa"):
        ok, data, _ = asyncio.run(validate_domain_target(name))
        assert ok is False and data["stage"] in {"blocked", "format"}, (name, data)


# ── Header redaction ────────────────────────────────────────────────────────
def test_sensitive_headers_are_redacted_case_insensitively() -> None:
    out = privacy.redact_headers({
        "Cookie": "sid=1", "cookie2": "x", "Set-Cookie": "sid=1; HttpOnly", "AUTHORIZATION": "Bearer abc",
        "Proxy-Authorization": "Basic x", "X-Api-Key": "k", "x-auth-token": "t", "X-CSRF-Token": "c",
        "X-Amz-Security-Token": "a", "Content-Type": "application/json", "User-Agent": "UA",
    })
    for h in ("Cookie", "cookie2", "Set-Cookie", "AUTHORIZATION", "Proxy-Authorization", "X-Api-Key",
              "x-auth-token", "X-CSRF-Token", "X-Amz-Security-Token"):
        assert out[h] == privacy.REDACTED, h
    assert out["Content-Type"] == "application/json" and out["User-Agent"] == "UA"


def test_traffic_analyze_redacts_headers_before_processing(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.api.traffic as traffic_module
    from fastapi.testclient import TestClient
    from app.main import app

    seen = []
    real = traffic_module.analyze_request

    def spy(clf, req):
        seen.append(dict(req.headers))
        return real(clf, req)

    monkeypatch.setattr(traffic_module, "analyze_request", spy)
    body = {"requests": [{"method": "GET", "url": "https://a.test/?q=1",
                          "headers": {"Cookie": "sid=SECRET", "Authorization": "Bearer SECRET", "Content-Type": "text/html"}}]}
    assert TestClient(app).post("/traffic/analyze", json=body).status_code == 200
    assert seen and "SECRET" not in json.dumps(seen) and seen[0]["Content-Type"] == "text/html"


def _load_mitm_addon():
    spec = importlib.util.spec_from_file_location("mitm_addon_under_test", TOOLS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_mitm_addon_redacts_headers_before_sending_them_anywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    addon = _load_mitm_addon()
    captured = {}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"findings": []}'

    def fake_urlopen(req, timeout=0):
        captured["body"] = req.data
        return _Resp()

    monkeypatch.setattr(addon.urllib.request, "urlopen", fake_urlopen)
    addon._score("POST", "https://a.test/x?q=1",
                 {"Cookie": "sid=SECRET", "Authorization": "Bearer SECRET", "X-Api-Key": "SECRET", "Content-Type": "application/json"}, "a=1")
    sent = captured["body"].decode()
    assert "SECRET" not in sent and "application/json" in sent


# ── Retention ───────────────────────────────────────────────────────────────
def test_retention_defaults_to_30_days() -> None:
    assert Settings(_env_file=None).NETWORK_RETENTION_DAYS == 30


@pytest_asyncio.fixture
async def seeded_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from app.network.models import AlertEvidence, AlertType, NetworkAlert, Severity, SignalContribution
    from app.network.service import NetworkMonitorService

    db = tmp_path / "retention.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db.as_posix()}")
    get_settings.cache_clear()
    svc = NetworkMonitorService()
    await svc.init()
    monkeypatch.setattr("app.network.service._service", svc)   # the endpoint uses get_service()
    now = datetime.now(timezone.utc)

    async def device(mac: str, age_days: int) -> None:
        await svc.store.observe_device(mac, "192.168.1.9")
        await svc.store.record_dns(mac, f"site-{mac[-2:]}.example", "192.168.1.9")
        stamp = (now - timedelta(days=age_days)).isoformat()
        con = sqlite3.connect(db)
        con.execute("UPDATE net_devices SET last_seen=?, first_seen=? WHERE mac=?", (stamp, stamp, mac))
        con.execute("UPDATE net_device_domains SET last_seen=?, first_seen=? WHERE mac=?", (stamp, stamp, mac))
        con.commit(); con.close()

    async def alert(age_days: int) -> None:
        a = NetworkAlert(alert_id=f"a{age_days}", timestamp=now - timedelta(days=age_days), alert_type=AlertType.NEW_DEVICE,
                         severity=Severity.LOW, fused_score=30.0, title="t", trigger_type="x",
                         evidence=AlertEvidence(signals=[SignalContribution(name="n", label="l", points=30.0, detail="d")]))
        await svc._store_alert(a)

    await device("aa:aa:aa:aa:aa:01", age_days=45)     # stale
    await device("aa:aa:aa:aa:aa:02", age_days=2)      # recent
    await alert(45); await alert(1)
    yield svc, db
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_purge_removes_only_data_older_than_the_retention_window(seeded_service) -> None:
    svc, db = seeded_service
    counts = await svc.purge(30)
    assert counts["devices"] == 1 and counts["domains"] == 1 and counts["alerts"] == 1
    con = sqlite3.connect(db)
    assert [r[0] for r in con.execute("select mac from net_devices")] == ["aa:aa:aa:aa:aa:02"]
    assert [r[0] for r in con.execute("select alert_id from net_alerts")] == ["a1"]
    con.close()
    assert [a.alert_id for a in svc.get_alerts()] == ["a1"], "the in-memory feed is purged too"


@pytest.mark.asyncio
async def test_a_retention_of_zero_keeps_everything(seeded_service) -> None:
    svc, _ = seeded_service
    assert await svc.purge(0) == {"devices": 0, "domains": 0, "ports": 0, "alerts": 0}
    assert len(await svc.store.list_devices()) == 2


@pytest.mark.asyncio
async def test_delete_network_data_endpoint_erases_everything(seeded_service) -> None:
    svc, db = seeded_service
    from app.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as c:
        # authentication and the JSON-only rule apply to DELETE too
        assert (await c.request("DELETE", "/network/data", headers={"Authorization": ""}, json={})).status_code == 401
        assert (await c.request("DELETE", "/network/data", content=b"", headers={"Content-Type": "text/plain"})).status_code == 415
        r = await c.request("DELETE", "/network/data", json={})
    assert r.status_code == 200 and r.json()["devices"] == 2 and r.json()["alerts"] == 2
    con = sqlite3.connect(db)
    assert con.execute("select count(*) from net_devices").fetchone()[0] == 0
    assert con.execute("select count(*) from net_device_domains").fetchone()[0] == 0
    assert con.execute("select count(*) from net_alerts").fetchone()[0] == 0
    con.close()
    assert svc.get_alerts() == []
