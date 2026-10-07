"""A1-1 — VirusTotal: one shared client, a real quota limiter, a persistent TTL cache, the right endpoint per kind.

Audit P1-1: a new ``VirusTotalClient`` was built per scan (and per DNS event), so its in-memory cache never
hit, nothing enforced the free tier's 4 requests/minute and 500/day, IPs were sent to ``/domains/``, and a
429's ``Retry-After`` was ignored.  Acceptance: *in a 50-scan load test the limit is never exceeded and the
cache hits; IP targets use* ``/ip_addresses``.

No live call is made anywhere in this file: VirusTotal is mocked with respx; the limiter is driven by a fake
clock wherever time matters.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest
import respx

from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.ingestion.virustotal import VirusTotalClient
from app.models.schemas import ProviderResult, ProviderStatus, VirusTotalResult
from tests.conftest import mock_site

VT_ANY = r"https://www\.virustotal\.com/api/v3/.*"
VT_OK_JSON = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 2, "harmless": 60, "suspicious": 1, "undetected": 7},
    "reputation": 5, "last_analysis_date": 1_700_000_000, "categories": {"Sophos": "business"}}}}


class FakeClock:
    """Monotonic clock + sleep that advances it, so quota windows can be crossed instantly."""

    def __init__(self) -> None:
        self.t = 10_000.0

    def __call__(self) -> float:
        return self.t

    async def sleep(self, seconds: float) -> None:
        self.t += max(0.0, seconds)


def _ok(source: str = "virustotal") -> ProviderResult[VirusTotalResult]:
    return ProviderResult[VirusTotalResult](
        source=source, status=ProviderStatus.OK, http_status=200,
        data=VirusTotalResult(malicious_count=1, harmless_count=60, suspicious_count=0, undetected_count=9,
                              total_engines=70, reputation_score=3))


# ── QuotaLimiter ────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_limiter_grants_the_per_minute_budget_then_asks_callers_to_wait() -> None:
    clk = FakeClock()
    lim = QuotaLimiter(per_minute=4, per_day=500, clock=clk, sleep=clk.sleep)
    assert [await lim.acquire(max_wait=0) for _ in range(4)] == [None] * 4
    retry = await lim.acquire(max_wait=0)
    assert retry is not None and 59.0 <= retry <= 60.0, "the 5th call must wait for the oldest slot to age out"
    # A refusal consumes nothing: once the window has passed the very next call is granted.
    clk.t += 60
    assert await lim.acquire(max_wait=0) is None


@pytest.mark.asyncio
async def test_limiter_never_lets_more_than_n_calls_into_any_sixty_second_window() -> None:
    clk = FakeClock()
    lim = QuotaLimiter(per_minute=4, per_day=500, clock=clk, sleep=clk.sleep)
    granted: list[float] = []
    for _ in range(23):
        assert await lim.acquire(max_wait=600) is None      # queued: it sleeps (fake) until a slot is free
        granted.append(clk.t)
    assert all(granted[i + 4] - granted[i] >= 60.0 for i in range(len(granted) - 4)), granted


@pytest.mark.asyncio
async def test_limiter_daily_budget_is_enforced_separately() -> None:
    clk = FakeClock()
    lim = QuotaLimiter(per_minute=0, per_day=3, clock=clk, sleep=clk.sleep)      # per-minute window disabled
    assert [await lim.acquire(max_wait=0) for _ in range(3)] == [None] * 3
    retry = await lim.acquire(max_wait=30)                                       # far beyond the queue limit
    assert retry is not None and 86_000 <= retry <= 86_400


@pytest.mark.asyncio
async def test_limiter_penalize_honours_retry_after_and_never_shortens_a_block() -> None:
    clk = FakeClock()
    lim = QuotaLimiter(per_minute=4, per_day=500, clock=clk, sleep=clk.sleep)
    lim.penalize(120)
    retry = await lim.acquire(max_wait=5)
    assert retry is not None and 119.0 <= retry <= 120.0
    lim.penalize(10)                                         # a shorter hint must not cut the block short
    retry2 = await lim.acquire(max_wait=5)
    assert retry2 is not None and retry2 > 100
    clk.t += 120
    assert await lim.acquire(max_wait=0) is None


@pytest.mark.asyncio
async def test_limiter_with_zero_limits_is_disabled() -> None:
    lim = QuotaLimiter(per_minute=0, per_day=0)
    assert [await lim.acquire(max_wait=0) for _ in range(1000)] == [None] * 1000


@pytest.mark.asyncio
async def test_limiter_is_exact_under_concurrency() -> None:
    lim = QuotaLimiter(per_minute=4, per_day=500)
    results = await asyncio.gather(*(lim.acquire(max_wait=0) for _ in range(50)))
    assert sum(r is None for r in results) == 4, "exactly the budget is granted, however many callers race"


# ── ProviderCache ───────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_cache_roundtrip_keeps_the_original_timestamp_and_marks_cached() -> None:
    cache = ProviderCache()
    original = _ok()
    await cache.put("virustotal", "domain:example.com", original, ttl_ok=60, ttl_not_found=10)
    hit = await cache.get("virustotal", "domain:example.com", VirusTotalResult)
    assert hit is not None and hit.cached is True and hit.fetched_at == original.fetched_at
    assert hit.data == original.data and hit.status == ProviderStatus.OK
    assert await cache.get("virustotal", "domain:other.example", VirusTotalResult) is None
    assert await cache.get("shodan", "domain:example.com", VirusTotalResult) is None, "keys are per source"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [ProviderStatus.ERROR, ProviderStatus.SKIPPED, ProviderStatus.NOT_CONFIGURED])
async def test_cache_never_remembers_failures_or_gaps(status) -> None:
    cache = ProviderCache()
    await cache.put("virustotal", "k", ProviderResult(source="virustotal", status=status, reason="x"),
                    ttl_ok=60, ttl_not_found=10)
    assert await cache.get("virustotal", "k", VirusTotalResult) is None and await cache.count() == 0


@pytest.mark.asyncio
async def test_cache_not_found_expires_sooner_than_an_answer() -> None:
    now = [1_000.0]
    cache = ProviderCache(clock=lambda: now[0])
    await cache.put("virustotal", "ok", _ok(), ttl_ok=100, ttl_not_found=10)
    await cache.put("virustotal", "nf", ProviderResult(source="virustotal", status=ProviderStatus.NOT_FOUND,
                                                       http_status=404), ttl_ok=100, ttl_not_found=10)
    now[0] += 11
    assert await cache.get("virustotal", "nf", VirusTotalResult) is None
    assert await cache.get("virustotal", "ok", VirusTotalResult) is not None
    now[0] += 90
    assert await cache.get("virustotal", "ok", VirusTotalResult) is None
    assert await cache.purge_expired() >= 0 and await cache.count() == 0


@pytest.mark.asyncio
async def test_sqlite_cache_survives_a_restart(tmp_path) -> None:
    db = tmp_path / "cache.db"
    first = ProviderCache(path_provider=lambda: db)
    original = _ok()
    await first.put("virustotal", "domain:example.com", original, ttl_ok=3600, ttl_not_found=60)
    second = ProviderCache(path_provider=lambda: db)             # a "new process"
    hit = await second.get("virustotal", "domain:example.com", VirusTotalResult)
    assert hit is not None and hit.cached and hit.data == original.data and hit.fetched_at == original.fetched_at


@pytest.mark.asyncio
async def test_sqlite_cache_purge_and_clear(tmp_path) -> None:
    now = [1_000.0]
    cache = ProviderCache(path_provider=lambda: tmp_path / "c.db", clock=lambda: now[0])
    await cache.put("virustotal", "a", _ok(), ttl_ok=10, ttl_not_found=5)
    await cache.put("virustotal", "b", _ok(), ttl_ok=1000, ttl_not_found=5)
    now[0] += 20
    assert await cache.purge_expired() == 1 and await cache.count() == 1
    assert await cache.clear() == 1 and await cache.count() == 0


def test_migration_v3_adds_provider_cache_in_place(tmp_path) -> None:
    from app.core.db import LATEST_VERSION, init_db
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE scans (scan_id TEXT PRIMARY KEY, target TEXT NOT NULL, target_type TEXT NOT NULL, "
        "timestamp TEXT NOT NULL, result_json TEXT NOT NULL, baseline_score REAL, ml_score REAL, ml_label TEXT, "
        "created_at TEXT DEFAULT CURRENT_TIMESTAMP);"
        "INSERT INTO scans (scan_id, target, target_type, timestamp, result_json) VALUES ('s1','a.example','domain','t','{}');"
        "PRAGMA user_version = 1;")
    con.commit(); con.close()
    asyncio.run(init_db(db))
    con = sqlite3.connect(db)
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "provider_cache" in tables and LATEST_VERSION >= 3
    assert con.execute("PRAGMA user_version").fetchone()[0] == LATEST_VERSION
    assert con.execute("SELECT count(*) FROM scans").fetchone()[0] == 1, "existing rows are kept"
    con.close()


# ── Right endpoint per kind ─────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("ip", ["8.8.8.8", "2606:4700:4700::1111"])
async def test_ip_lookups_use_the_ip_addresses_endpoint(ip) -> None:
    vt = VirusTotalClient(api_key="k", use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_ANY).respond(200, json=VT_OK_JSON)
        res = await vt.lookup_ip(ip)
        urls = [str(c.request.url) for c in router.calls]
    await vt.close()
    assert res.ok and res.data.total_engines == 70
    assert urls == [f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"]


@pytest.mark.asyncio
async def test_private_ips_are_never_sent_to_virustotal_and_cost_no_quota() -> None:
    lim = QuotaLimiter(per_minute=1, per_day=500)
    vt = VirusTotalClient(api_key="k", use_mock=False, limiter=lim)
    with respx.mock(assert_all_called=False) as router:
        res = await vt.lookup_ip("192.168.1.10")
        assert len(router.calls) == 0
    await vt.close()
    assert res.status == ProviderStatus.SKIPPED
    assert await lim.acquire(max_wait=0) is None, "the skipped lookup must not have used the only slot"


@pytest.mark.asyncio
async def test_url_lookups_cache_under_a_hash_not_the_raw_url(tmp_path) -> None:
    db = tmp_path / "u.db"
    vt = VirusTotalClient(api_key="k", use_mock=False, cache=ProviderCache(path_provider=lambda: db))
    secret_url = "https://shop.example/reset?token=SUPERSECRET123"
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_ANY).respond(200, json=VT_OK_JSON)
        await vt.lookup_url(secret_url)
    await vt.close()
    con = sqlite3.connect(db)
    dump = json.dumps(con.execute("SELECT * FROM provider_cache").fetchall())
    con.close()
    assert "SUPERSECRET123" not in dump and "shop.example/reset" not in dump


# ── Retry-After ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_429_with_retry_after_blocks_further_calls_until_it_elapses() -> None:
    clk = FakeClock()
    lim = QuotaLimiter(per_minute=4, per_day=500, clock=clk, sleep=clk.sleep)
    vt = VirusTotalClient(api_key="k", use_mock=False, limiter=lim, max_queue_seconds=15)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=VT_ANY).respond(429, headers={"Retry-After": "120"})
        first = await vt.lookup_domain("a.example.com")
        second = await vt.lookup_domain("b.example.com")      # must not even try
        assert route.call_count == 1
        clk.t += 121
        route.respond(200, json=VT_OK_JSON)
        third = await vt.lookup_domain("c.example.com")
        assert route.call_count == 2
    await vt.close()
    assert first.status == ProviderStatus.ERROR and first.reason == "rate_limited" and first.retry_after == 120
    assert second.status == ProviderStatus.ERROR and second.reason == "rate_limited"
    assert second.retry_after is not None and 115 <= second.retry_after <= 120 and second.http_status is None
    assert third.ok


@pytest.mark.asyncio
async def test_retry_after_accepts_an_http_date_and_ignores_garbage() -> None:
    clk = FakeClock()
    for header, lo, hi in [
        (format_datetime(datetime.now(timezone.utc) + timedelta(seconds=90), usegmt=True), 80, 91),
        ("soon", 60, 60),                       # unparseable -> a safe default, not a hammering retry
        ("-5", 60, 60),
    ]:
        lim = QuotaLimiter(per_minute=4, per_day=500, clock=clk, sleep=clk.sleep)
        vt = VirusTotalClient(api_key="k", use_mock=False, limiter=lim)
        with respx.mock(assert_all_called=False) as router:
            router.get(url__regex=VT_ANY).respond(429, headers={"Retry-After": header})
            res = await vt.lookup_domain("a.example.com")
        await vt.close()
        assert res.reason == "rate_limited" and lo <= res.retry_after <= hi, (header, res.retry_after)


# ── Concurrency / load ──────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_fifty_concurrent_lookups_never_exceed_the_per_minute_budget() -> None:
    lim = QuotaLimiter(per_minute=4, per_day=500)
    vt = VirusTotalClient(api_key="k", use_mock=False, limiter=lim, max_queue_seconds=0)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=VT_ANY).respond(200, json=VT_OK_JSON)
        results = await asyncio.gather(*(vt.lookup_domain(f"d{i}.example.com") for i in range(50)))
        assert route.call_count == 4
    await vt.close()
    assert sum(r.ok for r in results) == 4
    refused = [r for r in results if not r.ok]
    assert len(refused) == 46 and all(r.reason == "rate_limited" and r.retry_after > 0 for r in refused)


# ── Scan level ──────────────────────────────────────────────────────────────
@pytest.fixture
def live_scan(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation
    from fastapi.testclient import TestClient
    from app.core.config import get_settings
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1000")
    monkeypatch.setenv("VIRUSTOTAL_REQUESTS_PER_MINUTE", "4")
    monkeypatch.setenv("VIRUSTOTAL_REQUESTS_PER_DAY", "500")
    monkeypatch.setenv("VIRUSTOTAL_MAX_QUEUE_SECONDS", "0")
    get_settings.cache_clear()

    async def _ok_validation(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok_validation)
    yield TestClient(app)
    get_settings.cache_clear()


def _vt_calls(router) -> list[str]:
    return [str(c.request.url) for c in router.calls if "virustotal.com" in str(c.request.url)]


def _vt_outcome(resp_json: dict) -> dict:
    return next(o for o in resp_json["result"]["provider_results"] if o["source"] == "virustotal")


def test_fifty_scans_never_exceed_the_quota_and_repeats_hit_the_cache(live_scan) -> None:
    hosts = [f"d{i}.example.com" for i in range(5)]
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_ANY).respond(200, json=VT_OK_JSON)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        for h in hosts:
            mock_site(router, h, text="<html></html>")
        outcomes = [
            _vt_outcome(live_scan.post("/scan", json={"target": hosts[i % 5], "target_type": "domain"}).json())
            for i in range(50)
        ]
        calls = _vt_calls(router)
    assert len(calls) == 4, "4/min budget: only four distinct targets can be looked up"
    assert len(set(calls)) == 4
    ok = [o for o in outcomes if o["status"] == "ok"]
    cached = [o for o in ok if o["cached"]]
    refused = [o for o in outcomes if o["status"] == "error"]
    assert len(ok) == 40 and len(cached) == 36, "4 live lookups + 36 cache hits"
    assert len(refused) == 10 and all(o["reason"] == "rate_limited" and o["retry_after"] > 0 for o in refused)


def test_an_ip_scan_calls_the_ip_addresses_endpoint(live_scan) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_ANY).respond(200, json=VT_OK_JSON)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        resp = live_scan.post("/scan", json={"target": "8.8.8.8", "target_type": "ip"})
        calls = _vt_calls(router)
    assert resp.status_code == 200
    assert calls == ["https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"]


def test_one_client_serves_every_scan_and_scans_do_not_close_it(live_scan, monkeypatch) -> None:
    from app.core.hub import hub
    closes = {"n": 0}
    real_close = VirusTotalClient.close

    async def counting_close(self):
        closes["n"] += 1
        return await real_close(self)

    monkeypatch.setattr(VirusTotalClient, "close", counting_close)
    seen = []
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_ANY).respond(200, json=VT_OK_JSON)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        mock_site(router, "one.example.com", text="<html></html>")
        for _ in range(3):
            live_scan.post("/scan", json={"target": "one.example.com", "target_type": "domain"})
            seen.append(hub.virustotal())
    assert seen[0] is seen[1] is seen[2]
    assert closes["n"] == 0


@pytest.mark.asyncio
async def test_the_network_layer_shares_the_scans_quota_and_uses_the_ip_endpoint(monkeypatch) -> None:
    """A 429 seen by a scan must stop the network layer from calling VirusTotal too (one shared bucket)."""
    from app.core.config import get_settings
    from app.core.hub import hub
    from app.network.enrichment.app_layer import AppLayerScorer
    from tests.netfakes import url_model

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    monkeypatch.setenv("NETWORK_VT_PER_MINUTE", "10")
    get_settings.cache_clear()
    try:
        with url_model(flagged=True), respx.mock(assert_all_called=False) as router:
            route = router.get(url__regex=VT_ANY).respond(200, json=VT_OK_JSON)
            ip_score = await AppLayerScorer().score("8.8.8.8", "ip")
            assert ip_score.available is False and "not looked up passively" in ip_score.reason and route.call_count == 0
            first = await AppLayerScorer().score("flagged-one.example.org", "domain")     # the model flagged it: VirusTotal is asked
            assert first.source == "virustotal" and route.call_count == 1
            hub.virustotal()._limiter.penalize(300)             # e.g. a scan just got a 429 + Retry-After
            before = route.call_count
            blocked = await AppLayerScorer().score("another.example.org", "domain")
            assert route.call_count == before, "the network layer must respect the shared Retry-After block"
        assert blocked.available is False and "rate_limited" in (blocked.reason or "")
    finally:
        get_settings.cache_clear()


def test_erasing_network_data_also_clears_cached_lookups(live_scan) -> None:
    """The cache holds hostnames (incl. ones the network layer looked up) — the user's 'erase' must cover it."""
    import asyncio as _asyncio
    from app.core.hub import hub
    _asyncio.run(hub.cache.put("virustotal", "domain:seen-on-lan.example", _ok(), ttl_ok=3600, ttl_not_found=60))
    assert _asyncio.run(hub.cache.count()) >= 1
    with live_scan as c:                      # run the lifespan (initialises the network service's tables)
        r = c.request("DELETE", "/network/data", json={})
    assert r.status_code == 200 and r.json()["cached_lookups"] >= 1
    assert _asyncio.run(hub.cache.count()) == 0
