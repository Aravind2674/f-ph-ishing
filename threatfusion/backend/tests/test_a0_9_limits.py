"""A0-9 — request limits and event-loop hygiene (AUDIT_REPORT.md §H4).

Audit finding (Medium): one client could stall the whole process (including the SSE stream) or burn all
provider quota: no rate limit on ``/scan`` (``RATE_LIMIT_REQUESTS_PER_MINUTE`` existed but nothing used it),
torch inference and DNS ran *synchronously inside* ``async def`` handlers, ``/traffic/analyze`` accepted
unbounded ``requests`` / HAR, and a slow provider could hold a scan open for minutes.

Contract now:
* request bodies are capped (413); ``/traffic/analyze`` additionally caps the number of requests / HAR entries (413);
* ``/scan`` is rate-limited per client (429 + Retry-After) and the refusal costs no provider quota;
* model inference runs in worker threads — the event loop (and therefore the SSE heartbeat) keeps ticking;
* every scan has an overall deadline and every provider call a cap; a slow provider becomes ``error/timeout``.
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings

AUTH = {"Authorization": "Bearer test-token-0123456789abcdef0123456789abcdef"}


@pytest.fixture
def limits(monkeypatch: pytest.MonkeyPatch):
    """Configure limits like an operator would (env + settings cache reset) and reset limiters."""
    def configure(**kw) -> None:
        for k, v in kw.items():
            monkeypatch.setenv(k, str(v))
        get_settings.cache_clear()
        from app.core.ratelimit import SCAN_LIMITER
        SCAN_LIMITER.clear()

    yield configure
    get_settings.cache_clear()
    from app.core.ratelimit import SCAN_LIMITER
    SCAN_LIMITER.clear()


@pytest.fixture
def stub_validation(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)


# ── Settings ────────────────────────────────────────────────────────────────
def test_rate_limit_setting_is_no_longer_dead_and_has_sane_defaults() -> None:
    s = Settings(_env_file=None)
    assert s.RATE_LIMIT_REQUESTS_PER_MINUTE >= 10          # per-client cap on /scan (not the VT free-tier 4)
    assert s.MAX_REQUEST_BODY_BYTES >= 1_000_000 and s.MAX_TRAFFIC_REQUESTS >= 100
    assert 10 <= s.SCAN_DEADLINE_SECONDS <= 120 and s.PROVIDER_TIMEOUT_SECONDS < s.SCAN_DEADLINE_SECONDS


# ── Body size and request-count caps → 413 ──────────────────────────────────
def _har(n_entries: int, pad: int = 0) -> dict:
    return {"log": {"entries": [
        {"request": {"method": "GET", "url": f"https://shop.test/item?id={i}", "headers": [], "x": "y" * pad}}
        for i in range(n_entries)]}}


def test_an_oversized_body_is_rejected_with_413_by_content_length(limits) -> None:
    limits(MAX_REQUEST_BODY_BYTES=5_000)
    from app.main import app
    r = TestClient(app).post("/traffic/analyze", json={"har": _har(5, pad=3_000)})
    assert r.status_code == 413 and "too large" in r.json()["detail"].lower()


def test_an_oversized_chunked_body_is_rejected_too(limits) -> None:
    """No Content-Length (chunked upload): the cap must still hold while streaming."""
    limits(MAX_REQUEST_BODY_BYTES=5_000)
    from app.main import app

    def gen():
        for _ in range(50):
            yield b"x" * 1000

    r = TestClient(app).post("/traffic/analyze", content=gen(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_a_normal_body_still_passes(limits) -> None:
    limits(MAX_REQUEST_BODY_BYTES=1_000_000)
    from app.main import app
    r = TestClient(app).post("/traffic/analyze", json={"requests": []})
    assert r.status_code == 200


def test_too_many_requests_in_a_batch_is_413(limits) -> None:
    limits(MAX_TRAFFIC_REQUESTS=3)
    from app.main import app
    batch = [{"method": "GET", "url": f"https://a.test/?q={i}", "headers": {}} for i in range(4)]
    r = TestClient(app).post("/traffic/analyze", json={"requests": batch})
    assert r.status_code == 413 and "3" in r.json()["detail"]
    ok = TestClient(app).post("/traffic/analyze", json={"requests": batch[:3]})
    assert ok.status_code == 200


def test_too_many_har_entries_is_413(limits) -> None:
    limits(MAX_TRAFFIC_REQUESTS=3)
    from app.main import app
    assert TestClient(app).post("/traffic/analyze", json={"har": _har(4)}).status_code == 413
    assert TestClient(app).post("/traffic/analyze", json={"har": _har(3)}).status_code == 200


def test_requests_plus_har_together_count_against_the_cap(limits) -> None:
    limits(MAX_TRAFFIC_REQUESTS=3)
    from app.main import app
    batch = [{"method": "GET", "url": "https://a.test/?q=1", "headers": {}}] * 2
    assert TestClient(app).post("/traffic/analyze", json={"requests": batch, "har": _har(2)}).status_code == 413


# ── /scan rate limit → 429 ──────────────────────────────────────────────────
def test_scan_is_rate_limited_per_client_and_a_refusal_costs_no_provider_quota(
    limits, stub_validation, monkeypatch
) -> None:
    limits(RATE_LIMIT_REQUESTS_PER_MINUTE=2, USE_MOCK_DATA="true")
    from app.ingestion.virustotal import VirusTotalClient
    from app.main import app

    calls = {"n": 0}
    real = VirusTotalClient.lookup_domain

    async def counting(self, domain):
        calls["n"] += 1
        return await real(self, domain)

    monkeypatch.setattr(VirusTotalClient, "lookup_domain", counting)
    c = TestClient(app)
    codes = [c.post("/scan", json={"target": f"s{i}.example", "target_type": "domain"}).status_code for i in range(3)]
    assert codes == [200, 200, 429]
    assert calls["n"] == 2, "the rejected request must not reach any provider"
    r = c.post("/scan", json={"target": "s9.example", "target_type": "domain"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert "rate" in r.json()["detail"].lower()


def test_reading_scan_history_is_not_rate_limited(limits) -> None:
    limits(RATE_LIMIT_REQUESTS_PER_MINUTE=1)
    from app.main import app
    c = TestClient(app)
    assert [c.get("/scan/history").status_code for _ in range(5)] == [200] * 5


# ── Event loop stays responsive ─────────────────────────────────────────────
async def _max_loop_lag(coro, interval: float = 0.02) -> tuple[float, object]:
    """Run ``coro`` while a ticker measures how late the event loop wakes it up."""
    lags: list[float] = []
    stop = asyncio.Event()

    async def ticker():
        while not stop.is_set():
            t0 = time.perf_counter()
            await asyncio.sleep(interval)
            lags.append(time.perf_counter() - t0 - interval)

    task = asyncio.create_task(ticker())
    try:
        result = await coro
    finally:
        stop.set()
        await task
    return max(lags), result


@pytest.mark.asyncio
async def test_a_blocking_model_call_does_not_stall_the_event_loop_during_scan(limits, stub_validation, monkeypatch) -> None:
    limits(USE_MOCK_DATA="true", RATE_LIMIT_REQUESTS_PER_MINUTE=100)
    import app.api.scan as scan_module
    from app.main import app

    def blocking_predict(*a, **k):
        time.sleep(1.0)          # a CPU-bound torch forward pass, simulated
        return 0.5

    monkeypatch.setattr(scan_module._neural_model, "predict_proba", blocking_predict)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as client:
        t0 = time.perf_counter()
        lag, resp = await _max_loop_lag(client.post("/scan", json={"target": "lag.example", "target_type": "domain"}))
        took = time.perf_counter() - t0
    assert resp.status_code == 200 and took >= 1.0
    assert lag < 0.4, f"the event loop was blocked for {lag:.2f}s while a model ran (SSE heartbeats would stall)"


@pytest.mark.asyncio
async def test_a_blocking_classifier_does_not_stall_the_event_loop_in_analyze(limits, monkeypatch) -> None:
    limits()
    import app.api.analyze as analyze_module
    from app.main import app

    def blocking_classify(text):
        time.sleep(0.8)
        return {"label": "benign", "class_id": 0, "confidence": 0.99, "probs": {"benign": 0.99}}

    monkeypatch.setattr(analyze_module._clf, "classify", blocking_classify)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as client:
        lag, resp = await _max_loop_lag(client.post("/analyze", json={"text": "hello"}))
    assert resp.status_code == 200 and lag < 0.4, lag


@pytest.mark.asyncio
async def test_a_blocking_classifier_does_not_stall_the_event_loop_in_traffic_analyze(limits, monkeypatch) -> None:
    limits()
    import app.api.traffic as traffic_module
    from app.main import app

    def blocking_classify(text):
        time.sleep(0.8)
        return {"label": "benign", "class_id": 0, "confidence": 0.99, "probs": {"benign": 0.99}}

    monkeypatch.setattr(traffic_module._clf, "classify", blocking_classify)
    body = {"requests": [{"method": "GET", "url": "https://a.test/?q=1", "headers": {}}]}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as client:
        lag, resp = await _max_loop_lag(client.post("/traffic/analyze", json=body))
    assert resp.status_code == 200 and lag < 0.4, lag


# ── Deadlines: slow providers become error/timeout ──────────────────────────
@pytest.mark.asyncio
async def test_a_slow_provider_times_out_instead_of_holding_the_scan_open(limits, stub_validation, monkeypatch) -> None:
    limits(USE_MOCK_DATA="true", RATE_LIMIT_REQUESTS_PER_MINUTE=100, PROVIDER_TIMEOUT_SECONDS=1, SCAN_DEADLINE_SECONDS=10)
    from app.ingestion.virustotal import VirusTotalClient
    from app.main import app

    async def hang(self, domain):
        await asyncio.sleep(30)

    monkeypatch.setattr(VirusTotalClient, "lookup_domain", hang)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as client:
        t0 = time.perf_counter()
        resp = await client.post("/scan", json={"target": "slow.example", "target_type": "domain"})
        took = time.perf_counter() - t0
    res = resp.json()["result"]
    assert took < 5, f"scan took {took:.1f}s although the provider cap is 1s"
    assert "VirusTotal" in res["data_sources_failed"]
    vt = next(p for p in res["provider_results"] if p["source"] == "virustotal")
    assert vt["status"] == "error" and vt["reason"] == "timeout"
    assert res["verdict_status"] == "unknown" and res["ml_score"] is None
    assert "Shodan" in res["data_sources_succeeded"], "other providers still ran"


@pytest.mark.asyncio
async def test_the_overall_scan_deadline_bounds_total_time(limits, stub_validation, monkeypatch) -> None:
    limits(USE_MOCK_DATA="true", RATE_LIMIT_REQUESTS_PER_MINUTE=100, PROVIDER_TIMEOUT_SECONDS=30, SCAN_DEADLINE_SECONDS=2)
    from app.ingestion.shodan import ShodanClient
    from app.ingestion.virustotal import VirusTotalClient
    from app.main import app

    async def hang(self, *a, **k):
        await asyncio.sleep(30)

    monkeypatch.setattr(VirusTotalClient, "lookup_domain", hang)
    monkeypatch.setattr(ShodanClient, "lookup_ip", hang)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as client:
        t0 = time.perf_counter()
        resp = await client.post("/scan", json={"target": "slow2.example", "target_type": "domain"})
        took = time.perf_counter() - t0
    assert took < 5, f"deadline of 2s was not enforced (took {took:.1f}s)"
    res = resp.json()["result"]
    assert {"VirusTotal", "Shodan"} <= set(res["data_sources_failed"])
    assert all(p["reason"] == "timeout" for p in res["provider_results"] if p["status"] == "error")
