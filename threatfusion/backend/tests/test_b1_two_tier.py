"""B1 — the fast / slow two-tier pipeline.

* **Fast tier** (``core/fast.py``, ``POST /scan/fast``): answers from *local* data only — the local blocklist feeds, the brand
  check, the URL-text models and a recent stored scan.  Nothing about the target is sent anywhere.  The verdict is a transparent
  rule (``block`` / ``warn`` / ``info`` / ``none``) and "nothing found" is explicitly not a clean bill of health.
* **Slow tier** (``POST /scan`` with ``mode: "async"``): the fast verdict and a ``scan_id`` come back at once; the full pipeline
  runs as a background job (in-process queue — ``core/jobs.py``) whose progress streams over SSE; ``GET /scan/{id}`` reports
  ``running`` and then the stored result.  The default ``mode: "sync"`` is unchanged.
* Acceptance: p95 under 300 ms for listed or cached targets.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
import respx

from app.core.jobs import JobRegistry, QueueFull
from app.ingestion.blocklists import _index

AUTH = {"Authorization": "Bearer test-token-0123456789abcdef0123456789abcdef"}


# ── the job registry ────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_job_runs_and_reports_done_or_error() -> None:
    reg = JobRegistry(max_concurrent=2)

    async def ok():
        return None

    async def bad():
        return "provider exploded"

    async def crash():
        raise RuntimeError("boom")

    for sid, fn in (("a", ok), ("b", bad), ("c", crash)):
        reg.submit(sid, fn)
    await asyncio.gather(*(reg._jobs[s].task for s in "abc"), return_exceptions=True)
    assert reg.state("a") == "done" and reg.state("b") == "error" and reg.error("b") == "provider exploded"
    assert reg.state("c") == "error" and reg.error("c") == "RuntimeError", "a crashed job is an error, never a silent loss"
    assert reg.state("nope") is None and reg.counts()["done"] == 1


@pytest.mark.asyncio
async def test_concurrency_is_bounded_and_the_rest_wait_their_turn() -> None:
    reg = JobRegistry(max_concurrent=2)
    running = {"now": 0, "max": 0}
    gate = asyncio.Event()

    async def work():
        running["now"] += 1
        running["max"] = max(running["max"], running["now"])
        await gate.wait()
        running["now"] -= 1

    for i in range(6):
        reg.submit(f"j{i}", work)
    await asyncio.sleep(0.05)
    assert running["now"] == 2 and reg.counts()["queued"] == 4
    gate.set()
    await asyncio.gather(*(j.task for j in reg._jobs.values()))
    assert running["max"] == 2 and reg.counts()["done"] == 6


@pytest.mark.asyncio
async def test_the_pending_queue_is_bounded() -> None:
    reg = JobRegistry(max_concurrent=1, max_pending=2)
    gate = asyncio.Event()

    async def hold():
        await gate.wait()

    reg.submit("run", hold)
    await asyncio.sleep(0.01)
    reg.submit("q1", hold)
    reg.submit("q2", hold)
    with pytest.raises(QueueFull):
        reg.submit("q3", hold)
    with pytest.raises(ValueError):
        reg.submit("q1", hold)
    gate.set()
    await reg.shutdown()


@pytest.mark.asyncio
async def test_finished_jobs_are_forgotten_after_the_retention_window_and_shutdown_cancels_running_ones() -> None:
    clock = {"t": 0.0}
    reg = JobRegistry(retention=10.0, clock=lambda: clock["t"])

    async def quick():
        return None

    reg.submit("x", quick)
    await reg._jobs["x"].task
    assert reg.state("x") == "done"
    clock["t"] = 11.0
    assert reg.state("x") is None and not reg.has("x")

    async def forever():
        await asyncio.sleep(3600)

    reg.submit("y", forever)
    await asyncio.sleep(0.01)
    await reg.shutdown()
    assert reg.state("y") == "error" and reg.error("y") == "cancelled"


# ── the fast tier ───────────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def live(monkeypatch):
    """Live-mode settings, no providers configured: only local data can answer."""
    from app.core.config import get_settings
    from app.core.hub import hub

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1000")
    get_settings.cache_clear()
    hub.reset()
    await hub.feeds.replace("openphish", _index([("https://secure-paypa1.example.net/login/verify?id=1", {}), ("http://evil.example.com/a", {})]),
                            source_url="test://openphish")
    await hub.feeds.replace("phishtank", _index([("https://login-hdfcbank.example.org/netbanking", {"target": "HDFC Bank"})]), source_url="test://pt")
    await hub.feeds.replace("tranco", {"ranked-site.org": 321}, source_url="test://tranco")
    yield hub
    get_settings.cache_clear()
    hub.reset()


@pytest.mark.asyncio
async def test_an_exact_listed_url_is_blocked_from_local_data_with_no_network_call(live) -> None:
    from app.core.fast import fast_check

    with respx.mock(assert_all_called=False) as router:
        v = await fast_check("https://secure-paypa1.example.net/login/verify?id=1", send_full_url=True)
        assert not router.calls, "the fast tier is local: nothing is sent anywhere"
    assert v.level == "block" and v.status == "listed" and "openphish" in v.listed_by
    assert any("Listed by openphish" in r for r in v.reasons)
    assert v.tier == "fast" and v.latency_ms >= 0


@pytest.mark.asyncio
async def test_a_listed_host_with_another_page_is_a_warning_not_a_block(live) -> None:
    from app.core.fast import fast_check

    v = await fast_check("https://evil.example.com/never-listed")
    assert v.level == "warn" and v.status == "suspicious" and any("other pages listed" in r for r in v.reasons)


@pytest.mark.asyncio
async def test_a_lookalike_is_a_warning_with_the_real_domain(live) -> None:
    from app.core.fast import fast_check

    v = await fast_check("https://hdfcbank-netbanking-login.com/verify")
    assert v.level == "warn" and v.brand_check.status == "lookalike" and v.brand_check.match.brand == "HDFC Bank"
    assert any("hdfcbank.com" in r for r in v.reasons)


@pytest.mark.asyncio
async def test_a_brands_own_domain_is_info_and_unknown_is_not_a_clean_bill_of_health(live) -> None:
    from app.core.fast import fast_check

    official = await fast_check("https://netbanking.hdfcbank.com/login")
    assert official.level == "info" and official.status == "official" and official.brand_check.official_of == "HDFC Bank"
    plain = await fast_check("https://unranked.example.net/about")
    assert plain.level == "none" and plain.popularity_rank is None
    assert any("not a clean bill of health" in r for r in plain.reasons)
    ranked = await fast_check("https://ranked-site.org/about")
    assert ranked.popularity_rank == 321, "the popularity prior is reported (a popular site is also treated as a protected domain)"


@pytest.mark.asyncio
async def test_invalid_private_and_non_applicable_targets_are_not_checked(live) -> None:
    from app.core.fast import fast_check

    assert (await fast_check("")).status == "invalid"
    assert (await fast_check("http://printer.local/admin")).status == "not_assessable"
    assert (await fast_check("8.8.8.8")).status == "not_applicable"
    assert (await fast_check("a" * 64)).status in ("not_applicable", "invalid")


@pytest.mark.asyncio
async def test_a_recent_stored_scan_is_offered_as_the_cache(live, tmp_path) -> None:
    from app.core.fast import fast_check, recent_scan_summary
    from app.api.scan import _store
    from app.models.schemas import ScanResult, TargetType, CanonicalTarget

    result = ScanResult(scan_id="cached-scan-0001", target="cached.example.org", target_type=TargetType.DOMAIN,
                        timestamp=datetime.now(timezone.utc), canonical=CanonicalTarget(kind=TargetType.DOMAIN, host="cached.example.org"),
                        baseline_score=0.2, baseline_label="Low", ml_label="Low", verdict_status="ok")
    await _store.save(result)

    async def recent(t):
        return await recent_scan_summary(_store, t)

    v = await fast_check("https://cached.example.org/x", recent_scan_lookup=recent)
    assert v.cached_scan and v.cached_scan["scan_id"] == "cached-scan-0001" and v.cached_scan["baseline_label"] == "Low"
    old = await _store.latest_for_target("cached.example.org", datetime.now(timezone.utc) + timedelta(hours=1))
    assert old is None, "only scans newer than the window count"
    assert (await fast_check("https://never-scanned.example.org/", recent_scan_lookup=recent)).cached_scan is None


@pytest.mark.asyncio
async def test_p95_latency_is_under_300_ms_for_listed_and_cached_targets(live) -> None:
    from app.core.fast import fast_check

    targets = ["https://secure-paypa1.example.net/login/verify?id=1", "https://evil.example.com/a", "https://netbanking.hdfcbank.com/login",
               "https://ranked-site.org/about", "https://hdfcbank-netbanking-login.com/verify"]
    await fast_check(targets[0], send_full_url=True)                       # warm-up: model + brand index load
    took = []
    for _ in range(12):
        for t in targets:
            t0 = time.perf_counter()
            await fast_check(t, send_full_url=True)
            took.append((time.perf_counter() - t0) * 1000)
    took.sort()
    p95 = took[int(len(took) * 0.95) - 1]
    assert p95 < 300, f"p95 {p95:.0f} ms"


@pytest.mark.asyncio
async def test_a_missing_local_list_is_reported_as_a_gap_not_as_clean(live) -> None:
    from app.core.fast import fast_check

    await live.feeds.clear("openphish")
    with respx.mock(assert_all_called=False):
        v = await fast_check("https://unranked.example.net/about")
        await asyncio.sleep(0.05)
        for feed in live.reputation().feeds():
            if feed._background is not None:
                feed._background.cancel()
    assert "openphish" in v.list_gaps


# ── the HTTP surface ────────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def client(monkeypatch):
    import app.core.validation as validation
    from app.core.config import get_settings
    from app.core.hub import hub
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "true")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1000")
    get_settings.cache_clear()
    hub.reset()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as c:
        yield c
    get_settings.cache_clear()
    hub.reset()


@pytest.mark.asyncio
async def test_the_fast_endpoint_needs_the_token_and_answers_in_mock_mode(client) -> None:
    anon = await client.post("/scan/fast", json={"target": "example.com"}, headers={"Authorization": ""})
    assert anon.status_code in (401, 403)
    r = await client.post("/scan/fast", json={"target": "evil-login.example.com"})
    body = r.json()
    assert r.status_code == 200 and body["tier"] == "fast" and body["level"] in ("warn", "block")
    assert "openphish" in body["listed_by"], "mock mode serves labelled mock list answers"


@pytest.mark.asyncio
async def test_async_mode_returns_the_fast_verdict_at_once_and_the_slow_tier_finishes_later(client) -> None:
    t0 = time.perf_counter()
    r = await client.post("/scan", json={"target": "evil-login.example.com", "target_type": "domain", "mode": "async", "scan_id": "async-scan-0001"})
    first = time.perf_counter() - t0
    body = r.json()
    assert r.status_code == 200 and body["status"] == "running" and body["scan_id"] == "async-scan-0001" and body["result"] is None
    assert body["fast"]["level"] in ("warn", "block") and body["fast"]["tier"] == "fast"
    assert first < 2.0

    for _ in range(100):
        got = (await client.get("/scan/async-scan-0001")).json()
        if got["status"] != "running":
            break
        await asyncio.sleep(0.1)
    assert got["success"] is True and got["result"]["scan_id"] == "async-scan-0001"
    assert got["result"]["reputation"] is not None and got["result"]["url_risk"] is not None


@pytest.mark.asyncio
async def test_sync_mode_is_unchanged(client) -> None:
    r = await client.post("/scan", json={"target": "plain.example.org", "target_type": "domain"})
    body = r.json()
    assert body["success"] is True and body["result"]["scan_id"] and body["status"] is None and body["fast"] is None


@pytest.mark.asyncio
async def test_async_mode_rejects_bad_input_and_reused_ids_at_once(client) -> None:
    bad = await client.post("/scan", json={"target": "not a domain!!", "target_type": "domain", "mode": "async"})
    assert bad.status_code == 400
    await client.post("/scan", json={"target": "a.example.org", "target_type": "domain", "mode": "async", "scan_id": "dup-scan-0001"})
    dup = await client.post("/scan", json={"target": "b.example.org", "target_type": "domain", "mode": "async", "scan_id": "dup-scan-0001"})
    assert dup.status_code == 409


@pytest.mark.asyncio
async def test_a_validation_failure_in_the_background_is_an_error_status_and_an_sse_error(client, monkeypatch) -> None:
    import app.core.validation as validation
    from app.core.scan_events import bus

    async def _no(target):
        return False, {"success": False, "stage": "dns", "message": "The domain does not resolve."}, target

    monkeypatch.setattr(validation, "validate_domain_target", _no)
    r = await client.post("/scan", json={"target": "gone.example.org", "target_type": "domain", "mode": "async", "scan_id": "bgfail-scan-001"})
    assert r.json()["status"] == "running"
    for _ in range(100):
        got = (await client.get("/scan/bgfail-scan-001")).json()
        if got["status"] != "running":
            break
        await asyncio.sleep(0.05)
    assert got["success"] is False and got["status"] == "error" and "does not resolve" in got["error"]
    assert bus.events("bgfail-scan-001")[-1]["type"] == "error"


@pytest.mark.asyncio
async def test_a_flood_of_async_scans_is_bounded(client, monkeypatch) -> None:
    from app.core.config import get_settings
    from app.core.jobs import JOBS

    monkeypatch.setenv("SCAN_MAX_CONCURRENT_JOBS", "1")
    monkeypatch.setenv("SCAN_MAX_PENDING_JOBS", "2")
    get_settings.cache_clear()
    JOBS.max_concurrent, JOBS.max_pending = 1, 2
    gate = asyncio.Event()

    async def hold():
        await gate.wait()

    JOBS.submit("holder-job-001", hold)
    await asyncio.sleep(0.01)
    codes = []
    for i in range(5):
        r = await client.post("/scan", json={"target": f"flood{i}.example.org", "target_type": "domain", "mode": "async", "scan_id": f"flood-scan-{i:03d}"})
        codes.append(r.status_code)
    gate.set()
    await JOBS.shutdown()
    assert 429 in codes and codes.count(200) <= 3
