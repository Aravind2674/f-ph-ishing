"""A1-2 — NVD: real backoff, a bounded fan-out with a deadline, a persistent CVE cache and CPE lookups.

Audit P1-2: the client looked up CVEs one after another with no deadline (a slow NVD lost *every* result when
the scan's timeout fired), treated 403/429/503 as final, kept its cache in memory only, fetched only the first
page of a CPE query and a CPE from InternetDB was never looked up at all.  Acceptance: *a 20-CVE fixture finishes
within the deadline; the Log4Shell fixture returns CVSS 10.0.*

Everything is respx-mocked; time-dependent behaviour (backoff, the rate window) runs on a fake clock.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import pytest
import respx

from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.ingestion.cve import CVEClient, cpe22_to_cpe23
from app.models.schemas import CVEDetail, ProviderStatus
from tests.conftest import mock_site

NVD_URL = r"https://services\.nvd\.nist\.gov/rest/json/cves/2\.0.*"


def nvd_item(cve_id: str, score: float = 7.5, severity: str = "HIGH") -> dict[str, Any]:
    return {"cve": {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"{cve_id} test description"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": severity}}]},
        "published": "2021-12-10T10:15:00.000"}}


def nvd_page(items: list, total: int | None = None, start: int = 0) -> dict[str, Any]:
    return {"resultsPerPage": len(items), "startIndex": start,
            "totalResults": len(items) if total is None else total, "vulnerabilities": items}


class FakeClock:
    def __init__(self) -> None:
        self.t = 5_000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.t

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 3))
        self.t += max(0.0, seconds)


def _client(clk: FakeClock | None = None, **kw) -> CVEClient:
    clk = clk or FakeClock()
    kw.setdefault("limiter", QuotaLimiter(0, 0, clock=clk, sleep=clk.sleep))
    return CVEClient(api_key="real-key", use_mock=False, clock=clk, **kw)


def _ids(n: int) -> list[str]:
    return [f"CVE-2021-{10000 + i}" for i in range(n)]


# ── Log4Shell ───────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_log4shell_fixture_returns_cvss_10_with_the_key_in_a_header() -> None:
    nvd = _client()
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=NVD_URL).respond(200, json=nvd_page([nvd_item("CVE-2021-44228", 10.0, "CRITICAL")]))
        res = await nvd.lookup_cves(["cve-2021-44228"])
        sent = route.calls.last.request
    await nvd.close()
    assert res.ok and res.data.max_cvss_score == 10.0 and res.data.cves[0].severity == "CRITICAL"
    assert sent.url.params["cveId"] == "CVE-2021-44228"
    assert sent.headers["apiKey"] == "real-key" and "real-key" not in str(sent.url), "key goes in a header, never the URL"


# ── Fan-out, bounded, with a deadline ───────────────────────────────────────
@pytest.mark.asyncio
async def test_twenty_cves_finish_within_the_deadline_with_bounded_concurrency() -> None:
    inflight = {"now": 0, "max": 0}

    async def slow(request: httpx.Request) -> httpx.Response:
        inflight["now"] += 1
        inflight["max"] = max(inflight["max"], inflight["now"])
        await asyncio.sleep(0.05)
        inflight["now"] -= 1
        return httpx.Response(200, json=nvd_page([nvd_item(request.url.params["cveId"])]))

    nvd = CVEClient(api_key="real-key", use_mock=False, limiter=QuotaLimiter(0, 0), max_concurrency=5,
                    deadline_seconds=5.0)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).mock(side_effect=slow)
        t0 = time.perf_counter()
        res = await nvd.lookup_cves(_ids(20))
        took = time.perf_counter() - t0
    await nvd.close()
    assert res.ok and res.reason is None and res.data.total_cves == 20
    assert took < 0.8, f"20 lookups took {took:.2f}s — still sequential? (20 x 0.05s = 1.0s)"
    assert 2 <= inflight["max"] <= 5, inflight


@pytest.mark.asyncio
async def test_a_slow_nvd_returns_what_finished_instead_of_losing_everything() -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.25)
        return httpx.Response(200, json=nvd_page([nvd_item(request.url.params["cveId"])]))

    nvd = CVEClient(api_key="real-key", use_mock=False, limiter=QuotaLimiter(0, 0), max_concurrency=2,
                    deadline_seconds=0.6)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).mock(side_effect=slow)
        t0 = time.perf_counter()
        res = await nvd.lookup_cves(_ids(20))
        took = time.perf_counter() - t0
    await nvd.close()
    assert took < 1.2, "the deadline must be enforced by the client itself"
    assert res.ok and res.reason and res.reason.startswith("partial:"), res.reason
    got = int(res.reason.split(":")[1].split("/")[0])
    assert 2 <= got < 20 and res.data.total_cves == got, "completed lookups are kept"


@pytest.mark.asyncio
async def test_nothing_finishing_before_the_deadline_is_a_timeout_not_an_empty_result() -> None:
    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json=nvd_page([]))

    nvd = CVEClient(api_key="real-key", use_mock=False, limiter=QuotaLimiter(0, 0), deadline_seconds=0.2)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).mock(side_effect=hang)
        res = await nvd.lookup_cves(_ids(3))
    await nvd.close()
    assert res.status == ProviderStatus.ERROR and res.reason == "timeout" and res.data is None


# ── Backoff ─────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 429, 503])
async def test_it_backs_off_exponentially_and_retries_on_403_429_503(status) -> None:
    clk = FakeClock()
    nvd = _client(clk, backoff_base=1.0, max_retries=3)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=NVD_URL).mock(side_effect=[
            httpx.Response(status), httpx.Response(status), httpx.Response(200, json=nvd_page([nvd_item("CVE-2021-44228", 10.0)]))])
        res = await nvd.lookup_cves(["CVE-2021-44228"])
        assert route.call_count == 3
    await nvd.close()
    assert res.ok and res.data.max_cvss_score == 10.0
    assert clk.sleeps == [1.0, 2.0], "exponential: base, 2x base"


@pytest.mark.asyncio
async def test_retry_after_overrides_the_backoff_and_is_shared_by_later_calls() -> None:
    clk = FakeClock()
    nvd = _client(clk, backoff_base=1.0, max_retries=2)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).mock(side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(200, json=nvd_page([nvd_item("CVE-2021-44228")]))])
        res = await nvd.lookup_cves(["CVE-2021-44228"])
    await nvd.close()
    assert res.ok and clk.sleeps == [7.0]


@pytest.mark.asyncio
@pytest.mark.parametrize("status,reason", [(503, "server_error"), (429, "rate_limited"), (403, "auth_or_rate_limited")])
async def test_when_retries_are_exhausted_the_failure_is_reported_never_hidden(status, reason) -> None:
    clk = FakeClock()
    nvd = _client(clk, backoff_base=1.0, max_retries=3)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=NVD_URL).respond(status)
        res = await nvd.lookup_cves(["CVE-2021-44228"])
        assert route.call_count == 4, "1 try + 3 retries"
    await nvd.close()
    assert res.status == ProviderStatus.ERROR and res.reason == reason and res.data is None
    assert clk.sleeps == [1.0, 2.0, 4.0]


@pytest.mark.asyncio
async def test_a_backoff_that_would_overrun_the_deadline_gives_up_early() -> None:
    clk = FakeClock()
    nvd = _client(clk, backoff_base=1.0, max_retries=5, deadline_seconds=3.0)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=NVD_URL).respond(503)
        res = await nvd.lookup_cves(["CVE-2021-44228"])
        assert route.call_count == 3, "t=0 try, wait 1, try, wait 2 (t=3), try, a further 4s wait would overrun"
    await nvd.close()
    assert res.status == ProviderStatus.ERROR and res.reason == "server_error"


@pytest.mark.asyncio
@pytest.mark.parametrize("status,reason", [(404, None), (401, "auth"), (400, "bad_request")])
async def test_other_statuses_are_not_retried(status, reason) -> None:
    nvd = _client()
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=NVD_URL).respond(status)
        res = await nvd.lookup_cves(["CVE-2021-44228"])
        assert route.call_count == 1
    await nvd.close()
    assert res.status in (ProviderStatus.ERROR, ProviderStatus.NOT_FOUND) and res.reason == reason


# ── Rate window from config ─────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_limiter_supports_arbitrary_windows_like_nvds_30_seconds() -> None:
    clk = FakeClock()
    lim = QuotaLimiter(windows=[(2, 30.0)], clock=clk, sleep=clk.sleep)
    assert [await lim.acquire(max_wait=0) for _ in range(2)] == [None, None]
    retry = await lim.acquire(max_wait=0)
    assert retry is not None and 29.0 <= retry <= 30.0
    clk.t += 30
    assert await lim.acquire(max_wait=0) is None


@pytest.mark.asyncio
async def test_the_client_spaces_requests_by_the_configured_nvd_window() -> None:
    clk = FakeClock()
    lim = QuotaLimiter(windows=[(2, 30.0)], clock=clk, sleep=clk.sleep)
    nvd = CVEClient(api_key="real-key", use_mock=False, limiter=lim, clock=clk, max_concurrency=1,
                    deadline_seconds=1000.0)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=NVD_URL).mock(side_effect=lambda r: httpx.Response(
            200, json=nvd_page([nvd_item(r.url.params["cveId"])])))
        res = await nvd.lookup_cves(_ids(5))
        assert route.call_count == 5
    await nvd.close()
    assert res.ok and res.data.total_cves == 5
    assert sum(clk.sleeps) >= 60.0, f"5 calls at 2 per 30s need >=60s of waiting, slept {clk.sleeps}"


# ── Persistent cache ────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_cve_details_are_cached_across_clients_and_restarts(tmp_path) -> None:
    db = tmp_path / "nvd.db"
    first = _client(cache=ProviderCache(path_provider=lambda: db))
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=NVD_URL).mock(side_effect=lambda r: httpx.Response(
            200, json=nvd_page([nvd_item(r.url.params["cveId"], 9.8, "CRITICAL")])))
        await first.lookup_cves(_ids(3))
        assert route.call_count == 3
        second = _client(cache=ProviderCache(path_provider=lambda: db))            # "after a restart"
        again = await second.lookup_cves(_ids(3))
        assert route.call_count == 3, "everything came from SQLite"
        mixed = await second.lookup_cves(_ids(4))                                  # 3 cached + 1 new
        assert route.call_count == 4
    await first.close(); await second.close()
    assert again.ok and again.cached is True and again.data.max_cvss_score == 9.8
    assert mixed.ok and mixed.cached is False and mixed.data.total_cves == 4


@pytest.mark.asyncio
async def test_failures_are_never_cached_but_not_found_is_remembered_briefly() -> None:
    nvd = _client(cache=ProviderCache())
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=NVD_URL).mock(side_effect=[
            httpx.Response(401), httpx.Response(200, json=nvd_page([nvd_item("CVE-2021-44228")]))])
        a = await nvd.lookup_cves(["CVE-2021-44228"])
        b = await nvd.lookup_cves(["CVE-2021-44228"])          # must retry, not reuse the failure
        assert route.call_count == 2
        c = await nvd.lookup_cves(["CVE-2021-44228"])          # now cached
        assert route.call_count == 2
        router.get(url__regex=NVD_URL).respond(200, json=nvd_page([]))
        d1 = await nvd.lookup_cves(["CVE-1999-0001"])
        d2 = await nvd.lookup_cves(["CVE-1999-0001"])
    await nvd.close()
    assert a.status == ProviderStatus.ERROR and b.ok and c.ok and c.cached
    assert d1.status == ProviderStatus.NOT_FOUND and d2.status == ProviderStatus.NOT_FOUND


# ── CPE lookups ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("cpe:/a:apache:http_server:2.4.49", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
    ("cpe:/a:openbsd:openssh:8.2p1", "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"),
    ("cpe:/a:apache:http_server:2.4.49:-", "cpe:2.3:a:apache:http_server:2.4.49:-:*:*:*:*:*:*"),
    ("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
    ("cpe:/a:vendor:prod%2fuct:1.0", r"cpe:2.3:a:vendor:prod\/uct:1.0:*:*:*:*:*:*:*"),
])
def test_cpe_22_uris_become_cpe_23_names(raw, expected) -> None:
    assert cpe22_to_cpe23(raw) == expected


@pytest.mark.parametrize("raw", ["", "not a cpe", "cpe:/", "cpe:/a:apache", "http://example.com"])
def test_malformed_cpes_are_rejected(raw) -> None:
    assert cpe22_to_cpe23(raw) is None


@pytest.mark.asyncio
async def test_cpe_lookup_follows_pagination_and_reports_truncation() -> None:
    pages = {0: nvd_page([nvd_item("CVE-2020-0001"), nvd_item("CVE-2020-0002")], total=5, start=0),
             2: nvd_page([nvd_item("CVE-2020-0003"), nvd_item("CVE-2020-0004")], total=5, start=2),
             4: nvd_page([nvd_item("CVE-2020-0005")], total=5, start=4)}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=pages[int(request.url.params.get("startIndex", "0"))])

    cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    nvd = _client(results_per_page=2, max_pages=5)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=NVD_URL).mock(side_effect=handler)
        res = await nvd.lookup_by_cpe(cpe)
        starts = [c.request.url.params.get("startIndex") for c in route.calls]
        assert route.calls[0].request.url.params["cpeName"] == cpe
        assert route.calls[0].request.url.params["resultsPerPage"] == "2"
    assert res.ok and res.data.total_cves == 5 and res.reason is None and starts == ["0", "2", "4"]

    capped = _client(results_per_page=2, max_pages=2)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).mock(side_effect=handler)
        res2 = await capped.lookup_by_cpe(cpe)
    await nvd.close(); await capped.close()
    assert res2.ok and res2.data.total_cves == 4 and res2.reason == "truncated:4/5"


@pytest.mark.asyncio
async def test_a_failing_second_page_keeps_the_first() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("startIndex", "0") == "0":
            return httpx.Response(200, json=nvd_page([nvd_item("CVE-2020-0001")], total=3, start=0))
        return httpx.Response(401)

    nvd = _client(results_per_page=1, max_pages=3)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=NVD_URL).mock(side_effect=handler)
        res = await nvd.lookup_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    await nvd.close()
    assert res.ok and res.data.total_cves == 1 and res.reason.startswith("truncated:")


# ── Wired into the scan ─────────────────────────────────────────────────────
@pytest.fixture
def live_scan(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation
    from fastapi.testclient import TestClient
    from app.core.config import get_settings
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    monkeypatch.setenv("NVD_API_KEY", "nvd-key-for-tests-123456")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1000")
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    yield TestClient(app)
    get_settings.cache_clear()


IDB = {"ports": [80, 443], "cpes": ["cpe:/a:apache:http_server:2.4.49", "cpe:/o:microsoft:windows"],
       "vulns": ["CVE-2021-44228"], "hostnames": [], "tags": []}


def _scan_with_nvd(live_scan, **extra):
    def nvd_handler(request: httpx.Request) -> httpx.Response:
        p = request.url.params
        if "cveId" in p:
            return httpx.Response(200, json=nvd_page([nvd_item(p["cveId"], 10.0, "CRITICAL")]))
        return httpx.Response(200, json=nvd_page([nvd_item("CVE-2021-41773", 7.5), nvd_item("CVE-2021-44228", 10.0, "CRITICAL")]))

    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(200, json=IDB)
        nvd_route = router.get(url__regex=NVD_URL).mock(side_effect=nvd_handler)
        mock_site(router, "nvd-scan.example.com", text="<html></html>")
        resp = live_scan.post("/scan", json={"target": "nvd-scan.example.com", "target_type": "domain", **extra})
        params = [dict(c.request.url.params) for c in nvd_route.calls]
    return resp.json(), params


def test_scan_looks_up_listed_cves_and_the_specific_cpes_and_merges_without_duplicates(live_scan) -> None:
    body, params = _scan_with_nvd(live_scan)
    cve = body["result"]["cve"]
    assert cve["max_cvss_score"] == 10.0
    assert sorted(c["cve_id"] for c in cve["cves"]) == ["CVE-2021-41773", "CVE-2021-44228"], "deduplicated"
    assert any(p.get("cveId") == "CVE-2021-44228" for p in params)
    cpe_calls = [p for p in params if "cpeName" in p]
    assert [p["cpeName"] for p in cpe_calls] == ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"], \
        "versionless CPEs (cpe:/o:microsoft:windows) match thousands of CVEs and are not looked up"
    nvd_outcomes = [o for o in body["result"]["provider_results"] if o["source"] == "nvd"]
    assert len(nvd_outcomes) == 1 and nvd_outcomes[0]["status"] == "ok"


def test_cpe_lookups_can_be_switched_off(live_scan, monkeypatch) -> None:
    from app.core.config import get_settings
    monkeypatch.setenv("NVD_LOOKUP_BY_CPE", "false")
    get_settings.cache_clear()
    body, params = _scan_with_nvd(live_scan)
    assert not any("cpeName" in p for p in params) and any("cveId" in p for p in params)
    assert body["result"]["cve"]["max_cvss_score"] == 10.0


def test_one_nvd_client_serves_every_scan_and_scans_do_not_close_it(live_scan, monkeypatch) -> None:
    from app.core.hub import hub
    closes = {"n": 0}
    real_close = CVEClient.close

    async def counting_close(self):
        closes["n"] += 1
        return await real_close(self)

    monkeypatch.setattr(CVEClient, "close", counting_close)
    _scan_with_nvd(live_scan)
    first = hub.nvd()
    _scan_with_nvd(live_scan)
    assert hub.nvd() is first and closes["n"] == 0


def test_hub_builds_the_nvd_limiter_from_config(monkeypatch) -> None:
    from app.core.config import get_settings
    from app.core.hub import hub
    monkeypatch.setenv("NVD_API_KEY", "nvd-key-for-tests-123456")
    monkeypatch.setenv("NVD_REQUESTS_PER_WINDOW", "7")
    monkeypatch.setenv("NVD_WINDOW_SECONDS", "12")
    get_settings.cache_clear()
    try:
        snap = hub.nvd()._limiter.snapshot()
    finally:
        get_settings.cache_clear()
    assert {"limit": 7, "window_seconds": 12.0} .items() <= snap["windows"][0].items()
