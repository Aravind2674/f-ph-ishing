"""B11 (sources) — EPSS (FIRST.org) and CISA Vulnrichment (SSVC decision points).

EPSS gives a *probability* of exploitation (batched, cached daily); Vulnrichment publishes the SSVC decision points CISA
attached to the CVE record (Exploitation / Automatable / Technical Impact).  Both are three-state, cached, rate-limited,
send **only CVE ids**, and every status is covered with respx — nothing is fetched live.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx

from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.ingestion.epss import EpssClient
from app.ingestion.vulnrichment import VulnrichmentClient
from app.models.schemas import ProviderStatus

EPSS_URL = r"https://api\.first\.org/data/v1/epss.*"
CVE_URL = r"https://cveawg\.mitre\.org/api/cve/.*"


def epss_page(rows: dict[str, tuple[float, float]], date: str = "2026-10-03") -> dict:
    return {"status": "OK", "status-code": 200, "version": "1.0", "total": len(rows),
            "data": [{"cve": c, "epss": f"{e:.5f}", "percentile": f"{p:.5f}", "date": date} for c, (e, p) in rows.items()]}


def _ids(n: int, year: int = 2021) -> list[str]:
    return [f"CVE-{year}-{10000 + i}" for i in range(n)]


# ── EPSS ────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_epss_parses_probability_percentile_and_date_and_absent_means_no_row() -> None:
    client = EpssClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=EPSS_URL).respond(200, json=epss_page({"CVE-2021-44228": (0.94358, 0.99991)}))
        res = await client.lookup(["CVE-2021-44228", "cve-2099-0001"])
        sent = router.calls.last.request
    await client.close()
    assert res.ok and set(res.data.rows) == {"CVE-2021-44228"}, "a CVE EPSS has no row for is absent, never 0.0"
    row = res.data.rows["CVE-2021-44228"]
    assert row.epss == pytest.approx(0.94358) and row.percentile == pytest.approx(0.99991) and row.date == "2026-10-03"
    assert sent.url.params["cve"] == "CVE-2021-44228,CVE-2099-0001"
    assert set(sent.url.params) == {"cve"}, "only CVE ids are sent"


@pytest.mark.asyncio
async def test_epss_requests_are_batched() -> None:
    client = EpssClient(use_mock=False, batch_size=100)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=EPSS_URL).mock(side_effect=lambda r: httpx.Response(200, json=epss_page(
            {c: (0.01, 0.5) for c in r.url.params["cve"].split(",")})))
        res = await client.lookup(_ids(150))
        sizes = sorted(len(c.request.url.params["cve"].split(",")) for c in route.calls)
    await client.close()
    assert sizes == [50, 100] and res.ok and len(res.data.rows) == 150


@pytest.mark.asyncio
async def test_epss_answers_are_cached_a_day_including_no_row_and_failures_are_not() -> None:
    client = EpssClient(use_mock=False, cache=ProviderCache())
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=EPSS_URL).mock(side_effect=[
            httpx.Response(200, json=epss_page({"CVE-2021-0001": (0.2, 0.9)})),       # CVE-2021-0002 has no row
            httpx.Response(503), httpx.Response(503)])
        first = await client.lookup(["CVE-2021-0001", "CVE-2021-0002"])
        again = await client.lookup(["CVE-2021-0001", "CVE-2021-0002"])               # all from the cache, incl. "no row"
        assert route.call_count == 1
        failed = await client.lookup(["CVE-2021-0003"])
        retry = await client.lookup(["CVE-2021-0003"])                                # an error is retried, not remembered
        assert route.call_count == 3
    await client.close()
    assert first.ok and again.ok and again.cached is True and set(again.data.rows) == {"CVE-2021-0001"}
    assert failed.status == ProviderStatus.ERROR and failed.reason == "server_error"
    assert retry.status == ProviderStatus.ERROR


@pytest.mark.asyncio
@pytest.mark.parametrize("code,reason", [(429, "rate_limited"), (503, "server_error"), (403, "auth"), (400, "bad_request")])
async def test_epss_http_failures_are_errors(code, reason) -> None:
    client = EpssClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=EPSS_URL).respond(code)
        res = await client.lookup(["CVE-2021-44228"])
    await client.close()
    assert res.status == ProviderStatus.ERROR and res.reason == reason and res.data is None


@pytest.mark.asyncio
async def test_epss_429_retry_after_is_honoured_by_later_calls() -> None:
    client = EpssClient(use_mock=False, limiter=QuotaLimiter(0, 0), max_queue_seconds=5)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=EPSS_URL).respond(429, headers={"Retry-After": "120"})
        first = await client.lookup(["CVE-2021-0001"])
        second = await client.lookup(["CVE-2021-0002"])
        assert route.call_count == 1
    await client.close()
    assert first.retry_after == 120.0 and second.reason == "rate_limited" and 100 <= second.retry_after <= 120


@pytest.mark.asyncio
async def test_epss_timeout_and_garbage_are_errors_and_one_bad_batch_keeps_the_others() -> None:
    client = EpssClient(use_mock=False, batch_size=2)
    with respx.mock(assert_all_called=False) as router:
        def handler(request: httpx.Request) -> httpx.Response:
            ids = request.url.params["cve"].split(",")
            if "CVE-2021-0003" in ids:
                return httpx.Response(500)
            return httpx.Response(200, json=epss_page({c: (0.3, 0.9) for c in ids}))
        route = router.get(url__regex=EPSS_URL).mock(side_effect=handler)
        partial = await client.lookup(["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0004"])
        route.mock(side_effect=httpx.ReadTimeout("slow"))          # (re-program the SAME route: the first match wins)
        slow = await client.lookup(["CVE-2021-0009"])
        route.mock(side_effect=None)
        route.respond(200, text="<html>nope</html>")
        junk = await client.lookup(["CVE-2021-0010"])
    await client.close()
    assert partial.ok and partial.reason == "partial:1/2" and set(partial.data.rows) == {"CVE-2021-0001", "CVE-2021-0002"}
    assert slow.reason == "timeout" and junk.reason == "parse_error"


@pytest.mark.asyncio
async def test_epss_answered_but_empty_is_not_found_and_junk_input_is_skipped() -> None:
    client = EpssClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=EPSS_URL).respond(200, json=epss_page({}))
        res = await client.lookup(["CVE-2099-0001"])
        none = await client.lookup(["not-a-cve", ""])
        assert router.calls.call_count == 1, "invalid ids never reach the API"
    await client.close()
    assert res.status == ProviderStatus.NOT_FOUND and none.status == ProviderStatus.SKIPPED


@pytest.mark.asyncio
async def test_epss_mock_mode_is_deterministic_and_labelled() -> None:
    client = EpssClient(use_mock=True)
    a, b = await client.lookup(["CVE-2021-44228", "CVE-2021-12345"]), await client.lookup(["CVE-2021-44228", "CVE-2021-12345"])
    assert a.mock and a.data == b.data and a.data.rows["CVE-2021-44228"].epss > 0.9


# ── Vulnrichment ────────────────────────────────────────────────────────────
def cve_record(cve: str, *, ssvc: list[dict] | None = None, adp_name: str = "CISA-ADP") -> dict:
    adp = []
    if ssvc is not None:
        adp.append({"providerMetadata": {"shortName": adp_name, "orgId": "134c704f"}, "metrics": [{"other": {
            "type": "ssvc", "content": {"id": cve, "role": "CISA Coordinator", "version": "2.0.3",
                                        "timestamp": "2026-09-30T12:00:00.000Z", "options": ssvc}}}]})
    adp.append({"providerMetadata": {"shortName": "CVE Program Container"}, "references": []})
    return {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": cve, "state": "PUBLISHED"}, "containers": {"cna": {}, "adp": adp}}


LOG4J = cve_record("CVE-2021-44228", ssvc=[{"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"}])


@pytest.mark.asyncio
async def test_vulnrichment_reads_the_cisa_adp_ssvc_decision_points() -> None:
    client = VulnrichmentClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=CVE_URL).respond(200, json=LOG4J)
        res = await client.lookup(["CVE-2021-44228"])
        assert str(route.calls.last.request.url) == "https://cveawg.mitre.org/api/cve/CVE-2021-44228"
    await client.close()
    row = res.data.rows["CVE-2021-44228"]
    assert (row.exploitation, row.automatable, row.technical_impact) == ("active", "yes", "total")
    assert row.timestamp == "2026-09-30T12:00:00.000Z"


@pytest.mark.asyncio
async def test_vulnrichment_ignores_other_adp_containers_and_cves_without_ssvc() -> None:
    client = VulnrichmentClient(use_mock=False)
    docs = {"CVE-2022-0001": cve_record("CVE-2022-0001", ssvc=[{"Exploitation": "none"}], adp_name="Some-Other-ADP"),
            "CVE-2022-0002": cve_record("CVE-2022-0002", ssvc=None),
            "CVE-2022-0003": cve_record("CVE-2022-0003", ssvc=[{"Exploitation": "poc"}, {"Automatable": "no"}, {"Technical Impact": "partial"}])}
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=CVE_URL).mock(side_effect=lambda r: httpx.Response(200, json=docs[r.url.path.rsplit("/", 1)[1]]))
        res = await client.lookup(list(docs))
    await client.close()
    assert set(res.data.rows) == {"CVE-2022-0003"}, "only a CISA-ADP container counts; unenriched CVEs are absent, not 'none'"


@pytest.mark.asyncio
async def test_vulnrichment_statuses_are_three_state_and_failures_are_not_cached() -> None:
    client = VulnrichmentClient(use_mock=False, cache=ProviderCache())
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=CVE_URL).mock(side_effect=[
            httpx.Response(404), httpx.Response(503), httpx.Response(200, json=LOG4J)])
        nf = await client.lookup(["CVE-2099-0001"])
        bad = await client.lookup(["CVE-2021-44228"])
        ok = await client.lookup(["CVE-2021-44228"])                  # the failure was not remembered
        cached = await client.lookup(["CVE-2021-44228"])
        again_nf = await client.lookup(["CVE-2099-0001"])             # "no record" is remembered (briefly)
        assert route.call_count == 3
    await client.close()
    assert nf.status == ProviderStatus.NOT_FOUND
    assert bad.status == ProviderStatus.ERROR and bad.reason == "server_error"
    assert ok.ok and cached.cached is True and again_nf.status == ProviderStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_vulnrichment_one_failing_cve_does_not_lose_the_others() -> None:
    client = VulnrichmentClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=CVE_URL).mock(side_effect=lambda r: httpx.Response(200, json=LOG4J) if r.url.path.endswith("44228")
                                            else httpx.Response(500))
        res = await client.lookup(["CVE-2021-44228", "CVE-2021-0001"])
    await client.close()
    assert res.ok and res.reason == "partial:1/2" and set(res.data.rows) == {"CVE-2021-44228"}


@pytest.mark.asyncio
async def test_vulnrichment_is_bounded_in_concurrency_and_count() -> None:
    inflight = {"now": 0, "max": 0}

    async def slow(request: httpx.Request) -> httpx.Response:
        inflight["now"] += 1
        inflight["max"] = max(inflight["max"], inflight["now"])
        await asyncio.sleep(0.03)
        inflight["now"] -= 1
        return httpx.Response(404)

    client = VulnrichmentClient(use_mock=False, max_concurrency=3, max_cves=10)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=CVE_URL).mock(side_effect=slow)
        await client.lookup(_ids(40))
        assert route.call_count == 10, "capped: the 10 first ids are asked about, not all 40"
    await client.close()
    assert 1 < inflight["max"] <= 3


@pytest.mark.asyncio
async def test_vulnrichment_mock_mode() -> None:
    client = VulnrichmentClient(use_mock=True)
    res = await client.lookup(["CVE-2021-44228"])
    assert res.ok and res.mock and res.data.rows["CVE-2021-44228"].exploitation == "active"
