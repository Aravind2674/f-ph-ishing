"""A1-5 — concurrent providers and live per-provider progress.

Before: ``/scan`` awaited VirusTotal, InternetDB, NVD, the tech fingerprint (and now TLS/RDAP/DNS/endoflife) one
after another, so a scan took the *sum* of its providers and the UI could show nothing until the end.  Now the
independent providers run together (``asyncio.gather``), the dependent ones are chained (InternetDB → NVD,
tech fingerprint → end-of-life), a process-wide gate bounds the number of provider calls in flight, and every
state change is published to ``GET /scan/{id}/events`` (Server-Sent Events) so the UI can draw live status chips.

The ordering assertions are on the *event log* (deterministic), not on wall-clock timing.
"""

from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from app.core.scan_events import ScanEventBus
from app.models.schemas import DnsInfo, ProviderResult, ProviderStatus, RdapInfo, TlsInfo
from tests.conftest import mock_site

AUTH = {"Authorization": "Bearer test-token-0123456789abcdef0123456789abcdef"}
NOW = datetime.now(timezone.utc)
INDEPENDENT = {"virustotal", "shodan_internetdb", "tech_fingerprint", "tls", "rdap", "dns"}
IDB = {"ports": [80], "cpes": [], "vulns": ["CVE-2021-44228"], "hostnames": [], "tags": []}
NVD = {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
                                    "published": "2021-12-10T10:15:00.000"}}]}
WP_PAGE = '<html><head><meta name="generator" content="WordPress 4.9.8"></head><body>' + "x" * 25000 + "</body></html>"
EOL_WP = [{"cycle": "4.9", "eol": True, "latest": "4.9.26"}]


class Probe:
    """A stub client whose call is slow and which records how many calls were in flight at once."""

    def __init__(self, source, data, delay=0.05, tracker=None) -> None:
        self.source, self.data, self.delay, self.tracker = source, data, delay, tracker if tracker is not None else {"now": 0, "max": 0}

    async def lookup(self, *args):
        self.tracker["now"] += 1
        self.tracker["max"] = max(self.tracker["max"], self.tracker["now"])
        await asyncio.sleep(self.delay)
        self.tracker["now"] -= 1
        return ProviderResult(source=self.source, status=ProviderStatus.OK, data=self.data)

    async def close(self) -> None:
        return None


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch, fake_dns):
    """A live-mode scan with every provider enabled and slowed down; returns (TestClient, tracker)."""
    import app.core.validation as validation
    from fastapi.testclient import TestClient
    from app.core.config import get_settings
    from app.core.hub import hub
    from app.main import app

    for name, value in {"USE_MOCK_DATA": "false", "VIRUSTOTAL_API_KEY": "vt-key-for-tests-123456",
                        "NVD_API_KEY": "nvd-key-for-tests-123456", "RATE_LIMIT_REQUESTS_PER_MINUTE": "1000",
                        "TLS_ENABLED": "true", "RDAP_ENABLED": "true", "DNS_ENABLED": "true", "EOL_ENABLED": "true"}.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    tracker = {"now": 0, "max": 0}
    stubs = {
        "tls": Probe("tls", TlsInfo(host="www.example.com", has_tls=True, chain_valid=True, san_matches_host=True,
                                    not_after=NOW + timedelta(days=60)), tracker=tracker),
        "rdap": Probe("rdap", RdapInfo(domain="example.com", registered_at=NOW - timedelta(days=900)), tracker=tracker),
        "dns": Probe("dns", DnsInfo(host="www.example.com", lookup_domain="example.com", a=["93.184.216.34"]), tracker=tracker),
    }
    monkeypatch.setattr(hub, "tls", lambda: stubs["tls"])
    monkeypatch.setattr(hub, "rdap", lambda: stubs["rdap"])
    monkeypatch.setattr(hub, "dns", lambda: stubs["dns"])

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    yield TestClient(app), tracker
    get_settings.cache_clear()


def _providers(router, tracker, delay=0.05):
    """respx routes for VT / InternetDB / the page / NVD / endoflife — each slow, each counted in ``tracker``."""
    def slow(make):
        async def handler(request: httpx.Request) -> httpx.Response:
            tracker["now"] += 1
            tracker["max"] = max(tracker["max"], tracker["now"])
            await asyncio.sleep(delay)
            tracker["now"] -= 1
            return make(request)
        return handler

    router.get(url__regex=r"https://www\.virustotal\.com/.*").mock(side_effect=slow(lambda r: httpx.Response(404)))
    router.get(url__regex=r"https://internetdb\.shodan\.io/.*").mock(side_effect=slow(lambda r: httpx.Response(200, json=IDB)))
    router.get(url__regex=r"https://services\.nvd\.nist\.gov/.*").mock(side_effect=slow(lambda r: httpx.Response(200, json=NVD)))
    mock_site(router, "www.example.com", side_effect=slow(lambda r: httpx.Response(200, text=WP_PAGE)))
    mock_site(router, "endoflife.date", path="/api/wordpress.json",
              side_effect=slow(lambda r: httpx.Response(200, json=EOL_WP, headers={"content-type": "application/json"})))


def _run_scan(client, tracker, scan_id=None, delay=0.05, **extra):
    from app.core.scan_events import bus
    body = {"target": "www.example.com", "target_type": "domain", **extra}
    if scan_id:
        body["scan_id"] = scan_id
    with respx.mock(assert_all_called=False) as router:
        _providers(router, tracker, delay)
        resp = client.post("/scan", json=body)
    return resp, bus


def _provider_events(events):
    return [e for e in events if e["type"] == "provider"]


# ── concurrency ─────────────────────────────────────────────────────────────
def test_independent_providers_start_together_and_dependent_ones_wait_for_their_parent(world) -> None:
    client, tracker = world
    resp, bus = _run_scan(client, tracker, scan_id="scan-concurrency-1")
    assert resp.status_code == 200 and resp.json()["success"] is True, resp.text
    events = bus.events("scan-concurrency-1")
    prov_events = _provider_events(events)

    # every independent provider reports "running" before ANY provider has finished -> they run side by side
    first_terminal = next(i for i, e in enumerate(prov_events) if e["status"] != "running")
    running_first = {e["source"] for e in prov_events[:first_terminal]}
    assert INDEPENDENT <= running_first, f"only {running_first} were running when the first provider finished"

    def index(source, status):
        return next(i for i, e in enumerate(prov_events) if e["source"] == source and (e["status"] == "running") == (status == "running"))

    assert index("nvd", "running") > index("shodan_internetdb", "done"), "NVD needs InternetDB's CVE list first"
    assert index("endoflife", "running") > index("tech_fingerprint", "done"), "EOL needs the detected versions first"
    assert tracker["max"] >= 4, f"expected several provider calls in flight at once, saw {tracker['max']}"


def test_the_outcome_order_in_the_result_is_stable_whatever_finishes_first(world) -> None:
    client, tracker = world
    resp, _ = _run_scan(client, tracker, scan_id="scan-order-0001")
    sources = [o["source"] for o in resp.json()["result"]["provider_results"]]
    assert sources == ["virustotal", "shodan_internetdb", "nvd", "epss", "kev", "vulnrichment",
                       "tech_fingerprint", "endoflife", "tls", "rdap", "dns", "ct"]


def test_a_process_wide_gate_bounds_provider_calls_in_flight(world, monkeypatch) -> None:
    from app.core.config import get_settings
    client, tracker = world
    monkeypatch.setenv("SCAN_MAX_CONCURRENT_PROVIDERS", "2")
    get_settings.cache_clear()
    resp, _ = _run_scan(client, tracker, scan_id="scan-gate-00001")
    assert resp.json()["success"] is True and tracker["max"] <= 2, tracker


def test_one_provider_raising_does_not_sink_the_scan_and_is_reported(world, monkeypatch) -> None:
    from app.core.hub import hub
    client, tracker = world

    class Boom:
        async def lookup(self, *a):
            raise RuntimeError("kaboom")

    monkeypatch.setattr(hub, "rdap", lambda: Boom())
    resp, bus = _run_scan(client, tracker, scan_id="scan-boom-0001")
    body = resp.json()
    rdap = next(o for o in body["result"]["provider_results"] if o["source"] == "rdap")
    assert body["success"] is True and rdap["status"] == "error" and rdap["reason"].startswith("unexpected:")
    assert any(e["source"] == "rdap" and e["status"] == "error" for e in _provider_events(bus.events("scan-boom-0001")))


# ── events ──────────────────────────────────────────────────────────────────
def test_events_describe_the_scan_without_leaking_the_target(world) -> None:
    client, tracker = world
    _, bus = _run_scan(client, tracker, scan_id="scan-privacy-01")
    events = bus.events("scan-privacy-01")
    assert events[0]["type"] == "start" and INDEPENDENT <= set(events[0]["providers"])
    assert events[-1]["type"] == "done" and events[-1]["scan_id"] == "scan-privacy-01"
    assert events[-1]["verdict_status"] in ("ok", "partial", "unknown")
    stages = [e["stage"] for e in events if e["type"] == "stage"]
    assert stages == ["lookalike", "features", "scoring"]   # B4: the local brand check runs between enrichment and features
    done = [e for e in _provider_events(events) if e["status"] != "running"]
    assert {"source", "status", "reason", "cached", "mock", "latency_ms"} <= set(done[0])
    blob = json.dumps(events)
    assert "example.com" not in blob and "WordPress" not in blob and "CVE-2021" not in blob


def test_a_failing_scan_publishes_an_error_event_and_closes_the_stream(world, monkeypatch) -> None:
    import app.api.scan as scan_module
    client, tracker = world
    monkeypatch.setattr(scan_module, "extract_features_with_coverage", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bad")))
    resp, bus = _run_scan(client, tracker, scan_id="scan-failure-01")
    assert resp.json()["success"] is False
    last = bus.events("scan-failure-01")[-1]
    assert last["type"] == "error" and "bad" not in json.dumps(last), "no internals in events"


def test_mock_mode_scans_publish_events_too(client) -> None:
    import app.core.validation as v
    from app.core.scan_events import bus
    from fastapi.testclient import TestClient
    from app.main import app

    async def _ok(t):
        return True, {"success": True}, t

    orig = v.validate_domain_target
    v.validate_domain_target = _ok
    try:
        TestClient(app).post("/scan", json={"target": "google.com", "target_type": "domain", "scan_id": "scan-mock-0001"})
    finally:
        v.validate_domain_target = orig
    events = bus.events("scan-mock-0001")
    assert events[0]["type"] == "start" and events[-1]["type"] == "done"
    assert all(e["mock"] is True for e in _provider_events(events) if e["status"] != "running")


# ── client-chosen scan ids ──────────────────────────────────────────────────
def test_a_client_supplied_scan_id_is_used_and_cannot_be_reused(world) -> None:
    client, tracker = world
    resp, _ = _run_scan(client, tracker, scan_id="my-scan-id-0001")
    assert resp.json()["result"]["scan_id"] == "my-scan-id-0001"
    assert client.get("/scan/my-scan-id-0001").json()["result"]["scan_id"] == "my-scan-id-0001"
    again, _ = _run_scan(client, tracker, scan_id="my-scan-id-0001")
    assert again.status_code == 409


@pytest.mark.parametrize("bad", ["short", "has spaces in it", "../../etc/passwd", "x" * 65, "semi;colon-id"])
def test_scan_ids_are_validated(world, bad) -> None:
    client, tracker = world
    with respx.mock(assert_all_called=False) as router:
        _providers(router, tracker)
        resp = client.post("/scan", json={"target": "www.example.com", "target_type": "domain", "scan_id": bad})
    assert resp.status_code == 422


# ── the SSE endpoint ────────────────────────────────────────────────────────
def _parse_sse(text: str) -> list[dict]:
    out = []
    for block in text.split("\n\n"):
        data = [line[5:].strip() for line in block.splitlines() if line.startswith("data:")]
        if data:
            out.append(json.loads("".join(data)))
    return out


@pytest.mark.asyncio
async def test_events_stream_over_sse_with_a_single_use_ticket_even_when_opened_before_the_scan(world) -> None:
    from app.main import app
    _client, tracker = world
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as c:
        ticket = (await c.post("/scan/events-ticket", json={})).json()["ticket"]
        with respx.mock(assert_all_called=False) as router:
            _providers(router, tracker)
            sse = asyncio.create_task(c.get(f"/scan/sse-scan-0001/events?ticket={ticket}", headers={"Authorization": ""}))
            await asyncio.sleep(0.05)                                   # the stream is open BEFORE the scan starts
            post = await c.post("/scan", json={"target": "www.example.com", "target_type": "domain", "scan_id": "sse-scan-0001"})
            streamed = await asyncio.wait_for(sse, timeout=30)
        assert post.json()["success"] is True
        assert streamed.status_code == 200 and streamed.headers["content-type"].startswith("text/event-stream")
        events = _parse_sse(streamed.text)
        assert events[0]["type"] == "start" and events[-1]["type"] == "done"
        assert {e["source"] for e in events if e["type"] == "provider"} >= INDEPENDENT

        reuse = await c.get(f"/scan/sse-scan-0001/events?ticket={ticket}", headers={"Authorization": ""})
        assert reuse.status_code == 401, "a ticket is single-use"
        fresh = (await c.post("/scan/events-ticket", json={})).json()["ticket"]
        replay = await c.get(f"/scan/sse-scan-0001/events?ticket={fresh}", headers={"Authorization": ""})
        assert [e["type"] for e in _parse_sse(replay.text)][-1] == "done", "a finished scan's events are replayed"


@pytest.mark.asyncio
async def test_the_events_endpoint_needs_a_token_or_a_ticket() -> None:
    from app.main import app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as c:
        assert (await c.get("/scan/anything-0001/events")).status_code == 401
        assert (await c.get("/scan/anything-0001/events?ticket=forged")).status_code == 401
        assert (await c.post("/scan/events-ticket", json={})).status_code == 401


# ── the bus itself ──────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_bus_replays_history_then_delivers_live_events_and_stops_at_the_terminal_one() -> None:
    bus = ScanEventBus()
    bus.publish("s-bus-0001", {"type": "start"})
    bus.publish("s-bus-0001", {"type": "provider", "source": "a", "status": "running"})
    seen: list[str] = []

    async def consume():
        async for e in bus.subscribe("s-bus-0001", wait_seconds=5):
            if e is not None:
                seen.append(e["type"])

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.02)
    bus.publish("s-bus-0001", {"type": "provider", "source": "a", "status": "ok"})
    bus.publish("s-bus-0001", {"type": "done"})
    bus.publish("s-bus-0001", {"type": "provider", "source": "late", "status": "ok"})      # after done: ignored
    await asyncio.wait_for(task, 2)
    assert seen == ["start", "provider", "provider", "done"]
    assert [e["type"] for e in bus.events("s-bus-0001")] == ["start", "provider", "provider", "done"]


@pytest.mark.asyncio
async def test_bus_gives_up_on_a_scan_that_never_starts_and_heartbeats_while_idle() -> None:
    bus = ScanEventBus()
    items = [e async for e in bus.subscribe("never-0001", wait_seconds=0.3, heartbeat=0.1)]
    assert items[-1] == {"type": "timeout"} and items.count(None) >= 1, items


def test_bus_is_bounded_and_forgets_finished_scans() -> None:
    now = [0.0]
    bus = ScanEventBus(max_channels=3, linger_seconds=10, clock=lambda: now[0])
    for i in range(5):
        bus.publish(f"s-cap-{i:04d}", {"type": "start"})
    assert len(bus._channels) <= 3 and bus.events("s-cap-0000") == [], "oldest channels are evicted"
    bus.publish("s-fin-0001", {"type": "done"})
    now[0] += 11
    bus.publish("s-new-0001", {"type": "start"})                      # any publish triggers housekeeping
    assert bus.events("s-fin-0001") == [], "finished scans are forgotten after the linger time"


def test_bus_publish_is_thread_safe_and_wakes_subscribers_on_another_loop() -> None:
    bus = ScanEventBus()
    received: list[str] = []
    ready = threading.Event()

    def reader():
        async def run():
            async for e in bus.subscribe("s-thr-0001", wait_seconds=5):
                if e is not None:
                    received.append(e["type"])
                ready.set()
        asyncio.run(run())

    t = threading.Thread(target=reader)
    t.start()
    for _ in range(100):                                              # wait for the subscriber to register
        if bus._channels.get("s-thr-0001") and bus._channels["s-thr-0001"].subscribers:
            break
        threading.Event().wait(0.02)
    bus.publish("s-thr-0001", {"type": "start"})
    bus.publish("s-thr-0001", {"type": "done"})
    t.join(5)
    assert received == ["start", "done"]
