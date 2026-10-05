"""A1-5 follow-up — the attack-chain step must not hold a scan open.

Found when a timing test in the suite started failing: with the providers now running concurrently, the remaining
~5 s of a mock scan was the *vulnerability chainer*, which asked a local Ollama LLM about each CVE **one after
another**, each with a 5 s timeout and no memory of failures — on a machine without Ollama every CVE paid the
connection attempt again, and with 20 CVEs the step could outlast the whole scan deadline (it was not bounded by it).

Now: the first lookup probes Ollama and a failure is remembered for a minute (the heuristic is used straight away),
connecting has its own short timeout, the per-CVE lookups run concurrently (bounded), and the whole step is bounded by
what is left of the scan's deadline.
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest

from app.ml.chaining import VulnerabilityChainer
from app.models.schemas import CVEDetail
from tests.test_a0_9_limits import limits, stub_validation  # noqa: F401  (fixtures)


def _cves(n: int) -> list[CVEDetail]:
    return [CVEDetail(cve_id=f"CVE-2021-{20000 + i}", description="Remote code execution via a crafted request",
                      cvss_v3_score=9.8, severity="CRITICAL") for i in range(n)]


def _chainer() -> VulnerabilityChainer:
    c = VulnerabilityChainer()
    c._initialized = True                       # skip the (large) EPSS/KEV/Exploit-DB CSV parse
    return c


class FakeOllama:
    """Replaces httpx.AsyncClient inside app.ml.chaining; counts connection attempts."""

    calls = 0
    mode = "down"
    delay = 0.0
    seen_timeouts: list = []

    def __init__(self, *a, **k) -> None:
        FakeOllama.seen_timeouts.append(k.get("timeout"))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, **k):
        FakeOllama.calls += 1
        await asyncio.sleep(FakeOllama.delay)
        if FakeOllama.mode == "down":
            raise httpx.ConnectError("connection refused")
        return httpx.Response(200, json={"response": __import__("json").dumps(
            {"pre_conditions": ["network_access"], "post_conditions": ["remote_code_execution"]})})


@pytest.fixture
def ollama(monkeypatch):
    import app.ml.chaining as chaining
    FakeOllama.calls, FakeOllama.mode, FakeOllama.delay, FakeOllama.seen_timeouts = 0, "down", 0.0, []
    monkeypatch.setattr(chaining.httpx, "AsyncClient", FakeOllama)
    return FakeOllama


@pytest.mark.asyncio
async def test_a_missing_ollama_is_detected_once_not_once_per_cve(ollama) -> None:
    chainer = _chainer()
    paths = await chainer.build_and_solve_chain(_cves(10))
    assert ollama.calls == 1, "the first failure is remembered; the other nine CVEs use the heuristic immediately"
    assert paths, "the rule-based heuristic still produces attack paths"
    again = await chainer.build_and_solve_chain(_cves(5))
    assert ollama.calls == 1 and again, "and it is not retried for a while"


@pytest.mark.asyncio
async def test_connecting_to_ollama_has_its_own_short_timeout(ollama) -> None:
    await _chainer().build_and_solve_chain(_cves(1))
    timeout = ollama.seen_timeouts[0]
    assert isinstance(timeout, httpx.Timeout) and timeout.connect <= 1.0 and timeout.read >= 5.0


@pytest.mark.asyncio
async def test_a_working_ollama_is_asked_concurrently(ollama) -> None:
    ollama.mode, ollama.delay = "up", 0.2
    t0 = time.perf_counter()
    paths = await _chainer().build_and_solve_chain(_cves(9))
    took = time.perf_counter() - t0
    assert ollama.calls == 9 and paths
    assert took < 1.0, f"9 lookups of 0.2 s took {took:.2f}s — sequential would be 1.8 s"


@pytest.mark.asyncio
async def test_the_chain_step_is_bounded_by_the_scan_deadline(limits, stub_validation, monkeypatch) -> None:  # noqa: F811
    limits(USE_MOCK_DATA="true", RATE_LIMIT_REQUESTS_PER_MINUTE=100, PROVIDER_TIMEOUT_SECONDS=1, SCAN_DEADLINE_SECONDS=3)
    import app.api.scan as scan_module
    from app.main import app

    async def hang(cves):
        await asyncio.sleep(60)

    monkeypatch.setattr(scan_module._chainer, "build_and_solve_chain", hang)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost",
                                 headers={"Authorization": "Bearer test-token-0123456789abcdef0123456789abcdef"}) as client:
        t0 = time.perf_counter()
        resp = await client.post("/scan", json={"target": "chain-hang.example", "target_type": "domain"})
        took = time.perf_counter() - t0
    body = resp.json()
    assert body["success"] is True and body["result"]["attack_paths"] == []
    assert took < 8, f"a hanging chainer held the scan for {took:.1f}s although the deadline is 3s"
