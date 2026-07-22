"""Tests for the Phase 4 active verification engine.

Detection logic is exercised against a fake HTTP client that simulates
vulnerable vs safe server behaviour — deterministic and network-free. The scope
gate (the safety-critical part) is tested directly and through the endpoint.
"""

import asyncio
import html
from urllib.parse import parse_qs, urlsplit

from app.verify.active import ActiveVerifier, host_is_authorized


# ── Fake target server ───────────────────────────────────────────────────────
class _FakeResp:
    def __init__(self, text: str):
        self.text = text


class _FakeClient:
    """Simulates a target. mode: 'vuln' (reflects raw), 'safe' (escapes), 'sqli'."""

    def __init__(self, mode: str):
        self.mode = mode

    async def get(self, url: str, follow_redirects: bool = False):
        val = parse_qs(urlsplit(url).query).get("q", [""])[0]
        if self.mode == "vuln":
            return _FakeResp(f"<h1>Results for {val}</h1>")
        if self.mode == "safe":
            return _FakeResp(f"<h1>Results for {html.escape(val)}</h1>")
        if self.mode == "sqli":
            if "or '1'='1" in val.lower():
                return _FakeResp("<ul>" + "<li>row</li>" * 25 + "</ul>")
            if "and '1'='2" in val.lower():
                return _FakeResp("<ul></ul>")
            return _FakeResp("<ul><li>row</li></ul>")
        return _FakeResp("")


def _probe(mode: str):
    v = ActiveVerifier()
    return asyncio.run(
        v._probe_param(_FakeClient(mode), "http://127.0.0.1/search?q=test", "q", "test")
    )


# ── Scope gate (safety-critical) ─────────────────────────────────────────────
def test_host_is_authorized_defaults_to_loopback_only():
    assert host_is_authorized("127.0.0.1", set())
    assert host_is_authorized("localhost", set())
    assert not host_is_authorized("example.com", set())
    assert not host_is_authorized("evil.test", set())


def test_host_is_authorized_respects_allowlist():
    assert host_is_authorized("staging.internal", {"staging.internal"})
    assert not host_is_authorized("other.internal", {"staging.internal"})


def test_verify_endpoint_refuses_out_of_scope(client):
    resp = client.post("/verify", json={"target": "http://example.com/p?q=1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["authorized"] is False
    assert data["confirmed_count"] == 0
    assert "scope" in data["summary"].lower() or "not authorised" in (data["error"] or "").lower()


# ── Detection logic ──────────────────────────────────────────────────────────
def test_probe_confirms_reflected_xss():
    probes = _probe("vuln")
    xss = [p for p in probes if p.technique == "reflected-xss"]
    assert xss and xss[0].confirmed


def test_probe_ignores_escaped_output():
    probes = _probe("safe")
    xss = [p for p in probes if p.technique == "reflected-xss"]
    # Escaped reflection must NOT be reported as a confirmed vulnerability.
    assert all(not p.confirmed for p in xss)


def test_probe_confirms_boolean_sqli():
    probes = _probe("sqli")
    boolean = [p for p in probes if p.technique == "boolean-sqli"]
    assert boolean and boolean[0].confirmed
