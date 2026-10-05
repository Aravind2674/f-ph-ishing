"""A0-4 — one SSRF-safe fetcher (AUDIT_REPORT.md §H2).

The audit showed ``/scan`` validated a hostname once, then re-resolved it when fetching and followed
redirects with no destination check (DNS-rebinding TOCTOU + redirect-to-metadata SSRF).  These tests
prove, with a resolver we control and with *real local HTTP servers*, that:

* every resolved A/AAAA address is checked (one internal record poisons the whole host);
* the connection is pinned to the validated IP — a resolver that changes its answer between lookups
  has no effect;
* every redirect hop is re-validated (metadata, loopback, bad scheme, bad port);
* size / time / hop caps hold.
"""

from __future__ import annotations

import asyncio
import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
import respx

from app.core.safe_http import (
    FetchError,
    FetchPolicy,
    SafeFetcher,
    UnsafeTargetError,
    blocked_reason,
    parse_host_ip,
)
from tests.conftest import PUBLIC_IP, mock_site


# ── Address classification (ipaddress-based, not string checks) ─────────────
@pytest.mark.parametrize("addr", ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "64:ff9b::808:808"])
def test_public_addresses_are_allowed(addr: str) -> None:
    assert blocked_reason(ipaddress.ip_address(addr)) is None


@pytest.mark.parametrize("addr,why", [
    ("127.0.0.1", "loopback"), ("::1", "loopback"),
    ("10.0.0.5", "private"), ("172.16.9.9", "private"), ("192.168.1.1", "private"),
    ("169.254.169.254", "link_local"),             # AWS/GCP/Azure metadata
    ("fe80::1", "link_local"),
    ("fd00:ec2::254", "private"),                  # AWS IPv6 metadata (ULA)
    ("100.64.0.1", "non_global"),                  # CGNAT
    ("0.0.0.0", "unspecified"), ("224.0.0.1", "multicast"), ("240.0.0.1", "private"),
    ("::ffff:127.0.0.1", "loopback"),              # IPv4-mapped
    ("::ffff:10.0.0.1", "private"),
    ("64:ff9b::7f00:1", "loopback"),               # NAT64 wrapping 127.0.0.1
    ("2002:7f00:1::1", "loopback"),                # 6to4 wrapping 127.0.0.1
])
def test_internal_addresses_are_blocked(addr: str, why: str) -> None:
    assert blocked_reason(ipaddress.ip_address(addr)) == why


@pytest.mark.parametrize("host", ["2130706433", "0x7f.1", "127.1", "0177.0.0.1", "017700000001"])
def test_legacy_numeric_ipv4_spellings_are_normalised(host: str) -> None:
    ip = parse_host_ip(host)
    assert ip == ipaddress.ip_address("127.0.0.1")


# ── Policy: scheme, port, userinfo ──────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("url,reason", [
    ("file:///etc/passwd", "blocked_scheme"),
    ("ftp://example.org/x", "blocked_scheme"),
    ("gopher://example.org/", "blocked_scheme"),
    ("http://example.org:22/", "blocked_port"),
    ("http://example.org:6379/", "blocked_port"),
    ("http://user:pw@example.org/", "blocked_userinfo"),
    ("http://169.254.169.254/latest/meta-data/", "blocked_address"),
    ("http://[::1]/", "blocked_address"),
    ("http://2130706433/", "blocked_address"),
    ("http://0x7f.1/", "blocked_address"),
])
async def test_unsafe_targets_are_refused_before_any_request(fake_dns, url: str, reason: str) -> None:
    with respx.mock(assert_all_called=False) as router:   # an unmatched request would raise
        with pytest.raises(UnsafeTargetError) as ei:
            await SafeFetcher(FetchPolicy()).fetch(url)
        assert len(router.calls) == 0                     # (respx clears .calls on exit: assert inside)
    assert ei.value.reason == reason


@pytest.mark.asyncio
async def test_any_internal_record_blocks_the_whole_host(fake_dns) -> None:
    fake_dns.set("mixed.test", PUBLIC_IP, "127.0.0.1")        # one public + one internal answer
    with pytest.raises(UnsafeTargetError, match="mixed.test") as ei:
        await SafeFetcher(FetchPolicy()).fetch("https://mixed.test/")
    assert ei.value.reason == "blocked_address"


@pytest.mark.asyncio
async def test_dns_failure_is_a_fetch_error_not_an_unsafe_target() -> None:
    # real resolver; ".invalid" is guaranteed never to resolve (RFC 2606)
    with pytest.raises(FetchError) as ei:
        await SafeFetcher(FetchPolicy()).fetch("https://definitely-not-real.invalid/")
    assert ei.value.reason == "dns_failure"


# ── DNS pinning: the connection goes to the validated IP, with the original Host/SNI ──
@pytest.mark.asyncio
async def test_connection_is_pinned_to_the_validated_ip(fake_dns) -> None:
    seen = {}

    def handler(request: httpx.Request):
        seen["url_host"] = request.url.host
        seen["host_header"] = request.headers["host"]
        seen["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(200, text="ok")

    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "site.example", side_effect=handler)
        res = await SafeFetcher(FetchPolicy()).fetch("https://site.example/")
    assert res.status_code == 200 and res.ip == PUBLIC_IP
    assert seen == {"url_host": PUBLIC_IP, "host_header": "site.example", "sni": "site.example"}


@pytest.mark.asyncio
async def test_a_resolver_that_changes_its_answer_has_no_effect(fake_dns) -> None:
    """DNS rebinding: 1st answer public, 2nd answer loopback. We resolve once and pin."""
    fake_dns.sequence("rebind.test", [PUBLIC_IP], ["127.0.0.1"])
    with respx.mock(assert_all_called=False) as router:
        route = mock_site(router, "rebind.test", text="public content")
        res = await SafeFetcher(FetchPolicy()).fetch("http://rebind.test/")
        assert route.call_count == 1
        assert len(router.calls) == 1 and all(c.request.url.host == PUBLIC_IP for c in router.calls)
    assert res.text == "public content" and res.ip == PUBLIC_IP
    assert fake_dns.calls.count("rebind.test") == 1, "exactly one DNS lookup per hop — nothing to swap"


# ── Redirects are validated hop by hop ──────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("location,reason", [
    ("http://169.254.169.254/latest/meta-data/", "blocked_address"),
    ("http://127.0.0.1/admin", "blocked_address"),
    ("http://localhost/admin", "blocked_address"),
    ("http://[::ffff:10.0.0.1]/", "blocked_address"),
    ("file:///etc/passwd", "blocked_scheme"),
    ("http://example.org:22/", "blocked_port"),
])
async def test_redirect_to_an_unsafe_destination_is_blocked(fake_dns, location: str, reason: str) -> None:
    fake_dns.set("localhost", "127.0.0.1")
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "start.example", status=302, headers={"Location": location})
        with pytest.raises(UnsafeTargetError) as ei:
            await SafeFetcher(FetchPolicy()).fetch("https://start.example/")
        # only the first (public) hop was ever requested
        assert len(router.calls) == 1
    assert ei.value.reason == reason and ei.value.hop == 1


@pytest.mark.asyncio
async def test_safe_redirects_are_followed_including_relative_ones(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "a.example", status=301, headers={"Location": "https://b.example/landing"})
        mock_site(router, "b.example", path="/landing", status=302, headers={"Location": "/final"})
        mock_site(router, "b.example", path="/final", text="done")
        res = await SafeFetcher(FetchPolicy()).fetch("https://a.example/")
    assert res.text == "done" and res.url == "https://b.example/final"
    assert res.redirects == ["https://a.example/", "https://b.example/landing"]


@pytest.mark.asyncio
async def test_redirect_loops_are_capped(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "loop.example", status=302, headers={"Location": "https://loop.example/"})
        with pytest.raises(UnsafeTargetError) as ei:
            await SafeFetcher(FetchPolicy(max_redirects=3)).fetch("https://loop.example/")
    assert ei.value.reason == "too_many_redirects"


@pytest.mark.asyncio
async def test_redirects_are_not_followed_when_disabled(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "r.example", status=302, headers={"Location": "http://169.254.169.254/"})
        res = await SafeFetcher(FetchPolicy()).fetch("https://r.example/", follow_redirects=False)
    assert res.status_code == 302


# ── Size and time caps ──────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_response_size_is_capped(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "big.example", text="x" * 100_000)
        res = await SafeFetcher(FetchPolicy(max_bytes=1_000)).fetch("https://big.example/")
    assert res.truncated is True and len(res.body) == 1_000


@pytest.mark.asyncio
async def test_total_time_is_capped(fake_dns) -> None:
    async def slow(request):
        await asyncio.sleep(1.0)
        return httpx.Response(200, text="late")

    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "slow.example", side_effect=slow)
        with pytest.raises(FetchError) as ei:
            await SafeFetcher(FetchPolicy(total_timeout=0.2)).fetch("https://slow.example/")
    assert ei.value.reason == "timeout"


@pytest.mark.asyncio
async def test_transport_errors_become_fetch_errors(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "down.example", side_effect=httpx.ConnectError("refused"))
        with pytest.raises(FetchError) as ei:
            await SafeFetcher(FetchPolicy()).fetch("https://down.example/")
    assert ei.value.reason == "network"


# ── Real local servers: pinning + redirect-to-internal over real sockets ────
class _Handler(BaseHTTPRequestHandler):
    seen: list[tuple[str, str]] = []

    def do_GET(self):  # noqa: N802
        _Handler.seen.append((self.path, self.headers.get("Host", "")))
        if self.path == "/to-metadata":
            self.send_response(302); self.send_header("Location", "http://169.254.169.254/latest/meta-data/"); self.end_headers()
        elif self.path == "/to-loopback-name":
            self.send_response(302); self.send_header("Location", f"http://localhost:{self.server.server_port}/secret"); self.end_headers()
        elif self.path == "/relative":
            self.send_response(302); self.send_header("Location", "/ok"); self.end_headers()
        else:
            body = b"hello from the lab"
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


@pytest.fixture
def lab_server():
    _Handler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield server
    server.shutdown()
    t.join(timeout=5)


@pytest.mark.asyncio
async def test_operator_allowed_private_host_works_with_original_host_header(fake_dns, lab_server) -> None:
    """The explicit, configured exception (used for the local vulnerable lab) — over a real socket."""
    port = lab_server.server_port
    fake_dns.set("lab.test", "127.0.0.1")
    policy = FetchPolicy(allow_private=frozenset({("lab.test", port)}))
    res = await SafeFetcher(policy).fetch(f"http://lab.test:{port}/ok")
    assert res.text == "hello from the lab" and res.ip == "127.0.0.1"
    assert _Handler.seen == [("/ok", f"lab.test:{port}")], "connected by IP, but Host kept the logical name"


@pytest.mark.asyncio
async def test_without_the_allowance_the_same_internal_host_is_refused(fake_dns, lab_server) -> None:
    port = lab_server.server_port
    fake_dns.set("lab.test", "127.0.0.1")
    with pytest.raises(UnsafeTargetError) as ei:
        await SafeFetcher(FetchPolicy(allowed_ports=None)).fetch(f"http://lab.test:{port}/ok")
    assert ei.value.reason == "blocked_address"
    assert _Handler.seen == [], "no packet reached the internal server"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/to-metadata", "/to-loopback-name"])
async def test_redirect_from_an_allowed_host_to_internal_targets_is_blocked_over_real_sockets(
    fake_dns, lab_server, path: str
) -> None:
    port = lab_server.server_port
    fake_dns.set("lab.test", "127.0.0.1"); fake_dns.set("localhost", "127.0.0.1")
    policy = FetchPolicy(allow_private=frozenset({("lab.test", port)}))     # lab.test only
    with pytest.raises(UnsafeTargetError) as ei:
        await SafeFetcher(policy).fetch(f"http://lab.test:{port}{path}")
    assert ei.value.reason in {"blocked_address", "blocked_port"} and ei.value.hop == 1
    assert [p for p, _ in _Handler.seen] == [path], "the redirect target was never contacted"
