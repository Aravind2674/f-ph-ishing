"""A1-3 (RDAP) — ``ingestion/rdap.py``: RDAP through the IANA bootstrap (RFC 9224) → the real ``domain_age_days``.

``domain_age_days`` used to be a hard-coded placeholder.  It now comes from the registry's own registration
event.  WHOIS is used *only* for TLDs the bootstrap has no RDAP service for.  Everything is three-state, cached,
SSRF-checked (the RDAP base URL comes from remote JSON, so it is fetched through ``SafeFetcher``) and respx-mocked;
the WHOIS fallback talks to throw-away local TCP servers.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.core.safe_http import FetchPolicy
from app.ingestion.rdap import RdapClient, domain_age_days
from app.models.schemas import ProviderStatus
from tests.conftest import mock_site

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
BOOTSTRAP = {"version": "1.0", "publication": "2026-09-01T00:00:00Z", "services": [
    [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
    [["uk"], ["https://rdap.nominet.uk/uk/"]],
]}


def rdap_json(name: str, registered: str | None, **extra) -> dict:
    events = [{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
              {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"}]
    if registered:
        events.insert(0, {"eventAction": "registration", "eventDate": registered})
    return {"objectClassName": "domain", "ldhName": name.upper(), "status": ["client transfer prohibited"],
            "events": events,
            "entities": [{"objectClassName": "entity", "roles": ["registrar"], "vcardArray": [
                "vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}, {"ldhName": "NS2.EXAMPLE.NET"}], **extra}


def _client(**kw) -> RdapClient:
    kw.setdefault("limiter", QuotaLimiter(0, 0))
    return RdapClient(use_mock=False, clock=lambda: NOW, **kw)


def _bootstrap(router, **kw):
    return mock_site(router, "data.iana.org", path="/rdap/dns.json", text=json.dumps(kw.pop("doc", BOOTSTRAP)),
                     headers={"content-type": "application/json"}, **kw)


def _rdap(router, host: str, path: str, doc: dict | None = None, status: int = 200, **kw):
    return mock_site(router, host, path=path, status=status, text=json.dumps(doc or {}),
                     headers={"content-type": "application/rdap+json"}, **kw)


# ── ages ────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_an_old_domain_and_a_two_day_old_domain_produce_different_ages(fake_dns) -> None:
    two_days_ago = (NOW - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with respx.mock(assert_all_called=False) as router:
        _bootstrap(router)
        _rdap(router, "rdap.verisign.com", "/com/v1/domain/old.com", rdap_json("old.com", "1995-08-14T04:00:00Z"))
        _rdap(router, "rdap.verisign.com", "/com/v1/domain/fresh.com", rdap_json("fresh.com", two_days_ago))
        old = await _client().lookup("old.com")
        fresh = await _client().lookup("fresh.com")
    assert old.ok and fresh.ok
    old_age, fresh_age = domain_age_days(old.data, NOW), domain_age_days(fresh.data, NOW)
    assert old_age > 10_000 and abs(fresh_age - 2.0) < 0.01, (old_age, fresh_age)
    assert old.data.registrar == "Example Registrar, Inc." and old.data.nameservers == ["ns1.example.net", "ns2.example.net"]
    assert old.data.statuses == ["client transfer prohibited"] and old.data.source == "rdap"
    assert old.data.expires_at.year == 2030 and old.data.registered_at.year == 1995


def test_age_is_unknown_not_zero_without_a_registration_date() -> None:
    from app.models.schemas import RdapInfo
    assert domain_age_days(RdapInfo(domain="x.com", registered_at=None), NOW) is None
    assert domain_age_days(None, NOW) is None


@pytest.mark.asyncio
async def test_a_record_without_a_registration_event_is_ok_but_age_stays_unknown(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        _bootstrap(router)
        _rdap(router, "rdap.verisign.com", "/com/v1/domain/noevent.com", rdap_json("noevent.com", None))
        res = await _client().lookup("noevent.com")
    assert res.ok and res.reason == "no_registration_date" and domain_age_days(res.data, NOW) is None


# ── bootstrap ───────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_the_iana_bootstrap_picks_the_server_per_tld_and_is_fetched_once(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        boot = _bootstrap(router)
        com = _rdap(router, "rdap.verisign.com", "/com/v1/domain/a.com", rdap_json("a.com", "2001-01-01T00:00:00Z"))
        uk = _rdap(router, "rdap.nominet.uk", "/uk/domain/b.co.uk", rdap_json("b.co.uk", "2002-02-02T00:00:00Z"))
        client = _client(cache=ProviderCache())
        r1 = await client.lookup("a.com")
        r2 = await client.lookup("b.co.uk")
        assert boot.call_count == 1, "bootstrap cached after the first lookup"
        assert com.call_count == 1 and uk.call_count == 1
        accept = com.calls.last.request.headers["accept"]
    assert r1.ok and r2.ok and "application/rdap+json" in accept


@pytest.mark.asyncio
async def test_results_are_cached_and_age_is_computed_at_use_time(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        _bootstrap(router)
        route = _rdap(router, "rdap.verisign.com", "/com/v1/domain/c.com", rdap_json("c.com", "2026-10-02T12:00:00Z"))
        client = _client(cache=ProviderCache())
        first = await client.lookup("c.com")
        second = await client.lookup("c.com")
        assert route.call_count == 1
    assert second.cached is True and second.fetched_at == first.fetched_at
    assert abs(domain_age_days(second.data, NOW) - 2.0) < 0.01
    assert abs(domain_age_days(second.data, NOW + timedelta(days=5)) - 7.0) < 0.01, "a cached record keeps ageing"


# ── three-state failures ────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected,reason", [
    (404, ProviderStatus.NOT_FOUND, None),
    (429, ProviderStatus.ERROR, "rate_limited"),
    (503, ProviderStatus.ERROR, "server_error"),
    (403, ProviderStatus.ERROR, "auth"),
])
async def test_http_failures_are_classified_and_never_cached(fake_dns, status, expected, reason) -> None:
    with respx.mock(assert_all_called=False) as router:
        _bootstrap(router)
        route = _rdap(router, "rdap.verisign.com", "/com/v1/domain/f.com", {}, status=status)
        client = _client(cache=ProviderCache())
        res = await client.lookup("f.com")
        again = await client.lookup("f.com")
        # 404 is an answer (cached -> 1 call); 403/503 are failures (retried, never cached -> 2 calls);
        # a 429's Retry-After blocks the second lookup entirely (1 call).
        assert route.call_count == (1 if status in (404, 429) else 2)
    assert res.status == expected and res.data is None and (reason is None or res.reason == reason)
    assert again.status == expected


@pytest.mark.asyncio
async def test_a_429_retry_after_is_honoured_for_later_lookups(fake_dns) -> None:
    limiter = QuotaLimiter(0, 0)
    with respx.mock(assert_all_called=False) as router:
        _bootstrap(router)
        route = mock_site(router, "rdap.verisign.com", path="/com/v1/domain/r.com", status=429,
                          headers={"retry-after": "90"})
        client = _client(limiter=limiter)
        first = await client.lookup("r.com")
        second = await client.lookup("r2.com")
        assert route.call_count == 1, "the second lookup must not call the server during the Retry-After block"
    assert first.reason == "rate_limited" and first.retry_after == 90.0
    assert second.reason == "rate_limited" and 80 <= second.retry_after <= 90


@pytest.mark.asyncio
async def test_timeouts_and_garbage_are_errors(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        _bootstrap(router)
        mock_site(router, "rdap.verisign.com", path="/com/v1/domain/slow.com", side_effect=httpx.ReadTimeout("slow"))
        mock_site(router, "rdap.verisign.com", path="/com/v1/domain/junk.com", text="<html>not json</html>")
        slow = await _client().lookup("slow.com")
        junk = await _client().lookup("junk.com")
    assert slow.status == ProviderStatus.ERROR and slow.reason == "timeout"
    assert junk.status == ProviderStatus.ERROR and junk.reason == "parse_error"


@pytest.mark.asyncio
async def test_an_unreachable_bootstrap_is_an_error_not_a_guess(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "data.iana.org", path="/rdap/dns.json", status=500)
        res = await _client().lookup("a.com")
    assert res.status == ProviderStatus.ERROR and res.reason == "bootstrap_failed"


# ── safety & privacy ────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_bootstrap_entry_pointing_at_an_internal_address_is_refused(fake_dns) -> None:
    evil = {"version": "1.0", "services": [[["com"], ["https://169.254.169.254/latest/"]]]}
    with respx.mock(assert_all_called=False) as router:
        _bootstrap(router, doc=evil)
        res = await _client().lookup("a.com")
        calls = [str(c.request.url) for c in router.calls if "169.254" in str(c.request.url)]
    assert res.status == ProviderStatus.ERROR and res.reason.startswith("blocked"), res.reason
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["printer.local", "files.corp.lan", "localhost", "10.0.0.5", "intranet"])
async def test_private_names_and_ips_are_never_sent_to_a_registry(name) -> None:
    with respx.mock(assert_all_called=False) as router:
        res = await _client().lookup(name)
        assert len(router.calls) == 0
    assert res.status == ProviderStatus.SKIPPED


@pytest.mark.asyncio
async def test_no_registered_domain_means_no_lookup() -> None:
    with respx.mock(assert_all_called=False) as router:
        res = await _client().lookup(None)
        assert len(router.calls) == 0
    assert res.status == ProviderStatus.SKIPPED and res.reason == "no_registered_domain"


# ── WHOIS only where a TLD has no RDAP ──────────────────────────────────────
async def _whois_server(replies: dict[str, str]):
    """A throw-away WHOIS server: reads one line, answers with ``replies[line]`` (or nothing)."""
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = (await reader.readline()).decode().strip().lower()
        writer.write(replies.get(line, "").encode())
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


@pytest.mark.asyncio
async def test_whois_is_used_only_when_the_tld_has_no_rdap(fake_dns) -> None:
    fake_dns.set("iana-whois.test", "127.0.0.1")
    fake_dns.set("whois.nic.xx", "127.0.0.1")
    tld_server, tld_port = await _whois_server({
        "fresh.xx": "Domain Name: FRESH.XX\r\nRegistrar: Foo Registrar Ltd\r\nCreation Date: 2026-10-03T10:00:00Z\r\n"})
    iana, iana_port = await _whois_server({"xx": "domain: XX\r\nwhois:        whois.nic.xx\r\n"})
    policy = FetchPolicy(allowed_ports=None, allow_private=frozenset({("iana-whois.test", iana_port), ("whois.nic.xx", tld_port)}))
    try:
        with respx.mock(assert_all_called=False) as router:
            _bootstrap(router)                                 # .xx is not in it -> no RDAP -> WHOIS
            client = _client(policy=policy, iana_whois=("iana-whois.test", iana_port), whois_port=tld_port)
            res = await client.lookup("fresh.xx")
            com_calls = [c for c in router.calls if "verisign" in str(c.request.url)]
    finally:
        for s in (tld_server, iana):
            s.close(); await s.wait_closed()
    assert res.ok and res.data.source == "whois" and res.data.registrar == "Foo Registrar Ltd"
    assert abs(domain_age_days(res.data, NOW) - (1 + 2 / 24)) < 0.05 and com_calls == []


@pytest.mark.asyncio
async def test_a_tld_with_no_rdap_and_no_whois_server_is_skipped_not_guessed(fake_dns) -> None:
    fake_dns.set("iana-whois.test", "127.0.0.1")
    iana, iana_port = await _whois_server({"xx": "domain: XX\r\n"})        # no `whois:` line
    policy = FetchPolicy(allowed_ports=None, allow_private=frozenset({("iana-whois.test", iana_port)}))
    try:
        with respx.mock(assert_all_called=False) as router:
            _bootstrap(router)
            res = await _client(policy=policy, iana_whois=("iana-whois.test", iana_port)).lookup("a.xx")
    finally:
        iana.close(); await iana.wait_closed()
    assert res.status == ProviderStatus.SKIPPED and res.reason == "no_rdap_for_tld"


@pytest.mark.asyncio
async def test_whois_fallback_can_be_switched_off(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        _bootstrap(router)
        res = await _client(whois_fallback=False).lookup("a.xx")
    assert res.status == ProviderStatus.SKIPPED and res.reason == "no_rdap_for_tld"


@pytest.mark.asyncio
async def test_whois_registry_that_hangs_is_an_error(fake_dns) -> None:
    fake_dns.set("iana-whois.test", "127.0.0.1")
    fake_dns.set("whois.nic.xx", "127.0.0.1")

    async def hang(reader, writer):
        await asyncio.sleep(30)
    tld = await asyncio.start_server(hang, "127.0.0.1", 0)
    tld_port = tld.sockets[0].getsockname()[1]
    iana, iana_port = await _whois_server({"xx": "whois:        whois.nic.xx\r\n"})
    policy = FetchPolicy(allowed_ports=None, allow_private=frozenset({("iana-whois.test", iana_port), ("whois.nic.xx", tld_port)}))
    try:
        with respx.mock(assert_all_called=False) as router:
            _bootstrap(router)
            res = await _client(policy=policy, iana_whois=("iana-whois.test", iana_port), whois_port=tld_port,
                                whois_timeout=0.3).lookup("a.xx")
    finally:
        for s in (tld, iana):
            s.close()
    assert res.status == ProviderStatus.ERROR and res.reason == "whois_failed"


# ── mock mode ───────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_mock_mode_is_deterministic_labelled_and_tells_old_from_new() -> None:
    client = RdapClient(use_mock=True, clock=lambda: NOW)
    old, evil, evil2 = (await client.lookup("google.com"), await client.lookup("evil-login.com"),
                        await client.lookup("evil-login.com"))
    assert old.mock and evil.mock and evil.data == evil2.data
    assert domain_age_days(old.data, NOW) > 3000 and domain_age_days(evil.data, NOW) < 10
