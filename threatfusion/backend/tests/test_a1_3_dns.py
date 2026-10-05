"""A1-3 (DNS) — ``ingestion/dns_records.py``: A/AAAA/MX/NS/TXT/CAA, SPF + DMARC, hosting ASN.

Three-state per record family: a list (possibly empty = "the zone says there are none") when the lookup
answered, ``None`` when it *failed* — so "no CAA record" and "CAA lookup timed out" are never confused.
No real DNS is used: a fake ``dns.asyncresolver.Resolver`` serves real dnspython rdata from a table.
"""

from __future__ import annotations

import dns.exception
import dns.resolver
import dns.rrset
import pytest

from app.core.cache import ProviderCache
from app.ingestion.dns_records import DnsClient
from app.models.schemas import DnsInfo, ProviderStatus


def rr(name: str, rdtype: str, *texts: str):
    return dns.rrset.from_text(name + ".", 300, "IN", rdtype, *texts)


class FakeResolver:
    """``(name, type) -> rrset | exception``; anything not listed answers 'no such record type' (NoAnswer)."""

    def __init__(self, table: dict | None = None, default: BaseException | None = None) -> None:
        self.table = table or {}
        self.default = default
        self.queries: list[tuple[str, str]] = []

    async def resolve(self, qname, rdtype="A", **_kw):
        key = (str(qname).rstrip(".").lower(), str(rdtype).upper())
        self.queries.append(key)
        value = self.table.get(key, self.default if self.default is not None else dns.resolver.NoAnswer())
        if isinstance(value, BaseException):
            raise value
        return value


WWW = "www.example.com"
TABLE = {
    (WWW, "A"): rr(WWW, "A", "93.184.216.34"),
    (WWW, "AAAA"): rr(WWW, "AAAA", "2606:2800:220:1:248:1893:25c8:1946"),
    ("example.com", "MX"): rr("example.com", "MX", "10 mail.example.com.", "20 mail2.example.com."),
    ("example.com", "NS"): rr("example.com", "NS", "a.iana-servers.net.", "b.iana-servers.net."),
    ("example.com", "TXT"): rr("example.com", "TXT", '"v=spf1 include:_spf.example.com ~all"', '"google-site-verification=abc"'),
    ("example.com", "CAA"): rr("example.com", "CAA", '0 issue "letsencrypt.org"'),
    ("_dmarc.example.com", "TXT"): rr("_dmarc.example.com", "TXT", '"v=DMARC1; p=reject; rua=mailto:d@example.com"'),
    ("34.216.184.93.origin.asn.cymru.com", "TXT"): rr("x", "TXT", '"15133 | 93.184.216.0/24 | US | arin | 2008-06-02"'),
    ("as15133.asn.cymru.com", "TXT"): rr("x", "TXT", '"15133 | US | arin | 2008-06-02 | EDGECAST, US"'),
}


def _client(resolver, **kw) -> DnsClient:
    return DnsClient(use_mock=False, resolver=resolver, **kw)


@pytest.mark.asyncio
async def test_collects_every_record_family_spf_dmarc_and_hosting_asn() -> None:
    res = await _client(FakeResolver(TABLE)).lookup(WWW, "example.com")
    assert res.status == ProviderStatus.OK and res.reason is None
    d: DnsInfo = res.data
    assert d.a == ["93.184.216.34"] and d.aaaa == ["2606:2800:220:1:248:1893:25c8:1946"]
    assert d.mx == ["10 mail.example.com", "20 mail2.example.com"]
    assert d.ns == ["a.iana-servers.net", "b.iana-servers.net"]
    assert d.caa == ["0 issue letsencrypt.org"]
    assert d.spf is True and d.spf_record.startswith("v=spf1")
    assert d.dmarc is True and d.dmarc_policy == "reject"
    assert d.asn == 15133 and d.asn_prefix == "93.184.216.0/24" and d.asn_country == "US" and "EDGECAST" in d.asn_org
    assert d.failed_types == []


@pytest.mark.asyncio
async def test_records_that_do_not_exist_are_empty_lists_and_false_not_none() -> None:
    table = {(WWW, "A"): rr(WWW, "A", "93.184.216.34")}                       # everything else: NoAnswer
    res = await _client(FakeResolver(table)).lookup(WWW, "example.com")
    d = res.data
    assert res.ok and d.mx == [] and d.ns == [] and d.caa == [] and d.aaaa == []
    assert d.spf is False and d.dmarc is False and d.spf_record is None and d.dmarc_policy is None
    assert d.failed_types == []


@pytest.mark.asyncio
async def test_a_failed_lookup_is_none_and_listed_never_an_empty_list() -> None:
    table = dict(TABLE)
    table[("example.com", "TXT")] = dns.resolver.LifetimeTimeout()
    table[("example.com", "CAA")] = dns.resolver.NoNameservers()
    res = await _client(FakeResolver(table)).lookup(WWW, "example.com")
    d = res.data
    assert res.status == ProviderStatus.OK and res.reason == "partial:caa,txt"
    assert d.txt is None and d.caa is None, "unknown, not 'none exist'"
    assert d.spf is None, "SPF can't be judged when the TXT lookup failed"
    assert sorted(d.failed_types) == ["caa", "txt"]
    assert d.mx == ["10 mail.example.com", "20 mail2.example.com"], "other families are unaffected"


@pytest.mark.asyncio
async def test_a_dmarc_lookup_failure_does_not_masquerade_as_no_dmarc() -> None:
    table = dict(TABLE)
    table[("_dmarc.example.com", "TXT")] = dns.exception.Timeout()
    d = (await _client(FakeResolver(table)).lookup(WWW, "example.com")).data
    assert d.dmarc is None and "dmarc" in d.failed_types and d.spf is True


@pytest.mark.asyncio
async def test_nxdomain_is_not_found() -> None:
    res = await _client(FakeResolver(default=dns.resolver.NXDOMAIN())).lookup("nope.example.com", "example.com")
    assert res.status == ProviderStatus.NOT_FOUND and res.data is None


@pytest.mark.asyncio
async def test_everything_timing_out_is_an_error_not_an_empty_result() -> None:
    res = await _client(FakeResolver(default=dns.resolver.LifetimeTimeout())).lookup(WWW, "example.com")
    assert res.status == ProviderStatus.ERROR and res.reason == "timeout" and res.data is None


@pytest.mark.asyncio
async def test_servfail_everywhere_is_a_network_error() -> None:
    res = await _client(FakeResolver(default=dns.resolver.NoNameservers())).lookup(WWW, "example.com")
    assert res.status == ProviderStatus.ERROR and res.reason == "dns_failure"


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["printer.local", "files.corp.lan", "localhost", "intranet", "10.0.0.5"])
async def test_private_and_local_names_are_never_resolved(host) -> None:
    fake = FakeResolver(TABLE)
    res = await _client(fake).lookup(host, None)
    assert res.status == ProviderStatus.SKIPPED and fake.queries == []


@pytest.mark.asyncio
async def test_internal_addresses_are_never_sent_to_the_asn_service() -> None:
    table = {(WWW, "A"): rr(WWW, "A", "10.1.2.3")}
    fake = FakeResolver(table)
    d = (await _client(fake).lookup(WWW, "example.com")).data
    assert d.a == ["10.1.2.3"] and d.asn is None
    assert not any("cymru" in name for name, _t in fake.queries), fake.queries


@pytest.mark.asyncio
async def test_ipv6_only_hosts_use_the_ipv6_asn_zone() -> None:
    table = {(WWW, "AAAA"): rr(WWW, "AAAA", "2606:4700:4700::1111")}
    fake = FakeResolver(table)
    await _client(fake).lookup(WWW, "example.com")
    asked = [n for n, _t in fake.queries if "cymru" in n]
    assert asked and asked[0].endswith(".origin6.asn.cymru.com") and asked[0].startswith("1.1.1.1.0.0.0.0")


@pytest.mark.asyncio
async def test_answers_are_cached_failures_are_not() -> None:
    fake = FakeResolver(TABLE)
    client = _client(fake, cache=ProviderCache())
    first = await client.lookup(WWW, "example.com")
    n = len(fake.queries)
    second = await client.lookup(WWW, "example.com")
    assert len(fake.queries) == n, "second lookup answered from the cache"
    assert second.cached is True and second.fetched_at == first.fetched_at and second.data == first.data

    broken = FakeResolver(default=dns.resolver.LifetimeTimeout())
    c2 = _client(broken, cache=ProviderCache())
    await c2.lookup(WWW, "example.com")
    n2 = len(broken.queries)
    await c2.lookup(WWW, "example.com")
    assert len(broken.queries) > n2, "a failed lookup must be retried, not remembered"


@pytest.mark.asyncio
async def test_mock_mode_is_deterministic_and_labelled() -> None:
    client = DnsClient(use_mock=True)
    a = await client.lookup("www.example.com", "example.com")
    b = await client.lookup("www.example.com", "example.com")
    assert a.ok and a.mock is True and a.data == b.data and a.data.a
