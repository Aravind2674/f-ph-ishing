"""A1-3 (TLS) — ``ingestion/tls.py``: what the host's certificate really is.

Real handshakes against throw-away local TLS servers whose certificates are generated here with ``cryptography``
(a test CA + leaves: valid DV/OV/EV, expired, self-signed, wrong host, unknown issuer, wildcard) — nothing about
the crypto is mocked.  The client's SSRF policy is relaxed only for the test host names (``allow_private``), exactly
how an operator would allow a lab host.

Acceptance (master prompt A1-3): *an expired certificate gives* ``ssl_cert_valid=0``.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import socket
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

from app.core.cache import ProviderCache
from app.core.safe_http import FetchPolicy
from app.ingestion.tls import TlsClient, cert_age_days, days_to_expiry, host_matches, tls_cert_valid
from app.models.schemas import ProviderStatus

NOW = dt.datetime.now(dt.timezone.utc)
DV, OV, EV = "2.23.140.1.2.1", "2.23.140.1.2.2", "2.23.140.1.1"


# ── certificate factory ─────────────────────────────────────────────────────
def _name(cn: str, org: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


def make_ca(cn="Test Root CA", org="Test Trust Services"):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(cn, org)).issuer_name(_name(cn, org))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=30)).not_valid_after(NOW + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def make_leaf(ca_key, ca_cert, cn: str, sans: list[str], *, days_left: float = 90, age_days: float = 0.05,
              policy: str | None = None, self_signed: bool = False):
    key = ec.generate_private_key(ec.SECP256R1())
    issuer = _name(cn) if self_signed else ca_cert.subject
    signer = key if self_signed else ca_key
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(issuer).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(NOW - dt.timedelta(days=age_days)).not_valid_after(NOW + dt.timedelta(days=days_left))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if not self_signed:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    if policy:
        b = b.add_extension(x509.CertificatePolicies([x509.PolicyInformation(ObjectIdentifier(policy), None)]), critical=False)
    return key, b.sign(signer, hashes.SHA256())


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@contextlib.asynccontextmanager
async def tls_server(tmp_path: Path, leaf_key, leaf_cert, counter: list | None = None):
    certfile, keyfile = tmp_path / f"{id(leaf_cert)}.crt", tmp_path / f"{id(leaf_cert)}.key"
    certfile.write_bytes(_pem(leaf_cert)); keyfile.write_bytes(_key_pem(leaf_key))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)

    async def handle(reader, writer):
        if counter is not None:
            counter.append(1)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


@pytest.fixture
def ca(tmp_path):
    key, cert = make_ca()
    path = tmp_path / "ca.pem"
    path.write_bytes(_pem(cert))
    return key, cert, str(path)


def _client(port: int, host: str, ca_path: str | None, fake_dns, **kw) -> TlsClient:
    fake_dns.set(host, "127.0.0.1")
    policy = FetchPolicy(allowed_ports=None, allow_private=frozenset({(host, port)}))
    return TlsClient(use_mock=False, policy=policy, port=port, trust_cafile=ca_path, timeout=3.0, **kw)


# ── what the certificate is ─────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_valid_free_dv_certificate(tmp_path, ca, fake_dns) -> None:
    ca_key, ca_cert, ca_path = ca
    lets = make_ca("Test R3", "Let's Encrypt")                            # a free ACME CA, by issuer name
    lets_path = tmp_path / "le.pem"; lets_path.write_bytes(_pem(lets[1]))
    key, cert = make_leaf(*lets, "ok.test", ["ok.test", "www.ok.test"], days_left=90, age_days=0.05, policy=DV)
    async with tls_server(tmp_path, key, cert) as port:
        res = await _client(port, "ok.test", str(lets_path), fake_dns).lookup("ok.test")
    assert res.status == ProviderStatus.OK and res.reason is None
    t = res.data
    assert t.has_tls and t.chain_valid is True and t.verify_error is None and t.san_matches_host is True
    assert t.validation_level == "dv" and t.issuer_type == "free_dv" and t.issuer_org == "Let's Encrypt"
    assert t.san_names == ["ok.test", "www.ok.test"] and t.self_signed is False
    assert 88 <= days_to_expiry(t) <= 91 and 0 <= cert_age_days(t) < 1
    assert t.tls_version and t.tls_version.startswith("TLSv1") and t.key_type == "EC" and t.key_bits == 256
    assert tls_cert_valid(t) == 1.0


@pytest.mark.asyncio
@pytest.mark.parametrize("policy,org,level,kind", [
    (DV, "DigiCert Inc", "dv", "paid_dv"),
    (OV, "DigiCert Inc", "ov", "ov"),
    (EV, "Sectigo Limited", "ev", "ev"),
    (None, "Some CA", None, "unknown"),
])
async def test_validation_level_and_issuer_type_come_from_the_certificate_policies(tmp_path, policy, org, level, kind, fake_dns) -> None:
    ca_key, ca_cert = make_ca("Issuing CA", org)
    path = tmp_path / "x.pem"; path.write_bytes(_pem(ca_cert))
    key, cert = make_leaf(ca_key, ca_cert, "pol.test", ["pol.test"], policy=policy)
    async with tls_server(tmp_path, key, cert) as port:
        t = (await _client(port, "pol.test", str(path), fake_dns).lookup("pol.test")).data
    assert (t.validation_level, t.issuer_type) == (level, kind)


@pytest.mark.asyncio
async def test_an_expired_certificate_gives_ssl_cert_valid_zero(tmp_path, ca, fake_dns) -> None:
    ca_key, ca_cert, ca_path = ca
    key, cert = make_leaf(ca_key, ca_cert, "old.test", ["old.test"], days_left=-1, age_days=100)
    async with tls_server(tmp_path, key, cert) as port:
        res = await _client(port, "old.test", ca_path, fake_dns).lookup("old.test")
    t = res.data
    assert res.ok and t.has_tls and t.chain_valid is False and t.verify_error == "expired"
    assert t.san_matches_host is True, "the certificate is still parsed: its names are fine, its dates are not"
    assert days_to_expiry(t) < 0 and cert_age_days(t) > 99
    assert tls_cert_valid(t) == 0.0


@pytest.mark.asyncio
async def test_a_self_signed_certificate(tmp_path, ca, fake_dns) -> None:
    ca_key, ca_cert, ca_path = ca
    key, cert = make_leaf(ca_key, ca_cert, "self.test", ["self.test"], self_signed=True)
    async with tls_server(tmp_path, key, cert) as port:
        t = (await _client(port, "self.test", ca_path, fake_dns).lookup("self.test")).data
    assert t.chain_valid is False and t.verify_error == "self_signed" and t.self_signed is True
    assert tls_cert_valid(t) == 0.0


@pytest.mark.asyncio
async def test_a_certificate_from_an_untrusted_issuer(tmp_path, ca, fake_dns) -> None:
    _k, _c, ca_path = ca                                              # the client trusts THIS CA ...
    other_key, other_cert = make_ca("Rogue CA", "Rogue")               # ... but the leaf is signed by another
    key, cert = make_leaf(other_key, other_cert, "rogue.test", ["rogue.test"])
    async with tls_server(tmp_path, key, cert) as port:
        t = (await _client(port, "rogue.test", ca_path, fake_dns).lookup("rogue.test")).data
    assert t.chain_valid is False and t.verify_error == "unknown_issuer" and t.self_signed is False


@pytest.mark.asyncio
async def test_a_certificate_for_another_host_is_a_hostname_mismatch(tmp_path, ca, fake_dns) -> None:
    ca_key, ca_cert, ca_path = ca
    key, cert = make_leaf(ca_key, ca_cert, "other.test", ["other.test"])
    async with tls_server(tmp_path, key, cert) as port:
        t = (await _client(port, "wanted.test", ca_path, fake_dns).lookup("wanted.test")).data
    assert t.chain_valid is False and t.verify_error == "hostname_mismatch"
    assert t.san_matches_host is False and t.san_names == ["other.test"]
    assert tls_cert_valid(t) == 0.0


@pytest.mark.parametrize("host,names,expected", [
    ("example.com", ["example.com"], True),
    ("EXAMPLE.com", ["example.COM"], True),
    ("www.example.com", ["*.example.com"], True),
    ("a.b.example.com", ["*.example.com"], False),          # a wildcard covers exactly one label
    ("example.com", ["*.example.com"], False),               # ... and not the bare domain
    ("evilexample.com", ["*.example.com"], False),
    ("xn--bcher-kva.example", ["xn--bcher-kva.example"], True),
    ("example.com", [], False),
    ("example.com", ["*.com"], False),                       # no wildcard directly on a TLD
    ("example.com.", ["example.com"], True),
])
def test_host_matching_follows_rfc_6125(host, names, expected) -> None:
    assert host_matches(host, names) is expected


# ── hosts that are not (properly) TLS ───────────────────────────────────────
@pytest.mark.asyncio
async def test_a_server_that_speaks_plain_http_on_the_port_has_no_tls(fake_dns) -> None:
    async def handle(reader, writer):
        await reader.read(10)
        writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        await writer.drain(); writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        res = await _client(port, "plain.test", None, fake_dns).lookup("plain.test")
    finally:
        server.close()
    assert res.ok and res.data.has_tls is False and tls_cert_valid(res.data) == 0.0


@pytest.mark.asyncio
async def test_a_closed_port_means_no_tls_not_an_error(fake_dns) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]            # nothing listens here any more
    res = await _client(port, "closed.test", None, fake_dns).lookup("closed.test")
    assert res.ok and res.data.has_tls is False


@pytest.mark.asyncio
async def test_a_server_that_never_answers_is_a_timeout_error_not_invalid_tls(fake_dns) -> None:
    async def hang(reader, writer):
        await asyncio.sleep(30)
    server = await asyncio.start_server(hang, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    fake_dns.set("hang.test", "127.0.0.1")
    policy = FetchPolicy(allowed_ports=None, allow_private=frozenset({("hang.test", port)}))
    try:
        res = await TlsClient(use_mock=False, policy=policy, port=port, timeout=0.4).lookup("hang.test")
    finally:
        server.close()
    assert res.status == ProviderStatus.ERROR and res.reason == "timeout" and res.data is None
    assert tls_cert_valid(res.data) is None, "unknown, never 0 or 1"


# ── safety, privacy, caching ────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_host_resolving_to_an_internal_address_is_never_connected_to(fake_dns) -> None:
    fake_dns.set("sneaky.example.com", "10.0.0.5")
    client = TlsClient(use_mock=False, policy=FetchPolicy(allowed_ports=None), timeout=1.0)
    res = await client.lookup("sneaky.example.com")
    assert res.status == ProviderStatus.ERROR and res.reason.startswith("blocked"), res.reason


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["printer.local", "files.corp.lan", "localhost", "10.0.0.5", "8.8.8.8", "intranet"])
async def test_private_names_and_ip_literals_are_not_probed(name) -> None:
    res = await TlsClient(use_mock=False, policy=FetchPolicy(allowed_ports=None)).lookup(name)
    assert res.status == ProviderStatus.SKIPPED


@pytest.mark.asyncio
async def test_answers_are_cached_and_failures_are_not(tmp_path, ca, fake_dns) -> None:
    ca_key, ca_cert, ca_path = ca
    key, cert = make_leaf(ca_key, ca_cert, "cache.test", ["cache.test"])
    hits: list[int] = []
    async with tls_server(tmp_path, key, cert, counter=hits) as port:
        client = _client(port, "cache.test", ca_path, fake_dns, cache=ProviderCache())
        first = await client.lookup("cache.test")
        second = await client.lookup("cache.test")
    assert len(hits) == 1 and second.cached is True and second.fetched_at == first.fetched_at and second.data == first.data
    assert abs(days_to_expiry(second.data, NOW + dt.timedelta(days=10)) - 80) < 1, "a cached record keeps ageing"

    async def hang(reader, writer):
        await asyncio.sleep(30)
    server = await asyncio.start_server(hang, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    fake_dns.set("flaky.test", "127.0.0.1")
    policy = FetchPolicy(allowed_ports=None, allow_private=frozenset({("flaky.test", port)}))
    cache = ProviderCache()
    try:
        c = TlsClient(use_mock=False, policy=policy, port=port, timeout=0.3, cache=cache)
        await c.lookup("flaky.test")
    finally:
        server.close()
    assert await cache.count() == 0


@pytest.mark.asyncio
async def test_mock_mode_is_deterministic_labelled_and_tells_good_from_bad() -> None:
    client = TlsClient(use_mock=True, clock=lambda: NOW)
    good, bad, bad2 = await client.lookup("www.google.com"), await client.lookup("evil-login.com"), await client.lookup("evil-login.com")
    assert good.mock and bad.mock and bad.data == bad2.data
    assert tls_cert_valid(good.data) == 1.0 and tls_cert_valid(bad.data) == 0.0


def test_derived_values_are_unknown_not_zero_without_a_certificate() -> None:
    from app.models.schemas import TlsInfo
    t = TlsInfo(host="x.test", has_tls=False)
    assert days_to_expiry(t) is None and cert_age_days(t) is None
    assert tls_cert_valid(t) == 0.0 and tls_cert_valid(None) is None
