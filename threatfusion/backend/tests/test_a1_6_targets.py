"""A1-6 — one input canonicaliser (``core/targets.py``).

Audit §H2/§C: every component re-parsed the raw string its own way — ``scan.py`` split on ``/`` and ``:``,
validation stripped ``www.``, the VirusTotal client interpolated whatever it was given, IPs were sent to the
*domain* endpoint and IP/hash targets were never validated at all.  ``canonicalize(raw)`` now produces one
``Target`` (kind, ASCII host, registered domain, IP, port, hash, public URL …) that every component consumes.

The table below covers scheme / ``www.`` / trailing dot / IDN / IPv6 / case / ports / legacy numeric IPv4 /
junk input.  No network is used: the Public Suffix List is the offline snapshot bundled with ``tldextract``.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest
import respx

from app.core.targets import Target, canonicalize
from app.models.schemas import TargetType
from tests.conftest import mock_site

D, U, I, H = TargetType.DOMAIN, TargetType.URL, TargetType.IP, TargetType.FILE_HASH


# ── Domains ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,host,registered,sub", [
    ("Example.COM", "example.com", "example.com", ""),
    ("www.example.com", "www.example.com", "example.com", "www"),
    ("example.com.", "example.com", "example.com", ""),                      # trailing dot
    ("  example.com  ", "example.com", "example.com", ""),                   # whitespace around
    ("a.b.c.example.org", "a.b.c.example.org", "example.org", "a.b.c"),
    ("sub.example.co.uk", "sub.example.co.uk", "example.co.uk", "sub"),       # multi-label public suffix
    ("foo.github.io", "foo.github.io", "github.io", "foo"),
    ("bücher.example", "xn--bcher-kva.example", None, "xn--bcher-kva"),                    # IDN -> punycode
    ("BÜCHER.de", "xn--bcher-kva.de", "xn--bcher-kva.de", ""),
    ("xn--bcher-kva.de", "xn--bcher-kva.de", "xn--bcher-kva.de", ""),
    ("localhost", "localhost", None, ""),
    ("printer.local", "printer.local", None, "printer"),
])
def test_domain_variants(raw, host, registered, sub) -> None:
    t = canonicalize(raw, D)
    assert t.valid, t.problem
    assert (t.kind, t.host, t.registered_domain, t.subdomain) == (D, host, registered, sub)
    assert t.ip is None and t.url_full is None, "a domain target has no URL"


@pytest.mark.parametrize("raw,host,port", [
    ("https://example.com/a/b?x=1#frag", "example.com", None),               # typed as a URL, scanned as a domain
    ("HTTP://EXAMPLE.com:8080/x", "example.com", 8080),
    ("example.com:8443/path", "example.com", 8443),
    ("user:pw@example.com", "example.com", None),
])
def test_a_domain_typed_as_a_url_is_reduced_to_its_host(raw, host, port) -> None:
    t = canonicalize(raw, D)
    assert t.valid and t.kind == D and t.host == host and t.port == port
    assert t.path == "" or t.url_full is None


def test_userinfo_is_flagged_and_never_kept() -> None:
    t = canonicalize("https://user:secret@example.com/p?q=1", U)
    assert t.has_userinfo is True
    assert "secret" not in (t.url_full or "") and "secret" not in (t.url_public or "")


# ── URLs ────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,full,public,host,path,query", [
    ("https://Example.com/Login?token=abc#frag", "https://example.com/Login?token=abc", "https://example.com/Login",
     "example.com", "/Login", "token=abc"),
    ("example.com/login", "https://example.com/login", "https://example.com/login", "example.com", "/login", ""),
    ("http://example.com:80/x", "http://example.com/x", "http://example.com/x", "example.com", "/x", ""),      # default port dropped
    ("https://example.com:443/", "https://example.com/", "https://example.com/", "example.com", "/", ""),
    ("https://example.com", "https://example.com/", "https://example.com/", "example.com", "/", ""),           # empty path -> "/"
    ("https://example.com:8443/a", "https://example.com:8443/a", "https://example.com:8443/a", "example.com", "/a", ""),
    ("HTTP://EXAMPLE.COM/A%20B", "http://example.com/A%20B", "http://example.com/A%20B", "example.com", "/A%20B", ""),
    ("https://[2001:DB8::1]:8443/x", "https://[2001:db8::1]:8443/x", "https://[2001:db8::1]:8443/x", "2001:db8::1", "/x", ""),
    ("https://bücher.example/straße?q=1", "https://xn--bcher-kva.example/straße?q=1",
     "https://xn--bcher-kva.example/straße", "xn--bcher-kva.example", "/straße", "q=1"),
    ("https://www.example.com./x", "https://www.example.com/x", "https://www.example.com/x", "www.example.com", "/x", ""),
])
def test_url_variants(raw, full, public, host, path, query) -> None:
    t = canonicalize(raw, U)
    assert t.valid, t.problem
    assert (t.kind, t.url_full, t.url_public, t.host, t.path, t.query) == (U, full, public, host, path, query)


def test_the_public_url_never_contains_query_fragment_or_credentials() -> None:
    t = canonicalize("https://u:p@example.com:8443/reset?token=SECRET&sid=1#frag", U)
    assert t.url_public == "https://example.com:8443/reset"
    assert all(s not in t.url_public for s in ("SECRET", "sid", "frag", "u:p", "@"))


@pytest.mark.parametrize("raw,problem", [
    ("ftp://example.com/x", "unsupported_scheme"),
    ("javascript:alert(1)", "unsupported_scheme"),
    ("file:///etc/passwd", "unsupported_scheme"),
    ("data:text/html,<script>", "unsupported_scheme"),
    ("https:///nohost", "empty_host"),
    ("https://exa mple.com/", "whitespace"),
    ("https://example.com:99999/", "invalid_port"),
    ("https://a..com/", "invalid_hostname"),
])
def test_unsafe_or_malformed_urls_are_invalid(raw, problem) -> None:
    t = canonicalize(raw, U)
    assert not t.valid and t.problem == problem
    assert t.url_full is None and t.url_public is None


# ── IP addresses ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("8.8.8.8", "8.8.8.8"),
    ("2130706433", "127.0.0.1"),            # legacy numeric spellings are normalised, not trusted
    ("0x7f.1", "127.0.0.1"),
    ("0177.0.0.1", "127.0.0.1"),
    ("::1", "::1"),
    ("[::1]", "::1"),
    ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
    ("::ffff:1.2.3.4", str(ipaddress.ip_address("::ffff:1.2.3.4"))),
    ("1.2.3.4:80", "1.2.3.4"),
])
def test_ip_variants(raw, expected) -> None:
    t = canonicalize(raw, I)
    assert t.valid and t.kind == I and t.ip == expected and t.host == expected and t.registered_domain is None


@pytest.mark.parametrize("raw", ["999.1.1.1", "example.com", "hello", "1.2.3.4.5", "1.2.3.4/8"])
def test_invalid_ip_targets_are_rejected(raw) -> None:
    t = canonicalize(raw, I)
    assert not t.valid and t.problem == "invalid_ip"


def test_a_domain_target_that_is_really_an_ip_is_flagged() -> None:
    t = canonicalize("8.8.8.8", D)
    assert t.kind == I and not t.valid and t.problem == "declared_domain_is_ip"


# ── File hashes ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,kind", [
    ("D41D8CD98F00B204E9800998ECF8427E", "md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
    ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "sha256"),
])
def test_hash_variants_are_lowercased_and_typed(raw, kind) -> None:
    t = canonicalize(raw, H)
    assert t.valid and t.kind == H and t.hash == raw.lower() and t.hash_type == kind and t.host is None


@pytest.mark.parametrize("raw", ["xyz", "d41d8cd98f00b204e9800998ecf8427", "g" * 32, "d41d8cd9-8f00-b204-e980-0998ecf8427e", "a" * 65])
def test_invalid_hashes_are_rejected(raw) -> None:
    t = canonicalize(raw, H)
    assert not t.valid and t.problem == "invalid_hash"


# ── Auto-detection (no declared type) ───────────────────────────────────────
@pytest.mark.parametrize("raw,kind", [
    ("8.8.8.8", I), ("::1", I), ("example.com", D), ("www.example.com", D),
    ("https://example.com/x", U), ("example.com/login", U), ("example.com?x=1", U),
    ("d41d8cd98f00b204e9800998ecf8427e", H),
])
def test_kind_is_detected_when_not_declared(raw, kind) -> None:
    assert canonicalize(raw).kind == kind


# ── Junk ────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,problem", [
    ("", "empty"), ("   ", "empty"), ("example.com\x00", "control_characters"), ("exa\nmple.com", "control_characters"),
    ("exa mple.com", "whitespace"), ("a" * 64 + ".com", "invalid_hostname"), ("-a.com", "invalid_hostname"),
    ("a%2fb.com", "invalid_hostname"),
])
def test_junk_is_rejected_with_a_machine_readable_problem(raw, problem) -> None:
    t = canonicalize(raw, D)
    assert not t.valid and t.problem == problem


def test_non_string_input_is_invalid_not_an_exception() -> None:
    assert not canonicalize(None).valid  # type: ignore[arg-type]


def test_canonicalisation_is_idempotent() -> None:
    for raw, declared in [("BÜCHER.de.", D), ("HTTPS://Example.com:443/A?b=1#c", U), ("2130706433", I), ("D41D8CD98F00B204E9800998ECF8427E", H)]:
        once = canonicalize(raw, declared)
        again = canonicalize(once.url_full or once.ip or once.hash or once.host, declared)
        assert (once.host, once.ip, once.hash, once.url_full) == (again.host, again.ip, again.hash, again.url_full), raw


def test_outbound_block_reason_reuses_the_privacy_rules() -> None:
    assert canonicalize("printer.local", D).outbound_block_reason() == "private_name"
    assert canonicalize("10.0.0.5", I).outbound_block_reason() == "private_address"
    assert canonicalize("example.com", D).outbound_block_reason() is None
    assert canonicalize("d41d8cd98f00b204e9800998ecf8427e", H).outbound_block_reason() is None  # hashes are not hosts


def test_the_public_suffix_list_is_never_fetched(monkeypatch: pytest.MonkeyPatch) -> None:
    """Canonicalisation must work offline (and must not leak lookups): block every socket."""
    def no_net(*a, **k):
        raise AssertionError("canonicalize() attempted network access")
    monkeypatch.setattr(socket.socket, "connect", no_net)
    import app.core.targets as targets
    targets._extractor.cache_clear()          # force a fresh extractor
    assert canonicalize("a.b.example.co.uk", D).registered_domain == "example.co.uk"


# ── /scan consumes the canonical Target ─────────────────────────────────────
@pytest.fixture
def live_scan(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation
    from fastapi.testclient import TestClient
    from app.core.config import get_settings
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1000")
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    yield TestClient(app)
    get_settings.cache_clear()


def _vt_urls(router) -> list[str]:
    return [str(c.request.url) for c in router.calls if "virustotal.com" in str(c.request.url)]


def test_scan_sends_the_canonical_host_to_virustotal_and_reports_it(live_scan) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        mock_site(router, "xn--bcher-kva.example", text="<html></html>")
        res = live_scan.post("/scan", json={"target": "BÜCHER.example.", "target_type": "domain"}).json()["result"]
        urls = _vt_urls(router)
    assert urls == ["https://www.virustotal.com/api/v3/domains/xn--bcher-kva.example"]
    assert res["canonical"]["host"] == "xn--bcher-kva.example" and res["canonical"]["kind"] == "domain"


def test_a_domain_typed_as_a_url_reaches_providers_as_the_bare_host(live_scan) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        mock_site(router, "example.com", text="<html></html>")
        live_scan.post("/scan", json={"target": "https://Example.com/a?b=1", "target_type": "domain"})
        urls = _vt_urls(router)
    assert urls == ["https://www.virustotal.com/api/v3/domains/example.com"]


def test_url_scan_reports_the_canonical_public_url_without_secrets(live_scan) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        mock_site(router, "www.example.com", text="<html></html>", path="/Login")
        res = live_scan.post("/scan", json={"target": "HTTPS://WWW.Example.COM:443/Login?token=SECRET#f", "target_type": "url"}).json()["result"]
    c = res["canonical"]
    assert (c["host"], c["registered_domain"], c["url"]) == ("www.example.com", "example.com", "https://www.example.com/Login")
    assert "SECRET" not in str(c)


@pytest.mark.parametrize("target,ttype", [("999.1.1.1", "ip"), ("example.com", "ip"), ("not-a-hash", "file_hash"), ("d41d8cd9", "file_hash")])
def test_invalid_ip_and_hash_targets_are_refused_before_any_provider_is_called(live_scan, target, ttype) -> None:
    with respx.mock(assert_all_called=False) as router:
        r = live_scan.post("/scan", json={"target": target, "target_type": ttype})
        assert len(router.calls) == 0
    assert r.status_code == 400 and r.json()["success"] is False and r.json()["stage"] == "format"


def test_hash_scans_use_the_lowercased_hash(live_scan) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        live_scan.post("/scan", json={"target": "D41D8CD98F00B204E9800998ECF8427E", "target_type": "file_hash"})
        urls = _vt_urls(router)
    assert urls == ["https://www.virustotal.com/api/v3/files/d41d8cd98f00b204e9800998ecf8427e"]
