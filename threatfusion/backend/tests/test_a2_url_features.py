"""A2-1/A2-3 — the URL canonical form and the offline URL features.

The audit: the URL model scored ``https://x`` 0.99 and ``x`` 0.13.  The canonical form makes the learned models blind to the
scheme and a leading ``www.`` *by construction*; the features are computed from that form, so they are invariant too.  Also
checked: no feature leaks a label source (no popularity rank, no blocklist membership), features are finite, fast and
deterministic, and the brand features agree with the B4 detector.
"""

from __future__ import annotations

import math
import time

import pytest

from app.ml.url_canon import canonical_url_text, hostname_of, split_canonical
from app.ml.url_features import FEATURE_GROUPS, FEATURE_NAMES, URL_FEATURE_SCHEMA_VERSION, extract_url_features, feature_row


# ── canonical form ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("https://www.Example.COM/Login?X=1", "example.com/Login?X=1"),            # host lower-cased, path/query keep case
    ("http://example.com", "example.com"),
    ("example.com/", "example.com"),                                         # a lone trailing slash is not information
    ("HTTPS://WWW.EXAMPLE.COM:8443/a#Frag", "example.com:8443/a#Frag"),
    ("ftp://user:pw@Host.example/x", "user:pw@host.example/x"),
    ("https://paypal.com@evil.example/signin", "paypal.com@evil.example/signin"),   # the deception stays visible
    ("  https://example.com/a b  ", "example.com/a b"),
    ("www.example.com", "example.com"),
    ("www.", "www."),                                                        # nothing left to strip
    ("", ""),
])
def test_canonical_form(raw, expected) -> None:
    assert canonical_url_text(raw) == expected


def test_scheme_and_www_variants_collapse_to_one_string() -> None:
    variants = ["https://www.evil-login.example.com/a/b?x=1", "http://www.evil-login.example.com/a/b?x=1",
                "https://evil-login.example.com/a/b?x=1", "evil-login.example.com/a/b?x=1", "HTTPS://WWW.EVIL-LOGIN.EXAMPLE.COM/a/b?x=1"]
    assert len({canonical_url_text(v) for v in variants}) == 1


def test_split_and_hostname() -> None:
    assert split_canonical("https://www.a.example.com:81/p?q") == ("a.example.com:81", "/p?q")
    assert hostname_of("https://user@Www.A.Example.com:81/p") == "a.example.com"
    assert hostname_of("http://[2001:db8::1]:8080/x") == "[2001:db8::1]"
    assert hostname_of("") == ""


def test_canonicalisation_is_idempotent() -> None:
    for raw in ["https://www.Example.com/A?b=C", "paypal.com@evil.example", "example.com", ""]:
        once = canonical_url_text(raw)
        assert canonical_url_text(once) == once


# ── features ────────────────────────────────────────────────────────────────
def test_feature_names_groups_and_version_are_consistent() -> None:
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)) >= 35
    assert set(FEATURE_GROUPS) == set(FEATURE_NAMES)
    assert set(FEATURE_GROUPS.values()) == {"surface", "host", "path", "risk", "brand"}
    assert URL_FEATURE_SCHEMA_VERSION == 1


def test_features_are_scheme_and_www_invariant() -> None:
    base = extract_url_features("https://www.secure-login.example.com/verify/account?id=42")
    for variant in ["http://secure-login.example.com/verify/account?id=42", "SECURE-LOGIN.EXAMPLE.COM/verify/account?id=42"]:
        assert extract_url_features(variant) == base


def test_features_are_finite_and_in_order() -> None:
    for raw in ["", "x", "https://", "http://[::1]:80/", "xn--pypal-4ve.com", "a" * 3000, "http://1.2.3.4/a/b/c.php?x=1&y=2",
                "https://user@host.example:99/p#f", "‮\u0000weird"]:
        row = feature_row(raw)
        assert len(row) == len(FEATURE_NAMES) and all(math.isfinite(v) for v in row), raw


def test_structure_features() -> None:
    f = extract_url_features("https://a.b.paypa1-secure.co.uk:8080/Login/verify.php?x=1&y=2")
    assert f["subdomain_depth"] == 2 and f["host_hyphens"] == 1 and f["host_has_port"] == 1 and f["tld_len"] == 5
    assert f["path_segments"] == 2 and f["path_has_extension"] == 1 and f["query_params"] == 2 and f["risk_words_path"] >= 2
    ip = extract_url_features("http://203.0.113.9/x")
    assert ip["host_is_ip"] == 1 and ip["subdomain_depth"] == 0
    assert extract_url_features("user@evil.example/x")["host_has_userinfo"] == 1
    assert extract_url_features("xn--pypal-4ve.com")["host_is_punycode"] == 1
    assert extract_url_features("pаypal.com")["host_mixed_script"] == 1


def test_brand_features_follow_the_b4_detector() -> None:
    fake = extract_url_features("https://paypa1-secure.com/signin")
    assert fake["lookalike_flagged"] == 1 and fake["lookalike_score"] >= 0.9 and fake["brand_keyword"] == 1 and fake["is_official_domain"] == 0
    sub = extract_url_features("https://paypal.com.account-verify.info/")
    assert sub["brand_in_subdomain"] == 1 and sub["lookalike_flagged"] == 1
    real = extract_url_features("https://www.paypal.com/us/signin")
    assert real["is_official_domain"] == 1 and real["lookalike_flagged"] == 0 and real["brand_in_path"] == 0
    path_brand = extract_url_features("https://random-host.example/paypal/login")
    assert path_brand["brand_in_path"] == 1 and path_brand["lookalike_flagged"] == 0
    plain = extract_url_features("https://wikipedia.org/wiki/Cat")
    assert plain["lookalike_flagged"] == 0 and plain["brand_in_path"] == 0


def test_no_feature_encodes_a_label_source() -> None:
    banned = ("rank", "tranco", "popular", "blocklist", "listed", "openphish", "phishtank", "https", "scheme", "www")
    assert not [n for n in FEATURE_NAMES if any(b in n for b in banned)], "a feature that a label feed also supplies would leak"


def test_extraction_is_deterministic_and_fast() -> None:
    urls = ["https://paypa1-secure.com/signin", "https://www.example.org/a/b/c?d=e", "http://203.0.113.9/x.php",
            "https://login.hdfcbank.com.verify-account.top/netbanking"]
    first = [extract_url_features(u) for u in urls]
    assert first == [extract_url_features(u) for u in urls]
    t0 = time.perf_counter()
    for _ in range(50):
        for u in urls:
            extract_url_features(u)
    per_call_ms = (time.perf_counter() - t0) * 1000 / (50 * len(urls))
    assert per_call_ms < 5, f"{per_call_ms:.2f} ms per URL"
