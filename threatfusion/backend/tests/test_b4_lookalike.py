"""B4 (detector) — is this domain impersonating a protected brand?

Protected brands = a curated list (global + a curated India list: banks, UPI apps, IRCTC, India Post, UIDAI, Income Tax,
EPFO, DigiLocker, e-commerce, telecom) plus, optionally, the top of the Tranco popularity list.  A scanned host is compared
with each brand on its **registered label** after Unicode-confusable normalisation (TR39 skeleton, leetspeak, ``rn`` → ``m``),
by edit distance, and for "brand + keyword" patterns; a brand name in a *subdomain* of an unrelated registered domain
(``paypal.com.secure-login.xyz``) is caught too.  The result is ``lookalike_of`` — the matched brand, the kind of trick and
a similarity — with the evidence that produced it.  Genuine brand domains (and their subdomains) are never flagged.
"""

from __future__ import annotations

import time

import pytest

from app.ml.brands import CURATED_BRANDS, Brand, BrandIndex, edit_distance
from app.ml.lookalike import assess_lookalike

INDEX = BrandIndex.build()


def check(host: str, index: BrandIndex = INDEX, **kw):
    return assess_lookalike(host, index, **kw)


# ── edit distance ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("a,b,d", [
    ("paypal", "paypal", 0), ("paypal", "paypall", 1), ("paypal", "paypa", 1), ("paypal", "pyapal", 1),   # transposition = 1
    ("paypal", "peypel", 2), ("kitten", "sitting", 3), ("", "abc", 3), ("abc", "", 3),
])
def test_damerau_levenshtein(a, b, d) -> None:
    assert edit_distance(a, b, max_distance=10) == d


def test_edit_distance_gives_up_early_beyond_the_limit() -> None:
    assert edit_distance("paypal", "completelydifferent", max_distance=2) == 3, "returns limit + 1, not the exact value"
    assert edit_distance("abcdef", "abcdeg", max_distance=0) == 1


# ── the brand list ──────────────────────────────────────────────────────────
def test_the_curated_list_covers_global_and_india_brands() -> None:
    keys = {b.key for b in CURATED_BRANDS}
    assert {"paypal", "google", "microsoft", "amazon", "netflix"} <= keys
    india = {b.key for b in CURATED_BRANDS if b.country == "IN"}
    assert {"hdfcbank", "icicibank", "sbi", "axisbank", "paytm", "phonepe", "irctc", "indiapost", "uidai", "incometax",
            "epfo", "digilocker", "flipkart", "airtel", "jio"} <= india
    assert len(CURATED_BRANDS) >= 100
    assert all(b.domains for b in CURATED_BRANDS), "every brand has at least one official domain"
    assert len({b.key for b in CURATED_BRANDS}) == len(CURATED_BRANDS), "keys are unique"


# ── look-alike kinds ────────────────────────────────────────────────────────
@pytest.mark.parametrize("host,brand,kind", [
    ("xn--pypal-4ve.com", "PayPal", "homoglyph"),                  # pаypal (Cyrillic а) as punycode
    ("gооgle.com", "Google", "homoglyph"),               # gооgle with Cyrillic о о
    ("paypa1.com", "PayPal", "leetspeak"),
    ("netfl1x.com", "Netflix", "leetspeak"),
    ("micr0s0ft.com", "Microsoft", "leetspeak"),
    ("g00gle.com", "Google", "leetspeak"),
    ("faceb00k.com", "Facebook", "leetspeak"),
    ("arnazon.com", "Amazon", "leetspeak"),                        # rn -> m (sequence stage)
    ("hdfcbank.co", "HDFC Bank", "same_name_other_tld"),
    ("paypall.com", "PayPal", "typo"),
    ("paypaI.com", "PayPal", "typo"),                              # (DNS lowercases: paypai, one character off)
    ("amazom.com", "Amazon", "typo"),
    ("pay-pal.com", "PayPal", "separator"),
    ("icicibannk.com", "ICICI Bank", "typo"),
    ("paypal-secure.com", "PayPal", "brand_keyword"),
    ("secure-paypal.com", "PayPal", "brand_keyword"),
    ("paypalsupport.net", "PayPal", "brand_keyword"),
    ("hdfcbank-login.com", "HDFC Bank", "brand_keyword"),
    ("sbi-kyc-update.in", "State Bank of India", "brand_keyword"),
    ("irctc-ticket-booking.com", "IRCTC", "brand_keyword"),
    ("uidai-aadhaar-verify.com", "UIDAI (Aadhaar)", "brand_keyword"),
    ("incometax-refund.in", "Income Tax Department", "brand_keyword"),
    ("paytm-wallet-kyc.com", "Paytm", "brand_keyword"),
    ("paypal.com.secure-login.xyz", "PayPal", "brand_in_subdomain"),
    ("login.hdfcbank.com.verify-account.top", "HDFC Bank", "brand_in_subdomain"),
    ("www.amazon.in.deals-today.shop", "Amazon", "brand_in_subdomain"),
])
def test_lookalikes_are_found_with_the_right_kind(host, brand, kind) -> None:
    r = check(host)
    assert r.status in ("lookalike", "no_match"), r
    m = r.match or (r.candidates[0] if r.candidates else None)
    assert m is not None, f"{host}: nothing matched"
    assert (m.brand, m.kind) == (brand, kind), (host, m.brand, m.kind, m.similarity)
    if kind != "same_name_other_tld":
        assert r.status == "lookalike" and m.similarity >= 0.80, (host, m.similarity)
    assert m.evidence, "every match explains itself"


def test_same_name_on_another_tld_is_noted_but_not_flagged_on_its_own() -> None:
    """``hdfcbank.co`` may be a defensive registration: shown as a candidate, below the flagging threshold."""
    r = check("hdfcbank.co")
    assert r.status == "no_match" and r.match is None
    assert r.candidates[0].kind == "same_name_other_tld" and r.candidates[0].similarity < 0.80


def test_the_match_carries_the_official_domain_and_evidence() -> None:
    m = check("paypa1-secure.com").match
    assert m.brand == "PayPal" and m.brand_domain == "paypal.com" and m.source == "curated" and m.sector == "payments"
    joined = " ".join(m.evidence)
    assert "paypal" in joined and ("'1'" in joined or "1" in joined) and "secure" in joined


def test_mixed_script_hosts_are_marked() -> None:
    assert check("pаypal.com").match.mixed_script is True
    assert check("paypa1.com").match.mixed_script is False


# ── genuine domains are never flagged ───────────────────────────────────────
@pytest.mark.parametrize("host,brand", [
    ("paypal.com", "PayPal"), ("www.paypal.com", "PayPal"), ("accounts.google.com", "Google"),
    ("netbanking.hdfcbank.com", "HDFC Bank"), ("www.onlinesbi.sbi", "State Bank of India"),
    ("www.irctc.co.in", "IRCTC"), ("myaadhaar.uidai.gov.in", "UIDAI (Aadhaar)"), ("www.incometax.gov.in", "Income Tax Department"),
    ("amazon.in", "Amazon"), ("smile.amazon.com", "Amazon"), ("login.microsoftonline.com", "Microsoft"),
    ("web.whatsapp.com", "WhatsApp"), ("www.flipkart.com", "Flipkart"), ("paytm.com", "Paytm"),
])
def test_official_domains_and_their_subdomains_are_not_lookalikes(host, brand) -> None:
    r = check(host)
    assert r.status == "official" and r.official_of == brand and r.match is None


def test_unrelated_domains_are_not_flagged() -> None:
    for host in ["example.org", "wikipedia.org", "gitlab.com", "my-bakery.in", "kittens.example.com", "blog.rust-lang.org",
                 "openstreetmap.org", "tailscale.com", "stripe.com", "python.org"]:
        r = check(host)
        assert r.status == "no_match" and r.match is None, (host, r.match)


def test_government_suffixes_cannot_be_registered_by_attackers() -> None:
    r = check("someministry.gov.in")
    assert r.status == "official" and "government" in " ".join(r.notes).lower()


def test_plain_containment_without_a_risk_word_is_only_a_candidate() -> None:
    r = check("applesauce-recipes.com")
    assert r.status == "no_match", "an ordinary word that happens to contain a brand name is not impersonation"
    assert any(c.kind == "contains_brand" and c.similarity < 0.80 for c in r.candidates)


def test_short_brand_names_do_not_match_inside_other_words() -> None:
    for host in ["classics.com", "lickety.com", "jiotech-blog.com", "sbirthday.com"]:
        r = check(host)
        assert r.match is None, (host, r.match)


def test_short_brands_still_match_as_a_standalone_token_with_a_risk_word() -> None:
    assert check("sbi-login.com").match.brand == "State Bank of India"
    assert check("jio-recharge-offer.com").match.brand in ("Jio", "Reliance Jio")


# ── thresholds & output shape ───────────────────────────────────────────────
def test_the_threshold_is_configurable_and_reported() -> None:
    strict = check("paypall.com", threshold=0.95)
    assert strict.status == "no_match" and strict.threshold == 0.95 and strict.candidates
    lenient = check("hdfcbank.co", threshold=0.6)
    assert lenient.status == "lookalike" and lenient.match.kind == "same_name_other_tld"


def test_coverage_is_part_of_the_answer() -> None:
    r = check("example.org")
    assert r.brands_checked == len(CURATED_BRANDS) and r.popular_checked == 0


def test_ips_and_junk_hosts_are_not_assessable() -> None:
    for host in ["8.8.8.8", "", "localhost", "::1"]:
        r = check(host)
        assert r.status == "no_match" and r.match is None


def test_results_are_deterministic() -> None:
    a, b = check("paypa1-secure.com"), check("paypa1-secure.com")
    assert a.model_dump() == b.model_dump()


# ── popular (Tranco-style) brands ───────────────────────────────────────────
def test_popular_domains_extend_the_list_for_typosquats_but_not_for_containment() -> None:
    idx = BrandIndex.build(popular=[("weatherunderground.com", 800), ("kaggle.com", 900), ("stackoverflow.com", 120)])
    typo = check("stackoverfiow.com", idx)
    assert typo.status == "lookalike" and typo.match.source == "popular" and typo.match.kind in ("typo", "leetspeak")
    assert check("mystackoverflowblog.com", idx).match is None, "no containment matching for non-curated brands"
    assert idx.stats() == {"curated": len(CURATED_BRANDS), "popular": 3}


def test_a_popular_domain_that_is_already_a_curated_brand_is_not_duplicated() -> None:
    idx = BrandIndex.build(popular=[("paypal.com", 40), ("example-popular-site.com", 50)])
    assert idx.stats()["popular"] == 1


def test_popular_matching_is_conservative_to_limit_false_positives() -> None:
    idx = BrandIndex.build(popular=[("weather.com", 300), ("blog.com", 400), ("steam.com", 500)])
    for host in ["weathers.com", "blogs.com", "steams.com", "blog.org"]:
        assert check(host, idx).match is None, host            # short / ordinary words: only exact-skeleton tricks count


def test_a_custom_brand_works() -> None:
    idx = BrandIndex([Brand(key="acmebank", name="Acme Bank", domains=("acmebank.example",), sector="bank", country=None)])
    assert check("acmebank-login.com", idx).match.brand == "Acme Bank"
    assert check("acmebank.example", idx).status == "official"


# ── speed: this runs in the fast tier ───────────────────────────────────────
def test_assessment_is_fast_even_with_thousands_of_popular_brands() -> None:
    popular = [(f"popular-site-{i:05d}.com", i + 1) for i in range(5000)]
    idx = BrandIndex.build(popular=popular)
    hosts = ["paypa1-secure.com", "example.org", "login.hdfcbank.com.verify-account.top", "popular-site-0042x.com",
             "my-long-ordinary-domain-name.co.in", "xn--pypal-4ve.com"]
    check("warmup.com", idx)
    t0 = time.perf_counter()
    for _ in range(20):
        for h in hosts:
            check(h, idx)
    per_call_ms = (time.perf_counter() - t0) * 1000 / (20 * len(hosts))
    assert per_call_ms < 25, f"{per_call_ms:.1f} ms per assessment"
