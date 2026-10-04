"""A1-4 — technology / end-of-life accuracy.

Audit P1-4: ``EOL_SET`` was six hard-coded strings (``"jQuery 1"``, ``"PHP 5"``, … — WordPress was not even in
it, so ``tech_has_eol_cms_version`` could never be 1); every technology got ``confidence=100``; the shared
Wappalyzer instance leaked detected *versions* from one page into the next; the library's bundled fingerprint
data (1,270 technologies) was used while the repo's own newer ``wappalyzer_tech.json`` (3,965) sat unused;
and loading the data printed a flood of regex warnings.

Acceptance: *old WordPress / PHP 5.x / AngularJS 1.x fixtures are flagged as end-of-life.*  endoflife.date is
mocked with respx (fixtures shaped like its API); the fingerprinting runs on the real Wappalyzer data.
"""

from __future__ import annotations

import asyncio
import json
import warnings
from datetime import date

import httpx
import pytest
import respx

from app.core.cache import ProviderCache
from app.core.safe_http import FetchPolicy
from app.ingestion import techfingerprint as tf
from app.ingestion.eol import (EOL_SLUGS, EolClient, apply_eol, assessable, evaluate, parse_product, slug_for)
from app.ingestion.techfingerprint import TechFingerprintClient
from app.ml.features import extract_features_with_coverage
from app.models.schemas import DetectedTechnology, ProviderStatus, TechFingerprintResult
from tests.conftest import mock_site

TODAY = date(2026, 10, 4)

WORDPRESS = [{"cycle": "6.8", "eol": False, "latest": "6.8.3"},
             {"cycle": "5.9", "eol": "2022-05-24", "latest": "5.9.12"},
             {"cycle": "4.9", "eol": True, "latest": "4.9.26"}]
PHP = [{"cycle": "8.4", "eol": "2028-12-31", "latest": "8.4.14"},
       {"cycle": "8.1", "eol": "2025-12-31", "latest": "8.1.34"},
       {"cycle": "5.6", "eol": "2018-12-31", "latest": "5.6.40"}]
ANGULARJS = [{"cycle": "1.8", "eol": "2022-01-01", "latest": "1.8.3"}, {"cycle": "1.5", "eol": "2022-01-01", "latest": "1.5.11"}]
JQUERY = [{"cycle": "3", "eol": False, "latest": "3.7.1"}, {"cycle": "2", "eol": True}, {"cycle": "1", "eol": True}]
FIXTURES = {"wordpress": WORDPRESS, "php": PHP, "angularjs": ANGULARJS, "jquery": JQUERY}


def _tech(name, version, *cats) -> DetectedTechnology:
    return DetectedTechnology(name=name, version=version, categories=list(cats) or ["x"], confidence=100)


def _eol_routes(router, fixtures=None, host="endoflife.date"):
    routes = {}
    for slug, doc in (fixtures or FIXTURES).items():
        routes[slug] = mock_site(router, host, path=f"/api/{slug}.json", text=json.dumps(doc),
                                 headers={"content-type": "application/json"})
    return routes


def _client(**kw) -> EolClient:
    return EolClient(use_mock=False, clock=lambda: TODAY, **kw)


# ── mapping & evaluation ────────────────────────────────────────────────────
def test_wappalyzer_names_map_to_endoflife_slugs_case_insensitively() -> None:
    assert slug_for("WordPress") == "wordpress" and slug_for("php") == "php" and slug_for("AngularJS") == "angularjs"
    assert slug_for("Apache HTTP Server") == "apache-http-server" and slug_for("Node.js") == "nodejs"
    assert slug_for("Google Analytics") is None and slug_for("") is None
    assert {"wordpress", "php", "angularjs", "jquery", "drupal", "joomla", "nginx"} <= set(EOL_SLUGS.values())


@pytest.mark.parametrize("version,eol,cycle", [
    ("4.9.8", True, "4.9"),            # flagged: boolean eol
    ("5.9.3", True, "5.9"),            # flagged: EOL date in the past
    ("6.8.1", False, "6.8"),           # supported
    ("v6.8", False, "6.8"),            # leading v
    ("4.9", True, "4.9"),
])
def test_wordpress_versions_are_matched_to_their_release_cycle(version, eol, cycle) -> None:
    v = evaluate(parse_product("wordpress", WORDPRESS), version, TODAY)
    assert (v.eol, v.cycle) == (eol, cycle)


def test_a_future_eol_date_is_still_supported_but_carries_the_date() -> None:
    v = evaluate(parse_product("php", PHP), "8.4.2", TODAY)
    assert v.eol is False and v.eol_date == "2028-12-31" and v.latest == "8.4.14"
    assert evaluate(parse_product("php", PHP), "5.6.40", TODAY).eol is True
    assert evaluate(parse_product("php", PHP), "8.1.27", TODAY).eol is True, "2025-12-31 is in the past on 2026-10-04"


def test_major_only_cycles_match_by_prefix() -> None:
    p = parse_product("jquery", JQUERY)
    assert (evaluate(p, "1.12.4", TODAY).eol, evaluate(p, "2.2.4", TODAY).eol, evaluate(p, "3.6.0", TODAY).eol) == (True, True, False)


@pytest.mark.parametrize("version", ["", "latest", "unknown", "x.y", "0.0.1", "99.1"])
def test_an_unmatchable_version_is_unknown_never_guessed(version) -> None:
    v = evaluate(parse_product("wordpress", WORDPRESS), version, TODAY)
    assert v.eol is None


def test_the_v1_api_shape_is_understood_too() -> None:
    v1 = {"schema_version": "1.2.0", "result": {"name": "php", "releases": [
        {"name": "8.1", "isEol": True, "eolFrom": "2025-12-31", "latest": {"name": "8.1.34"}},
        {"name": "8.4", "isEol": False, "eolFrom": "2028-12-31", "latest": {"name": "8.4.14"}}]}}
    p = parse_product("php", v1)
    assert evaluate(p, "8.1.2", TODAY).eol is True and evaluate(p, "8.4.0", TODAY).eol is False
    with pytest.raises(ValueError):
        parse_product("php", {"unexpected": "shape"})


# ── the client ──────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_old_wordpress_php5_and_angularjs1_are_flagged_end_of_life(fake_dns) -> None:
    techs = [_tech("WordPress", "4.9.8", "CMS"), _tech("PHP", "5.6.40", "Programming languages"),
             _tech("AngularJS", "1.5.8", "JavaScript frameworks"), _tech("jQuery", "3.6.0", "JavaScript libraries")]
    with respx.mock(assert_all_called=False) as router:
        _eol_routes(router)
        res = await _client().assess(techs)
    assert res.ok and res.reason is None
    flags = {k: v.eol for k, v in res.data.items.items()}
    assert flags == {"WordPress": True, "PHP": True, "AngularJS": True, "jQuery": False}
    out = apply_eol(TechFingerprintResult(technologies=techs), res.data)
    assert out.eol_assessed == 4 and [t.eol for t in out.technologies] == [True, True, True, False]
    assert out.technologies[1].eol_date == "2018-12-31" and out.technologies[0].latest_version == "4.9.26"


@pytest.mark.asyncio
async def test_only_versioned_known_products_are_queried_once_each_and_only_slugs_are_sent(fake_dns) -> None:
    techs = [_tech("PHP", "5.6.40"), _tech("PHP", "7.0.1"), _tech("Google Analytics", None), _tech("Nginx", None),
             _tech("Some Unmapped Thing", "1.2.3")]
    assert [t.name for t in assessable(techs)] == ["PHP", "PHP"]
    with respx.mock(assert_all_called=False) as router:
        routes = _eol_routes(router)
        await _client().assess(techs)
        urls = [str(c.request.url) for r in router.calls for c in [r]]
        assert routes["php"].call_count == 1, "two PHP detections, one lookup"
        assert all(u.startswith("https://") for u in urls) and not any("example" in u for u in urls)


@pytest.mark.asyncio
async def test_products_are_cached_for_a_week_and_failures_are_not(fake_dns) -> None:
    cache = ProviderCache()
    client = _client(cache=cache)
    with respx.mock(assert_all_called=False) as router:
        route = mock_site(router, "endoflife.date", path="/api/php.json", text=json.dumps(PHP),
                          headers={"content-type": "application/json"})
        first = await client.assess([_tech("PHP", "5.6.40")])
        second = await client.assess([_tech("PHP", "7.4.1")])
        assert route.call_count == 1 and second.cached is True and first.ok and second.ok

        broken = _client(cache=ProviderCache())
        bad = mock_site(router, "endoflife.date", path="/api/wordpress.json", status=503, text="")
        a = await broken.assess([_tech("WordPress", "4.9.8")])
        b = await broken.assess([_tech("WordPress", "4.9.8")])
        assert bad.call_count == 2, "an error must be retried, not remembered"
    assert a.status == ProviderStatus.ERROR and a.reason == "server_error" and b.status == ProviderStatus.ERROR


@pytest.mark.asyncio
async def test_one_failing_product_leaves_only_that_technology_unknown(fake_dns) -> None:
    techs = [_tech("WordPress", "4.9.8", "CMS"), _tech("PHP", "5.6.40")]
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "endoflife.date", path="/api/wordpress.json", status=503, text="")
        mock_site(router, "endoflife.date", path="/api/php.json", text=json.dumps(PHP),
                  headers={"content-type": "application/json"})
        res = await _client().assess(techs)
    assert res.ok and res.reason == "partial:1/2"
    out = apply_eol(TechFingerprintResult(technologies=techs), res.data)
    assert [t.eol for t in out.technologies] == [None, True] and out.eol_assessed == 1


@pytest.mark.asyncio
async def test_unknown_slug_is_unknown_not_supported(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "endoflife.date", path="/api/wordpress.json", status=404, text="")
        res = await _client().assess([_tech("WordPress", "4.9.8", "CMS")])
    assert res.status == ProviderStatus.NOT_FOUND and res.data is None


@pytest.mark.asyncio
async def test_a_poisoned_base_url_pointing_inside_is_refused(fake_dns) -> None:
    client = _client(base_url="https://169.254.169.254/api")
    res = await client.assess([_tech("PHP", "5.6.40")])
    assert res.status == ProviderStatus.ERROR and res.reason.startswith("blocked")


@pytest.mark.asyncio
async def test_nothing_to_assess_is_skipped_not_ok() -> None:
    res = await _client().assess([_tech("Google Analytics", None)])
    assert res.status == ProviderStatus.SKIPPED and res.reason == "no_assessable_technologies"


@pytest.mark.asyncio
async def test_mock_mode_is_deterministic_and_labelled() -> None:
    client = EolClient(use_mock=True, clock=lambda: TODAY)
    techs = [_tech("WordPress", "4.9.8", "CMS"), _tech("PHP", "8.4.1")]
    a, b = await client.assess(techs), await client.assess(techs)
    assert a.mock and a.data == b.data and a.data.items["WordPress"].eol is True and a.data.items["PHP"].eol is False


# ── features ────────────────────────────────────────────────────────────────
def _eol(name, version, eol, *cats):
    return DetectedTechnology(name=name, version=version, categories=list(cats) or ["x"], eol=eol)


def test_features_use_real_eol_data_and_wordpress_can_make_the_cms_flag_one() -> None:
    tech = TechFingerprintResult(technologies=[_eol("WordPress", "4.9.8", True, "CMS"), _eol("PHP", "8.4.1", False)])
    vec, _ = extract_features_with_coverage(None, None, None, tech)
    assert vec.tech_has_known_eol_component == 1.0 and vec.tech_has_eol_cms_version == 1.0


def test_features_assessed_and_supported_is_zero_unassessed_is_unknown() -> None:
    ok = TechFingerprintResult(technologies=[_eol("WordPress", "6.8", False, "CMS"), _eol("PHP", "8.4", False)])
    v1, _ = extract_features_with_coverage(None, None, None, ok)
    assert v1.tech_has_known_eol_component == 0.0 and v1.tech_has_eol_cms_version == 0.0

    unknown = TechFingerprintResult(technologies=[_eol("WordPress", "6.8", None, "CMS"), _eol("PHP", None, None)])
    v2, _ = extract_features_with_coverage(None, None, None, unknown)
    assert v2.tech_has_known_eol_component is None and v2.tech_has_eol_cms_version is None, "unknown, never 0"

    nothing, _ = extract_features_with_coverage(None, None, None, TechFingerprintResult(technologies=[]))
    assert nothing.tech_has_known_eol_component == 0.0 and nothing.tech_has_eol_cms_version == 0.0

    no_cms = TechFingerprintResult(technologies=[_eol("PHP", "5.6", True)])
    v3, _ = extract_features_with_coverage(None, None, None, no_cms)
    assert v3.tech_has_known_eol_component == 1.0 and v3.tech_has_eol_cms_version == 0.0


def test_the_static_eol_set_is_gone() -> None:
    import app.ml.features as features
    assert not hasattr(features, "EOL_SET") and not hasattr(features, "is_eol")


def test_average_confidence_uses_the_real_confidences() -> None:
    tech = TechFingerprintResult(technologies=[DetectedTechnology(name="A", confidence=50), DetectedTechnology(name="B", confidence=100)])
    vec, _ = extract_features_with_coverage(None, None, None, tech)
    assert vec.tech_avg_confidence == 0.75


# ── Wappalyzer: data, warnings, confidence, state ───────────────────────────
def test_fingerprint_data_loads_without_any_warning_and_js_only_syntax_is_translated() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")                      # any regex / syntax warning fails the test
        wapp, stats = tf.load_wappalyzer()
    assert stats.technologies > 1000 and stats.patterns > 1500
    assert stats.fixed_patterns >= 1, "e.g. Symfony's toolbar pattern uses the JS-only [^] class"
    assert stats.unusable_patterns <= 0.01 * stats.patterns, f"{stats.unusable_patterns}/{stats.patterns} patterns unusable"
    assert {"WordPress", "AngularJS", "PHP", "jQuery"} <= set(wapp.technologies)


def test_the_unused_fingerprint_dump_is_gone() -> None:
    from pathlib import Path
    assert not (Path(tf.__file__).with_name("wappalyzer_tech.json")).exists()


def test_a_custom_data_file_can_be_configured(tmp_path, monkeypatch) -> None:
    from app.core.config import get_settings
    custom = tmp_path / "technologies.json"
    custom.write_text(json.dumps({"categories": {"1": {"name": "Cat"}}, "technologies": {
        "Only Here": {"cats": [1], "html": "only-here-marker", "meta": None, "url": None}}}), encoding="utf-8")
    monkeypatch.setenv("WAPPALYZER_DATA_FILE", str(custom))
    get_settings.cache_clear()
    try:
        wapp, stats = tf.load_wappalyzer()
    finally:
        get_settings.cache_clear()
    assert stats.source == str(custom) and list(wapp.technologies) == ["Only Here"], "null fields are tolerated"


def _tiny():
    techs = {
        "Half": {"cats": [1], "html": ["half-marker\\;confidence:50"]},
        "TwoHalves": {"cats": [1], "html": ["alpha-marker\\;confidence:50", "beta-marker\\;confidence:50"]},
        "Full": {"cats": [1], "headers": {"X-Full": "yes"}, "implies": ["Implied"]},
        "Implied": {"cats": [1]},
        "Versioned": {"cats": [1], "html": ["versioned/([\\d.]+)\\;version:\\1"]},
    }
    wapp, _ = tf.build_wappalyzer(techs, {"1": {"name": "Cat"}})
    return wapp


def test_confidence_is_wappalyzers_real_confidence_not_a_constant() -> None:
    wapp = _tiny()
    found = {t.name: t for t in tf.analyze_page(wapp, "https://x.test/", "<p>half-marker alpha-marker beta-marker</p>", {"X-Full": "yes"})}
    assert found["Half"].confidence == 50 and found["TwoHalves"].confidence == 100 and found["Full"].confidence == 100
    assert found["Implied"].implied is True and found["Implied"].confidence == 50, "inferred, not observed"
    assert found["Full"].implied is False


def test_versions_do_not_leak_from_one_page_to_the_next() -> None:
    wapp = _tiny()
    first = {t.name: t for t in tf.analyze_page(wapp, "https://a.test/", "<p>versioned/4.9.8</p>", {})}
    second = {t.name: t for t in tf.analyze_page(wapp, "https://b.test/", "<p>versioned/</p> versioned/x", {})}
    third = {t.name: t for t in tf.analyze_page(wapp, "https://c.test/", "<p>nothing here</p>", {})}
    assert first["Versioned"].version == "4.9.8"
    assert second.get("Versioned") is None or second["Versioned"].version is None, "site A's version leaked into site B"
    assert "Versioned" not in third


@pytest.mark.asyncio
async def test_concurrent_analyses_do_not_mix_up_their_results() -> None:
    wapp = _tiny()
    pages = [(f"https://p{i}.test/", f"<p>versioned/{i}.{i}</p>") for i in range(1, 9)]
    results = await asyncio.gather(*(asyncio.to_thread(tf.analyze_page, wapp, u, h, {}) for u, h in pages))
    for i, res in enumerate(results, start=1):
        versioned = next(t for t in res if t.name == "Versioned")
        assert versioned.version == f"{i}.{i}"


# ── end to end: real Wappalyzer data + EOL fixtures ─────────────────────────
OLD_SITE = """<html><head><meta name="generator" content="WordPress 4.9.8">
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js"></script></head>
<body><p>blog</p></body></html>""" + "<!-- pad -->" * 2500


@pytest.mark.asyncio
async def test_real_fingerprinting_finds_old_wordpress_php5_and_angularjs1_with_versions(fake_dns) -> None:
    client = TechFingerprintClient(use_mock=False)
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "old.example.com", text=OLD_SITE, headers={"X-Powered-By": "PHP/5.6.40", "Server": "Apache/2.2.34"})
        res = await client.fingerprint_url("https://old.example.com/")
    await client.close()
    assert res.ok
    found = {t.name: t for t in res.data.technologies}
    assert found["WordPress"].version == "4.9.8" and "CMS" in found["WordPress"].categories
    assert found["PHP"].version == "5.6.40"
    assert found["AngularJS"].version == "1.5.8"
    assert all(0 < t.confidence <= 100 for t in found.values())


@pytest.fixture
def live_scan(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation
    from fastapi.testclient import TestClient
    from app.core.config import get_settings
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1000")
    monkeypatch.setenv("EOL_ENABLED", "true")
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    yield TestClient(app)
    get_settings.cache_clear()


def _scan_old_site(client, eol_status: int = 200):
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
        mock_site(router, "old.example.com", text=OLD_SITE, headers={"X-Powered-By": "PHP/5.6.40"})
        if eol_status == 200:
            _eol_routes(router)
        else:                                    # SafeFetcher dials the pinned IP, so route by host header, not URL regex
            for slug in FIXTURES:
                mock_site(router, "endoflife.date", path=f"/api/{slug}.json", status=eol_status, text="")
        return client.post("/scan", json={"target": "old.example.com", "target_type": "domain"}).json()


def test_scan_flags_old_wordpress_php_and_angularjs_as_end_of_life(live_scan) -> None:
    body = _scan_old_site(live_scan)
    r = body["result"]
    techs = {t["name"]: t for t in r["tech_fingerprint"]["technologies"]}
    assert techs["WordPress"]["eol"] is True and techs["PHP"]["eol"] is True and techs["AngularJS"]["eol"] is True
    assert r["features"]["tech_has_known_eol_component"] == 1.0
    assert r["features"]["tech_has_eol_cms_version"] == 1.0, "a CMS can finally be flagged EOL"
    out = next(o for o in r["provider_results"] if o["source"] == "endoflife")
    assert out["status"] == "ok" and r["tech_fingerprint"]["eol_assessed"] >= 3


def test_an_endoflife_outage_leaves_eol_unknown_and_says_so(live_scan) -> None:
    body = _scan_old_site(live_scan, eol_status=503)
    r = body["result"]
    assert r["tech_fingerprint"] is not None and all(t["eol"] is None for t in r["tech_fingerprint"]["technologies"])
    assert r["features"]["tech_has_known_eol_component"] is None and r["features"]["tech_has_eol_cms_version"] is None
    out = next(o for o in r["provider_results"] if o["source"] == "endoflife")
    assert out["status"] == "error" and out["reason"] == "server_error"


def test_the_eol_lookup_can_be_switched_off(live_scan, monkeypatch) -> None:
    from app.core.config import get_settings
    monkeypatch.setenv("EOL_ENABLED", "false")
    get_settings.cache_clear()
    body = _scan_old_site(live_scan)
    out = next(o for o in body["result"]["provider_results"] if o["source"] == "endoflife")
    assert out["status"] == "skipped" and out["reason"] == "disabled"
    assert body["result"]["features"]["tech_has_known_eol_component"] is None
