"""B11 (feeds) — the local feed store (schema v4) and CISA's KEV catalogue on top of it.

A "feed" is a bulk list we download and keep locally (KEV today; OpenPhish, PhishTank, Tranco in B2): looking a target up
costs no quota and no network, and — important for honesty — every feed has an **age** that the UI shows.  A feed that was
never downloaded, or could not be, is *unknown*; it is never silently "not listed".
"""

from __future__ import annotations

import asyncio
import json
import sqlite3

import httpx
import pytest
import respx

from app.core.feeds import FeedStore
from app.core.safe_http import FetchPolicy
from app.ingestion.kev import KevFeed
from app.models.schemas import KevRow, ProviderStatus
from tests.conftest import mock_site

KEV_DOC = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.10.03",
    "dateReleased": "2026-10-03T14:00:00.000Z", "count": 3,
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Log4Shell",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2021-41773", "vendorProject": "Apache", "product": "HTTP Server", "vulnerabilityName": "Path traversal",
         "dateAdded": "2021-11-03", "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "cve-2014-0160", "vendorProject": "OpenSSL", "product": "OpenSSL", "vulnerabilityName": "Heartbleed",
         "dateAdded": "2022-05-04", "dueDate": "2022-05-25", "knownRansomwareCampaignUse": "Unknown"},
    ],
}
KEV_URL_HOST, KEV_PATH = "www.cisa.gov", "/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _kev_route(router, doc=None, status=200, **kw):
    return mock_site(router, KEV_URL_HOST, path=KEV_PATH, status=status, text=json.dumps(doc if doc is not None else KEV_DOC),
                     headers={"content-type": "application/json"}, **kw)


def _feed(store=None, clock=None, **kw) -> KevFeed:
    """``clock`` is accepted for readability: freshness is derived from the *store's* clock (see the stale-feed test)."""
    return KevFeed(use_mock=False, store=store or FeedStore(), **kw)


# ── FeedStore ───────────────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("persistent", [False, True])
async def test_feed_store_replaces_atomically_and_reports_age(tmp_path, persistent) -> None:
    now = [1_000_000.0]
    store = FeedStore(path_provider=(lambda: tmp_path / "f.db") if persistent else None, clock=lambda: now[0])
    assert await store.meta("kev") is None and await store.age_days("kev") is None
    await store.replace("kev", {"A": {"x": 1}, "B": {"x": 2}}, source_url="https://example/feed", version="v1")
    meta = await store.meta("kev")
    assert meta.record_count == 2 and meta.version == "v1" and meta.source_url == "https://example/feed"
    now[0] += 3 * 86400
    assert await store.age_days("kev") == pytest.approx(3.0)
    assert await store.get("kev", "A") == {"x": 1} and await store.get("kev", "Z") is None
    assert await store.get_many("kev", ["A", "B", "Z"]) == {"A": {"x": 1}, "B": {"x": 2}}
    await store.replace("kev", {"C": {"x": 3}}, source_url="https://example/feed", version="v2")      # a refresh REPLACES
    assert await store.get("kev", "A") is None and await store.count("kev") == 1
    assert await store.age_days("kev") == pytest.approx(0.0)


@pytest.mark.asyncio
async def test_feed_store_persists_across_instances_and_isolates_feeds(tmp_path) -> None:
    db = tmp_path / "f.db"
    await FeedStore(path_provider=lambda: db).replace("kev", {"A": {"n": 1}}, source_url="u")
    await FeedStore(path_provider=lambda: db).replace("tranco", {"example.com": {"rank": 1}}, source_url="u2")
    other = FeedStore(path_provider=lambda: db)                                         # a "new process"
    assert await other.get("kev", "A") == {"n": 1} and await other.get("tranco", "A") is None
    assert await other.clear("kev") == 1 and await other.count("tranco") == 1


def test_migration_v4_adds_the_feed_tables_in_place(tmp_path) -> None:
    from app.core.db import LATEST_VERSION, init_db
    db = tmp_path / "old.db"
    asyncio.run(init_db(db))
    con = sqlite3.connect(db)
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"feed_meta", "feed_entries", "provider_cache"} <= tables and LATEST_VERSION >= 4
    assert con.execute("PRAGMA user_version").fetchone()[0] == LATEST_VERSION
    con.close()


# ── KEV: refresh ────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_refresh_downloads_the_catalogue_into_the_store(fake_dns) -> None:
    store = FeedStore()
    with respx.mock(assert_all_called=False) as router:
        route = _kev_route(router)
        res = await _feed(store).refresh()
        assert route.call_count == 1
    assert res.ok and res.data.count == 3 and res.data.catalog_version == "2026.10.03"
    assert (await store.meta("kev")).record_count == 3
    row = KevRow.model_validate(await store.get("kev", "CVE-2021-44228"))
    assert row.ransomware is True and row.vendor == "Apache" and row.date_added == "2021-12-10"
    assert await store.get("kev", "CVE-2014-0160") is not None, "ids are normalised to upper case"


@pytest.mark.asyncio
@pytest.mark.parametrize("doc,status", [({"vulnerabilities": "nope"}, 200), ({}, 200), ([], 200)])
async def test_an_unusable_catalogue_is_an_error_and_keeps_the_old_data(fake_dns, doc, status) -> None:
    store = FeedStore()
    await store.replace("kev", {"CVE-1999-0001": KevRow(date_added="1999-01-01").model_dump()}, source_url="old")
    with respx.mock(assert_all_called=False) as router:
        _kev_route(router, doc=doc, status=status)
        res = await _feed(store).refresh()
    assert res.status == ProviderStatus.ERROR and res.reason == "parse_error"
    assert await store.get("kev", "CVE-1999-0001") is not None, "a bad download must not wipe the working copy"


@pytest.mark.asyncio
@pytest.mark.parametrize("status,reason", [(503, "server_error"), (404, "not_found_upstream"), (429, "rate_limited")])
async def test_http_failures_are_errors_and_keep_the_old_data(fake_dns, status, reason) -> None:
    store = FeedStore()
    await store.replace("kev", {"CVE-1999-0001": KevRow().model_dump()}, source_url="old")
    with respx.mock(assert_all_called=False) as router:
        _kev_route(router, status=status)
        res = await _feed(store).refresh()
    assert res.status == ProviderStatus.ERROR and res.reason == reason
    assert await store.count("kev") == 1


@pytest.mark.asyncio
async def test_a_catalogue_that_shrinks_drastically_is_refused(fake_dns) -> None:
    """A truncated or poisoned download must not replace a good catalogue (KEV only ever grows)."""
    store = FeedStore()
    big = {f"CVE-2020-{i:04d}": KevRow().model_dump() for i in range(1, 201)}
    await store.replace("kev", big, source_url="old")
    tiny = {**KEV_DOC, "count": 1, "vulnerabilities": KEV_DOC["vulnerabilities"][:1]}
    with respx.mock(assert_all_called=False) as router:
        _kev_route(router, doc=tiny)
        res = await _feed(store).refresh()
    assert res.status == ProviderStatus.ERROR and res.reason == "suspicious_shrink"
    assert await store.count("kev") == 200


@pytest.mark.asyncio
async def test_the_download_goes_through_the_ssrf_safe_fetcher(fake_dns) -> None:
    fake_dns.set(KEV_URL_HOST, "10.0.0.5")                       # DNS says the feed host is internal
    res = await _feed(url=f"https://{KEV_URL_HOST}{KEV_PATH}").refresh()
    assert res.status == ProviderStatus.ERROR and res.reason.startswith("blocked")


# ── KEV: lookup ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_lookup_answers_from_the_local_copy_with_its_age(fake_dns) -> None:
    now = [1_000_000.0]
    store = FeedStore(clock=lambda: now[0])
    feed = _feed(store, clock=lambda: now[0])
    with respx.mock(assert_all_called=False) as router:
        route = _kev_route(router)
        first = await feed.lookup(["CVE-2021-44228", "CVE-2099-0001"])
        now[0] += 2 * 3600                                       # two hours later: still fresh, no new download
        second = await feed.lookup(["cve-2021-41773"])
        assert route.call_count == 1
    assert first.ok and set(first.data.entries) == {"CVE-2021-44228"}, "unlisted CVEs are simply absent"
    assert first.data.entries["CVE-2021-44228"].ransomware is True and first.data.stale is False
    assert second.data.entries["CVE-2021-41773"].ransomware is False
    assert 0.07 < second.data.age_days < 0.1 and second.data.catalog_version == "2026.10.03"


@pytest.mark.asyncio
async def test_a_stale_feed_is_refreshed_when_possible_and_flagged_when_not(fake_dns) -> None:
    now = [1_000_000.0]
    store = FeedStore(clock=lambda: now[0])
    feed = _feed(store, clock=lambda: now[0], max_age_hours=24)
    with respx.mock(assert_all_called=False) as router:
        route = _kev_route(router)
        await feed.lookup(["CVE-2021-44228"])
        now[0] += 30 * 3600                                      # 30 h later: older than 24 h -> refresh
        refreshed = await feed.lookup(["CVE-2021-44228"])
        assert route.call_count == 2 and refreshed.data.stale is False

        route.respond(503)                                       # the next refresh fails ...
        now[0] += 30 * 3600
        degraded = await feed.lookup(["CVE-2021-44228"])
    assert degraded.ok and degraded.data.stale is True and degraded.reason == "stale_feed"
    assert degraded.data.age_days > 1 and "CVE-2021-44228" in degraded.data.entries, "old data beats no data, but says so"


@pytest.mark.asyncio
async def test_a_feed_that_was_never_downloaded_is_unknown_not_empty(fake_dns) -> None:
    with respx.mock(assert_all_called=False) as router:
        _kev_route(router, status=503)
        res = await _feed().lookup(["CVE-2021-44228"])
    assert res.status == ProviderStatus.ERROR and res.reason == "feed_unavailable" and res.data is None


@pytest.mark.asyncio
async def test_concurrent_lookups_download_the_feed_once(fake_dns) -> None:
    feed = _feed()
    with respx.mock(assert_all_called=False) as router:
        route = _kev_route(router)
        results = await asyncio.gather(*(feed.lookup(["CVE-2021-44228"]) for _ in range(8)))
        assert route.call_count == 1
    assert all(r.ok and "CVE-2021-44228" in r.data.entries for r in results)


@pytest.mark.asyncio
async def test_mock_mode_has_a_labelled_deterministic_catalogue() -> None:
    feed = KevFeed(use_mock=True, store=FeedStore())
    res = await feed.lookup(["CVE-2021-44228", "CVE-2021-0000"])
    assert res.ok and res.mock is True and "CVE-2021-44228" in res.data.entries and "CVE-2021-0000" not in res.data.entries
    assert res.data.entries["CVE-2021-44228"].ransomware is True
