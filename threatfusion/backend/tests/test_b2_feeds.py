"""B2 (local feeds) — OpenPhish, PhishTank and Tranco kept in the local feed store.

A bulk feed is downloaded once and looked up offline: no quota, nothing about the target leaves the machine, and every
answer carries the list's **age**.  Honesty rules under test: a feed never downloaded is *unknown* (never "not listed") and
starts a background download; a stale feed is used but flagged; a failed / truncated / shrunken download keeps the previous
copy; "not listed" is ``not_found`` (absence of evidence); how a target matched (exact URL / same page / other URLs on the
host) is reported; Tranco is a popularity prior and never sets ``listed``.  Fixtures only — no live download.
"""

from __future__ import annotations

import asyncio
import io
import json
import zipfile

import httpx
import pytest
import respx

from app.core.feeds import FeedStore
from app.core.safe_http import FetchPolicy
from app.ingestion.blocklists import OpenPhishFeed, PhishTankFeed, TrancoFeed, split_url
from app.ingestion.reputation import Subject
from app.models.schemas import ProviderStatus
from tests.conftest import mock_site

OPENPHISH = "\n".join([
    "https://secure-paypa1.example.net/login/verify?id=42&session=abc",
    "http://evil.example.com/a/b",
    "http://evil.example.com/other",
    "https://compromised-blog.example.org/wp-content/uploads/kit/index.php",
])
PHISHTANK = json.dumps([
    {"phish_id": "1", "url": "https://login-hdfcbank.example.net/netbanking", "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=1",
     "submission_time": "2026-10-01T08:00:00+00:00", "verification_time": "2026-10-01T09:00:00+00:00", "target": "HDFC Bank"},
    {"phish_id": "2", "url": "http://unknown-brand.example.net/x", "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=2", "target": "Other"},
])


def zip_of(csv_text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", csv_text)
    return buf.getvalue()


TRANCO = zip_of("\n".join(f"{i},site{i}.com" for i in range(3, 50)) + "\n1,google.com\n2,facebook.com\n")


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def feeds(clock: Clock | None = None):
    return FeedStore(clock=clock or Clock())


def serve(router, host: str, path: str, body, status: int = 200):
    if isinstance(body, bytes):
        return mock_site(router, host, path=path, side_effect=lambda r: httpx.Response(status, content=body))
    return mock_site(router, host, path=path, status=status, text=body)


def subject(url=None, host=None, kind="url"):
    return Subject(kind=kind, host=host or split_url(url)[2], url=url, registered_domain=None)


# ── URL normalisation ───────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("https://Evil.Example.com/Login/?a=1#frag", ("evil.example.com/Login?a=1", "evil.example.com/Login", "evil.example.com")),
    ("http://evil.example.com", ("evil.example.com/", "evil.example.com/", "evil.example.com")),
    ("evil.example.com:8080/x", ("evil.example.com:8080/x", "evil.example.com:8080/x", "evil.example.com")),
    ("https://evil.example.com:443/x/", ("evil.example.com/x", "evil.example.com/x", "evil.example.com")),
    ("https://evil.example.com./x", ("evil.example.com/x", "evil.example.com/x", "evil.example.com")),
])
def test_urls_are_normalised_for_matching(raw, expected) -> None:
    assert split_url(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "http://", "http://[::1", "http://host:notaport/x"])
def test_junk_urls_are_ignored(raw) -> None:
    assert split_url(raw) is None


# ── OpenPhish ───────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_openphish_refresh_and_the_three_match_levels(fake_dns) -> None:
    store = feeds()
    feed = OpenPhishFeed(False, store=store, policy=FetchPolicy())
    with respx.mock(assert_all_called=False) as router:
        serve(router, "openphish.com", "/feed.txt", OPENPHISH)
        meta = await feed.refresh()
    assert meta.ok and meta.data.count > 4

    exact = await feed.lookup(subject("https://secure-paypa1.example.net/login/verify?id=42&session=abc"))
    assert exact.status == ProviderStatus.OK and exact.data.match == "exact_url" and exact.data.listed and exact.data.category == "phishing"
    same_page = await feed.lookup(subject("https://secure-paypa1.example.net/login/verify"))
    assert same_page.data.match == "url_path"
    other_page = await feed.lookup(subject("https://evil.example.com/never-listed"))
    assert other_page.data.match == "host" and "2 other URL" in other_page.data.detail
    clean = await feed.lookup(subject("https://www.example.org/"))
    assert clean.status == ProviderStatus.NOT_FOUND and clean.data is None


@pytest.mark.asyncio
async def test_a_domain_target_matches_the_host_and_the_answer_carries_the_feed_age(fake_dns) -> None:
    clock = Clock()
    store = feeds(clock)
    feed = OpenPhishFeed(False, store=store, policy=FetchPolicy())
    with respx.mock(assert_all_called=False) as router:
        serve(router, "openphish.com", "/feed.txt", OPENPHISH)
        await feed.refresh()
    clock.now += 3 * 3600
    res = await feed.lookup(Subject(kind="domain", host="evil.example.com"))
    assert res.data.match == "host" and res.data.feed_age_days == pytest.approx(0.125, abs=0.001) and not res.data.stale


@pytest.mark.asyncio
async def test_a_feed_that_was_never_downloaded_is_unknown_and_starts_a_background_download(fake_dns) -> None:
    store = feeds()
    feed = OpenPhishFeed(False, store=store, policy=FetchPolicy())
    with respx.mock(assert_all_called=False) as router:
        route = serve(router, "openphish.com", "/feed.txt", OPENPHISH)
        first = await feed.lookup(subject("https://evil.example.com/a/b"))
        assert first.status == ProviderStatus.ERROR and first.reason == "feed_unavailable", "unknown, never 'not listed'"
        assert feed._background is not None
        await feed._background                                           # the download the lookup kicked off
        assert route.called
    second = await feed.lookup(subject("https://evil.example.com/a/b"))
    assert second.status == ProviderStatus.OK and second.data.match == "exact_url"


@pytest.mark.asyncio
async def test_a_stale_feed_is_used_but_flagged_and_refreshed_in_the_background(fake_dns) -> None:
    clock = Clock()
    feed = OpenPhishFeed(False, store=feeds(clock), policy=FetchPolicy(), max_age_hours=12)
    with respx.mock(assert_all_called=False) as router:
        serve(router, "openphish.com", "/feed.txt", OPENPHISH)
        await feed.refresh()
        clock.now += 30 * 3600
        res = await feed.lookup(subject("https://evil.example.com/a/b"))
        assert feed._background is not None
        await feed._background
    assert res.status == ProviderStatus.OK and res.reason == "stale_feed" and res.data.stale is True
    assert res.data.feed_age_days == pytest.approx(1.25, abs=0.01)


@pytest.mark.asyncio
@pytest.mark.parametrize("status,body,reason", [(503, "busy", "server_error"), (404, "gone", "not_found_upstream"),
                                                 (200, "", "parse_error")])
async def test_a_failed_refresh_keeps_the_previous_copy(fake_dns, status, body, reason) -> None:
    store = feeds()
    feed = OpenPhishFeed(False, store=store, policy=FetchPolicy())
    with respx.mock(assert_all_called=False) as router:
        serve(router, "openphish.com", "/feed.txt", OPENPHISH)
        await feed.refresh()
    before = await store.count("openphish")
    with respx.mock(assert_all_called=False) as router:
        serve(router, "openphish.com", "/feed.txt", body, status)
        res = await feed.refresh()
    assert res.status == ProviderStatus.ERROR and res.reason == reason
    assert await store.count("openphish") == before and (await feed.lookup(subject("https://evil.example.com/a/b"))).ok


@pytest.mark.asyncio
async def test_a_download_that_shrinks_a_big_list_is_refused(fake_dns) -> None:
    store = feeds()
    feed = OpenPhishFeed(False, store=store, policy=FetchPolicy())
    big = "\n".join(f"http://phish{i}.example.net/x" for i in range(300))
    with respx.mock(assert_all_called=False) as router:
        serve(router, "openphish.com", "/feed.txt", big)
        assert (await feed.refresh()).ok
    with respx.mock(assert_all_called=False) as router:
        serve(router, "openphish.com", "/feed.txt", "http://only-one.example.net/x")
        res = await feed.refresh()
    assert res.status == ProviderStatus.ERROR and res.reason == "suspicious_shrink"
    assert (await feed.lookup(subject("http://phish7.example.net/x"))).ok


@pytest.mark.asyncio
async def test_an_oversized_download_is_an_error_not_a_partial_list(fake_dns) -> None:
    feed = OpenPhishFeed(False, store=feeds(), policy=FetchPolicy(max_bytes=100))
    with respx.mock(assert_all_called=False) as router:
        serve(router, "openphish.com", "/feed.txt", OPENPHISH)
        res = await feed.refresh()
    assert res.status == ProviderStatus.ERROR and res.reason == "response_too_large"


@pytest.mark.asyncio
async def test_concurrent_lookups_share_one_download(fake_dns) -> None:
    feed = OpenPhishFeed(False, store=feeds(), policy=FetchPolicy())
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, text=OPENPHISH)

    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "openphish.com", path="/feed.txt", side_effect=handler)
        await asyncio.gather(*(feed.ensure_fresh() for _ in range(5)))
    assert calls["n"] == 1


# ── PhishTank ───────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_phishtank_records_the_targeted_brand(fake_dns) -> None:
    feed = PhishTankFeed(False, store=feeds(), policy=FetchPolicy())
    with respx.mock(assert_all_called=False) as router:
        serve(router, "data.phishtank.com", "/data/online-valid.json", PHISHTANK)
        assert (await feed.refresh()).ok
    hit = await feed.lookup(subject("https://login-hdfcbank.example.net/netbanking"))
    assert hit.data.listed and hit.data.extra["brand"] == "HDFC Bank" and "targets HDFC Bank" in hit.data.detail
    assert hit.data.reference == "https://www.phishtank.com/phish_detail.php?phish_id=1" and hit.data.last_seen.startswith("2026-10-01")
    other = await feed.lookup(subject("http://unknown-brand.example.net/x"))
    assert other.data.extra["brand"] is None and "targets" not in other.data.detail, "'Other' is not a brand"


@pytest.mark.asyncio
@pytest.mark.parametrize("body", ["{}", "not json", "[1, 2, 3]", "[]"])
async def test_phishtank_garbage_is_a_parse_error(fake_dns, body) -> None:
    feed = PhishTankFeed(False, store=feeds(), policy=FetchPolicy())
    with respx.mock(assert_all_called=False) as router:
        serve(router, "data.phishtank.com", "/data/online-valid.json", body)
        res = await feed.refresh()
    assert res.status == ProviderStatus.ERROR and res.reason == "parse_error"


# ── Tranco ──────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_tranco_is_a_popularity_prior_and_never_listed(fake_dns) -> None:
    feed = TrancoFeed(False, store=feeds(), policy=FetchPolicy(), top_n=30)
    with respx.mock(assert_all_called=False) as router:
        serve(router, "tranco-list.eu", "/top-1m.csv.zip", TRANCO)
        meta = await feed.refresh()
    assert meta.ok and meta.data.count == 30, "only the top N are kept"
    top = await feed.lookup(Subject(kind="domain", host="www.google.com", registered_domain="google.com"))
    assert top.status == ProviderStatus.OK and top.data.listed is False and top.data.category == "popular" and top.data.extra["rank"] == 1
    assert "#1" in top.data.detail
    assert (await feed.lookup(Subject(kind="domain", host="unpopular.example", registered_domain="unpopular.example"))).status == ProviderStatus.NOT_FOUND
    assert (await feed.lookup(Subject(kind="domain", host="site40.com", registered_domain="site40.com"))).status == ProviderStatus.NOT_FOUND, "rank 40 > top_n"


@pytest.mark.asyncio
async def test_tranco_applies_to_domains_and_urls_only(fake_dns) -> None:
    feed = TrancoFeed(False, store=feeds(), policy=FetchPolicy())
    assert (await feed.lookup(Subject(kind="ip", host="93.184.216.34", ip="93.184.216.34"))).status == ProviderStatus.SKIPPED
    assert (await feed.lookup(Subject(kind="hash", hash="a" * 64))).status == ProviderStatus.SKIPPED
    unknown = await feed.lookup(Subject(kind="domain", host="x.example.com", registered_domain="example.com"))
    assert unknown.status == ProviderStatus.ERROR and unknown.reason == "feed_unavailable"
    if feed._background is not None:
        feed._background.cancel()


@pytest.mark.asyncio
async def test_a_bad_zip_is_a_parse_error(fake_dns) -> None:
    feed = TrancoFeed(False, store=feeds(), policy=FetchPolicy())
    with respx.mock(assert_all_called=False) as router:
        serve(router, "tranco-list.eu", "/top-1m.csv.zip", b"PK\x03\x04 truncated")
        res = await feed.refresh()
    assert res.status == ProviderStatus.ERROR and res.reason == "parse_error"


# ── privacy & mock ──────────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["localhost", "printer.local", "intranet", "10.0.0.5"])
async def test_private_names_are_skipped(host) -> None:
    feed = OpenPhishFeed(False, store=feeds())
    res = await feed.lookup(Subject(kind="domain", host=host))
    assert res.status == ProviderStatus.SKIPPED


@pytest.mark.asyncio
async def test_a_lookup_makes_no_network_call(fake_dns) -> None:
    feed = OpenPhishFeed(False, store=feeds(), policy=FetchPolicy())
    with respx.mock(assert_all_called=False) as router:
        serve(router, "openphish.com", "/feed.txt", OPENPHISH)
        await feed.refresh()
        downloads = len(router.calls)
        await feed.lookup(subject("https://evil.example.com/a/b"))
        assert len(router.calls) == downloads, "once downloaded, a lookup is entirely local"


@pytest.mark.asyncio
async def test_mock_mode_is_offline_deterministic_and_labelled() -> None:
    bad = Subject(kind="domain", host="evil-login.example.com", registered_domain="example.com")
    for cls in (OpenPhishFeed, PhishTankFeed):
        feed = cls(True, store=feeds())
        with respx.mock(assert_all_called=False) as router:
            a, b = await feed.lookup(bad), await feed.lookup(bad)
            clean = await feed.lookup(Subject(kind="domain", host="www.example.org", registered_domain="example.org"))
            assert not router.calls
        assert a.mock and a.data.listed and a.data == b.data and clean.status == ProviderStatus.NOT_FOUND and clean.mock
    tranco = TrancoFeed(True, store=feeds())
    g = await tranco.lookup(Subject(kind="domain", host="www.google.com", registered_domain="google.com"))
    assert g.mock and g.data.extra["rank"] == 1
