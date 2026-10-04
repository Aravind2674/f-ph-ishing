"""B4 (wiring) — the brand-impersonation check inside ``POST /scan``.

The check is local and deterministic, so it also runs in mock mode and needs no network.  It is reported next to the
maliciousness scores (``brand_check`` / ``lookalike_of``) and is *not* a provider outcome: it does not count as evidence
for the verdict.  Covered: look-alike flagged with its evidence and in the summary, a genuine brand and an unrelated
domain not flagged, IP targets skipped, the switch and threshold honoured, the brand index extended by the Tranco feed,
and the feed store's ``items()``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.feeds import FeedStore


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    import app.core.validation as validation
    from app.main import app

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    return TestClient(app)


def _scan(client, target, target_type="domain"):
    return client.post("/scan", json={"target": target, "target_type": target_type}).json()["result"]


def test_a_lookalike_domain_is_flagged_with_evidence_and_named_in_the_summary(client) -> None:
    r = _scan(client, "paypa1-secure.com")
    assert r["brand_check"]["status"] == "lookalike"
    assert r["lookalike_of"]["brand"] == "PayPal" and r["lookalike_of"]["kind"] == "brand_keyword"
    assert r["lookalike_of"] == r["brand_check"]["match"] and r["lookalike_of"]["evidence"]
    assert "imitates PayPal" in r["summary"]
    assert r["brand_check"]["brands_checked"] >= 100 and r["brand_check"]["popular_checked"] == 0


def test_a_genuine_brand_domain_and_an_unrelated_domain_are_not_flagged(client) -> None:
    genuine = _scan(client, "login.microsoftonline.com")
    assert genuine["brand_check"]["status"] == "official" and genuine["lookalike_of"] is None
    assert genuine["brand_check"]["official_of"] == "Microsoft" and "imitates" not in genuine["summary"]
    other = _scan(client, "my-bakery.example.com")
    assert other["brand_check"]["status"] == "no_match" and other["lookalike_of"] is None


def test_a_url_target_is_checked_on_its_host(client) -> None:
    r = _scan(client, "https://hdfcbank-login.com/netbanking?x=1", "url")
    assert r["lookalike_of"]["brand"] == "HDFC Bank"


def test_ip_targets_have_no_brand_check(client) -> None:
    r = _scan(client, "8.8.8.8", "ip")
    assert r["brand_check"] is None and r["lookalike_of"] is None


def test_the_check_is_not_evidence_for_the_verdict(client) -> None:
    r = _scan(client, "paypa1-secure.com")
    assert "lookalike" not in [o["source"] for o in r["provider_results"]]
    assert "lookalike" not in " ".join(r["data_sources_succeeded"])


def test_the_switch_and_the_threshold_are_honoured(client, monkeypatch) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("LOOKALIKE_ENABLED", "false")
    get_settings.cache_clear()
    try:
        assert _scan(client, "paypa1-secure.com")["brand_check"] is None
        monkeypatch.setenv("LOOKALIKE_ENABLED", "true")
        monkeypatch.setenv("LOOKALIKE_THRESHOLD", "0.99")
        get_settings.cache_clear()
        r = _scan(client, "paypa1-secure.com")
        assert r["brand_check"]["status"] == "no_match" and r["brand_check"]["threshold"] == 0.99
        assert r["lookalike_of"] is None and r["brand_check"]["candidates"]
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_the_tranco_feed_extends_the_brand_index_and_is_reloaded_when_refetched() -> None:
    from app.core.hub import TRANCO_FEED, hub

    base = await hub.brands()
    assert base.stats()["popular"] == 0, "no feed yet: the curated list alone, reported as such"
    await hub.feeds.replace(TRANCO_FEED, {"stackoverflow.com": 120, "kaggle.com": 900}, source_url="test://tranco")
    extended = await hub.brands()
    assert extended is not base and extended.stats()["popular"] == 2
    assert await hub.brands() is extended, "unchanged feed: the index is reused, not rebuilt per scan"
    await hub.feeds.replace(TRANCO_FEED, {"stackoverflow.com": 120}, source_url="test://tranco")
    assert (await hub.brands()).stats()["popular"] == 1


@pytest.mark.asyncio
async def test_feed_store_items_returns_a_bounded_slice_of_a_feed(tmp_path) -> None:
    for store in (FeedStore(), FeedStore(lambda: tmp_path / "feeds.db")):
        assert await store.items("nothing") == []
        await store.replace("ranked", {f"d{i}.com": i for i in range(10)}, source_url="test://x")
        assert len(await store.items("ranked", limit=4)) == 4
        assert dict(await store.items("ranked"))["d7.com"] == 7
