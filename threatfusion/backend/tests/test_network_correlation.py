"""
Tests for the Network-Layer correlation & fusion scoring engine.

These assert on **real logic and real observed inputs**, not mocked
detections:

* The App-Layer sub-score is produced by the *actual* App-Layer pipeline
  (VirusTotal client → extract_features → baseline + XGBoost fusion). Under
  the test harness the App layer runs in its deterministic USE_MOCK_DATA
  mode (forced by conftest), so a domain literally containing "malicious"
  yields a genuinely high VT malicious count and the fusion model scores it
  as malicious — we assert the correlation engine folds that real result in.
* The behavioural baseline is built from real observed DNS tuples recorded
  into a real SQLite store; deviation is derived from that stored state.
* WiGLE / degradation paths assert the engine's honest behaviour when a
  signal is unavailable (no fabricated values).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.network.baseline_store import BaselineStore
from app.network.correlation import (
    CorrelationEngine,
    WIGLE_ESTABLISHED_PENALTY,
    WIGLE_UNSEEN_BONUS,
    severity_from_score,
)
from app.network.enrichment.app_layer import AppLayerScorer
from app.network.enrichment.wigle import WigleClient
from app.network.models import (
    AlertType,
    EventType,
    SensorEvent,
    Severity,
    SignalContribution,
    WigleResult,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _make_store(tmp_path, min_observations: int = 3) -> BaselineStore:
    """Build a real SQLite-backed baseline store for a test."""
    s = BaselineStore(str(tmp_path / "net_test.db"), min_observations=min_observations)
    await s.init()
    return s


async def _make_engine(tmp_path) -> CorrelationEngine:
    """Correlation engine wired to the real App-Layer scorer + WiGLE client.

    WiGLE has no credentials here, so its signal degrades honestly — which
    is itself part of what we test.
    """
    store = await _make_store(tmp_path)
    return CorrelationEngine(store, AppLayerScorer(), WigleClient("", ""))


# ── Severity mapping ──────────────────────────────────────────────────────

def test_severity_bands() -> None:
    assert severity_from_score(90) == Severity.CRITICAL
    assert severity_from_score(75) == Severity.CRITICAL
    assert severity_from_score(60) == Severity.HIGH
    assert severity_from_score(30) == Severity.MEDIUM
    assert severity_from_score(10) == Severity.LOW
    # Score is always clamped into a valid band.
    assert severity_from_score(0) == Severity.LOW


# ── Baseline store: learned purely from observed traffic ──────────────────

@pytest.mark.asyncio
async def test_baseline_learns_and_flags_novel_domain(tmp_path) -> None:
    store = await _make_store(tmp_path)
    mac = "aa:bb:cc:dd:ee:01"
    # Observe the same benign domain enough times to establish the profile.
    for _ in range(3):
        await store.record_dns(mac, "streaming.example.com", "192.168.1.20")

    # A repeat of a known domain is NOT a deviation.
    await store.record_dns(mac, "streaming.example.com", "192.168.1.20")
    known = await store.compare_dns(mac, "streaming.example.com")
    assert known.established is True
    assert known.is_new_domain is False

    # A never-before-seen domain for an established device IS a deviation.
    await store.record_dns(mac, "c2.badhost.example", "192.168.1.20")
    novel = await store.compare_dns(mac, "c2.badhost.example")
    assert novel.established is True
    assert novel.is_new_domain is True
    assert "not been seen before" in novel.deviation_detail


@pytest.mark.asyncio
async def test_baseline_not_established_stays_quiet(tmp_path) -> None:
    store = await _make_store(tmp_path)
    mac = "aa:bb:cc:dd:ee:02"
    await store.record_dns(mac, "first.example.com", "192.168.1.21")
    cmp_ = await store.compare_dns(mac, "second.example.com")
    # Too little history — we must NOT manufacture a deviation.
    assert cmp_.established is False


# ── New device detection (real INSERT-vs-UPDATE state) ────────────────────

@pytest.mark.asyncio
async def test_new_device_alert_once(tmp_path) -> None:
    engine = await _make_engine(tmp_path)
    event = SensorEvent(
        event_type=EventType.ARP_OBSERVED, timestamp=_now(), sensor="arp",
        mac="de:ad:be:ef:00:11", ip="192.168.1.50",
    )
    alerts = await engine.correlate(event)
    assert len(alerts) == 1
    assert alerts[0].alert_type == AlertType.NEW_DEVICE
    assert alerts[0].device_mac == "de:ad:be:ef:00:11"

    # Same device observed again → no duplicate alert.
    again = await engine.correlate(event)
    assert again == []


# ── Cross-layer correlation: real App-Layer sub-score folded in ───────────

@pytest.mark.asyncio
async def test_cross_layer_hit_uses_real_app_layer_score(tmp_path) -> None:
    engine = await _make_engine(tmp_path)
    # The App-Layer pipeline scores this as malicious for real (mock VT gives
    # a high malicious count for names containing "malicious"/"evil").
    event = SensorEvent(
        event_type=EventType.DNS_QUERY, timestamp=_now(), sensor="dns",
        mac="aa:bb:cc:dd:ee:10", ip="192.168.1.30",
        domain="malicious-evil.example.com", raw={"qtype": 1},
    )
    alerts = await engine.correlate(event)
    cross = [a for a in alerts if a.alert_type == AlertType.CROSS_LAYER_HIT]
    assert len(cross) == 1
    alert = cross[0]

    # The App-Layer sub-score must be present, real and flagged.
    assert alert.evidence.app_layer is not None
    assert alert.evidence.app_layer.available is True
    assert alert.evidence.app_layer.flagged is True
    assert alert.evidence.app_layer.vt_malicious_count > 0
    # The app_layer signal must actually contribute points, and the fused
    # score must exceed the cross-layer base alone — i.e. the real App-Layer
    # sub-score materially drives the number (not over-fitting the exact ML
    # calibration on a mock VT input).
    app_sig = next(s for s in alert.evidence.signals if s.name == "app_layer")
    assert app_sig.available is True
    assert app_sig.points > 0
    assert alert.fused_score > 20.0  # 20 = cross-layer base; > means app added


@pytest.mark.asyncio
async def test_benign_known_domain_raises_no_alert(tmp_path) -> None:
    engine = await _make_engine(tmp_path)
    mac = "aa:bb:cc:dd:ee:20"
    # Establish a benign baseline (google.com is benign in the App layer).
    for _ in range(4):
        await engine._store.record_dns(mac, "google.com", "192.168.1.31")

    event = SensorEvent(
        event_type=EventType.DNS_QUERY, timestamp=_now(), sensor="dns",
        mac=mac, ip="192.168.1.31", domain="google.com", raw={"qtype": 1},
    )
    alerts = await engine.correlate(event)
    # Known-benign, in-baseline traffic → all clear.
    assert alerts == []


@pytest.mark.asyncio
async def test_behavioral_deviation_on_novel_benign_domain(tmp_path) -> None:
    engine = await _make_engine(tmp_path)
    mac = "aa:bb:cc:dd:ee:21"
    for _ in range(4):
        await engine._store.record_dns(mac, "google.com", "192.168.1.32")

    # A novel (but not App-Layer-flagged) domain for an established device.
    event = SensorEvent(
        event_type=EventType.DNS_QUERY, timestamp=_now(), sensor="dns",
        mac=mac, ip="192.168.1.32", domain="microsoft.com", raw={"qtype": 1},
    )
    alerts = await engine.correlate(event)
    dev = [a for a in alerts if a.alert_type == AlertType.BEHAVIORAL_DEVIATION]
    assert len(dev) == 1
    assert dev[0].evidence.baseline is not None
    assert dev[0].evidence.baseline.is_new_domain is True


# ── WiGLE folding + honest degradation ────────────────────────────────────

def test_wigle_zero_history_raises_points_and_established_lowers() -> None:
    eng = CorrelationEngine(None, None, None)  # type: ignore[arg-type]

    unseen: list[SignalContribution] = []
    eng._apply_wigle(unseen, WigleResult(available=True, bssid="x", found=False,
                                         total_observations=0))
    assert unseen[0].points == WIGLE_UNSEEN_BONUS
    assert "NO public record" in unseen[0].detail

    established: list[SignalContribution] = []
    eng._apply_wigle(established, WigleResult(available=True, bssid="x", found=True,
                                              total_observations=5000,
                                              first_seen="2015-01-01"))
    assert established[0].points == WIGLE_ESTABLISHED_PENALTY


@pytest.mark.asyncio
async def test_evil_twin_degrades_honestly_without_wigle(tmp_path) -> None:
    engine = await _make_engine(tmp_path)
    event = SensorEvent(
        event_type=EventType.EVIL_TWIN, timestamp=_now(), sensor="wifi",
        bssid="00:11:22:33:44:55", ssid="HomeNet", channel=36, signal=80,
    )
    alerts = await engine.correlate(event)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == AlertType.EVIL_TWIN
    assert alert.evidence.wigle is not None
    # No credentials → WiGLE unavailable, honest reason, zero points from it.
    assert alert.evidence.wigle.available is False
    assert "credentials" in (alert.evidence.wigle.reason or "").lower()
    wigle_sig = next(s for s in alert.evidence.signals if s.name == "wigle")
    assert wigle_sig.available is False
    assert wigle_sig.points == 0.0


@pytest.mark.asyncio
async def test_deauth_flood_scores_high(tmp_path) -> None:
    engine = await _make_engine(tmp_path)
    event = SensorEvent(
        event_type=EventType.DEAUTH_FLOOD, timestamp=_now(), sensor="dot11",
        bssid="66:77:88:99:aa:bb",
        raw={"frame_count": 80, "threshold": 20, "window_seconds": 10,
             "frame_type": "deauth", "reason_code": 7},
    )
    alerts = await engine.correlate(event)
    assert len(alerts) == 1
    assert alerts[0].alert_type == AlertType.DEAUTH_FLOOD
    assert alerts[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert alerts[0].fused_score >= 70.0


# ── WiGLE client honest degradation (no network) ──────────────────────────

@pytest.mark.asyncio
async def test_wigle_client_reports_missing_credentials() -> None:
    client = WigleClient("", "")
    assert client.configured is False
    result = await client.lookup_bssid("aa:bb:cc:dd:ee:ff")
    assert result.available is False
    assert "credentials" in (result.reason or "").lower()
