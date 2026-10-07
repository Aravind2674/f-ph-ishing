"""Revamp T2d — Wi-Fi that works in any Windows language, remembers access points, and only judges the networks you watch.

Fixtures are synthetic (documentation-range MACs, invented SSIDs) but follow the layout Windows prints; the layout of the English one was
checked against this machine's real ``netsh`` output.  No test needs a Wi-Fi adapter except the one marked as such, which skips cleanly.
"""

from __future__ import annotations

import platform
import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio

from app.core.config import get_settings
from app.network.aps import ApStore
from app.network.baseline_store import BaselineStore
from app.network.correlation import EVIL_TWIN_BASE, OPEN_TWIN_BONUS, SECURITY_MISMATCH_POINTS, CorrelationEngine
from app.network.enrichment.app_layer import AppLayerScorer
from app.network.enrichment.wigle import WigleClient
from app.network.models import AlertType, EventType, SensorEvent, Severity
from app.network.sensor import wlan
from app.network.sensor.wifi_scanner import WifiScanner
from app.network.sensor.wlan import AccessPoint, WifiUnavailable, canonical_security, channel_from_khz, normalize_bssid, oui_of

# ── netsh output in four languages ──────────────────────────────────────────
EN = """Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : CampusNet
    Network type            : Infrastructure
    Authentication          : WPA2-Enterprise
    Encryption              : CCMP
    BSSID 1                 : 30:86:2D:11:22:01
         Signal             : 84%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 36
         Bss Load:
             Connected Stations:         3
             Channel Utilization:        130 (50 %)
         Basic rates (Mbps) : 6 12 24
    BSSID 2                 : 30:86:2D:11:22:02
         Signal             : 41%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6

SSID 2 : CoffeeShop
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 70%
         Channel            : 11
"""

DE = """Schnittstellenname : WLAN
Zurzeit sind 1 Netzwerke sichtbar.

SSID 1 : Heimnetz
    Netzwerktyp            : Infrastruktur
    Authentifizierung      : WPA2-Personal
    Verschlüsselung        : CCMP
    BSSID 1                : aa:bb:cc:11:22:33
         Signal            : 80%
         Funktyp           : 802.11n
         Band              : 2,4 GHz
         Kanal             : 6
         Basisraten (MBit/s) : 1 2 5.5 11
"""

FR = """Nom de l'interface : Wi-Fi
2 réseaux sont actuellement visibles.

SSID 1 : Maison
    Type de réseau          : Infrastructure
    Authentification        : WPA3-Personal
    Chiffrement             : CCMP
    BSSID 1                 : de:ad:be:ef:00:01
         Signal             : 55%
         Type de radio      : 802.11ax
         Canal              : 44
"""

ZH = """接口名称 : WLAN
当前可见 1 个网络。

SSID 1 : 校园网
    网络类型            : 结构
    身份验证            : WPA2-个人
    加密                : CCMP
    BSSID 1             : 11:22:33:44:55:66
         信号           : 90%
         无线电类型     : 802.11n
         通道           : 11
         基本速率(Mbps) : 1 2 5.5 11
"""


def test_english_output_is_parsed_with_the_connected_network_and_canonical_security() -> None:
    aps = wlan.parse_netsh_networks(EN)
    assert [(a.ssid, a.bssid, a.signal_percent, a.channel, a.band_ghz, a.security) for a in aps] == [
        ("CampusNet", "30:86:2d:11:22:01", 84, 36, 5.0, "WPA2-Enterprise/CCMP"),
        ("CampusNet", "30:86:2d:11:22:02", 41, 6, 2.4, "WPA2-Enterprise/CCMP"),
        ("CoffeeShop", "00:11:22:33:44:55", 70, 11, None, "Open/None"),
    ], "the 'Connected Stations: 3' line after the channel must not be mistaken for it"
    assert all(a.oui == oui_of(a.bssid) for a in aps) and aps[0].oui == "30:86:2d"


@pytest.mark.parametrize("text,expected", [
    (DE, ("Heimnetz", "aa:bb:cc:11:22:33", 80, 6, "WPA2-Personal/CCMP")),
    (FR, ("Maison", "de:ad:be:ef:00:01", 55, 44, "WPA3-Personal/CCMP")),
    (ZH, ("校园网", "11:22:33:44:55:66", 90, 11, None)),
])
def test_other_languages_are_parsed_by_structure_and_unrecognised_values_stay_unknown(text, expected) -> None:
    (ap,) = wlan.parse_netsh_networks(text)
    assert (ap.ssid, ap.bssid, ap.signal_percent, ap.channel, ap.security) == expected      # ZH: "WPA2-个人" is not guessed -> None


def test_garbage_or_empty_output_gives_no_access_points_not_a_crash() -> None:
    assert wlan.parse_netsh_networks("") == []
    assert wlan.parse_netsh_networks("The Wireless AutoConfig Service (wlansvc) is not running.") == []


def test_the_connected_network_comes_from_the_ap_bssid_line_in_any_language() -> None:
    en = "    State                  : connected\n    SSID                   : CampusNet\n    AP BSSID               : 30:86:2d:11:22:01\n    Band : 5 GHz\n"
    de = "    Status                 : Verbunden\n    SSID                   : Heimnetz\n    BSSID                  : aa-bb-cc-11-22-33\n"
    down = "    State                  : disconnected\n"
    assert wlan.parse_netsh_connection(en) == ("CampusNet", "30:86:2d:11:22:01")
    assert wlan.parse_netsh_connection(de) == ("Heimnetz", "aa:bb:cc:11:22:33")
    assert wlan.parse_netsh_connection(down) == (None, None)


def test_small_helpers() -> None:
    assert normalize_bssid("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff" and normalize_bssid("aa:bb:cc") is None and normalize_bssid(None) is None
    assert [channel_from_khz(k) for k in (2412000, 2484000, 5180000, 5745000, 5955000)] == [(1, 2.4), (14, 2.4), (36, 5.0), (149, 5.0), (1, 6.0)]
    assert channel_from_khz(900000) == (None, None)
    assert canonical_security("WPA2-PSK", "CCMP") == canonical_security("WPA2-Personal", "CCMP") == "WPA2-Personal/CCMP"
    assert canonical_security("Offen", "Keine") is None and canonical_security(None, "CCMP") is None


# ── the Native Wifi API, with a fake ────────────────────────────────────────
class FakeApi:
    def __init__(self, *, open_code=0, interfaces=("guid", "Intel Wi-Fi"), bss_code=0, bss=(), available=()) -> None:
        self.open_code, self._interfaces, self.bss_code, self._bss, self._available, self.closed = open_code, interfaces, bss_code, list(bss), list(available), False

    def open(self): return self.open_code
    def close(self): self.closed = True
    def interfaces(self): return (0, [self._interfaces] if self._interfaces else [])
    def trigger_scan(self, guid): pass
    def bss_list(self, guid): return self.bss_code, self._bss
    def available(self, guid): return 0, self._available


def test_native_scan_converts_frequency_signal_and_security() -> None:
    api = FakeApi(bss=[{"ssid": "CampusNet", "bssid": "30:86:2d:11:22:01", "rssi": -57, "quality": 84, "khz": 5180000},
                       {"ssid": "CoffeeShop", "bssid": "00:11:22:33:44:55", "rssi": -80, "quality": 40, "khz": 2462000}],
                  available=[{"ssid": "CampusNet", "secure": True, "auth": 6, "cipher": 4}, {"ssid": "CoffeeShop", "secure": False, "auth": 1, "cipher": 0}])
    scan = wlan.scan_native(api, connection=lambda: ("CampusNet", "30:86:2d:11:22:01"))
    a, b = scan.aps
    assert (a.channel, a.band_ghz, a.signal_percent, a.rssi_dbm, a.security) == (36, 5.0, 84, -57, "WPA2-Enterprise/CCMP")
    assert (b.channel, b.band_ghz, b.security) == (11, 2.4, "Open/None")
    assert scan.backend == "native" and scan.connected_ssid == "CampusNet" and api.closed, "the handle is always closed"


@pytest.mark.parametrize("api,code,fix_word", [
    (FakeApi(bss_code=5), "access_denied", "Location"),                     # Windows 11 24H2: scans need Location permission
    (FakeApi(open_code=1062), "no_wlan_service", "WLAN AutoConfig"),
    (FakeApi(interfaces=None), "no_interface", "adapter"),
    (FakeApi(bss_code=87), "failed", None),
])
def test_native_failures_are_classified_and_carry_a_fix(api, code, fix_word) -> None:
    with pytest.raises(WifiUnavailable) as e:
        wlan.scan_native(api, connection=lambda: (None, None))
    assert e.value.code == code and (fix_word is None or fix_word in (e.value.fix or ""))
    assert api.closed or code == "no_wlan_service"


def test_netsh_is_the_fallback_but_a_location_refusal_is_final(monkeypatch) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    calls = []
    monkeypatch.setattr(wlan, "scan_with_netsh", lambda: calls.append("netsh") or wlan.WifiScan(backend="netsh"))
    monkeypatch.setattr(wlan, "scan_native", lambda: (_ for _ in ()).throw(WifiUnavailable("failed", "struct mismatch")))
    assert wlan.scan().backend == "netsh" and calls == ["netsh"]
    monkeypatch.setattr(wlan, "scan_native", lambda: (_ for _ in ()).throw(WifiUnavailable("access_denied", "denied", wlan.LOCATION_FIX)))
    with pytest.raises(WifiUnavailable) as e:
        wlan.scan()
    assert e.value.code == "access_denied" and calls == ["netsh"], "netsh would be refused for the same reason: it is not tried"


def test_netsh_failure_with_no_output_is_reported_with_the_location_fix() -> None:
    runner = lambda *a, **k: SimpleNamespace(returncode=1, stdout="The requested operation requires elevation.\n", stderr="")   # noqa: E731
    with pytest.raises(WifiUnavailable) as e:
        wlan.scan_with_netsh(runner)
    assert "exit code 1" in e.value.message and "requires elevation" in e.value.message and "Location" in e.value.fix


@pytest.mark.skipif(platform.system() != "Windows", reason="the native Wifi API exists only on Windows")
def test_a_real_scan_on_this_machine_returns_well_formed_access_points_or_a_classified_reason() -> None:
    try:
        scan = wlan.scan()
    except WifiUnavailable as exc:
        pytest.skip(f"no Wi-Fi scan possible here: {exc.code}")
    for ap in scan.aps:
        assert normalize_bssid(ap.bssid) == ap.bssid and (ap.channel is None or 1 <= ap.channel <= 233)
        assert ap.signal_percent is None or 0 <= ap.signal_percent <= 100


# ── the access-point store and its rules ────────────────────────────────────
def ap(bssid, ssid="CampusNet", security="WPA2-Enterprise/CCMP", channel=36, signal=80) -> dict:
    return AccessPoint(ssid=ssid, bssid=bssid, security=security, channel=channel, signal_percent=signal).to_dict()


WATCH = {"campusnet"}


@pytest_asyncio.fixture
async def store(tmp_path):
    s = ApStore(str(tmp_path / "aps.db"))
    await s.init()
    return s


@pytest.mark.asyncio
async def test_the_first_scan_only_learns(store) -> None:
    assert await store.observe([ap("30:86:2d:00:00:01"), ap("de:ad:be:00:00:09")], WATCH) == []
    assert await store.count() == 2


@pytest.mark.asyncio
async def test_hundreds_of_access_points_of_one_system_are_not_news(store) -> None:
    """The campus case: one SSID, one vendor prefix, a new BSSID every few steps."""
    await store.observe([ap("30:86:2d:00:00:01")], WATCH)
    findings = []
    for i in range(2, 202):
        findings += await store.observe([ap(f"30:86:2d:{i // 256:02x}:{i % 256:02x}:ff", channel=36 if i % 2 else 6)], WATCH)
    assert findings == [], "200 new access points under the same SSID and vendor prefix raise nothing"
    assert await store.count() == 201


@pytest.mark.asyncio
async def test_unfamiliar_hardware_under_a_watched_name_is_reported_with_its_evidence(store) -> None:
    await store.observe([ap("30:86:2d:00:00:01"), ap("30:86:2d:00:00:02")], WATCH)
    (f,) = await store.observe([ap("de:ad:be:ef:00:66")], WATCH)
    assert f.kind == "unexpected_oui" and f.bssid == "de:ad:be:ef:00:66"
    assert f.evidence["observed_oui"] == "de:ad:be" and f.evidence["known_ouis"] == ["30:86:2d"] and f.evidence["known_bssids"] == 2
    assert await store.observe([ap("de:ad:be:ef:00:66")], WATCH) == [], "reported once; the same BSSID is not new again"


@pytest.mark.asyncio
async def test_a_reported_twin_does_not_make_a_second_twin_look_ordinary_until_you_confirm_it(store) -> None:
    await store.observe([ap("30:86:2d:00:00:01")], WATCH)
    assert [f.kind for f in await store.observe([ap("de:ad:be:ef:00:66")], WATCH)] == ["unexpected_oui"]
    assert [f.kind for f in await store.observe([ap("de:ad:be:ef:00:67")], WATCH)] == ["unexpected_oui"], "same hardware, still unfamiliar"
    assert await store.set_known("de:ad:be:ef:00:66", True) is True
    assert await store.observe([ap("de:ad:be:ef:00:68")], WATCH) == [], "confirmed: its vendor prefix is now part of the accepted set"
    assert await store.set_known("00:00:00:00:00:00", True) is False


@pytest.mark.asyncio
async def test_a_network_you_do_not_watch_is_recorded_not_judged(store) -> None:
    await store.observe([ap("aa:aa:aa:00:00:01", ssid="Neighbour")], WATCH)
    assert await store.observe([ap("bb:bb:bb:00:00:02", ssid="Neighbour")], WATCH) == []
    assert await store.count() == 2


@pytest.mark.asyncio
async def test_an_open_twin_of_a_secured_network_is_a_security_mismatch_but_unknown_security_is_not_compared(store) -> None:
    await store.observe([ap("30:86:2d:00:00:01")], WATCH)
    (f,) = await store.observe([ap("30:86:2d:00:00:77", security="Open/None")], WATCH)       # same vendor prefix, but open
    assert f.kind == "security_mismatch" and f.evidence["observed_security"] == "Open/None" and f.evidence["known_security"] == ["WPA2-Enterprise/CCMP"]
    assert await store.observe([ap("30:86:2d:00:00:78", security=None)], WATCH) == [], "unknown (e.g. a language the parser does not know) is never a mismatch"


@pytest.mark.asyncio
async def test_a_neighbours_access_point_renamed_to_your_network_is_a_new_access_point_for_that_name(store) -> None:
    await store.observe([ap("30:86:2d:00:00:01"), ap("de:ad:be:ef:00:66", ssid="NeighbourGuest")], WATCH)
    (f,) = await store.observe([ap("30:86:2d:00:00:01"), ap("de:ad:be:ef:00:66", ssid="CampusNet")], WATCH)
    assert f.kind == "unexpected_oui" and f.bssid == "de:ad:be:ef:00:66", "same BSSID, new name: the cheapest twin there is"


@pytest.mark.asyncio
async def test_a_bssid_that_switches_security_is_reported(store) -> None:
    await store.observe([ap("30:86:2d:00:00:01")], WATCH)
    (f,) = await store.observe([ap("30:86:2d:00:00:01", security="Open/None")], WATCH)
    assert f.kind == "security_mismatch" and f.evidence["previous_security_of_this_bssid"] == "WPA2-Enterprise/CCMP"


@pytest.mark.asyncio
async def test_a_channel_change_counts_only_after_enough_sightings(store) -> None:
    await store.observe([ap("30:86:2d:00:00:01", channel=36)], WATCH)
    for _ in range(3):
        await store.observe([ap("30:86:2d:00:00:01", channel=36)], WATCH)
    assert await store.observe([ap("30:86:2d:00:00:01", channel=149)], WATCH) == [], "4 sightings: access points do hop channels"
    store2 = ApStore(str(store._db_path))
    for _ in range(3):
        await store2.observe([ap("30:86:2d:00:00:01", channel=149)], WATCH)
    (f,) = await store2.observe([ap("30:86:2d:00:00:01", channel=44)], WATCH)
    assert f.kind == "unexpected_channel" and f.evidence["observed_channel"] == 44 and 36 in f.evidence["channels_used_before"]


@pytest.mark.asyncio
async def test_the_baseline_survives_a_restart(tmp_path) -> None:
    first = ApStore(str(tmp_path / "keep.db"))
    await first.observe([ap("30:86:2d:00:00:01")], WATCH)
    second = ApStore(str(tmp_path / "keep.db"))                                # a new process: nothing is held in memory
    assert [f.kind for f in await second.observe([ap("de:ad:be:ef:00:66")], WATCH)] == ["unexpected_oui"]


# ── through the correlation engine ──────────────────────────────────────────
async def engine_with_aps(tmp_path, **env) -> CorrelationEngine:
    base = BaselineStore(str(tmp_path / "b.db"), min_observations=3)
    await base.init()
    aps = ApStore(str(tmp_path / "b.db"))
    await aps.init()
    return CorrelationEngine(base, AppLayerScorer(), WigleClient("", ""), ap_store=aps)


def scan_event(aps: list[dict], connected="CampusNet") -> SensorEvent:
    return SensorEvent(event_type=EventType.WIFI_SCAN, timestamp=datetime.now(timezone.utc), sensor="wifi",
                       raw={"aps": aps, "connected_ssid": connected, "connected_bssid": aps[0]["bssid"] if aps else None, "backend": "native"})


@pytest.mark.asyncio
async def test_the_connected_network_is_watched_automatically_and_an_open_twin_alerts(tmp_path) -> None:
    engine = await engine_with_aps(tmp_path)
    assert await engine.correlate(scan_event([ap("30:86:2d:00:00:01")])) == []                      # learning
    alerts = await engine.correlate(scan_event([ap("30:86:2d:00:00:01"), ap("30:86:2d:00:00:77", security="Open/None")]))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type == AlertType.EVIL_TWIN and a.severity == Severity.HIGH
    assert a.fused_score == SECURITY_MISMATCH_POINTS + OPEN_TWIN_BONUS
    assert {s.name for s in a.evidence.signals} >= {"security_mismatch", "open_twin", "wigle"}
    wigle = next(s for s in a.evidence.signals if s.name == "wigle")
    assert wigle.available is False and "credentials" in (wigle.reason or "").lower(), "no WiGLE key: said so, scored on the rest"
    assert a.evidence.raw["bssid"] == "30:86:2d:00:00:77" and a.evidence.raw["security"] == "Open/None"
    assert any("Mark known" in x for x in a.recommended_actions)
    again = await engine.correlate(scan_event([ap("30:86:2d:00:00:01"), ap("30:86:2d:00:00:77", security="Open/None")]))
    assert again == []


@pytest.mark.asyncio
async def test_unfamiliar_hardware_scores_as_an_evil_twin_and_a_channel_change_stays_low(tmp_path) -> None:
    engine = await engine_with_aps(tmp_path)
    await engine.correlate(scan_event([ap("30:86:2d:00:00:01")]))
    (twin,) = await engine.correlate(scan_event([ap("30:86:2d:00:00:01"), ap("de:ad:be:ef:00:66")]))
    assert twin.alert_type == AlertType.EVIL_TWIN and twin.fused_score >= EVIL_TWIN_BASE and "different hardware" in twin.evidence.signals[0].label.lower()
    for _ in range(6):
        await engine.correlate(scan_event([ap("30:86:2d:00:00:01")]))
    (chan,) = await engine.correlate(scan_event([ap("30:86:2d:00:00:01", channel=149)]))
    assert chan.alert_type == AlertType.ROGUE_AP and chan.severity == Severity.LOW and chan.evidence.wigle is None


@pytest.mark.asyncio
async def test_without_a_connection_only_configured_ssids_are_watched(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NETWORK_MONITORED_SSIDS", "HomeNet, Office")
    get_settings.cache_clear()
    try:
        engine = await engine_with_aps(tmp_path)
        assert engine.watched_ssids() == {"homenet", "office"}
        await engine.correlate(scan_event([ap("30:86:2d:00:00:01")], connected=None))
        assert await engine.correlate(scan_event([ap("30:86:2d:00:00:01"), ap("de:ad:be:ef:00:66")], connected=None)) == [], "CampusNet is not watched"
        await engine.correlate(scan_event([ap("aa:bb:cc:00:00:01", ssid="HomeNet")], connected=None))
        (t,) = await engine.correlate(scan_event([ap("aa:bb:cc:00:00:01", ssid="HomeNet"), ap("de:ad:be:ef:00:66", ssid="HomeNet")], connected=None))
        assert t.alert_type == AlertType.EVIL_TWIN
    finally:
        get_settings.cache_clear()


# ── the sensor ──────────────────────────────────────────────────────────────
def test_the_scanner_emits_one_event_per_scan_and_keeps_retrying_after_an_error() -> None:
    events: list[SensorEvent] = []
    results = iter([WifiUnavailable("access_denied", "Windows refused the Wi-Fi scan", wlan.LOCATION_FIX),
                    wlan.WifiScan(aps=[AccessPoint("CampusNet", "30:86:2d:00:00:01", channel=36)], connected_ssid="CampusNet", backend="native")])

    def scan_fn():
        r = next(results)
        if isinstance(r, Exception):
            raise r
        return r

    s = WifiScanner(events.append, 30, ["CampusNet"], scan_fn=scan_fn)
    assert s.scan_once() is False
    st = s.status()
    assert st["available"] is False and st["error"]["code"] == "access_denied" and "Location" in st["fix"] and events == []
    assert s.scan_once() is True
    st = s.status()
    assert st["available"] is True and st["error"] is None and st["ap_count"] == 1 and st["backend"] == "native"
    assert len(events) == 1 and events[0].event_type == EventType.WIFI_SCAN and events[0].raw["aps"][0]["oui"] == "30:86:2d"
    assert events[0].raw["connected_ssid"] == "CampusNet" and events[0].raw["monitored"] == ["CampusNet"]


def test_the_scanner_thread_starts_and_stops_cleanly_and_an_empty_scan_is_a_real_answer() -> None:
    events: list[SensorEvent] = []
    s = WifiScanner(events.append, 5, scan_fn=lambda: wlan.WifiScan(aps=[], backend="netsh"))
    for _ in range(5):
        s.start()
        time.sleep(0.05)
        s.stop()
    assert events and events[0].raw["aps"] == [] and s.status()["ap_count"] == 0
    assert [t for t in threading.enumerate() if t.name == "sensor-wifi"] == []


def test_a_crashing_backend_becomes_a_visible_reason_not_a_dead_thread() -> None:
    s = WifiScanner(lambda e: None, 30, scan_fn=lambda: 1 / 0)
    assert s.scan_once() is False
    assert s.status()["error"]["code"] == "failed" and "ZeroDivisionError" in s.status()["reason"]


# ── API ─────────────────────────────────────────────────────────────────────
def test_the_access_point_endpoints_list_confirm_and_validate(tmp_path, monkeypatch) -> None:
    import asyncio

    from fastapi.testclient import TestClient

    from app.main import app
    from app.network import service as network_service

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'api.db').as_posix()}")
    get_settings.cache_clear()
    try:
        with TestClient(app) as c:
            svc = network_service.get_service()
            asyncio.run(svc.aps.observe([ap("30:86:2d:00:00:01")], WATCH))
            rows = c.get("/network/aps").json()
            assert rows[0]["bssid"] == "30:86:2d:00:00:01" and rows[0]["known"] is False and rows[0]["watched"] is False
            assert c.post("/network/aps/known", json={"bssid": "30-86-2D-00-00-01", "known": True}).json() == {"bssid": "30:86:2d:00:00:01", "known": True}
            assert c.get("/network/aps").json()[0]["known"] is True
            assert c.post("/network/aps/known", json={"bssid": "nonsense", "known": True}).status_code == 400
            assert c.post("/network/aps/known", json={"bssid": "aa:bb:cc:dd:ee:ff", "known": True}).status_code == 404
            assert c.post("/network/aps/known", json={"bssid": "30:86:2d:00:00:01"}, headers={"Authorization": ""}).status_code == 401
    finally:
        get_settings.cache_clear()
