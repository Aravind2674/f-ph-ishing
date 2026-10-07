"""Revamp T2a/T2b — the network service: preflight gate, one shared sniffer, honest state, bounded inbox, resumable alert stream.

No Npcap is needed: the sniffer is a fake that feeds packets from a synthetic PCAP, and the preflight is injected.  What is
verified is the service's behaviour, not a particular network card.
"""

from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from scapy.all import rdpcap

from app.core.config import get_settings
from app.network.models import AlertEvidence, AlertType, EventType, NetworkAlert, SensorEvent, Severity
from app.network.preflight import CapturePreflight, CaptureState, InterfaceInfo
from app.network.sensor.shared import BPF_FULL, BPF_SAFE
from app.network.service import MonitorRunning, NetworkMonitorService, UnknownInterface
from tests.test_a3_capture import FakeSniffer, pcap  # noqa: F401  (pcap is a fixture)

WIFI = InterfaceInfo(name="Wi-Fi", description="Intel(R) Wi-Fi 6", ipv4=["192.168.0.50"], usable=True)
ETH = InterfaceInfo(name="Ethernet", description="Realtek", ipv4=["192.168.1.5"], usable=True)


def ready(iface: str = "") -> CapturePreflight:
    return CapturePreflight(CaptureState.READY, True, "ready", None, iface or "Wi-Fi", [WIFI, ETH],
                            {"platform": "Windows", "gateway": "192.168.0.1", "interface_source": "default route"})


def broken(state: CaptureState, reason: str, fix: str):
    return lambda iface="": CapturePreflight(state, False, reason, fix, None, [], {"platform": "Windows"})


class FakeWifi:
    """Stands in for the netsh scanner: starts / stops, never emits."""

    instances: list = []

    def __init__(self, emit, interval=30, monitored=None) -> None:
        self.running = False
        FakeWifi.instances.append(self)

    def start(self) -> None:
        self.running = True

    def stop(self) -> None:
        self.running = False

    def status(self) -> dict:
        return {"available": True, "running": self.running, "reason": None, "events": 0, "last_event_at": None}


@pytest.fixture(autouse=True)
def _tmp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'net.db').as_posix()}")
    get_settings.cache_clear()
    FakeSniffer.instances.clear()
    FakeWifi.instances.clear()
    yield
    get_settings.cache_clear()


def make_service(feed=None, *, preflight=ready, fail: str | None = None, factory=None) -> NetworkMonitorService:
    return NetworkMonitorService(
        preflight_fn=preflight,
        sniffer_factory=factory or (lambda **kw: FakeSniffer(feed=feed or [], fail=fail, **kw)),
        wifi_factory=FakeWifi,
        list_interfaces_fn=lambda: [WIFI, ETH],
    )


def leaked() -> list[str]:
    return [t.name for t in threading.enumerate() if t.name == "fake-sniffer" or t.name.startswith("sensor-")]


async def settle(svc: NetworkMonitorService, timeout: float = 5.0) -> None:
    """Wait until the consumer has drained the inbox."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if svc._inbox.empty():
            await asyncio.sleep(0.15)
            if svc._inbox.empty():
                return
        await asyncio.sleep(0.02)


# ── T2a: the preflight gates everything ─────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("state,reason,fix", [
    (CaptureState.NO_NPCAP, "Npcap is not installed", "Npcap not found — install it from npcap.com"),
    (CaptureState.NOT_ELEVATED, "lacks the privileges", "Run as Administrator"),
    (CaptureState.NO_INTERFACE, "no usable interface", "Pick an interface in Settings"),
])
async def test_when_capture_cannot_work_nothing_starts_and_the_status_says_why(state, reason, fix) -> None:
    svc = make_service(preflight=broken(state, reason, fix))
    await svc.init()
    await svc.start()
    st = await svc.status()
    assert st.running is False
    assert st.capture["state"] == state.value and st.capture["reason"] == reason and st.capture["fix"] == fix
    assert FakeSniffer.instances == [] and FakeWifi.instances == [], "no sensor of any kind is created"
    assert all(not s["running"] for s in st.sensors.values())
    assert leaked() == []


@pytest.mark.asyncio
async def test_capturing_is_claimed_only_after_a_real_packet() -> None:
    svc = make_service(feed=[])
    await svc.init()
    await svc.start()
    st = await svc.status()
    assert st.running is True and st.capture["state"] == "starting", "running with zero packets is not 'capturing'"
    assert st.capture["packets_seen"] == 0
    await svc.stop()


@pytest.mark.asyncio
async def test_no_traffic_is_reported_when_nothing_arrives(monkeypatch) -> None:
    monkeypatch.setenv("NETWORK_NO_TRAFFIC_SECONDS", "0")
    get_settings.cache_clear()
    svc = make_service(feed=[])
    await svc.init()
    await svc.start()
    st = await svc.status()
    assert st.capture["state"] == "no_traffic" and "without seeing a single packet" in st.capture["reason"] and st.capture["fix"]
    await svc.stop()


@pytest.mark.asyncio
async def test_real_packets_flip_the_state_to_capturing_and_every_sensor_reports_its_own_counts(pcap: Path) -> None:
    packets = list(rdpcap(str(pcap)))
    svc = make_service(feed=packets)
    await svc.init()
    await svc.start()
    await settle(svc)
    st = await svc.status()
    assert st.capture["state"] == "capturing" and st.capture["packets_seen"] == len(packets)
    for name in ("arp", "dns", "tls", "wifi"):
        assert set(st.sensors[name]) >= {"available", "running", "packets", "events", "last_event_at", "reason"}, name
    assert st.sensors["dns"]["packets"] == 8 and st.sensors["dns"]["events"] == 5
    assert st.sensors["tls"]["events"] == 3
    assert st.sensors["arp"]["events"] >= 2 and st.sensors["arp"]["last_event_at"]
    assert st.sensors["wifi"]["running"] is True
    assert st.dropped_events == 0 and "scope_note" in st.model_dump()
    await svc.stop()


@pytest.mark.asyncio
async def test_the_capture_interface_and_gateway_come_from_the_preflight() -> None:
    svc = make_service()
    await svc.init()
    await svc.start()
    k = FakeSniffer.instances[0].kwargs
    assert k["iface"] == "Wi-Fi"
    st = await svc.status()
    assert st.capture["details"]["gateway"] == "192.168.0.1" and st.capture["selected_interface"] == "Wi-Fi"
    await svc.stop()


# ── T2b: one shared sniffer ─────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_one_sniffer_serves_arp_dns_and_tls_with_the_combined_filter() -> None:
    svc = make_service()
    await svc.init()
    await svc.start()
    assert len(FakeSniffer.instances) == 1, "ARP, DNS and TLS share ONE capture handle"
    assert FakeSniffer.instances[0].kwargs["filter"] == BPF_FULL
    assert "arp" in BPF_FULL and "port 53" in BPF_FULL and "port 443" in BPF_FULL and "0x16" in BPF_FULL
    await svc.stop()


@pytest.mark.asyncio
async def test_a_rejected_filter_retries_once_with_the_plain_filter_and_says_so() -> None:
    seen: list[str] = []

    def factory(**kw):
        seen.append(kw["filter"])
        if kw["filter"] == BPF_FULL:
            return FakeSniffer(fail="syntax error in filter expression", **kw)
        return FakeSniffer(**kw)

    svc = make_service(factory=factory)
    await svc.init()
    await svc.start()
    st = await svc.status()
    assert seen == [BPF_FULL, BPF_SAFE]
    assert st.running and st.capture["filter"] == BPF_SAFE and st.capture["filter_fallback"] is True
    await svc.stop()


@pytest.mark.asyncio
async def test_an_interface_that_cannot_be_opened_reports_the_verbatim_reason_and_runs_nothing() -> None:
    svc = make_service(fail="Interface 'Wi-Fi' not found !")
    await svc.init()
    await svc.start()
    st = await svc.status()
    assert st.running is False and st.capture["state"] == "error"
    assert "not found" in st.capture["reason"] and "ValueError" in st.capture["reason"]
    assert FakeWifi.instances == [], "the Wi-Fi scanner is not started when capture failed"
    await svc.stop()
    assert leaked() == []


@pytest.mark.asyncio
async def test_start_stop_ten_times_leaves_no_thread_and_no_task_behind() -> None:
    svc = make_service()
    await svc.init()
    for _ in range(10):
        await svc.start()
        assert (await svc.status()).running
        await svc.start()                                       # idempotent
        await svc.stop()
        await svc.stop()                                        # idempotent
        assert not (await svc.status()).running
    assert leaked() == []
    assert len(FakeSniffer.instances) == 10, "a second start() while running must not open a second sniffer"
    assert svc._consumer_task is None


@pytest.mark.asyncio
async def test_a_full_inbox_drops_and_counts_never_blocks(monkeypatch) -> None:
    monkeypatch.setenv("NETWORK_EVENT_QUEUE_MAX", "5")
    get_settings.cache_clear()
    svc = make_service()
    await svc.init()
    emit = svc._make_emit()
    ev = SensorEvent(event_type=EventType.ARP_OBSERVED, timestamp=datetime.now(timezone.utc), sensor="arp", mac="aa:bb:cc:00:00:01")
    t0 = time.monotonic()
    for _ in range(20):
        emit(ev)                                                # no consumer is running: the inbox fills
    assert time.monotonic() - t0 < 1.0
    assert svc._inbox.qsize() == 5 and svc.dropped_events == 15
    assert (await svc.status()).dropped_events == 15


# ── T2a: choosing the interface ─────────────────────────────────────────────
@pytest.mark.asyncio
async def test_the_chosen_interface_is_used_and_survives_a_restart() -> None:
    svc = make_service()
    await svc.init()
    out = await svc.set_interface("Ethernet")
    assert out["configured"] == "Ethernet"
    await svc.start()
    assert FakeSniffer.instances[0].kwargs["iface"] == "Ethernet"
    with pytest.raises(MonitorRunning):
        await svc.set_interface("Wi-Fi")
    await svc.stop()

    again = make_service()
    await again.init()
    assert again.selected_interface_name() == "Ethernet", "the choice is stored, not held in memory"
    assert (await again.set_interface(""))["configured"] is None, "empty = automatic"


@pytest.mark.asyncio
async def test_an_unknown_interface_is_refused() -> None:
    svc = make_service()
    await svc.init()
    with pytest.raises(UnknownInterface):
        await svc.set_interface("Nonexistent 7")
    assert (await svc.interfaces())["configured"] is None


# ── T2e (backend): the alert stream resumes from Last-Event-ID ──────────────
def _alert(n: int) -> NetworkAlert:
    return NetworkAlert(alert_id=f"a{n:02d}", timestamp=datetime.now(timezone.utc), alert_type=AlertType.NEW_DEVICE, severity=Severity.LOW,
                        fused_score=30.0, title=f"alert {n}", trigger_type="t", evidence=AlertEvidence())


@pytest.mark.asyncio
async def test_a_reconnecting_client_gets_the_alerts_it_missed_in_order() -> None:
    svc = make_service()
    await svc.init()
    seqs = [await svc._store_alert(_alert(i)) for i in range(5)]
    assert seqs == sorted(set(seqs)), "sequence numbers are unique and increasing"
    q = svc.subscribe(last_event_id=seqs[1])
    got = [q.get_nowait() for _ in range(q.qsize())]
    assert [a.alert_id for _, a in got] == ["a02", "a03", "a04"] and [s for s, _ in got] == seqs[2:]
    assert svc.subscribe().qsize() == 0, "a fresh client starts empty; it loads the list over the REST endpoint"
    live = svc.subscribe(last_event_id=seqs[-1])
    svc._broadcast(99, _alert(9))
    assert live.get_nowait()[0] == 99


@pytest.mark.asyncio
async def test_the_ring_keeps_only_the_newest_alerts(monkeypatch) -> None:
    monkeypatch.setenv("NETWORK_ALERT_RING", "3")
    get_settings.cache_clear()
    svc = make_service()
    await svc.init()
    seqs = [await svc._store_alert(_alert(i)) for i in range(5)]
    q = svc.subscribe(last_event_id=0)
    assert [s for s, _ in (q.get_nowait() for _ in range(q.qsize()))] == seqs[-3:]


@pytest.mark.asyncio
async def test_sequence_numbers_continue_after_a_restart() -> None:
    first = make_service()
    await first.init()
    last = [await first._store_alert(_alert(i)) for i in range(3)][-1]
    second = make_service()
    await second.init()
    assert second.last_sequence == last
    assert await second._store_alert(_alert(7)) > last
    q = second.subscribe(last_event_id=last)
    assert [a.alert_id for _, a in (q.get_nowait() for _ in range(q.qsize()))] == ["a07"]


def test_last_event_id_can_come_from_the_header_or_the_query() -> None:
    from app.api.network import _last_id

    assert _last_id(None, None) is None and _last_id("", None) is None and _last_id("junk", None) is None
    assert _last_id("41", None) == 41 and _last_id("41", 7) == 7
