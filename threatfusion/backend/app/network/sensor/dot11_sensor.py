"""
ThreatFusion – 802.11 Deauth / Disassoc Sensor
=================================================

Detects deauthentication / disassociation floods — a hallmark of WiFi
denial-of-service and evil-twin "kick the client off the real AP" attacks.

Hard requirement: **802.11 monitor mode.** Management frames like Deauth /
Disassoc are only visible to an adapter capturing raw 802.11 (not the fake
Ethernet frames a normal managed-mode Windows driver hands up). This needs
a monitor-mode-capable adapter with Npcap in monitor mode.

Honesty contract
----------------
* If no monitor interface is configured, the sensor is unavailable with a
  clear reason and emits nothing.
* If the interface exists but the driver/Npcap refuses monitor mode, the
  underlying scapy error is captured verbatim as the reason.
* It **never** manufactures deauth frames to make the feature "work".

A flood is declared only from *real counted frames*: at least
``threshold`` deauth/disassoc frames attributed to a BSSID within
``window`` seconds (measured on the frames' own capture times, so a replay
behaves like the live capture).
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable

from app.network.models import EventType, SensorEvent
from app.network.sensor.capture import CaptureSensor, packet_time

_MAX_TRACKED_BSSIDS = 2048


class Dot11Sensor(CaptureSensor):
    name = "dot11"
    sniff_kwargs = {"monitor": True}

    def __init__(self, emit, monitor_interface: str = "", threshold: int = 20, window_seconds: int = 10, **kw) -> None:
        super().__init__(emit, monitor_interface, **kw)
        self._threshold = max(3, threshold)
        self._window = max(2, window_seconds)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._last_alert: dict[str, float] = {}

    def start(self) -> None:
        if not self._interface and not self._offline:
            # Not an error the user did wrong — just an honest capability gap.
            self.available, self.running = False, False
            self.reason = ("802.11 deauth detection requires a monitor-mode interface (set NETWORK_MONITOR_INTERFACE). "
                           "None configured — this signal is disabled; other real signals continue.")
            return
        super().start()

    def handle(self, pkt: Any) -> Iterable[SensorEvent]:
        is_deauth, is_disas = pkt.haslayer("Dot11Deauth"), pkt.haslayer("Dot11Disas")
        if not (is_deauth or is_disas):
            return ()
        bssid = None
        if pkt.haslayer("Dot11"):
            bssid = (pkt["Dot11"].addr3 or pkt["Dot11"].addr2 or "").lower() or None
        key = bssid or "unknown"
        if key not in self._events and len(self._events) >= _MAX_TRACKED_BSSIDS:
            return ()                                              # bounded: a flood of spoofed BSSIDs cannot grow the table
        now = float(pkt.time)
        dq = self._events[key]
        dq.append(now)
        cutoff = now - self._window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) < self._threshold:
            return ()
        # Debounce: at most one flood alert per window per BSSID.
        if now - self._last_alert.get(key, float("-inf")) < self._window:
            return ()
        self._last_alert[key] = now
        reason_code = 0
        try:
            reason_code = int(pkt["Dot11Deauth"].reason) if is_deauth else int(pkt["Dot11Disas"].reason)
        except Exception:
            reason_code = 0
        return (SensorEvent(
            event_type=EventType.DEAUTH_FLOOD, timestamp=packet_time(pkt), sensor=self.name, bssid=bssid,
            raw={"frame_count": len(dq), "window_seconds": self._window, "threshold": self._threshold,
                 "frame_type": "deauth" if is_deauth else "disassoc", "reason_code": reason_code},
        ),)
