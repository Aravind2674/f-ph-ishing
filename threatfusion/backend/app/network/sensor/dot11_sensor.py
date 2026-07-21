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
``window`` seconds.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from app.network.models import EventType, SensorEvent
from app.network.sensor.base import BaseSensor, EmitFn, load_scapy

logger = logging.getLogger(__name__)


class Dot11Sensor(BaseSensor):
    name = "dot11"

    def __init__(
        self,
        emit: EmitFn,
        monitor_interface: str = "",
        threshold: int = 20,
        window_seconds: int = 10,
    ) -> None:
        super().__init__(emit)
        self._iface = monitor_interface or None
        self._threshold = max(3, threshold)
        self._window = max(2, window_seconds)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._last_alert: dict[str, float] = {}

    def _run(self) -> None:
        if not self._iface:
            # Not an error the user did wrong — just an honest capability gap.
            raise RuntimeError(
                "802.11 deauth detection requires a monitor-mode interface "
                "(set NETWORK_MONITOR_INTERFACE). None configured — this signal "
                "is disabled; other real signals continue."
            )

        scapy = load_scapy()
        Dot11Deauth = scapy.Dot11Deauth
        Dot11Disas = scapy.Dot11Disas
        Dot11 = scapy.Dot11

        def handle(pkt) -> None:
            is_deauth = pkt.haslayer(Dot11Deauth)
            is_disas = pkt.haslayer(Dot11Disas)
            if not (is_deauth or is_disas):
                return

            bssid = None
            if pkt.haslayer(Dot11):
                bssid = (pkt[Dot11].addr3 or pkt[Dot11].addr2 or "").lower() or None
            key = bssid or "unknown"

            now = time.monotonic()
            dq = self._events[key]
            dq.append(now)
            # Prune anything outside the sliding window.
            cutoff = now - self._window
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= self._threshold:
                # Debounce: at most one flood alert per window per BSSID.
                if now - self._last_alert.get(key, 0.0) < self._window:
                    return
                self._last_alert[key] = now
                reason_code = 0
                try:
                    if is_deauth:
                        reason_code = int(pkt[Dot11Deauth].reason)
                    elif is_disas:
                        reason_code = int(pkt[Dot11Disas].reason)
                except Exception:
                    reason_code = 0
                self._emit(SensorEvent(
                    event_type=EventType.DEAUTH_FLOOD,
                    timestamp=datetime.now(timezone.utc),
                    sensor=self.name,
                    bssid=bssid,
                    raw={
                        "frame_count": len(dq),
                        "window_seconds": self._window,
                        "threshold": self._threshold,
                        "frame_type": "deauth" if is_deauth else "disassoc",
                        "reason_code": reason_code,
                    },
                ))

        logger.info("802.11 deauth sensor sniffing on monitor iface %s", self._iface)
        scapy.sniff(
            iface=self._iface,
            prn=handle,
            store=False,
            monitor=True,
            stop_filter=self._should_stop,
        )
