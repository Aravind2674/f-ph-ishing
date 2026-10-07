"""
ThreatFusion – Wi-Fi access-point scanner
=========================================

Lists the access points in range every ``interval`` seconds (``wlan.py``: the Windows Native Wifi API, ``netsh`` as a fallback; any
Windows language) and reports each scan as **one** ``WIFI_SCAN`` event carrying the whole list.  It judges nothing: remembering access
points and deciding which one is suspicious is the correlator's job (``aps.py``), which can read and write the database.

No monitor mode and no Npcap are needed.  When a scan cannot be made the sensor says exactly why (``error.code`` / ``message`` / ``fix``:
Location services off, no adapter, WLAN service stopped …) and keeps trying every interval, so fixing the cause needs no restart.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

from app.network.models import EventType, SensorEvent
from app.network.sensor import wlan
from app.network.sensor.base import BaseSensor, EmitFn, _iso
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class WifiScanner(BaseSensor):
    name = "wifi"

    def __init__(self, emit: EmitFn, interval_seconds: int = 30, monitored_ssids: Optional[list[str]] = None, *,
                 scan_fn: Optional[Callable[[], wlan.WifiScan]] = None) -> None:
        super().__init__(emit)
        self._interval = max(5, interval_seconds)
        self._monitored = [s.strip() for s in (monitored_ssids or []) if s.strip()]
        self._scan = scan_fn or wlan.scan
        self.error: Optional[dict[str, Any]] = None
        self.last_scan_at: Optional[float] = None
        self.ap_count: Optional[int] = None
        self.backend: Optional[str] = None

    def scan_once(self) -> bool:
        """One scan. Returns True when a scan was made (an empty list is a real answer: nothing in range)."""
        try:
            scan = self._scan()
        except wlan.WifiUnavailable as exc:
            self.available, self.reason = False, exc.message
            self.error = {"code": exc.code, "message": exc.message, "fix": exc.fix}
            logger.warning("Wi-Fi scan unavailable (%s): %s", exc.code, exc.message)
            return False
        except Exception as exc:                                      # a bug in a backend must be a visible reason, not a dead thread
            self.available, self.reason = False, f"{type(exc).__name__}: {exc}"
            self.error = {"code": "failed", "message": self.reason, "fix": None}
            logger.exception("Wi-Fi scan crashed")
            return False
        self.available, self.reason, self.error = True, None, None
        self.last_scan_at, self.ap_count, self.backend = time.time(), len(scan.aps), scan.backend
        self._emit(SensorEvent(
            event_type=EventType.WIFI_SCAN, timestamp=datetime.now(timezone.utc), sensor=self.name,
            raw={"aps": [a.to_dict() for a in scan.aps], "connected_ssid": scan.connected_ssid, "connected_bssid": scan.connected_bssid,
                 "backend": scan.backend, "monitored": list(self._monitored)}))
        return True

    def _run(self) -> None:
        logger.info("Wi-Fi scanner starting (interval=%ss, monitored=%s)", self._interval, self._monitored or "your connected network only")
        while not self._stop_event.is_set():
            self.scan_once()
            if self._stop_event.wait(self._interval):
                break

    def status(self) -> dict[str, Any]:
        d = super().status()
        d.update({"running": bool(self.running), "error": self.error, "fix": (self.error or {}).get("fix"), "backend": self.backend,
                  "ap_count": self.ap_count, "last_scan_at": _iso(self.last_scan_at)})
        return d
