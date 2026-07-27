"""
ThreatFusion – WiFi Access-Point Scanner
==========================================

Enumerates nearby access points using the **native Windows WiFi stack**
(``netsh wlan show networks mode=bssid``). This deliberately does *not*
require 802.11 monitor mode — it works on ordinary Windows WiFi adapters,
returning real SSID / BSSID / signal / channel data for every visible AP.

Signals produced
----------------
* **Rogue AP candidate** (``ROGUE_AP``) — a BSSID that appears *after* the
  initial RF baseline has been learned. The correlation engine then queries
  WiGLE for its public history (differentiator #2).
* **Evil twin** (``EVIL_TWIN``) — one of the operator's monitored SSIDs
  being advertised by a BSSID that has never carried that SSID before.

RF baseline honesty
-------------------
The *first* completed scan seeds the set of already-present BSSIDs silently
(this is the real, observed RF environment at startup) and raises no
alerts. Only APs that appear in *subsequent* scans are treated as new
arrivals. Nothing is invented — a "new AP" is one genuinely absent from the
prior observed environment.
"""

from __future__ import annotations

import logging
import re
import subprocess
from datetime import datetime, timezone

from app.network.models import EventType, SensorEvent
from app.network.sensor.base import BaseSensor, EmitFn

logger = logging.getLogger(__name__)

_SSID_RE = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)$")
_BSSID_RE = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})\s*$")
_SIGNAL_RE = re.compile(r"^\s*Signal\s*:\s*(\d+)%")
_CHANNEL_RE = re.compile(r"^\s*Channel\s*:\s*(\d+)")


class WifiScanner(BaseSensor):
    name = "wifi"

    def __init__(
        self,
        emit: EmitFn,
        interval_seconds: int = 30,
        monitored_ssids: list[str] | None = None,
    ) -> None:
        super().__init__(emit)
        self._interval = max(5, interval_seconds)
        self._monitored = {s.strip().lower() for s in (monitored_ssids or []) if s.strip()}
        # Learned RF baseline (populated from the first real scan).
        self._known_bssids: set[str] = set()
        # ssid(lower) -> set of BSSIDs observed carrying it.
        self._ssid_bssids: dict[str, set[str]] = {}
        self._baseline_learned = False

    def _scan(self) -> list[dict]:
        """Run netsh and parse visible APs into a list of dicts.

        Raises on failure so the sensor degrades honestly (e.g. no WiFi
        adapter, WLAN AutoConfig service stopped, non-Windows host).
        """
        proc = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            encoding="utf-8",
            errors="ignore",
            timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"netsh wlan failed (rc={proc.returncode}): "
                f"{(proc.stderr or proc.stdout or '').strip()[:200]}"
            )
        out = proc.stdout or ""
        low = out.lower()
        if "wireless" in low and ("not running" in low or "no wireless" in low):
            raise RuntimeError("WLAN AutoConfig service not running or no wireless interface")

        aps: list[dict] = []
        current_ssid: str | None = None
        current: dict | None = None
        for line in out.splitlines():
            m = _SSID_RE.match(line)
            if m:
                current_ssid = m.group(1).strip()
                continue
            m = _BSSID_RE.match(line)
            if m:
                if current is not None:
                    aps.append(current)
                current = {
                    "ssid": current_ssid or "",
                    "bssid": m.group(1).lower(),
                    "signal": None,
                    "channel": None,
                }
                continue
            if current is not None:
                m = _SIGNAL_RE.match(line)
                if m:
                    current["signal"] = int(m.group(1))
                    continue
                m = _CHANNEL_RE.match(line)
                if m:
                    current["channel"] = int(m.group(1))
                    continue
        if current is not None:
            aps.append(current)
        return aps

    def _process(self, aps: list[dict]) -> None:
        for ap in aps:
            bssid = ap["bssid"]
            ssid = ap["ssid"]
            ssid_l = ssid.lower()

            if not self._baseline_learned:
                # First scan: learn the real environment, raise nothing.
                self._known_bssids.add(bssid)
                self._ssid_bssids.setdefault(ssid_l, set()).add(bssid)
                continue

            ts = datetime.now(timezone.utc)
            prior_bssids = self._ssid_bssids.setdefault(ssid_l, set())

            # Evil-twin: a monitored SSID carried by a BSSID never seen for it.
            if ssid_l in self._monitored and bssid not in prior_bssids:
                self._emit(SensorEvent(
                    event_type=EventType.EVIL_TWIN,
                    timestamp=ts,
                    sensor=self.name,
                    bssid=bssid,
                    ssid=ssid,
                    channel=ap.get("channel"),
                    signal=ap.get("signal"),
                    raw={"known_bssids_for_ssid": sorted(prior_bssids)},
                ))
            # Rogue-AP candidate: a BSSID absent from the learned baseline.
            elif bssid not in self._known_bssids:
                self._emit(SensorEvent(
                    event_type=EventType.ROGUE_AP,
                    timestamp=ts,
                    sensor=self.name,
                    bssid=bssid,
                    ssid=ssid,
                    channel=ap.get("channel"),
                    signal=ap.get("signal"),
                    raw={"first_seen": ts.isoformat()},
                ))

            self._known_bssids.add(bssid)
            prior_bssids.add(bssid)

    def _run(self) -> None:
        logger.info("WiFi scanner starting (interval=%ss, monitored=%s)",
                    self._interval, sorted(self._monitored) or "none")
        # First scan confirms the capability *and* seeds the baseline.
        aps = self._scan()
        self._process(aps)
        self._baseline_learned = True
        logger.info("WiFi RF baseline learned: %d AP(s)", len(self._known_bssids))

        while not self._stop_event.wait(self._interval):
            try:
                aps = self._scan()
                self._process(aps)
            except Exception as e:
                # Transient scan error (e.g. adapter busy) — record but keep
                # trying; a persistent failure will keep the reason current.
                self.reason = f"scan error: {e}"
                logger.warning("WiFi scan error: %s", e)
