"""
ThreatFusion – Network Monitor Service
========================================

Orchestrates the whole network layer:

    preflight ─► one shared sniffer ─► ARP / DNS / TLS parsers ─┐
                 Wi-Fi scanner (netsh) ─────────────────────────┤
                                                                ▼
                          bounded inbox (thread-safe, drops are counted)
                                                                ▼
                                    correlation engine (asyncio consumer)
                                                                │
                              ┌─────────────────────────────────┴───────────┐
                              ▼                                               ▼
                    alert store (SQLite + memory)                    SSE subscribers (ring of the last 500)

Honesty rules (revamp T2a)
--------------------------
* ``start()`` runs the capture **preflight first**.  If capture cannot work (no scapy, no Npcap, not elevated, no interface) *nothing*
  is started, ``running`` is false and the status carries the preflight's state, reason and one-line fix.
* ``running`` is true only while the capture thread is alive, and the *state* is ``capturing`` only after at least one real packet has
  been seen; ``starting`` before that, ``no_traffic`` after ``NETWORK_NO_TRAFFIC_SECONDS`` without one.
* Sensor events cross from sensor threads to the event loop through a bounded thread-safe inbox.  When it is full an event is dropped
  and ``dropped_events`` goes up — never silently, never by blocking a sniffer thread.

The service is a process-wide singleton (``get_service``) so the FastAPI routers and the app lifespan share one instance.
"""

from __future__ import annotations

import asyncio
import logging
import queue
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import aiosqlite

from app.core.config import get_settings
from app.network.baseline_store import BaselineStore
from app.network.correlation import CorrelationEngine
from app.network.enrichment.app_layer import AppLayerScorer
from app.network.enrichment.wigle import WigleClient
from app.network.models import MonitorStatus, NetworkAlert, SensorEvent
from app.network.preflight import CapturePreflight, CaptureState, Probes, effective_state, fix_for, run_preflight
from app.network.sensor.arp_sensor import ArpSensor
from app.network.sensor.base import _iso
from app.network.sensor.dns_sensor import DnsSensor
from app.network.sensor.shared import SharedCapture
from app.network.sensor.tls_sensor import TlsSensor
from app.network.sensor.wifi_scanner import WifiScanner

logger = logging.getLogger(__name__)

_MAX_MEMORY_ALERTS = 1000
_RATE_WINDOW_SECONDS = 10.0

CREATE_ALERTS_SQL = """
CREATE TABLE IF NOT EXISTS net_alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    fused_score REAL NOT NULL,
    title TEXT,
    device_mac TEXT,
    device_ip TEXT,
    json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_net_alerts_ts ON net_alerts(timestamp);
CREATE TABLE IF NOT EXISTS net_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class MonitorRunning(RuntimeError):
    """A setting that needs the monitor stopped was changed while it was running."""


class UnknownInterface(ValueError):
    """The requested capture interface does not exist on this machine."""


class NetworkMonitorService:
    """Singleton coordinator for capture, correlation, storage and streaming.

    The three keyword arguments exist for tests: a fake preflight, a fake sniffer factory (no Npcap needed) and a fake Wi-Fi scanner.
    """

    def __init__(self, *, preflight_fn: Optional[Callable[[str], CapturePreflight]] = None, sniffer_factory: Optional[Callable[..., Any]] = None,
                 wifi_factory: Optional[Callable[..., Any]] = None, list_interfaces_fn: Optional[Callable[[], list]] = None) -> None:
        settings = get_settings()
        self._db_path = str(settings.database_path)
        self._settings = settings
        self._preflight_fn = preflight_fn or (lambda iface: run_preflight(iface))
        self._sniffer_factory = sniffer_factory
        self._wifi_factory = wifi_factory or WifiScanner
        self._list_interfaces_fn = list_interfaces_fn or Probes().list_interfaces

        self.store = BaselineStore(self._db_path, settings.BASELINE_MIN_OBSERVATIONS)
        self._app_scorer = AppLayerScorer()
        self._wigle = WigleClient(settings.WIGLE_API_NAME, settings.WIGLE_API_TOKEN)
        self.engine = CorrelationEngine(self.store, self._app_scorer, self._wigle)

        # sensors → inbox (any thread) → consumer (event loop)
        self._inbox: "queue.Queue[SensorEvent]" = queue.Queue(maxsize=max(1, settings.NETWORK_EVENT_QUEUE_MAX))
        self._wake: Optional[asyncio.Event] = None
        self.dropped_events = 0

        self._capture: Optional[SharedCapture] = None
        self._parsers: list = []
        self._wifi: Any = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._lifecycle = asyncio.Lock()

        self._preflight: Optional[CapturePreflight] = None
        self._preflight_at = 0.0
        self._preflight_lock = asyncio.Lock()
        self._interface_override: Optional[str] = None
        self._capture_started_mono = 0.0
        self._rate_samples: "deque[tuple[float, int]]" = deque(maxlen=64)

        # alerts: newest first in memory; a ring of (sequence, alert) lets an SSE client resume with Last-Event-ID
        self._alerts: list[NetworkAlert] = []
        self._alerts_by_id: dict[str, NetworkAlert] = {}
        self._ring: "deque[tuple[int, NetworkAlert]]" = deque(maxlen=max(1, settings.NETWORK_ALERT_RING))
        self._seq = 0
        self._subscribers: set["asyncio.Queue[tuple[int, NetworkAlert]]"] = set()
        self.running = False
        self.started_at: Optional[datetime] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def init(self) -> None:
        """Create tables, hydrate recent alerts and the saved interface choice from disk."""
        await self.store.init()
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(CREATE_ALERTS_SQL)
            await db.commit()
            async with db.execute("SELECT rowid, json FROM net_alerts ORDER BY rowid DESC LIMIT ?", (_MAX_MEMORY_ALERTS,)) as cur:
                rows = await cur.fetchall()
            async with db.execute("SELECT value FROM net_settings WHERE key = 'capture_interface'") as cur:
                saved = await cur.fetchone()
        self._interface_override = (saved[0] if saved and saved[0] else None)
        for rowid, blob in rows:                                  # newest first
            try:
                alert = NetworkAlert.model_validate_json(blob)
            except Exception:
                logger.warning("Skipping malformed persisted alert")
                continue
            self._alerts.append(alert)
            self._alerts_by_id[alert.alert_id] = alert
            self._seq = max(self._seq, int(rowid))
            if len(self._ring) < (self._ring.maxlen or 0):
                self._ring.appendleft((int(rowid), alert))        # keep ascending order: oldest on the left
        logger.info("NetworkMonitorService init: %d alert(s) restored", len(self._alerts))

    def selected_interface_name(self) -> str:
        """The interface to capture on: the one picked in Settings, else NETWORK_CAPTURE_INTERFACE, else '' (= the default route)."""
        return self._interface_override or self._settings.NETWORK_CAPTURE_INTERFACE.strip()

    def _make_emit(self) -> Callable[[SensorEvent], None]:
        def emit(event: SensorEvent) -> None:                     # called from sensor threads
            try:
                self._inbox.put_nowait(event)
            except queue.Full:
                self.dropped_events += 1                          # visible in /network/status — never silent, never blocking
                return
            loop, wake = self._loop, self._wake
            if loop is not None and wake is not None and not loop.is_closed():
                loop.call_soon_threadsafe(wake.set)
        return emit

    async def preflight(self, *, max_age: float = 15.0, force: bool = False) -> CapturePreflight:
        """The capture preflight, cached for ``max_age`` seconds and never re-run while capture is live (a second probe could clash)."""
        async with self._preflight_lock:
            if self.running and self._preflight is not None:
                return self._preflight
            if not force and self._preflight is not None and time.monotonic() - self._preflight_at < max_age:
                return self._preflight
            self._preflight = await asyncio.to_thread(self._preflight_fn, self.selected_interface_name())
            self._preflight_at = time.monotonic()
            return self._preflight

    async def start(self) -> None:
        """Preflight, then start capture.  Never raises: a machine that cannot capture gets a reason and a fix, and nothing runs."""
        async with self._lifecycle:
            if self.running:
                return
            self._loop = asyncio.get_running_loop()
            self._wake = asyncio.Event()
            pre = await self.preflight(force=True)
            if not pre.ok:
                logger.warning("Network monitoring not started — %s: %s", pre.state.value, pre.reason)
                return

            s = self._settings
            emit = self._make_emit()
            iface = pre.selected_interface or ""
            gateway = s.NETWORK_GATEWAY_IP.strip() or (pre.details.get("gateway") or "")
            parsers = [ArpSensor(emit, iface, gateway), DnsSensor(emit, iface), TlsSensor(emit, iface)]
            capture = SharedCapture(emit, iface, parsers, sniffer_factory=self._sniffer_factory)
            await asyncio.to_thread(capture.start)               # waits (bounded) for the handle to open or fail
            self._capture, self._parsers = capture, parsers
            if not (capture.available and capture.running):
                logger.warning("Capture could not be started on %s: %s", iface, capture.reason)
                return                                            # the status reports capture.reason verbatim

            monitored = [x.strip() for x in s.NETWORK_MONITORED_SSIDS.split(",") if x.strip()]
            self._wifi = self._wifi_factory(emit, s.WIFI_SCAN_INTERVAL_SECONDS, monitored)
            self._wifi.start()

            self._consumer_task = asyncio.create_task(self._consume(), name="net-consumer")
            self.running = True
            self.started_at = datetime.now(timezone.utc)
            self._capture_started_mono = time.monotonic()
            self._rate_samples.clear()
            logger.info("Network monitoring started on %s with %d parser(s) and the Wi-Fi scanner", iface, len(parsers))

    async def stop(self) -> None:
        """Stop the sniffer, the Wi-Fi scanner and the consumer.  Safe to call repeatedly or when nothing was started."""
        async with self._lifecycle:
            for sensor in (self._wifi, self._capture):
                if sensor is not None:
                    await asyncio.to_thread(sensor.stop)
            if self._consumer_task:
                self._consumer_task.cancel()
                try:
                    await self._consumer_task
                except asyncio.CancelledError:
                    pass
                self._consumer_task = None
            await self._wigle.close()
            was_running = self.running
            self.running = False
            self._capture, self._parsers, self._wifi = None, [], None
            if was_running:
                logger.info("Network monitoring stopped")

    # ------------------------------------------------------------------
    # Interface choice (Settings)
    # ------------------------------------------------------------------

    async def interfaces(self) -> dict[str, Any]:
        """Every interface scapy can see, which one capture would use, and where that choice came from."""
        try:
            listed = await asyncio.to_thread(self._list_interfaces_fn)
            error = None
        except Exception as exc:
            listed, error = [], f"{type(exc).__name__}: {exc}"
        pre = self._preflight
        return {
            "interfaces": [i.__dict__ for i in listed],
            "selected": pre.selected_interface if pre else None,
            "configured": self.selected_interface_name() or None,
            "source": (pre.details.get("interface_source") if pre else None),
            "error": error,
        }

    async def set_interface(self, name: str) -> dict[str, Any]:
        """Pick the capture interface (empty = automatic).  Needs the monitor stopped; the choice survives a restart."""
        if self.running:
            raise MonitorRunning("Stop monitoring before changing the capture interface.")
        name = (name or "").strip()
        if name:
            listed = await asyncio.to_thread(self._list_interfaces_fn)
            if not any(i.name == name and i.usable for i in listed):
                raise UnknownInterface(f"“{name}” is not a usable interface on this machine.")
        async with aiosqlite.connect(self._db_path) as db:
            if name:
                await db.execute("INSERT OR REPLACE INTO net_settings(key, value) VALUES ('capture_interface', ?)", (name,))
            else:
                await db.execute("DELETE FROM net_settings WHERE key = 'capture_interface'")
            await db.commit()
        self._interface_override = name or None
        self._preflight = None                                    # the next status re-checks with the new choice
        await self.preflight(force=True)
        return await self.interfaces()

    # ------------------------------------------------------------------
    # Retention / erasure (A0-10)
    # ------------------------------------------------------------------

    async def purge(self, retention_days: int) -> dict[str, int]:
        """Delete network data older than ``retention_days`` (0 or less = keep everything)."""
        if retention_days <= 0:
            return {"devices": 0, "domains": 0, "ports": 0, "alerts": 0}
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        counts = await self.store.purge_older_than(cutoff)
        async with aiosqlite.connect(self._db_path) as db:
            cur = await db.execute("DELETE FROM net_alerts WHERE timestamp < ?", (cutoff,))
            await db.commit()
            counts["alerts"] = cur.rowcount
        self._alerts = [a for a in self._alerts if a.timestamp.isoformat() >= cutoff]
        self._alerts_by_id = {a.alert_id: a for a in self._alerts}
        kept = {a.alert_id for a in self._alerts}
        self._ring = deque((item for item in self._ring if item[1].alert_id in kept), maxlen=self._ring.maxlen)
        return counts

    async def delete_all_data(self) -> dict[str, int]:
        """Erase every stored device profile, domain history and alert (user-initiated)."""
        counts = await self.store.delete_all()
        async with aiosqlite.connect(self._db_path) as db:
            cur = await db.execute("DELETE FROM net_alerts")
            await db.commit()
            counts["alerts"] = cur.rowcount
        self._alerts.clear()
        self._alerts_by_id.clear()
        self._ring.clear()
        return counts

    # ------------------------------------------------------------------
    # Event consumption
    # ------------------------------------------------------------------

    async def _consume(self) -> None:
        wake = self._wake
        assert wake is not None
        while True:
            try:
                event = self._inbox.get_nowait()
            except queue.Empty:
                wake.clear()
                if not self._inbox.empty():                       # an event slipped in between the check and the clear
                    continue
                await wake.wait()
                continue
            try:
                for alert in await self.engine.correlate(event):
                    seq = await self._store_alert(alert)
                    self._broadcast(seq, alert)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Error handling sensor event")

    async def _store_alert(self, alert: NetworkAlert) -> int:
        """Keep the alert in memory and on disk; returns its sequence number (the SQLite rowid when it was persisted)."""
        self._alerts.insert(0, alert)
        self._alerts_by_id[alert.alert_id] = alert
        if len(self._alerts) > _MAX_MEMORY_ALERTS:
            dropped = self._alerts[_MAX_MEMORY_ALERTS:]
            self._alerts = self._alerts[:_MAX_MEMORY_ALERTS]
            for d in dropped:
                self._alerts_by_id.pop(d.alert_id, None)
        seq = self._seq + 1
        try:
            async with aiosqlite.connect(self._db_path) as db:
                cur = await db.execute(
                    "INSERT OR REPLACE INTO net_alerts "
                    "(alert_id, timestamp, alert_type, severity, fused_score, title, "
                    "device_mac, device_ip, json) VALUES (?,?,?,?,?,?,?,?,?)",
                    (alert.alert_id, alert.timestamp.isoformat(), alert.alert_type.value, alert.severity.value, alert.fused_score,
                     alert.title, alert.device_mac, alert.device_ip, alert.model_dump_json()),
                )
                await db.commit()
                if cur.lastrowid:
                    seq = max(seq, int(cur.lastrowid))
        except Exception:
            logger.exception("Failed to persist alert %s", alert.alert_id)
        self._seq = seq
        self._ring.append((seq, alert))
        logger.info("ALERT [%s/%s] %.0f — %s", alert.alert_type.value, alert.severity.value, alert.fused_score, alert.title)
        return seq

    # ------------------------------------------------------------------
    # SSE pub/sub
    # ------------------------------------------------------------------

    def subscribe(self, last_event_id: Optional[int] = None) -> "asyncio.Queue[tuple[int, NetworkAlert]]":
        """A queue of ``(sequence, alert)``.  With ``last_event_id`` it starts with every alert still in the ring that is newer than that,
        so a client that reconnected after a gap does not miss any (up to the last ``NETWORK_ALERT_RING`` alerts)."""
        q: "asyncio.Queue[tuple[int, NetworkAlert]]" = asyncio.Queue(maxsize=max(100, (self._ring.maxlen or 0) + 100))
        if last_event_id is not None:
            for seq, alert in self._ring:
                if seq > last_event_id:
                    q.put_nowait((seq, alert))
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: "asyncio.Queue[tuple[int, NetworkAlert]]") -> None:
        self._subscribers.discard(q)

    def _broadcast(self, seq: int, alert: NetworkAlert) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait((seq, alert))
            except asyncio.QueueFull:
                logger.debug("Dropping alert for a slow SSE subscriber")     # a slow client must not stall the pipeline

    @property
    def last_sequence(self) -> int:
        return self._seq

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_alerts(self, severity: Optional[str] = None, limit: int = 200) -> list[NetworkAlert]:
        items = self._alerts
        if severity:
            want = severity.strip().lower()
            items = [a for a in items if a.severity.value.lower() == want]
        return items[:limit]

    def get_alert(self, alert_id: str) -> Optional[NetworkAlert]:
        return self._alerts_by_id.get(alert_id)

    def _packets_per_second(self, packets: int) -> Optional[float]:
        now = time.monotonic()
        self._rate_samples.append((now, packets))
        while len(self._rate_samples) > 2 and now - self._rate_samples[0][0] > _RATE_WINDOW_SECONDS:
            self._rate_samples.popleft()
        t0, p0 = self._rate_samples[0]
        return round((packets - p0) / (now - t0), 2) if now - t0 >= 0.5 else None

    async def status(self) -> MonitorStatus:
        pre = await self.preflight()
        capture = self._capture
        capture_alive = bool(capture is not None and capture.available and capture.running)
        running = bool(self.running and capture_alive)
        packets = capture.packets_seen if capture is not None else 0

        if capture is not None and not capture.available:
            state, reason, fix = CaptureState.ERROR, f"Capture could not be opened: {capture.reason}", fix_for(CaptureState.ERROR)
        elif self.running and not capture_alive:
            state, reason, fix = CaptureState.ERROR, f"The capture thread stopped: {(capture.reason if capture else None) or 'unknown reason'}", None
        else:
            state, reason, fix = effective_state(
                pre, sensors_running=running, packets_seen=packets,
                seconds_running=(time.monotonic() - self._capture_started_mono) if running else 0.0,
                no_packets_after=float(self._settings.NETWORK_NO_TRAFFIC_SECONDS))
        capture_dict = pre.to_dict()
        capture_dict.update({
            "state": state.value, "reason": reason, "fix": fix, "packets_seen": packets,
            "packets_per_second": self._packets_per_second(packets) if running else None,
            "filter": capture.bpf if capture is not None else None,
            "filter_fallback": capture.filter_fallback if capture is not None else False,
        })

        sensors: dict[str, dict[str, Any]] = {}
        if capture is not None:
            for parser in self._parsers:
                sensors[parser.name] = capture.parser_status(parser)
        if self._wifi is not None:
            w = self._wifi.status()
            sensors["wifi"] = {"available": w.get("available"), "running": w.get("running"), "reason": w.get("reason"), "packets": None,
                               "events": w.get("events", 0), "last_event_at": w.get("last_event_at")}
        if not sensors:
            idle = {"available": None, "running": False, "reason": "not started", "packets": 0, "events": 0, "last_event_at": None}
            sensors = {name: dict(idle) for name in ("arp", "dns", "tls", "wifi")}

        return MonitorStatus(
            running=running,
            sensors=sensors,
            alert_count=len(self._alerts),
            device_count=await self.store.device_count(),
            started_at=self.started_at if running else None,
            capture=capture_dict,
            dropped_events=self.dropped_events,
        )


# ── Process-wide singleton ───────────────────────────────────────────────
_service: Optional[NetworkMonitorService] = None


def get_service() -> NetworkMonitorService:
    """Return the shared :class:`NetworkMonitorService` instance."""
    global _service
    if _service is None:
        _service = NetworkMonitorService()
    return _service


def reset_service() -> None:
    """Forget the singleton (tests)."""
    global _service
    _service = None
