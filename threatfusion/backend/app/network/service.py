"""
ThreatFusion – Network Monitor Service
========================================

Orchestrates the whole network layer:

    sensors (threads)  →  asyncio event queue  →  correlation engine
                                                        │
                              ┌─────────────────────────┴───────────┐
                              ▼                                       ▼
                        alert store (SQLite + memory)        SSE subscribers

Sensors run in background threads (scapy sniffing / netsh polling are
blocking) and hand events back to the event loop via a thread-safe
``emit`` callback. A single async consumer drains the queue, runs
correlation, persists any resulting alerts, and fans them out to connected
SSE clients in real time.

The service is a process-wide singleton (``get_service``) so the FastAPI
routers and the app lifespan share one instance.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from app.core.config import get_settings
from app.network.baseline_store import BaselineStore
from app.network.correlation import CorrelationEngine
from app.network.enrichment.app_layer import AppLayerScorer
from app.network.enrichment.wigle import WigleClient
from app.network.models import MonitorStatus, NetworkAlert, SensorEvent, Severity
from app.network.sensor.arp_sensor import ArpSensor
from app.network.sensor.base import BaseSensor
from app.network.sensor.dns_sensor import DnsSensor
from app.network.sensor.dot11_sensor import Dot11Sensor
from app.network.sensor.wifi_scanner import WifiScanner

logger = logging.getLogger(__name__)

_MAX_MEMORY_ALERTS = 1000

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
"""


class NetworkMonitorService:
    """Singleton coordinator for capture, correlation, storage and streaming."""

    def __init__(self) -> None:
        settings = get_settings()
        self._db_path = str(settings.database_path)
        self._settings = settings

        self.store = BaselineStore(self._db_path, settings.BASELINE_MIN_OBSERVATIONS)
        self._app_scorer = AppLayerScorer()
        self._wigle = WigleClient(settings.WIGLE_API_NAME, settings.WIGLE_API_TOKEN)
        self.engine = CorrelationEngine(self.store, self._app_scorer, self._wigle)

        self._sensors: list[BaseSensor] = []
        self._event_queue: "asyncio.Queue[SensorEvent]" = asyncio.Queue()
        self._subscribers: set["asyncio.Queue[NetworkAlert]"] = set()
        self._consumer_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        self._alerts: list[NetworkAlert] = []
        self._alerts_by_id: dict[str, NetworkAlert] = {}
        self.running = False
        self.started_at: Optional[datetime] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def init(self) -> None:
        """Create tables and hydrate recent alerts from disk."""
        await self.store.init()
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(CREATE_ALERTS_SQL)
            await db.commit()
            async with db.execute(
                "SELECT json FROM net_alerts ORDER BY timestamp DESC LIMIT ?",
                (_MAX_MEMORY_ALERTS,),
            ) as cur:
                rows = await cur.fetchall()
        for (blob,) in rows:
            try:
                alert = NetworkAlert.model_validate_json(blob)
                self._alerts.append(alert)
                self._alerts_by_id[alert.alert_id] = alert
            except Exception:
                logger.warning("Skipping malformed persisted alert")
        # Persisted order was newest-first; keep internal list newest-first.
        logger.info("NetworkMonitorService init: %d alert(s) restored", len(self._alerts))

    async def start(self) -> None:
        """Start sensors + the correlation consumer.

        Sensors that cannot initialise their capture backend degrade
        honestly (see :meth:`status`); this never raises.
        """
        if self.running:
            return
        self._loop = asyncio.get_running_loop()

        def emit(event: SensorEvent) -> None:
            # Called from sensor threads — hop back onto the event loop.
            loop = self._loop
            if loop is not None:
                loop.call_soon_threadsafe(self._event_queue.put_nowait, event)

        s = self._settings
        monitored = [x for x in s.NETWORK_MONITORED_SSIDS.split(",") if x.strip()]
        self._sensors = [
            ArpSensor(emit, s.NETWORK_CAPTURE_INTERFACE, s.NETWORK_GATEWAY_IP),
            DnsSensor(emit, s.NETWORK_CAPTURE_INTERFACE),
            WifiScanner(emit, s.WIFI_SCAN_INTERVAL_SECONDS, monitored),
            Dot11Sensor(
                emit, s.NETWORK_MONITOR_INTERFACE,
                s.DEAUTH_FLOOD_THRESHOLD, s.DEAUTH_WINDOW_SECONDS,
            ),
        ]

        self._consumer_task = asyncio.create_task(self._consume(), name="net-consumer")
        for sensor in self._sensors:
            sensor.start()

        self.running = True
        self.started_at = datetime.now(timezone.utc)
        logger.info("Network monitoring started with %d sensor(s)", len(self._sensors))

    async def stop(self) -> None:
        """Stop sensors and the consumer; release the WiGLE client."""
        if not self.running:
            return
        for sensor in self._sensors:
            sensor.stop()
        if self._consumer_task:
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
            self._consumer_task = None
        await self._wigle.close()
        self.running = False
        logger.info("Network monitoring stopped")

    # ------------------------------------------------------------------
    # Event consumption
    # ------------------------------------------------------------------

    async def _consume(self) -> None:
        while True:
            event = await self._event_queue.get()
            try:
                alerts = await self.engine.correlate(event)
                for alert in alerts:
                    await self._store_alert(alert)
                    self._broadcast(alert)
            except Exception:
                logger.exception("Error handling sensor event")

    async def _store_alert(self, alert: NetworkAlert) -> None:
        self._alerts.insert(0, alert)
        self._alerts_by_id[alert.alert_id] = alert
        if len(self._alerts) > _MAX_MEMORY_ALERTS:
            dropped = self._alerts[_MAX_MEMORY_ALERTS:]
            self._alerts = self._alerts[:_MAX_MEMORY_ALERTS]
            for d in dropped:
                self._alerts_by_id.pop(d.alert_id, None)
        try:
            async with aiosqlite.connect(self._db_path) as db:
                await db.execute(
                    "INSERT OR REPLACE INTO net_alerts "
                    "(alert_id, timestamp, alert_type, severity, fused_score, title, "
                    "device_mac, device_ip, json) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        alert.alert_id,
                        alert.timestamp.isoformat(),
                        alert.alert_type.value,
                        alert.severity.value,
                        alert.fused_score,
                        alert.title,
                        alert.device_mac,
                        alert.device_ip,
                        alert.model_dump_json(),
                    ),
                )
                await db.commit()
        except Exception:
            logger.exception("Failed to persist alert %s", alert.alert_id)
        logger.info(
            "ALERT [%s/%s] %.0f — %s",
            alert.alert_type.value, alert.severity.value, alert.fused_score, alert.title,
        )

    # ------------------------------------------------------------------
    # SSE pub/sub
    # ------------------------------------------------------------------

    def subscribe(self) -> "asyncio.Queue[NetworkAlert]":
        q: "asyncio.Queue[NetworkAlert]" = asyncio.Queue(maxsize=100)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: "asyncio.Queue[NetworkAlert]") -> None:
        self._subscribers.discard(q)

    def _broadcast(self, alert: NetworkAlert) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(alert)
            except asyncio.QueueFull:
                # Slow client — drop rather than block the whole pipeline.
                logger.debug("Dropping alert for a slow SSE subscriber")

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_alerts(
        self, severity: Optional[str] = None, limit: int = 200
    ) -> list[NetworkAlert]:
        items = self._alerts
        if severity:
            want = severity.strip().lower()
            items = [a for a in items if a.severity.value.lower() == want]
        return items[:limit]

    def get_alert(self, alert_id: str) -> Optional[NetworkAlert]:
        return self._alerts_by_id.get(alert_id)

    async def status(self) -> MonitorStatus:
        sensors = {s.name: s.status() for s in self._sensors}
        # Advertise configured-but-not-started sensors too, so the UI can show
        # the intended capability surface even before monitoring starts.
        if not sensors:
            sensors = {
                "arp": {"available": None, "running": False, "reason": "not started"},
                "dns": {"available": None, "running": False, "reason": "not started"},
                "wifi": {"available": None, "running": False, "reason": "not started"},
                "dot11": {"available": None, "running": False, "reason": "not started"},
            }
        return MonitorStatus(
            running=self.running,
            sensors=sensors,
            alert_count=len(self._alerts),
            device_count=await self.store.device_count(),
            started_at=self.started_at,
        )


# ── Process-wide singleton ───────────────────────────────────────────────
_service: Optional[NetworkMonitorService] = None


def get_service() -> NetworkMonitorService:
    """Return the shared :class:`NetworkMonitorService` instance."""
    global _service
    if _service is None:
        _service = NetworkMonitorService()
    return _service
