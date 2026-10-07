"""
ThreatFusion – Sensor Base + scapy availability probe
=======================================================

Common scaffolding for capture sensors. Every sensor:

* runs its capture off the event loop (a polling thread, or scapy's ``AsyncSniffer`` thread — see ``capture.py``),
* pushes :class:`SensorEvent` objects through a thread-safe ``emit`` callback,
* tracks its own ``available`` / ``reason`` / ``running`` state so the service can report honest, per-sensor health.

Lifecycle contract (A3-2, each point has a test): ``start()`` and ``stop()`` are **idempotent**; ``stop()`` waits for the worker
to finish (bounded), so a start/stop loop leaves no thread behind; a start after a stop works.

The scapy import is deferred to runtime (``load_scapy``) so the API process boots cleanly even when scapy/Npcap are not
installed — in that case the sensor simply reports why it is unavailable.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

from app.network.models import SensorEvent

logger = logging.getLogger(__name__)

EmitFn = Callable[[SensorEvent], None]

STOP_JOIN_SECONDS = 5.0


def load_scapy() -> Any:
    """Import and return the scapy module, or raise a clear error.

    Isolated here so every sensor reports an identical, actionable reason
    when the capture backend is missing.
    """
    try:
        import scapy.all as scapy  # noqa: WPS433 (runtime import is intentional)
        return scapy
    except Exception as e:  # ImportError, or Npcap DLL load failure on Windows
        raise RuntimeError(
            f"scapy/Npcap not available: {e}. Install scapy and Npcap "
            f"(https://npcap.com/) to enable real capture."
        ) from e


def _iso(epoch: Optional[float]) -> Optional[str]:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat() if epoch else None


class BaseSensor:
    """Lifecycle + health bookkeeping shared by all sensors (polling-thread flavour)."""

    name: str = "base"

    def __init__(self, emit: EmitFn) -> None:
        self._raw_emit = emit
        self.events_emitted: int = 0            # events this sensor has handed to the service
        self.last_event_at: Optional[float] = None
        self.available: bool = True
        self.reason: Optional[str] = None
        self.running: bool = False
        self.packets_seen: int = 0              # capture sensors count what they receive; polling sensors leave it at 0
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()

    def _emit(self, event: SensorEvent) -> None:
        """Hand an event to the service, counting it (the status shows per-sensor event counts)."""
        self.events_emitted += 1
        self.last_event_at = time.time()
        self._raw_emit(event)

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the sensor in a background daemon thread (no-op while it is already running).

        Any failure to initialise the real capture backend is captured and reflected in ``available`` / ``reason``;
        it never crashes the app.
        """
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self.available, self.reason = True, None
            self.running = True
            self._thread = threading.Thread(target=self._safe_run, name=f"sensor-{self.name}", daemon=True)
            self._thread.start()

    def _safe_run(self) -> None:
        try:
            self._run()
        except Exception as e:  # degrade honestly; do not fake events
            self.available = False
            self.reason = str(e)
            logger.warning("Sensor '%s' degraded: %s", self.name, e)
        finally:
            self.running = False

    def _run(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def stop(self, timeout: float = STOP_JOIN_SECONDS) -> None:
        """Signal the worker to stop and wait (bounded) for it to finish. Safe to call repeatedly or when never started."""
        with self._lock:
            thread = self._thread
            self._stop_event.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        with self._lock:
            if thread is not None and not thread.is_alive():
                self._thread = None
                self.running = False
            elif thread is not None:
                logger.warning("Sensor '%s' did not stop within %.0fs", self.name, timeout)

    def status(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "running": self.running,
            "reason": self.reason,
            "packets_seen": self.packets_seen,
            "events": self.events_emitted,
            "last_event_at": _iso(self.last_event_at),
        }

    # ── Helpers ──────────────────────────────────────────────────────────

    def _should_stop(self, *_args: Any) -> bool:
        """scapy ``stop_filter`` predicate."""
        return self._stop_event.is_set()
