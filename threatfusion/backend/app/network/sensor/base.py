"""
ThreatFusion – Sensor Base + scapy availability probe
=======================================================

Common scaffolding for capture sensors. Every sensor:

* runs its (blocking) capture loop off the event loop,
* pushes :class:`SensorEvent` objects through a thread-safe ``emit`` callback,
* tracks its own ``available`` / ``reason`` / ``running`` state so the
  service can report honest, per-sensor health via ``MonitorStatus``.

The scapy import is deferred to runtime (``load_scapy``) so the API process
boots cleanly even when scapy/Npcap are not installed — in that case the
sensor simply reports why it is unavailable.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Optional

from app.network.models import SensorEvent

logger = logging.getLogger(__name__)

EmitFn = Callable[[SensorEvent], None]


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


class BaseSensor:
    """Lifecycle + health bookkeeping shared by all sensors."""

    name: str = "base"

    def __init__(self, emit: EmitFn) -> None:
        self._emit = emit
        self.available: bool = True
        self.reason: Optional[str] = None
        self.running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the sensor in a background daemon thread.

        Any failure to initialise the real capture backend is captured and
        reflected in ``available`` / ``reason``; it never crashes the app.
        """
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._safe_run, name=f"sensor-{self.name}", daemon=True)
        self._thread.start()

    def _safe_run(self) -> None:
        self.running = True
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

    def stop(self) -> None:
        """Signal the capture loop to stop."""
        self._stop_event.set()

    def status(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "running": self.running,
            "reason": self.reason,
        }

    # ── Helpers ──────────────────────────────────────────────────────────

    def _should_stop(self, *_args: Any) -> bool:
        """scapy ``stop_filter`` predicate."""
        return self._stop_event.is_set()
