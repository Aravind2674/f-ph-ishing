"""
Packet-capture sensors on scapy's ``AsyncSniffer`` (A3-2)
=========================================================

The audited sensors called the blocking ``scapy.sniff`` inside their own thread with a ``stop_filter`` predicate.  A
``stop_filter`` is evaluated **only when a packet arrives**, so on a quiet link ``stop()`` never took effect and the thread leaked;
a second ``start()`` could race the first; and a sniffer that failed to open (wrong interface, no privileges) died in a thread that
nothing was watching.

``CaptureSensor`` fixes those with ``AsyncSniffer``:

* ``start()`` builds one sniffer, starts it and waits (bounded) until it has *opened its handle* or died; an open failure becomes
  ``available = False`` with the **verbatim reason** instead of a silent dead thread.  Calling it while running is a no-op.
* ``stop()`` calls ``AsyncSniffer.stop(join=True)`` — which wakes the capture loop whether or not packets are flowing — then joins the
  sniffer thread.  Calling it twice, or before ``start()``, is harmless.  Start / stop ×10 leaves no thread behind (test).
* every packet is counted (``packets_seen``, ``last_packet_at``) so the service can say "capturing but nothing seen";
  a handler that raises is counted in ``handler_errors`` and never kills the capture thread.
* event timestamps come from the **packet's capture time** (``pkt.time``), not from "now", so a queued or replayed packet is
  dated when it was seen.

``offline`` replays a PCAP file through the same handlers.  It is how the parsing is tested without a network card or Npcap
(AsyncSniffer's offline reader needs neither) and how a recorded capture can be analysed.

Subclasses set ``bpf`` and implement ``handle(pkt) -> Iterable[SensorEvent]``; IPv4 and IPv6 are both handled by the shared
helpers in ``packets.py``.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

from app.network.models import SensorEvent
from app.network.sensor.base import STOP_JOIN_SECONDS, BaseSensor, EmitFn, load_scapy

logger = logging.getLogger(__name__)

SnifferFactory = Callable[..., Any]          # (**kwargs) -> an object with the AsyncSniffer surface


class CaptureSensor(BaseSensor):
    bpf: str = ""
    sniff_kwargs: dict[str, Any] = {}

    def __init__(self, emit: EmitFn, interface: str = "", *, offline: Optional[str] = None,
                 sniffer_factory: Optional[SnifferFactory] = None, startup_wait: float = 3.0) -> None:
        super().__init__(emit)
        self._interface = interface or None
        self._offline = offline
        self._factory = sniffer_factory
        self._startup_wait = startup_wait
        self._sniffer: Any = None
        self.last_packet_at: Optional[float] = None       # wall-clock seconds of the newest packet's capture time
        self.started_at: Optional[float] = None           # monotonic
        self.handler_errors = 0
        self.filtered: dict[str, int] = {}                # packets deliberately ignored, by reason (mDNS, PTR, …)

    # ── to be provided by subclasses ─────────────────────────────────────
    def handle(self, pkt: Any) -> Iterable[SensorEvent]:  # pragma: no cover - overridden
        raise NotImplementedError

    def wants(self, pkt: Any) -> bool:
        """Is this packet this sensor's business?  Used when several parsers share one sniffer (``shared.SharedCapture``): a parser
        only counts and handles the packets it asks for.  A sensor with its own sniffer takes everything its BPF filter lets through."""
        return True

    def reset_counters(self) -> None:
        self.packets_seen, self.handler_errors, self.last_packet_at = 0, 0, None
        self.events_emitted, self.last_event_at = 0, None
        self.filtered = {}

    # ── lifecycle ────────────────────────────────────────────────────────
    def _alive(self) -> bool:
        s = self._sniffer
        thread = getattr(s, "thread", None) if s is not None else None
        return bool(thread is not None and thread.is_alive())

    def start(self) -> None:
        with self._lock:
            if self._sniffer is not None and self._alive():
                return                                     # idempotent
            self._sniffer = None
            self.available, self.reason = True, None
            self.reset_counters()
            try:
                factory = self._factory or load_scapy().AsyncSniffer
            except RuntimeError as exc:
                self.available, self.reason, self.running = False, str(exc), False
                return
            opened = threading.Event()
            kwargs: dict[str, Any] = dict(prn=self._on_packet, store=False, started_callback=opened.set, **self.sniff_kwargs)
            if self._offline:
                kwargs["offline"] = self._offline
            else:
                if self._interface:
                    kwargs["iface"] = self._interface
                if self.bpf:
                    kwargs["filter"] = self.bpf
            try:
                sniffer = factory(**kwargs)
                sniffer.start()
            except Exception as exc:                       # constructing / starting can fail synchronously (bad filter, bad file)
                self.available, self.reason, self.running = False, f"{type(exc).__name__}: {exc}", False
                logger.warning("Sensor '%s' could not start: %s", self.name, self.reason)
                return
            # Wait until the handle is open (started_callback) or the thread has died with an exception.
            deadline = time.monotonic() + self._startup_wait
            while time.monotonic() < deadline and not opened.is_set():
                thread = getattr(sniffer, "thread", None)
                if thread is not None and not thread.is_alive():
                    break
                time.sleep(0.01)
            thread = getattr(sniffer, "thread", None)
            exc = getattr(sniffer, "exception", None)
            replay_done = bool(self._offline) and exc is None      # a short PCAP replay can finish before we look: that is success
            if not opened.is_set() and thread is not None and not thread.is_alive() and not replay_done:
                self.available, self.running = False, False
                self.reason = f"{type(exc).__name__}: {exc}" if exc else "the capture thread exited immediately"
                logger.warning("Sensor '%s' could not open its capture: %s", self.name, self.reason)
                self._sniffer = sniffer
                self._reap(sniffer)
                self._sniffer = None
                return
            self._sniffer = sniffer
            self.started_at = time.monotonic()
            self.running = True

    @staticmethod
    def _reap(sniffer: Any) -> None:
        thread = getattr(sniffer, "thread", None)
        if thread is not None and thread is not threading.current_thread():
            thread.join(STOP_JOIN_SECONDS)

    def stop(self, timeout: float = STOP_JOIN_SECONDS) -> None:
        with self._lock:
            sniffer, self._sniffer = self._sniffer, None
            self.running = False
        if sniffer is None:
            return
        try:
            if getattr(sniffer, "running", False) and self._alive_of(sniffer):
                sniffer.stop(join=False)                   # wakes the loop even on a quiet link
        except Exception as exc:                           # "Not running" races, a socket already closed, …
            logger.debug("Sensor '%s' stop(): %s", self.name, exc)
        thread = getattr(sniffer, "thread", None)
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
            if thread.is_alive():
                logger.warning("Sensor '%s' capture thread did not stop within %.0fs", self.name, timeout)

    @staticmethod
    def _alive_of(sniffer: Any) -> bool:
        thread = getattr(sniffer, "thread", None)
        return bool(thread is not None and thread.is_alive())

    # ── packet path (runs on the sniffer thread) ─────────────────────────
    def _on_packet(self, pkt: Any) -> None:
        self.packets_seen += 1
        try:
            self.last_packet_at = float(pkt.time)
        except Exception:
            self.last_packet_at = time.time()
        try:
            for event in self.handle(pkt) or ():
                self._emit(event)
        except Exception:
            self.handler_errors += 1
            logger.debug("Sensor '%s' handler error", self.name, exc_info=True)

    def note_filtered(self, reason: str) -> None:
        self.filtered[reason] = self.filtered.get(reason, 0) + 1

    def status(self) -> dict[str, Any]:
        d = super().status()
        d.update({
            "running": bool(self.running and self._alive()),
            "last_packet_at": datetime.fromtimestamp(self.last_packet_at, tz=timezone.utc).isoformat() if self.last_packet_at else None,
            "handler_errors": self.handler_errors,
            "filtered": dict(self.filtered),
            "interface": self._interface,
            "source": "pcap replay" if self._offline else "live",
        })
        return d


def packet_time(pkt: Any) -> datetime:
    """The packet's capture time as an aware UTC datetime (falls back to now for a packet without one)."""
    try:
        return datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)
