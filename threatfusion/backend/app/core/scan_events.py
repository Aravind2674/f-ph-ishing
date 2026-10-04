"""
Live scan progress (A1-5)
=========================

``POST /scan`` runs its providers concurrently; this bus lets the UI watch them.  The scan handler publishes one
small event per state change (``start`` → ``provider`` running/ok/error/… → ``stage`` → ``done`` | ``error``) and
``GET /scan/{id}/events`` replays them as Server-Sent Events, so the dashboard can draw live per-source status chips
instead of a spinner.

Design
------
* **Replay + live.**  Every channel keeps its events, so a subscriber that connects late — or after the scan has
  finished — first receives the history and then the live tail.  The client may even subscribe *before* it POSTs the
  scan (it chooses the ``scan_id``); a channel nobody has published to yet simply waits (bounded by ``wait_seconds``).
* **Thread- and loop-safe.**  Publishing takes a lock and hands each event to the subscriber's *own* event loop with
  ``call_soon_threadsafe``; nothing here assumes the publisher and the consumer share a loop.
* **Bounded.**  At most ``max_channels`` scans are remembered (oldest evicted first), finished scans are forgotten
  after ``linger_seconds``, a channel keeps at most ``max_events`` events, and a subscription ends at the terminal
  event, on ``wait_seconds`` of silence for a scan that never started, or after ``max_seconds``.
* **No payloads.**  Events carry provider *names, statuses, reasons and timings* only — never the target, URL, host,
  findings or any provider data (privacy, A0-10).  The full result is fetched with ``GET /scan/{id}`` as before.

Event shapes (``type``): ``start`` {scan_id, target_type, providers[], mock} · ``provider`` {source, status
(``running`` | ok | not_found | error | skipped | not_configured), reason, cached, mock, latency_ms, retry_after} ·
``stage`` {stage: features | scoring} · ``done`` {scan_id, verdict_status, success} · ``error`` {scan_id, message}.
A subscription may also yield ``None`` (a keep-alive tick) and a final ``{"type": "timeout"}``.
"""

from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime, timezone
from typing import AsyncIterator, Callable, Optional

TERMINAL = ("done", "error")


class _Channel:
    __slots__ = ("events", "subscribers", "done", "started", "done_at")

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.subscribers: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = []
        self.done = False
        self.started = False
        self.done_at = 0.0


class ScanEventBus:
    def __init__(self, max_channels: int = 200, linger_seconds: float = 120.0, max_events: int = 300,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_channels = max_channels
        self.linger_seconds = linger_seconds
        self.max_events = max_events
        self._clock = clock
        self._lock = threading.Lock()
        self._channels: dict[str, _Channel] = {}

    # ── housekeeping (caller holds the lock) ───────────────────────────
    def _channel(self, scan_id: str) -> _Channel:
        ch = self._channels.get(scan_id)
        if ch is None:
            ch = self._channels[scan_id] = _Channel()
        return ch

    def _gc(self) -> None:
        now = self._clock()
        for sid in [s for s, c in self._channels.items() if c.done and now - c.done_at > self.linger_seconds]:
            del self._channels[sid]
        while len(self._channels) > self.max_channels:            # oldest first (dicts keep insertion order)
            del self._channels[next(iter(self._channels))]

    # ── publishing ─────────────────────────────────────────────────────
    def publish(self, scan_id: str, event: dict) -> None:
        event = {**event, "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}
        with self._lock:
            ch = self._channel(scan_id)
            if ch.done:
                return                                              # nothing follows a terminal event
            if len(ch.events) < self.max_events:
                ch.events.append(event)
            if event.get("type") == "start":
                ch.started = True
            if event.get("type") in TERMINAL:
                ch.done, ch.done_at = True, self._clock()
            subscribers = list(ch.subscribers)
            self._gc()
        for loop, queue in subscribers:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, event)
            except RuntimeError:                                    # that subscriber's loop is gone
                with self._lock:
                    if (loop, queue) in ch.subscribers:
                        ch.subscribers.remove((loop, queue))

    # ── inspection ─────────────────────────────────────────────────────
    def events(self, scan_id: str) -> list[dict]:
        with self._lock:
            ch = self._channels.get(scan_id)
            return list(ch.events) if ch else []

    def is_started(self, scan_id: str) -> bool:
        with self._lock:
            ch = self._channels.get(scan_id)
            return bool(ch and ch.started)

    # ── subscribing ────────────────────────────────────────────────────
    async def subscribe(self, scan_id: str, *, wait_seconds: float = 30.0, heartbeat: float = 15.0,
                        max_seconds: float = 300.0) -> AsyncIterator[Optional[dict]]:
        """Yield the channel's history, then live events, ending at the terminal event.

        Yields ``None`` as a keep-alive tick every ``heartbeat`` seconds of silence, and a final
        ``{"type": "timeout"}`` if the scan never started within ``wait_seconds`` or the stream outlives ``max_seconds``.
        """
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        with self._lock:
            ch = self._channel(scan_id)
            snapshot, finished = list(ch.events), ch.done
            if not finished:
                ch.subscribers.append((loop, queue))
            self._gc()
        try:
            for event in snapshot:
                yield event
            if finished:
                return
            started_at = self._clock()
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=heartbeat)
                except (asyncio.TimeoutError, TimeoutError):
                    waited = self._clock() - started_at
                    if (not ch.started and waited >= wait_seconds) or waited >= max_seconds:
                        yield {"type": "timeout"}
                        return
                    yield None
                    continue
                yield event
                if event.get("type") in TERMINAL:
                    return
        finally:
            with self._lock:
                if (loop, queue) in ch.subscribers:
                    ch.subscribers.remove((loop, queue))


bus = ScanEventBus()
