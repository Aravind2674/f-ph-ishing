"""
Outbound quota limiter for third-party APIs (A1-1)
==================================================

VirusTotal's free tier allows **4 requests/minute and 500/day**.  Until now nothing enforced that: a fresh client
(with a fresh, never-hit cache) was built per scan, so a burst of scans — or the network layer enriching DNS
events — simply ran into 429s and the ``Retry-After`` header was ignored.

:class:`QuotaLimiter` is the single, process-wide gate that scans *and* the network layer share:

* **Sliding windows** (per minute and per day), not a refilling bucket: "at most N calls in *any* W-second window"
  is exactly how provider quotas are written, and a token bucket can briefly exceed that after idling.
* **Reservation, not locking.**  ``acquire`` computes the earliest instant a call may start, *reserves* that slot
  and then sleeps until it.  There is no ``await`` between the computation and the reservation, so on a
  single-threaded event loop it is exact however many callers race (a test fires 50 at once and exactly the budget
  gets through) and callers are served FIFO.
* **Bounded queueing.**  A caller says how long it is willing to wait (``max_wait``).  If the next free slot is
  further away than that it gets ``retry_after`` back *immediately* and nothing is consumed — the scan reports the
  provider as ``error/rate_limited`` rather than hanging until the scan deadline.
* **``penalize(seconds)``** records a provider's own ``Retry-After`` so every later caller (scan or network layer)
  backs off together.  A shorter hint never shortens an existing block.

Process-local by design (single-process app).  The windows are in memory: after a restart the day's count starts
again, which can only make the app *under*-use the provider in the first minute after a crash loop — never
over-use the per-minute budget.  Limits of ``0`` disable the corresponding window (premium keys).
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Awaitable, Callable, Optional, Sequence


class QuotaLimiter:
    """``per_minute`` / ``per_day`` are the common provider limits; ``windows=[(limit, seconds), ...]`` adds any
    other (NVD: 50 requests per rolling 30 s).  A limit of 0 disables that window."""

    def __init__(
        self,
        per_minute: int = 0,
        per_day: int = 0,
        *,
        windows: Sequence[tuple[int, float]] = (),
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        specs: list[tuple[int, float]] = []
        if per_minute and per_minute > 0:
            specs.append((int(per_minute), 60.0))
        if per_day and per_day > 0:
            specs.append((int(per_day), 86_400.0))
        specs += [(int(limit), float(seconds)) for limit, seconds in windows if limit and limit > 0 and seconds > 0]
        self._clock = clock
        self._sleep = sleep
        # (limit, window seconds, reserved *start* times — which may lie in the future)
        self._windows: list[tuple[int, float, deque[float]]] = [(lim, sec, deque()) for lim, sec in specs]
        self._blocked_until: float = 0.0

    # ── state ──────────────────────────────────────────────────────────
    @property
    def blocked_for(self) -> float:
        """Seconds a provider-imposed ``Retry-After`` block still has to run (0 if none)."""
        return max(0.0, self._blocked_until - self._clock())

    def snapshot(self) -> dict[str, object]:
        """Usage for ``/health`` and logs (no secrets)."""
        now = self._clock()
        return {
            "windows": [
                {"limit": lim, "window_seconds": sec, "used": sum(1 for t in dq if now - sec < t)}
                for lim, sec, dq in self._windows
            ],
            "blocked_for_seconds": round(self.blocked_for, 1),
        }

    def penalize(self, seconds: float) -> None:
        """Honour a provider's ``Retry-After``/backoff: nobody calls it again for ``seconds`` (never shortens a block)."""
        if seconds and seconds > 0:
            self._blocked_until = max(self._blocked_until, self._clock() + float(seconds))

    # ── acquire ────────────────────────────────────────────────────────
    def _earliest_start(self, now: float) -> float:
        start = max(now, self._blocked_until)
        for limit, seconds, hits in self._windows:
            while hits and hits[0] <= now - seconds:
                hits.popleft()
            if len(hits) >= limit:
                start = max(start, hits[-limit] + seconds)
        return start

    async def acquire(self, max_wait: float = 0.0) -> Optional[float]:
        """Reserve a slot.

        Returns ``None`` once the call may proceed (after sleeping for the slot, if it was in the near future),
        or the number of seconds the caller should retry after — in which case *nothing was consumed*.
        """
        now = self._clock()
        start = self._earliest_start(now)
        wait = start - now
        if wait > max(0.0, max_wait):
            return wait
        for _limit, _seconds, hits in self._windows:
            hits.append(start)
        if wait > 0:
            await self._sleep(wait)
        return None
