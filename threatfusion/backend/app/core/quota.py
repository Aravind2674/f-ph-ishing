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
from typing import Awaitable, Callable, Optional


class QuotaLimiter:
    def __init__(
        self,
        per_minute: int = 0,
        per_day: int = 0,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.per_minute = max(0, int(per_minute))
        self.per_day = max(0, int(per_day))
        self._clock = clock
        self._sleep = sleep
        self._minute: deque[float] = deque()      # reserved *start* times (may lie in the future)
        self._day: deque[float] = deque()
        self._blocked_until: float = 0.0

    # ── state ──────────────────────────────────────────────────────────
    @property
    def blocked_for(self) -> float:
        """Seconds a provider-imposed ``Retry-After`` block still has to run (0 if none)."""
        return max(0.0, self._blocked_until - self._clock())

    def snapshot(self) -> dict[str, float | int]:
        """Usage for ``/health`` and logs (no secrets)."""
        now = self._clock()
        return {
            "per_minute": self.per_minute, "per_day": self.per_day,
            "used_last_minute": sum(1 for t in self._minute if now - 60.0 < t <= now + 60.0),
            "used_last_day": sum(1 for t in self._day if now - 86_400.0 < t),
            "blocked_for_seconds": round(self.blocked_for, 1),
        }

    def penalize(self, seconds: float) -> None:
        """Honour a provider's ``Retry-After``: nobody calls it again for ``seconds`` (never shortens a block)."""
        if seconds and seconds > 0:
            self._blocked_until = max(self._blocked_until, self._clock() + float(seconds))

    # ── acquire ────────────────────────────────────────────────────────
    def _earliest_start(self, now: float) -> float:
        start = max(now, self._blocked_until)
        if self.per_minute:
            while self._minute and self._minute[0] <= now - 60.0:
                self._minute.popleft()
            if len(self._minute) >= self.per_minute:
                start = max(start, self._minute[-self.per_minute] + 60.0)
        if self.per_day:
            while self._day and self._day[0] <= now - 86_400.0:
                self._day.popleft()
            if len(self._day) >= self.per_day:
                start = max(start, self._day[-self.per_day] + 86_400.0)
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
        if self.per_minute:
            self._minute.append(start)
        if self.per_day:
            self._day.append(start)
        if wait > 0:
            await self._sleep(wait)
        return None
