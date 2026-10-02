"""
Tiny in-memory sliding-window rate limiter (A0-3; reused for ``/scan`` in A0-9).

Per-key timestamps in a deque; ``check`` returns whether the call is allowed and, if not, how many
seconds until a slot frees up.  Process-local by design (the project is a single-process app); a
shared store would be needed only for multi-worker deployments.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable


class SlidingWindowLimiter:
    def __init__(self, window_seconds: float = 60.0, clock: Callable[[], float] = time.monotonic) -> None:
        self.window = window_seconds
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, limit: int) -> tuple[bool, float]:
        """Record a hit for ``key`` if under ``limit``. Returns ``(allowed, retry_after_seconds)``.

        A ``limit`` of 0 or less disables limiting.
        """
        if limit <= 0:
            return True, 0.0
        now = self._clock()
        hits = self._hits[key]
        while hits and now - hits[0] >= self.window:
            hits.popleft()
        if len(hits) >= limit:
            return False, max(0.0, self.window - (now - hits[0]))
        hits.append(now)
        return True, 0.0

    def clear(self) -> None:
        self._hits.clear()
