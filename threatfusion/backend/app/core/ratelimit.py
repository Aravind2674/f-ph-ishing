"""
Tiny in-memory sliding-window rate limiter (A0-3; reused for ``/scan`` in A0-9).

Per-key timestamps in a deque; ``check`` returns whether the call is allowed and, if not, how many
seconds until a slot frees up.  Process-local by design (the project is a single-process app); a
shared store would be needed only for multi-worker deployments.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from typing import Callable

from fastapi import HTTPException, Request


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


# ── /scan: per-client limit (A0-9) ──────────────────────────────────────────
SCAN_LIMITER = SlidingWindowLimiter(window_seconds=60.0)


async def scan_rate_limit(request: Request) -> None:
    """FastAPI dependency for ``POST /scan``: at most RATE_LIMIT_REQUESTS_PER_MINUTE per client.

    Runs *before* the handler, so a refused request consumes no provider quota.
    """
    from app.core.config import get_settings

    limit = get_settings().RATE_LIMIT_REQUESTS_PER_MINUTE
    client = request.client.host if request.client else "unknown"
    allowed, retry_after = SCAN_LIMITER.check(client, limit)
    if not allowed:
        wait = max(1, math.ceil(retry_after))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: at most {limit} scans per minute per client; retry in {wait}s.",
            headers={"Retry-After": str(wait)},
        )
