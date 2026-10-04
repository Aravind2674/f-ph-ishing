"""
In-process job queue for the slow tier (B1)
===========================================

``POST /scan`` with ``mode: "async"`` returns the fast verdict immediately and runs the slow tier (provider calls, page fetch,
fusion, persistence) as a background job; progress streams over the existing SSE bus (``core/scan_events``) and the final
result is fetched with ``GET /scan/{id}``.

**Design choice (the master prompt's [ASK]): an in-process ``asyncio`` queue, not ``arq`` + Redis.**  Reasons: this is a
single-user, single-machine tool (the API token lives on the local disk, the extension talks to ``localhost``); Redis would add
a service to install and run for no isolation benefit; and every slow-tier step is already I/O-bound and bounded by the
per-scan deadline and the provider gate (A0-9, A1-5).  What it gives up, stated plainly: jobs do **not** survive a process
restart (a scan that was running is simply gone — ``GET /scan/{id}`` then answers 404, and the client re-submits), and there is
one worker process.  The interface (``submit`` / ``state`` / ``shutdown``) is small enough to put an ``arq`` backend behind later.

Bounded: at most ``max_concurrent`` jobs run at once (the rest wait their turn, state ``queued``), at most ``max_pending`` may
be waiting — beyond that ``submit`` refuses (``QueueFull``) so a flood cannot grow memory without bound — and finished job
records are kept briefly (``retention`` seconds) so a client that polls just after completion still sees the outcome.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

logger = logging.getLogger(__name__)


class QueueFull(RuntimeError):
    """Too many scans are already waiting."""


@dataclass
class Job:
    scan_id: str
    state: str = "queued"              # queued | running | done | error
    error: Optional[str] = None
    submitted_at: float = field(default_factory=time.monotonic)
    finished_at: Optional[float] = None
    task: Optional[asyncio.Task] = None


class JobRegistry:
    def __init__(self, max_concurrent: int = 4, max_pending: int = 50, retention: float = 600.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_concurrent = max(1, max_concurrent)
        self.max_pending = max_pending
        self.retention = retention
        self._clock = clock
        self._jobs: dict[str, Job] = {}
        self._sem: Optional[asyncio.Semaphore] = None
        self._sem_size = 0
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ── internals ──────────────────────────────────────────────────────
    def _semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._sem is None or self._loop is not loop or self._sem_size != self.max_concurrent:
            # a fresh loop (tests) or a changed limit gets a fresh semaphore; jobs already running keep the old one
            self._sem, self._loop, self._sem_size = asyncio.Semaphore(self.max_concurrent), loop, self.max_concurrent
        return self._sem

    def _prune(self) -> None:
        now = self._clock()
        for sid in [s for s, j in self._jobs.items() if j.finished_at is not None and now - j.finished_at > self.retention]:
            del self._jobs[sid]

    # ── public ─────────────────────────────────────────────────────────
    def has(self, scan_id: str) -> bool:
        self._prune()
        return scan_id in self._jobs

    def state(self, scan_id: str) -> Optional[str]:
        self._prune()
        job = self._jobs.get(scan_id)
        return job.state if job else None

    def error(self, scan_id: str) -> Optional[str]:
        job = self._jobs.get(scan_id)
        return job.error if job else None

    def counts(self) -> dict[str, int]:
        out = {"queued": 0, "running": 0, "done": 0, "error": 0}
        for j in self._jobs.values():
            out[j.state] += 1
        return out

    def submit(self, scan_id: str, factory: Callable[[], Awaitable[Optional[str]]]) -> Job:
        """Start ``factory()`` as a job. It returns ``None`` on success or an error message (it may also raise)."""
        self._prune()
        if scan_id in self._jobs:
            raise ValueError(f"job {scan_id!r} already exists")
        pending = sum(1 for j in self._jobs.values() if j.state == "queued")
        if pending >= self.max_pending:
            raise QueueFull(f"{pending} scans are already waiting")
        job = Job(scan_id)
        self._jobs[scan_id] = job
        job.task = asyncio.get_running_loop().create_task(self._run(job, factory), name=f"scan-job-{scan_id[:8]}")
        return job

    async def _run(self, job: Job, factory: Callable[[], Awaitable[Optional[str]]]) -> None:
        try:
            async with self._semaphore():
                job.state = "running"
                problem = await factory()
            job.state, job.error = ("error", problem) if problem else ("done", None)
        except asyncio.CancelledError:
            job.state, job.error = "error", "cancelled"
            raise
        except Exception as exc:                                         # a crashed job is an error, never a silent loss
            logger.exception("scan job %s crashed", job.scan_id)
            job.state, job.error = "error", f"{type(exc).__name__}"
        finally:
            job.finished_at = self._clock()

    async def shutdown(self) -> None:
        tasks = [j.task for j in self._jobs.values() if j.task is not None and not j.task.done()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


JOBS = JobRegistry()
