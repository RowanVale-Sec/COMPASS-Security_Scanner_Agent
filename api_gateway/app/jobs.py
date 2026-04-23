"""
In-memory job registry.

Each /api/scan POST creates a Job. The registry holds:
  - event queue (SSE stream)
  - final bundle (for /api/download)
  - status + error
  - timestamps for TTL eviction

Credentials are NEVER persisted here. They live only on the request handler's
stack for the duration of the scan, are forwarded to the orchestrator, and are
dropped from the gateway's memory as soon as the scan completes.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

JOB_TTL_SECONDS = 3600  # results available for 1 hour then evicted
MAX_JOBS = 256


@dataclass
class Job:
    id: str
    created_at: float
    status: str = "pending"  # pending | running | succeeded | failed
    error: Optional[str] = None
    bundle: Optional[Dict[str, Any]] = None
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=256))
    finished: bool = False


class JobRegistry:
    """Async-safe job registry with TTL eviction on access."""

    def __init__(self, ttl_seconds: int = JOB_TTL_SECONDS, max_jobs: int = MAX_JOBS) -> None:
        self._jobs: Dict[str, Job] = {}
        self._lock = asyncio.Lock()
        self._ttl = ttl_seconds
        self._max_jobs = max_jobs

    def _evict_expired_locked(self) -> None:
        now = time.time()
        dead = [jid for jid, job in self._jobs.items() if now - job.created_at > self._ttl]
        for jid in dead:
            self._jobs.pop(jid, None)

        if len(self._jobs) > self._max_jobs:
            # LRU-ish: drop oldest by created_at
            ordered = sorted(self._jobs.items(), key=lambda kv: kv[1].created_at)
            for jid, _ in ordered[: len(self._jobs) - self._max_jobs]:
                self._jobs.pop(jid, None)

    async def create(self) -> Job:
        async with self._lock:
            self._evict_expired_locked()
            job_id = secrets.token_urlsafe(16)
            job = Job(id=job_id, created_at=time.time())
            self._jobs[job_id] = job
            return job

    async def get(self, job_id: str) -> Optional[Job]:
        async with self._lock:
            self._evict_expired_locked()
            return self._jobs.get(job_id)


registry = JobRegistry()
