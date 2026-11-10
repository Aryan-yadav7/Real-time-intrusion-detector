"""A tiny in-memory sliding-window rate limiter (login attempts, signups, API batches).

Only ALLOWED hits are recorded, so an attacker who keeps hammering does not keep
extending their own lockout; it simply ends `window` seconds after their last
allowed hit. Memory lives in one process (a multi-worker deployment would use Redis).
"""
from __future__ import annotations

import math
import time
from collections import deque


class RateLimiter:
    def __init__(self, limit: int, window: float, clock=time.monotonic, max_keys: int = 10_000):
        self.limit = limit
        self.window = window
        self.clock = clock
        self.max_keys = max_keys
        self._hits: dict[str, deque] = {}

    def hit(self, key: str) -> bool:
        """Record an attempt. False means the caller is over the limit."""
        now = self.clock()
        hits = self._hits.setdefault(key, deque())
        self._expire(hits, now)
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        if len(self._hits) > self.max_keys:
            self._cleanup(now)
        return True

    def retry_after(self, key: str) -> int:
        """Seconds until one more attempt would be allowed (at least 1)."""
        now = self.clock()
        hits = self._hits.get(key)
        if not hits:
            return 1
        self._expire(hits, now)
        if len(hits) < self.limit:
            return 1
        return max(1, math.ceil(hits[0] + self.window - now))

    def _expire(self, hits: deque, now: float) -> None:
        while hits and hits[0] <= now - self.window:
            hits.popleft()

    def _cleanup(self, now: float) -> None:
        for key in [k for k, h in self._hits.items() if not h or h[-1] <= now - self.window]:
            del self._hits[key]
