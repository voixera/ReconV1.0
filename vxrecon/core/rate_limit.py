"""Per-host token-bucket rate limiter.

VXRecon defaults to a polite 2 requests/second per host. The limiter is
process-local (sufficient for a single-run CLI) and sleeps just long enough to
respect the configured rate. It never becomes a "stealth" mechanism; it makes
the tool *less* aggressive, never more.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    capacity: float
    refill_per_sec: float
    tokens: float = 0.0
    last: float = field(default_factory=time.monotonic)


class RateLimiter:
    """Thread-safe token bucket keyed by an arbitrary string (e.g. host)."""

    def __init__(self, rate_rps: float = 2.0, burst: float | None = None) -> None:
        self.rate_rps = max(rate_rps, 0.1)
        self.burst = burst if burst is not None else max(1.0, self.rate_rps)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _bucket_for(self, key: str) -> _Bucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(capacity=self.burst, refill_per_sec=self.rate_rps)
            bucket.tokens = bucket.capacity
            self._buckets[key] = bucket
        return bucket

    def acquire(self, key: str = "default") -> None:
        """Block until a token is available for ``key``."""

        while True:
            with self._lock:
                bucket = self._bucket_for(key)
                now = time.monotonic()
                elapsed = now - bucket.last
                bucket.tokens = min(
                    bucket.capacity, bucket.tokens + elapsed * bucket.refill_per_sec
                )
                bucket.last = now
                if bucket.tokens >= 1.0:
                    bucket.tokens -= 1.0
                    return
                needed = 1.0 - bucket.tokens
                wait = needed / bucket.refill_per_sec
            time.sleep(wait)
