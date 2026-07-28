"""
Rate limiting.

A sliding-window-log limiter is used rather than a fixed window or a simple
token bucket: it stores the timestamp of every request in the current window
per key and counts how many fall within the last N seconds, which avoids the
classic fixed-window edge case where a client can send 2x the intended limit
by clustering requests around a window boundary. For a single-process demo
this trades a small amount of memory for exact correctness, which is the
right trade-off when the point is to demonstrate the *governance pattern*
rather than to survive a distributed, multi-million-request production load
(a production deployment would back this with Redis; see README "Limitations").

Two limiter instances are used:
  - `login_limiter`  -- keyed by client IP, protects the unauthenticated
                         /auth/login endpoint against credential-stuffing /
                         brute-force attempts.
  - `role_limiter`   -- keyed by "{username}:{role}", applied to every
                         authenticated request, with the numeric limit
                         looked up per role from Settings.
"""
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass

from app.config import get_settings

settings = get_settings()


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    limit: int
    retry_after_seconds: float


class SlidingWindowRateLimiter:
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int) -> RateLimitResult:
        now = time.monotonic()
        window_start = now - self.window_seconds
        with self._lock:
            q = self._hits[key]
            while q and q[0] < window_start:
                q.popleft()

            if len(q) >= limit:
                retry_after = q[0] + self.window_seconds - now
                return RateLimitResult(allowed=False, remaining=0, limit=limit,
                                        retry_after_seconds=max(retry_after, 0.0))

            q.append(now)
            return RateLimitResult(allowed=True, remaining=limit - len(q), limit=limit,
                                    retry_after_seconds=0.0)

    def reset(self):
        """Testing/demo utility -- clears all recorded hits."""
        with self._lock:
            self._hits.clear()


ROLE_LIMITS = {
    "VIEWER": settings.rate_limit_viewer,
    "ANALYST": settings.rate_limit_analyst,
    "AUDITOR": settings.rate_limit_auditor,
    "ADMIN": settings.rate_limit_admin,
}

login_limiter = SlidingWindowRateLimiter(window_seconds=settings.rate_limit_window_seconds)
role_limiter = SlidingWindowRateLimiter(window_seconds=settings.rate_limit_window_seconds)

LOGIN_ATTEMPTS_PER_WINDOW = 10
UNAUTHENTICATED_LIMIT_PER_WINDOW = 15
