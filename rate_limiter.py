import time
from collections import defaultdict


class InMemoryRateLimiter:
    def __init__(self, limit: int = 60, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.buckets = defaultdict(list)

    def allow(self, key: str) -> tuple[bool, str]:
        now = time.time()
        events = [t for t in self.buckets[key] if now - t < self.window_seconds]
        self.buckets[key] = events
        if len(events) >= self.limit:
            return False, "rate_limit_exceeded"
        self.buckets[key].append(now)
        return True, "allowed"
