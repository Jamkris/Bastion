"""In-memory login rate limiter (brute-force protection).

Tracks failed login attempts per client key (IP) within a sliding window and
locks further attempts once a threshold is crossed. State is process-local and
intentionally ephemeral — a restart clears it, which is fine for a single-node
homelab dashboard. The counting logic is pulled out as a pure function so it can
be unit-tested without touching time or shared state.
"""

from __future__ import annotations

from typing import Iterable


def count_within(events: Iterable[float], now: float, window_sec: float) -> int:
    """Number of timestamps within `window_sec` before `now`."""
    return sum(1 for t in events if t > now - window_sec)


class RateLimiter:
    def __init__(self) -> None:
        self._failures: dict[str, list[float]] = {}

    def _prune(self, key: str, now: float, window_sec: float) -> list[float]:
        recent = [t for t in self._failures.get(key, []) if t > now - window_sec]
        if recent:
            self._failures[key] = recent
        else:
            self._failures.pop(key, None)
        return recent

    def is_locked(self, key: str, now: float, max_attempts: int, window_sec: float) -> bool:
        """True once `max_attempts` failures have occurred within the window."""
        recent = self._prune(key, now, window_sec)
        return len(recent) >= max(1, max_attempts)

    def record_failure(self, key: str, now: float) -> None:
        self._failures.setdefault(key, []).append(now)

    def clear(self, key: str) -> None:
        """Forget a key's failures (call on a successful login)."""
        self._failures.pop(key, None)
