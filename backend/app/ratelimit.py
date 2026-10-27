"""Per-token rate limiting (token bucket), in-process.

Each token gets a bucket that refills at RATE_LIMIT tokens/second up to a cap of
RATE_BURST. Every relay call spends one token; if the bucket is empty the call
is rejected (HTTP 429). This smooths bursts and caps the sustained rate, so a
single token can't be used to flood the server.

Single-process only, like EventBroker/Stash. For multiple workers/instances,
back this with a shared store (e.g. Redis) keyed by token id.
"""

import time

from .config import settings


class _Bucket:
    __slots__ = ("tokens", "last", "strikes")

    def __init__(self, tokens: float, last: float) -> None:
        self.tokens = tokens      # credits currently available
        self.last = last          # last refill time (monotonic)
        self.strikes = 0          # consecutive rejections (for the backoff)


class RateLimiter:
    def __init__(self, rate: float, burst: float, retry_max: float) -> None:
        self.rate = rate
        self.burst = burst
        self.retry_max = retry_max
        self._state: dict[str, _Bucket] = {}

    @property
    def enabled(self) -> bool:
        return self.rate > 0

    def check(self, key: str) -> float:
        """Spend one credit for `key`.

        Returns 0.0 when the call is allowed. When over the limit, returns the
        number of seconds the caller should wait (Retry-After): 1, 2, 4, 8, ...
        growing on each consecutive rejection, capped at `retry_max`, and reset
        to 0 as soon as the token is within its budget again.
        """
        if not self.enabled:
            return 0.0
        now = time.monotonic()
        b = self._state.get(key)
        if b is None:
            b = self._state[key] = _Bucket(self.burst, now)
        # Refill proportionally to elapsed time, capped at burst.
        b.tokens = min(self.burst, b.tokens + (now - b.last) * self.rate)
        b.last = now
        if b.tokens >= 1.0:
            b.tokens -= 1.0
            b.strikes = 0           # behaved: clear the penalty
            return 0.0
        # Over the limit: exponential backoff on repeated abuse.
        b.strikes = min(b.strikes + 1, 30)  # cap exponent to avoid huge ints
        return min(2.0 ** (b.strikes - 1), self.retry_max)

    def forget(self, key: str) -> None:
        """Drop a key's bucket (e.g. when the token is deleted)."""
        self._state.pop(key, None)


limiter = RateLimiter(settings.RATE_LIMIT, settings.RATE_BURST, settings.RATE_RETRY_MAX)
