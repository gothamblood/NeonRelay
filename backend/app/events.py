"""In-process pub/sub used to push captured requests to SSE listeners.

Single-process only. For multi-instance deployments, swap this for Redis
pub/sub (same publish/subscribe interface).
"""

import asyncio
from collections import defaultdict


class EventBroker:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, token_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers[token_id].add(queue)
        return queue

    def unsubscribe(self, token_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(token_id)
        if subs:
            subs.discard(queue)
            if not subs:
                self._subscribers.pop(token_id, None)

    def publish(self, token_id: str, payload: str) -> int:
        """Push to every live listener of a token. Returns how many got it."""
        delivered = 0
        for queue in list(self._subscribers.get(token_id, ())):
            try:
                queue.put_nowait(payload)
                delivered += 1
            except asyncio.QueueFull:
                pass  # Slow listener: drop rather than block the relay.
        return delivered

    def listener_count(self, token_id: str) -> int:
        return len(self._subscribers.get(token_id, ()))


class Stash:
    """One hold-until-next-stream slot per token, held in memory.

    A request relayed with ?__stash while nobody is listening is parked here and
    popped by the next listener that connects. Keep-latest: setting a slot
    overwrites any previous value, so a flood never piles up -- at most ONE
    payload is retained. Popping a slot destroys it. Nothing touches disk.

    Single-process only, like EventBroker. Dict operations here run without
    awaiting, so they are atomic with respect to the asyncio event loop.
    """

    def __init__(self) -> None:
        self._slots: dict[str, str] = {}

    def set(self, token_id: str, payload: str) -> None:
        """Store (overwriting) the single slot for a token."""
        self._slots[token_id] = payload

    def pop(self, token_id: str) -> str | None:
        """Return and DESTROY the slot. None if empty (already burned)."""
        return self._slots.pop(token_id, None)

    def clear(self, token_id: str) -> None:
        """Drop the slot without reading it (e.g. when the token is deleted)."""
        self._slots.pop(token_id, None)

    def has(self, token_id: str) -> bool:
        return token_id in self._slots


class Revocations:
    """Boîtes supprimées pendant que des flux sont ouverts (canal, /listen).

    L'authentification n'a lieu qu'à l'ouverture d'un flux : sans ce registre,
    un flux ouvert survivrait à la suppression de sa boîte. Chaque flux consulte
    ce registre (et l'expiration de la boîte) à chaque tic et se ferme aussitôt.
    En mémoire seulement ; une entrée est oubliée après une heure (les ids de
    boîte ne sont jamais réutilisés, et les flux se ferment en quelques secondes).
    """

    _KEEP = 3600.0

    def __init__(self) -> None:
        self._ids: dict[str, float] = {}

    def revoke(self, token_id: str) -> None:
        import time

        now = time.monotonic()
        for k in [k for k, t in self._ids.items() if now - t > self._KEEP]:
            del self._ids[k]
        self._ids[token_id] = now

    def is_revoked(self, token_id: str) -> bool:
        return token_id in self._ids


broker = EventBroker()
stash = Stash()
revocations = Revocations()
