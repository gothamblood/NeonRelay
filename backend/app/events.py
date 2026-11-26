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


class ChannelStash:
    """$/stashserver : UN message par boîte (des trames chiffrées de bout en bout,
    opaques pour le serveur) gardé en mémoire jusqu'à la prochaine session du
    canal, puis détruit. Le dernier dépôt écrase le précédent. Rien sur disque.

    Le slot retient l'identifiant de la session qui dépose : une reconnexion de
    CETTE session ne le consomme pas, et elle seule peut le compléter (message
    de plusieurs trames). Une autre session (y compris une relance du même
    client, qui tire un nouvel identifiant) le reçoit.
    """

    def __init__(self) -> None:
        self._slots: dict[str, tuple[str, list[bytes]]] = {}

    def start(self, token_id: str, session: str, frame: bytes) -> None:
        self._slots[token_id] = (session, [frame])

    def extend(self, token_id: str, session: str, frame: bytes, max_frames: int) -> bool:
        slot = self._slots.get(token_id)
        if slot is None or slot[0] != session or len(slot[1]) >= max_frames:
            return False
        slot[1].append(frame)
        return True

    def pop_for(self, token_id: str, session: str) -> list[bytes]:
        """Trames gardées pour une session qui s'ouvre (vide si rien, ou si c'est
        la session qui les a déposées). Le slot est détruit."""
        slot = self._slots.get(token_id)
        if slot is None or slot[0] == session:
            return []
        del self._slots[token_id]
        return slot[1]

    def clear(self, token_id: str) -> None:
        self._slots.pop(token_id, None)


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
channel_stash = ChannelStash()
revocations = Revocations()
