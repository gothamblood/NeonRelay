"""Canal bruité (/channel) : trafic de taille et de rythme constants.

Le relais classique (/relay + /listen) trahit l'activité : un message = une
requête de la taille du message, au moment où il est envoyé. Le canal bruité
supprime ces deux signaux.

  * POST /channel/{token}  (montant) : UNE requête longue en Transfer-Encoding
    chunked. Le client y écrit à chaque tic 1 octet de contrôle + une trame de
    FRAME_BYTES octets, qu'il ait quelque chose à dire ou non (vraie trame, ou
    fausse trame chiffrée marquée « fake » À L'INTÉRIEUR du chiffré). Taille
    constante : le réseau ne distingue pas les octets de contrôle.
      0 : relayer la trame telle quelle aux autres auditeurs de la boîte ;
      1 : $/stashserver, 1re trame : la garder pour la prochaine session (écrase
          le message gardé) ; 3 : trame suivante du même message ;
      2 : $/stashserver cancel : oublier le message gardé (la trame, un bruit
          chiffré, est relayée normalement).
    Le serveur ne comprend aucune trame : il sait seulement qu'un message attend.
  * GET /channel/{token}   (descendant) : UNE réponse longue. À chaque tic, le
    serveur écrit exactement SLOTS trames : celles en attente pour cet auditeur,
    complétées par des octets aléatoires. Aléatoire et chiffré sont
    indiscernables ; le client rejette ce qui ne s'authentifie pas.

Le mot de passe (PBKDF2) n'est vérifié qu'UNE fois, à l'ouverture de chaque
connexion : vérifier chaque trame saturerait le processeur.

Le client choisit un identifiant de session aléatoire (en-tête
X-NeonRelay-Session), le même sur ses deux connexions : ses propres trames ne
lui sont pas renvoyées (sinon la voie descendante devrait porter deux fois plus
de créneaux). Cet identifiant ne vit qu'en mémoire et ne désigne rien d'autre
qu'une session.

Rien n'est stocké ni journalisé, à part une ligne d'action sans contenu (et, en
mémoire seulement, au plus un message $/stashserver chiffré par boîte).
"""

import asyncio
import os
import re
import time

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import Response, StreamingResponse
from starlette.requests import ClientDisconnect

from ..auth import resolve_token
from ..config import settings
from ..database import SessionLocal
from ..events import channel_stash, revocations
from ..logging_setup import log_action
from ..ratelimit import RateLimiter

router = APIRouter(prefix="/channel", tags=["channel"])

_SESSION_HEADER = "x-neonrelay-session"
_SESSION_RE = re.compile(r"^[0-9a-f]{32}$")

CTL_RELAY, CTL_STASH, CTL_CANCEL, CTL_STASH_MORE = 0, 1, 2, 3

# Débit montant toléré par boîte (toutes sessions confondues). Un client honnête
# envoie 1/TICK trames par seconde ; au-delà, la connexion est coupée.
frame_limiter = RateLimiter(
    settings.CHANNEL_FRAME_RATE, settings.CHANNEL_FRAME_BURST, settings.RATE_RETRY_MAX
)


class ChannelBroker:
    """Files de trames par boîte et par session, en mémoire uniquement."""

    def __init__(self) -> None:
        self._subs: dict[str, dict[str, asyncio.Queue]] = {}
        self._senders: dict[str, set[str]] = {}

    def listening(self, token_id: str, session: str) -> bool:
        return session in self._subs.get(token_id, {})

    def listeners(self, token_id: str) -> int:
        return len(self._subs.get(token_id, {}))

    def senders(self, token_id: str) -> set[str]:
        return self._senders.setdefault(token_id, set())

    def drop_sender(self, token_id: str, session: str) -> None:
        s = self._senders.get(token_id)
        if s is not None:
            s.discard(session)
            if not s:
                del self._senders[token_id]

    def subscribe(self, token_id: str, session: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=settings.CHANNEL_QUEUE_FRAMES)
        self._subs.setdefault(token_id, {})[session] = queue
        return queue

    def unsubscribe(self, token_id: str, session: str, queue: asyncio.Queue) -> None:
        subs = self._subs.get(token_id)
        if subs and subs.get(session) is queue:
            del subs[session]
            if not subs:
                del self._subs[token_id]

    def publish(self, token_id: str, frame: bytes, sender: str) -> int:
        delivered = 0
        for session, queue in list(self._subs.get(token_id, {}).items()):
            if session == sender:
                continue  # pas d'écho vers l'expéditeur
            try:
                queue.put_nowait(frame)
                delivered += 1
            except asyncio.QueueFull:
                pass  # auditeur trop lent : on jette plutôt que de bloquer
        return delivered


channel_broker = ChannelBroker()


def _refuse(code: int, detail: str) -> HTTPException:
    # Connection: close -> uvicorn ferme la connexion TCP après la réponse : un
    # client refusé ne peut pas continuer à pousser des octets que l'on lirait.
    return HTTPException(status_code=code, detail=detail, headers={"Connection": "close"})


def _session_id(request: Request) -> str:
    sid = request.headers.get(_SESSION_HEADER, "").strip().lower()
    if not _SESSION_RE.match(sid):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing session id.")
    return sid


async def _authenticate(token_id: str, request: Request):
    """PBKDF2 une seule fois, avec une session SQL courte (pas gardée ouverte
    pendant toute la durée du flux)."""
    async with SessionLocal() as session:
        return await resolve_token(token_id, request, session)


@router.get("/{token_id}")
async def channel_down(token_id: str, request: Request):
    sid = _session_id(request)
    token = await _authenticate(token_id, request)
    # Vérifications et inscription sans « await » entre elles : atomiques pour
    # la boucle asyncio (pas de course entre deux connexions simultanées).
    if channel_broker.listening(token.id, sid):
        raise _refuse(status.HTTP_409_CONFLICT, "Session already listening.")
    if channel_broker.listeners(token.id) >= settings.CHANNEL_MAX_LISTENERS:
        log_action("channel.down.refused", token=token.id, reason="cap")
        raise _refuse(status.HTTP_429_TOO_MANY_REQUESTS, "Too many listeners for this box.")
    queue = channel_broker.subscribe(token.id, sid)
    for held in channel_stash.pop_for(token.id, sid):  # $/stashserver : livré d'abord
        queue.put_nowait(held)
    frame, slots, tick = settings.CHANNEL_FRAME_BYTES, settings.CHANNEL_SLOTS, settings.CHANNEL_TICK
    log_action("channel.down.start", token=token.id)

    async def frames():
        next_tick = time.monotonic()
        try:
            while True:
                if await request.is_disconnected():
                    break
                if token.is_expired() or revocations.is_revoked(token.id):
                    break  # boîte expirée ou supprimée : le flux se ferme au tic suivant
                out = bytearray()
                for _ in range(slots):
                    try:
                        out += queue.get_nowait()
                    except asyncio.QueueEmpty:
                        out += os.urandom(frame)  # bruit : indiscernable d'un chiffré
                yield bytes(out)
                next_tick += tick
                delay = next_tick - time.monotonic()
                if delay > 0:
                    await asyncio.sleep(delay)
                else:
                    next_tick = time.monotonic()  # retard (machine chargée) : on se recale
        finally:
            channel_broker.unsubscribe(token.id, sid, queue)
            log_action("channel.down.stop", token=token.id)

    return StreamingResponse(
        frames(),
        media_type="application/octet-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/{token_id}")
async def channel_up(token_id: str, request: Request):
    sid = _session_id(request)
    token = await _authenticate(token_id, request)
    senders = channel_broker.senders(token.id)
    if sid in senders:
        raise _refuse(status.HTTP_409_CONFLICT, "Session already sending.")
    if len(senders) >= settings.CHANNEL_MAX_SENDERS:
        log_action("channel.up.refused", token=token.id, reason="cap")
        raise _refuse(status.HTTP_429_TOO_MANY_REQUESTS, "Too many senders for this box.")
    senders.add(sid)
    size = settings.CHANNEL_FRAME_BYTES
    unit = 1 + size                       # octet de contrôle + trame
    buf = bytearray()
    log_action("channel.up.start", token=token.id)
    reason = "closed"
    try:
        async for chunk in request.stream():
            if token.is_expired() or revocations.is_revoked(token.id):
                reason = "revoked"
                return Response(status_code=status.HTTP_410_GONE, headers={"Connection": "close"})
            buf += chunk
            while len(buf) >= unit:
                ctl, frame = buf[0], bytes(buf[1:unit])
                del buf[:unit]
                if frame_limiter.check(token.id):
                    reason = "throttled"
                    return Response(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                    headers={"Connection": "close"})
                if ctl == CTL_STASH:
                    channel_stash.start(token.id, sid, frame)
                    log_action("channel.stash", token=token.id)
                elif ctl == CTL_STASH_MORE:
                    channel_stash.extend(token.id, sid, frame, settings.CHANNEL_STASH_FRAMES)
                elif ctl == CTL_CANCEL:
                    channel_stash.clear(token.id)
                    log_action("channel.stash.cancel", token=token.id)
                    channel_broker.publish(token.id, frame, sid)
                elif ctl == CTL_RELAY:
                    channel_broker.publish(token.id, frame, sid)
                else:
                    reason = "bad-control"
                    return Response(status_code=status.HTTP_400_BAD_REQUEST,
                                    headers={"Connection": "close"})
    except ClientDisconnect:
        pass
    finally:
        channel_broker.drop_sender(token.id, sid)
        log_action("channel.up.stop", token=token.id, reason=reason)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
