"""Canal bruité (/channel) : trafic de taille et de rythme constants.

Le relais classique (/relay + /listen) trahit l'activité : un message = une
requête de la taille du message, au moment où il est envoyé. Le canal bruité
supprime ces deux signaux.

  * POST /channel/{token}  (montant) : UNE requête longue en Transfer-Encoding
    chunked. Le client y écrit une trame de FRAME_BYTES octets à chaque tic,
    qu'il ait quelque chose à dire ou non (vraie trame, ou fausse trame chiffrée
    marquée « fake » À L'INTÉRIEUR du chiffré). Le serveur relaie chaque trame
    telle quelle aux autres auditeurs de la boîte, sans la comprendre.
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

Rien n'est stocké ni journalisé, à part une ligne d'action sans contenu.
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
from ..logging_setup import log_action
from ..ratelimit import RateLimiter

router = APIRouter(prefix="/channel", tags=["channel"])

_SESSION_HEADER = "x-neonrelay-session"
_SESSION_RE = re.compile(r"^[0-9a-f]{32}$")

# Débit montant toléré par boîte (toutes sessions confondues). Un client honnête
# envoie 1/TICK trames par seconde ; au-delà, la connexion est coupée.
frame_limiter = RateLimiter(
    settings.CHANNEL_FRAME_RATE, settings.CHANNEL_FRAME_BURST, settings.RATE_RETRY_MAX
)


class ChannelBroker:
    """Files de trames par boîte et par session, en mémoire uniquement."""

    def __init__(self) -> None:
        self._subs: dict[str, dict[str, asyncio.Queue]] = {}

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
    queue = channel_broker.subscribe(token.id, sid)
    frame, slots, tick = settings.CHANNEL_FRAME_BYTES, settings.CHANNEL_SLOTS, settings.CHANNEL_TICK
    log_action("channel.down.start", token=token.id)

    async def frames():
        next_tick = time.monotonic()
        try:
            while True:
                if await request.is_disconnected():
                    break
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
    size = settings.CHANNEL_FRAME_BYTES
    buf = bytearray()
    log_action("channel.up.start", token=token.id)
    reason = "closed"
    try:
        async for chunk in request.stream():
            buf += chunk
            while len(buf) >= size:
                frame = bytes(buf[:size])
                del buf[:size]
                if frame_limiter.check(token.id):
                    reason = "throttled"
                    return Response(status_code=status.HTTP_429_TOO_MANY_REQUESTS)
                channel_broker.publish(token.id, frame, sid)
    except ClientDisconnect:
        pass
    finally:
        log_action("channel.up.stop", token=token.id, reason=reason)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
