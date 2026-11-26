"""Owner-side API, split by purpose:

  * config  (/config)  -- create / inspect / configure / delete a token
  * listen  (/listen)  -- live SSE stream (also flushes a held __stash message)

There is no request-history endpoint -- nothing is stored."""

import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..admin import require_admin
from ..auth import authenticate_token
from ..database import SessionLocal, get_session
from ..events import broker, channel_stash, revocations, stash
from ..logging_setup import log_action
from ..models import Token
from ..ratelimit import RateLimiter, limiter
from ..schemas import (DeadmanCancel, DeadmanIn, LifecycleStatus, SelfDestructIn, TokenCreate,
                       TokenCreated, TokenPublic, TokenUpdate)
from ..security import generate_password, hash_password, verify_password

# Managing a token (create / inspect / update / delete).
config_router = APIRouter(prefix="/config", tags=["config"])
# Receiving a token's traffic (live SSE stream; also flushes a held "stash"
# message to the first listener that connects).
listen_router = APIRouter(prefix="/listen", tags=["listen"])


@config_router.post("/tokens", response_model=TokenCreated, status_code=201)
async def create_token(
    payload: TokenCreate,
    session: AsyncSession = Depends(get_session),
    _admin: str = Depends(require_admin),
):
    password = payload.password or generate_password()
    expires_at = None
    if payload.ttl_seconds:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=payload.ttl_seconds)
    token = Token(
        password_hash=hash_password(password),
        response_status=payload.response_status,
        response_headers=payload.response_headers,
        response_body=payload.response_body,
        response_content_type=payload.response_content_type,
        response_delay_ms=payload.response_delay_ms,
        expires_at=expires_at,
    )
    session.add(token)
    await session.commit()
    await session.refresh(token)
    log_action("token.create")

    data = TokenPublic.model_validate(token, from_attributes=True).model_dump()
    return TokenCreated(**data, password=password)


@config_router.get("/{token_id}", response_model=TokenPublic)
async def get_token(token: Token = Depends(authenticate_token)):
    return TokenPublic.model_validate(token, from_attributes=True)


@config_router.patch("/{token_id}", response_model=TokenPublic)
async def update_token(
    payload: TokenUpdate,
    token: Token = Depends(authenticate_token),
    session: AsyncSession = Depends(get_session),
):
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(token, field, value)
    session.add(token)
    await session.commit()
    await session.refresh(token)
    log_action("token.update")
    return TokenPublic.model_validate(token, from_attributes=True)


# ---------------------------------------------------------------------------
# Fin de vie d'une boîte : $/selfdestruct (compte à rebours) et $/deadman
# (homme mort). L'heure qui compte est celle du SERVEUR. Un balayeur détruit
# réellement les boîtes échues (ligne supprimée, flux ouverts coupés).
# ---------------------------------------------------------------------------

# Mot de passe de l'homme mort : 5 essais, puis 1 par minute (en plus de PBKDF2).
deadman_limiter = RateLimiter(1 / 60, 5, 3600)
_DEADMAN_REFUSED = HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Wrong deadman password.")


def _seconds_until(dt) -> int | None:
    if dt is None:
        return None
    dt = Token._aware(dt)
    return max(0, int((dt - datetime.now(timezone.utc)).total_seconds()))


def _status(token: Token, result: str = "status") -> LifecycleStatus:
    return LifecycleStatus(
        destroy_in=_seconds_until(token.expires_at),
        deadman_in=_seconds_until(token.deadman_deadline),
        deadman_armed=token.deadman_hash is not None,
        result=result,
    )


async def _check_deadman_password(token: Token, password: str) -> None:
    retry = deadman_limiter.check(token.id)
    if retry:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many attempts.", headers={"Retry-After": str(int(retry))})
    if not await asyncio.to_thread(verify_password, password, token.deadman_hash):
        log_action("token.deadman.refused")
        raise _DEADMAN_REFUSED


@config_router.get("/{token_id}/lifecycle", response_model=LifecycleStatus)
async def lifecycle_status(token: Token = Depends(authenticate_token)):
    return _status(token)


@config_router.post("/{token_id}/selfdestruct", response_model=LifecycleStatus)
async def self_destruct(
    payload: SelfDestructIn,
    token: Token = Depends(authenticate_token),
    session: AsyncSession = Depends(get_session),
):
    """Avance l'échéance de la boîte. Ne la recule JAMAIS : une clé saisie ne
    peut pas prolonger la vie d'une boîte (seul l'admin le pourrait)."""
    when = datetime.now(timezone.utc) + timedelta(seconds=payload.seconds)
    current = Token._aware(token.expires_at)
    if current is not None and current <= when:
        return _status(token, "unchanged")
    token.expires_at = when
    session.add(token)
    await session.commit()
    log_action("token.selfdestruct")
    return _status(token, "set")


@config_router.post("/{token_id}/deadman", response_model=LifecycleStatus)
async def deadman_arm_or_reset(
    payload: DeadmanIn,
    token: Token = Depends(authenticate_token),
    session: AsyncSession = Depends(get_session),
):
    """Arme l'homme mort, ou (même mot de passe) remet le compteur à zéro."""
    if token.deadman_hash is None:
        token.deadman_hash = await asyncio.to_thread(hash_password, payload.password)
        result = "armed"
    else:
        await _check_deadman_password(token, payload.password)
        result = "reset"
    token.deadman_deadline = datetime.now(timezone.utc) + timedelta(seconds=payload.seconds)
    session.add(token)
    await session.commit()
    log_action(f"token.deadman.{result}")
    return _status(token, result)


@config_router.post("/{token_id}/deadman/cancel", response_model=LifecycleStatus)
async def deadman_cancel(
    payload: DeadmanCancel,
    token: Token = Depends(authenticate_token),
    session: AsyncSession = Depends(get_session),
):
    if token.deadman_hash is None:
        return _status(token, "not-armed")
    await _check_deadman_password(token, payload.password)
    token.deadman_hash = None
    token.deadman_deadline = None
    session.add(token)
    await session.commit()
    log_action("token.deadman.cancelled")
    return _status(token, "cancelled")


def _forget_box(token_id: str) -> None:
    """Tout ce qui vit en mémoire pour une boîte détruite ; ses flux ouverts se
    ferment au tic suivant."""
    stash.clear(token_id)
    channel_stash.clear(token_id)
    limiter.forget(token_id)
    deadman_limiter.forget(token_id)
    revocations.revoke(token_id)


SWEEP_SECONDS = 5


async def sweep_expired() -> int:
    """Détruit les boîtes dont l'échéance est passée (TTL, $/selfdestruct,
    $/deadman). Renvoie le nombre de boîtes détruites."""
    async with SessionLocal() as session:
        rows = (await session.execute(select(Token).where(
            or_(Token.expires_at.is_not(None), Token.deadman_deadline.is_not(None))
        ))).scalars().all()
        dead = [t for t in rows if t.is_expired()]
        for t in dead:
            await session.delete(t)
        if dead:
            await session.commit()
    for t in dead:
        _forget_box(t.id)
        log_action("token.destroyed")
    return len(dead)


async def sweep_loop() -> None:
    while True:
        try:
            await sweep_expired()
        except Exception as exc:  # jamais d'arrêt du balayeur
            log_action("sweep.error", error=type(exc).__name__)
        await asyncio.sleep(SWEEP_SECONDS)


@config_router.delete("/{token_id}", status_code=204)
async def delete_token(
    token: Token = Depends(authenticate_token),
    session: AsyncSession = Depends(get_session),
):
    await session.delete(token)
    await session.commit()
    _forget_box(token.id)  # ferme aussi les flux déjà ouverts (canal, /listen)
    log_action("token.delete")


@listen_router.get("/{token_id}/count")
async def listener_count(token: Token = Depends(authenticate_token)):
    """How many listeners are currently streaming this token (live count).

    This is the number of open /listen/{id} connections right now -- i.e. how
    many would receive a request if one arrived this instant. In-process only.
    """
    return {"listeners": broker.listener_count(token.id)}


@listen_router.get("/{token_id}")
async def stream_requests(
    request: Request,
    token: Token = Depends(authenticate_token),
):
    """Server-Sent Events: live push of each incoming request as it arrives.

    If a message was relayed with ?__stash while nobody was listening, it was
    held in the token's single in-memory slot; the first listener to connect
    receives it right away (then it is destroyed). After that, this is a plain
    live stream -- a request that arrives with no listener is gone.
    """
    queue = broker.subscribe(token.id)
    # Consume any message held for the next stream, to flush it to this listener.
    held = stash.pop(token.id)
    log_action("listen.start", flushed=held is not None)

    async def event_generator():
        yield "event: ready\ndata: {}\n\n"
        # Deliver the held (stashed) message first, exactly like a live request.
        if held is not None:
            yield f"event: request\ndata: {held}\n\n"
        idle = 0.0
        try:
            while True:
                if await request.is_disconnected():
                    break
                if token.is_expired() or revocations.is_revoked(token.id):
                    break  # boîte expirée ou supprimée : on ferme le flux
                try:
                    # Réveil chaque seconde pour vérifier la révocation ; le
                    # keep-alive reste toutes les 15 s.
                    payload = await asyncio.wait_for(queue.get(), timeout=1.0)
                    idle = 0.0
                    yield f"event: request\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    idle += 1.0
                    if idle >= 15.0:
                        idle = 0.0
                        yield ": keep-alive\n\n"
        finally:
            broker.unsubscribe(token.id, queue)
            log_action("listen.stop")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
