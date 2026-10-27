"""Owner-side API, split by purpose:

  * config  (/config)  -- create / inspect / configure / delete a token
  * listen  (/listen)  -- live SSE stream (also flushes a held __stash message)

There is no request-history endpoint -- nothing is stored."""

import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from sqlalchemy.ext.asyncio import AsyncSession

from ..admin import require_admin
from ..auth import authenticate_token
from ..database import get_session
from ..events import broker, stash
from ..logging_setup import log_action
from ..models import Token
from ..ratelimit import limiter
from ..schemas import TokenCreate, TokenCreated, TokenPublic, TokenUpdate
from ..security import generate_password, hash_password

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


@config_router.delete("/{token_id}", status_code=204)
async def delete_token(
    token: Token = Depends(authenticate_token),
    session: AsyncSession = Depends(get_session),
):
    await session.delete(token)
    await session.commit()
    stash.clear(token.id)
    limiter.forget(token.id)
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
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: request\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            broker.unsubscribe(token.id, queue)
            log_action("listen.stop")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
