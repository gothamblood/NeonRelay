"""The catch-all relay endpoint (fire-and-forget).

An incoming request is authenticated, pushed LIVE to any connected SSE
listener of the token, and then discarded. Nothing the sender transmits is
ever stored: no database row, no file, no access log line. If someone was
listening, they get it; if not, it's gone.
"""

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import ensure_live, extract_password
from ..config import settings
from ..database import get_session
from ..events import broker, stash
from ..logging_setup import log_action
from ..models import Token
from ..ratelimit import limiter
from ..security import verify_password

router = APIRouter(prefix="/relay", tags=["relay"])

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Missing or invalid token password.",
    headers={"WWW-Authenticate": 'Basic realm="NeonRelay"'},
)


# Anonymity is the whole point: a listener must never learn WHO sent a request.
# No request header is ever relayed (strict allowlist with nothing on it), so
# nothing -- IP, user-agent, cookies, client hints, even application headers --
# can identify or fingerprint the sender. Only the body (and basic request
# shape: method, path, query) reaches the receiver.


def _flag(value: str | None) -> bool:
    """Truthiness for a control query param (?__stash=1 / true / yes / on)."""
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on", ""}


def _stash_payload(event: dict, raw: bytes) -> str:
    """JSON for the held event, with the body capped at STASH_MAX_BYTES so one
    held message can't grow past the stash budget whatever the relay limit."""
    if len(raw) <= settings.STASH_MAX_BYTES:
        return json.dumps(event)
    stash_event = dict(event)
    stash_event["body_truncated"] = True
    clipped = raw[: settings.STASH_MAX_BYTES]
    if "body_base64" in stash_event:
        import base64

        stash_event["body_base64"] = base64.b64encode(clipped).decode("ascii")
    else:
        stash_event["body_text"] = clipped.decode("utf-8", "replace")
    return json.dumps(stash_event)


async def _handle(token_id: str, subpath: str, request: Request, session: AsyncSession):
    token = await session.get(Token, token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Token not found.")

    password = extract_password(request)
    if not password or not verify_password(password, token.password_hash):
        raise _UNAUTHORIZED

    # TTL: reject a token whose lifetime has elapsed.
    ensure_live(token)

    # Anti-spam: spend one token-bucket credit; over the limit -> 429 with a
    # Retry-After that grows (1s, 2s, 4s, ...) the more the token is abused. We
    # log the throttled token so a flood is visible (which box is hammered).
    retry_after = limiter.check(token.id)
    if retry_after:
        log_action("relay.throttled", token=token.id, retry_after=int(retry_after))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for this token.",
            headers={"Retry-After": str(int(retry_after))},
        )

    # Read the body only to relay it live; it is never written anywhere.
    raw = await request.body()
    truncated = False
    if len(raw) > settings.MAX_BODY_BYTES:
        raw = raw[: settings.MAX_BODY_BYTES]
        truncated = True

    try:
        body_text = raw.decode("utf-8")
        body_field = {"body_text": body_text}
    except UnicodeDecodeError:
        import base64

        body_field = {"body_base64": base64.b64encode(raw).decode("ascii")}

    # __stash : garder le message jusqu'au prochain stream s'il n'est livré à
    # personne tout de suite. On retire __stash (paramètre de contrôle) et aussi
    # __pw de la query relayée : le mot de passe n'est plus accepté dans l'URL,
    # mais si quelqu'un l'y met par habitude on ne le pousse jamais au listener.
    stash_requested = _flag(request.query_params.get("__stash"))
    query = {
        k: v for k, v in request.query_params.items() if k not in ("__pw", "__stash")
    }

    # Build the live event and push it to connected listeners -- then forget it.
    event = {
        "method": request.method,
        "path": "/" + subpath if subpath else "/",
        "query": query,
        "body_size": len(raw),
        "body_truncated": truncated,
        # No sender IP: the receiver must stay unable to identify who sent this.
        **body_field,
    }

    # Delay BEFORE relaying: we wait, then the message is delivered to listeners
    # (and the sender gets its response). So "delay 1000ms" means the request is
    # held 1s and only then pushed, not pushed now and acknowledged 1s later.
    if token.response_delay_ms:
        await asyncio.sleep(token.response_delay_ms / 1000)

    delivered = broker.publish(token.id, json.dumps(event))

    # Hold-until-next-stream : si demandé (__stash) ET que personne n'écoutait
    # (delivered == 0), on garde le message dans l'unique slot du token
    # (keep-latest : un nouvel envoi écrase le précédent). Il sera livré au
    # prochain listener qui se connecte, puis détruit. S'il a déjà été livré en
    # direct, il n'y a rien à garder. Jamais écrit sur disque.
    if stash_requested and delivered == 0:
        stash.set(token.id, _stash_payload(event, raw))

    # Minimal action line: which token was used (to spot abuse), method, and
    # delivery -- never the URL, body or password.
    log_action(
        "relay",
        token=token.id,
        method=request.method,
        delivered=delivered,
        stashed=stash_requested and delivered == 0,
    )

    return Response(
        content=token.response_body,
        status_code=token.response_status,
        media_type=token.response_content_type,
        headers=dict(token.response_headers or {}),
    )


@router.api_route("/{token_id}", methods=_METHODS)
async def relay_root(
    token_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    return await _handle(token_id, "", request, session)


@router.api_route("/{token_id}/{subpath:path}", methods=_METHODS)
async def relay_subpath(
    token_id: str,
    subpath: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    return await _handle(token_id, subpath, request, session)
