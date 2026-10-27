"""Per-token password authentication.

The password may be supplied two ways (first match wins):
  1. Header     X-NeonRelay-Password: <password>
  2. HTTP Basic Authorization: Basic base64(<token_id>:<password>)

The password is deliberately NOT accepted in the URL query: a password in a URL
leaks into server/proxy access logs, browser history and the Referer header
(metadata that survives decryption), so that path is removed, not just
discouraged. A token is only reachable by someone who holds BOTH the token id
and its password; a wrong or missing password returns 401.
"""

import base64

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from .database import get_session
from .models import Token
from .security import verify_password

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Missing or invalid token password.",
    headers={"WWW-Authenticate": 'Basic realm="NeonRelay"'},
)

_GONE = HTTPException(status_code=status.HTTP_410_GONE, detail="Token has expired.")


def ensure_live(token: Token) -> None:
    """Raise 410 if the token's TTL has elapsed. Shared by every endpoint."""
    if token.is_expired():
        raise _GONE


def extract_password(request: Request) -> str | None:
    header = request.headers.get("x-neonrelay-password")
    if header:
        return header

    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(authz[6:]).decode("utf-8")
            _, _, pw = decoded.partition(":")
            if pw:
                return pw
        except Exception:
            return None
    return None


async def authenticate_token(
    token_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> Token:
    """Resolve a token by id and verify its password, or raise 401/404."""
    token = await session.get(Token, token_id)
    if token is None:
        # Same 401 as a bad password would be ideal to avoid leaking which
        # tokens exist, but a 404 is friendlier for a dev tool. Choose 404.
        raise HTTPException(status_code=404, detail="Token not found.")

    password = extract_password(request)
    if not password or not verify_password(password, token.password_hash):
        raise _UNAUTHORIZED
    ensure_live(token)
    return token
