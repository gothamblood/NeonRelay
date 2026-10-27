"""Admin authentication for the token-creation endpoint.

POST /api/tokens is privileged: only an admin (username + password, sent as
HTTP Basic auth) may create tokens. The admin password is stored hashed in the
database, exactly like token passwords. On first start a default admin is
created and its credentials are written once to a plaintext file so you know
them (meant as a temporary convenience — rotate/remove in production).
"""

import base64
import os

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .database import SessionLocal, get_session
from .models import AdminUser
from .security import generate_password, hash_password, verify_password

ADMIN_CREDS_FILE = settings.ADMIN_CREDS_FILE

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Admin username/password required to create a token.",
    headers={"WWW-Authenticate": 'Basic realm="NeonRelay Admin"'},
)


def _write_creds_file(username: str, password: str) -> None:
    old = os.umask(0o077)  # file readable by owner only (holds a secret)
    try:
        with open(ADMIN_CREDS_FILE, "w", encoding="utf-8") as fh:
            fh.write(
                "# NeonRelay admin credentials (temporary, do not commit)\n"
                f"username={username}\n"
                f"password={password}\n"
            )
    finally:
        os.umask(old)


async def ensure_admin() -> None:
    """Create a default admin on first boot and write its credentials once."""
    async with SessionLocal() as session:
        count = await session.scalar(select(func.count()).select_from(AdminUser))
        if count:
            return  # An admin already exists; never overwrite the creds file.

        username = os.getenv("NEONRELAY_ADMIN_USER", "neonrelayadmin")
        password = os.getenv("NEONRELAY_ADMIN_PASSWORD") or generate_password()

        session.add(
            AdminUser(username=username, password_hash=hash_password(password))
        )
        await session.commit()
        _write_creds_file(username, password)


def _basic_credentials(request: Request) -> tuple[str, str] | None:
    authz = request.headers.get("authorization", "")
    if not authz.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(authz[6:]).decode("utf-8")
    except Exception:
        return None
    username, sep, password = decoded.partition(":")
    if not sep:
        return None
    return username, password


async def require_admin(
    request: Request, session: AsyncSession = Depends(get_session)
) -> str:
    """Verify HTTP Basic admin credentials, or raise 401."""
    creds = _basic_credentials(request)
    if creds is None:
        raise _UNAUTHORIZED
    username, password = creds

    user = await session.get(AdminUser, username)
    if user is None or not verify_password(password, user.password_hash):
        raise _UNAUTHORIZED
    return username
