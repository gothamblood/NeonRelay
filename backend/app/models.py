"""ORM models for the fire-and-forget relay.

Only the token registry is persisted: an admin account and the tokens (id,
password hash, and the response each inbox returns to senders). Incoming
traffic -- methods, headers, bodies -- is pushed live to SSE listeners and
then discarded. Nothing about what a sender transmits is ever stored.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AdminUser(Base):
    """An operator allowed to create tokens via POST /api/tokens."""

    __tablename__ = "admin_users"

    username: Mapped[str] = mapped_column(String(128), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Token(Base):
    """A relay inbox: id + password, plus the response returned to senders."""

    __tablename__ = "tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    password_hash: Mapped[str] = mapped_column(String(255))

    # Response returned to whoever hits the capture endpoint (configurable).
    response_status: Mapped[int] = mapped_column(Integer, default=202)
    response_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    response_body: Mapped[str] = mapped_column(Text, default="NeonRelay: relayed")
    response_content_type: Mapped[str] = mapped_column(String(255), default="text/plain")
    response_delay_ms: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # Optional time-to-live: once past, the token is treated as gone (410) on
    # every endpoint. NULL means no expiry.
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )

    # $/deadman : homme mort. La boîte est détruite si personne ne remet le
    # compteur à zéro (avec le mot de passe de l'homme mort, distinct de celui de
    # la boîte, haché PBKDF2) avant l'échéance. NULL = pas d'homme mort.
    deadman_hash: Mapped[str | None] = mapped_column(String(255), nullable=True, default=None)
    deadman_deadline: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )

    @staticmethod
    def _aware(dt: datetime | None) -> datetime | None:
        if dt is not None and dt.tzinfo is None:  # SQLite may hand back a naive datetime
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def deadline(self) -> datetime | None:
        """Échéance effective : la plus proche de expires_at ($/selfdestruct, TTL)
        et de l'homme mort. None = jamais."""
        dates = [d for d in (self._aware(self.expires_at), self._aware(self.deadman_deadline)) if d]
        return min(dates) if dates else None

    def is_expired(self) -> bool:
        d = self.deadline()
        return d is not None and _now() >= d
