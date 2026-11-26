"""Pydantic request/response models for the management API."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class TokenCreate(BaseModel):
    # Optional: supply your own password, otherwise one is generated.
    password: Optional[str] = Field(default=None, min_length=6, max_length=128)
    response_status: int = Field(default=202, ge=100, le=599)
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = "NeonRelay: relayed"
    response_content_type: str = "text/plain"
    response_delay_ms: int = Field(default=0, ge=0, le=30_000)
    # Optional lifetime in seconds. When set, the token expires after this many
    # seconds and is then rejected (410) everywhere. None/0 means it never expires.
    ttl_seconds: Optional[int] = Field(default=None, ge=1, le=31_536_000)


class TokenUpdate(BaseModel):
    response_status: Optional[int] = Field(default=None, ge=100, le=599)
    response_headers: Optional[dict[str, str]] = None
    response_body: Optional[str] = None
    response_content_type: Optional[str] = None
    response_delay_ms: Optional[int] = Field(default=None, ge=0, le=30_000)


_DAY = 86_400


class SelfDestructIn(BaseModel):
    # $/selfdestruct : dans combien de secondes (1 min à 1 an).
    seconds: int = Field(ge=60, le=365 * _DAY)


class DeadmanIn(BaseModel):
    # $/deadman <durée> <mot de passe> : armer, ou remettre le compteur à zéro.
    seconds: int = Field(ge=60, le=365 * _DAY)
    password: str = Field(min_length=8, max_length=256)


class DeadmanCancel(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class LifecycleStatus(BaseModel):
    # Secondes restantes avant destruction (selon l'heure du serveur), ou None.
    destroy_in: Optional[int] = None
    deadman_in: Optional[int] = None
    deadman_armed: bool = False
    # selfdestruct : "set" / "unchanged" (échéance déjà plus proche) ;
    # deadman : "armed" / "reset" / "cancelled" / "not-armed" ; lecture : "status".
    result: str = "status"


class TokenPublic(BaseModel):
    id: str
    response_status: int
    response_headers: dict
    response_body: str
    response_content_type: str
    response_delay_ms: int
    created_at: datetime
    expires_at: Optional[datetime] = None


class TokenCreated(TokenPublic):
    # Plaintext password, returned ONLY once at creation time.
    password: str
