"""Async SQLAlchemy engine, session factory and declarative base."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False, future=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


async def init_db() -> None:
    # Import models so they register on Base before create_all.
    from . import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _migrate(conn)


async def _migrate(conn) -> None:
    """Tiny forward-only migrations for columns added after the first release.

    create_all() creates missing tables but never alters existing ones, so a
    DB from before a column was added needs the column back-filled by hand.
    """
    rows = await conn.exec_driver_sql("PRAGMA table_info(tokens)")
    columns = {row[1] for row in rows}
    # The stash is now a per-request option (?__stash), no longer a token column.
    # Drop the old flag from databases created by an earlier version.
    if "stash_enabled" in columns:
        await conn.execute(text("ALTER TABLE tokens DROP COLUMN stash_enabled"))
    # TTL column added later; back-fill it (NULL = never expires) on old DBs.
    if "expires_at" not in columns:
        await conn.execute(text("ALTER TABLE tokens ADD COLUMN expires_at DATETIME"))
