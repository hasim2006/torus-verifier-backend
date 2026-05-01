"""
Async SQLAlchemy engine + session factory.

Tables are created automatically at startup via `init_db()`.
For production migrations, swap in Alembic.
"""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from backend.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    pool_pre_ping=True,          # detect stale connections
    pool_recycle=1800,           # recycle every 30 min
)

async_session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Shared declarative base — all ORM models inherit from this."""
    pass


async def init_db() -> None:
    """Create all tables (idempotent). Call once on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose the connection pool. Call on shutdown."""
    await engine.dispose()
