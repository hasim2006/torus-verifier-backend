"""
FastAPI dependency-injection factories for shared resources.

Import these into route handlers:

    async def my_route(redis: Redis = Depends(get_redis)):
        ...
"""

from typing import AsyncGenerator
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.db.session import async_session_factory

# ── Redis ──────────────────────────────────────────────────────────────────────

_redis_client: Redis | None = None


async def get_redis() -> Redis:
    """Return the shared async Redis client (one per process)."""
    global _redis_client
    if _redis_client is None:
        _redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


async def close_redis() -> None:
    """Gracefully close the Redis connection (called on app shutdown)."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


# ── Database session ──────────────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield a per-request async DB session, auto-committed on exit."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
