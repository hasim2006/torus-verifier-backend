"""
Redis-backed replay prevention cache.

Every consumed challenge_id is stored with TTL:
  TTL = challenge_ttl (300 s) + max_clock_skew (60 s) = 360 s

If a challenge_id is seen again within that window, it's a replay.

⚠ MUST use Redis (not in-process dict) for multi-instance deployments.
  An in-process set silently fails under horizontal scaling.
"""

from uuid import UUID
from redis.asyncio import Redis
from backend.config import settings

REPLAY_CACHE_TTL = settings.replay_cache_ttl_seconds


async def is_replay(challenge_id: UUID, redis: Redis) -> bool:
    """Return True if this challenge_id has already been consumed."""
    return bool(await redis.exists(f"used_challenge:{challenge_id}"))


async def mark_used(challenge_id: UUID, redis: Redis) -> None:
    """Mark a challenge_id as consumed. Expires after REPLAY_CACHE_TTL seconds."""
    await redis.setex(f"used_challenge:{challenge_id}", REPLAY_CACHE_TTL, "1")
