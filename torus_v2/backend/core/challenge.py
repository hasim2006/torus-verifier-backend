"""
Challenge (context vector) generation.

Stores each challenge in Redis with TTL = CHALLENGE_TTL_SECONDS.
fetch_and_expire_challenge atomically retrieves+deletes it so a challenge
can never be used twice (replay prevention at the challenge layer).
"""

import json
import secrets
from datetime import datetime, timezone
from uuid import UUID, uuid4

from redis.asyncio import Redis

from backend.config import settings

CHALLENGE_TTL = settings.challenge_ttl_seconds


async def generate_challenge(
    *,
    user_id: UUID,
    device_id: str,
    ring_version: int,
    redis: Redis,
) -> dict:
    """
    Generate a fresh context vector C and store it in Redis.

    C = (challenge_id, nonce, timestamp, device_id, entropy, ring_version)

    Returns a dict suitable for ChallengeResponse.
    """
    challenge_id = uuid4()
    nonce        = secrets.token_bytes(32).hex()   # 256-bit nonce
    timestamp    = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entropy      = secrets.token_bytes(4).hex()    # 32-bit extra entropy

    context = {
        "challenge_id" : str(challenge_id),
        "nonce"        : nonce,
        "timestamp"    : timestamp,
        "device_id"    : device_id,
        "entropy"      : entropy,
        "ring_version" : ring_version,
        "user_id"      : str(user_id),
    }

    await redis.setex(
        f"challenge:{challenge_id}",
        CHALLENGE_TTL,
        json.dumps(context),
    )

    return context


async def fetch_and_expire_challenge(
    challenge_id: UUID,
    redis: Redis,
) -> dict | None:
    """
    Atomically fetch and delete a challenge from Redis.
    Returns None if the challenge has expired or never existed (CONTEXT_EXPIRED).
    """
    raw = await redis.getdel(f"challenge:{challenge_id}")
    if raw is None:
        return None
    return json.loads(raw)
