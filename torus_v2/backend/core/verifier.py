"""
Full server-side verification pipeline.

Pipeline:
  challenge_id → fetch C from Redis → derive S, L, δ
  → extract D → hash chain → k* → k → P_expected
  → constant-time compare(P_expected, P_received)

Security notes:
  ✅ On-curve validation before any computation (invalid-curve attack prevention)
  ✅ Constant-time comparison via hmac.compare_digest
  ✅ Challenge fetched+deleted atomically (prevents re-use at this layer too)
  ✅ k == 0 edge case handled (PRD §8.3)
  ⚠  Ephemeral zeroisation (D, k_star, k) — Python GC is non-deterministic;
     see _zero_list note below
"""

from dataclasses import dataclass
from uuid import UUID

from redis.asyncio import Redis

from backend.core.challenge import fetch_and_expire_challenge
from backend.core.derive_params import derive_params
from backend.crypto.projection import extract_projection
from backend.crypto.hash import sha256, hash_context, encode_int
from backend.crypto.ecc import (
    ECPoint,
    is_on_curve,
    scalar_mult,
    points_equal_constant_time,
    CURVE_ORDER,
)


@dataclass
class VerificationResult:
    success: bool
    failure_reason: str | None = None
    k: int | None = None   # returned so evolve_ring can use it; never logged/transmitted


def sequential_hash_chain(context: dict, projection: list[int]) -> int:
    """
    Compress projection into scalar k* via sequential hash chain.

    x₀ = H(C)
    xᵢ = H(xᵢ₋₁ || dᵢ)
    k* = x_L  (as integer)

    Sequential — each step depends on the previous, preventing parallelism.
    """
    x = hash_context(context)
    for d in projection:
        x = sha256(x + encode_int(d, length=1))
    return int.from_bytes(x, "big")


def _zero_list(lst: list) -> None:
    """Best-effort zero-fill a list of ints (Python GC is non-deterministic)."""
    for i in range(len(lst)):
        lst[i] = 0


async def verify_authentication(
    *,
    challenge_id: UUID,
    p_x: str,
    p_y: str,
    ring: list[int],
    seeds: dict,
    redis: Redis,
) -> VerificationResult:
    """
    Full verification pipeline.

    Args:
        challenge_id : UUID — fetches and expires challenge from Redis
        p_x, p_y     : hex strings of received EC point P
        ring         : user's decrypted ring R
        seeds        : {"alpha": bytes, "beta": bytes, "gamma": bytes}
        redis        : async Redis client

    Returns:
        VerificationResult with success flag, optional failure reason, and k.
    """
    # ── Step 0: parse + validate received point ───────────────────────────────
    try:
        P_received = ECPoint.from_hex(p_x, p_y)
    except (ValueError, OverflowError):
        return VerificationResult(success=False, failure_reason="INVALID_POINT_FORMAT")

    if not is_on_curve(P_received):
        return VerificationResult(success=False, failure_reason="POINT_NOT_ON_CURVE")

    # ── Step 1: fetch + expire challenge from Redis ───────────────────────────
    context = await fetch_and_expire_challenge(challenge_id, redis)
    if context is None:
        return VerificationResult(success=False, failure_reason="CONTEXT_EXPIRED")

    # ── Step 2: derive traversal parameters ──────────────────────────────────
    n = len(ring)
    S, L, delta = derive_params(
        context=context,
        alpha=seeds["alpha"],
        beta=seeds["beta"],
        gamma=seeds["gamma"],
        n=n,
    )

    # ── Step 3: extract projection D ─────────────────────────────────────────
    D = extract_projection(ring, S, L, delta)

    # ── Step 4: sequential hash chain → k* ───────────────────────────────────
    k_star = sequential_hash_chain(context, D)

    # ── Step 5: scalar reduction k = k* mod q ────────────────────────────────
    k = k_star % CURVE_ORDER
    if k == 0:
        _zero_list(D)
        return VerificationResult(success=False, failure_reason="INVALID_SCALAR")

    # ── Step 6: P_expected = k × G ───────────────────────────────────────────
    P_expected = scalar_mult(k)
    if P_expected is None:
        _zero_list(D)
        return VerificationResult(success=False, failure_reason="INVALID_SCALAR")

    # ── Step 7: constant-time comparison ─────────────────────────────────────
    match = points_equal_constant_time(P_received, P_expected)

    # ── Step 8: zeroise ephemeral projection ─────────────────────────────────
    _zero_list(D)

    if not match:
        return VerificationResult(success=False, failure_reason="VERIFICATION_FAILED")

    return VerificationResult(success=True, k=k)
