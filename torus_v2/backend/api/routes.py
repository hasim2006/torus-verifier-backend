"""
API routes for the TORUS Verifier service.

Endpoints:
  GET  /api/v1/challenge      — issue a fresh authentication challenge
  POST /api/v1/authenticate   — verify client point P
  POST /api/v1/enroll         — register a new user+ring
  GET  /api/v1/health         — liveness probe
  GET  /api/v1/ready          — readiness probe (Redis + DB)

All responses contain only the minimum fields needed.
Error responses NEVER include ring state, scalars, or seeds.
"""

import secrets
import structlog
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.config import settings
from backend.dependencies import get_redis, get_db
from torus_v2.backend.db.models.user import User, UserRepository
from backend.core.challenge import generate_challenge
from backend.core.verifier import verify_authentication
from backend.core.evolve_ring import apply_ring_evolution
from backend.core.replay_cache import is_replay, mark_used
from backend.core.versioning import resolve_ring_version, VersionDesyncError

log = structlog.get_logger()

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ChallengeResponse(BaseModel):
    challenge_id: UUID
    nonce:        str
    timestamp:    str
    device_id:    str
    entropy:      str
    ring_version: int


class AuthRequest(BaseModel):
    challenge_id:  UUID
    user_id:       UUID
    p_x:           str = Field(..., pattern=r"^[0-9a-f]{64}$")
    p_y:           str = Field(..., pattern=r"^[0-9a-f]{64}$")
    ring_version:  int = Field(..., ge=0)


class AuthResponse(BaseModel):
    success:     bool
    new_version: int


class EnrollRequest(BaseModel):
    device_id:  str = Field(..., min_length=8, max_length=128)
    ring:       list[int] = Field(..., min_length=8, max_length=64)
    alpha_hex:  str = Field(..., pattern=r"^[0-9a-f]{64}$")
    beta_hex:   str = Field(..., pattern=r"^[0-9a-f]{64}$")
    gamma_hex:  str = Field(..., pattern=r"^[0-9a-f]{64}$")


class EnrollResponse(BaseModel):
    user_id: UUID


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/challenge", response_model=ChallengeResponse)
@limiter.limit(settings.challenge_rate_limit)
async def challenge(
    request:   Request,
    user_id:   UUID,
    device_id: str,
    redis:     Redis        = Depends(get_redis),
    db:        AsyncSession = Depends(get_db),
):
    """Issue a fresh authentication challenge (TTL = 300 s)."""
    repo = UserRepository(db)
    try:
        user = await repo.get(user_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    if user.device_id != device_id:
        raise HTTPException(status_code=403, detail="DEVICE_MISMATCH")

    ctx = await generate_challenge(
        user_id=user_id,
        device_id=device_id,
        ring_version=user.ring_version,
        redis=redis,
    )
    return ctx


@router.post("/authenticate", response_model=AuthResponse)
@limiter.limit(settings.auth_rate_limit)
async def authenticate(
    request: Request,
    body:    AuthRequest,
    redis:   Redis        = Depends(get_redis),
    db:      AsyncSession = Depends(get_db),
):
    """Submit P for verification. Returns 200 or an error code."""
    t_start = datetime.now(timezone.utc)

    # ── 1. Replay check (before any expensive crypto) ────────────────────────
    if await is_replay(body.challenge_id, redis):
        raise HTTPException(status_code=409, detail="REPLAY_DETECTED")

    await mark_used(body.challenge_id, redis)

    # ── 2. Load user ──────────────────────────────────────────────────────────
    repo = UserRepository(db)
    try:
        user = await repo.get(body.user_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    # ── 3. Resolve ring version ───────────────────────────────────────────────
    try:
        ring, seeds = await resolve_ring_version(user, body.ring_version)
    except VersionDesyncError:
        raise HTTPException(status_code=409, detail="VERSION_DESYNC")

    # ── 4. Verify ─────────────────────────────────────────────────────────────
    result = await verify_authentication(
        challenge_id=body.challenge_id,
        p_x=body.p_x,
        p_y=body.p_y,
        ring=ring,
        seeds=seeds,
        redis=redis,
    )

    latency_ms = (datetime.now(timezone.utc) - t_start).total_seconds() * 1000

    if not result.success:
        log.info(
            "auth_attempt",
            user_id=str(body.user_id),
            challenge_id=str(body.challenge_id),
            ring_version=body.ring_version,
            result="FAILURE",
            failure_reason=result.failure_reason,
            latency_ms=round(latency_ms, 2),
        )
        status = 422 if result.failure_reason in (
            "CONTEXT_EXPIRED", "INVALID_SCALAR", "CLOCK_SKEW"
        ) else 401
        raise HTTPException(status_code=status, detail=result.failure_reason)

    # ── 5. Evolve ring ────────────────────────────────────────────────────────
    new_version = await apply_ring_evolution(user, result.k, db)

    log.info(
        "auth_attempt",
        user_id=str(body.user_id),
        challenge_id=str(body.challenge_id),
        ring_version=body.ring_version,
        result="SUCCESS",
        new_version=new_version,
        latency_ms=round(latency_ms, 2),
    )

    return AuthResponse(success=True, new_version=new_version)


@router.post("/enroll", response_model=EnrollResponse, status_code=201)
async def enroll(
    body: EnrollRequest,
    db:   AsyncSession = Depends(get_db),
):
    """
    Register a new user with an initial ring and derivation seeds.

    In production this endpoint MUST be protected by an out-of-band
    verification step (e.g. email/OTP confirmation) before the user
    is activated.
    """
    user_id = uuid4()
    repo = UserRepository(db)
    await repo.create(
        user_id=user_id,
        device_id=body.device_id,
        ring=body.ring,
        alpha=bytes.fromhex(body.alpha_hex),
        beta=bytes.fromhex(body.beta_hex),
        gamma=bytes.fromhex(body.gamma_hex),
        ring_size=len(body.ring),
    )
    log.info("user_enrolled", user_id=str(user_id), device_id=body.device_id)
    return EnrollResponse(user_id=user_id)


@router.get("/health")
async def health():
    """Liveness probe — returns 200 if the process is alive."""
    return {"status": "ok"}


@router.get("/ready")
async def ready(
    redis: Redis        = Depends(get_redis),
    db:    AsyncSession = Depends(get_db),
):
    """
    Readiness probe — checks Redis and DB connectivity.
    Returns 503 if either dependency is unavailable.
    """
    errors: dict[str, str] = {}

    # Ping Redis
    try:
        await redis.ping()
    except Exception as exc:
        errors["redis"] = str(exc)

    # Ping DB
    try:
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        errors["database"] = str(exc)

    if errors:
        return JSONResponse(status_code=503, content={"status": "unavailable", "errors": errors})

    return {"status": "ready"}
