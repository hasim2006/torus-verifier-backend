"""
TORUS Verifier — FastAPI application entry point.

Startup sequence:
  1. Initialise DB tables (idempotent)
  2. Warm Redis connection
  3. Mount Prometheus metrics at /metrics

Run locally:
  uvicorn backend.main:app --reload

Production (Docker):
  uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 4
"""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.api.routes import router
from backend.config import settings
from backend.db.session import init_db, close_db
from backend.dependencies import get_redis, close_redis

log = structlog.get_logger()


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("startup", service="torus-verifier", version=settings.app_version)

    # Init DB tables (no-op if already exist)
    await init_db()

    # Warm Redis connection
    redis = await get_redis()
    try:
        await redis.ping()
        log.info("redis_connected", url=settings.redis_url)
    except Exception as exc:
        log.warning("redis_unavailable", error=str(exc))

    yield  # ── app running ──────────────────────────────────────────────────

    log.info("shutdown")
    await close_redis()
    await close_db()


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    limiter = Limiter(key_func=get_remote_address)

    application = FastAPI(
        title=settings.app_title,
        version=settings.app_version,
        docs_url="/docs" if settings.debug else None,   # hide Swagger in prod
        redoc_url="/redoc" if settings.debug else None,
        lifespan=lifespan,
    )

    # Rate limiting
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # CORS
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Prometheus metrics at /metrics
    Instrumentator().instrument(application).expose(application)

    # Routes
    application.include_router(router, prefix="/api/v1")

    # Generic exception handler — never leak internals
    @application.exception_handler(Exception)
    async def generic_handler(request: Request, exc: Exception) -> JSONResponse:
        log.error(
            "unhandled_exception",
            path=request.url.path,
            error_type=type(exc).__name__,
        )
        return JSONResponse(status_code=500, content={"error": "INTERNAL_ERROR"})

    return application


app = create_app()
