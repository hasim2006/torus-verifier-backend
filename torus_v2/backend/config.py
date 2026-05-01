"""
Centralised configuration — all tunables live here.
Values are read from environment variables (with .env file fallback).

Usage:
    from backend.config import settings
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── App ───────────────────────────────────────────────────────────────────
    app_title: str = "TORUS Verifier"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Database ──────────────────────────────────────────────────────────────
    # Async SQLAlchemy URL.  Use sqlite+aiosqlite for local dev.
    # In production set: postgresql+asyncpg://user:pass@host/db
    database_url: str = "sqlite+aiosqlite:///./torus_dev.db"

    # ── Security ──────────────────────────────────────────────────────────────
    challenge_ttl_seconds: int = 300          # PRD §7.1
    replay_cache_ttl_seconds: int = 360       # ttl + max_clock_skew
    max_clock_skew_seconds: int = 60

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    challenge_rate_limit: str = "10/minute"
    auth_rate_limit: str = "5/minute"

    # ── CORS ──────────────────────────────────────────────────────────────────
    cors_origins: list[str] = ["*"]           # Tighten in production


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Module-level singleton so most imports can just do `from backend.config import settings`
settings: Settings = get_settings()
