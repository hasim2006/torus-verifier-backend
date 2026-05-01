"""
User ORM model + async repository.

Security requirements:
  - `ring` and seed columns are stored AES-256 encrypted at the DB layer.
    In production use an encrypted column type or a KMS-backed HSM.
  - ring is NEVER transmitted over the wire or included in logs.
  - __repr__ deliberately omits all sensitive fields.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import String, Integer, DateTime, Text, select
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import Base


# ── ORM Model ─────────────────────────────────────────────────────────────────

class UserORM(Base):
    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    ring_json: Mapped[str] = mapped_column(Text, nullable=False)           # JSON list[int], encrypted at rest
    ring_version: Mapped[int] = mapped_column(Integer, default=0)
    previous_ring_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    alpha_hex: Mapped[str] = mapped_column(String(64), nullable=False)     # encrypted at rest
    beta_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    gamma_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    ring_size: Mapped[int] = mapped_column(Integer, default=16)
    enrolled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_auth_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        # Deliberately omit ring, seeds
        return f"User(user_id={self.user_id}, ring_version={self.ring_version}, device_id={self.device_id})"


# ── Domain model (in-memory, decrypted view) ──────────────────────────────────

class User:
    """Decrypted in-memory representation. Never serialise directly to JSON."""

    def __init__(self, orm: UserORM):
        self.user_id: UUID       = UUID(orm.user_id)
        self.device_id: str      = orm.device_id
        self.ring: list[int]     = json.loads(orm.ring_json)
        self.ring_version: int   = orm.ring_version
        self.previous_ring: Optional[list[int]] = (
            json.loads(orm.previous_ring_json) if orm.previous_ring_json else None
        )
        self.alpha: bytes  = bytes.fromhex(orm.alpha_hex)
        self.beta: bytes   = bytes.fromhex(orm.beta_hex)
        self.gamma: bytes  = bytes.fromhex(orm.gamma_hex)
        self.ring_size: int    = orm.ring_size
        self.enrolled_at       = orm.enrolled_at
        self.last_auth_at      = orm.last_auth_at

    @property
    def seeds(self) -> dict:
        return {"alpha": self.alpha, "beta": self.beta, "gamma": self.gamma}

    def __repr__(self) -> str:
        return f"User(user_id={self.user_id}, ring_version={self.ring_version}, device_id={self.device_id})"


# ── Async Repository ──────────────────────────────────────────────────────────

class UserRepository:
    def __init__(self, session: AsyncSession):
        self._session = session

    async def get(self, user_id: UUID) -> User:
        orm = await self._session.get(UserORM, str(user_id))
        if orm is None:
            raise KeyError(f"User {user_id} not found")
        return User(orm)

    async def exists(self, user_id: UUID) -> bool:
        result = await self._session.execute(
            select(UserORM.user_id).where(UserORM.user_id == str(user_id))
        )
        return result.scalar() is not None

    async def create(
        self,
        *,
        user_id: UUID,
        device_id: str,
        ring: list[int],
        alpha: bytes,
        beta: bytes,
        gamma: bytes,
        ring_size: int = 16,
    ) -> User:
        orm = UserORM(
            user_id=str(user_id),
            device_id=device_id,
            ring_json=json.dumps(ring),
            ring_version=0,
            alpha_hex=alpha.hex(),
            beta_hex=beta.hex(),
            gamma_hex=gamma.hex(),
            ring_size=ring_size,
            enrolled_at=datetime.now(timezone.utc),
        )
        self._session.add(orm)
        await self._session.flush()
        return User(orm)

    async def save_evolved_ring(
        self,
        user_id: UUID,
        previous_ring: list[int],
        new_ring: list[int],
        new_version: int,
    ) -> None:
        orm = await self._session.get(UserORM, str(user_id))
        if orm is None:
            raise KeyError(f"User {user_id} not found")
        orm.previous_ring_json = json.dumps(previous_ring)
        orm.ring_json          = json.dumps(new_ring)
        orm.ring_version       = new_version
        orm.last_auth_at       = datetime.now(timezone.utc)
        await self._session.flush()
