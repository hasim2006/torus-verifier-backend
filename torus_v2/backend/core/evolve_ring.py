"""
Post-authentication ring evolution.

After every successful authentication:
  R_new = rotate(R, k mod n) ⊕ H(k)

Both client and server apply this independently. The server persists R_new
and increments ring_version via the async UserRepository.

Forward security: even if R_new is compromised, R (and all past rings)
cannot be recovered — one-way ratchet.
"""

from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession

from backend.crypto.ring import evolve_ring as _evolve_ring
from torus_v2.backend.db.models.user import User, UserRepository


async def apply_ring_evolution(
    user: User,
    k: int,
    session: AsyncSession,
) -> int:
    """
    Evolve the user's ring and persist the new state.

    Args:
        user    : authenticated user
        k       : scalar derived during this session
        session : async DB session (injected)

    Returns:
        new_version (int)
    """
    previous_ring = list(user.ring)
    new_ring      = _evolve_ring(user.ring, k)
    new_version   = user.ring_version + 1

    repo = UserRepository(session)
    await repo.save_evolved_ring(
        user_id=user.user_id,
        previous_ring=previous_ring,
        new_ring=new_ring,
        new_version=new_version,
    )

    return new_version
