"""
Ring version management.

Handles the v / v-1 fallback for the edge case where the client
evolves its ring before receiving the server's success ACK.

If the version gap exceeds 1, triggers VERSION_DESYNC requiring re-enrollment.
"""

from torus_v2.backend.db.models.user import User


class VersionDesyncError(Exception):
    pass


async def resolve_ring_version(user: User, client_version: int) -> tuple[list[int], dict]:
    """
    Return the ring and seeds appropriate for the client's ring_version.

    Accepts:
      - client_version == user.ring_version      → use current ring
      - client_version == user.ring_version - 1  → use previous ring (fallback)

    Raises:
      VersionDesyncError if the gap is > 1 (triggers re-enrollment flow).
    """
    server_version = user.ring_version

    if client_version == server_version:
        return user.ring, user.seeds

    if client_version == server_version - 1:
        # Fallback: client hasn't yet received server's evolution ACK
        if user.previous_ring is None:
            raise VersionDesyncError(
                f"Client at v{client_version} but no previous ring stored "
                f"(server at v{server_version})"
            )
        return user.previous_ring, user.seeds

    raise VersionDesyncError(
        f"Version gap too large: client={client_version}, server={server_version}. "
        f"Re-enrollment required."
    )
