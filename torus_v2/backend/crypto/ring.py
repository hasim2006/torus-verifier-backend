"""
Ring operations: rotation and XOR-with-hash for forward-secure evolution.
⚠ Must be byte-for-byte equivalent to client's crypto/ring.py.
"""

from backend.crypto.hash import sha256


def rotate_ring(ring: list[int], positions: int) -> list[int]:
    """
    Rotate ring left by `positions` steps.
    Example: rotate([1,2,3,4,5], 2) → [3,4,5,1,2]
    """
    n = len(ring)
    pos = positions % n
    return ring[pos:] + ring[:pos]


def xor_with_hash(ring: list[int], k: int) -> list[int]:
    """
    XOR each element of ring with successive bytes of SHA-256(k).
    Produces a new ring of the same length.
    """
    k_bytes = k.to_bytes(32, byteorder="big")
    h = sha256(k_bytes)
    # Cycle hash bytes if ring is longer than 32 elements
    h_extended = (h * ((len(ring) // 32) + 1))[:len(ring)]
    return [r ^ b for r, b in zip(ring, h_extended)]


def evolve_ring(ring: list[int], k: int) -> list[int]:
    """
    R_new = rotate(R, k mod n) ⊕ H(k)

    This is the forward-security ratchet applied after every successful auth.
    Even if an attacker learns R_new, they cannot reverse to R (one-way).
    """
    n = len(ring)
    rotated = rotate_ring(ring, k % n)
    return xor_with_hash(rotated, k)
