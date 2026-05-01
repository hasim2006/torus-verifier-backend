"""
Derives traversal parameters S, L, δ from context C and shared seeds.

All derivation is deterministic — given the same C and seeds, both client and
server must produce identical S, L, δ values.
"""

from backend.crypto.hash import hash_context, hash_with_seed


def derive_params(context: dict, alpha: bytes, beta: bytes, gamma: bytes,
                  n: int) -> tuple[int, int, int]:
    """
    Derive start index S, length L, and direction δ from context.

    Args:
        context : challenge dict (nonce, timestamp, device_id, entropy)
        alpha   : seed for start-index derivation
        beta    : seed for length derivation
        gamma   : seed for direction derivation
        n       : ring size

    Returns:
        (S, L, delta) where:
          S     ∈ [0, n-1]
          L     ∈ [1, n]
          delta ∈ {+1, -1}
    """
    ctx_hash = hash_context(context)

    # S = H(C || α) mod n
    h_alpha = hash_with_seed(ctx_hash, alpha)
    S = int.from_bytes(h_alpha, "big") % n

    # L = (H(C || β) mod (n-1)) + 1  →  ensures 1 ≤ L ≤ n
    h_beta = hash_with_seed(ctx_hash, beta)
    L = (int.from_bytes(h_beta, "big") % (n - 1)) + 1

    # δ = (-1)^(H(C || γ) mod 2)  →  LSB determines direction
    h_gamma = hash_with_seed(ctx_hash, gamma)
    delta = 1 if (int.from_bytes(h_gamma, "big") % 2 == 0) else -1

    return S, L, delta
