"""
Extracts a linear projection D from the cyclic ring R given parameters S, L, δ.
⚠ Must be byte-for-byte equivalent to client's crypto/projection.py.
"""


def extract_projection(ring: list[int], S: int, L: int, delta: int) -> list[int]:
    """
    Extract L elements from ring starting at index S, stepping by delta.

    Args:
        ring  : cyclic ring R of n elements
        S     : start index (0 ≤ S < n)
        L     : number of elements to read (1 ≤ L ≤ n)
        delta : +1 (clockwise) or -1 (counter-clockwise)

    Returns:
        Projection D as a list of L integers.

    Example:
        ring=[87,23,56,91,42,15,78,34,69,50], S=2, L=7, delta=+1
        → [56, 91, 42, 15, 78, 34, 69]

    Wrap-around example:
        ring=[87,23,56,91,42,15,78,34,69,50], S=8, L=4, delta=+1
        → indices 8,9,0,1 → [69, 50, 87, 23]
    """
    n = len(ring)
    if not (1 <= L <= n):
        raise ValueError(f"L must be in [1, {n}], got {L}")
    if delta not in (1, -1):
        raise ValueError(f"delta must be +1 or -1, got {delta}")

    return [ring[(S + i * delta) % n] for i in range(L)]
