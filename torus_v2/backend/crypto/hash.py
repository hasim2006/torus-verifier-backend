"""
SHA-256 wrapper with deterministic byte encoding.
⚠ This file MUST be byte-for-byte equivalent to the client's crypto/hash.py.
   Any divergence causes silent verification failure for all users.
"""

import hashlib


def sha256(data: bytes) -> bytes:
    """Return 32-byte SHA-256 digest."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_int(value: int, length: int = 32) -> bytes:
    """Encode an integer to a fixed-length big-endian byte string."""
    return value.to_bytes(length, byteorder="big")


def hash_context(context: dict) -> bytes:
    """
    Deterministic hash of a context dict.
    Fields are sorted alphabetically before encoding to ensure
    identical output regardless of insertion order.
    """
    parts = b"".join(
        k.encode() + b":" + str(v).encode() + b"|"
        for k, v in sorted(context.items())
    )
    return sha256(parts)


def hash_with_seed(context_hash: bytes, seed: bytes) -> bytes:
    """H(context_hash || seed) — used for S, L, δ derivation."""
    return sha256(context_hash + seed)
