"""
Elliptic curve operations over secp256r1 (NIST P-256).
⚠ This file MUST be byte-for-byte equivalent to the client's crypto/ecc.py.

Changes vs. original:
  ✅ scalar_mult now correctly computes k × G using tinyec (was returning a
     random public key — silent security bug in the original placeholder).
  ✅ Constant-time comparison via hmac.compare_digest (already present).
  ✅ On-curve validation using cryptography library (already present).
"""

import hmac
from dataclasses import dataclass
from typing import Optional

# On-curve validation — cryptography library
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

# Scalar multiplication — tinyec (pure Python secp256r1)
from tinyec import registry as _tinyec_registry

_CURVE = _tinyec_registry.get_curve("P-256")  # secp256r1 / NIST P-256
_CRYPTOGRAPHY_CURVE = SECP256R1()

CURVE_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


@dataclass
class ECPoint:
    x: int
    y: int

    def to_bytes(self) -> bytes:
        """Uncompressed point encoding (64 bytes): x || y."""
        return self.x.to_bytes(32, "big") + self.y.to_bytes(32, "big")

    def to_hex(self) -> tuple[str, str]:
        return (self.x.to_bytes(32, "big").hex(), self.y.to_bytes(32, "big").hex())

    @classmethod
    def from_hex(cls, p_x: str, p_y: str) -> "ECPoint":
        return cls(x=int(p_x, 16), y=int(p_y, 16))


def is_on_curve(point: ECPoint) -> bool:
    """
    Validate that the point lies on secp256r1.
    MUST be called before any computation on a received point (invalid-curve attack prevention).
    """
    try:
        EllipticCurvePublicNumbers(
            x=point.x, y=point.y, curve=_CRYPTOGRAPHY_CURVE
        ).public_key(default_backend())
        return True
    except (InvalidKey, ValueError):
        return False


def scalar_mult(k: int) -> Optional[ECPoint]:
    """
    Compute P = k × G on secp256r1.
    Returns None if k == 0 or k >= curve order.

    Uses tinyec for deterministic scalar multiplication. ✅
    (The original placeholder was returning a random public key — this is the fix.)
    """
    if k <= 0 or k >= CURVE_ORDER:
        return None

    point = k * _CURVE.g
    return ECPoint(x=point.x, y=point.y)


def points_equal_constant_time(a: ECPoint, b: ECPoint) -> bool:
    """
    Constant-time equality check for two EC points.
    Uses hmac.compare_digest to prevent timing side-channels.
    """
    return hmac.compare_digest(a.to_bytes(), b.to_bytes())
