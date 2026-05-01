"""
Unit tests for crypto primitives.
Run: pytest tests/test_crypto.py -v
"""

import pytest
from backend.crypto.projection import extract_projection
from backend.crypto.ring import rotate_ring, xor_with_hash, evolve_ring
from backend.crypto.hash import sha256, hash_with_seed, encode_int
from backend.crypto.ecc import ECPoint, is_on_curve


# ── Projection tests ──────────────────────────────────────────────────────────

class TestProjection:

    RING = [87, 23, 56, 91, 42, 15, 78, 34, 69, 50]  # PRD example ring

    def test_basic_clockwise(self):
        D = extract_projection(self.RING, S=2, L=7, delta=1)
        assert D == [56, 91, 42, 15, 78, 34, 69]  # PRD §4.2 Step 3 example

    def test_wrap_around_clockwise(self):
        # S=8, L=4, δ=+1 → indices 8,9,0,1
        D = extract_projection(self.RING, S=8, L=4, delta=1)
        assert D == [69, 50, 87, 23]

    def test_counter_clockwise(self):
        # S=4, L=3, δ=-1 → indices 4,3,2
        D = extract_projection(self.RING, S=4, L=3, delta=-1)
        assert D == [42, 91, 56]

    def test_wrap_around_counter_clockwise(self):
        # S=1, L=4, δ=-1 → indices 1,0,9,8
        D = extract_projection(self.RING, S=1, L=4, delta=-1)
        assert D == [23, 87, 50, 69]

    def test_full_ring_length(self):
        D = extract_projection(self.RING, S=0, L=10, delta=1)
        assert D == self.RING

    def test_single_element(self):
        D = extract_projection(self.RING, S=5, L=1, delta=1)
        assert D == [15]

    def test_invalid_L_raises(self):
        with pytest.raises(ValueError):
            extract_projection(self.RING, S=0, L=0, delta=1)
        with pytest.raises(ValueError):
            extract_projection(self.RING, S=0, L=11, delta=1)

    def test_invalid_delta_raises(self):
        with pytest.raises(ValueError):
            extract_projection(self.RING, S=0, L=3, delta=0)


# ── Ring evolution tests ──────────────────────────────────────────────────────

class TestRingEvolution:

    RING = [87, 23, 56, 91, 42, 15, 78, 34, 69, 50]

    def test_rotate_basic(self):
        assert rotate_ring([1, 2, 3, 4, 5], 2) == [3, 4, 5, 1, 2]

    def test_rotate_zero(self):
        assert rotate_ring(self.RING, 0) == self.RING

    def test_rotate_full_cycle_is_identity(self):
        assert rotate_ring(self.RING, len(self.RING)) == self.RING

    def test_evolve_changes_ring(self):
        k = 77234891623
        evolved = evolve_ring(self.RING, k)
        assert evolved != self.RING
        assert len(evolved) == len(self.RING)

    def test_evolve_is_deterministic(self):
        k = 77234891623
        assert evolve_ring(self.RING, k) == evolve_ring(self.RING, k)

    def test_evolve_different_k_gives_different_ring(self):
        assert evolve_ring(self.RING, 1) != evolve_ring(self.RING, 2)


# ── Hash tests ────────────────────────────────────────────────────────────────

class TestHash:

    def test_sha256_deterministic(self):
        h1 = sha256(b"hello")
        h2 = sha256(b"hello")
        assert h1 == h2

    def test_sha256_length(self):
        assert len(sha256(b"test")) == 32

    def test_encode_int_big_endian(self):
        b = encode_int(256, length=2)
        assert b == b"\x01\x00"

    def test_hash_with_seed_different_seeds(self):
        ctx = b"context"
        assert hash_with_seed(ctx, b"seed1") != hash_with_seed(ctx, b"seed2")


# ── ECC on-curve validation ───────────────────────────────────────────────────

class TestECC:

    def test_invalid_point_rejected(self):
        fake = ECPoint(x=0xDEADBEEF, y=0xDEADBEEF)
        assert is_on_curve(fake) is False

    def test_zero_point_rejected(self):
        zero = ECPoint(x=0, y=0)
        assert is_on_curve(zero) is False
