"""
API endpoint tests.
Run: pytest tests/test_routes.py -v
"""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from httpx import AsyncClient, ASGITransport
from backend.main import app


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


# ── Health / Ready ────────────────────────────────────────────────────────────

class TestHealthEndpoints:

    @pytest.mark.asyncio
    async def test_health(self, client):
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_ready_returns_200_or_503(self, client):
        # Either all deps up (200) or some down (503) — both are valid responses
        resp = await client.get("/api/v1/ready")
        assert resp.status_code in (200, 503)


# ── /authenticate validation ──────────────────────────────────────────────────

class TestAuthValidation:

    @pytest.mark.asyncio
    async def test_invalid_p_x_rejected(self, client):
        payload = {
            "challenge_id" : str(uuid4()),
            "user_id"      : str(uuid4()),
            "p_x"          : "ZZZZ",       # not valid hex64
            "p_y"          : "a" * 64,
            "ring_version" : 0,
        }
        resp = await client.post("/api/v1/authenticate", json=payload)
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_wrong_length_p_rejected(self, client):
        payload = {
            "challenge_id" : str(uuid4()),
            "user_id"      : str(uuid4()),
            "p_x"          : "aa",          # too short
            "p_y"          : "bb",
            "ring_version" : 0,
        }
        resp = await client.post("/api/v1/authenticate", json=payload)
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_negative_ring_version_rejected(self, client):
        payload = {
            "challenge_id" : str(uuid4()),
            "user_id"      : str(uuid4()),
            "p_x"          : "a" * 64,
            "p_y"          : "b" * 64,
            "ring_version" : -1,
        }
        resp = await client.post("/api/v1/authenticate", json=payload)
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_replay_rejected(self, client):
        """Second submission of the same challenge_id must return 409."""
        challenge_id = str(uuid4())
        payload = {
            "challenge_id" : challenge_id,
            "user_id"      : str(uuid4()),
            "p_x"          : "a" * 64,
            "p_y"          : "b" * 64,
            "ring_version" : 0,
        }

        with patch("backend.api.routes.is_replay", new_callable=AsyncMock) as mock_replay, \
             patch("backend.api.routes.mark_used",  new_callable=AsyncMock):
            seen: set[str] = set()

            async def fake_is_replay(cid, redis):
                return str(cid) in seen

            async def fake_mark_used(cid, redis):
                seen.add(str(cid))

            mock_replay.side_effect = fake_is_replay

            # First attempt passes replay check (may fail auth — that's fine)
            await client.post("/api/v1/authenticate", json=payload)

            # Force the second attempt to be seen as a replay
            seen.add(challenge_id)
            mock_replay.side_effect = fake_is_replay
            resp2 = await client.post("/api/v1/authenticate", json=payload)
            assert resp2.status_code == 409

    @pytest.mark.asyncio
    async def test_error_response_no_crypto_material(self, client):
        """Error responses must never contain ring/scalar/seed data."""
        payload = {
            "challenge_id" : str(uuid4()),
            "user_id"      : str(uuid4()),
            "p_x"          : "a" * 64,
            "p_y"          : "b" * 64,
            "ring_version" : 0,
        }
        resp = await client.post("/api/v1/authenticate", json=payload)
        body = resp.text.lower()
        for forbidden in ["ring", "projection", "scalar", "seed", "alpha", "beta", "gamma"]:
            assert forbidden not in body, f"Forbidden term '{forbidden}' in error response"
