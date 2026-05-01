"""
Integration tests — sequential authentication loop and ring evolution.
Run: pytest tests/test_integration.py -v

NOTE: These tests require the full pipeline to be wired (Redis, DB stubs).
      Until then they serve as the specification for accepted behaviour.
"""

import pytest

# Placeholder — wire when Redis + DB stubs are in place
pytestmark = pytest.mark.skip(reason="Requires Redis + DB wiring (Phase 1 Week 4)")


@pytest.mark.asyncio
async def test_sequential_authentications_with_evolution(client, enroll_test_user):
    """
    10 sequential authentications must all succeed.
    After round 3 the ring must differ from the initial R.
    Any previous P replayed against a new challenge must be rejected.
    """
    RING = [87, 23, 56, 91, 42, 15, 78, 34, 69, 50]
    user_id = await enroll_test_user(ring=RING)

    initial_ring = list(RING)
    previous_Ps  = []

    for i in range(10):
        ch   = (await client.get(f"/api/v1/challenge?user_id={user_id}&device_id=test")).json()
        P    = client_compute_P(ch)          # uses client-side crypto engine
        resp = await client.post("/api/v1/authenticate", json={
            "challenge_id": ch["challenge_id"],
            "user_id"     : str(user_id),
            "p_x"         : P["p_x"],
            "p_y"         : P["p_y"],
            "ring_version": i,
        })
        assert resp.status_code == 200, f"Auth round {i} failed: {resp.json()}"
        previous_Ps.append(P)

    # Ring must have evolved
    from torus_v2.backend.db.models.user import get_user
    updated_user = get_user(user_id)
    assert updated_user.ring != initial_ring, "Ring must evolve after auth"
    assert updated_user.ring_version == 10

    # Replay of round 0 must be rejected
    ch_new = (await client.get(f"/api/v1/challenge?user_id={user_id}&device_id=test")).json()
    replay = await client.post("/api/v1/authenticate", json={
        "challenge_id": ch_new["challenge_id"],
        "user_id"     : str(user_id),
        **previous_Ps[0],
        "ring_version": 10,
    })
    assert replay.status_code == 401, "Replayed P from round 0 must be rejected"
