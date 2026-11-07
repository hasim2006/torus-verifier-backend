# TORUS Backend — Verifier Service (v2)

Cyclic Projection Authentication System — scalable, API-only backend verifier.

---

## What changed from v1

| Area | v1 (original) | v2 (this release) |
|---|---|---|
| `scalar_mult` |  returned a **random** public key (silent bug) |  correct `k × G` via tinyec |
| Redis |  commented-out stubs / in-memory fallbacks |  fully wired (challenge store + replay cache) |
| Database |  in-memory dict |  async SQLAlchemy (SQLite dev / PostgreSQL prod) |
| Config |  hardcoded values |  pydantic-settings / `.env` |
| Rate limiting |  commented out |  wired via slowapi |
| Enrollment |  missing entirely |  `POST /api/v1/enroll` |
| `/ready` probe |  stub |  pings Redis + DB, returns 503 on failure |
| Route errors |  tuple returns (Flask-style, broken in FastAPI) |  `HTTPException` throughout |
| Docker |  none |  `Dockerfile` + `docker-compose.yml` |
| Metrics |  not wired |  Prometheus at `/metrics` |

---

## Quick start (local, SQLite + no Redis)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # edit if needed
uvicorn backend.main:app --reload
```

Swagger UI (debug mode only): http://localhost:8000/docs

---

## Quick start (Docker — full stack)

```bash
docker compose up --build
```

This starts:
- `api` on port 8000
- `redis:7-alpine` on port 6379
- `postgres:16-alpine` on port 5432

---

## Project Structure

```
torus_backend/
├── backend/
│   ├── api/
│   │   └── routes.py          # GET /challenge, POST /authenticate,
│   │                          # POST /enroll, GET /health, GET /ready
│   ├── core/
│   │   ├── challenge.py       # Context vector generation (Redis-backed)
│   │   ├── verifier.py        # Full verification pipeline
│   │   ├── evolve_ring.py     # Post-auth ring evolution
│   │   ├── replay_cache.py    # Redis-backed nonce cache
│   │   ├── derive_params.py   # S, L, δ derivation
│   │   └── versioning.py      # v / v-1 fallback, desync detection
│   ├── crypto/                #  MUST match client crypto/ exactly
│   │   ├── hash.py
│   │   ├── ecc.py             # FIXED: scalar_mult now correct
│   │   ├── projection.py
│   │   └── ring.py
│   ├── db/
│   │   └── session.py         # Async SQLAlchemy engine + Base
│   ├── models/
│   │   └── user.py            # ORM + domain model + async repository
│   ├── config.py              # Centralised config (pydantic-settings)
│   ├── dependencies.py        # FastAPI DI factories (Redis, DB)
│   └── main.py                # App factory, lifespan, middleware
├── docs/
│   ├── test_vectors.json
│   └── openapi.yaml
├── tests/
│   ├── test_crypto.py
│   ├── test_routes.py
│   └── test_integration.py
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── requirements.txt
└── README.md
```

---

## API Reference

### `GET /api/v1/challenge`

Issue a fresh authentication challenge.

| Param | In | Required | Description |
|---|---|---|---|
| `user_id` | query |  | UUID of the user |
| `device_id` | query |  | Bound device identifier |

**Response 200**
```json
{
  "challenge_id": "uuid",
  "nonce": "64-char hex",
  "timestamp": "ISO-8601",
  "device_id": "string",
  "entropy": "8-char hex",
  "ring_version": 0
}
```

---

### `POST /api/v1/authenticate`

Submit point P for verification.

**Body**
```json
{
  "challenge_id":  "uuid",
  "user_id":       "uuid",
  "p_x":           "64-char hex",
  "p_y":           "64-char hex",
  "ring_version":  0
}
```

**Responses**

| Status | Detail |
|---|---|
| 200 | `{ "success": true, "new_version": N }` |
| 401 | `VERIFICATION_FAILED` / `POINT_NOT_ON_CURVE` |
| 404 | `USER_NOT_FOUND` |
| 409 | `REPLAY_DETECTED` / `VERSION_DESYNC` |
| 422 | `CONTEXT_EXPIRED` / `INVALID_SCALAR` / `CLOCK_SKEW` |
| 429 | Rate limit exceeded |

---

### `POST /api/v1/enroll`

Register a new user+ring. Protect with out-of-band verification in production.

**Body**
```json
{
  "device_id":  "string (8–128 chars)",
  "ring":       [87, 23, 56, ...],
  "alpha_hex":  "64-char hex",
  "beta_hex":   "64-char hex",
  "gamma_hex":  "64-char hex"
}
```

**Response 201**: `{ "user_id": "uuid" }`

---

### `GET /api/v1/health`   →   `{"status": "ok"}`
### `GET /api/v1/ready`    →   `{"status": "ready"}` or 503 with error details
### `GET /metrics`         →   Prometheus metrics

---

## Scalability Notes

- **Stateless per request** — suits any number of horizontally-scaled instances.
- **Redis** is the only shared mutable state (challenge store + replay cache). Use Redis Sentinel or Cluster for HA.
- **PostgreSQL** with connection pooling via `asyncpg`. Target: PgBouncer in transaction mode for high concurrency.
- **Rate limiting** is per-IP via slowapi. For multi-instance deployments, swap the default in-memory store for a Redis-backed SlowAPI storage backend.
- **Prometheus + OpenTelemetry** hooks are present for p50/p99 latency tracking.

---

## Phase 2 Roadmap

- [ ] Enrollment out-of-band verification (OTP / email gate)
- [ ] Prometheus alerting rules (latency SLO, error rate)
- [ ] Desync recovery protocol (re-enrollment flow)
- [ ] HSM-backed ring storage
- [ ] `IAuthWitness` interface for post-quantum swap
- [ ] Multi-device support per user
- [ ] Alembic migrations
