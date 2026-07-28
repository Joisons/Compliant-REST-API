# Compliant FinTech Data API

A small, working REST API (FastAPI) implementing three governance controls central to operating a data platform in a regulated financial-technology environment: **role-based access control**, **tamper-evident audit logging**, and **role-tiered rate limiting** built as a companion implementation to the 2022 paper on leadership practices in overseeing data engineers in regulated FinTech environments.

The paper argues that technical governance of a data engineering function is, in practice, a leadership discipline: who is allowed to do what, how that is proven after the fact, and how the system protects itself from both external abuse and internal error. This repository is that argument turned into 700+ lines of running, tested code rather than a description of it.

## Governance pattern → implementation map

| Governance concern | Implementation |
|---|---|
| Who is allowed to do what | `app/core/rbac.py` — four roles, permissions declared per-route |
| Segregation of duties | AUDITOR has full read access but zero write access anywhere in the system |
| Proving what happened, after the fact | `app/middleware/audit_logging.py` every request logged, including denials and rate-limit rejections |
| Proving the log itself hasn't been altered | SHA-256 hash chain across log entries; `GET /api/v1/audit-logs/verify` |
| Protecting the system from abuse | `app/middleware/rate_limit.py` role-tiered sliding-window limits, plus IP-based brute-force protection on login |
| Immediate access revocation | `get_current_user` re-checks `is_active` against the database on every request, not only at login |
| Consistent, machine-readable errors | RFC 7807 "Problem Details" format on every error response |

## Roles and permissions

| Resource | VIEWER | ANALYST | AUDITOR | ADMIN |
|---|---|---|---|---|
| Accounts — read | ✅ | ✅ | ✅ | ✅ |
| Accounts — create | ❌ | ✅ | ❌ | ✅ |
| Accounts — delete | ❌ | ❌ | ❌ | ✅ |
| Transactions — read | ❌ | ✅ | ✅ | ✅ |
| Transactions — create | ❌ | ✅ | ❌ | ✅ |
| Reports — generate | ❌ | ✅ | ✅ | ✅ |
| Audit log — read / verify | ❌ | ❌ | ✅ | ✅ |
| User management | ❌ | ❌ | ❌ | ✅ |

AUDITOR's row is deliberately "read everything, write nothing" — the control that matters here is *independence*: the role responsible for reviewing activity should not itself be a source of the activity being reviewed.

**Rate limits** (requests per rolling 60-second window): VIEWER 30, ANALYST 60, AUDITOR 100, ADMIN 200 — plus a separate 10-attempts/minute IP-based limit on `POST /auth/login`, independent of username, to blunt credential-stuffing attempts regardless of which account is being targeted.

## Why a hash-chained audit log, not just a log file

A plain log file (or an ordinary, unprotected database table) can be edited after the fact with no trace. Each row here instead stores `entry_hash = SHA256(canonical_fields || previous_row_hash)`. Altering any field in any historical row even one character changes that row's recomputed hash, which no longer matches what's stored, and breaks every hash after it in the chain. `GET /api/v1/audit-logs/verify` recomputes the entire chain from the genesis hash and reports not just *whether* it's intact but the exact `id` of the first entry where it diverges. This is the same integrity pattern used by write-once ledgers, applied here to API access logs specifically because "was our audit trail itself tampered with" is a real question a regulator or forensic examiner can ask, and this system can answer it instead of assuming the answer.

The Integrity Verification page of the dashboard includes a live "tamper with an entry and re-verify" control that directly edits the database and shows detection happening in real time.

## Getting started

```bash
git clone <your-repo-url>
cd compliant_api_project
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 1. Seed demo users (one per role) and sample accounts
python -m scripts.seed_data

# 2. Start the API
uvicorn app.main:app --reload
# -> interactive OpenAPI docs at http://localhost:8000/docs

# 3. In a second terminal: generate realistic traffic, including deliberate
#    policy violations, against the running API
python -m scripts.simulate_traffic --base-url http://localhost:8000

# 4. In a third terminal: launch the monitoring dashboard
streamlit run dashboard/streamlit_dashboard.py
```

Demo credentials (also printed by `seed_data.py`):

| Username | Password | Role |
|---|---|---|
| `vera_viewer` | `ViewerPass123!` | VIEWER |
| `alex_analyst` | `AnalystPass123!` | ANALYST |
| `amara_auditor` | `AuditorPass123!` | AUDITOR |
| `admin` | `AdminPass123!` | ADMIN |

### Docker

```bash
docker compose up --build
# API      -> http://localhost:8000/docs
# Dashboard -> http://localhost:8501
```
(The Dockerfile and compose file are provided and reviewed for correctness, but Docker itself was not available in the environment this project was built in, so this path has not been executed end-to-end — test it before relying on it.)

## Testing

30 automated tests, each run against a fresh, isolated database:

```bash
pytest tests/ -v
```

```
tests/test_auth.py ....... (7 tests: login, bad credentials, missing/invalid
                             token, admin-only user creation, immediate
                             revocation of a deactivated user's session)
tests/test_rbac.py .............. (16 tests: full read/write matrix across
                             all four roles and all five resources, including
                             the AUDITOR segregation-of-duties check)
tests/test_rate_limit_and_audit.py ....... (7 tests: exact role-tiered
                             limits enforced, higher roles get higher
                             ceilings, login brute-force protection,
                             rate-limited requests appear in the audit log,
                             chain verifies clean, chain detects tampering
                             at the exact altered row, denials are logged)

30 passed
```

The project was also exercised end-to-end against a real running `uvicorn` server (not only in-process tests): `scripts/simulate_traffic.py` was run against a live instance, producing a real audit trail subsequently verified via the live `/api/v1/audit-logs/verify` endpoint, and the Streamlit dashboard was driven programmatically through every page and every interactive control (including the live-simulation trigger and the tamper/re-verify button) via Streamlit's `AppTest` framework, with zero runtime exceptions.

## Repository structure

```
compliant_api_project/
├── app/
│   ├── main.py                     # app assembly, middleware order, error handlers
│   ├── config.py                   # settings (env-overridable)
│   ├── database.py                 # SQLAlchemy engine/session
│   ├── core/
│   │   ├── security.py             # password hashing (bcrypt), JWT issue/decode
│   │   ├── rbac.py                 # get_current_user, require_roles(...)
│   │   └── rate_limiter.py         # sliding-window limiter
│   ├── middleware/
│   │   ├── audit_logging.py        # hash-chained request logging
│   │   └── rate_limit.py           # role-tiered + IP-based limiting
│   ├── models/
│   │   ├── db_models.py            # User, Account, Transaction, AuditLogEntry
│   │   └── schemas.py              # Pydantic request/response models
│   └── api/                        # auth, accounts, transactions, reports, audit, health
├── scripts/
│   ├── seed_data.py                # demo users + sample accounts
│   └── simulate_traffic.py         # realistic multi-role traffic generator
├── dashboard/
│   └── streamlit_dashboard.py      # audit trail / RBAC / rate-limit / integrity views
├── tests/                          # 30 pytest tests, isolated per-test database
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── LICENSE
```

## Design choices worth calling out

- **Middleware ordering is deliberate, not incidental.** `AuditLogMiddleware` is registered after `RateLimitMiddleware` specifically so it becomes the *outermost* layer (Starlette executes the last-registered middleware first on the way in). This means a 429 from the rate limiter or a 403 from an RBAC dependency deep inside a route still passes back through the audit logger and gets recorded — if the order were reversed, denied and rate-limited requests would silently vanish from the audit trail, which would defeat the point of having one.
- **Every outcome is logged, not just successes.** A pattern of repeated 403s from one account, or a burst of 429s from one IP, is itself a signal worth being able to query for later — so DENIED and RATE_LIMITED requests are recorded with the same fidelity as SUCCESS.
- **Direct `bcrypt` rather than `passlib`.** `passlib`'s bcrypt backend has a known incompatibility with `bcrypt>=4.0` (it introspects an internal `__about__.__version__` attribute that current bcrypt releases no longer expose). Calling `bcrypt.hashpw`/`checkpw` directly is simpler and sidesteps the issue rather than pinning an old dependency.
- **Timestamp canonicalization for the hash chain.** SQLite (via SQLAlchemy's default `DateTime` type) silently drops timezone info on read-back, even when a timezone-aware value was written. Hashing `dt.isoformat()` directly would have made an aware string at write-time ("...+00:00") mismatch its own naive string at verify-time ("...", no offset) — a false "tampering detected" on every single entry. `canonical_timestamp()` normalizes to naive UTC, truncated to millisecond precision, identically on both the write and verify paths, before it is ever hashed.
- **Best-effort identity extraction in the audit middleware.** The middleware tries to read the bearer token for logging purposes even before FastAPI's dependency injection has validated it, so that a *failed* auth attempt still gets logged with as much identifying information as is honestly available — an invalid token simply logs as anonymous; the RBAC dependency downstream remains the actual authorization control, this is purely for audit-trail completeness.

## Limitations & what a real deployment would add

- **In-memory rate limiter.** The sliding-window limiter is single-process; a real deployment behind multiple API instances needs a shared store (Redis is the standard choice) so limits are enforced consistently across instances rather than per-process.
- **SQLite.** Fine for a demo; a production deployment handling concurrent write load would move to PostgreSQL, and the audit log specifically would benefit from write-once storage guarantees at the database or infrastructure layer (e.g., an append-only table with revoked UPDATE/DELETE privileges, or a dedicated ledger service) rather than relying solely on the application-level hash chain.
- **No secrets management.** `JWT_SECRET_KEY` is read from an environment variable with an insecure demo default; a real deployment should source it from a secrets manager and rotate it.
- **No refresh tokens.** Access tokens simply expire after 30 minutes with no renewal flow; a production system would add a refresh-token pattern.
- **Docker path unexecuted.** As noted above reviewed but not run end-to-end in this environment.
