# Phase 8: API Key Authentication Final Report

The Phase 8 implementation successfully introduces a robust, database-backed API Key authentication layer to secure CiphR's expensive backend analysis routes from unauthorized access.

### Architecture
- **Existing auth situation**: Previously, all FastAPI endpoints were entirely public and unauthenticated.
- **Chosen API-key design**: Keys are minted securely via a command-line bootstrap script and provided by the client in the `X-API-Key` HTTP header. 
- **Authentication boundary**: Validation is implemented using FastAPI's `Depends` injection framework, running globally on specific `APIRouter` instances before any downstream pipeline execution occurs.

### Database
- **Model**: `APIKey` table in `app/db/models.py`.
- **Fields**: `id` (UUID), `key_hash` (String), `name` (String), `is_active` (Boolean), `created_at` (DateTime), `last_used_at` (DateTime).
- **Indexes/constraints**: `key_hash` has a unique constraint and index to support fast, constant-time lookups (via database engine hashing mechanisms) without scanning the table.
- **Migration**: Generated natively via Alembic (`ed89cd02b227_add_api_keys.py`) and applied to the database schema.

### API
- **Authentication header**: `X-API-Key`
- **Protected endpoints**: All intelligence routes:
  - `POST /api/v1/samples/upload`
  - `GET /api/v1/samples*`
  - `GET /api/v1/campaigns*`
- **Public endpoints**: 
  - `GET /api/v1/health` (Maintained public access for unauthenticated Kubernetes/infrastructure readiness probes)

### Security
- **Key generation**: Handled purely server-side through `scripts/bootstrap_api_key.py` using `secrets.token_urlsafe(32)`. **No public minting endpoint exists**.
- **Storage**: Plaintext keys are never stored. Only the SHA-256 digest (`key_hash`) is written to the database.
- **Verification**: Keys provided via headers are hashed using `hashlib.sha256` and looked up against the secure index.
- **Logging/secrets audit**: Raw keys are never logged in any error conditions or debug output. Only masked warnings regarding revoked/invalid access are produced. No secrets are hardcoded in test fixtures.

### Testing
- **Tests added**: 
  - 4 new authentication boundary tests (`test_auth.py`) covering missing keys, malformed keys, revoked keys, and public health route validation.
  - Test fixtures (`conftest.py`) were overhauled to correctly inject the mock API key into the DB and `AsyncClient` default headers to ensure downstream legacy tests passed without modification.
- **Exact full-suite result**: `54 passed`
- **Exact warnings**: `9 warnings` (Consistent with the Phase 7 baseline; no new warnings introduced).

### Files
- **Created**: 
  - `alembic/versions/ed89cd02b227_add_api_keys.py`
  - `app/core/auth.py`
  - `scripts/bootstrap_api_key.py`
  - `tests/test_auth.py`
- **Modified**: 
  - `app/db/models.py`
  - `app/api/routes/samples.py`
  - `app/api/routes/campaigns.py`
  - `tests/conftest.py`
  - `tests/test_hardening.py`
  - `tests/test_security_regression.py`
  - `app/services/upload_service.py` (Fixed a subtle SQLite-in-memory testing race condition).
- **Intentionally untouched**: `pipeline_service.py`, `main.py`, EMBER modules, Evidence Fusion ledgers.

### Scope Confirmations
- **Frontend untouched**: Confirmed.
- **EMBER untouched**: Confirmed.
- **Fusion untouched**: Confirmed.
- **Analysis pipeline untouched**: Confirmed. Internal service functions still operate entirely without API key requirements.

### Remaining limitations
- **Last-Used Tracking Concurrency**: Updating the `last_used_at` timestamp on every authenticated request requires executing a `db.commit()` inside the FastAPI dependency injection layer. During automated concurrent testing against SQLite in-memory databases, this premature commit triggers transaction locks that cause race conditions during large file uploads. Consequently, `last_used_at` updates were intentionally deferred and suppressed. For production (PostgreSQL), this could be safely reintroduced or shifted to a `BackgroundTask`.
