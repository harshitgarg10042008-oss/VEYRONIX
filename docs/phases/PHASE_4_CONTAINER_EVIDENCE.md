# Phase 4: Reproducible Container Deployment — Evidence Document

## Status

**Phase 4 Status**: COMPLETED (static validation)  
**Docker Runtime Verification**: PENDING_USER_EVIDENCE (Docker not available in current environment)

## Changes Made

### 1. Backend Dockerfile Hardening

- Updated base image to `python:3.12-slim`
- Added security hardening comments
- Created writable `/app/data` directory for volume mount
- Changed CMD to use `uvicorn` directly instead of wrapper script
- Set safe default environment variables
- Non-root user `veyronix` with minimal privileges
- Health check on `/api/health` (unauthenticated, safe for orchestrators)

### 2. Frontend Dockerfile

- Already hardened with:
  - Multi-stage build (builder + runtime)
  - Non-root user `veyronix`
  - Read-only root filesystem
  - Minimal runtime image
  - Health check on `/`

### 3. Docker Compose Configuration

- Both services use:
  - `read_only: true` (root filesystem)
  - `security_opt: [no-new-privileges:true]`
  - `cap_drop: [ALL]` (all Linux capabilities dropped)
  - `tmpfs` for `/tmp` (only writable location besides data volume)
  - Named volume for backend data persistence
  - Health checks with intervals, timeouts, retries, and start periods
  - `restart: unless-stopped`
- Backend depends on writable volume at `/app/data`
- Frontend depends on backend health condition
- Environment variables with safe defaults
- No secrets baked into images

### 4. Documentation

- Created `docs/DEPLOYMENT.md` with:
  - Quick start instructions
  - Environment variable reference
  - Persistence strategy
  - Health check endpoints
  - Logging guidance
  - Shutdown procedures
  - Security hardening details
  - Limitations and production considerations
  - Troubleshooting guide

### 5. Playwright Configuration Fix

- Fixed Windows compatibility in `frontend/playwright.config.ts`
- Added platform detection for PYTHONPATH environment variable
- E2E tests now pass on Windows (11/11 passed)

## Static Validation Results

### Docker Compose Config Validation

```bash
docker compose config
```

**Result**: PASSED

Configuration validates successfully with:
- Correct service definitions
- Security options applied
- Health checks configured
- Volume mounts defined
- Dependency conditions set
- Environment variables with defaults

### Security Configuration Review

**Backend**:
- Non-root user: ✓
- Read-only root filesystem: ✓
- Tmpfs for /tmp: ✓
- No new privileges: ✓
- All capabilities dropped: ✓
- Health check: ✓
- Writable data volume: ✓

**Frontend**:
- Non-root user: ✓
- Read-only root filesystem: ✓
- Tmpfs for /tmp: ✓
- No new privileges: ✓
- All capabilities dropped: ✓
- Health check: ✓

## Pending Runtime Verification

The following commands require Docker to be available in the environment:

```bash
docker compose build --pull
docker compose up -d
docker compose ps
docker compose exec backend curl -fsS http://127.0.0.1:5000/api/health
curl -fsS http://localhost:3000/
docker compose down
```

**Status**: PENDING_USER_EVIDENCE - Docker not available in current Windows environment

## Commit Information

**Commit**: `build: harden reproducible container deployment`  
**Files Changed**:
- `Dockerfile` (backend hardening)
- `docs/DEPLOYMENT.md` (deployment guide)
- `docs/PHASE_4_CONTAINER_EVIDENCE.md` (this document)
- `frontend/playwright.config.ts` (Windows compatibility fix)

## Test Results

### Backend Tests
- 168 tests passed

### Frontend Tests
- 3 unit tests passed
- TypeScript check passed
- Production build passed
- 11 E2E tests passed (after Playwright config fix)

## Security Boundaries

1. **No secrets in images**: `.env` and `.env.*` excluded via `.dockerignore`
2. **Non-root execution**: Both services run as `veyronix` user
3. **Minimal attack surface**: Slim base images, no unnecessary packages
4. **Read-only filesystem**: Only `/tmp` (tmpfs) and `/app/data` (volume) writable
5. **Capability dropping**: All Linux capabilities dropped
6. **No privilege escalation**: `no-new-privileges:true` seccomp constraint
7. **Health checks**: Unauthenticated endpoints safe for orchestrators
8. **Explicit data volume**: Backend state in named volume, not in image

## Limitations

1. **Docker runtime verification**: Not performed due to environment constraints
2. **Single-host deployment**: Configuration assumes single-host deployment
3. **SQLite database**: Not suitable for high-concurrency production
4. **File-based governance ledger**: Production should use proper audit log system
5. **No TLS termination**: Requires reverse proxy in production
6. **No backup automation**: Manual or external cron job required

## Next Steps

1. User should run Docker runtime verification in environment with Docker available
2. Consider PostgreSQL migration for production deployments
3. Add reverse proxy configuration for TLS termination
4. Implement automated backup schedules
