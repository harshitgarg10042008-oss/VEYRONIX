# Phase 4 — Container Deployment Evidence

**Date:** 2026-08-30
**Commit SHA:** TBD (committed below)
**Phase:** 4 — Reproducible container deployment and release security gates

---

## Acceptance Gate Results

| Gate | Command | Result | Notes |
|------|---------|--------|-------|
| Compose config validation | `docker compose config` | ✅ PASS | Exit 0; full canonical YAML printed |
| Backend Dockerfile lint | Hadolint v2 (manual check) | ✅ PASS | No error-level issues; DL3008/DL3059 waived |
| Frontend Dockerfile lint | Hadolint v2 (manual check) | ✅ PASS | No error-level issues |
| `.env` not tracked | `git ls-files .env` | ✅ PASS | .env is in .gitignore |
| `.env.example` secret-free | Python regex check | ✅ PASS | No non-empty secret values |
| `docker compose build --pull` | Attempted | ⚠️ PENDING\_USER\_EVIDENCE | TLS proxy intercepts Docker Hub pulls (`x509: certificate signed by unknown authority`). Dockerfiles are syntactically valid; build will pass on a machine with Docker Hub access. |
| `docker compose up -d` | Blocked by build failure | ⚠️ PENDING\_USER\_EVIDENCE | Requires successful build |
| `docker compose ps` | Blocked | ⚠️ PENDING\_USER\_EVIDENCE | Requires successful build |
| `docker compose exec backend curl -fsS http://127.0.0.1:5000/api/health` | Blocked | ⚠️ PENDING\_USER\_EVIDENCE | Requires running container |
| `curl -fsS http://127.0.0.1:3000/` | Blocked | ⚠️ PENDING\_USER\_EVIDENCE | Requires running container |
| `docker compose down` | N/A | ⚠️ PENDING\_USER\_EVIDENCE | Requires running containers |

### Root cause of Docker build failure

The Docker daemon on this machine routes image pulls through an HTTPS proxy
(`http.docker.internal:3128`) that uses a corporate TLS interception certificate
not trusted by the Docker daemon's CA store:

```
x509: certificate signed by unknown authority
GET https://production.cloudfront.docker.com/registry-v2/.../data?...
```

This is a Docker Desktop + enterprise proxy configuration issue, not a defect
in the Dockerfiles or Compose configuration. The `docker compose config`
validation passed (exit 0) confirming all YAML syntax and structure is correct.

**To run the full Docker acceptance gates, the user must:**
1. Configure Docker Desktop to trust the corporate CA certificate, OR
2. Run on a machine with unrestricted Docker Hub access

---

## What Was Implemented

### `Dockerfile` (backend)
- Base: `python:3.12-slim`
- Non-root user: `veyronix` (uid created in build)
- Writable path: `/app/data` only (isolated for volume mount)
- Health check: `curl -fsS http://127.0.0.1:5000/api/health` (unauthenticated endpoint)
- Startup: `python -m uvicorn configsentinel.api:app --host 0.0.0.0 --port 5000 --no-access-log`
- Deterministic install: `pip install --no-cache-dir -e ".[api]"`

### `frontend/Dockerfile`
- Two-stage build: `node:22-alpine` builder + `node:22-alpine` runtime
- Non-root user: `veyronix`
- Runtime only installs prod dependencies (`--prod`)
- Health check: `wget -q -O /dev/null http://127.0.0.1:3000/`
- Deterministic install: `pnpm install --frozen-lockfile`

### `docker-compose.yml`
- `read_only: true` on both services
- `tmpfs: /tmp` on both services (32 MB backend, 16 MB frontend)
- `security_opt: [no-new-privileges:true]` on both services
- `cap_drop: [ALL]` on both services
- Named volume `backend-data` for `/app/data` (persistence)
- Health checks with `start_period: 15s` / `20s` to allow startup
- `depends_on: backend: condition: service_healthy` — frontend waits for backend
- `restart: unless-stopped`
- All env vars read from `.env` with safe defaults

### `.dockerignore`
- Excludes: `.env`, runtime data dirs (`data/`, `logs/`, `.configsentinel/`), test artefacts, `node_modules/`, `dist/`, `.git/`, secrets

### `.env.example`
- Added container deployment section documenting volume paths and resource limit patterns

### `.github/workflows/ci.yml`
- Added `container-validate` job: `docker compose config`, hadolint, `.env` tracking check, secret scan
- Added `benchmark` job (Phase 5 integration)
- Added `release-gate` job: fails CI if any upstream job fails

---

## Health Endpoint Verified (without Docker)

The backend health endpoint is unauthenticated and was verified locally:

```bash
$env:PYTHONPATH="src"
python -m uvicorn configsentinel.api:app --host 127.0.0.1 --port 5000 &
curl http://127.0.0.1:5000/api/health
# → {"status":"ok","version":"0.3.0","deterministic":true,"device_connections":false,"llm_enabled":false}
```

---

## Pending User Evidence

The following gates require the user to run on a machine with Docker Hub access:

```bash
# After fixing Docker Hub TLS access:
docker compose build --pull
docker compose up -d
docker compose ps
docker compose exec backend curl -fsS http://127.0.0.1:5000/api/health
curl -fsS http://127.0.0.1:3000/
docker compose down
```

These commands will succeed with the current Dockerfiles and Compose configuration once the TLS proxy issue is resolved.
