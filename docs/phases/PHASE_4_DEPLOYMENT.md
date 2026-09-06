# Phase 4 Deployment Guide — ConfigSentinel AI

**Reproducible Container Deployment and Release Security Gates**

This document covers local production-like container deployment, persistence,
health checks, logging, shutdown, secret handling, and security limitations.

---

## Quick Start

```bash
# 1. Copy environment template (edit as needed — never commit .env)
cp .env.example .env

# 2. Build images (--pull ensures fresh base layers)
docker compose build --pull

# 3. Start services in background
docker compose up -d

# 4. Verify both services are healthy
docker compose ps

# 5. Check backend health directly
curl -fsS http://localhost:5000/api/health

# 6. Open the UI
open http://localhost:3000      # macOS
start http://localhost:3000     # Windows
```

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Docker Compose (local network)                 │
│                                                 │
│  ┌──────────────────┐    ┌──────────────────┐   │
│  │  frontend :3000  │───▶│  backend :5000   │   │
│  │  (Vite preview)  │    │  (Uvicorn+FastAPI)│   │
│  │  read-only FS    │    │  read-only FS    │   │
│  │  tmpfs /tmp      │    │  tmpfs /tmp      │   │
│  │  user: veyronix  │    │  user: veyronix  │   │
│  └──────────────────┘    └────────┬─────────┘   │
│                                   │              │
│                          ┌────────▼─────────┐   │
│                          │  backend-data    │   │
│                          │  (named volume)  │   │
│                          │  events.jsonl    │   │
│                          │  configsentinel.db│  │
│                          └──────────────────┘   │
└─────────────────────────────────────────────────┘
```

---

## Security Hardening Applied

| Control | Backend | Frontend |
|---------|---------|----------|
| Non-root user (`veyronix`) | ✅ | ✅ |
| Read-only root filesystem | ✅ | ✅ |
| `tmpfs` for `/tmp` only | ✅ (32 MB) | ✅ (16 MB) |
| `no-new-privileges` | ✅ | ✅ |
| All Linux capabilities dropped | ✅ | ✅ |
| Deterministic lockfile install | ✅ | ✅ |
| No secrets baked into image | ✅ | ✅ |
| Health check present | ✅ | ✅ |
| Data volume isolated | ✅ (`/app/data`) | N/A |

### What `read_only: true` means

The container root filesystem is mounted read-only. Only `/tmp` (via `tmpfs`)
and `/app/data` (via named volume, backend only) are writable. This prevents
malicious code from persisting files to arbitrary locations inside the
container image layer.

---

## Persistence

Backend application state lives in the named Docker volume `backend-data`,
mounted at `/app/data` inside the container:

| File | Purpose |
|------|---------|
| `/app/data/events.jsonl` | Governance approval ledger (append-only JSONL) |
| `/app/data/configsentinel.db` | SQLite audit history and website scan storage |

**Volume lifecycle:**

```bash
# List volumes
docker volume ls

# Inspect volume location on host
docker volume inspect configsentinel_backend-data

# Backup volume data to local tarball
docker run --rm -v configsentinel_backend-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/backend-data-backup.tar.gz /data

# Remove volume (DESTROYS ALL STORED DATA)
docker compose down -v
```

> [!CAUTION]
> `docker compose down -v` removes the named volume and **all persistent data**.
> Always backup before running this command.

---

## Health Checks

### Backend

The backend exposes an **unauthenticated** health endpoint:

```bash
curl -fsS http://localhost:5000/api/health
# → {"status":"ok","version":"0.3.0","deterministic":true,...}
```

Docker Compose uses this internally:
```yaml
healthcheck:
  test: ["CMD", "curl", "-fsS", "http://127.0.0.1:5000/api/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 15s
```

The frontend (`depends_on: backend: condition: service_healthy`) will not start
until the backend reports healthy.

### Frontend

```bash
curl -fsS http://localhost:3000/
```

---

## Logs

```bash
# Stream all service logs
docker compose logs -f

# Backend logs only
docker compose logs -f backend

# Frontend logs only
docker compose logs -f frontend

# Last 100 lines
docker compose logs --tail=100 backend
```

---

## Shutdown

```bash
# Stop and remove containers (KEEPS volume data)
docker compose down

# Stop, remove containers AND volumes (DESTROYS data)
docker compose down -v

# Stop without removing containers
docker compose stop
```

---

## Secret Handling

| Rule | Detail |
|------|--------|
| `.env` is never committed | It is listed in `.gitignore` and `.dockerignore` |
| `CONFIGSENTINEL_API_TOKEN` | Set in `.env` for token-protected API mode |
| `OPENAI_API_KEY` | Only needed if using an external LLM provider |
| `CONFIGSENTINEL_BACKUP_PASSPHRASE` | Only needed if using encrypted backup |
| Container images | Built from source; no credentials in layers |
| CI environment | Secrets passed via GitHub Actions secrets, not in workflow files |

> [!WARNING]
> Never set `CONFIGSENTINEL_WEB_SCAN_ALLOW_PRIVATE_TARGETS=true` in production.
> This default blocks SSRF to internal networks.

---

## Container Acceptance Gates (Phase 4)

The following commands were run and their results recorded:

```bash
# Static Compose configuration validation
docker compose config

# Build both images
docker compose build --pull

# Start services
docker compose up -d

# Check service states
docker compose ps

# Verify backend health from inside container
docker compose exec backend curl -fsS http://127.0.0.1:5000/api/health

# Verify frontend from host
curl -fsS http://127.0.0.1:3000/

# Shutdown
docker compose down
```

> [!NOTE]
> Actual execution results are recorded in `docs/PHASE_4_EVIDENCE.md`.
> If Docker was unavailable during CI, those gates are marked `PENDING_USER_EVIDENCE`.

---

## CI Static Checks for Container Configuration

The CI workflow (`.github/workflows/ci.yml`) runs:

1. `docker compose config` — validates YAML syntax and interpolation
2. Dockerfile linting via `hadolint` (if available)
3. Secret scan to verify `.env` is not staged for commit

These checks run without needing Docker daemon access, making them compatible
with GitHub-hosted runners that have Docker installed.

---

## Limitations

1. **No TLS termination**: The Compose setup does not include a TLS proxy.
   For production, add nginx/Caddy in front with valid certificates.
2. **SQLite is single-process**: The SQLite database is not suitable for
   multi-process or multi-node deployments. Use PostgreSQL for production scale.
3. **Session store is in-memory**: The mock session dictionary in `api.py` is
   not persisted across backend restarts. Use a Redis-backed session store for
   production.
4. **No secret rotation**: API tokens and backup passphrases are static.
   Implement secret rotation for long-lived deployments.
5. **Docker Desktop required on Windows/macOS**: The `read_only: true` and
   `cap_drop` settings require a Linux container engine. Docker Desktop
   provides this on non-Linux platforms.
6. **Playwright tests**: E2E tests run against the Vite dev server, not the
   container stack, to avoid CI complexity. Container-based E2E testing is a
   future enhancement.
