# ConfigSentinel AI — Deployment Guide

## Overview

ConfigSentinel AI runs as a containerized application with hardened security settings. This guide covers local deployment, persistence, health checks, logging, shutdown, and secret handling.

## Prerequisites

- Docker 20.10+ or Docker Compose 2.0+
- 2GB available RAM minimum
- Network access to pull base images (python:3.12-slim, node:22-alpine)

## Quick Start

```bash
# Copy environment template and configure
cp .env.example .env
# Edit .env with your settings (see Environment Variables below)

# Build and start services
docker compose build --pull
docker compose up -d

# Verify health
docker compose ps
curl -fsS http://localhost:5000/api/health
curl -fsS http://localhost:3000/

# View logs
docker compose logs -f
```

## Environment Variables

### Backend (configsentinel-backend)

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIGSENTINEL_AUTH_REQUIRED` | `false` | Require API token authentication |
| `CONFIGSENTINEL_API_TOKEN` | (empty) | API token for authenticated mode |
| `CONFIGSENTINEL_RATE_LIMIT_PER_MINUTE` | `120` | API rate limit per minute |
| `CONFIGSENTINEL_LLM_PROVIDER` | `offline` | LLM provider (offline, openai, anthropic) |
| `CONFIGSENTINEL_LLM_ENABLED` | `false` | Enable AI explanation features |
| `CONFIGSENTINEL_GOVERNANCE_LEDGER` | `/app/data/events.jsonl` | Path to governance ledger |
| `CONFIGSENTINEL_DATABASE_URL` | `sqlite:////app/data/configsentinel.db` | SQLite database path |
| `CONFIGSENTINEL_WEB_SCAN_ENABLED` | `true` | Enable website security scanner |
| `CONFIGSENTINEL_WEB_SCAN_TIMEOUT_SECONDS` | `15` | Website scan timeout |
| `CONFIGSENTINEL_WEB_SCAN_MAX_RESPONSE_BYTES` | `2000000` | Max response size for scans |
| `CONFIGSENTINEL_WEB_SCAN_ALLOW_PRIVATE_TARGETS` | `false` | Allow scanning private IP ranges |

### Frontend (configsentinel-frontend)

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `3000` | HTTP port |
| `NODE_ENV` | `production` | Node environment |
| `VITE_API_URL` | `http://backend:5000` | Backend API URL (internal) |

## Persistence

Application state is stored in the `backend-data` Docker volume:

- **Governance ledger**: `/app/data/events.jsonl` — append-only audit trail of approvals and decisions
- **SQLite database**: `/app/data/configsentinel.db` — website scan results and cached data
- **Backups**: `/app/data/backups/` — encrypted backup archives (if backup feature enabled)

The volume survives container restarts. To persist data across host reboots, ensure Docker volumes are configured appropriately.

## Health Checks

### Backend Health Endpoint

```
GET /api/health
```

Returns unauthenticated health status:

```json
{
  "status": "ok",
  "scanner_enabled": true,
  "version": "1.0.0"
}
```

Container health check runs every 30 seconds with 3 retries.

### Frontend Health Check

Frontend health is verified by checking HTTP 200 on `/` via `wget`.

Container health check runs every 30 seconds with 3 retries after a 20-second start period.

## Logging

Logs are output to stdout/stderr and captured by Docker:

```bash
# View all logs
docker compose logs

# Follow logs in real-time
docker compose logs -f

# View specific service logs
docker compose logs backend
docker compose logs frontend
```

For production deployments, configure a log driver (e.g., syslog, journald, or cloud logging) in docker-compose.yml.

## Shutdown

```bash
# Stop services gracefully
docker compose down

# Stop and remove volumes (WARNING: deletes all data)
docker compose down -v
```

## Security Hardening

Both containers use the following security measures:

- **Non-root runtime user**: `veyronix` user with minimal privileges
- **Read-only root filesystem**: Only `/tmp` (tmpfs) and `/app/data` (volume) are writable
- **No new privileges**: `no-new-privileges:true` seccomp constraint
- **Dropped capabilities**: All Linux capabilities dropped
- **Minimal base images**: `python:3.12-slim` and `node:22-alpine`
- **No secrets in images**: `.env` and `.env.*` excluded via `.dockerignore`

## Limitations

- **Single-host deployment**: Current configuration is for single-host deployment. Multi-host orchestration requires additional networking and secret management.
- **SQLite database**: Not suitable for high-concurrency multi-user deployments. PostgreSQL or MySQL recommended for production.
- **File-based governance ledger**: For production, consider a proper audit log system with tamper-evident storage.
- **No TLS termination**: TLS should be terminated at a reverse proxy (nginx, Traefik, Caddy) in production.
- **No built-in backup automation**: Backups must be triggered manually or via external cron jobs.

## Troubleshooting

### Container fails to start

```bash
# Check logs
docker compose logs backend
docker compose logs frontend

# Verify volume permissions
docker compose exec backend ls -la /app/data
```

### Health check failing

```bash
# Test health endpoint from inside container
docker compose exec backend curl -f http://127.0.0.1:5000/api/health
docker compose exec frontend wget -q -O /dev/null http://127.0.0.1:3000/
```

### Data persistence issues

```bash
# Inspect volume
docker volume inspect sih_backend-data

# Backup volume
docker run --rm -v sih_backend-data:/data -v $(pwd):/backup alpine tar czf /backup/backend-data-backup.tar.gz /data
```

## Production Considerations

For production deployments, consider:

1. **Reverse proxy**: Add nginx/traefik for TLS termination and request routing
2. **Secret management**: Use Docker secrets or external vault service for API tokens
3. **Database**: Migrate to PostgreSQL or MySQL for better concurrency
4. **Monitoring**: Add Prometheus metrics and alerting
5. **Backup automation**: Implement automated backup schedules with retention policies
6. **High availability**: Use container orchestration (Kubernetes, Swarm) with health checks and auto-restart
7. **Rate limiting**: Configure stricter rate limits for public deployments
8. **Audit logging**: Forward governance ledger to external SIEM or log aggregation system
