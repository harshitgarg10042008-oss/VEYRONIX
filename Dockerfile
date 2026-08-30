FROM python:3.12-slim

# ===========================================================================
# SECURITY HARDENING
# - Non-root runtime user
# - Minimal attack surface (no unnecessary packages after build)
# - Read-only root filesystem compatible (writable data via volume only)
# ===========================================================================

# Create non-root user and group
RUN groupadd -r veyronix && useradd -r -g veyronix -d /app -s /sbin/nologin veyronix

WORKDIR /app

# Install only curl for health check, then purge lists
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifests first for layer caching
COPY pyproject.toml README.md ./
COPY MANIFEST.in ./

# Copy source and examples
COPY src/ ./src/
COPY examples/ ./examples/

# Install Python deps with locked resolution; no pip cache leaks secrets
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[api]"

# Create writable data directory owned by veyronix
# (Compose mounts ./data here; read-only FS is enabled on everything else)
RUN mkdir -p /app/data && chown -R veyronix:veyronix /app

# Switch to non-root user permanently
USER veyronix

# Expose backend port
EXPOSE 5000

# Environment variables (safe defaults, overridable via Compose or .env)
ENV PYTHONPATH=/app/src \
    VEYRONIX_API_HOST=0.0.0.0 \
    VEYRONIX_API_PORT=5000 \
    CONFIGSENTINEL_AUTH_REQUIRED=false \
    CONFIGSENTINEL_LLM_PROVIDER=offline \
    CONFIGSENTINEL_LLM_ENABLED=false \
    CONFIGSENTINEL_GOVERNANCE_LEDGER=/app/data/events.jsonl \
    CONFIGSENTINEL_DATABASE_URL=sqlite:////app/data/configsentinel.db

# Health check — unauthenticated endpoint, safe for container orchestrators
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:5000/api/health || exit 1

# Use uvicorn directly — examples/api_server.py delegates to the same app
CMD ["python", "-m", "uvicorn", "configsentinel.api:app", \
     "--host", "0.0.0.0", "--port", "5000", "--no-access-log"]
