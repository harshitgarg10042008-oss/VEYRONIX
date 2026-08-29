#!/usr/bin/env bash
# ============================================================
# VEYRONIX / ConfigSentinel AI  —  Linux/macOS launcher
# Usage: bash start.sh   (or chmod +x start.sh && ./start.sh)
# ============================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$REPO_DIR/.venv"
PYTHON="$VENV/bin/python"
LOG_DIR="$REPO_DIR/logs"
BACKEND_PORT=5000
FRONTEND_PORT=3000

mkdir -p "$LOG_DIR"

echo "============================================================"
echo " VEYRONIX / ConfigSentinel AI  —  Starting..."
echo "============================================================"
echo ""

# ── Create virtual environment if missing ──────────────────────
if [ ! -f "$PYTHON" ]; then
    echo "[SETUP] Creating Python virtual environment..."
    python3 -m venv "$VENV"
    echo "[SETUP] Virtual environment created."
fi

# ── Install backend dependencies from pyproject.toml ──────────
echo "[SETUP] Installing backend dependencies..."
"$PYTHON" -m pip install --upgrade pip -q
"$PYTHON" -m pip install -e "$REPO_DIR[api,dev]" -q
echo "[SETUP] Backend dependencies OK."

# ── Load .env if present ──────────────────────────────────────
if [ -f "$REPO_DIR/.env" ]; then
    echo "[ENV] Loading .env ..."
    set -a
    # shellcheck disable=SC1090
    source "$REPO_DIR/.env"
    set +a
fi

# ── Check port availability ───────────────────────────────────
check_port() {
    local port=$1
    if lsof -i ":$port" -sTCP:LISTEN -t > /dev/null 2>&1; then
        return 0  # port in use
    fi
    return 1  # port free
}

BACKEND_RUNNING=false
if check_port "$BACKEND_PORT"; then
    echo "[WARN] Port $BACKEND_PORT already in use — reusing existing backend."
    BACKEND_RUNNING=true
fi

# ── Start backend ─────────────────────────────────────────────
if [ "$BACKEND_RUNNING" = false ]; then
    echo "[START] Launching backend on http://127.0.0.1:$BACKEND_PORT ..."
    PYTHONPATH="$REPO_DIR/src" "$PYTHON" "$REPO_DIR/examples/api_server.py" \
        > "$LOG_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!
    echo "[LOG] Backend log: $LOG_DIR/backend.log  (PID $BACKEND_PID)"
fi

# ── Wait for backend health endpoint ─────────────────────────
echo "[WAIT] Waiting for backend health check (up to 30s)..."
HEALTH_OK=false
for i in $(seq 1 30); do
    if "$PYTHON" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$BACKEND_PORT/api/health', timeout=1)" > /dev/null 2>&1; then
        echo "[OK] Backend is healthy."
        HEALTH_OK=true
        break
    fi
    sleep 1
done

if [ "$HEALTH_OK" = false ]; then
    echo "[ERROR] Backend did not become healthy within 30 seconds."
    echo "        Check $LOG_DIR/backend.log for details."
    exit 1
fi

# ── Start frontend ────────────────────────────────────────────
if command -v pnpm &> /dev/null; then
    if [ ! -d "$REPO_DIR/frontend/node_modules/.pnpm" ]; then
        echo "[SETUP] Installing frontend dependencies..."
        (cd "$REPO_DIR/frontend" && pnpm install --frozen-lockfile)
    fi
    echo "[START] Launching frontend on http://localhost:$FRONTEND_PORT ..."
    (cd "$REPO_DIR/frontend" && pnpm dev) > "$LOG_DIR/frontend.log" 2>&1 &
    FRONTEND_PID=$!
    echo "[LOG] Frontend log: $LOG_DIR/frontend.log  (PID $FRONTEND_PID)"

    # Wait for frontend
    for i in $(seq 1 20); do
        if "$PYTHON" -c "import urllib.request; urllib.request.urlopen('http://localhost:$FRONTEND_PORT', timeout=1)" > /dev/null 2>&1; then
            echo "[OK] Frontend is ready."
            break
        fi
        sleep 1
    done
else
    echo "[WARN] pnpm not found. Frontend will not start."
    echo "       Install Node.js 20+ and run: corepack enable pnpm"
fi

# ── Open browser ─────────────────────────────────────────────
URL="http://localhost:$FRONTEND_PORT"
echo ""
echo "============================================================"
echo " VEYRONIX is running at: $URL"
echo " Backend API:            http://127.0.0.1:$BACKEND_PORT"
echo " Press Ctrl+C to stop."
echo "============================================================"
echo ""

if command -v xdg-open &> /dev/null; then
    xdg-open "$URL" &
elif command -v open &> /dev/null; then
    open "$URL"
fi

# Keep script alive so Ctrl+C stops children
wait
