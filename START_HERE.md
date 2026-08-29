# START HERE — VEYRONIX / ConfigSentinel AI

> **Local-first, evidence-backed network compliance auditing.**
> No cloud account. No device connections. No autonomous changes.

---

## ⚡ One-Click Startup (Windows)

1. **Double-click `start-local.bat`** in Windows Explorer.
2. Two minimised terminal windows will appear (backend + frontend).
3. The browser opens automatically at **http://localhost:3000**.
4. The launcher exits; the child processes keep running.

> **What the launcher does automatically:**
> - Creates `.venv` if it does not exist.
> - Installs Python dependencies from `pyproject.toml` via `pip install -e .[api,dev]`.
> - Enables pnpm and installs frontend `node_modules` if needed.
> - Waits for the backend health endpoint before opening the browser.
> - Writes logs to `logs/backend.log` and `logs/frontend.log`.
> - Loads `.env` silently (no values are printed).

---

## 🐧 One-Click Startup (Linux / macOS)

```bash
chmod +x start.sh
./start.sh
```

---

## 🛠 Manual Setup (if the launcher fails)

### Prerequisites

| Tool | Minimum version | Download |
|---|---|---|
| Python | 3.11 | https://python.org |
| Node.js | 20 | https://nodejs.org |
| pnpm | 10 | `corepack enable pnpm` |

### Step 1 — Python virtual environment

```powershell
# Windows PowerShell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[api,dev]"
```

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[api,dev]"
```

> **No `requirements.txt` needed.** The authoritative dependency source is `pyproject.toml`.  
> A `requirements.txt` is also provided for tooling compatibility, but always install via `pip install -e .`.

### Step 2 — Frontend dependencies

```powershell
cd frontend
pnpm install --frozen-lockfile
cd ..
```

### Step 3 — Environment configuration

```powershell
# Copy the example and edit if needed
copy .env.example .env
```

For local development, the defaults in `.env.example` are sufficient.  
**No external API keys are required.** The deterministic engine works fully offline.

### Step 4 — Start backend (Terminal 1)

```powershell
# Windows
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe examples\api_server.py
```

```bash
# Linux / macOS
PYTHONPATH=src .venv/bin/python examples/api_server.py
```

Backend listens on **http://127.0.0.1:5000**.

### Step 5 — Start frontend (Terminal 2)

```powershell
cd frontend
pnpm dev
```

Frontend serves on **http://localhost:3000**.  
The Vite dev server proxies `/api/*` to `http://127.0.0.1:5000` automatically.

### Step 6 — Open browser

Navigate to **http://localhost:3000**

---

## 🏥 Health Check

```powershell
# Should return: {"status":"ok","version":"...","deterministic":true}
Invoke-RestMethod http://127.0.0.1:5000/api/health
```

---

## 📋 Run Tests

```powershell
# Backend tests (217 deterministic tests)
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m pytest

# Compile-check all Python source
.\.venv\Scripts\python.exe -m compileall -q src tests examples

# Frontend type check
cd frontend ; pnpm check

# Frontend build
cd frontend ; pnpm build

# E2E tests (Playwright — requires both backend and frontend)
cd frontend ; pnpm test:e2e
```

---

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "Python Launcher not found" | `py.exe` not on PATH | Install Python 3.11+ and tick "Add to PATH" |
| "Failed to create virtual environment" | Python 3.11 not installed | `py -3.11 -m venv .venv` |
| "Backend did not become healthy" | Port 5000 blocked or install failed | Check `logs\backend.log` |
| "pnpm not found" | Node.js or pnpm missing | `corepack enable pnpm` or install Node 20+ |
| "Module not found: uvicorn" | Virtual environment not activated | Run: `.\.venv\Scripts\python.exe -m pip install -e .[api]` |
| "Port 5000 in use" | Stale process from a previous run | `netstat -ano \| findstr :5000` then kill the PID |
| "Port 3000 in use" | Another dev server running | Stop the other server, or change `FRONTEND_PORT` in `start-local.bat` |
| Browser shows blank page | Frontend not ready yet | Wait 5–10 s and refresh |
| API calls return 401 | `CONFIGSENTINEL_AUTH_REQUIRED=true` set | Set `CONFIGSENTINEL_API_TOKEN` in `.env` or disable auth |

### Log files

| File | Contents |
|---|---|
| `logs\backend.log` | FastAPI / Uvicorn startup and request logs |
| `logs\frontend.log` | Vite dev server output |

---

## 🔒 Security Notes

- `.env` is in `.gitignore` and will never be committed.
- API keys and tokens are never printed to logs or terminal.
- The backend only listens on `127.0.0.1` (localhost) by default.
- All API routes are CORS-restricted to `localhost` origins.
- No device connections are made at any point.
- No AI verdict overrides — the deterministic engine is always authoritative.

---

## 📖 Further Reading

| Document | Purpose |
|---|---|
| [`docs/SIH_EVIDENCE.md`](docs/SIH_EVIDENCE.md) | Project defensibility and SIH impact evidence |
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Operator walkthrough |
| [`docs/API_KEYS_AND_ENVIRONMENT.md`](docs/API_KEYS_AND_ENVIRONMENT.md) | Environment variable reference |
| [`README.md`](README.md) | Full project documentation |
| [`.env.example`](.env.example) | All available configuration variables |
