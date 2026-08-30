@echo off
setlocal EnableDelayedExpansion

:: ============================================================
:: VEYRONIX / ConfigSentinel AI  —  One-click Windows launcher
:: Double-click this file from Windows Explorer to start.
:: ============================================================
:: What this script does:
::   1. Resolves its own project directory (does NOT rely on cwd).
::   2. Creates .venv automatically if missing.
::   3. Installs Python dependencies from pyproject.toml via pip install -e .[api].
::   4. Detects / activates pnpm via Corepack; installs frontend deps if needed.
::   5. Loads .env if present (values are never echoed).
::   6. Checks that ports 5000 and 3000 are free; shows a clear message if not.
::   7. Starts backend (port 5000) and frontend (port 3000) in separate windows.
::   8. Waits for backend health endpoint to respond before opening the browser.
::   9. Opens http://localhost:3000 automatically.
::  10. Writes timestamped logs to logs\backend.log and logs\frontend.log.
::  11. Never prints .env values.
:: ============================================================

set "REPO=%~dp0"
:: Strip trailing backslash
if "%REPO:~-1%"=="\" set "REPO=%REPO:~0,-1%"

set "BACKEND_PORT=5000"
set "FRONTEND_PORT=3000"
set "VENV=%REPO%\.venv"
set "PYTHON=%VENV%\Scripts\python.exe"
set "PIP=%VENV%\Scripts\pip.exe"
set "LOG_DIR=%REPO%\logs"

:: ── Ensure log directory exists ──────────────────────────────
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║        VEYRONIX / ConfigSentinel AI  —  Starting...     ║
echo ╚══════════════════════════════════════════════════════════╝
echo.

:: ── Check for Python 3.11+ ───────────────────────────────────
where py >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python Launcher ^(py.exe^) not found.
    echo         Install Python 3.11+ from https://python.org and ensure
    echo         "Add python.exe to PATH" is checked during installation.
    pause
    exit /b 1
)
set "PY_LAUNCHER=py -3.11"

:: ── Create virtual environment if missing ────────────────────
if not exist "%PYTHON%" (
    echo [SETUP] Creating Python virtual environment in .venv ...
    %PY_LAUNCHER% -m venv "%VENV%"
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        echo         Make sure Python 3.11 or later is installed.
        pause
        exit /b 1
    )
    echo [SETUP] Virtual environment created.
)

:: ── Upgrade pip silently ─────────────────────────────────────
echo [SETUP] Checking pip ...
"%PYTHON%" -m pip install --upgrade pip --quiet

:: ── Install/verify backend dependencies from pyproject.toml ──
echo [SETUP] Installing backend dependencies (api + dev extras) ...
"%PYTHON%" -m pip install -e "%REPO%[api,dev]" --quiet
if errorlevel 1 (
    echo [ERROR] Backend dependency installation failed.
    echo         Check that pyproject.toml is valid and pip can reach PyPI.
    pause
    exit /b 1
)
echo [SETUP] Backend dependencies OK.

:: ── Verify frontend folder exists ────────────────────────────
if not exist "%REPO%\frontend\package.json" (
    echo [ERROR] Frontend not found: %REPO%\frontend\package.json
    pause
    exit /b 1
)

:: ── Enable pnpm via Corepack if available ────────────────────
where node >nul 2>&1
if errorlevel 1 (
    echo [WARN] Node.js not found. Frontend will not start.
    echo        Install Node.js 20+ from https://nodejs.org
    set "SKIP_FRONTEND=1"
) else (
    where pnpm >nul 2>&1
    if errorlevel 1 (
        echo [SETUP] pnpm not found — enabling via corepack ...
        corepack enable pnpm >nul 2>&1
        where pnpm >nul 2>&1
        if errorlevel 1 (
            echo [SETUP] corepack enable failed — trying npm install -g pnpm ...
            call npm install -g pnpm --silent
        )
    )
    :: Install frontend deps if node_modules is missing
    if not exist "%REPO%\frontend\node_modules\.pnpm" (
        echo [SETUP] Installing frontend dependencies ...
        cd /d "%REPO%\frontend"
        call pnpm install --frozen-lockfile
        if errorlevel 1 (
            echo [ERROR] Frontend dependency installation failed ^(pnpm install^).
            pause
            exit /b 1
        )
        echo [SETUP] Frontend dependencies OK.
        cd /d "%REPO%"
    )
)

:: ── Load .env silently (values are never echoed) ─────────────
if exist "%REPO%\.env" (
    echo [ENV] Loading .env ...
    for /f "usebackq tokens=1,* delims==" %%A in ("%REPO%\.env") do (
        set "line=%%A"
        if not "!line:~0,1!"=="#" (
            if not "%%A"=="" (
                set "%%A=%%B"
            )
        )
    )
)

:: ── Check port availability ──────────────────────────────────
netstat -ano | find ":%BACKEND_PORT% " | find "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [WARN] Port %BACKEND_PORT% is already in use ^(backend port^).
    echo        Another process may already be running the backend.
    echo        Either stop the other process, or the existing backend will be reused.
    set "BACKEND_RUNNING=1"
) else (
    set "BACKEND_RUNNING=0"
)

netstat -ano | find ":%FRONTEND_PORT% " | find "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [WARN] Port %FRONTEND_PORT% is already in use ^(frontend port^).
    echo        If the app is already running, just open http://localhost:%FRONTEND_PORT%
    set "FRONTEND_RUNNING=1"
) else (
    set "FRONTEND_RUNNING=1"
    set "FRONTEND_RUNNING=0"
)

:: ── Start backend ────────────────────────────────────────────
if "%BACKEND_RUNNING%"=="0" (
    echo [START] Launching backend on http://127.0.0.1:%BACKEND_PORT% ...
    set "PYTHONPATH=%REPO%\src"
    start "VEYRONIX-Backend" /min cmd /c ""%PYTHON%" "%REPO%\examples\api_server.py" > "%LOG_DIR%\backend.log" 2>&1"
    echo [LOG] Backend log: %LOG_DIR%\backend.log
) else (
    echo [INFO] Reusing existing backend process on port %BACKEND_PORT%.
)

:: ── Wait for backend health endpoint (up to 30s) ────────────
echo [WAIT] Waiting for backend health check (up to 30 seconds) ...
set "HEALTH_OK=0"
for /l %%i in (1,1,30) do (
    if "!HEALTH_OK!"=="0" (
        "%PYTHON%" -c "import urllib.request, sys; urllib.request.urlopen('http://127.0.0.1:%BACKEND_PORT%/api/health', timeout=1); sys.exit(0)" >nul 2>&1
        if not errorlevel 1 (
            set "HEALTH_OK=1"
            echo [OK] Backend is healthy.
        ) else (
            timeout /t 1 /nobreak >nul
        )
    )
)
if "!HEALTH_OK!"=="0" (
    echo [ERROR] Backend did not become healthy within 30 seconds.
    echo         Check %LOG_DIR%\backend.log for errors.
    echo         Common fixes:
    echo           - Run: %PYTHON% -m pip install -e .[api]
    echo           - Check that port %BACKEND_PORT% is not blocked by a firewall.
    pause
    exit /b 1
)

:: ── Start frontend ───────────────────────────────────────────
if not defined SKIP_FRONTEND (
    echo [START] Launching frontend on http://localhost:%FRONTEND_PORT% ...
    start "VEYRONIX-Frontend" /min cmd /c "cd /d "%REPO%\frontend" && pnpm dev > "%LOG_DIR%\frontend.log" 2>&1"
    echo [LOG] Frontend log: %LOG_DIR%\frontend.log

    echo [WAIT] Waiting for frontend to start (up to 20 seconds) ...
    for /l %%i in (1,1,20) do (
        "%PYTHON%" -c "import urllib.request, sys; urllib.request.urlopen('http://localhost:%FRONTEND_PORT%', timeout=1); sys.exit(0)" >nul 2>&1
        if not errorlevel 1 (
            echo [OK] Frontend is ready.
            goto :open_browser
        )
        timeout /t 1 /nobreak >nul
    )
    echo [WARN] Frontend did not respond in 20 seconds. Opening browser anyway.
)

:open_browser
echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║  VEYRONIX is running at: http://localhost:%FRONTEND_PORT%           ║
echo ║  Backend API:            http://127.0.0.1:%BACKEND_PORT%           ║
echo ║  Close this window to continue (processes run in background) ║
echo ╚══════════════════════════════════════════════════════════╝
echo.
start "" "http://localhost:%FRONTEND_PORT%"

endlocal
