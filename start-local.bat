@echo off
setlocal

rem ConfigSentinel AI / VEYRONIX local launcher
rem Starts only local processes. No device connections or outbound submission are performed.

set "REPO=%~dp0"

if not exist "%REPO%.venv\Scripts\python.exe" (
  echo [ERROR] Python virtual environment not found: %REPO%.venv
  echo Create it first with: py -3.12 -m venv .venv
  pause
  exit /b 1
)

if not exist "%REPO%examples\api_server.py" (
  echo [ERROR] Backend entrypoint not found: %REPO%examples\api_server.py
  pause
  exit /b 1
)

if not exist "%REPO%frontend\package.json" (
  echo [ERROR] Frontend folder not found: %REPO%frontend
  pause
  exit /b 1
)

start "ConfigSentinel AI - Backend" powershell.exe -NoExit -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%REPO%'; $env:PYTHONPATH='src'; .\.venv\Scripts\python.exe .\examples\api_server.py"

timeout /t 3 /nobreak >nul

start "ConfigSentinel AI - Frontend" powershell.exe -NoExit -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%REPO%frontend'; $env:VITE_API_BASE_URL='http://127.0.0.1:8000'; pnpm dev"

timeout /t 5 /nobreak >nul
start "" "http://localhost:3000/"

endlocal
