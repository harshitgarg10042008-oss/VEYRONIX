# VEYRONIX LAN Deployment Guide

This document details the single-host Docker Compose deployment architecture for local area networks (LAN), multi-device access (Judge PC, Operator Laptop, Browser A/B), reverse proxy routing, and container hardening.

---

## 1. Network Architecture & Topology

```
                  +----------------------------------------------+
                  |                 LAN Network                  |
                  |     (e.g., 192.168.1.0/24 or Host Wi-Fi)     |
                  +----------------------------------------------+
                                  |                 |
                    Judge PC / Browser A      Operator Laptop / Browser B
                    http://192.168.1.100:3000 http://192.168.1.100:3000
                                  |                 |
                                  v                 v
            +----------------------------------------------------------+
            | HOST MACHINE (192.168.1.100)                             |
            |                                                          |
            |  +----------------------------------------------------+  |
            |  | Frontend Service (Express + Vite Static App)       |  |
            |  | - Port: 0.0.0.0:3000:3000                          |  |
            |  | - Role: Same-origin UI hosting & Reverse Proxy     |  |
            |  +----------------------------------------------------+  |
            |                         |                                |
            |      Internal Docker Network (configsentinel-net)        |
            |      http://backend:5000/api                             |
            |                         |                                |
            |                         v                                |
            |  +----------------------------------------------------+  |
            |  | Backend Service (FastAPI / Uvicorn)                |  |
            |  | - Port: 127.0.0.1:5000:5000 (Internal/Local only)  |  |
            |  | - Storage: Named volume backend-data:/app/data     |  |
            |  | - DB: SQLite WAL mode at /app/data/configsentinel.db| |
            |  +----------------------------------------------------+  |
            +----------------------------------------------------------+
```

### Security Boundary Principle
1. **Frontend Only on LAN**: The Express container binds `0.0.0.0:3000` to provide the unified web UI and `/api/*` reverse proxy.
2. **Backend Protected**: The FastAPI backend is NOT exposed to external LAN interfaces. It binds only to `127.0.0.1:5000` for optional local troubleshooting or communicates exclusively across the isolated Docker bridge network `configsentinel-net`.
3. **No Direct Backend Access from LAN**: All LAN browser clients communicate with the backend through the same-origin Express reverse proxy, eliminating CORS complexity and enforcing rate limiting and request timeouts.

---

## 2. Prerequisites & Quickstart

### Prerequisites
- Docker Engine 24.0+ and Docker Compose v2.20+
- Host machine connected to the evaluation LAN / Wi-Fi
- Port 3000 available on the host machine

### Quickstart Commands

```bash
# 1. Clone repository and navigate to root
cd VEYRONIX

# 2. Configure environment
cp .env.example .env

# 3. Start services in background
docker compose up -d --build

# 4. Verify containers are healthy
docker compose ps

# 5. Check health endpoint from host
curl -s http://localhost:3000/api/health | jq .
```

### Multi-Device Verification
To access the platform from another machine on the LAN:
1. Obtain host IP address:
   - Linux/macOS: `ip addr show` or `ifconfig`
   - Windows: `ipconfig` (look for IPv4 Address, e.g., `192.168.1.100`)
2. On any LAN client device (Judge PC, Auditor tablet, Operator laptop):
   - Open browser to `http://192.168.1.100:3000`
   - Verify health indicator displays **LOCAL API ONLINE** or **Shared server online**
   - Perform uploads, deterministic audits, or view shared compliance history.

---

## 3. Container Hardening & Security Controls

Both containers are configured with defense-in-depth Linux kernel and container runtime protections:

| Hardening Control | Configuration | Purpose |
| :--- | :--- | :--- |
| **Non-Root Execution** | `user: "10001:10001"` | Prevents container breakouts from inheriting host UID 0 |
| **Read-Only Root FS** | `read_only: true` | Prevents filesystem modification, persistence of malware, or binary replacement |
| **Drop Capabilities** | `cap_drop: [ALL]` | Removes all Linux capabilities (e.g. `CAP_NET_RAW`, `CAP_SYS_ADMIN`) |
| **No New Privileges** | `security_opt: [no-new-privileges:true]` | Blocks privilege escalation via setuid/setgid binaries |
| **Temporary FS** | `tmpfs: [/tmp:size=64M,mode=1777]` | Ephemeral writable temporary memory for scratch operations |
| **Persistent Data Volume** | `backend-data:/app/data` | Dedicated, isolated volume with strict permissions for SQLite storage |
| **Resource Limits** | `deploy.resources.limits` | Prevents denial-of-service via memory exhaustion or CPU starvation |

---

## 4. Troubleshooting & Diagnostics

### View Real-Time Logs
```bash
# Backend logs
docker compose logs -f backend

# Frontend reverse proxy logs
docker compose logs -f frontend
```

### Subsystem Health Checks
Query the extended diagnostics endpoint:
```bash
curl http://localhost:3000/api/health
```
Expected output:
```json
{
  "status": "ok",
  "version": "0.4.0",
  "storage": "healthy",
  "deterministic": true,
  "device_connections": false,
  "llm_enabled": false,
  "backup_age_hours": null,
  "auth_required": false,
  "deployment_mode": "lan"
}
```
