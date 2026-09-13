# VEYRONIX Backup, Restore & Disaster Recovery Guide

This guide details the procedures for creating, verifying, encrypting, and restoring VEYRONIX database snapshots, audit ledgers, and compliance history.

---

## 1. Overview & Backup Architecture

The VEYRONIX persistent state comprises:
- **SQLite Database**: `/app/data/configsentinel.db` (and associated `-wal` / `-shm` files) containing shared audit records, project metadata, and user preferences.
- **Audit Ledger**: Cryptographic attestation logs and governance records.

The system includes automated backup creation, SHA-256 integrity verification, optional symmetric encryption (AES-256-GCM), and age monitoring via `GET /api/health` (`backup_age_hours`).

---

## 2. CLI Backup & Restore Commands

The VEYRONIX CLI provides native commands for snapshot lifecycle management:

### 2.1 Create a Backup
```bash
# Basic unencrypted snapshot
configsentinel backup-create --output /path/to/backup_latest.tar.gz

# Encrypted backup with passphrase (AES-256-GCM)
configsentinel backup-create \
  --output /path/to/backup_secure.enc \
  --password "$BACKUP_ENCRYPTION_KEY"
```

The backup routine:
1. Flushes SQLite WAL (Write-Ahead Log) into the primary database file.
2. Archives the database, schema, and attestation logs.
3. Calculates SHA-256 checksum and embeds manifest metadata.
4. If password is provided, encrypts the payload using AES-256-GCM with PBKDF2 key derivation.

### 2.2 Verify Backup Integrity
```bash
# Verify checksum and manifest without modifying database
configsentinel backup-verify --input /path/to/backup_latest.tar.gz
```

### 2.3 Restore from Backup
```bash
# Restore unencrypted backup
configsentinel backup-restore --input /path/to/backup_latest.tar.gz

# Restore encrypted backup
configsentinel backup-restore \
  --input /path/to/backup_secure.enc \
  --password "$BACKUP_ENCRYPTION_KEY"
```

---

## 3. Docker Named Volume Backup & Restore

In Docker Compose deployments, the persistent data resides in the `backend-data` volume.

### 3.1 Host-Level Volume Backup
To create a complete host-level snapshot while containers are running:
```bash
# Create host-level archive from backend-data volume
docker run --rm \
  -v veyronix_backend-data:/data:ro \
  -v $(pwd)/backups:/backup \
  alpine:latest tar czf /backup/veyronix_data_$(date +%Y%m%d_%H%M%S).tar.gz -C /data .
```

### 3.2 Host-Level Volume Restore
To restore data into a clean environment:
```bash
# 1. Stop the backend service
docker compose stop backend

# 2. Extract snapshot into the volume
docker run --rm \
  -v veyronix_backend-data:/data \
  -v $(pwd)/backups:/backup \
  alpine:latest sh -c "rm -rf /data/* && tar xzf /backup/veyronix_data_*.tar.gz -C /data"

# 3. Restart the backend service
docker compose start backend

# 4. Verify system health
curl -s http://localhost:3000/api/health | jq .
```

---

## 4. Health Monitoring & Freshness Alerting

The health diagnostics endpoint reports backup status:

```json
{
  "status": "ok",
  "version": "0.4.0",
  "storage": "healthy",
  "deterministic": true,
  "backup_age_hours": 1.4,
  "deployment_mode": "lan"
}
```

- **`backup_age_hours`**: Floating-point number representing hours elapsed since the last verified backup.
- **Alerting Threshold**: If `backup_age_hours > 24.0`, monitoring dashboards display a cautionary notice indicating an overdue backup.
