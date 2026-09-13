# VEYRONIX Shared History & Server-Authoritative State

This document describes the server-authoritative audit history mechanism in VEYRONIX, ensuring multiple evaluation clients (Operator Browser, Judge Browser, Auditor Laptop) observe an identical, tamper-evident record of configuration audits.

---

## 1. Overview & Multi-Client Synchronization Flow

In an evaluation or team environment, client-only storage (such as browser `localStorage`) causes split-brain state: audits executed on Operator Laptop A are invisible to Judge PC B.

VEYRONIX resolves this with **Server-Authoritative State**:

```
+------------------+         POST /api/audit         +----------------------+
| Operator Laptop  | ------------------------------> |                      |
| (Browser A)      | <------------------------------ |                      |
|                  |       Deterministic Report      |                      |
+------------------+                                 |                      |
         |                                           |                      |
         | POST /api/audits                          |  VEYRONIX Backend    |
         | (Audit Record & Provenance)               |  (FastAPI + SQLite)  |
         v                                           |                      |
+------------------+                                 |  backend-data volume |
| Database Record  | ==============================> |  /app/data/          |
| (SQLite WAL)     |                                 |  configsentinel.db   |
+------------------+                                 |                      |
                                                     |                      |
+------------------+         GET /api/audits         |                      |
| Judge PC         | ------------------------------> |                      |
| (Browser B)      | <------------------------------ |                      |
|                  |     Authoritative History List  |                      |
+------------------+                                 +----------------------+
```

### End-to-End Workflow
1. **Audit Execution**: Operator runs an audit on Browser A. The engine produces the deterministic findings and score.
2. **Authoritative Persistence**: Browser A immediately sends `POST /api/audits` containing the full audit payload, summary metrics, input SHA-256 hash, and engine versions.
3. **Idempotent Storage**: The SQLite database inserts or updates the record based on `audit_id`. Duplicate runs with the same ID update timestamps and score cleanly without crashing.
4. **Instant Peer Visibility**: When Judge PC opens the dashboard or refreshes, `GET /api/audits` hydrates the exact shared audit history, displaying the identical compliance posture score, finding counts, and evidence.
5. **Reviewer Annotations**: Multiple actors can record review dispositions (`POST /api/audits/{id}/reviews`) on findings, creating a collaborative audit trail.

---

## 2. Database Schema

The database is housed at `/app/data/configsentinel.db` (or configured via `CONFIGSENTINEL_DATABASE_URL`).

### `shared_audits` Table

| Column | Type | Description |
| :--- | :--- | :--- |
| `audit_id` | `TEXT PRIMARY KEY` | Unique deterministic or UUID audit identifier |
| `project_id` | `TEXT` | Logical project partition (defaults to `"local"`) |
| `filename` | `TEXT` | Name of the audited configuration file |
| `input_sha256` | `TEXT` | Cryptographic SHA-256 digest of original input text |
| `vendor` | `TEXT` | Classified vendor (e.g., `cisco_ios`, `junos`, `fortigate`) |
| `format` | `TEXT` | Parser format classification |
| `parser_id` | `TEXT` | Specific parser implementation key |
| `parser_version` | `TEXT` | Semantic version of parser used |
| `control_pack_version` | `TEXT` | Version of rules/control pack evaluated |
| `score_state` | `TEXT` | `NO_AUDIT`, `AUDIT_PENDING`, `AUDIT_FAILED`, `SCORE_AVAILABLE` |
| `score` | `REAL` | Calculated compliance posture score (0.0 - 100.0) |
| `summary_json` | `TEXT` | Finding counts (pass, fail, unknown, warning) |
| `created_by` | `TEXT` | Actor ID or operator role initiating audit |
| `report_json` | `TEXT` | Complete serialized `AuditReport` data structure |
| `reviews_json` | `TEXT` | Array of human reviewer decisions and justifications |
| `created_at` | `TIMESTAMP` | ISO 8601 creation timestamp |
| `updated_at` | `TIMESTAMP` | ISO 8601 last-modified timestamp |

### `projects` Table

| Column | Type | Description |
| :--- | :--- | :--- |
| `project_id` | `TEXT PRIMARY KEY` | Project identifier slug |
| `name` | `TEXT` | Human-readable project title |
| `description` | `TEXT` | Optional workspace description |
| `created_at` | `TIMESTAMP` | Project creation timestamp |
| `updated_at` | `TIMESTAMP` | Project modification timestamp |

---

## 3. REST API Interface

### 1. List Shared Audits
- **Endpoint**: `GET /api/audits`
- **Query Parameters**:
  - `project_id` (optional): Filter by project
  - `limit` (default: 50, max: 100)
  - `offset` (default: 0)
- **Response**:
```json
{
  "total": 1,
  "audits": [
    {
      "audit_id": "audit-cisco-001",
      "project_id": "local",
      "filename": "edge_router.conf",
      "input_sha256": "4a7d...391e",
      "vendor": "cisco_ios",
      "score": 85.0,
      "score_state": "SCORE_AVAILABLE",
      "summary": { "finding_count": 7, "failed_count": 1 },
      "created_at": "2026-09-13T11:00:00Z"
    }
  ]
}
```

### 2. Save / Update Audit Record
- **Endpoint**: `POST /api/audits`
- **Behavior**: Idempotent insert or update.
- **Request Body**: `SharedAuditRecordPayload` (audit_id, filename, vendor, score, report_json, etc.)

### 3. Get Single Audit Details
- **Endpoint**: `GET /api/audits/{audit_id}`
- **Response**: Full record including `report_json`, `original_configuration_text`, and `reviews`.

### 4. Delete Audit
- **Endpoint**: `DELETE /api/audits/{audit_id}`
- **Response**: `{"status": "deleted", "audit_id": "..."}`

### 5. Clear History
- **Endpoint**: `DELETE /api/audits`
- **Response**: `{"status": "reset", "deleted_count": N}`

### 6. Record Review Decision
- **Endpoint**: `POST /api/audits/{audit_id}/reviews`
- **Request Body**:
```json
{
  "reviewer": "judge-officer",
  "finding_id": "f-cisco-ssh-01",
  "disposition": "EXCEPTION_APPROVED",
  "justification": "Out-of-band management interface approved under policy exception EX-2026."
}
```

---

## 4. Offline Fallback & Graceful Degradation

If the centralized backend server is temporarily unreachable:
- Browser clients do NOT crash or lock up.
- The UI status badge switches to **OFFLINE DRAFT MODE**.
- Audits can run using local client heuristics or cached definitions.
- Snapshots are cached in local browser storage and staged for synchronization once connectivity is restored.
