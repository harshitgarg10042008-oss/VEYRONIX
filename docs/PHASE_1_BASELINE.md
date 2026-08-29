# Phase 1: Baseline, Architecture, and Scorecard

**Status:** In Progress  
**Objective:** Inspect codebase, create dependency/feature map, identify gaps, establish clean baseline

## Repository Structure

### Backend (Python SDK)
- **Package:** `configsentinel-sdk` v0.3.0
- **Python:** 3.11+
- **Dependencies:** Zero runtime dependencies (optional: fastapi, cryptography)
- **Entry Points:** 
  - SDK: `configsentinel.client.ConfigSentinelClient`
  - CLI: `configsentinel` command
  - API: `examples/api_server.py` (FastAPI adapter)

### Frontend (React/Vite)
- **Framework:** React 19.2.1, TypeScript 5.6.3, Vite 7.1.7
- **UI Library:** Radix UI components, Tailwind CSS 4.1.14
- **State Management:** React hooks, wouter for routing
- **Build:** Vite + esbuild for server bundle

### Test Coverage
- **Backend:** 52 test files covering:
  - API endpoints
  - Parser behavior (Cisco IOS, Junos, Arista EOS, Linux nftables, generic firewall)
  - Compliance engine
  - Security (redaction, ingestion limits)
  - Remediation generation
  - Vendor detection
  - Governance/approvals
  - LLM integration (offline and provider)
  - Baseline/drift detection
  - GitOps gate
  - Evidence graph
  - Analytics
  - Backup/restore
  - And more...

- **Frontend:** 0 automated tests (manual testing only)

## Dependency Matrix

### Python Runtime Dependencies
```
None (zero runtime dependencies for core SDK)
```

### Python Optional Dependencies
```
dev: pytest>=8
api: fastapi>=0.115, uvicorn[standard]>=0.30
backup: cryptography>=42.0
```

### Frontend Dependencies
```
Core: react, react-dom, wouter (routing)
UI: @radix-ui/* (component library), tailwindcss, lucide-react (icons)
Forms: react-hook-form, zod (validation)
Charts: recharts
PDF: jspdf
HTTP: axios
Build: vite, esbuild, typescript
Testing: vitest
```

## Feature Map

### Implemented Features ✅

#### Core Deterministic Engine
- Configuration parsing (Cisco IOS, Junos, Arista EOS, Linux nftables, generic firewall)
- Control evaluation (7 built-in controls: SSH, Telnet, AAA, logging, NTP, SNMP, HTTP)
- Evidence extraction with source line references
- Input SHA-256 hashing
- Secret redaction
- Severity-aware findings (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Status classification (PASS, FAIL, UNKNOWN, NOT_APPLICABLE, REVIEW_REQUIRED)

#### API Surface
- `/api/health` - Health check
- `/api/audit` - Submit configuration for audit
- `/api/v1/audit` - Versioned audit endpoint
- `/api/detect` - Vendor detection with confidence
- `/api/v1/health` - Versioned health endpoint
- `/api/control-pack` - Retrieve control registry
- `/openapi.json` - OpenAPI specification

#### CLI Commands
- `configsentinel audit` - Single configuration audit
- `configsentinel batch` - Multi-file/directory/archive audit
- `configsentinel baseline-save` - Save approved baseline
- `configsentinel drift-check` - Check for configuration drift
- `configsentinel gitops-check` - Git repository change gate
- `configsentinel approval-request` - Request remediation approval
- `configsentinel approval-decide` - Approve/reject remediation
- `configsentinel sensitive-scan` - Scan for sensitive data
- `configsentinel ticket-export` - Export to ticketing formats
- `configsentinel inventory-import` - Import topology inventory
- `configsentinel topology-analyze` - Analyze topology
- `configsentinel cache-audit` - Content-addressed audit cache
- `configsentinel siem-export` - Export to SIEM formats
- `configsentinel backup-create/restore` - Encrypted backup
- `configsentinel release-artifacts` - SBOM and release metadata
- Plus many more...

#### Frontend Dashboard
- Overview page with posture metrics
- Audits page with findings table and evidence panel
- Review queue for UNKNOWN/REVIEW_REQUIRED findings
- Control packs page (currently hardcoded)
- Remediation page with preview
- Settings page (theme, API connection)
- Operator guide
- Local audit history (localStorage, max 20 entries)
- PDF export
- Configuration upload with validation
- Vendor detection integration
- Filtering by severity, status, framework

#### Safety Features
- Non-executable remediation previews
- Explicit UNKNOWN semantics (not treated as PASS)
- Source-line evidence preservation
- Input hashing for provenance
- Secret redaction before AI/external processing
- Bounded input/output sizes
- No live device connections
- Review-only governance model

#### AI Integration
- Offline explanation provider (no network)
- OpenAI-compatible provider support (opt-in)
- Schema-validated output
- Bounded input/output
- Provider failure handling
- AI never changes deterministic verdicts

### Partially Implemented Features ⚠️

#### Frontend Integration
- Control packs page exists but uses hardcoded data instead of `/api/control-pack`
- Remediation page shows findings but no structured diff download
- Approval workflow exists in CLI but not connected to UI
- AI explanation exists in backend but not exposed in dashboard
- Several actions show toast messages instead of real workflows

#### Security
- Optional bearer token protection (`CONFIGSENTINEL_API_TOKEN`)
- No rate limiting in deployed API
- No authentication/authorization for multi-user
- No tenant/workspace isolation
- No TLS termination guidance
- No structured audit logging

### Missing Features ❌

#### Authentication & Authorization
- No real user authentication (login, sessions, identity)
- No role-based access control (RBAC)
- No tenant/workspace isolation
- No resource ownership checks
- No audit events tied to authenticated identities

#### Durable Storage
- No database persistence
- No migrations
- No retention policies
- No backup/restore for production data
- Browser-only history (localStorage)

#### Frontend Testing
- No unit tests for React components
- No E2E browser tests
- No accessibility tests
- No coverage thresholds

#### Security Gates
- No dependency vulnerability scanning in CI
- No secret scanning
- No SAST/DAST
- No container security checks

#### Production Operations
- No metrics/observability
- No correlation IDs
- No health/readiness endpoints for orchestration
- No graceful degradation
- No rate limiting
- No request size limits (beyond basic validation)

#### Control Expansion
- Only 7 built-in controls
- No accuracy measurements
- No fixture matrix with expected outcomes
- No false-positive/false-negative analysis
- No unsupported syntax rate reporting

#### Impact Evidence
- No measured throughput
- No fleet-scale ingestion
- No user studies
- No operational time saved metrics
- No integration proof with real organizations

## Environment Variable Matrix

### Required for Core Local Mode
| Variable | Secret? | Required? | Purpose | Default |
|---|---|---:|---|---|
| `PYTHONPATH` | No | Yes (for dev) | Import package before install | `src` |
| `VITE_API_BASE_URL` | No | Yes (for frontend) | Frontend API URL | `http://127.0.0.1:8000` |

### Optional Security
| Variable | Secret? | Required? | Purpose | Default |
|---|---|---:|---|---|
| `CONFIGSENTINEL_API_TOKEN` | **Yes** | No | Bearer token for API protection | None |
| `CONFIGSENTINEL_AUTH_REQUIRED` | No | No | Make bearer token mandatory | `false` |
| `CONFIGSENTINEL_RATE_LIMIT_PER_MINUTE` | No | No | Per-client rate limit | `120` |

### Optional AI
| Variable | Secret? | Required? | Purpose | Default |
|---|---|---:|---|---|
| `CONFIGSENTINEL_LLM_ENABLED` | No | No | Enable AI copilot | `false` |
| `CONFIGSENTINEL_LLM_ENDPOINT` | No | If AI enabled | OpenAI-compatible endpoint | None |
| `OPENAI_API_KEY` | **Yes** | If AI enabled | Provider authentication | None |
| `CONFIGSENTINEL_LLM_MODEL` | No | If AI enabled | Model identifier | None |
| `CONFIGSENTINEL_LLM_TIMEOUT_S` | No | No | Request timeout (seconds) | `20` |
| `CONFIGSENTINEL_LLM_MAX_INPUT_CHARS` | No | No | Input bound | `24000` |
| `CONFIGSENTINEL_LLM_MAX_OUTPUT_CHARS` | No | No | Output bound | `8000` |

### Optional Backup
| Variable | Secret? | Required? | Purpose | Default |
|---|---|---:|---|---|
| `CONFIGSENTINEL_BACKUP_PASSPHRASE` | **Yes** | If backup used | Encrypt backup artifacts | None |

## Current SIH Scorecard (67/100)

| Category | Weight | Current Score | Gap |
|---|---:|---:|---:|
| Problem definition and SIH alignment | 10 | 7 | 3 |
| Core functional completeness | 20 | 12 | 8 |
| Backend correctness and frontend wiring | 15 | 12 | 3 |
| Security, privacy, authentication, authorization | 15 | 8 | 7 |
| Reliability, testing, observability, operations | 15 | 9 | 6 |
| AI safety and responsible-AI boundaries | 10 | 8 | 2 |
| Deployment and scalability readiness | 5 | 2 | 3 |
| UX, accessibility, and demo quality | 5 | 4 | 1 |
| Evidence, documentation, and measurable impact | 5 | 3 | 2 |
| **Total** | **100** | **67** | **33** |

## Identified Issues

### P0 (Blocking SIH 100/100)
1. **Frontend authority errors:** Hardcoded vendor labels, control counts, version text
2. **Cosmetic actions:** Toast messages instead of real workflows (policy provenance, approval, proof view)
3. **Incomplete operational loop:** No end-to-end workflow from audit to verification
4. **Vendor detection inconsistency:** Frontend only supports 3 vendors, backend supports 5
5. **Limit mismatch:** Frontend 2 MB, backend 5 MB

### P1 (High Impact)
1. **No AI integration in UI:** AI exists but not exposed in dashboard
2. **No frontend tests:** Zero automated browser/component tests
3. **No security gates:** No dependency audit, secret scan, SAST in CI
4. **Control pack too small:** Only 7 controls for "network assurance" claim
5. **No authentication:** Single-user local-only model

### P2 (Medium Impact)
1. **No durable storage:** Browser-only history
2. **No metrics/observability:** No structured logging, correlation IDs
3. **Bundle size warning:** Frontend chunk > 500 KB
4. **No accuracy measurements:** No fixture matrix, false-positive analysis
5. **No impact evidence:** No operational metrics, user studies

## Baseline Test Results

### Backend Tests
```bash
python -m pytest -q
```
**Result:** ✅ PASS (all tests passing)

### Frontend Type Check
```bash
cd frontend && pnpm run check
```
**Result:** ✅ PASS (no TypeScript errors)

### Frontend Build
```bash
cd frontend && pnpm run build
```
**Result:** ⚠️ PASS with chunk-size warning (> 500 KB)

### Python Compilation
```bash
python -m compileall -q src tests examples
```
**Result:** ✅ PASS

## Next Steps

1. ✅ Complete codebase inspection
2. ✅ Create dependency and feature map
3. ✅ Identify gaps and issues
4. ⏳ Create definitive SIH scorecard document
5. ⏳ Run complete baseline validation
6. ⏳ Commit and push Phase 1 baseline

## Acceptance Criteria for Phase 1

- [x] All source files inspected
- [x] Dependency matrix documented
- [x] Feature map created
- [x] Environment variable matrix completed
- [x] Current SIH score calculated (67/100)
- [x] All baseline tests pass
- [x] Issues prioritized (P0, P1, P2)
- [ ] Phase 1 documentation committed
- [ ] Baseline commit pushed to GitHub
