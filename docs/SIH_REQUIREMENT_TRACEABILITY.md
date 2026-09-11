# SIH 26155 Requirement Traceability

| Requirement | Implementation | Evidence location | Demo step | Status |
|---|---|---|---|---|
| Multi-vendor configuration support | Cisco IOS/IOS XE, Junos, and conservative generic firewall parser paths | `src/configsentinel/parsers.py`, `src/configsentinel/capabilities.py` | Network audit | Implemented for supported syntax |
| Secure ingestion | Extension, size, UTF-8, NUL, path, line, and source validation | `src/configsentinel/ingestion.py`, `tests/test_phase4.py` | Upload config | Implemented |
| Secret protection | Redaction before downstream analysis and sensitive-value handling | `src/configsentinel/sensitive.py`, `tests/test_sensitive.py` | Upload config | Implemented and tested |
| Normalized evaluation | Canonical model feeds deterministic controls | `src/configsentinel/canonical.py`, `src/configsentinel/engine.py` | Network audit | Implemented |
| PASS / FAIL / UNKNOWN | Typed status model with uncertainty preserved | `src/configsentinel/models.py`, `frontend/client/src/pages/Home.tsx` | Findings and Review Queue | Implemented |
| Exact evidence | Source line spans, excerpts, expected and observed state, input hash | `src/configsentinel/reporting.py`, `frontend/client/src/pages/Home.tsx` | Open finding | Implemented |
| Framework mapping | Backend-authoritative control registry and mappings | `src/configsentinel/frameworks.py`, `/api/control-pack` | Control Packs | Implemented |
| Review-only remediation | Deterministic preview with non-execution warning and approval boundary | `src/configsentinel/remediation.py`, `src/configsentinel/governance.py` | Remediation | Implemented; no device executor |
| Assurance trail | Approval events, audit IDs, hashes, local history, verification modules | `src/configsentinel/auditlog.py`, `src/configsentinel/verification.py` | Assurance Chain | Local implementation |
| Website posture inspection | Passive website scan API and dedicated evidence UI | `src/configsentinel/website_scanner.py`, `frontend/client/src/pages/WebsiteSecurityPage.tsx` | Website Security | Implemented with explicit limitations |
| Local operation | FastAPI adapter, browser fixture fallback, one-click launcher | `examples/api_server.py`, `start-local.bat` | Open workbench | Implemented |
| AI assistance | Optional bounded explanation path; not authoritative | `src/configsentinel/llm.py`, `src/configsentinel/api.py` | Explain only if configured | Optional and disabled by default |
| Live device remediation | Not present by design | README safety boundary, remediation modules | Do not claim | Not implemented |
| Production identity | Local/scaffold auth only; no external IdP integration | `src/configsentinel/api.py`, readiness report | Do not claim | Limited |
| Real-world accuracy | Synthetic fixture benchmark only | `docs/reports/BENCHMARK_REPORT.md`, `tests/fixtures/manifest.json` | Do not claim | Evidence gap |
