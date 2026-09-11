# VEYRONIX / ConfigSentinel AI

## SIH 26155 Final Gap Analysis

**Audit date:** 2026-09-11  
**Scope:** repository source, tests, frontend routes, API wiring, Docker files, and documented local runtime  
**Evidence rule:** this report distinguishes implemented behavior from compatibility/demo behavior. It does not award points for claims that are not reproducible.

## Current and Target Score

**Current engineering score: 88/100.** This is a code-and-evidence assessment, not a prediction of a judge's final mark. The target is **95/100 or higher** after the acceptance criteria below are demonstrated with a clean release build, browser evidence, and approved representative fixtures.

| Category                         |  Weight | Current | Basis                                                                                                                   |
| -------------------------------- | ------: | ------: | ----------------------------------------------------------------------------------------------------------------------- |
| Problem alignment                |      25 |      22 | Strong configuration assurance workflow; limited field validation evidence                                              |
| Functional completeness          |      20 |      17 | Core audit and dedicated website inspection are real; advanced surfaces vary from real API data to bounded simulations  |
| Technical architecture           |      20 |      19 | Deterministic engine, evidence model, safety boundaries, local API, and compiled production proxy                       |
| UI/UX and demo quality           |      15 |      13 | Strong visual direction, dedicated website experience, and core workflow; research IA still needs consolidation         |
| Innovation and differentiation   |      10 |       8 | Evidence, unknowns, provenance, review-only remediation, and bounded AI are credible                                    |
| Testing, security, deployability |      10 |       9 | Broad Python/frontend/browser gates and corrected production topology; Docker runtime still needs daemon smoke evidence |
| **Total**                        | **100** |  **88** | Verified current-release assessment                                                                                     |

## Requirement-to-Feature Mapping

| SIH need                            | Verified implementation                                                                  | Evidence                                                                                                |
| ----------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Multi-vendor configuration auditing | Cisco IOS/IOS XE, Junos, and conservative generic firewall parser paths                  | `src/configsentinel/parsers.py`, `src/configsentinel/capabilities.py`, parser tests                     |
| Secure ingestion and redaction      | Extension, size, UTF-8, NUL, path, line, and redaction boundaries                        | `src/configsentinel/ingestion.py`, `src/configsentinel/sensitive.py`, phase 4 tests                     |
| Deterministic compliance            | Explicit PASS, FAIL, UNKNOWN, and NOT_APPLICABLE control results                         | `src/configsentinel/engine.py`, `src/configsentinel/controls.py`                                        |
| Evidence and source lines           | Evidence spans, excerpts, hashes, rationale, expected/observed state                     | `src/configsentinel/models.py`, `src/configsentinel/reporting.py`, `frontend/client/src/pages/Home.tsx` |
| Framework mapping                   | Backend control registry and framework mappings                                          | `src/configsentinel/frameworks.py`, `/api/control-pack`                                                 |
| Review-only remediation             | Preview generation, safety note, approval boundary, no device executor                   | `src/configsentinel/remediation.py`, `src/configsentinel/governance.py`                                 |
| Provenance and assurance            | Versioned evidence and notary/verification modules exist; some legacy aliases are weaker | `src/configsentinel/provenance.py`, `src/configsentinel/notarization.py`, `src/configsentinel/api.py`   |
| Local demo                          | Bundled fixture, browser local history, offline fallback, one-click launcher             | `examples/local_demo.py`, `start-local.bat`, `Home.tsx`                                                 |
| Website inspection                  | Passive scanner API and dedicated evidence UI with authorization confirmation            | `src/configsentinel/website_scanner.py`, `WebsiteSecurityPage.tsx`, website tests                       |

## Current Strengths

- The deterministic engine owns verdicts. Optional AI explanation is not used to replace compliance status.
- UNKNOWN is represented distinctly and is not treated as PASS.
- Ingestion and redaction boundaries are explicit and tested.
- Reports carry audit IDs, input hashes, evidence spans, framework mappings, and remediation metadata.
- Remediation is visibly review-only and does not connect to devices or execute commands.
- The local API exposes health, capabilities, detection, audit, approval, inventory, monitoring, drift, website, and evidence-related routes.
- The main dashboard has a usable local journey: run/upload, inspect findings, filter, open evidence, review unknowns, export, and request approval.
- Frontend typecheck, focused unit tests, accessibility checks, feature-route smoke tests, and production build have passed in the current work history.
- The visual system uses the requested mineral canvas, graphite rail, orange attention, teal positive, amber unknown, and dense evidence treatment.

## Critical Gaps

1. **Docker runtime still needs a daemon-backed smoke test.** The image now starts the compiled Express proxy and Compose passes `BACKEND_API_URL`, but the local environment has validated Compose syntax and the application build, not a full container-to-container request.
2. **Website Security is now a dedicated page component.** Its safe demo state and passive scan journey are complete, but several requested signals are represented by the backend rule set rather than a separate UI field for every category.
3. **Advanced feature pages are not uniformly backed by authoritative data.** Some use real API routes; others use bounded synthetic/compatibility responses. They need explicit Research Lab labeling or stronger populated states.
4. **Browser coverage does not prove the full judge journey.** Existing tests cover route loading, basic audit behavior, and accessibility, but not evidence opening, filters, website dedicated identity, approval transition, remediation warning, or mobile overflow.
5. **The frontend has duplicated navigation and API-fetch patterns.** `Home.tsx`, `Layout.tsx`, and `navigation.ts` can drift; raw fetch calls do not share a typed error/credential policy.
6. **Operational persistence is limited.** Inventory and monitors are process-global in parts of the API; monitoring heatmap/uptime includes synthetic behavior and is not a scheduler.

## Medium-Priority Gaps

- Missing exchange package download route behind the advertised `download_url` contract.
- Legacy notary and provenance aliases are weaker than the v1 evidence-oriented modules and should not be presented as equivalent.
- Authentication/OIDC is local/scaffold-level rather than a real external identity integration.
- Accuracy evidence is synthetic and small; the repository documents this, but the UI and scorecard must not imply production accuracy.
- Report documentation contains conflicting historical test counts and completion claims.
- Large frontend bundle warning remains; route-level lazy loading is not yet implemented.
- Loading and failure feedback is inconsistent on inventory and monitoring fetches.
- No automated production Docker smoke test covers frontend-to-backend routing.

## Cosmetic and UX Gaps

- Advanced research features occupy the same visual priority as the core audit workflow.
- The overview can still leave lower panels sparse when no history exists.
- The primary dashboard should surface evaluated/pass/fail/unknown/evidence coverage, vendor/parser, audit ID, hash, timestamp, framework, and mode in one compact first viewport.
- Some labels and copy imply more operational capability than the local implementation supports.
- Repeated inline styles make responsive maintenance harder.

## Unsupported or Restricted Claims

Do not claim live device connections, automatic remediation, cloud multi-tenancy, production OIDC, scheduled fleet monitoring, external knowledge graph, real-world accuracy, or external notarization unless separately implemented and evidenced. The LLM is optional and advisory only. Website inspection is passive and must be presented with authorization and limitations. Advanced pages with synthetic records are research/demo surfaces, not production integrations.

## Proposed Implementation Phases

1. **Release correctness:** fix Docker startup/proxy/environment naming; add production health/API smoke coverage.
2. **Judge path:** create a dedicated Website Security page with honest demo fixture, explicit mode/limitations, and full evidence layout.
3. **Information architecture:** promote Overview, Run Audit, Findings, Review Queue, Remediation, Assurance Chain, Reports, Inventory, and Settings; move bounded experiments under Research Lab.
4. **Demo evidence:** add two labeled vendor fixtures, before/after verification fixture, and a 5–7 minute script using only reproducible actions.
5. **Test evidence:** add frontend workflow tests, mobile/keyboard checks, console-error checks, website identity checks, and API contract regression tests.
6. **Maintainability:** centralize navigation/API helpers and lazy-load heavy research pages where this does not risk the core flow.
7. **Field proof:** add approved sanitized configurations, stakeholder validation, measured false-positive/false-negative results, and quantified time/risk impact.

## Acceptance Criteria

- `docker compose build --pull` and `docker compose up` serve the frontend and return backend JSON through same-origin `/api/health`.
- The first viewport clearly exposes score, evaluated/pass/fail/unknown counts, evidence coverage, vendor/parser, audit ID, hash, timestamp, framework, local mode, deterministic indicator, and primary audit action.
- A judge can complete upload/detect/redact/evaluate/evidence/unknown/mapping/remediation/approval/verification/export locally without credentials or live devices.
- Website Security is visibly distinct from Overview, has a safe demo state before scanning, and labels passive/local limitations.
- Every visible route is either backed by real API data, a clearly marked deterministic fixture, or the Research Lab section.
- PASS, FAIL, UNKNOWN, UNVERIFIED, and REVIEW REQUIRED remain semantically distinct in UI and API.
- No remediation or generated command executes automatically.
- Python tests, frontend unit tests, typecheck, production build, E2E, accessibility, and production API smoke checks pass from a clean checkout.
- Documentation claims match runtime behavior and identify unsupported integrations.
- No secrets or raw sensitive configuration are introduced.
