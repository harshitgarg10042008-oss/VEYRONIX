# ConfigSentinel AI

## SIH Presentation, Live Demonstration, Feature, and Judge-Question Guide

**Project:** ConfigSentinel AI by VEYRONIX
**Repository:** `harshitgarg10042008-oss/VEYRONIX`
**Latest verified commit:** `320728843bdc6e09a4dfe57d26185185a45ca58b`
**Document purpose:** Explain the problem, solution, architecture, feature set, live demonstration, validation status, limitations, and likely judge questions.

---

## 1. Executive summary

ConfigSentinel AI is an **evidence-first, deterministic, offline-first security assurance platform** for network configuration and authorized website posture analysis. It evaluates configuration text and website responses through versioned control rules, attaches evidence to every finding, preserves an explicit `UNKNOWN` state when evidence is insufficient, and produces review-only remediation previews.

The product is deliberately conservative. It does not pretend that unsupported evidence is a failure, it does not allow an AI explanation to override deterministic findings, and it does not automatically modify a live device. Its central promise is:

> **No unsupported verdict, no hidden uncertainty, and no automatic infrastructure mutation.**

### Current score

| Score type | Current rating | Interpretation |
|---|---:|---|
| Engineering readiness | **90/100** | Backend and frontend quality gates pass; core analysis, scanner, API, authentication hardening, and UX flows are implemented. |
| Honest SIH-style competition readiness | **86/100** | The software is strong, but judges may still deduct for missing field pilots, production OIDC, durable multi-tenant persistence, and quantified real-world impact evidence. |

The project should be presented as an **offline assurance and GitOps review platform**, not as a live fleet-management or automatic-remediation product.

---

## 2. Problem statement

Network and application security teams regularly receive configuration files, website endpoints, audit outputs, and change requests, but a simple pass/fail result is insufficient for high-consequence environments. A reviewer must know what was observed, where it was observed, which policy applies, how confident the system is, what remains unknown, and whether a proposed correction can be reviewed before implementation.

Existing approaches often create one or more of the following problems:

1. A black-box scanner returns a score without explaining the evidence behind it.
2. Missing evidence is silently treated as a pass or a failure.
3. AI-generated explanations are presented as if they were authoritative compliance decisions.
4. Remediation may be applied before an independent human review.
5. Security checks depend on live device access or external services, which is difficult to use in restricted environments.
6. Website posture scores can be misleading when missing defense-in-depth headers are treated like confirmed vulnerabilities.

### One-sentence problem statement

> Security teams need a safe and reproducible way to evaluate configurations and authorized websites, understand the evidence behind every finding, handle uncertainty explicitly, and review remediation without automatically changing infrastructure.

---

## 3. Solution statement

ConfigSentinel AI addresses the problem with a local workbench and API that combine:

- deterministic vendor-aware configuration parsing;
- versioned control packs and framework mappings;
- source-line evidence and input SHA-256 hashing;
- explicit `PASS`, `FAIL`, `UNKNOWN`, and review-required states;
- passive website security posture checks;
- evidence-weighted website scoring;
- safe, non-executable remediation previews;
- independent approval and reviewer workflow;
- notary, provenance, timeline, drift, supply-chain, secrets, and threat-model utilities;
- optional bounded AI explanations that cannot change the deterministic result;
- server-issued session identity mode for stronger local governance;
- offline-first operation for the primary audit workflow.

The system is designed to answer not only **“What is wrong?”**, but also **“What evidence proves it, what is still unknown, and what can a reviewer safely do next?”**

---

## 4. How to start the project

### Recommended one-click startup

Use the existing Windows batch file supplied with the repository. Do not start the frontend and backend manually for the normal presentation.

1. Open the repository folder on the demonstration machine.
2. Double-click the `.bat` startup file.
3. Allow it to install missing dependencies if prompted.
4. Wait for the backend health check to report success.
5. Wait for the frontend URL to be printed.
6. Open the URL automatically launched by the batch file, normally `http://localhost:5173` or the displayed frontend port.
7. Keep the backend and frontend command windows open during the demonstration.

The batch file starts the backend first, waits for `/api/health`, then starts the frontend. This order matters because the frontend uses the backend API for deterministic analysis.

### Startup verification

Before showing any feature, confirm these visible indicators:

| Check | Expected result |
|---|---|
| Sidebar status | `LOCAL API ONLINE` |
| Top status | `DETERMINISTIC` |
| Dashboard metadata | SDK version and control-pack data load |
| Backend health | `status: ok`, `deterministic: true` |
| Offline indicator | Must not say `OFFLINE MODE` during the live API demo |

If the dashboard says `OFFLINE MODE`, do not present the result as a live analysis. Check the backend log created by the batch file.

---

## 5. Recommended ten-minute judge demonstration

### 0:00–1:00 — Problem and solution

Say:

> “ConfigSentinel AI is an evidence-first security assurance platform. It analyzes network configurations and authorized websites locally, attaches source evidence to every decision, keeps uncertainty explicit, and produces review-only remediation instead of automatically changing infrastructure.”

Show the dashboard and the `LOCAL API ONLINE` status.

### 1:00–2:00 — Architecture and safety boundary

Explain this flow:

```text
User interface
    ↓
FastAPI API
    ↓
Vendor detection and parser registry
    ↓
Versioned deterministic control pack
    ↓
Evidence, findings, score, and governance records
    ↓
Review, approval, export, and verification
```

Emphasize that live device connections and automatic device mutation are intentionally disabled.

### 2:00–4:00 — Real configuration audit

1. Open **Audits**.
2. Click **Upload config**.
3. Select a sanitized `.cfg`, `.conf`, `.config`, or `.txt` file.
4. Show the **ACTIVE CONFIGURATION SOURCE** card.
5. Point out the exact filename, file size, and `ANALYZING` status.
6. Wait for `ANALYZED`.
7. Show the finding table and select a finding.
8. Show source lines, observed state, expected state, rationale, severity, confidence, and framework mappings.
9. Show the audit ID, rule-pack version, vendor, and SHA-256.

Say:

> “The uploaded source is visible and bound to the resulting report. This is not a generic demo result: the selected file is sent to the real local API, parsed, evaluated against versioned controls, and stored in the local audit history.”

### 4:00–5:00 — Unknown evidence and safe remediation

Select an `UNKNOWN` or review-required finding. Explain that the engine does not convert insufficient evidence into a false pass or false failure.

Export the remediation preview and show:

```text
NON-EXECUTABLE — review, approve, and test independently
```

Say:

> “The system proposes intent and evidence, but it does not silently apply changes to a device.”

### 5:00–6:00 — Independent approval

1. Request review for the audit.
2. Show `PENDING_REVIEW`.
3. Switch to the reviewer role.
4. Open the review queue.
5. Inspect the finding and remediation preview.
6. Approve or reject it.
7. Show the actor, role, timestamp, reason, and approval status.

### 6:00–7:30 — Website security scanner

1. Open **Website Security**.
2. Enter an authorized public URL such as `https://www.google.com`.
3. Confirm authorization.
4. Click **Scan website**.
5. Show final URL, timestamp, score, classification, findings, observed values, expected values, and limitations.

Say:

> “This is a passive posture score based on the response observed from this target. A missing hardening header is not automatically treated as a confirmed vulnerability, and unavailable evidence is reported as unknown.”

The latest verified Google run returned approximately **86/100, GOOD**. Live results can vary with CDN edge, response type, and network location.

### 7:30–8:30 — Drift and evidence export

Run two audits with different configuration files, open **Drift Detection**, select baseline and current snapshots, and show changed controls. Export an evidence PDF.

### 8:30–9:30 — Supporting feature tour

Use the feature table in Section 7. Open only two or three supporting pages during the live demo. Do not spend the entire presentation clicking every page.

### 9:30–10:00 — Validation, impact, and limitations

Show the test summary and close with:

> “Our strongest guarantee is not an inflated score. It is that every result has an evidence path, uncertainty is visible, AI is bounded, and infrastructure mutation is outside the product’s authority.”

---

## 6. Full feature descriptions

| Feature | What it does | What is real | Important boundary |
|---|---|---|---|
| Overview Dashboard | Displays current posture, findings, score, history, and navigation. | Loads live API health, control-pack, audit, approval, inventory, and monitor data when the API is online. | The bundled fixture is available for an offline/local smoke demo. |
| Configuration Audit | Accepts network configuration text and evaluates it against deterministic controls. | Real parser, vendor detection, control evaluation, evidence, status, severity, confidence, and SHA-256 flow. | It analyzes supplied text; it does not connect to a live device. |
| Upload Source Card | Shows the selected filename, size, and processing status. | The filename is tied to the uploaded source and report history. | Browser-side state is used for the visible upload status. |
| Vendor Detection | Identifies likely configuration vendor and parser. | Real API detection and candidate response. | Ambiguous or unsupported input should remain reviewable rather than being forced. |
| Evidence Panel | Shows source lines, observed state, expected state, rationale, and confidence. | Real report evidence from the deterministic engine. | Evidence quality depends on the supplied configuration. |
| Audit History | Stores recent reports for comparison and export. | Real local browser history. | It is not durable multi-user production storage. |
| Drift Detection | Compares two audit reports and identifies changed posture. | Real API comparison of selected audit snapshots. | It compares available reports; it does not monitor a device directly. |
| Website Security | Performs passive HTTPS, TLS, headers, cookies, redirects, mixed-content, and related checks. | Real network request and evidence-derived findings. | Only authorized passive assessment is permitted. |
| Website Score | Converts findings into a posture score. | Real weighted calculation; warnings have lower weight and unknown evidence has no security deduction. | It is a posture score, not a guarantee of no vulnerabilities. |
| Website AI Explanation | Explains a selected website finding. | Real API call to the configured offline or external provider mode. | Explanation is advisory and cannot change the authoritative finding. |
| Review Queue | Collects unknown or review-required findings. | Real findings from audit reports. | Human review is still required. |
| Control Packs | Displays deterministic rules, versions, vendors, and framework mappings. | Real versioned control-pack API. | Coverage is limited to implemented controls and supported vendors. |
| Remediation Preview | Exports suggested remediation intent for failed findings. | Real report-derived preview. | It is explicitly non-executable. |
| Approval Workflow | Requests, approves, or rejects review of remediation previews. | Real API state transitions and approval events. | Local demo persistence is not equivalent to enterprise workflow storage. |
| Asset Inventory | Adds and deletes tracked assets with owner, criticality, and exposure. | Real API interaction. | Current storage is local/in-memory rather than durable multi-tenant storage. |
| Continuous Monitoring | Creates, pauses, resumes, triggers, and deletes scheduled checks. | Real API lifecycle flow. | It is a local/demo monitoring layer, not a fleet scheduler connected to devices. |
| Assurance Chain | Presents evidence and governance chain navigation. | Uses project evidence and verification features. | It does not claim external legal notarization unless configured and verified. |
| Notary Console | Signs and verifies evidence bundles. | Real local signing/verification flow. | Key management must be supplied securely for production. |
| Provenance Tracker | Looks up artifact provenance. | Real API lookup and verification path. | Provenance is only as complete as the supplied artifact records. |
| Secrets Gate | Detects and assesses secret exposure/redaction. | Real deterministic assessment path. | It is not a replacement for a dedicated enterprise secret-management platform. |
| Supply Chain | Analyzes SBOM and dependency evidence. | Real analysis path for supplied SBOM data. | It does not automatically validate every external package registry claim. |
| Threat Models | Generates a STRIDE-style model from component information. | Real structured analysis endpoint. | It is a modelling aid, not a complete penetration test. |
| API Contracts | Compares API schema and runtime contract signals. | Real OpenAPI and conformance path. | Contract correctness does not prove business correctness. |
| Resilience Drills | Creates and runs failover/resilience drill records. | Real local workflow and API state. | It does not execute destructive production failover. |
| Incident Timeline | Records and displays incident events. | Real API event flow. | Current persistence and identity are local/demo scoped. |
| Regulatory Export | Exports audit evidence into regulatory-oriented formats. | Real export path. | Compliance suitability still requires qualified human review. |
| Knowledge Graph | Queries relationships among controls, findings, and institutional records. | Real query path. | Graph quality depends on the evidence and records entered. |
| Parser Differential | Compares parser interpretations to expose ambiguity. | Real parser-differential endpoint. | It requires supported parser/input combinations. |
| Mutation Lab | Tests rule robustness against controlled mutations. | Real local test/analysis path. | It mutates test data, not live infrastructure. |
| Counterfactuals | Evaluates hypothetical rule or status changes. | Real report-based what-if analysis. | It does not modify the original audit or policy state. |
| Settings | Changes local browser preferences and demo behavior. | Real local UI state. | It is not an enterprise configuration management console. |
| Operator Guide | Provides an in-product safe demonstration sequence. | Real static guide page. | It documents the product’s boundaries; it does not replace deployment documentation. |

---

## 7. What is connected and what is intentionally local

### Connected and verified

The latest validation confirmed that the backend starts, the frontend builds, the health endpoint works, the control pack loads, configuration audit requests return real findings, website scans perform real HTTP analysis, session login returns a server-issued HttpOnly cookie, and OpenAPI generation succeeds.

The frontend pages use API calls for the core feature actions. Backend and frontend tests pass on the verified commit.

### Intentionally local or offline

The following are not hidden failures; they are documented product boundaries:

- the bundled configuration is a local fixture for smoke demonstrations;
- audit history is stored in browser local storage;
- some inventory, monitoring, timeline, and approval state is local/demo scoped;
- offline AI explanation is optional and non-authoritative;
- production OIDC/SSO is not included;
- durable cloud multi-tenancy is not included;
- live device connections and automatic remediation are disabled by design.

When the API is unavailable, the UI labels itself `OFFLINE MODE` or `LOCAL DEMO`. It must never be presented as a completed live analysis.

---

## 8. Verification checklist before judges arrive

Run this checklist on the exact machine and commit being demonstrated.

| Check | Command or action | Expected |
|---|---|---|
| Repository state | `git log -1` | Matches submitted commit |
| Clean tree | `git status --short` | No unintended files |
| Backend tests | `PYTHONPATH=src python3 -m pytest -q` | All pass |
| Python compile | `PYTHONPATH=src python3 -m compileall -q src` | No errors |
| Frontend type check | `cd frontend && pnpm run check` | Pass |
| Frontend tests | `cd frontend && pnpm test -- --run` | 3 tests pass |
| Frontend build | `cd frontend && pnpm run build` | Build succeeds |
| Backend health | Open `/api/health` | `status: ok` |
| OpenAPI | Open `/openapi.json` | Valid schema |
| UI connectivity | Start `.bat` | `LOCAL API ONLINE` |
| File upload | Upload a sanitized config | Filename and `ANALYZED` status visible |
| Website scan | Scan authorized URL | Evidence-derived result and limitations visible |
| Error path | Stop backend and reload | Clear offline state; no fake completed report |

---

## 9. Judge questions and strong answers

### Q1. What is the main innovation?

**Answer:** The innovation is the evidence-first decision model. ConfigSentinel does not only output a score. It binds each deterministic finding to source evidence, expected state, confidence, framework mappings, and an explicit uncertainty state. It also separates analysis from remediation authority.

### Q2. Why use AI if deterministic rules are available?

**Answer:** AI is used only as a bounded explanation and analysis assistant. The deterministic rule engine remains authoritative for compliance status. AI cannot turn an unknown into a pass, remove evidence, approve remediation, or change the posture score.

### Q3. Is the website score hardcoded?

**Answer:** No. The scanner uses the observed HTTP/TLS/header/cookie/redirect evidence and a versioned scoring function. Earlier, a runtime compatibility error caused a misleading fallback path, which was fixed. Scanner errors now fail closed instead of returning a fake 50-point result. Missing hardening headers are low-weight warnings and unavailable evidence is `UNKNOWN` without a security deduction.

### Q4. Why did Google receive less than 100 if it is considered safe?

**Answer:** The score is an observed posture score, not a global safety verdict. Mature websites can omit some defense-in-depth headers on a particular response, use different CDN responses, or expose limited redirect evidence. The report separates confirmed failures, warnings, and unknown evidence so a judge can see exactly why points were deducted.

### Q5. Can it scan any website?

**Answer:** It can perform a passive assessment of an accessible website for which the operator is authorized. It must not be used for crawling, exploitation, brute force, port scanning, or bypass attempts. Government, defence, ISRO, Army, and other sensitive sites require explicit authorization.

### Q6. Can it connect to a router or firewall?

**Answer:** Not in the current product. The current release analyzes supplied configuration evidence and intentionally does not change live infrastructure. This reduces operational risk and keeps the demo reproducible. Live device connectors are future scope.

### Q7. How do you prevent false confidence?

**Answer:** The platform preserves `UNKNOWN`, attaches confidence and evidence, reports limitations, and separates warnings from confirmed failures. It does not claim that a missing observation proves a vulnerability.

### Q8. How is remediation made safe?

**Answer:** Remediation is a non-executable preview. A reviewer must inspect, approve, and test it independently. The platform does not authorize or apply a device change.

### Q9. Is authentication production-ready?

**Answer:** The release includes server-issued HttpOnly session identity mode and hardened strict identity behavior. Production enterprise SSO/OIDC, durable identity lifecycle, and full tenant isolation remain future work and are not claimed as complete.

### Q10. Is this a cloud SaaS product?

**Answer:** The current product is positioned as a local/offline-first workbench and API. Some workflows use local storage or local/demo persistence. A production cloud multi-tenant deployment is future scope.

### Q11. What evidence supports your accuracy claim?

**Answer:** The repository includes deterministic fixtures, parser tests, scanner tests, API tests, and regression coverage. Field accuracy across representative stakeholder configurations is still required for a stronger impact claim. We do not present synthetic benchmark performance as equivalent to field validation.

### Q12. How does the system support compliance frameworks?

**Answer:** Findings can include framework mappings and control-pack versions. The system exports reviewable evidence, but compliance certification still requires human governance and context-specific interpretation.

### Q13. What happens when the API is down?

**Answer:** The UI clearly changes to offline state and reports that live analysis is unavailable. It does not silently claim a successful result. The bundled fixture is explicitly labelled as a local fixture.

### Q14. Why is the product called AI if the core is deterministic?

**Answer:** AI is an assistive layer for explanation and bounded analysis. Making deterministic controls authoritative is a deliberate safety design choice for security assurance.

### Q15. What is the biggest remaining gap?

**Answer:** The biggest remaining gap is external validation: stakeholder interviews, representative field configurations, measured parser accuracy and false-positive/false-negative rates, quantified operational time savings, and production identity/persistence hardening.

---

## 10. Final presentation closing

Use this closing statement:

> “ConfigSentinel AI makes security findings reviewable instead of mysterious. It shows the evidence, preserves uncertainty, bounds AI, and keeps remediation under human control. The result is a safer and more reproducible assurance workflow for teams that cannot afford unsupported security decisions.”

---

## 11. Do not make these claims

Do not claim that the product currently provides live fleet management, automatic device remediation, complete cloud multi-tenancy, production OIDC/SSO, guaranteed vulnerability absence, or field-validated accuracy unless those capabilities are separately implemented and evidenced.

A credible SIH presentation is stronger when it clearly distinguishes **verified capability**, **local demo capability**, and **future scope**.

---

## 12. Repository evidence references

The following repository areas support this guide:

- `frontend/client/src/pages/Home.tsx` — dashboard, configuration upload, audit flow, website scanner, approval workflow, and visible source status.
- `frontend/client/src/index.css` — dashboard styling and uploaded-file status-card presentation.
- `src/configsentinel/api.py` — API routes, authentication, approval, audit, and OpenAPI behavior.
- `src/configsentinel/website_scanner.py` — website scan orchestration and fail-closed behavior.
- `src/configsentinel/website_scoring.py` — evidence-weighted posture scoring.
- `src/configsentinel/website_rules.py` — website rule definitions and severity semantics.
- `tests/` — backend and scanner regression coverage.
- `frontend/client/test/dashboard.test.tsx` — frontend dashboard behavior tests.
- `docs/SIH_EVIDENCE.md` — SIH evidence, limitations, and scoring documentation.
- `docs/API_KEYS_AND_ENVIRONMENT.md` — identity and environment deployment guidance.
- The repository’s Windows `.bat` startup script — one-click backend/frontend startup and health wait sequence.

**Prepared for the ConfigSentinel AI SIH demonstration.**
