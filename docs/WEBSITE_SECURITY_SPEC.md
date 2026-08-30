# ConfigSentinel AI — Website Security Assurance Feature Specification

**Status:** Proposed feature specification**Product:** ConfigSentinel AI**Project repository:** VEYRONIX**Primary goal:** Extend ConfigSentinel AI from network-configuration assurance into safe, evidence-backed website-security posture assessment.

> This feature must describe observable security posture, not promise that a website is absolutely safe. A passing result means that the tested checks passed at the time of assessment; it does not prove the absence of every vulnerability.

## 1. Problem Statement

Website owners and security teams often do not have a simple way to understand whether a website’s externally visible security configuration is strong. Manual checking of HTTPS, TLS, security headers, cookies, redirects, browser protections, and exposed technology signals is time-consuming and inconsistent.

Many security tools return large technical reports without clearly connecting each warning to the exact evidence that produced it. A general-purpose AI assistant may provide plausible recommendations without proving which response header, certificate property, or page resource was observed.

The practical problem is therefore not merely finding warnings. The real problem is producing a **clear, evidence-backed, repeatable, and safe assessment** of a website’s observable security posture without intrusive exploitation or unsafe automated changes.

## 2. Proposed Solution

ConfigSentinel AI will provide a **Website Security Posture Checker**. An authorized user will submit a website URL, and the system will perform bounded, non-invasive checks over HTTPS, TLS metadata, redirects, security headers, cookies, selected HTML resources, and other publicly observable signals.

The system will produce:

- a transparent posture score,

- passed checks,

- failed checks,

- warnings and unknown states,

- exact request/response evidence,

- severity and rationale,

- remediation guidance,

- scan timestamp and target identity,

- limitations and confidence boundaries,

- an exportable evidence report.

The deterministic rules will create the security findings. AI, if enabled, may explain or summarize findings, but it must never override the deterministic result, execute a command, or silently convert an unknown result into a pass.

## 3. Product Positioning

The initial feature should be called **Website Security Posture Checker**, not a full penetration-testing tool or vulnerability scanner. This naming accurately communicates that the MVP evaluates observable configuration signals through safe checks.

ConfigSentinel AI will then have two related assurance modules:

| Module | Input | Main result |
| --- | --- | --- |
| Network Configuration Assurance | Router, switch, firewall, or appliance configuration text | Deterministic control findings with source evidence |
| Website Security Posture Assurance | Authorized website URL | Observable web-security findings with response evidence |

Both modules should follow the same product principles:

> **Evidence first. Deterministic rules. Explicit uncertainty. Human-reviewed remediation. No unsafe autonomous action.**

## 4. Scope

### 4.1 In-scope MVP checks

The first implementation should support the following passive or low-impact checks:

| Check family | Examples of evidence |
| --- | --- |
| HTTPS availability | HTTPS response status, final URL, protocol used |
| HTTP-to-HTTPS redirect | Redirect chain and final destination |
| TLS certificate | Validity window, hostname match, issuer, certificate errors |
| TLS protocol | Negotiated protocol and clearly supported safe/unsafe protocol signals |
| HSTS | `Strict-Transport-Security` value and important directives |
| Content Security Policy | Presence and parsed directives of `Content-Security-Policy` |
| Clickjacking defense | `frame-ancestors` or `X-Frame-Options` |
| MIME sniffing defense | `X-Content-Type-Options` value |
| Referrer control | `Referrer-Policy` value |
| Browser permissions | `Permissions-Policy` presence and directives |
| Cookie flags | `Secure`, `HttpOnly`, and `SameSite` attributes for observed cookies |
| Mixed content | HTTPS document referencing HTTP scripts, styles, images, or frames |
| Redirect safety | Excessive redirects, scheme downgrades, suspicious final origin changes |
| Server disclosure | Unnecessary version information in observable headers |
| Security contact | Presence and parseability of `/.well-known/security.txt` |
| Basic HTML signals | Forms, external scripts, insecure resource references, and risky inline patterns |

The exact rule definitions must be versioned. A check must include its rule ID, version, severity, rationale, evidence, and remediation intent.

### 4.2 Future or separately governed features

The following capabilities must not be enabled by default in the MVP:

- brute-force authentication testing,

- credential testing,

- exploit attempts,

- destructive payloads,

- aggressive crawling,

- hidden-admin discovery,

- unrestricted port scanning,

- denial-of-service behavior,

- authenticated scanning with user credentials,

- arbitrary JavaScript execution against targets,

- automatic device or website modification.

Authenticated scanning may be designed later, but it requires explicit authorization, secure credential handling, session isolation, and a separate threat model.

## 5. Authorization and Responsible Use

Every scan must require the user to confirm that they are authorized to assess the target. The confirmation must be recorded with the scan request, authenticated user, workspace, timestamp, and target.

For a public deployment, add an abuse-prevention policy and enforce:

- authenticated access,

- per-user and per-workspace rate limits,

- maximum concurrent scans,

- target allowlists where appropriate,

- private and loopback IP blocking by default,

- DNS rebinding protection,

- redirect destination validation,

- maximum redirect count,

- connection timeout,

- total scan timeout,

- maximum response size,

- restricted schemes limited to `http` and `https`,

- no user-controlled proxy or arbitrary network route,

- audit logging without raw secrets.

The scanner must not allow Server-Side Request Forgery against internal services. Resolve the target safely, reject private/link-local/loopback/multicast addresses unless an explicit local-lab mode is enabled, and re-check every redirect destination.

## 6. Proposed User Experience

### 6.1 Entry point

Add a dashboard action named **Website Security Check**. The user enters a URL and sees an authorization confirmation before starting the scan.

The form should validate:

- URL scheme,

- hostname syntax,

- maximum URL length,

- disallowed IP ranges,

- unsupported schemes,

- duplicate or active scan state.

### 6.2 Scan progress

Show a safe progress state such as:

1. Validating target.

1. Resolving and checking target safety.

1. Inspecting HTTPS and redirects.

1. Inspecting TLS metadata.

1. Inspecting headers and cookies.

1. Inspecting selected page resources.

1. Evaluating deterministic controls.

1. Building evidence report.

Do not expose internal network addresses or sensitive resolver information in the user-facing report.

### 6.3 Results page

The results page should include:

- overall posture: `GOOD`, `NEEDS_REVIEW`, or `HIGH_RISK`,

- score and scoring explanation,

- counts by severity,

- passed checks,

- failed checks,

- warnings,

- unknown or unavailable checks,

- scan timestamp,

- final URL and origin,

- evidence snippets or normalized evidence fields,

- remediation recommendations,

- limitations.

Each finding should have:

| Field | Purpose |
| --- | --- |
| `finding_id` | Stable unique result identity |
| `rule_id` | Versioned deterministic rule |
| `title` | Human-readable finding title |
| `status` | `PASS`, `FAIL`, `WARN`, `UNKNOWN`, or `NOT_APPLICABLE` |
| `severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `evidence` | Normalized observed fact, not unnecessary raw data |
| `rationale` | Why the observation matters |
| `remediation` | Bounded recommended improvement |
| `observed_at` | Timestamp |
| `rule_version` | Reproducibility metadata |
| `target_hash` | Stable privacy-preserving target identity |
| `limitations` | What this check cannot prove |

## 7. Deterministic Scoring

The score must be reproducible from the result set and rule-pack version. Do not generate a score with an LLM.

A recommended initial model is severity-weighted deduction:

```
base_score = 100
score = base_score - weighted_failed_points - weighted_warning_points - unknown_penalty
score = clamp(score, 0, 100 )
```

The exact weights must be documented and versioned. For example, a missing high-value browser protection may carry more weight than missing security contact metadata. Unknown checks must not automatically become passes.

The report should also show the score’s limitations. A high posture score means the configured observable checks passed; it does not mean the site has no application vulnerabilities, business-logic flaws, supply-chain risk, or compromised credentials.

## 8. Evidence and Privacy Model

The scanner should collect the minimum evidence necessary to support each result.

Store or export:

- target origin,

- final URL,

- timestamp,

- response status,

- normalized security headers,

- normalized cookie attributes,

- TLS metadata,

- redirect chain with sensitive query values removed,

- resource-type and scheme summary,

- rule IDs and versions,

- finding statuses,

- evidence hashes,

- scan ID,

- scanner version.

Avoid storing:

- authorization headers,

- session cookies,

- passwords,

- request bodies containing personal data,

- full page contents unless explicitly required and authorized,

- unnecessary query parameters,

- hidden form values,

- raw private network details.

Implement redaction before persistence and before AI explanation. Define a retention period and provide deletion for authorized users.

## 9. API Design

Suggested endpoints:

```
POST /api/websites/scans
GET  /api/websites/scans/{scan_id}
GET  /api/websites/scans/{scan_id}/findings
GET  /api/websites/scans/{scan_id}/report
POST /api/websites/scans/{scan_id}/explanation
DELETE /api/websites/scans/{scan_id}
GET  /api/websites/rules
GET  /api/websites/health
```

### 9.1 Create scan request

Request:

```json
{
  "url": "https://example.com",
  "authorization_confirmed": true,
  "workspace_id": "derived-from-authenticated-principal"
}
```

The server must ignore a browser-supplied workspace identity and derive it from the authenticated principal.

Response:

```json
{
  "scan_id": "scan_123",
  "status": "QUEUED",
  "target_origin": "https://example.com",
  "rule_pack_version": "web-posture.v1",
  "created_at": "2026-08-30T00:00:00Z"
}
```

### 9.2 Security errors

Return safe errors for:

- invalid URL,

- unsupported scheme,

- target blocked by SSRF policy,

- authorization not confirmed,

- rate limit exceeded,

- scan timeout,

- target unavailable,

- redirect blocked,

- response too large,

- provider or parser failure.

Do not return stack traces, internal IPs, secret values, or raw connection details to the user.

## 10. Backend Architecture

Recommended components:

```
WebsiteScanRequest
        |
        v
TargetSafetyPolicy
        |
        v
SafeHTTPClient ---- TLSInspector
        |                  |
        v                  v
RedirectInspector     Header/CookieInspector
        |                  |
        +--------+---------+
                 v
       ResourceAndHTMLInspector
                 |
                 v
       DeterministicWebRuleEngine
                 |
                 v
       EvidenceAndScoreBuilder
                 |
                 v
       DurableScanStore / ReportExporter
                 |
                 v
       Optional Bounded AI Explainer
```

The HTTP client must use explicit timeouts, response-size limits, redirect policies, safe DNS handling, and a restricted user agent. The rule engine must be pure or as close to pure as practical so the same observations produce the same findings.

## 11. AI Boundary

AI is optional and disabled by default in local mode. It may:

- explain a deterministic finding,

- summarize a group of findings,

- translate technical language for a non-specialist,

- suggest a review question.

AI may not:

- create or change a finding status,

- change severity,

- claim that an untested property is safe,

- execute a request against the target,

- generate or apply a website change,

- receive secrets or unredacted session data.

Every AI explanation should contain the source finding IDs, model/provider mode, prompt version, and a statement that the deterministic finding remains authoritative.

## 12. Similar Companion Features

The following features fit naturally beside the website posture checker.

### 12.1 API security posture check

Assess an authorized API base URL for HTTPS, authentication challenge behavior, CORS response policy, rate-limit headers, cache controls, and safe error disclosure. Do not perform destructive or credentialed tests by default.

### 12.2 Security headers monitoring

Allow users to save an authorized website target and run periodic passive checks. Show posture drift when headers, certificate metadata, or redirect behavior changes. Drift must be shown as an assurance signal, not automatically classified as a vulnerability.

### 12.3 Certificate expiry monitoring

Track certificate expiry windows for authorized domains and issue reminders. Store only the minimum domain and certificate metadata required for the reminder.

### 12.4 Third-party resource inventory

List external scripts, stylesheets, frames, and image origins observed in the page. Highlight unexpected third-party origins and insecure scheme usage. Do not assert maliciousness solely from a third-party origin.

### 12.5 Privacy and cookie posture

Summarize observed cookies, security attributes, third-party status, and consent-banner signals. Do not infer legal compliance from technical signals alone.

### 12.6 Security contact and reporting readiness

Check `/.well-known/security.txt`, security contact information, and expiry metadata. Present this as responsible-disclosure readiness, not as proof of secure engineering.

### 12.7 Evidence comparison and drift report

Compare two scan reports and show new, resolved, and unchanged findings. Bind the comparison to scan IDs, timestamps, rule-pack versions, and target origins.

### 12.8 Remediation guidance library

Provide framework-specific examples for headers and TLS configuration, but keep them as review-only suggestions. Require human approval before any export to deployment tooling.

## 13. Environment Variables

Create `.env.example` with only variables actually used by the implementation. A possible design is:

```
# Backend connection
VITE_API_BASE_URL=http://127.0.0.1:5000

# Website scanner defaults
CONFIGSENTINEL_WEB_SCAN_ENABLED=true
CONFIGSENTINEL_WEB_SCAN_TIMEOUT_SECONDS=15
CONFIGSENTINEL_WEB_SCAN_MAX_RESPONSE_BYTES=2000000
CONFIGSENTINEL_WEB_SCAN_MAX_REDIRECTS=5
CONFIGSENTINEL_WEB_SCAN_MAX_CONCURRENT=2
CONFIGSENTINEL_WEB_SCAN_ALLOW_PRIVATE_TARGETS=false
CONFIGSENTINEL_WEB_SCAN_USER_AGENT=ConfigSentinel-Posture-Checker/1.0

# Public API protection
CONFIGSENTINEL_API_TOKEN=
CONFIGSENTINEL_AUTH_REQUIRED=false
CONFIGSENTINEL_RATE_LIMIT_PER_MINUTE=120

# Durable local storage
CONFIGSENTINEL_DATABASE_URL=sqlite:///./.configsentinel/configsentinel.db

# Optional AI explanations; offline mode requires no key
CONFIGSENTINEL_LLM_PROVIDER=offline
CONFIGSENTINEL_LLM_ENABLED=false
CONFIGSENTINEL_LLM_ENDPOINT=
CONFIGSENTINEL_LLM_MODEL=
OPENAI_API_KEY=
```

Do not request `OPENAI_API_KEY`, OAuth values, or cloud credentials unless the user explicitly enables those features. The passive local website posture checker should work without external API keys.

## 14. Testing Requirements

### 14.1 Unit tests

Test URL validation, scheme validation, SSRF blocking, DNS rebinding protection, redirect handling, timeout behavior, maximum response size, header parsing, cookie parsing, TLS parsing, mixed-content detection, score calculation, redaction, rule versioning, and unknown-state behavior.

### 14.2 API tests

Test authenticated and unauthenticated access, authorization confirmation, workspace isolation, rate limiting, safe errors, duplicate requests, scan cancellation, report export, retention/deletion, and AI explanation isolation.

### 14.3 Fixture tests

Create deterministic HTTP fixtures for:

- fully protected website,

- HTTPS without HSTS,

- missing CSP,

- missing clickjacking protection,

- weak cookie flags,

- mixed content,

- redirect loop,

- expired certificate simulation,

- timeout,

- oversized response,

- blocked private target,

- unknown/unavailable header behavior.

Synthetic fixtures must be labeled synthetic. Do not use them to claim real-world accuracy.

### 14.4 E2E tests

Add browser tests for:

1. opening Website Security Check,

1. invalid URL handling,

1. authorization confirmation,

1. scan progress,

1. result score and findings,

1. finding expansion and evidence,

1. unknown result display,

1. report export,

1. API failure/offline behavior,

1. keyboard accessibility and responsive layout.

### 14.5 Security tests

Add SSRF regression tests, secret-redaction tests, authorization tests, rate-limit tests, dependency scanning, secret scanning, SAST, and safe-host checks. Run accessibility tests without silently excluding severe rules.

## 15. Implementation Phases

### Phase A — Product and rule model

Add versioned website posture rule schemas, finding models, status/severity enums, evidence normalization, and score calculation. Add unit tests first.

### Phase B — Safe HTTP and TLS inspection

Implement the restricted HTTP client, target safety policy, DNS/IP checks, redirect policy, timeouts, response limits, HTTPS/TLS inspection, and safe error handling.

### Phase C — Header, cookie, resource, and HTML checks

Implement passive inspectors and deterministic rules for headers, cookies, mixed content, selected resources, server disclosure, and security.txt.

### Phase D — API and durable reports

Add scan creation/status/findings/report endpoints, authenticated workspace ownership, durable storage, retention, request IDs, rate limits, and exports.

### Phase E — Frontend experience

Add Website Security Check entry point, consent/authorization confirmation, progress state, results dashboard, finding detail, score explanation, limitations, and export.

### Phase F — Optional bounded AI explainer

Reuse ConfigSentinel AI’s safe explanation boundary. Redact observations, pass only deterministic findings, validate structured output, and show that AI does not control the verdict.

### Phase G — Companion features

Add certificate monitoring, drift comparison, third-party resource inventory, API posture checks, and remediation guidance only after the MVP is stable.

### Phase H — Evidence and SIH demo

Create real test output, screenshots, benchmark results, threat model, limitations, and a live demonstration using a target that the team owns or is authorized to assess.

## 16. SIH Demonstration Flow

Use a website owned by the team or a deliberately local lab website. Do not scan an unrelated public website without authorization.

1. Open ConfigSentinel AI.

1. Select **Website Security Check**.

1. Enter the authorized lab URL.

1. Confirm authorization.

1. Start the passive scan.

1. Show HTTPS/TLS and redirect results.

1. Expand a failed security-header finding.

1. Show exact evidence and severity.

1. Show an unknown result if a check is unavailable.

1. Open remediation guidance.

1. Explain that no change is automatically applied.

1. Export the evidence report.

1. Fix one header in the lab website.

1. Re-run the scan and show the finding becoming resolved.

1. Show the before/after comparison.

The strongest judge narrative is:

> “We are not claiming that one scan proves a website is perfectly secure. We are showing a transparent, repeatable posture assessment that tells an operator what was observed, why it matters, what remains unknown, and what can be reviewed next.”

## 17. Acceptance Criteria

The feature is MVP-complete when:

- only `http` and `https` targets are accepted,

- authorization confirmation is required,

- SSRF protections block private targets by default,

- redirect destinations are revalidated,

- timeouts and response-size limits are enforced,

- TLS, HTTPS, headers, cookies, redirects, mixed content, and selected resource checks work,

- each result has deterministic rule IDs and evidence,

- unknown states are explicit,

- score calculations are reproducible,

- raw secrets and unnecessary page data are redacted,

- API ownership is server-derived,

- frontend results and errors are connected to real API responses,

- exports include limitations,

- offline local mode needs no external API key,

- unit, API, E2E, accessibility, and security tests pass,

- the feature is documented in `START_HERE.md` and `docs/SIH_EVIDENCE.md`.

## 18. Limitations to State Clearly

The website posture checker cannot prove that a site has no vulnerabilities. It does not replace a professional penetration test, secure code review, dependency audit, threat model, or authenticated business-logic assessment.

It does not prove that a website is free from compromise, that its backend is secure, that its dependencies are safe, or that it complies with a legal or regulatory framework. It reports only what the configured safe checks observed at the scan time.

## References

[1]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html "OWASP HTTP Headers Cheat Sheet"

[2]: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html "OWASP Transport Layer Security Cheat Sheet"

[3]: https://owasp.org/www-project-web-security-testing-guide/latest/ "OWASP Web Security Testing Guide"

[4]: https://developer.mozilla.org/en-US/docs/Web/Security "MDN Web Security"

[5]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy "MDN Content-Security-Policy"

[6]: https://developer.mozilla.org/en-US/observatory "MDN HTTP Observatory"

# 19. Complete ConfigSentinel AI Feature Expansion Catalog

This section defines the broader product roadmap beyond the Website Security Posture Checker. Each feature is described as a product capability, not merely as a UI label. The implementation must preserve ConfigSentinel AI’s core principles: deterministic findings, evidence-backed explanations, explicit uncertainty, least privilege, human approval, and no unsafe autonomous changes.

## 19.1 Configuration Drift Detection

### Purpose

Configuration Drift Detection compares a new audit snapshot with a previous trusted snapshot. It identifies added, removed, and changed configuration lines or normalized security facts, then shows which controls and risk levels were affected.

### User flow

The operator selects two authorized snapshots, chooses a comparison mode, and receives a report containing new findings, resolved findings, unchanged findings, changed evidence, score movement, and parser/rule-pack differences.

### Implementation requirements

Store snapshot IDs, input hashes, parser versions, rule-pack versions, timestamps, asset IDs, and audit statuses. Compare normalized representations as well as raw-line evidence where safe. Never claim that an unchanged score means no operational change.

### Acceptance criteria

The comparison must be deterministic, reproducible, explainable, exportable, and protected by workspace ownership. Tests must cover changed parser versions, changed control packs, missing snapshots, duplicate snapshots, and cross-workspace access.

## 19.2 Continuous Monitoring and Scheduled Campaigns

### Purpose

Continuous Monitoring schedules authorized network, website, API, or policy checks and alerts operators when posture changes, certificates approach expiry, or findings remain unresolved.

### User flow

An authorized user chooses assets, check frequency, ownership, notification policy, retention, and thresholds. The system runs the campaign, records each result, and produces alerts only when a meaningful change occurs.

### Implementation requirements

Use a scheduler or queue with idempotent jobs, concurrency limits, timeout handling, retry policy, pause/resume, expiration, and audit logging. A failed scan must be labeled as unavailable and must not become a pass.

### Acceptance criteria

Tests must prove duplicate jobs are prevented, a paused campaign does not run, failures are visible, rate limits are honored, and the scheduler cannot reach unauthorized or private targets.

## 19.3 Asset and Infrastructure Inventory

### Purpose

The Asset Inventory gives operators one view of routers, switches, firewalls, websites, APIs, applications, cloud exports, and Kubernetes resources.

### Data fields

Each asset may include an asset ID, display name, type, environment, owner, business unit, criticality, exposure, workspace, tags, last audit, posture score, open findings, next review date, and data-retention policy.

### Security requirements

Assets must be workspace-scoped. Ownership and criticality changes must be audited. Users must not be able to assign themselves elevated ownership or view another workspace’s assets.

## 19.4 Risk Dashboard and Prioritization

### Purpose

The Risk Dashboard groups findings by asset, severity, age, owner, framework, exposure, and remediation state.

### Transparent risk model

Risk should be calculated from documented factors such as deterministic severity, asset criticality, internet exposure, evidence confidence, finding age, recurrence, and due date. The score must show the contributing factors rather than hiding them behind a black-box model.

### Acceptance criteria

The same findings and same metadata must produce the same ranking. AI may explain the ranking but may not silently change it.

## 19.5 Compliance Framework Mapping

### Purpose

Map technical findings to control families from CIS Benchmarks, NIST Cybersecurity Framework, ISO/IEC 27001, OWASP ASVS, CERT-In guidance, and organization-specific policies.

### Important limitation

The product should say “mapped to,” “supports assessment against,” or “provides evidence for.” It must not claim official certification or legal compliance based only on automated checks.

### Implementation requirements

Framework mappings must be versioned, reviewable, and linked to finding IDs and rule-pack versions. Reports should show mapped, not-applicable, pending-review, and unassessed control states.

## 19.6 Policy-as-Code and Custom Policy Builder

### Purpose

Organizations should be able to define local rules such as “Telnet must never be enabled,” “production websites must use HSTS,” or “critical assets must be reviewed every 30 days.”

### Governance

Custom policies require schema validation, test fixtures, versioning, approval, activation, rollback, and an owner. A policy must not become active merely because it was uploaded.

### Testing

Each policy needs positive, negative, unknown, and not-applicable fixtures. Invalid or ambiguous policies must fail closed and remain inactive.

## 19.7 Exception and Risk-Acceptance Workflow

### Purpose

Allow a team to document why a finding cannot be fixed immediately while preserving accountability.

### Required fields

Exception ID, finding ID, business justification, compensating control, owner, approver, creation date, expiry date, review date, status, and evidence attachment metadata.

### Safety rules

Exceptions expire automatically, cannot remove historical findings, and cannot silently change the deterministic verdict. Expired exceptions return to the review queue.

## 19.8 Proof-Carrying Audit and Evidence Packages

### Purpose

Create exportable artifacts that another reviewer can verify independently.

### Package contents

Audit ID, target/asset identity, input hash, evidence-span hashes, parser version, rule-pack version, findings, timestamps, approval events, remediation preview metadata, verification requirement, and limitations.

### Privacy

Raw secrets, credentials, authorization headers, and unnecessary configuration excerpts must be excluded or redacted.

## 19.9 Secure Report Sharing

### Purpose

Allow a reviewer to receive claims without receiving the original raw configuration.

### Implementation requirements

Use authenticated access, expiration, revocation, workspace scope, minimal evidence, optional encryption, and access logging. Shared reports must not reveal raw secrets or private infrastructure details.

## 19.10 API Security Posture Checker

### Purpose

Assess an authorized API endpoint for HTTPS, certificate posture, CORS signals, cache controls, rate-limit signals, authentication challenge behavior, and safe error disclosure.

### Scope boundary

The passive mode must not brute-force credentials, test arbitrary payloads, exploit endpoints, or alter server data. Authenticated testing requires a separate explicit authorization workflow.

## 19.11 Security-Header Drift Monitoring

### Purpose

Monitor authorized websites for changes to CSP, HSTS, cookie attributes, TLS metadata, redirects, and other observable security headers.

### Output

Show previous value, current value, timestamp, rule ID, severity, evidence, and whether the change increases or decreases posture. Drift is an assurance signal, not automatically a confirmed vulnerability.

## 19.12 Certificate Expiry Monitoring

### Purpose

Track certificate validity windows and warn before expiry.

### Data protection

Store only domain, certificate fingerprint, issuer, validity window, and authorized ownership metadata. Never store private keys.

## 19.13 Third-Party Resource Inventory

### Purpose

List scripts, frames, stylesheets, images, fonts, and other external origins observed on an authorized website.

### Interpretation

Highlight unexpected origins, insecure schemes, and new dependencies. Do not call a third-party origin malicious solely because it is external.

## 19.14 Privacy and Cookie Posture

### Purpose

Summarize observable cookie flags, third-party status, SameSite behavior, consent-banner signals, and privacy-related headers.

### Limitation

Technical observations do not prove legal compliance, consent validity, or the absence of tracking. Reports must state this limitation.

## 19.15 Security Contact and Reporting Readiness

### Purpose

Check for `/.well-known/security.txt`, contact information, expiry metadata, and reporting instructions.

### Output

Show presence, parseability, expiration, contact type, and evidence. Do not treat the presence of `security.txt` as proof of secure engineering.

## 19.16 Dependency and Supply-Chain Posture

### Purpose

For an authorized source repository, inspect dependency manifests, lockfiles, known advisory matches, outdated packages, licenses, provenance, and dependency drift.

### Safety

Repository scanning requires explicit authorization and secret redaction. Never upload private source code to an external AI provider by default.

## 19.17 Secure Code Review Assistant

### Purpose

Allow developers to submit selected code or policy snippets for deterministic checks and bounded explanation.

### AI boundary

The assistant may explain a detected issue or suggest a review question. It must not assert exploitability without evidence, expose submitted secrets, or replace a professional code review.

## 19.18 Notifications and Integrations

### Supported integration categories

Email, Slack, Microsoft Teams, Jira, GitHub Issues, GitLab, and SIEM platforms may receive minimal finding notifications.

### Implementation requirements

Use encrypted connector credentials, least privilege, retry limits, idempotency keys, delivery status, redaction, and revocation. Notifications should link to authenticated reports instead of embedding raw configuration.

## 19.19 Ticket and Remediation Workflow

### Purpose

Convert a finding into a tracked work item with owner, due date, SLA, exception status, remediation state, and verification result.

### Closure rule

A ticket must not be marked resolved solely because a remediation preview was created. Closure requires a new deterministic audit or an authorized verification artifact.

## 19.20 Multi-Tenant Workspaces

### Purpose

Support multiple teams or organizations with strict isolation of assets, audits, findings, approvals, reports, connectors, and policies.

### Required controls

Server-derived workspace identity, database-level filtering, authorization tests, administrator boundaries, membership lifecycle, invitation security, and cross-tenant negative tests.

## 19.21 Advanced Roles and Governance

Recommended roles include operator, reviewer, security lead, auditor, administrator, and read-only viewer. Roles must be enforced at the API boundary, recorded in audit events, and configurable only by authorized administrators.

## 19.22 Immutable Governance Ledger

Record login events, scan requests, configuration submissions, rule-pack changes, approvals, rejections, exports, exceptions, policy changes, and administrative actions in an append-only, tamper-evident ledger.

The ledger should support integrity verification, timestamp ordering, retention policy, export, and restricted deletion. Correction events should be appended rather than silently rewriting historical decisions.

## 19.23 Natural-Language Security Reports

Generate executive, technical, and beginner-friendly explanations from deterministic findings. Every explanation must retain source finding IDs, rule versions, evidence references, and limitations. The AI must never alter status, severity, score, or approval state.

## 19.24 Finding Correlation and Root-Cause Grouping

Group related findings that share a likely root cause, such as weak transport configuration producing insecure TLS, missing HSTS, and unsafe redirects. Correlation must be labeled as an analytical grouping, not a new confirmed vulnerability.

## 19.25 Risk Trend Analytics

Show score history, open-risk aging, repeated findings, average remediation time, resolved findings, drift events, and unknown rates. Every chart must show the underlying sample size, date range, and calculation method.

## 19.26 What-If Analysis

Allow an operator to simulate a proposed remediation and calculate its expected posture effect without applying it. The output must be labeled `SIMULATION` and must never claim that a real deployment occurred.

## 19.27 Explainable Prioritization

Answer “What should we fix first?” using deterministic ranking factors: severity, exposure, criticality, evidence confidence, recurrence, due date, and dependency. AI may convert the factors into natural language but cannot invent a factor.

## 19.28 Cloud Security Posture Checks

For explicitly authorized AWS, Azure, or Google Cloud exports or read-only connections, assess IAM, public exposure, storage access, encryption, logging, network security groups, and backup posture.

Use least-privilege read-only credentials. Never request broad administrator permissions for a posture scan.

## 19.29 Kubernetes Posture Checks

Assess authorized manifests or exported cluster data for privileged containers, host networking, unsafe capabilities, exposed services, missing network policies, RBAC risks, image configuration, and missing resource limits.

Do not connect to a cluster without explicit authorization. A manifest scan and live-cluster scan must be separate modes.

## 19.30 Infrastructure-as-Code Scanning

Support Terraform, Kubernetes YAML, Dockerfiles, Ansible, and cloud templates. Findings should identify file, line, rule, severity, evidence, and remediation preview. Add pull-request checks with configurable thresholds.

## 19.31 Container Image Posture

Inspect authorized image metadata, base-image age, package advisories, exposed ports, user privileges, secrets, SBOM, and provenance. Do not claim an image is safe merely because no known advisory matched.

## 19.32 CI/CD Security Gate

Fail a build when critical findings exist, secrets are detected, unknown rates exceed configured limits, or required evidence is missing. Every gate failure must include a reproducible rule and evidence reference.

## 19.33 Offline Demonstration Mode

Provide a bundled local lab mode that works without internet access or external API keys. Clearly label bundled data as demo data. The mode must not imply that bundled fixtures represent production accuracy.

## 19.34 Import and Export Formats

Support JSON, YAML, CSV, HTML, and SARIF where appropriate. Preserve rule versions, evidence references, timestamps, limitations, and redaction state across conversions.

## 19.35 Accessibility-First Interface

Support keyboard navigation, visible focus, semantic headings, accessible labels, sufficient color contrast, screen-reader-compatible dialogs, responsive layouts, and accessible charts. Accessibility tests must run without silently hiding severe rules.

## 19.36 Localization

Add English and Hindi translations for dashboard labels, reports, remediation explanations, error messages, and SIH presentation mode. Test text expansion, date/number formatting, and screen-reader language attributes.

## 19.37 Guided Learning Mode

Provide beginner and technical explanations for findings, with safe examples and explicit warnings against applying changes without review. Use the same deterministic source finding in both modes.

## 20. Recommended Roadmap

Do not build every feature simultaneously. Use dependency-aware delivery:

| Release | Features | Reason |
| --- | --- | --- |
| Release 1 | Website posture, API posture, drift comparison | Extends the core assurance model with high demo value |
| Release 2 | Asset inventory, risk dashboard, framework mapping | Creates a portfolio-level security view |
| Release 3 | Continuous monitoring, notifications, exceptions | Adds operational usefulness |
| Release 4 | Real identity, multi-tenant workspaces, ticket integrations | Enables enterprise governance |
| Release 5 | Cloud, Kubernetes, IaC, dependency, and container posture | Expands coverage across modern infrastructure |
| Release 6 | Analytics, localization, learning mode, advanced integrations | Improves adoption and scale |

For SIH, the most valuable first extension is the combination of **Website Security Posture Checker, Configuration Drift Detection, and Compliance Framework Mapping**. These features provide a coherent expansion without diluting the product’s evidence-first identity.

## 21. Overall Product Statement

> ConfigSentinel AI is an evidence-first security assurance platform that evaluates network configurations, websites, APIs, and infrastructure policies using deterministic controls, explains evidence clearly, tracks security drift, maps findings to recognized control families, and keeps remediation under accountable human review.

## 22. Cross-Feature Definition of Done

Every future feature must satisfy these conditions before release:

1. The feature has a documented problem, scope, threat model, and limitation.

1. The API contract and data model are versioned.

1. Authentication and workspace ownership are enforced server-side.

1. Secrets are redacted and never committed.

1. Findings are deterministic or clearly labeled as analytical suggestions.

1. Unknown and unavailable states are explicit.

1. UI actions are connected to real operations.

1. Unit, API, negative, E2E, accessibility, and security tests exist where applicable.

1. Reports contain evidence, timestamps, versions, and limitations.

1. The feature works in local no-key mode unless an external dependency is essential.

1. Operational logs contain request IDs but no secrets or unnecessary sensitive content.

1. Documentation, launcher behavior, `.env.example`, CI, and deployment instructions agree with the implementation.

1. The feature is pushed through a reviewed Git commit with reproducible verification output.

1. Any real-world accuracy or impact claim is backed by approved data, sample size, method, date, and limitation.
