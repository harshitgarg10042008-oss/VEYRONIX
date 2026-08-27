# ConfigSentinel AI — SIH 26155 Execution Checklist

> **VEYRONIX milestone status:** Repository Phases 1–7 are complete. Phase 7 delivered the SIH presentation and submission package. The implementation sequence is re-baselined so the next coding milestone is **Phase 8 — Framework Mapping and Reporting**, because the original checklist’s LLM-copilot work was already delivered in the earlier SDK/LLM milestone.

## VEYRONIX milestone map

| Repository phase | Status | Scope |
|---:|---|---|
| 1 | COMPLETE | Foundation, standards, licensing, provenance, and threat model |
| 2 | COMPLETE | Core SDK contracts and guarded LLM gateway |
| 3 | COMPLETE | Canonical model, vendor parsers, and deterministic controls |
| 4 | COMPLETE | Secure ingestion, validation, hashing, quarantine, and redaction |
| 5 | COMPLETE | Safe remediation previews and guarded CLI runner |
| 6 | COMPLETE | Packaging, wheel/sdist distribution, CI, and end-user docs |
| 7 | COMPLETE | SIH presentation deck and submission documentation |
| 8 | COMPLETE | Framework registry, mapping provenance, JSON/Markdown reports, reconciliation, and CLI report flags |
| 9 | COMPLETE (local MVP) | Interactive unknown-syntax queue, proposals, review authorization, versioned mappings, fixtures, and audit trail |
| 10 | PLANNED | Remediation safety hardening and approval workflows |
| 11 | PLANNED | SDK ecosystem, integrations, and plugin governance |
| 12 | PLANNED | Security, performance, reliability, and production hardening |
| 13 | PLANNED | Final production-readiness gate |

## Phase 8 acceptance gate

- [x] Versioned framework registry is implemented.
- [x] Control-to-framework mappings include source URL, version, status, and confidence.
- [x] Unmapped controls are visibly marked `UNVERIFIED`.
- [x] JSON and Markdown reports contain the same finding totals as the audit result.
- [x] Reports include evidence, expected state, observed state, severity, status, and input hash.
- [x] CLI supports framework selection and report output without changing deterministic verdicts.
- [x] Existing Phase 1–7 regression tests remain green.
- [x] Phase 8 fixtures cover mapped, unmapped, unknown, and multi-framework cases.
- [x] No report path exposes unredacted secrets or enables device execution.

**Phase 8 validation:** 30 tests passed; Python compilation passed; report smoke test passed with secret-redaction assertions.

---

**Problem statement:** SIH 2026 — 26155
**Product:** ConfigSentinel AI
**Purpose:** Build a secure, evidence-grounded, multi-vendor network security compliance auditor with an LLM copilot and reusable SDK.
**GitHub policy:** This file is local only. No GitHub push, commit, branch, pull request, or repository change is performed by Manus.

## Phase count

The implementation has **14 execution phases**, numbered **Phase 0 through Phase 13**. The project reaches **100% MVP readiness only after Phase 13 passes**. After that, the roadmap contains **30 expansion features** that must not destabilize the judged MVP.

| Phase | Name | Readiness contribution |
|---:|---|---:|
| 0 | Team alignment and acceptance contract | Scope foundation |
| 1 | Research, licensing, and threat model | Safety foundation |
| 2 | Repository, CI, contracts, and skeleton | Reproducibility foundation |
| 3 | Ingestion and secret protection | Safe input foundation |
| 4 | Vendor detection and parser plugins | Multi-vendor capability |
| 5 | Canonical normalization | Vendor-neutral model |
| 6 | Deterministic compliance engine | Core security correctness |
| 7 | Framework mapping and reporting | Audit usability |
| 8 | LLM copilot and retrieval guardrails | Safe AI capability |
| 9 | Unknown-syntax learning loop | Dynamic adaptation |
| 10 | Remediation planner and safety controls | Actionable output |
| 11 | SDK, CLI, and integration surface | Reusability |
| 12 | Security, performance, and reliability hardening | Production confidence |
| 13 | Demo, documentation, and judging package | Competition readiness |

---

## Global definition of done

- [ ] The product supports exactly the selected MVP vendor/platform set, with capability boundaries documented.
- [ ] The product never marks unsupported or unparseable configuration as compliant.
- [ ] Every finding contains control ID, status, severity, confidence, evidence span, observed state, expected state, and rationale.
- [ ] The deterministic engine remains usable when the LLM is unavailable.
- [ ] No raw secrets are sent to the LLM, written to logs, or displayed in reports.
- [ ] No remediation command can execute against a live device in the MVP.
- [ ] Dashboard, REST API, CLI, and SDK return equivalent results for the same audit.
- [ ] Every control has secure, insecure, edge, malformed, and unsupported fixtures as applicable.
- [ ] The clean-install path works on a new machine using documented commands.
- [ ] The judging demo works with an offline or cached fallback path.
- [ ] All high and critical security findings are fixed or formally accepted with compensating mitigation.

---

## Phase 0 — Team alignment and acceptance contract

### Deliverables

- [ ] Product name, one-sentence value proposition, and target user agreed.
- [ ] Exact SIH requirements copied into an internal requirements matrix.
- [ ] MVP vendors selected: Cisco IOS/IOS XE, Juniper Junos, and one firewall format.
- [ ] Initial framework scope selected: CIS-aligned controls plus crosswalks to NIST SP 800-53, DISA STIG, and ISO/IEC 27001 concepts.
- [ ] Initial control count fixed at approximately 30–50 high-confidence controls.
- [ ] Three-minute demo story approved.
- [ ] Team roles assigned and backup owners named.
- [ ] Definition of 100% MVP readiness approved.
- [ ] Stable demo branch/process defined locally; no automatic GitHub push configured.

### Exit gate

- [ ] Every team member can explain the pipeline: ingest → redact → detect → parse → normalize → evaluate → explain → report.
- [ ] The team agrees that `UNKNOWN` is safer than an unsupported `PASS`.

---

## Phase 1 — Research, licensing, and threat model

### Deliverables

- [ ] Official SIH statement stored with access date and source URL.
- [ ] NIST CSF 2.0, NIST AI RMF, CIS Benchmarks, OpenConfig, Batfish, and OWASP GenAI references recorded.
- [ ] Control-source and licensing register created.
- [ ] Dataset and fixture provenance register created.
- [ ] Threat model completed for files, APIs, users, plugins, retrieval corpus, model, reports, and remediation.
- [ ] Data-retention and deletion policy written.
- [ ] Secret categories defined: passwords, tokens, private keys, SNMP communities, certificates, IPs, and organization identifiers.
- [ ] Abuse cases documented: prompt injection, malicious configuration text, oversized file, path traversal, SSRF, output injection, privilege escalation, malicious plugin, and unsafe remediation.
- [ ] Privacy boundary approved: what may enter the LLM, what must be redacted, and what is retained.

### Exit gate

- [ ] Cybersecurity lead and technical lead sign off on threat model, licensing, data flow, and safe-operation boundaries.

---

## Phase 2 — Repository, CI, contracts, and skeleton

### Deliverables

- [ ] Monorepo created locally.
- [ ] Backend, frontend, worker, core packages, plugins, controls, fixtures, tests, and docs directories created.
- [ ] Python and Node dependency lockfiles pinned.
- [ ] Docker Compose starts API, frontend, database, and optional worker.
- [ ] Environment example contains no real secrets.
- [ ] Pre-commit hooks configured.
- [ ] CI workflow runs tests, lint, type checks, SAST, dependency scan, and build.
- [ ] Pydantic domain models and JSON Schemas defined.
- [ ] Database migrations configured.
- [ ] OpenAPI skeleton available.
- [ ] Health and readiness endpoints implemented.
- [ ] Local README includes setup, test, run, and reset commands.

### Exit gate

- [ ] A new team member can clone/copy the local project, run one setup command, start the system, and pass the smoke test.

---

## Phase 3 — Ingestion and secret protection

### Deliverables

- [ ] Upload endpoint and CLI file input implemented.
- [ ] File-size, line-length, extension, MIME, encoding, and decompression limits implemented.
- [ ] Path traversal and unsafe filename handling tested.
- [ ] Input SHA-256 hash stored.
- [ ] Original file quarantined with controlled access.
- [ ] Secret redaction engine implemented.
- [ ] Redacted copy generated for parsing and LLM use.
- [ ] Evidence renderer masks sensitive spans.
- [ ] Canary-secret tests added to logs, prompts, database, and reports.
- [ ] Retention and deletion operations implemented.

### Exit gate

- [ ] Automated tests prove that known passwords, tokens, keys, and community strings never reach the LLM or unredacted logs.

---

## Phase 4 — Vendor detection and parser plugins

### Deliverables

- [ ] Plugin interface defined: detect, parse, normalize, capabilities, fixtures.
- [ ] Cisco IOS/IOS XE detection and parser implemented.
- [ ] Juniper Junos detection and parser implemented.
- [ ] Third firewall parser selected and implemented.
- [ ] Line-number and source-span tracking implemented.
- [ ] Parser warnings and unsupported lines preserved.
- [ ] Parser capability manifest displayed.
- [ ] Vendor/version manual override available.
- [ ] Secure, insecure, mixed, malformed, and unsupported fixtures added per platform.
- [ ] Parser output is deterministic.

### Exit gate

- [ ] Known fixtures parse correctly, unsupported sections are explicit, and no parser failure is silently converted to compliance.

---

## Phase 5 — Canonical normalization

### Deliverables

- [ ] Canonical schema defined for management, AAA, logging, NTP, SNMP, interfaces, services, cryptography, ACLs, routing, VPN, exceptions, and unknown blocks.
- [ ] OpenConfig-inspired names used where appropriate without claiming exhaustive OpenConfig coverage.
- [ ] Vendor-to-canonical adapters implemented.
- [ ] Pydantic and JSON Schema validation implemented.
- [ ] Schema versioning and migration policy documented.
- [ ] Equivalent Cisco and Junos security intent maps to equivalent canonical fields.
- [ ] Unknown concepts retain raw evidence and context.
- [ ] Normalization coverage report implemented.

### Exit gate

- [ ] Cross-vendor equivalence tests pass for the selected security concepts.

---

## Phase 6 — Deterministic compliance engine

### Deliverables

- [ ] Declarative versioned control-pack format implemented.
- [ ] Control IDs, title, intent, severity, applicability, evidence query, remediation template, references, and tests defined.
- [ ] 30–50 high-confidence controls implemented.
- [ ] Secure management controls implemented.
- [ ] AAA and password controls implemented.
- [ ] Logging and NTP controls implemented.
- [ ] SNMP and cryptography controls implemented.
- [ ] Unused-service and interface controls implemented.
- [ ] ACL and routing-protection controls implemented.
- [ ] Applicability and `NOT_APPLICABLE` handling implemented.
- [ ] `PASS`, `FAIL`, `NOT_APPLICABLE`, `UNKNOWN`, and `REVIEW_REQUIRED` semantics implemented.
- [ ] Severity and risk-scoring logic documented.
- [ ] Positive, negative, edge, and unknown fixtures added for every control.
- [ ] Held-out evaluation set kept separate from development fixtures.

### Exit gate

- [ ] High-severity controls achieve at least 95% precision and selected-control recall reaches at least 90% on the held-out set.
- [ ] No high-severity finding lacks deterministic evidence.

---

## Phase 7 — Framework mapping and reporting

### Deliverables

- [ ] Versioned framework crosswalk implemented.
- [ ] Source URL, control identifier, version, and mapping confidence stored.
- [ ] Unsupported or unverified mappings visibly marked.
- [ ] Audit score explains evaluated versus unknown controls.
- [ ] Finding dashboard supports severity, status, vendor, framework, and device filters.
- [ ] Exact evidence lines highlighted.
- [ ] Expected secure state displayed.
- [ ] Observed state displayed.
- [ ] Remediation rationale displayed.
- [ ] Executive summary implemented.
- [ ] Technical report implemented.
- [ ] JSON export implemented.
- [ ] Markdown/PDF export implemented.
- [ ] Audit comparison and trend view implemented.
- [ ] Report totals reconcile with individual findings.

### Exit gate

- [ ] Dashboard, API, CLI, and exported report show the same findings and totals.

---

## Phase 8 — LLM copilot and retrieval guardrails

### Deliverables

- [ ] Provider-agnostic LLM adapter implemented.
- [ ] Live model selection is configurable; no model ID is hardcoded as a security dependency.
- [ ] Narrow LLM tasks defined: vendor hypothesis, unknown command analysis, normalized-field suggestion, explanation, remediation draft, and report narration.
- [ ] Strict JSON Schemas implemented with required fields and no extra properties.
- [ ] Approved retrieval corpus created with provenance, version, checksum, and license metadata.
- [ ] Prompt templates versioned.
- [ ] Configuration is clearly delimited as untrusted data.
- [ ] Prompt injection defenses tested.
- [ ] Output validation and confidence gates implemented.
- [ ] LLM timeouts, retries, rate limits, and cost limits implemented.
- [ ] Deterministic fallback works when LLM is unavailable.
- [ ] Model ID, prompt version, retrieval sources, and timestamps logged without secrets.
- [ ] Model-card-style limitations and evaluation record created.

### Exit gate

- [ ] LLM cannot create a compliance finding without deterministic evidence or reviewed mapping.
- [ ] Malformed, low-confidence, unsafe, or unexpected outputs are rejected or quarantined.

---

## Phase 9 — Interactive unknown-syntax learning loop

### Deliverables

- [ ] Unknown syntax queue implemented.
- [ ] Context window and source-span display implemented.
- [ ] LLM proposal includes confidence, interpretation, normalized concept, and evidence needed.
- [ ] Reviewer can approve, reject, or defer.
- [ ] Approval requires authorization.
- [ ] Approved mapping generates a regression fixture.
- [ ] Parser/rule update is versioned.
- [ ] Two-person review or reviewer-plus-automated-test policy implemented.
- [ ] Audit trail records who approved what and when.
- [ ] Re-run shows the change in finding status.

### Exit gate

- [ ] A previously unknown command can be reviewed and added through the plugin/control workflow without editing the core engine.

---

## Phase 10 — Remediation planner and safety controls

### Deliverables

- [ ] Remediation templates linked to control IDs.
- [ ] Before/after configuration diff implemented.
- [ ] Dependency and ordering warnings implemented.
- [ ] Rollback notes generated.
- [ ] Change-ticket or export format implemented.
- [ ] Human approval state implemented.
- [ ] Unsafe commands blocked by static checks.
- [ ] No live device credentials stored in the MVP.
- [ ] No shell execution from model output.
- [ ] No automatic device changes.

### Exit gate

- [ ] The system can safely show a remediation preview, but there is no code path that applies it to a live device.

---

## Phase 11 — SDK, CLI, and integration surface

### Deliverables

- [ ] Python SDK package created.
- [ ] Typed client methods implemented for audit, findings, reports, controls, and learning records.
- [ ] CLI implemented for local file audit, JSON export, and report generation.
- [ ] OpenAPI is the source of truth for remote clients.
- [ ] TypeScript client or SDK generated/implemented.
- [ ] Plugin registration contract documented.
- [ ] Local parsing mode and remote API mode documented.
- [ ] CI/CD integration example implemented.
- [ ] SDK quick-start example tested from a clean environment.
- [ ] SDK versioning and changelog established.

### Exit gate

- [ ] The same fixture produces equivalent findings through the dashboard, REST API, CLI, and SDK.

---

## Phase 12 — Security, performance, and reliability hardening

### Deliverables

- [ ] RBAC tested for analyst, reviewer, approver, and administrator roles.
- [ ] Authentication and session security tested.
- [ ] Authorization tested for cross-project report access.
- [ ] SAST and dependency scanning pass.
- [ ] Container scan passes with no unaccepted critical findings.
- [ ] API fuzz and contract tests pass.
- [ ] Prompt-injection and data-leakage red-team tests pass.
- [ ] Malicious-file and path-traversal tests pass.
- [ ] Plugin isolation tests pass.
- [ ] Rate limits and resource budgets tested.
- [ ] 1-, 10-, and 100-device benchmark measured.
- [ ] Structured logging and metrics implemented.
- [ ] Backup and restore tested.
- [ ] Failed job retry and partial audit recovery tested.
- [ ] Clean-room reproducibility test passes.
- [ ] Critical/high findings closed or formally accepted.

### Exit gate

- [ ] Security lead signs off and the application passes the release-blocker checklist.

---

## Phase 13 — Demo, documentation, and judging package

### Deliverables

- [ ] README includes problem, architecture, setup, limitations, controls, evaluation, and safety.
- [ ] Three-minute demo script rehearsed.
- [ ] Secure fixture prepared.
- [ ] Vulnerable multi-vendor fixture prepared.
- [ ] Unknown-command fixture prepared.
- [ ] Prompt-injection fixture prepared for the safety demonstration.
- [ ] SDK command prepared for live execution.
- [ ] Benchmark table prepared.
- [ ] Architecture diagram prepared.
- [ ] Impact statement prepared.
- [ ] Backup video recorded.
- [ ] Offline/cached fallback path tested.
- [ ] Three consecutive full rehearsals pass without code edits.
- [ ] No unsupported vendor or framework claims appear in slides or speech.
- [ ] Final judging machine is frozen and backed up.

### Exit gate: 100% MVP readiness

- [ ] Clean install works.
- [ ] Three platform families operate within documented coverage.
- [ ] Findings are evidence-backed and reproducible.
- [ ] Unknown syntax is quarantined or reviewed.
- [ ] LLM is guarded and optional to deterministic truth.
- [ ] SDK/API/dashboard/CLI parity passes.
- [ ] Security tests pass.
- [ ] Demo passes three times.

# 100% Readiness Scorecard

| Area | Weight | Evidence required | Score |
|---|---:|---|---:|
| Requirements and scope coverage | 10% | Requirements matrix and scope manifest | [ ] |
| Parser and normalization correctness | 20% | Fixture results and cross-vendor tests | [ ] |
| Compliance correctness and evidence | 20% | Precision/recall and evidence report | [ ] |
| LLM guardrails and learning loop | 10% | Red-team, schema, and review tests | [ ] |
| SDK/API/dashboard parity | 10% | Same-fixture equivalence report | [ ] |
| Security and privacy | 15% | Security test and sign-off report | [ ] |
| Testing, reproducibility, observability | 10% | CI, metrics, clean-room run | [ ] |
| Demo, documentation, and impact | 5% | Rehearsal record and final package | [ ] |
| **Total** | **100%** | **All release gates pass** | **[ ] / 100%** |

# Post-100% expansion checklist — 30 features

These features begin only after the 100% MVP gate passes. Each feature requires its own design, security review, tests, documentation, and rollback plan.

- [ ] 1. Additional vendor plugins.
- [ ] 2. AWS, Azure, and GCP security-group auditing.
- [ ] 3. Live read-only device collection.
- [ ] 4. GitOps/CI compliance gate.
- [ ] 5. Pull-request review bot.
- [ ] 6. Configuration drift detection.
- [ ] 7. Topology-aware reachability and ACL analysis.
- [ ] 8. Risk prioritization using asset criticality and exposure.
- [ ] 9. Safe attack-path simulation.
- [ ] 10. Compensating-control management.
- [ ] 11. Time-bound policy exception workflow.
- [ ] 12. Multi-tenant enterprise mode.
- [ ] 13. SSO and SCIM integration.
- [ ] 14. SIEM/SOAR integrations.
- [ ] 15. SBOM and supply-chain attestations.
- [ ] 16. Signed control packs.
- [ ] 17. Model and prompt evaluation console.
- [ ] 18. Active learning for unknown syntax.
- [ ] 19. Federated or private inference.
- [ ] 20. Offline small-model mode.
- [ ] 21. Multilingual reports.
- [ ] 22. Natural-language audit queries.
- [ ] 23. Security-aware configuration diff intelligence.
- [ ] 24. Vendor-specific remediation patch generation.
- [ ] 25. Policy-as-code marketplace.
- [ ] 26. CMDB/NetBox asset criticality integration.
- [ ] 27. Secrets-vault integration.
- [ ] 28. Continuous compliance scheduling.
- [ ] 29. Tamper-evident audit notarization.
- [ ] 30. Isolated developer sandbox for third-party plugins.

# Final pre-submission checklist

- [ ] The official SIH problem statement is correctly represented.
- [ ] The team has not promised support it cannot demonstrate.
- [ ] The project has a working dashboard, API, CLI, and SDK path.
- [ ] The LLM is an assistant, not the sole security authority.
- [ ] Exact evidence is visible for every important result.
- [ ] Unknown and unevaluated areas are visible.
- [ ] Sensitive data is redacted and retention is controlled.
- [ ] No model-generated command executes automatically.
- [ ] Control sources and licenses are documented.
- [ ] Held-out evaluation results are honest and reproducible.
- [ ] The fallback demo works without internet dependency.
- [ ] All team members know the 60-second and three-minute explanations.
- [ ] The local project folder is backed up before any manual GitHub push.
- [ ] The user, not Manus, performs any future GitHub commit or push.

## References

[1]: [Smart India Hackathon — SIH 2026 Problem Statements](https://www.sih.gov.in/sih2026PS)

[2]: [Center for Internet Security — CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)

[3]: [OpenConfig — Data Models](https://www.openconfig.net/projects/models/)

[4]: [Batfish — Network Configuration Analysis](https://batfish.org/)

[5]: [NIST — AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

[6]: [OWASP GenAI Security Project — LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

---

**Local file only. No GitHub operation has been performed.**
