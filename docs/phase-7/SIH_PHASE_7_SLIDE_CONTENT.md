# VEYRONIX — ConfigSentinel AI
## SIH 2026 Presentation Content

### Deck direction

Use a dark navy cybersecurity visual language with cyan and electric-violet accents. Keep each slide focused on one decision: why the problem matters, what VEYRONIX built, why it is trustworthy, and how it can scale. Use a clean architecture diagram and a terminal-style evidence panel rather than dense paragraphs.

## Slide 1 — Title

**VEYRONIX presents ConfigSentinel AI**

**Evidence-grounded, vendor-neutral network security compliance**

Smart India Hackathon 2026 | Software | Problem Statement 26155

Team: VEYRONIX

Speaker note: Open with the one-sentence promise: “We turn heterogeneous network configurations into explainable, evidence-backed compliance decisions and safe remediation previews.”

## Slide 2 — The problem

**Network security breaks at the configuration boundary**

Organizations operate firewalls, routers, switches, cloud controls, SASE platforms, and white-box networking from different vendors. Each uses different syntax, semantics, and security defaults. Manual audits are slow, inconsistent, difficult to reproduce, and unsafe to remediate at scale.

**Core challenge:** Detect violations across heterogeneous configurations, map them to recognized standards, explain the evidence, and adapt when unfamiliar syntax appears.

Callout: “A generic chatbot is not enough. A secure audit needs deterministic evidence.”

## Slide 3 — Our solution

**ConfigSentinel AI: a hybrid compliance SDK and CLI**

1. Securely ingest and redact configuration files.
2. Detect vendor and parse configuration into a canonical security model.
3. Evaluate deterministic controls against an extensible control pack.
4. Map findings to compliance frameworks and show exact evidence.
5. Use a guarded LLM only for explanation and unknown-syntax assistance.
6. Generate a human-reviewed, non-executable remediation preview.

Value proposition: Vendor-neutral normalization + deterministic verdicts + evidence-grounded AI + safe operator control.

## Slide 4 — End-to-end architecture

**One pipeline from raw configuration to defensible decision**

Diagram nodes:

User / CI pipeline → Secure ingestion boundary → Vendor detection and parser plugins → Canonical security model → Deterministic compliance engine → Findings and evidence → Framework mapping and report

Side branch from Findings and evidence → Guarded LLM copilot → Structured explanation / review-required classification

Side branch from Failed findings → Remediation planner → Non-executable preview → Human approval outside the system

Architecture labels: SHA-256 provenance, secret redaction, explicit UNKNOWN status, schema validation, no live device connection.

## Slide 5 — What is implemented today

**A working, testable foundation—not a concept demo**

| Capability | Current implementation |
|---|---|
| Parsers | Cisco IOS/IOS XE, Juniper Junos, conservative generic-firewall subset |
| Controls | Seven deterministic network-hardening controls |
| Security statuses | PASS, FAIL, UNKNOWN, REVIEW_REQUIRED, NOT_APPLICABLE |
| Ingestion | UTF-8 validation, size/line limits, path safety, SHA-256 hash, quarantine, redaction |
| LLM | Provider-agnostic, bounded, structured-output, fail-closed gateway |
| Remediation | Deterministic Cisco/Juniper preview templates with rollback notes |
| Interfaces | Python SDK, CLI, module entry point, OpenAPI-ready contracts |

## Slide 6 — Trust and safety by design

**AI assists interpretation; it does not decide or act alone**

**Deterministic authority:** Compliance verdicts come from tested control logic and parser evidence.

**LLM trust boundary:** Inputs are redacted and bounded; outputs are schema-validated; provider failure falls back safely.

**Fail-closed semantics:** Unknown syntax is never silently compliant.

**No excessive agency:** The prototype has no device connection or command-execution path.

**Auditability:** Every audit carries input hash, audit ID, evidence spans, control-pack version, and remediation metadata.

Reference callouts: NIST Cybersecurity Framework 2.0 [1] and OWASP GenAI LLM Top 10 2026 [2].

## Slide 7 — Live demo storyline

**Three minutes from insecure configuration to safe action plan**

1. Upload `edge.conf` containing `transport input telnet`.
2. Ingestion validates the file and produces an input hash.
3. Cisco parser extracts the VTY evidence span.
4. Control engine reports `NET-MGMT-TELNET-001: FAIL / CRITICAL`.
5. Dashboard shows the exact source line and expected secure state.
6. CLI generates a preview containing `transport input ssh`.
7. Safety banner confirms: no device connection and no execution.
8. Show an unfamiliar command becoming `REVIEW_REQUIRED`, not falsely passing.

Demo evidence: current regression suite contains 24 passing tests across contracts, parsers, controls, ingestion, redaction, remediation, CLI safeguards, and LLM fallback.

## Slide 8 — SDK and extensibility

**Build once; integrate everywhere**

The Python SDK exposes typed audit requests, results, findings, evidence spans, control definitions, parser plugins, secure ingestion, LLM explanations, and remediation bundles.

Integration surfaces:

- Python applications and notebooks.
- CLI automation and scheduled audits.
- CI/CD and GitOps compliance gates.
- SIEM/SOAR and CMDB integrations.
- Future vendor and framework plugins.

Extensibility rule: Every new parser or control must include secure/insecure fixtures, applicability rules, evidence tests, and regression coverage.

## Slide 9 — Impact and scale

**From hackathon prototype to operational security capability**

**For network teams:** Reduce manual review time and standardize findings across vendors.

**For auditors:** Produce reproducible, evidence-linked reports instead of opaque model answers.

**For security leaders:** Prioritize high-risk misconfigurations and track remediation readiness.

**For enterprises:** Extend the same canonical model to cloud controls, drift detection, GitOps, topology-aware risk, and continuous compliance.

Success metrics for pilot evaluation:

- Parser precision and recall by vendor fixture.
- Control verdict accuracy against manually verified expected outcomes.
- Evidence coverage for every FAIL result.
- Unknown/review rate for unsupported syntax.
- Audit latency and reproducibility across repeated runs.

## Slide 10 — Roadmap and team execution

**A safe path from MVP to enterprise adoption**

Now: Secure ingestion, three parser families, seven controls, guarded LLM, remediation previews, SDK/CLI, 24 passing tests.

Next: More vendor plugins, larger versioned control packs, framework crosswalks, dashboard, report exports, and active-learning review workflows.

Scale: GitOps gates, drift detection, topology and attack-path analysis, SIEM/SOAR, SSO/multi-tenancy, private inference, continuous compliance, signed plugins.

Team roles: security/control engineering; parser and canonical model; AI/LLM safety; SDK/backend; demo, testing, and documentation.

## Slide 11 — Why VEYRONIX should win

**The difference is trust at the point of action**

Many solutions can generate a security explanation. ConfigSentinel AI combines:

- Multi-vendor configuration understanding.
- Standards-oriented deterministic controls.
- Exact evidence for every finding.
- Explicit uncertainty instead of false confidence.
- LLM assistance without uncontrolled agency.
- Safe remediation previews that respect human change control.

Closing line: “ConfigSentinel AI makes network compliance explainable, portable, and safe to operationalize.”

## Slide 12 — Closing and references

**VEYRONIX | ConfigSentinel AI**

**Secure every configuration. Trust every finding.**

Problem Statement: SIH 2026 PS 26155

Repository: github.com/harshitgarg10042008-oss/VEYRONIX

References:

[1] NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
[2] OWASP GenAI LLM Top 10 2026: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
[3] Official SIH 2026 problem statements: https://www.sih.gov.in/sih2026PS

Speaker note: End with the product promise, then invite judges to see the three-minute live workflow.
