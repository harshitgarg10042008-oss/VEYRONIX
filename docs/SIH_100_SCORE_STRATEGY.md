# VEYRONIX 100/100 SIH Upgrade Strategy

## Objective

Raise VEYRONIX from a technically strong local MVP to a **defensible 100/100 SIH submission** by proving a complete, safe, measurable user journey rather than adding cosmetic screens. A literal 100/100 cannot be guaranteed because SIH judging includes human factors, presentation, innovation, and impact evidence. This document defines the engineering target required to make a 100/100 claim credible.

## 100/100 acceptance rubric

| Category | Weight | Required evidence for full marks |
|---|---:|---|
| Problem relevance and field validation | 15 | Named target users, documented workflow pain, baseline measurements, stakeholder validation, and a clear problem-to-feature traceability matrix. |
| Novelty and differentiation | 15 | Evidence-first deterministic compliance, explicit unknown semantics, safe AI boundary, and comparison against existing approaches using measurable criteria. |
| Technical architecture and correctness | 20 | Modular SDK/API/UI architecture, authoritative metadata, consistent validation, versioned contracts, parser fixtures, deterministic scoring, and zero known critical defects. |
| End-to-end product completeness | 20 | One complete journey from source/change ingestion through audit, evidence, risk, remediation preview, independent approval, and verification. Every visible action is functional. |
| Security, privacy, and governance | 10 | Authenticated identity, RBAC, tenant/workspace isolation, secure secret handling, audit trail, rate limits, safe defaults, threat model, and negative security tests. |
| AI quality and responsibility | 5 | Bounded redacted AI flow for unknown findings, schema validation, failure handling, auditability, and proof that AI cannot change deterministic verdicts. |
| Reliability, testing, and release quality | 10 | Backend and browser tests, accessibility checks, coverage threshold, dependency/secret scanning, malformed-input tests, performance benchmark, and reproducible CI. |
| Impact, scale, and demo evidence | 5 | Representative benchmark, accuracy metrics, unsupported-syntax rate, operational time saved, adoption plan, and a concise evidence-led demo. |
| **Total** | **100** | **All criteria demonstrated in code, tests, artifacts, and live demo.** |

## Phase execution order

### Phase 1 — Baseline and contract

Freeze the current score, define acceptance criteria, inventory secrets and environment variables, remove accidental build artifacts, and establish a phase gate. This phase is complete only when the strategy and API-key documents are committed and pushed.

### Phase 2 — Correctness and authority

Make backend metadata authoritative everywhere. Fix vendor detection coverage for every supported parser, eliminate hardcoded counts and labels, unify browser/API limits and validation, define a documented severity-aware posture score, and synchronize product/API/control-pack version labels.

### Phase 3 — Complete safe operational workflow

Implement a GitOps-first workflow because it preserves the local-first safety model. The user should be able to inspect a change, audit the changed configuration, view evidence, generate a structured remediation diff, request approval, record an independent reviewer decision, and run post-change verification. Governance must be exposed through API/UI rather than CLI-only.

### Phase 4 — Bounded AI copilot

Expose a controlled explanation/classification path only for `UNKNOWN` or review-required findings. Send redacted, bounded evidence; validate structured output; retain deterministic status as authoritative; show provider failures; and record whether AI was used. AI remains optional and disabled by default.

### Phase 5 — Production security and operations

Add identity-backed authentication, role-based authorization, workspace/tenant isolation, durable audit events, rate limiting, secure deployment profile, secret-manager integration points, retention policy, backup/recovery, request IDs, and explicit local-only fail-safe mode. The shared bearer token may remain as a development fallback but cannot be the production auth model.

### Phase 6 — Domain depth and measurable impact

Expand controls and vendor semantics, build a versioned fixture matrix, measure accuracy and unsupported syntax, benchmark throughput and memory, document false positives/negatives, and produce an impact report showing operational value.

### Phase 7 — Automated quality gates

Add browser E2E tests, accessibility checks, coverage thresholds, dependency and secret scanning, parser fuzz/property tests, API contract tests, benchmark gates, bundle-size checks, and release validation. No phase is complete unless its acceptance tests pass.

### Phase 8 — Final SIH evidence pack

Produce the architecture diagram, threat model, control matrix, benchmark report, stakeholder/problem validation, demo fixture, limitations, deployment guide, API-key guide, and final scorecard. Run the entire clean-room verification sequence and push the final tagged release.

## Phase gate rule

Every phase must end with: implementation, tests, documentation, clean diff review, a meaningful commit, and a push to the selected GitHub repository. A phase is not considered complete merely because the code compiles.

## Non-negotiable product principles

The deterministic engine remains authoritative. `UNKNOWN` never becomes `PASS` because an AI model provides an explanation. Remediation remains non-executable unless a separately designed and independently reviewed device-application service is introduced. Sensitive configuration data must remain local by default, and every external data flow must be explicit, opt-in, bounded, and documented.

## Current baseline

The repository currently has a real local audit path and a broad Python test suite, but it lacks a complete authenticated multi-user product, browser E2E coverage, a connected approval/verification journey, field-impact evidence, and production deployment controls. The starting score is **67/100** under the strict audit documented in `SIH_PROJECT_AUDIT_REPORT.md`.
