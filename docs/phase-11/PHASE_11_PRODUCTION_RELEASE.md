# Phase 11 — Final Deployment and Production Release Documentation

**Status:** Complete for release documentation

**Product:** ConfigSentinel AI

**Team:** VEYRONIX

**Current package:** `configsentinel-sdk 0.3.0`

## Release posture

The current release is a local, offline-capable SDK and CLI. It is suitable for controlled evaluation, package installation, and authorized configuration review. It is **not** a production multi-tenant service yet: it has no authenticated API, database-backed tenancy, live-device connector, automatic remediation, distributed worker, or organization-wide RBAC. This document defines the deployment path and release gates without claiming those capabilities are already implemented.

## Supported release modes

| Mode | Intended use | Status |
|---|---|---|
| Wheel installation | Local analyst workstation or CI runner | Supported and validated |
| Source installation | Development and controlled internal review | Supported |
| Offline CLI | Sensitive configuration review without provider calls | Supported |
| LLM-assisted local review | Optional explanation of redacted data | Supported with configured provider and guardrails |
| Hosted API service | Centralized enterprise deployment | Future phase; requires identity, tenancy, persistence, and isolation |
| Live device remediation | Automatic changes to network devices | Not supported; intentionally absent |

## Release gates

Before publishing a release, the release owner must confirm:

- The repository is clean and the version in `pyproject.toml` matches `configsentinel.__version__`.
- `python -m pytest` passes with no skipped security tests.
- `python -m compileall -q src tests examples` passes.
- Both wheel and source distribution build successfully.
- The wheel installs in a clean Python 3.11 and 3.12 environment.
- `configsentinel --help` and `python -m configsentinel --help` work after installation without `PYTHONPATH`.
- A redacted configuration audit produces reproducible input metadata and evidence-linked findings.
- Reports contain no test secrets or private configuration content.
- Remediation output remains preview-only and non-executable.
- The changelog, security policy, README, user guide, and release notes agree on supported scope.
- The release artifact checksum is recorded by the release owner.

## Clean installation

```powershell
py -3.12 -m venv .venv-release-test
.\.venv-release-test\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .\dist\configsentinel_sdk-0.3.0-py3-none-any.whl
configsentinel --help
python -m configsentinel --help
python -m pip show configsentinel-sdk
deactivate
```

## Operational runbook

Analysts should copy configuration files only from authorized sources, keep them in a protected local workspace, run the secure ingestion path, and inspect evidence before sharing a report. The operator must treat `UNKNOWN`, `REVIEW_REQUIRED`, and `UNVERIFIED` as review states rather than passes. Generated remediation is a review artifact; it must go through the organization’s normal change-control process and must never be piped directly to a shell or device session.

For LLM-assisted review, the operator must confirm the provider, region, retention policy, and organizational approval before enabling it. Redaction is a safety control, not a guarantee that every organization identifier is removed. Sensitive or regulated configurations should use offline mode until the organization approves a provider boundary.

## Rollback plan

A package release rollback means pinning the prior known-good wheel and reverting the repository release tag. A report-format rollback means using the previous report writer while retaining the original audit input hash and finding metadata. A control-pack rollback means selecting the previous versioned pack and re-running the audit; reports must preserve the parser and rule-pack versions used. No network-device rollback is defined because the current product has no live-device execution path.

## Incident response

If a secret appears in a report, prompt, log, or fixture, stop distribution, quarantine the artifact, rotate the exposed credential through the organization’s normal process, preserve only the minimum forensic metadata, and report the incident using `SECURITY.md`. Do not upload the affected configuration to an external issue tracker. If a parser or report produces an unsafe result, mark the control or output as `REVIEW_REQUIRED`, reproduce with a redacted fixture, and block the release until the regression test is added.

## Observability and support evidence

The current release provides deterministic audit IDs, SHA-256 input metadata, parser and rule-pack versions, report versions, status totals, reconciliation checks, and local timing utilities. These are engineering diagnostics, not a production service-level objective. A future hosted deployment must add authenticated structured logs, metrics, traces, retention rules, alerting, backup/recovery, and tenant-aware access controls before claiming production service readiness.

## Release ownership

The release owner signs the release checklist. The security reviewer verifies the threat-model boundaries and secret-handling tests. The technical reviewer verifies package artifacts, regression tests, compatibility, and rollback instructions. The demo owner verifies the clean-install workflow and offline fallback.
