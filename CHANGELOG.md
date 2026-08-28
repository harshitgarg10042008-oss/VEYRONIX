# Changelog

## Unreleased — SIH readiness hardening

The local API now exposes backend-authoritative control-pack metadata, validates NUL bytes and oversized lines at the HTTP boundary, supports typed and bounded vendor detection, and provides optional bearer-token protection for non-loopback deployments. The frontend now uses backend vendor selection, displays authoritative vendor labels, renders the live control registry, and exports a non-executable remediation preview. Clean environments can import the examples package reliably.

## Next — Phase 11 release readiness

Added final deployment and production-release documentation, a safe environment template, release gates, clean-install procedure, operational runbook, incident-response guidance, rollback plan, and explicit hosted-deployment limitations. No live-device execution or hosted multi-tenant service is introduced by this documentation-only release step.

## 0.3.0 — Phase 6

This release adds final packaging metadata, the `configsentinel` console command, `python -m configsentinel` support, an end-user guide, security policy, and distribution documentation. It packages the Phase 2–5 SDK, parsers, deterministic controls, secure ingestion boundary, guarded LLM gateway, remediation preview generator, and CLI runner.

## 0.2.0 — Phase 5

Added the typed SDK, guarded provider-agnostic LLM gateway, vendor parsers, deterministic compliance controls, secure ingestion, redaction, remediation previews, and CLI safety controls.

## Compatibility

Python 3.11 and 3.12 are supported. The current package is an alpha hackathon prototype and should be evaluated in a controlled environment before any production adoption.
