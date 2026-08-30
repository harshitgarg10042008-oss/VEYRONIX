# SIH Evidence Package

This document provides a summary of the evidence collected for the ConfigSentinel AI project (VEYRONIX) up to Phase 8.

## 1. Test Coverage Summary

- **Backend Unit & Integration Tests**: 352 passing tests, covering the core deterministic parsing engine, local API, LLM adapters, security boundaries, authentication, and continuous monitoring.
- **Negative Testing**: Comprehensive negative tests ensure strict boundaries, rejecting invalid API tokens, unauthenticated access to protected endpoints, and malformed boundary conditions.
- **Accuracy Benchmarking**: ConfigSentinel achieves 100% vendor detection accuracy and 85.71% control validation accuracy against a synthetic ground-truth dataset.
- **Security Check**: Verified via Pytest testing and Playwright E2E tests, verifying that no passive scans cross authorization boundaries, and no long-term persistence violates the isolation constraints.

## 2. Docker Configuration & CI Workflows

- **Backend Dockerfile**: Alpine-based slim image, optimized with a non-root user, secure dependency handling, and exposed to port 8000.
- **Frontend Dockerfile**: Multi-stage Node.js build using `nginx:alpine` to serve a static production bundle securely on port 80.
- **Docker Compose**: Pre-configured services to start the full stack, utilizing local volume mapping for isolated configuration processing.
- **GitHub Actions (CI)**: `ci.yml` strictly enforces testing (Python tests, TypeScript checks, and frontend unit tests), container validation (Hadolint syntax checking), E2E UI tests via Playwright, and accuracy benchmarking, operating as a required release quality gate.

## 3. E2E & Accessibility Summaries

- **Playwright E2E**: Fully passing test suites for critical user journeys, including local audit processing, active monitoring setup, configuration drift analysis, and website posture checking.
- **Accessibility Checks**: Keyboard navigation passes WCAG standards for primary elements on the dashboard, ensuring active focus on critical components. No critical or serious `axe-core` accessibility violations are present in the core workflows.
- **Zero-Trust**: Tests verify the workspace operates entirely local and offline for deterministic workflows.
