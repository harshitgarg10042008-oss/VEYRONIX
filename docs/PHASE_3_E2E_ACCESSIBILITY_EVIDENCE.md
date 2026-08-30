# Phase 3 E2E and Accessibility Evidence

## Verification date

2026-08-30.

## Commands executed

From `frontend/` after installing the locked dependencies and Chromium browser:

```bash
pnpm install --frozen-lockfile
CI=true pnpm run test:e2e
pnpm run test
pnpm run check
pnpm run build
```

## Observed results

| Gate | Result |
|---|---|
| Playwright Chromium suite | **11 passed** |
| Accessibility suite | Included in the Playwright run; critical and serious axe violations were required to be zero |
| Frontend unit suite | **3 passed** |
| TypeScript check | Passed |
| Production build | Passed |

The Playwright configuration originally used a Windows-only virtual-environment path. It now starts the backend with a cross-platform command using `PYTHONPATH=src python -m uvicorn ...`, so the same E2E configuration can run in Linux CI and local development environments where Python is on `PATH`.

The website-security E2E selectors were also made exact so navigation labels do not collide with the page’s scan button or evidence labels. The current coverage exercises dashboard navigation, offline fallback, website authorization confirmation, website scan execution, scan findings, evidence selection, negative flow behavior, and accessibility analysis.

## Evidence boundaries

A passing automated accessibility scan is evidence for the tested routes and current fixture state. It is not a legal accessibility certification and does not replace manual keyboard, screen-reader, color, zoom, and assistive-technology review. A passing website scan E2E proves the local workflow and fixture-backed integration, not the accuracy of every possible real-world website assessment.
