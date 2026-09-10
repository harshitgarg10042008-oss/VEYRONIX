# Repository Inventory

## Repository snapshot

- Branch: main
- Commit: d1393414108ec18a54e4888ac4af1255d586aa38
- Remote: https://github.com/harshitgarg10042008-oss/VEYRONIX.git
- Current verification date: 2026-09-10

## High-level classification

- Required source: src/configsentinel/\*\*
- Required tests: tests/\*\*
- Required configuration: pyproject.toml, requirements.txt, docker-compose.yml, Dockerfile, .github/**, deploy/**
- Required docs: README.md, START_HERE.md, docs/\*\*, SECURITY.md, CHANGELOG.md
- Required frontend: frontend/\*\*
- Generated artifacts: frontend/node_modules/**, frontend/dist/**, frontend/playwright-report/**, frontend/test-results/**, .pytest_cache/**, .venv/**, logs/\*\*
- Duplicate/stale: not materially required after verification; generated dependencies and reports were excluded from source control via .gitignore
- Suspicious: none found after repository-wide checks

## Tracked source directories

- src/configsentinel/
- tests/
- frontend/
- deploy/
- docs/
- examples/
- scripts/

## Key files

- API backend: src/configsentinel/api.py
- Capability manifest: src/configsentinel/capabilities.py
- Parser and detection logic: src/configsentinel/parsers.py, src/configsentinel/detection.py
- Security and governance: src/configsentinel/security.py, src/configsentinel/governance.py
- Frontend app entry: frontend/client/src/App.tsx and frontend/client/src/main.tsx
- Build config: frontend/package.json, frontend/vite.config.ts, frontend/vitest.config.ts

## Verified repository status

- Git working tree: clean on main
- Full Python test suite: passing (`python -m pytest -q`)
- Frontend validation: passing (`pnpm run check`, `pnpm run test`, `pnpm run build`)

## Duplicate and generated artifact assessment

- `frontend/node_modules` is generated and should remain untracked; it is intentionally excluded from Git by .gitignore.
- `frontend/dist` and `frontend/playwright-report` are build artifacts; excluded from Git.
- `logs/` and `.pytest_cache/` are transient runtime outputs.
- No required source, tests, or deployment files were removed in the verified release branch.
