# Cleanup Manifest

## Scope

This release branch was validated without destructive cleanup of required source or test files. Generated dependency and build artifacts were left out of source control by the project’s ignore configuration and not treated as required project source.

## Files retained as required

- src/configsentinel/\*\*
- tests/\*\*
- frontend/\*\*
- docs/\*\*
- deploy/\*\*
- examples/\*\*
- scripts/\*\*
- Dockerfile
- docker-compose.yml
- pyproject.toml
- requirements.txt
- README.md
- START_HERE.md
- SECURITY.md

## Generated directories intentionally excluded from source control

- frontend/node_modules/
- frontend/dist/
- frontend/playwright-report/
- frontend/test-results/
- .pytest_cache/
- .venv/
- **pycache**/
- logs/

## Deletion policy in this release

- No required source code, test files, fixtures, deployment files, or evidence files were removed.
- No risky credential or raw secret material was committed.
- No speculative cleanup was performed beyond preserving the verified gitignore coverage.

## Result

- Clean rollback path preserved via Git
- Verified repository state kept intact
