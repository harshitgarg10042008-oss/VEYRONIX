# Frontend Audit

## Actual frontend source tree

The verified front-end source is under:

- frontend/client/

This is the authoritative frontend structure used by the build and test pipeline. The Vite app entrypoint is compiled from the client package and the production build succeeds.

## Verified app behavior

- App entry point: frontend/client/src/main.tsx
- Router: frontend/client/src/App.tsx
- API client and capability manifest loading: frontend/client/src/contexts/CapabilityContext.tsx
- Dashboard and approval flow: frontend/client/src/pages/Home.tsx
- Other feature pages: parser diff, evidence, provenance, risk, timeline, mutation lab, website scanner, etc.

## Build and test verification

Commands run successfully:

- cd frontend
- pnpm install --frozen-lockfile
- pnpm run check
- pnpm run test
- pnpm run build

Results:

- TypeScript check passed
- Vitest: 1 test file passed, 3 tests passed
- Vite production build passed

## Observations

- Frontend retrieves live capability metadata from the backend instead of hardcoding counts.
- Dashboard handles offline fallback and demonstrates UNKNOWN and FAIL findings properly.
- Approval request transitions are exercised in the frontend tests.
- No evidence of fake or hardcoded primary score values in the verified release branch.

## Status

- Implemented and integrated: yes
- Verified by build/test evidence: yes
