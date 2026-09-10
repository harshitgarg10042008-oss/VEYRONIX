# API Audit

## Backend entrypoint

- Primary backend: src/configsentinel/api.py
- Framework: FastAPI
- Verified routes: health, capabilities, audit, detect, control-pack, explain, approval, OIDC, websites, verification, resilience, provenance, regulatory, graph, and non-versioned aliases.

## Key route inventory

| Method | Path                            | Requirement        | Notes                                            |
| ------ | ------------------------------- | ------------------ | ------------------------------------------------ |
| GET    | /api/health                     | none               | health check                                     |
| GET    | /api/capabilities               | none               | manifest; source of frontend capability metadata |
| POST   | /api/detect                     | none               | vendor/parser detection                          |
| POST   | /api/audit                      | auth/session-aware | main audit execution                             |
| POST   | /api/explain                    | auth/session-aware | explanation surface                              |
| POST   | /api/ai/classify-unknown        | auth/session-aware | security-critical AI boundary                    |
| POST   | /api/auth/login                 | none               | local auth                                       |
| GET    | /api/auth/me                    | auth               | session validation                               |
| GET    | /api/auth/oidc/login            | OIDC enabled       | enterprise SSO flow                              |
| GET    | /api/auth/oidc/callback         | OIDC enabled       | callback and replay protection                   |
| POST   | /api/approval/request           | auth               | approval request                                 |
| POST   | /api/approval/decision          | auth + role checks | approval gate                                    |
| POST   | /api/websites/scans             | auth               | website scan intake                              |
| GET    | /api/websites/rules             | auth               | website security rules                           |
| POST   | /api/v1/mutation-lab/run        | auth               | mutation testing                                 |
| POST   | /api/v1/parser-differential/run | auth               | parser comparison                                |
| POST   | /api/v1/secrets/scan            | auth               | secret scanning                                  |
| POST   | /api/v1/provenance/verify       | auth               | provenance verification                          |
| POST   | /api/v1/regulatory/export       | auth               | compliance export                                |

## Security observations

- OIDC flow validates state, nonce, code replay, issuer, audience, and session handling in src/configsentinel/api.py.
- AI classify-unknown route is enforced with schema validation and unsafe input rejection.
- Secret redaction and guardrails are implemented before AI use.
- Workspace/role policies are enforced for sensitive endpoints.

## Test coverage

The repository includes tests validating:

- API contract behavior
- AI classification boundary
- OIDC hardening
- governance and approvals
- website security scanner behavior
- parser and regulation paths

## Status

- Implemented and tested: yes, as evidenced by the passing suite and the targeted security regression tests.
- Unverified claims removed: yes, with score based on executable evidence only.
