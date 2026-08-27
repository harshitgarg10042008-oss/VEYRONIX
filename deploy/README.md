# ConfigSentinel AI Deployment Readiness

This directory contains deployment guidance only. The current VEYRONIX release is a local SDK/CLI and does not include a hosted API service, database, live-device connector, or automatic remediation worker.

## Required production prerequisites

Before hosting ConfigSentinel AI as an organization-wide service, implement and review authenticated API access, project/tenant isolation, RBAC, encrypted storage, audit-log persistence, worker isolation, secret-vault integration, rate limiting, backup/recovery, signed control packs, plugin isolation, and provider-specific LLM data-processing approval.

## Environment policy

Copy the example file to a protected environment-specific configuration location. Never commit real keys or customer configuration files. LLM provider credentials belong in the deployment secret manager, not in source control or `.env` files shared with the team.

```text
CONFIGSENTINEL_ENV=development
CONFIGSENTINEL_LLM_ENABLED=false
CONFIGSENTINEL_MAX_INPUT_BYTES=5242880
CONFIGSENTINEL_MAX_LINES=100000
CONFIGSENTINEL_MAX_LINE_BYTES=262144
CONFIGSENTINEL_MAX_REPORT_BYTES=10485760
CONFIGSENTINEL_REMEDIATION_MODE=preview_only
CONFIGSENTINEL_QUARANTINE_DIR=./private-quarantine
```

## Release sequence

1. Build and checksum the wheel and source distribution.
2. Install the wheel in clean Python 3.11 and 3.12 environments.
3. Run the complete regression and security suites.
4. Run the offline audit and report smoke tests.
5. Review the release notes, security policy, and limitations.
6. Obtain security and technical sign-off.
7. Publish the artifact through the organization’s approved package channel.
8. Monitor installation feedback and retain the rollback artifact.

The deployment owner must not enable a live-device execution path by configuration alone. Any future connector requires a separate threat model, authorization design, approval workflow, and release gate.
