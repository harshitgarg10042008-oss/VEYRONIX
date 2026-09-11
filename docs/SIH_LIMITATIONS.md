# SIH Submission Limitations

This document is part of the judge evidence pack. It describes boundaries that must be stated during the demonstration.

## Supported scope

- Supported parsers are Cisco IOS/IOS XE, Juniper Junos, and a conservative generic firewall subset.
- Unsupported vendors and unsupported syntax remain UNKNOWN or manual-review cases; they are not silently treated as compliant.
- Accuracy evidence currently uses labeled synthetic fixtures. It is not a claim of production false-positive or false-negative rates.

## Local and fixture behavior

- The deterministic SDK, API, CLI, browser history, PDF export, and remediation preview can run locally.
- The Website Security page shows a clearly labeled local illustrative fixture before a target is scanned.
- Inventory and monitoring views have local behavior, but monitoring is not a production scheduler and synthetic visual summaries must not be presented as fleet telemetry.
- Advanced Research Lab surfaces may use bounded compatibility fixtures; they are not evidence of external integrations.

## Integrations and identity

- No live network-device connection or automatic configuration application is included.
- No cloud multi-tenancy or production external identity provider integration is claimed.
- Local authentication and approval flows are demonstration boundaries, not a substitute for an enterprise identity architecture.
- External LLM inference is opt-in, bounded, and disabled by default. The engine's deterministic verdict remains authoritative.

## Website inspection

- Website inspection is passive and requires operator authorization.
- It does not exploit, brute-force, authenticate to, modify, or guarantee the absence of vulnerabilities.
- Private-target restrictions and response limits apply at the backend boundary.

## Operational risks

- Parser coverage can produce UNKNOWN findings where syntax is ambiguous or unsupported.
- False positives and false negatives remain possible; representative sanitized field fixtures and independent validation are required before production use.
- Local persistence and process-level resources are not equivalent to a durable multi-user service.
- Remediation previews require independent human review, testing, change approval, and a separate controlled application process.

## Deployment assumptions

- The documented container deployment uses a backend service and the compiled frontend Express proxy.
- Secrets must be supplied through approved environment or secret-management mechanisms and never committed.
- The release is suitable for controlled evaluation and local demonstration, not an unreviewed production rollout.
