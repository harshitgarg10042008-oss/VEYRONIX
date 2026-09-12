# VEYRONIX SIH Implementation Plan

## Executive decision

VEYRONIX should continue as a network-configuration compliance and evidence-auditing platform, but with a narrower and more defensible promise. The product should not present itself as a universal parser, a public website scanner, a complete email-security gateway, or a live device-management system.

The implementation target is a shared, deployable, evidence-first platform that runs on one designated LAN host while other computers use a browser. Docker Compose packages the React frontend, Node/Express entry point, FastAPI audit service, and persistent backend state. The browser is not the source of truth for shared audit history.

## Major product boundaries

- No live device modification.
- No automatic remediation execution.
- No full phishing prevention.
- Unsupported syntax is not treated as compliant.
- Shared records must live behind the server-side audit API.

## Supported first-release matrix

- Cisco IOS / IOS XE CLI text
- Junos set / ASCII text
- Arista EOS CLI text
- FortiOS native config where validated
- PAN-OS XML only where validated
- nftables text / JSON only where validated

## Implementation phases

### Phase 0 — Scope freeze

The product contract is narrowed to evidence-backed compliance and explicit product limitations.

### Phase 1 — Shared multi-computer deployment

- Add server-side audit records with audit metadata and hashes.
- Expose CRUD and review endpoints.
- Keep raw configuration out of the shared database by default.
- Support SQLite first and PostgreSQL later.
- Add LAN authentication and shared history.

### Phase 2 — Offline-capable selected workflows

- Keep the shell available offline.
- Store drafts and queued submissions locally.
- Mark server-backed audit entries as pending until confirmed.

### Phase 3 — Parser coverage and file ingestion

- Add ParseCoverage metadata to every report.
- Track PARSED, PARTIALLY_PARSED, UNSUPPORTED_FORMAT, MALFORMED, and PROTECTED_INPUT.
- Reject unsafe archive members and nested archives.

### Phase 4 — Evidence-first audit experience

- Include input hashes, parser versions, control pack versions, and exact evidence spans.
- Show coverage score alongside posture score.
- Require human review for remediation previews.

### Phase 5 — Email-authentication readiness

- Support SPF, DKIM, DMARC, raw-header review, and deterministic mismatch checks.
- Disclaim that authentication results do not prove benign content.

### Phase 6 — Comparison and network-behavior integration

- Compare current versus approved baseline.
- Keep Batfish as a separate evidence source rather than a replacement for VEYRONIX.

## Safety requirements before public deployment

1. Require HTTPS outside trusted localhost development.
2. Protect audit and export endpoints with authentication.
3. Add operator, reviewer, and administrator role boundaries.
4. Reject oversized or unsafe archives.
5. Redact secrets before LLM use or storage.
6. Disable live device execution until a separate review.

## Final positioning statement

VEYRONIX is an evidence-first network configuration compliance platform. It accepts declared configuration artifacts, identifies supported vendor and format adapters, evaluates deterministic security controls, shows the exact evidence behind every result, and generates review-only remediation guidance. It can run on one shared LAN host so multiple users access the same audit workspace without installing the backend on every computer.
