# Phase 9 — Interactive Unknown-Syntax Learning Loop

**Status:** Complete

**Product:** ConfigSentinel AI

**Team:** VEYRONIX

**Problem Statement:** SIH 26155

## Purpose

Phase 9 turns parser uncertainty into a controlled review workflow. When a parser encounters an unsupported configuration line, the system preserves the source span, vendor, parser version, context, and input hash as an `UnknownSyntaxCase`. A reviewer can then examine a proposal, approve or reject it, and—only after approval—create a versioned mapping and regression fixture.

## Safety model

Unknown syntax is never treated as compliant. The queue does not modify parser behavior or the deterministic control engine by itself. A proposal is only a suggestion containing an interpretation, normalized concept, confidence, evidence-needed list, model identifier, and prompt version. Approval requires a reviewer identity and either a second distinct reviewer or explicit automated-test evidence. Rejected and deferred proposals remain in the audit trail and create no mapping.

The learning loop stores a SHA-256 provenance reference rather than the original unredacted configuration. Context and evidence should already have passed through the secure ingestion/redaction boundary before being enqueued. No proposal is executable, and no review action connects to a network device.

## Workflow

> **Parse unknown block → enqueue case → create bounded proposal → reviewer approves/rejects/defers → approved mapping gets versioned → regression fixture is written → future parser/control work is reviewed separately**

The current implementation is local and in-memory by design. A later persistence phase may add a database, RBAC, two-person approval, and signed mapping packs, but those additions must preserve the same fail-closed semantics.

## SDK example

```python
from configsentinel import EvidenceSpan, ReviewDecision, UnknownSyntaxQueue

queue = UnknownSyntaxQueue()
case = queue.enqueue(
    vendor="cisco_ios",
    parser_version="cisco-ios-3.0.0",
    evidence=EvidenceSpan(12, 12, " service mystery-control"),
    context="line vty 0 4\n service mystery-control",
    source_sha256="a" * 64,
)
proposal = queue.propose(
    case.case_id,
    interpretation="Maps to a secure management service",
    normalized_concept="management_secure_service",
    confidence=0.82,
    evidence_needed=("vendor documentation",),
)
mapping = queue.review(
    proposal.proposal_id,
    reviewer="alice",
    second_reviewer="bob",
    decision=ReviewDecision.APPROVED,
    reason="Verified against approved vendor documentation",
)
if mapping:
    queue.write_regression_fixture(mapping.mapping_id, "fixtures/phase9/approved_mapping.json")
```

## Acceptance criteria

- Unknown blocks retain source context, line span, parser version, vendor, and input provenance.
- Proposals are bounded, typed, confidence-scored, and not compliance verdicts.
- Approval requires authorization and independent review or automated-test evidence.
- Rejection and deferral are auditable and do not create approved mappings.
- Approved mappings are versioned and produce regression fixtures.
- Existing deterministic audit behavior remains unchanged until a reviewed parser/control release incorporates the mapping.
- No secrets, live credentials, device connections, or executable commands enter the learning loop.

## Validation

The Phase 9 test suite covers case creation, proposal creation, second-reviewer enforcement, approval-to-fixture flow, rejection behavior, audit events, and provenance requirements. Run the full regression suite with:

```text
python -m pytest
python -m compileall -q src tests examples
```
