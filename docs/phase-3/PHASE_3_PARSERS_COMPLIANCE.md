# Phase 3 — Vendor Parsers and Deterministic Compliance Engine

## Delivered

Phase 3 connects the Phase 2 SDK boundary to a deterministic audit workflow. It adds a canonical security model, parser plugins for Cisco IOS/IOS XE, Juniper Junos, and a generic firewall subset, a versioned initial control pack, and an integrated `DeterministicComplianceEngine`.

## Safety semantics

The engine uses five statuses: `PASS`, `FAIL`, `NOT_APPLICABLE`, `UNKNOWN`, and `REVIEW_REQUIRED`. Unsupported lines are preserved as evidence and warnings. A parser failure or missing field cannot silently become a compliant result. The LLM is not required for deterministic evaluation.

## Initial controls

The control pack is version `3.0.0` and currently includes secure SSH, Telnet prohibition, AAA, security logging, NTP, secure SNMP, and plain-HTTP management checks. Every result contains the control ID, status, severity, confidence, evidence spans, observed state, expected state, rationale, and a remediation preview. Remediation remains non-executable and human-approval-required.

## Public usage

```python
from configsentinel import ConfigSentinelClient, DeterministicComplianceEngine

client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
result = client.audit_text(
    "version 17.9\\nline vty 0 4\\n transport input telnet\\n",
    vendor="cisco_ios",
)

for finding in result.findings:
    print(finding.control_id, finding.status.value, finding.evidence)
```

## Validation

Run from the repository root:

```bash
python -m pytest
python -m compileall -q src tests examples
PYTHONPATH=src python examples/phase2_sdk_demo.py
```

The current combined suite covers Phase 2 and Phase 3 contracts, including Cisco and Junos extraction, generic unknown handling, evidence-backed failures, auto-detection fail-closed behavior, secret redaction, LLM output validation, and deterministic fallback.

## Known boundaries

This is the first parser/control implementation, not universal vendor coverage. The generic firewall parser is intentionally conservative. Additional vendors and controls must be added with capability manifests, source spans, secure/insecure fixtures, applicability rules, and regression tests. Later phases should add richer ACL, routing, cryptography, and topology analysis without weakening the current explicit-unknown semantics.
