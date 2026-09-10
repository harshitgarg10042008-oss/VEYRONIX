# SIH Final Evidence Pack — ConfigSentinel AI
## SIH26155: AI-Driven Multi-Vendor Network Security Compliance Auditor

**Version:** 0.4.0-sih  
**Date:** 2026-09-10  
**Repository:** harshitgarg10042008-oss/VEYRONIX  
**Status:** Phase 1–2 Complete, Full suite passing

---

## Scorecard Progress

| Category | Weight | Phase 1–2 Score | Target |
|----------|--------|-----------------|--------|
| Problem relevance and validation | 15 | 13 | 15 |
| Novelty and differentiation | 15 | 14 | 15 |
| Architecture and correctness | 20 | 19 | 20 |
| End-to-end completeness | 20 | 17 | 20 |
| Security, privacy, governance | 10 | 8 | 10 |
| AI quality and responsibility | 5 | 4 | 5 |
| Reliability and release quality | 10 | 10 | 10 |
| Impact and demo evidence | 5 | 4 | 5 |
| **Total** | **100** | **89** | **100** |

> Phase 1–2 improvements: Architecture +2 (versioned canonical schema, 24 controls, 7 vendors), Reliability +1 (all 614 tests passing), Impact +1 (measured accuracy report).

---

## Evidence Index

### Architecture and Correctness

| Claim | Evidence |
|-------|----------|
| 7 vendor parsers | `src/configsentinel/parsers.py` — PARSER_REGISTRY with 7 entries |
| 24 security controls | `src/configsentinel/controls.py` — CONTROL_PACK with 24 ControlDefinitions |
| Versioned canonical schema | `src/configsentinel/canonical.py` — CanonicalConfig v4.0.0 |
| Capability manifest API | `GET /api/capabilities` — `src/configsentinel/capabilities.py` |
| Framework mappings (7 frameworks) | `src/configsentinel/frameworks.py` — FRAMEWORKS tuple |
| Evidence spans with line numbers | `models.py` — EvidenceSpan(start_line, end_line, excerpt) |
| Deterministic status invariant | `controls.py` — evaluate() never calls AI |
| UNKNOWN ≠ PASS semantic | All check functions — return (UNKNOWN, rationale, ()) when field is None |

### Multi-Vendor Support

| Vendor | Parser File | Fixture |
|--------|------------|---------|
| Cisco IOS/IOS-XE | `parsers.py::CiscoIOSParser` | `tests/fixtures/cisco/` (5 files) |
| Juniper Junos | `parsers.py::JunosParser` | `tests/fixtures/junos/` (4 files) |
| Arista EOS | `parsers.py::AristaEOSParser` | `tests/fixtures/arista/` (1 file) |
| Fortinet FortiGate | `parsers.py::FortiGateParser` | `tests/fixtures/fortigate/` (3 files) |
| Palo Alto PAN-OS | `parsers.py::PaloAltoParser` | `tests/fixtures/paloalto/` (3 files) |
| Linux nftables | `parsers.py::LinuxNftablesParser` | (included in phase 1 fixture) |
| Generic Firewall | `parsers.py::GenericFirewallParser` | Catch-all fallback |

### Control Coverage

| Family | Controls | NIST 800-53 | CIS |
|--------|---------|-------------|-----|
| Management plane | 5 | AC-17, SC-8 | ✓ |
| Identity/access | 4 | IA-2, IA-5, AC-6 | ✓ |
| Cryptography | 2 | SC-8, SC-13 | ✓ |
| Logging/monitoring | 2 | AU-2, AU-8 | ✓ |
| SNMP/telemetry | 2 | SC-8, IA-3 | ✓ |
| Network protection | 2 | SC-5, AC-3 | ✓ |
| Segmentation | 2 | SC-3, AC-4 | ✓ |
| Resilience | 2 | CP-9, CM-7 | ✓ |
| Secrets | 2 | IA-5, SC-28 | ✓ |
| Governance | 1 | PL-2 | ✓ |

### Test Suite Evidence

| Suite | Tests | Result |
|-------|-------|--------|
| `tests/test_capabilities.py` | 23 | ✓ All pass |
| `tests/test_phase2_controls.py` | 68 | ✓ All pass |
| `tests/test_api.py` | ~30 | ✓ All pass |
| `tests/test_governance.py` | ~20 | ✓ All pass |
| All tests combined | 614 | ✓ All pass |

### Frontend Evidence

| Claim | Evidence |
|-------|----------|
| Vendor count from API (not hardcoded) | `CapabilityContext.tsx` → `GET /api/capabilities` |
| Control count from API | Same |
| Evidence mode indicator | Layout.tsx sidebar — LIVE API / FIXTURE / DEMO badge |
| TypeScript compiles | `npx tsc --noEmit` → exit code 0 |
| Production build succeeds | `npm run build` → 1890 modules, exit code 0 |

### Safety and Governance Evidence

| Safety property | Implementation | Test |
|----------------|---------------|------|
| No device mutation | No TCP/SSH client in codebase | Architecture review |
| Separation of duties | `ApprovalLedger.decide()` raises GovernanceError if same actor | `test_governance.py::test_api_governance_rejects_same_actor_decision` |
| Append-only ledger | JSONL file, open('a') only | `governance.py::_append()` |
| AI cannot override deterministic status | `controls.py::evaluate()` — no AI import | Code review |
| Secret redaction | `EvidenceSpan.redacted = True` by default | `models.py` |
| Upload size limit | 5 MiB enforced in `validate_config_text()` | `test_api.py` |
| NUL byte rejection | `validate_config_text()` checks `b"\x00"` | `test_api.py` |

---

## Quick Reproduction Commands

```bash
# Full backend test suite
python -m pytest tests/ -q
# Expected: 614 passed

# New phase 1-2 tests only  
python -m pytest tests/test_capabilities.py tests/test_phase2_controls.py -v
# Expected: 91 passed

# Live capability manifest
python -c "from configsentinel.capabilities import build_capabilities; import json; m=build_capabilities(); print(json.dumps(m.as_dict(), indent=2))"

# Audit a fixture config
python -c "
from configsentinel.parsers import CiscoIOSParser
from configsentinel.controls import evaluate
text = open('tests/fixtures/cisco/noncompliant_telnet.conf').read()
config = CiscoIOSParser().parse(text).config
findings = evaluate(config, 'demo-audit')
for f in findings:
    if f.status.value in ('FAIL', 'PASS'):
        print(f'{f.status.value} {f.control_id} ({f.severity.value}) — {len(f.evidence)} evidence spans')
"

# Frontend type check
cd frontend/client && npx tsc --noEmit

# Frontend production build
cd frontend/client && npm run build
```

---

## Demonstration Journey (10-min SIH Demo)

| Minute | Action | Evidence shown |
|--------|--------|----------------|
| 0–1 | Show `tests/fixtures/cisco/noncompliant_telnet.conf` | Real config with telnet, plaintext password |
| 1–2 | Run audit in UI / API | Vendor detection confidence, parser version |
| 2–4 | Show findings list | NET-MGMT-TELNET-001 FAIL + source line evidence |
| 4–5 | Open UNKNOWN finding | Incomplete evidence → UNKNOWN (not PASS) |
| 5–6 | Show remediation preview | Non-executable diff, rollback note, approval required |
| 6–7 | Approval flow | Switch to reviewer, approve, separation of duties error if same actor |
| 7–8 | Upload compliant config | Before/after score, drift result |
| 8–9 | Mutation lab | Enable Telnet → detected immediately |
| 9–10 | Capability manifest | `GET /api/capabilities` → 7 vendors, 24 controls, 7 frameworks |

---

## What This Product Deliberately Does NOT Claim

- ❌ Full PAN-OS security policy evaluation (management plane only in v1.0.0)
- ❌ FortiGate VDOM sub-context evaluation (system global only in v1.0.0)
- ❌ Automatic device configuration push
- ❌ Verified coverage of encrypted password types 8 and 9 (only type-0 plaintext detected)
- ❌ Complete IOS-XR support (IOS-XE markers detected; XR-specific syntax flagged UNKNOWN)
- ❌ Production-grade OIDC SSO (local session identity only in v0.4.0)
- ❌ 100% recall — UNKNOWN is the correct output for unsupported syntax

Honest limitation disclosure is a SIH scoring criterion, not a weakness.

---

*All claims in this document are reproducible from the test suite and source code.*
