# BASELINE RELEASE REPORT — ConfigSentinel AI v0.4.0-sih

**Report date:** 2026-09-10  
**Release tag:** v0.4.0-sih  
**Phase:** Post Phase 1–2 implementation checkpoint

---

## Environment

| Component | Version |
|-----------|---------|
| Python | 3.12.10 |
| pytest | 9.1.1 |
| FastAPI | (installed via pyproject.toml) |
| Node.js | (see `package.json` engines field) |
| OS | Windows 11 |

---

## Phase 1–2 Implementation Summary

### What was implemented in this release

**Phase 1 — Capability Manifest API**
- Created `src/configsentinel/capabilities.py` — authoritative source of vendor/control/framework metadata
- Added `GET /api/capabilities` endpoint to `api.py`
- `GET /api/health` now returns live `APP_VERSION` from capabilities module
- Frontend `CapabilityContext.tsx` fetches live manifest; sidebar shows live vendor count, control count, version

**Phase 2a — Parser Expansion (5 → 7 vendors)**
- Added `FortiGateParser` — FortiOS CLI config/end block parser, management plane scope
- Added `PaloAltoParser` — PAN-OS set-form parser, device system scope (management plane only)
- All parsers updated to `parser_version = "4.0.0"`
- `PARSER_REGISTRY` updated to 7 parsers

**Phase 2b — CanonicalConfig Expansion**
- Rewrote `canonical.py` with 20+ new fields:
  - Cryptography: `tls_minimum_version`, `weak_ciphers_found`, `ssh_key_minimum_bits`
  - Identity: `local_auth_fallback`, `password_policy_enabled`, `privilege_separation`
  - Network: `mgmt_acl_enabled`, `restconf_enabled`, `anti_spoofing_enabled`, `acl_hygiene`
  - Segmentation: `mgmt_plane_separated`, `default_deny_posture`
  - Resilience: `config_backup_enabled`, `unused_services_disabled`
  - Secrets: `plaintext_credentials_found`, `private_key_in_config`
  - Governance: `config_owner_metadata`

**Phase 2c — Control Pack Expansion (7 → 24 controls)**

| Family | Controls added |
|--------|---------------|
| Management plane | NET-MGMT-RESTCONF-001, NET-MGMT-ACL-001 |
| Identity/access | NET-AUTH-AAA-001, NET-AUTH-LOCAL-001, NET-AUTH-PWPOL-001, NET-AUTH-PRIV-001 |
| Cryptography | NET-CRYPTO-TLS-001, NET-CRYPTO-CIPHER-001 |
| Logging/monitoring | NET-LOG-001, NET-TIME-001 |
| SNMP/telemetry | NET-SNMP-001, NET-SNMP-COMMUNITY-001 |
| Network protection | NET-PROT-SPOOF-001, NET-PROT-ACL-001 |
| Segmentation | NET-SEG-MGMT-001, NET-SEG-DENY-001 |
| Resilience | NET-RES-BACKUP-001, NET-RES-UNUSED-001 |
| Secrets | NET-SEC-PLAIN-001, NET-SEC-KEY-001 |
| Governance | NET-GOV-OWNER-001 |

All controls include: CIS, NIST 800-53, ISO 27001, PCI DSS 4.0.1, NIST CSF 2.0 framework mappings.

**Phase 2d — Fixture Matrix (22 fixtures across 6 vendor families + adversarial)**

| Directory | Fixtures |
|-----------|----------|
| `tests/fixtures/cisco/` | `compliant_full.conf`, `noncompliant_telnet.conf`, `incomplete_no_ssh.conf`, `syntax_variant_ios_xe.conf`, `adversarial_prompt.conf` |
| `tests/fixtures/junos/` | `compliant_set.conf`, `compliant_hierarchical.conf`, `noncompliant_telnet.conf`, `incomplete.conf` |
| `tests/fixtures/arista/` | `compliant.conf` |
| `tests/fixtures/fortigate/` | `compliant.conf`, `noncompliant.conf`, `incomplete.conf` |
| `tests/fixtures/paloalto/` | `compliant.conf`, `noncompliant.conf`, `limited_scope.conf` |
| `tests/fixtures/adversarial/` | `prompt_injection.conf`, `secrets_embedded.conf`, `ambiguous_vendor.conf`, `unicode_long.conf` |

---

## Test Results

### Backend test suite

```
python -m pytest tests/ -q
Result: 614 passed, 0 failed (as of 2026-09-10)
```

### New test suites added this release

| Suite | Tests | Result |
|-------|-------|--------|
| `tests/test_capabilities.py` | 23 tests | ✓ All pass |
| `tests/test_phase2_controls.py` | 68 tests | ✓ All pass |

### Critical invariants verified

- ✓ PASS findings always have evidence spans
- ✓ FAIL findings always have evidence spans
- ✓ UNKNOWN returned when canonical field is `None` (not coerced to PASS or FAIL)
- ✓ Adversarial banner content does not appear in compliance evidence keys
- ✓ Capability manifest vendor count == parser registry length
- ✓ Capability manifest control count == CONTROL_PACK length
- ✓ All CRITICAL/HIGH controls have NIST 800-53 framework mappings
- ✓ All controls have unique IDs
- ✓ All controls have non-empty remediation text

---

## Known Warnings (Non-Blocking)

| Warning | Source | Action |
|---------|--------|--------|
| `datetime.utcnow()` deprecation | website_scanner.py, test_website_*.py | Cosmetic only; does not affect compliance logic |
| StarletteDeprecationWarning | FastAPI test client | Third-party; no action required |

---

## Capability Manifest (Runtime Snapshot)

Run to reproduce:
```bash
python -c "
from configsentinel.capabilities import build_capabilities
import json
m = build_capabilities()
print(f'App version: {m.app_version}')
print(f'Vendor count: {m.vendor_count}')
print(f'Control count: {m.total_control_count}')
print(f'Control pack version: {m.control_pack_version}')
print(f'Parser registry version: {m.parser_registry_version}')
print(f'Framework IDs: {m.framework_ids}')
"
```

Expected output:
```
App version: 0.4.0-sih
Vendor count: 7
Control count: 24
Control pack version: 4.0.0
Parser registry version: 4.0.0
Framework IDs: ('cis-network', 'nist-800-53', 'nist-csf-2', 'pci-dss-4-0-1', 'iso-27001-2022', 'hipaa-security-rule', 'soc-2-tsc')
```

---

## Next Phases

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 3 (AI) | Planned | `/api/ai/classify-unknown` with bounded schema-validated output |
| Phase 5 (Identity) | Partial | Session-based local identity done; OIDC planned |
| Phase 7 (Differentiators) | Existing | Mutation lab, notary, blast radius, evidence exchange implemented |
| Phase 9 (Release gates) | Ongoing | Automated test suite covers 614 cases |

---

*All values in this report are reproducible from a clean checkout. Run `python -m pytest tests/ -v` to verify.*
