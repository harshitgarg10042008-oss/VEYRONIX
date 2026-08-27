# Phase 8 — Framework Mapping and Reporting

**Status:** Complete
**Product:** ConfigSentinel AI
**Team:** VEYRONIX
**Problem Statement:** SIH 26155

## Scope

Phase 8 adds a deterministic framework registry and evidence-linked audit reporting. The registry currently supports the `cis-network` and `nist-800-53` identifiers. Aliases `cis` and `nist` are normalized for CLI and SDK convenience. Each framework record contains an identifier, title, version, source URL, and a note that mappings require organization-specific verification before production reliance.

The reporting layer produces JSON and Markdown reports from the same `AuditResult` object. Reports include audit metadata, selected frameworks, parser and control-pack versions, input SHA-256, finding totals, status counts, exact evidence spans, observed and expected state, severity, confidence, framework mapping status, and reconciliation checks.

## Design principles

The deterministic compliance engine remains authoritative. Framework mapping enriches a finding and does not change its pass/fail/unknown status. A control without an explicit mapping is rendered as `UNVERIFIED`, not as compliant. Report generation is local and deterministic; it does not call an LLM, connect to a network device, or execute remediation.

The report path receives the already redacted audit result. The input hash supports reproducibility without placing original configuration content into the report. Generated remediation remains a non-executable preview requiring independent operator approval.

## SDK usage

```python
from configsentinel import ConfigSentinelClient, DeterministicComplianceEngine

client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
result = client.audit_text(
    config_text,
    vendor="cisco_ios",
    frameworks=("cis-network", "nist-800-53"),
)

markdown = client.report_markdown(result, frameworks=("cis-network",))
json_document = client.report_json(result, frameworks=("cis-network",))
```

## CLI usage

```powershell
configsentinel audit .\edge-test.conf `
  --vendor cisco_ios `
  --framework cis-network `
  --framework nist-800-53 `
  --report-out .\audit.md `
  --json-out .\audit.json
```

The CLI preserves the existing preview-only remediation boundary. The `--approve` flag still requires `--dry-run`, and no command in Phase 8 creates a live-device connection or executes a generated script.

## Validation

The complete regression suite contains **30 passing tests** after Phase 8. The test coverage includes framework alias normalization, mapping provenance, mapped and unverified status, JSON/Markdown reconciliation, SDK parity, report file output, secret-redaction assertions, and the existing Phase 2–7 behavior.

```text
python -m pytest
python -m compileall -q src tests examples
PYTHONPATH=src python -c "from configsentinel.frameworks import framework_catalog; print(len(framework_catalog()))"
```

## Limitations

The current registry is static and intentionally small. CIS mappings are reference mappings, not a substitute for licensed benchmark text or an assessor’s determination. NIST mappings are informative crosswalks. PDF export, a dashboard, trend comparisons, live read-only collection, and organization-specific signed control packs remain future phases.

## Acceptance gate

- Versioned framework registry: complete.
- Mapping provenance with source URL, version, status, and confidence: complete.
- Explicit `UNVERIFIED` handling: complete.
- JSON and Markdown report reconciliation: complete.
- Framework-aware CLI flags: complete.
- Secret-safe and no-execution report path: complete.
