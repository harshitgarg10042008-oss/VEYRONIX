# Differentiator #10: Evidence Freshness and Assurance Decay — Evidence Document

## Status

**Differentiator #10 Status**: IMPLEMENTED

## Overview

The evidence freshness and assurance decay module provides deterministic assessment of evidence age and semantic drift. It calculates decay based on time-to-live (TTL), identifies configuration changes between audits, and determines whether evidence needs re-audit.

## Implementation

### Core Module (`src/configsentinel/freshness.py`)

**Key Functions**:
- `build_freshness_assessment()`: Build deterministic freshness and drift assessment
- `load_report_for_freshness()`: Load report from file for freshness analysis

**Freshness States**:
- `FRESH`: Age ≤ TTL
- `STALE`: TTL < Age ≤ 2×TTL
- `EXPIRED`: Age > 2×TTL

**Assurance States**:
- `CURRENT`: Fresh and not drifted
- `AGING`: Stale but not drifted
- `EXPIRED`: Expired (regardless of drift)
- `DRIFTED`: Semantic drift detected (regardless of age)

**Drift Detection**:
- Input SHA256 change
- Vendor change
- Parser version change
- Rule pack version change
- Findings added/removed/changed

### Assessment Structure

```python
{
    "schema": "configsentinel.assurance-freshness.v1",
    "source": {
        "audit_id": str,
        "report_sha256": str(Cryptographic digest),
        "observed_at": ISO-8601 timestamp,
        "as_of": ISO-8601 timestamp,
        "ttl_seconds": int,
    },
    "freshness": {
        "age_seconds": float,
        "decay_fraction": float(0-1),
        "remaining_seconds": float,
        "state": "FRESH" | "STALE" | "EXPIRED",
        "model": "linear_age_over_ttl_bounded_0_to_1",
    },
    "drift": {
        "available": bool,
        "drifted": bool,
        "reasons": list[str],
        "added_findings": list[str],
        "removed_findings": list[str],
        "changed_findings": list[str],
        "baseline_input_sha256": str,
        "current_input_sha256": str,
    },
    "assurance": {
        "state": "CURRENT" | "AGING" | "EXPIRED" | "DRIFTED",
        "needs_reaudit": bool,
        "authoritative_verdict_source": "current_deterministic_audit",
        "verdicts_changed": bool,
    },
    "safety": {
        "raw_configuration_included": False,
        "raw_evidence_included": False,
        "live_device_query": False,
        "automatic_approval": False,
        "verdicts_changed": False,
    },
    "assessment_sha256": str(Cryptographic digest),
}
```

### Safety Boundaries

1. **No verdict changes**: Never changes control verdicts
2. **Deterministic**: Same inputs always produce same output
3. **Cryptographic integrity**: SHA256 digests for reports and assessments
4. **No raw data**: Excludes raw configuration and evidence
5. **No live queries**: Never queries devices
6. **No auto-approval**: Never approves automatically
7. **Size limits**: Reports limited to 8 MiB, findings limited to 10,000

## Test Coverage

### Freshness Tests (`tests/test_freshness.py`)

5 tests covering:
- Deterministic assessment (same inputs → same output)
- Stale and expired states require re-audit
- Semantic drift is separate from freshness
- Invalid time and negative age rejection
- CLI integration

**Test Results**: 5/5 passed

## Evidence Chain Example

```
1. Baseline Audit
   - Observed At: 2026-08-27T00:00:00Z
   - Input SHA256: aaaa...
   - Findings: CTRL-1 FAIL

2. Current Audit
   - Observed At: 2026-08-27T00:00:00Z
   - Input SHA256: bbbb...
   - Findings: CTRL-1 PASS

3. Freshness Assessment (as_of: 2026-08-27T01:00:00Z)
   - Age: 3600 seconds
   - Decay: 0.04 (4%)
   - State: FRESH
   - Drifted: True (input_sha256_changed, finding_attributes_changed)
   - Assurance: DRIFTED
   - Needs Re-audit: True

4. Deterministic Integrity
   - Report SHA256: abc123...
   - Assessment SHA256: def456...
   - Reproducible: Same inputs → same output
```

## Differentiation from Existing Solutions

| Feature | ConfigSentinel AI | Typical Evidence Systems |
|---------|-------------------|--------------------------|
| Deterministic decay | Linear model with 0-1 bounded fraction | Often heuristic or absent |
| Semantic drift | Separate from freshness, detailed reasons | Often conflated with age |
| Cryptographic integrity | SHA256 for reports and assessments | Often absent |
| No verdict changes | Explicit safety boundary | Sometimes auto-updates |
| TTL-based states | FRESH/STALE/EXPIRED with clear thresholds | Binary (valid/invalid) |
| Drift detection | Input, parser, rule pack, findings | Often input-only |
| CLI integration | Direct command-line access | Often API-only |

## Limitations

1. **Linear decay model**: Assumes linear decay, may not reflect real-world risk
2. **Manual TTL**: TTL must be configured manually
3. **Baseline required**: Drift detection requires baseline report
4. **Finding limit**: Limited to 10,000 findings per report
5. **Size limit**: Reports limited to 8 MiB
6. **No automatic TTL**: TTL must be set per assessment

## Future Enhancements

1. **Non-linear decay models**: Exponential or custom decay functions
2. **Automatic TTL inference**: Learn TTL from historical data
3. **Risk-weighted decay**: Different decay rates by control severity
4. **Baseline auto-selection**: Automatically select relevant baseline
5. **Trend analysis**: Track freshness and drift over time
6. **Alerting**: Integrate with alerting systems for stale/expired evidence

## Commit Information

**Commit**: Existing implementation (previously committed)  
**Files**:
- `src/configsentinel/freshness.py` (freshness module)
- `tests/test_freshness.py` (5 tests)
- `docs/DIFFERENTIATOR_10_FRESHNESS.md` (this document)

## Test Results Summary

- Backend tests: 252 passed (including 5 freshness tests)
- Freshness tests: 5 passed
- Total tests: 5
