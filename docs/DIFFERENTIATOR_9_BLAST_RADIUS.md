# Differentiator #9: Pre-Change Blast-Radius Simulation — Evidence Document

## Status

**Differentiator #9 Status**: IMPLEMENTED

## Overview

The pre-change blast-radius simulation analyzes proposed changes and predicts their impact on controls, assets, trust boundaries, and evidence without applying any changes. This helps reviewers understand the potential scope of changes before approval.

## Implementation

### Core Data Model (`src/configsentinel/simulation.py`)

**ImpactLabel** enum:
- `DIRECT`: Directly affected by the change
- `DEPENDENT`: Depends on changed component
- `POSSIBLE`: May be affected (uncertain)
- `UNKNOWN`: Cannot determine impact

**Impact** dataclass:
- target_id: Control ID, asset ID, or service ID
- target_type: "control", "asset", "service", "trust_boundary"
- impact_label: Confidence level
- rationale: Explanation of impact
- evidence_required: Whether post-change verification is needed

**SimulationResult** dataclass:
- simulation_id: Unique simulation identifier
- proposed_change_id: Reference to proposed change
- proposed_at: Timestamp
- impacts: Tuple of all predicted impacts
- Impact counts: total, direct, dependent, possible, unknown
- required_post_change_checks: IDs requiring verification
- limitations: Explicit constraints and assumptions

**ProposedChange** dataclass:
- change_id: Unique change identifier
- change_type: "remediation", "config_update", "service_change"
- target_resource_id: Primary resource being changed
- description: Human-readable description
- affected_controls: Tuple of control IDs directly affected
- affected_assets: Tuple of asset IDs directly affected
- metadata: Optional additional information

### Key Functions

1. **simulate_blast_radius()**: Main simulation function with dependency analysis
2. **simulate_remediation_blast_radius()**: Convenience function for remediation-specific simulation

### Simulation Logic

1. **Direct impacts**: All controls and assets in affected_controls/affected_assets
2. **Dependent impacts**: Controls/assets that depend on directly affected ones
3. **Impact labeling**: Direct vs. Dependent based on dependency graph
4. **Evidence requirements**: All direct and dependent impacts require post-change verification
5. **Limitations**: Explicitly documents static analysis limitations

### Safety Boundaries

1. **No mutation**: Simulation never applies changes
2. **Static analysis**: Based on declared dependencies only
3. **Explicit limitations**: Documents what is not considered
4. **Immutable results**: All dataclasses are frozen
5. **Evidence required**: Marks all impacts as requiring verification

## Test Coverage

### Simulation Tests (`tests/test_simulation.py`)

13 tests covering:
- Basic blast-radius simulation
- Simulation with control dependencies
- Simulation with asset dependencies
- Multiple affected controls
- High-confidence impact filtering
- Required post-change checks identification
- Convenience function for remediation
- Limitations inclusion
- Proposed change metadata
- Empty affected controls
- Complex dependency chains
- Impact immutability
- Simulation result immutability

**Test Results**: 13/13 passed

## Evidence Chain Example

```
1. Proposed Change
   - Change ID: change-001
   - Type: remediation
   - Affected Controls: NET-MGMT-SSH-001

2. Dependency Graph
   - NET-MGMT-SSH-001 -> NET-MGMT-TELNET-001
   - NET-MGMT-SSH-001 -> NET-AUTH-AAA-001

3. Simulation Result
   - Direct Impact: NET-MGMT-SSH-001
   - Dependent Impacts: NET-MGMT-TELNET-001, NET-AUTH-AAA-001
   - Total Affected: 3
   - Required Post-Change Checks: 3

4. Reviewer Decision
   - Reviewer sees blast radius before approval
   - Understands potential scope of change
   - Can request additional testing if needed
```

## Differentiation from Existing Solutions

| Feature | ConfigSentinel AI | Typical Change Management |
|---------|-------------------|--------------------------|
| Pre-change impact analysis | Explicit simulation with labels | Often manual or absent |
| Dependency tracking | Control and asset dependencies | Usually asset-only |
| Impact confidence levels | DIRECT, DEPENDENT, POSSIBLE, UNKNOWN | Binary (affected/not) |
| Evidence requirements | Automatic flagging | Manual checklist |
| Immutable results | Frozen dataclasses | Often mutable |
| Explicit limitations | Documented in result | Often implicit |
| No mutation guarantee | Never applies changes | Sometimes auto-applies |

## Limitations

1. **Static analysis only**: Runtime dependencies not considered
2. **One-level dependencies**: Only direct dependencies analyzed
3. **Manual dependency input**: Dependencies must be provided
4. **No cross-organization**: Doesn't analyze cross-org dependencies
5. **Estimates not guarantees**: Impact predictions are estimates
6. **No network topology**: Doesn't consider network-level dependencies

## Future Enhancements

1. **Multi-level dependencies**: Recursive dependency analysis
2. **Runtime dependency discovery**: Auto-detect dependencies from config
3. **Network topology analysis**: Include network-level dependencies
4. **Risk scoring**: Add risk scores to impacts
5. **Visualization**: Generate dependency graphs
6. **Historical comparison**: Compare with previous similar changes

## Commit Information

**Commit**: `feat: implement pre-change blast-radius simulation`  
**Files Changed**:
- `src/configsentinel/simulation.py` (simulation module)
- `tests/test_simulation.py` (13 tests)
- `docs/DIFFERENTIATOR_9_BLAST_RADIUS.md` (this document)

## Test Results Summary

- Backend tests: 216 passed (including 13 new simulation tests)
- Simulation tests: 13 passed
- Total new tests: 13
