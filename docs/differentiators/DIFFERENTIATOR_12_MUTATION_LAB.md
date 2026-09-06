# Differentiator #12: Control Mutation Quality Lab — Evidence Document

## Status

**Differentiator #12 Status**: IMPLEMENTED

## Overview

The control mutation quality lab generates controlled mutations from labeled fixtures, tests whether controls change as expected, and reports missed mutations and coverage metrics. This provides evidence of control effectiveness and identifies gaps in rule detection.

## Implementation

### Core Data Model (`src/configsentinel/mutation_lab.py`)

**MutationType** enum:
- `SAFE_TO_UNSAFE`: Change from compliant to non-compliant
- `UNSAFE_TO_SAFE`: Change from non-compliant to compliant
- `EQUIVALENT`: No change in compliance status

**MutationOutcome** enum:
- `EXPECTED`: Control changed as expected
- `MISSED`: Control should have changed but didn't
- `UNEXPECTED_FAILURE`: Control changed unexpectedly
- `UNEXPECTED_PASS`: Control passed unexpectedly

**Mutation** dataclass:
- mutation_id: Unique mutation identifier
- control_id: Control being tested
- mutation_type: Type of mutation
- original_config: Original configuration
- mutated_config: Mutated configuration
- description: Human-readable description
- expected_status_before: Expected status before mutation
- expected_status_after: Expected status after mutation

**MutationResult** dataclass:
- mutation: The mutation that was tested
- actual_status_before: Actual status from audit before mutation
- actual_status_after: Actual status from audit after mutation
- outcome: Mutation outcome
- passed: Whether the test passed

**MutationLabReport** dataclass:
- lab_id: Unique lab identifier
- fixture_id: Fixture being tested
- mutations_tested: Total mutations tested
- expected_count: Number with expected outcome
- missed_count: Number of missed mutations
- unexpected_failure_count: Number of unexpected failures
- unexpected_pass_count: Number of unexpected passes
- control_coverage: Control ID to mutation count mapping
- results: Tuple of all mutation results
- generated_at: Timestamp
- limitations: Explicit constraints

### Key Functions

1. **generate_safe_to_unsafe_mutation()**: Create a mutation from compliant to non-compliant
2. **generate_unsafe_to_safe_mutation()**: Create a mutation from non-compliant to compliant
3. **evaluate_mutation()**: Test a mutation by auditing both configs
4. **run_mutation_lab()**: Run mutation lab on a set of mutations
5. **get_missed_mutations()**: Filter missed mutations from report
6. **get_unexpected_failures()**: Filter unexpected failures from report
7. **get_control_quality_metrics()**: Get per-control quality metrics

### Evaluation Logic

1. **Audit original config**: Get baseline status
2. **Audit mutated config**: Get post-mutation status
3. **Compare with expectations**: Determine outcome
4. **Track coverage**: Count mutations per control
5. **Calculate metrics**: Success rate, missed count, etc.

### Safety Boundaries

1. **No mutation on production**: Only tests on provided fixtures
2. **Immutable results**: All dataclasses are frozen
3. **Explicit limitations**: Documents what is not tested
4. **Audit function dependency**: Relies on accurate audit function
5. **Controlled mutations**: Only tests explicitly defined mutations

## Test Coverage

### Mutation Lab Tests (`tests/test_mutation_lab.py`)

17 tests covering:
- Safe-to-unsafe mutation generation
- Unsafe-to-safe mutation generation
- Mutation immutability
- Mutation result immutability
- Lab report immutability
- Expected outcome detection
- Missed mutation detection
- Unexpected failure detection
- Unsafe-to-safe expected outcome
- Running mutation lab with multiple mutations
- Mutation lab with missed mutations
- Filtering missed mutations
- Filtering unexpected failures
- Control coverage tracking
- Per-control quality metrics
- Lab report limitations
- Empty mutation lab

**Test Results**: 17/17 passed

## Evidence Chain Example

```
1. Original Configuration (Compliant)
   - Config: "ssh version 2\n"
   - Status: PASS

2. Mutation (Safe to Unsafe)
   - Mutation ID: mut_abc123
   - Control: NET-MGMT-SSH-001
   - Mutated Config: "ssh version 1\n"
   - Expected: PASS -> FAIL

3. Evaluation
   - Audit Original: PASS (matches expected)
   - Audit Mutated: FAIL (matches expected)
   - Outcome: EXPECTED
   - Passed: True

4. Lab Report
   - Mutations Tested: 1
   - Expected Count: 1
   - Missed Count: 0
   - Success Rate: 100%

5. Quality Metrics
   - NET-MGMT-SSH-001: 100% success rate
   - Coverage: 1 mutation tested
```

## Differentiation from Existing Solutions

| Feature | ConfigSentinel AI | Typical Control Testing |
|---------|-------------------|--------------------------|
| Mutation testing | Explicit mutation generation | Usually manual testing |
| Outcome classification | EXPECTED, MISSED, UNEXPECTED | Binary (pass/fail) |
| Coverage tracking | Per-control mutation count | Often absent |
| Quality metrics | Success rate per control | Usually aggregate only |
| Missed mutation detection | Explicit MISSED outcome | Often silent failures |
| Immutable results | Frozen dataclasses | Often mutable |
| Explicit limitations | Documented in report | Often implicit |

## Limitations

1. **Audit function dependency**: Quality depends on audit function accuracy
2. **Explicit mutations only**: Doesn't discover new mutations automatically
3. **Manual fixture creation**: Requires labeled fixtures
4. **May miss edge cases**: Only tests defined mutations
5. **Success rate depends on mutation quality**: Not just rule quality
6. **No automatic mutation generation**: Mutations must be manually defined

## Future Enhancements

1. **Automatic mutation generation**: Generate mutations from control rules
2. **Edge case discovery**: Automatically discover edge cases
3. **Mutation templates**: Reusable mutation patterns
4. **Trend analysis**: Track quality metrics over time
5. **Regression testing**: Detect quality regressions
6. **Integration with control packs**: Auto-generate mutations from controls

## Commit Information

**Commit**: `feat: implement control mutation quality lab`  
**Files Changed**:
- `src/configsentinel/mutation_lab.py` (mutation lab module)
- `tests/test_mutation_lab.py` (17 tests)
- `docs/DIFFERENTIATOR_12_MUTATION_LAB.md` (this document)

## Test Results Summary

- Backend tests: 247 passed (including 17 new mutation lab tests)
- Mutation lab tests: 17 passed
- Total new tests: 17
