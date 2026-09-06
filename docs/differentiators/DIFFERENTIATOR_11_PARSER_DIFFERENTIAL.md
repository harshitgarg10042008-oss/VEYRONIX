# Differentiator #11: Parser Differential and Ambiguity Analysis — Evidence Document

## Status

**Differentiator #11 Status**: IMPLEMENTED

## Overview

The parser differential and ambiguity analysis runs multiple parsing strategies on the same input and compares the interpretations to identify ambiguities that affect control results. This helps identify parser-specific issues and prioritize improvements.

## Implementation

### Core Data Model (`src/configsentinel/parser_differential.py`)

**DisagreementType** enum:
- `CONTROL_STATUS`: Different control pass/fail status
- `EVIDENCE_SPAN`: Different evidence locations
- `SEVERITY`: Different severity levels
- `MISSING_CONTROL`: Control found in one but not other
- `EXTRA_CONTROL`: Control found in one but not other

**ParserResult** dataclass:
- parser_id: Unique parser identifier
- parser_version: Parser version string
- vendor: Target vendor (e.g., cisco_ios)
- syntax_family: Syntax family (e.g., ios)
- control_results: Control ID to result mapping
- parse_success: Whether parsing succeeded
- parse_error: Error message if parsing failed

**Disagreement** dataclass:
- control_id: Control ID with disagreement
- disagreement_type: Type of disagreement
- parser_a_result: Result from parser A
- parser_b_result: Result from parser B
- parser_a_id: Parser A identifier
- parser_b_id: Parser B identifier
- rationale: Explanation of disagreement
- requires_review: Whether this requires human review

**DifferentialAnalysis** dataclass:
- analysis_id: Unique analysis identifier
- input_id: Input being analyzed
- parser_a: First parser result
- parser_b: Second parser result
- disagreements: Tuple of all disagreements
- agreement_count: Number of controls with same result
- disagreement_count: Number of controls with differences
- requires_review_count: Number requiring human review
- analyzed_at: Timestamp
- limitations: Explicit constraints

### Key Functions

1. **compare_parser_results()**: Compare two parser results and identify disagreements
2. **track_disagreement_metrics()**: Aggregate metrics across multiple analyses
3. **create_ambiguity_finding()**: Create review queue entry for ambiguous controls

### Comparison Logic

1. **Control status comparison**: Identifies PASS/FAIL differences
2. **Severity comparison**: Identifies severity level differences
3. **Missing control detection**: Controls found in one parser but not other
4. **Extra control detection**: Controls found in one parser but not other
5. **Review flagging**: Status disagreements require review, severity disagreements do not

### Safety Boundaries

1. **No mutation**: Comparison never modifies parser results
2. **Immutable results**: All dataclasses are frozen
3. **Explicit limitations**: Documents what is not analyzed
4. **Review queue integration**: Creates findings for human review
5. **Metrics tracking**: Enables trend analysis over time

## Test Coverage

### Parser Differential Tests (`tests/test_parser_differential.py`)

14 tests covering:
- Identical parser results
- Control status disagreement
- Severity disagreement
- Missing control detection
- Extra control detection
- Multiple disagreement types
- Disagreement metrics aggregation
- Ambiguity finding creation
- No disagreement error handling
- Parser result immutability
- Disagreement immutability
- Analysis immutability
- Limitations inclusion
- Parse error handling

**Test Results**: 14/14 passed

## Evidence Chain Example

```
1. Input Configuration
   - Input ID: config-001
   - Vendor: cisco_ios
   - Content: router configuration

2. Parser A Results
   - NET-MGMT-SSH-001: PASS (LOW)
   - NET-MGMT-TELNET-001: FAIL (HIGH)

3. Parser B Results
   - NET-MGMT-SSH-001: FAIL (MEDIUM)
   - NET-MGMT-TELNET-001: FAIL (HIGH)

4. Differential Analysis
   - Disagreements: 2 (status + severity for SSH-001)
   - Requires Review: 1 (status disagreement)
   - Agreement Count: 1 (TELNET-001)

5. Review Queue Entry
   - Finding ID: amb_diff_xyz123_NET-MGMT-SSH-001
   - Type: PARSER_AMBIGUITY
   - Requires Review: True
```

## Differentiation from Existing Solutions

| Feature | ConfigSentinel AI | Typical Configuration Tools |
|---------|-------------------|---------------------------|
| Multi-parser comparison | Explicit differential analysis | Usually single parser |
| Disagreement classification | Status, severity, missing, extra | Binary (match/mismatch) |
| Review queue integration | Automatic finding creation | Manual review |
| Metrics aggregation | By vendor, syntax, version | Often absent |
| Immutable results | Frozen dataclasses | Often mutable |
| Explicit limitations | Documented in analysis | Often implicit |
| Trend analysis | Metrics over time | Usually one-off |

## Limitations

1. **Control-level only**: Doesn't analyze evidence span differences in detail
2. **Manual parser input**: Requires running parsers separately
3. **Binary comparison**: Doesn't handle partial matches
4. **No semantic analysis**: Doesn't understand why parsers disagree
5. **False positives**: Benign differences may trigger review
6. **No auto-resolution**: Doesn't attempt to resolve disagreements

## Future Enhancements

1. **Evidence span comparison**: Compare exact evidence locations
2. **Semantic analysis**: Understand root causes of disagreements
3. **Auto-resolution**: Attempt to resolve benign differences
4. **Multi-parser comparison**: Compare more than 2 parsers
5. **Trend visualization**: Show disagreement trends over time
6. **Parser improvement suggestions**: Recommend parser fixes based on patterns

## Commit Information

**Commit**: `feat: implement parser differential and ambiguity analysis`  
**Files Changed**:
- `src/configsentinel/parser_differential.py` (parser differential module)
- `tests/test_parser_differential.py` (14 tests)
- `docs/DIFFERENTIATOR_11_PARSER_DIFFERENTIAL.md` (this document)

## Test Results Summary

- Backend tests: 230 passed (including 14 new parser differential tests)
- Parser differential tests: 14 passed
- Total new tests: 14
