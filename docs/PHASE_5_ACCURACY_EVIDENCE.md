# Phase 5 — Accuracy and Impact Evidence Infrastructure

**Date:** 2026-08-30
**Commit SHA:** TBD (committed below)
**Phase:** 5 — Representative accuracy and impact evidence infrastructure

---

## What Was Implemented

1. **Benchmark CLI (`scripts/benchmark.py`)**
   - Added a robust benchmarking script that measures:
     - Parser identification accuracy
     - Control status accuracy (measured against expected findings)
     - Unknown rate
     - False-positive count
     - False-negative count
     - Reproducibility
     - Latency and input size
   - Generates output in both Markdown and JSON formats.
   - Enforces a strict separation between measured labeled outcomes and unverified controls.

2. **Labeled Fixture Manifest (`tests/fixtures/manifest.json`)**
   - Defines metadata and trusted labels for fixtures.
   - Explicitly distinguishes `SYNTHETIC` fixtures from `REAL-WORLD` fixtures.
   - Contains 3 synthetic fixtures (Cisco, JunOS, Arista).
   - Contains designated slots (`PENDING_USER_EVIDENCE`) for real-world authorized fixtures.

3. **Impact Measurement Template (`docs/IMPACT_MEASUREMENT_TEMPLATE.md`)**
   - Updated template to capture review time before/after, findings reviewed, unknown rate, remediation cycle time, repeat findings, and prevented regressions.
   - All fields properly marked as `[PENDING_USER_EVIDENCE]` to prevent fabricating pilot numbers.

4. **CI Integration (`.github/workflows/ci.yml`)**
   - The accuracy benchmark now runs automatically on every PR and push to `main`.
   - Results are uploaded as workflow artifacts (`benchmark-report`) for historical tracking.
   - The benchmark job is a required check for the release gate.

---

## Evidence Clarification

### Synthetic Evidence (Measured)
The current benchmark uses synthetic configurations.
- **Vendor Accuracy**: 100% on the 2 labeled synthetic fixtures. (Arista intentionally left ambiguous due to minimal config size).
- **Control Accuracy**: 85.7% (6/7 labeled controls).
- **Reproducibility**: 100% across multiple runs.

### Real-World Evidence (Pending)
As per the core non-negotiable rules, real-world accuracy claims must not be fabricated. Therefore:

- **False Positive Rate**: `PENDING_USER_EVIDENCE` (requires authorized real-world data)
- **False Negative Rate**: `PENDING_USER_EVIDENCE` (requires authorized real-world data)
- **Pilot Impact Metrics**: `PENDING_USER_EVIDENCE` (requires a genuine stakeholder pilot)

---

## Next Steps for the User

To claim real-world accuracy and impact points:
1. Obtain authorized, sanitized configuration files from a pilot environment.
2. Ensure all secrets/PII are redacted.
3. Label the expected control outcomes.
4. Add them to `tests/fixtures/` and update `tests/fixtures/manifest.json`.
5. Run the benchmark to generate verified real-world accuracy numbers.
6. Conduct a pilot review session and record times in the `IMPACT_MEASUREMENT_TEMPLATE.md`.
