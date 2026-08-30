# ConfigSentinel AI — Accuracy Benchmark Report

**Dataset:** `configsentinel-synthetic-v1` (SYNTHETIC)
**Timestamp:** 2026-08-30T09:46:05.658065+00:00
**Commit SHA:** `8bbea88c6f31`
**Control-pack version:** `3.0.0`
**Controls in pack:** 7
**Fixture runs (reproducibility):** 3

> **Note:** All fixtures in this dataset are **SYNTHETIC** — crafted to exercise
> specific code paths. This is **not** real-world validation. False-positive and
> false-negative rates against real production configurations are
> `PENDING_USER_EVIDENCE`.

## Summary

| Metric | Value |
|--------|-------|
| Total fixtures | 3 |
| Errored fixtures | 1 |
| Vendor-labeled fixtures | 2 |
| Vendor identification correct | 2 / 2 |
| **Vendor accuracy (labeled)** | **100.0%** |
| Control-labeled controls tested | 7 |
| Correct labeled control outcomes | 6 |
| **Control accuracy (labeled)** | **85.71%** |
| False positives (labeled) | 0 |
| False negatives (labeled) | 0 |
| Total findings | 14 |
| Unknown / N/A findings | 8 |
| Unknown rate | 57.14% |
| All runs reproducible | ✅ Yes |

## Per-Fixture Results

| Fixture | Source | Detected Vendor | Vendor ✓ | Findings | Unknown | Labeled Controls | Correct | FP | FN | Repro | Latency (ms) |
|---------|--------|-----------------|----------|----------|---------|-----------------|---------|----|----|-------|--------------|
| `arista.conf` | SYNTHETIC | error | — | — | — | — | — | — | — | — | — |
| `cisco.conf` | SYNTHETIC | `cisco_ios` | ✅ | 7 | 1 | 7 | 6 | 0 | 0 | ✅ | 0.16 |
| `junos.conf` | SYNTHETIC | `junos` | ✅ | 7 | 7 | 0 | 0 | 0 | 0 | ✅ | 0.11 |

## Limitations

- All fixtures in this manifest are synthetically crafted to exercise specific control paths.
- Synthetic fixtures do NOT constitute real-world validation.
- False-positive and false-negative rates against real production configurations are PENDING_USER_EVIDENCE.
- Parser accuracy on sanitized real-world configs requires user-provided, authorized, sanitized samples.
- Control accuracy is only measured against fixtures with labeled expected_controls.
- Unlabeled controls produce counts but cannot contribute to accuracy rates.
- Reproducibility is measured across fixture runs within this benchmark run only.
- Real-world false-positive/false-negative rates are PENDING_USER_EVIDENCE.

## Evidence Classification

| Category | Status |
|----------|--------|
| Parser vendor identification (synthetic) | Measured — see table above |
| Control status accuracy (synthetic, labeled) | Measured — see table above |
| Reproducibility | Measured — deterministic across runs |
| False-positive rate (real-world) | `PENDING_USER_EVIDENCE` |
| False-negative rate (real-world) | `PENDING_USER_EVIDENCE` |
| Pilot deployment accuracy | `PENDING_USER_EVIDENCE` |
