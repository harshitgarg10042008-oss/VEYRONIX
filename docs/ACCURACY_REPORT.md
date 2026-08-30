# Parser & Control Accuracy Report

**Status:** PENDING EXTERNAL FIXTURES (Currently using synthetic local fixtures)
**Date:** Generated 2026-08-30
**Total Fixtures Tested:** 3
**Correctly Detected Vendors:** 2
**Vendor Accuracy:** 66.67%
**Total Controls Evaluated:** 0
**Total Findings Generated:** 0
**Unknown Syntax Rate:** 0/0
**Execution Time:** 0.020 seconds

> **Note:** Real-world accuracy claims for false positives and false negatives require sanitized stakeholder configurations, which are currently pending.

## Fixture Evaluation Matrix

| Fixture | Detected Vendor | Expected Vendor | Controls Evaluated | Findings | Unknown Syntaxes |
|---|---|---|---|---|---|
| `arista.conf` | `error` | `arista_eos` | Error: unable to identify vendor safely: top parser candidates are too close to select safely | - | - |
| `cisco.conf` | `error` | `cisco_ios` | Error: 'DeterministicComplianceEngine' object has no attribute 'audit' | - | - |
| `junos.conf` | `error` | `junos` | Error: 'DeterministicComplianceEngine' object has no attribute 'audit' | - | - |
