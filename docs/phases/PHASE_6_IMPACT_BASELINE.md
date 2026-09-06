# Phase 6 — Control, Parser, and Impact Baseline

## Reproducible local benchmark

The existing `examples/phase10_benchmark.py` was executed against the repository’s deterministic audit engine.

| Metric | Observed result |
|---|---:|
| Iterations | 5 |
| Minimum latency | 0.034 ms |
| Maximum latency | 0.061 ms |
| Mean latency | 0.041 ms |
| P95 latency | 0.061 ms |
| Findings per sample | 7 |
| Failures per sample | 1 |
| External services | None |
| Device connections | None |

These values demonstrate that the local fixture path is fast and reproducible. They are **not** a fleet-scale performance claim because the benchmark uses a small synthetic/sample configuration and five iterations.

## Current control and parser coverage

The built-in registry currently exposes seven deterministic controls: secure SSH, Telnet prohibition, AAA, security logging, NTP, secure SNMP, and plain HTTP management. The parser registry represents Cisco IOS, Juniper Junos, generic firewall syntax, Arista EOS, and Linux nftables.

Coverage breadth is useful for a prototype, but full SIH marks require a versioned fixture matrix for each parser family, expected outcomes, unsupported-syntax rates, and false-positive/false-negative analysis. Those measurements require representative configurations supplied by the team or an approved lab dataset; they must not be invented.

## Impact measurement plan

The final evidence pack should measure baseline manual review time, automated review time, number of findings requiring manual investigation, unknown/unsupported syntax rate, remediation-review cycle time, and prevented high/critical configuration regressions. Each metric must include sample size, configuration/vendor mix, measurement method, and limitations.

## Acceptance interpretation

Phase 6 is partially evidenced: local deterministic performance is measured and documented. The remaining domain-accuracy and real-world-impact claims are intentionally marked as pending rather than presented as achieved. This preserves the project’s evidence-first integrity.
