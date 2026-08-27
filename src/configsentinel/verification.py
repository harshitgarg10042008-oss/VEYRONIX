"""Deterministic safety invariants for audit reports and benchmark fixtures."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    checks: tuple[str, ...]
    violations: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "checks": list(self.checks), "violations": list(self.violations)}


def verify_report(report: dict[str, Any]) -> VerificationResult:
    checks: list[str] = []
    violations: list[str] = []
    if not isinstance(report, dict) or not isinstance(report.get("audit"), dict):
        return VerificationResult(False, (), ("audit metadata is missing",))
    checks.append("audit metadata present")
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        return VerificationResult(False, tuple(checks), ("findings must be a list",))
    checks.append("findings list typed")
    allowed = {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"}
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            violations.append(f"finding {index} is not an object")
            continue
        status = finding.get("status")
        if status not in allowed:
            violations.append(f"finding {index} has invalid status")
        if status == "FAIL" and not finding.get("evidence"):
            violations.append(f"finding {index} FAIL lacks evidence")
        if "config_text" in finding or "raw_config" in finding:
            violations.append(f"finding {index} contains raw configuration")
    checks.append("status and evidence invariants checked")
    return VerificationResult(not violations, tuple(checks), tuple(violations))


def benchmark_cases() -> tuple[dict[str, Any], ...]:
    return (
        {"name": "evidence-backed-fail", "report": {"audit": {"audit_id": "fixture-1"}, "findings": [{"status": "FAIL", "evidence": [{"line": 1}]}]}, "expected": True},
        {"name": "fail-without-evidence", "report": {"audit": {"audit_id": "fixture-2"}, "findings": [{"status": "FAIL"}]}, "expected": False},
        {"name": "unknown-is-reviewable", "report": {"audit": {"audit_id": "fixture-3"}, "findings": [{"status": "UNKNOWN"}]}, "expected": True},
        {"name": "raw-config-rejected", "report": {"audit": {"audit_id": "fixture-4"}, "findings": [{"status": "PASS", "raw_config": "secret"}]}, "expected": False},
    )


def run_benchmark() -> dict[str, Any]:
    results = [{"name": case["name"], "expected": case["expected"], "actual": verify_report(case["report"]).valid} for case in benchmark_cases()]
    return {"passed": all(item["expected"] == item["actual"] for item in results), "cases": results}
