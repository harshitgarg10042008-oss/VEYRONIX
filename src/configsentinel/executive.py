"""Executive posture reporting from evidence-backed audit results."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import AuditResult, FindingStatus, Severity


@dataclass(frozen=True)
class ExecutiveReport:
    generated_at: str
    audit_id: str
    vendor: str
    input_sha256: str
    posture: str
    evaluated: int
    total_findings: int
    failed: int
    unknown: int
    mapped: int
    severity_counts: dict[str, int]
    control_coverage_percent: float
    top_risks: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {"generated_at": self.generated_at, "audit_id": self.audit_id, "vendor": self.vendor, "input_sha256": self.input_sha256, "posture": self.posture, "evaluated": self.evaluated, "total_findings": self.total_findings, "failed": self.failed, "unknown": self.unknown, "mapped": self.mapped, "severity_counts": self.severity_counts, "control_coverage_percent": self.control_coverage_percent, "top_risks": list(self.top_risks)}


def build_executive_report(result: AuditResult) -> ExecutiveReport:
    failed = [finding for finding in result.findings if finding.status == FindingStatus.FAIL]
    unknown = sum(finding.status in {FindingStatus.UNKNOWN, FindingStatus.REVIEW_REQUIRED} for finding in result.findings)
    evaluated = result.evaluated_count
    severity_counts = {severity.value: sum(finding.severity == severity for finding in result.findings) for severity in Severity}
    posture = "CRITICAL" if any(finding.severity == Severity.CRITICAL for finding in failed) else "ATTENTION" if failed or unknown else "CLEAR"
    top_risks = tuple({"control_id": finding.control_id, "severity": finding.severity.value, "status": finding.status.value, "evidence_lines": [span.start_line for span in finding.evidence], "rationale": finding.rationale[:240]} for finding in sorted(failed, key=lambda item: (list(Severity).index(item.severity), item.control_id))[:5])
    return ExecutiveReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        audit_id=result.audit_id,
        vendor=result.vendor,
        input_sha256=result.input_sha256,
        posture=posture,
        evaluated=evaluated,
        total_findings=len(result.findings),
        failed=len(failed),
        unknown=unknown,
        mapped=sum(bool(finding.evidence) for finding in result.findings),
        severity_counts=severity_counts,
        control_coverage_percent=round((evaluated / len(result.findings) * 100) if result.findings else 0.0, 1),
        top_risks=top_risks,
    )


def render_executive_markdown(report: ExecutiveReport) -> str:
    lines = ["# ConfigSentinel AI executive posture report", "", f"- Posture: **{report.posture}**", f"- Audit: `{report.audit_id}`", f"- Vendor: `{report.vendor}`", f"- Input SHA-256: `{report.input_sha256}`", "", "## Portfolio metrics", "", "| Metric | Value |", "|---|---:|", f"| Total findings | {report.total_findings} |", f"| Failed controls | {report.failed} |", f"| Unknown/review controls | {report.unknown} |", f"| Evaluated controls | {report.evaluated} |", f"| Control coverage | {report.control_coverage_percent}% |", "", "## Severity distribution", "", "| Severity | Count |", "|---|---:|"]
    lines.extend(f"| {severity} | {count} |" for severity, count in report.severity_counts.items())
    lines.extend(["", "## Top risks", ""])
    if report.top_risks:
        lines.extend(f"- **{risk['control_id']}** ({risk['severity']}): {risk['rationale']} Evidence lines: {', '.join(map(str, risk['evidence_lines'])) or 'none'}." for risk in report.top_risks)
    else:
        lines.append("No failed controls were identified.")
    lines.extend(["", "> This report is evidence-backed and review-only. It does not authorize device changes."])
    return "\n".join(lines) + "\n"


def render_executive_json(report: ExecutiveReport) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=True) + "\n"
