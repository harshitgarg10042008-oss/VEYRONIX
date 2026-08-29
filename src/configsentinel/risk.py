"""Deterministic risk prioritization layered on top of compliance findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class RiskError(ValueError):
    """Raised when risk inputs are invalid."""


_SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_STATUS = {
    "PASS": 0,
    "NOT_APPLICABLE": 0,
    "UNKNOWN": 1,
    "REVIEW_REQUIRED": 1,
    "FAIL": 2,
}
_CRITICALITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class RiskItem:
    finding_id: str
    control_id: str
    status: str
    severity: str
    asset_criticality: str
    score: int
    priority: str
    rationale: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "control_id": self.control_id,
            "status": self.status,
            "severity": self.severity,
            "asset_criticality": self.asset_criticality,
            "score": self.score,
            "priority": self.priority,
            "rationale": list(self.rationale),
        }


def prioritize_report(
    report: Mapping[str, Any], *, asset_criticality: str = "medium"
) -> tuple[RiskItem, ...]:
    if not isinstance(report.get("findings"), list):
        raise RiskError("report findings must be a list")
    normalized_criticality = asset_criticality.lower()
    if normalized_criticality not in _CRITICALITY:
        raise RiskError("asset criticality must be low, medium, high, or critical")
    items: list[RiskItem] = []
    for finding in report["findings"]:
        if not isinstance(finding, Mapping):
            raise RiskError("each finding must be an object")
        status, severity = str(finding.get("status", "UNKNOWN")), str(
            finding.get("severity", "INFO")
        )
        if status not in _STATUS or severity not in _SEVERITY:
            raise RiskError("finding status or severity is invalid")
        if status not in {"FAIL", "UNKNOWN", "REVIEW_REQUIRED"}:
            continue
        confidence = float(finding.get("confidence", 0.0))
        if not 0.0 <= confidence <= 1.0:
            raise RiskError("finding confidence must be between 0 and 1")
        score = (
            (_SEVERITY[severity] * 20)
            + (_STATUS[status] * 20)
            + (_CRITICALITY[normalized_criticality] * 10)
            + round(confidence * 10)
        )
        priority = (
            "P1"
            if score >= 100
            else "P2" if score >= 70 else "P3" if score >= 40 else "P4"
        )
        rationale = (
            f"severity={severity}",
            f"status={status}",
            f"asset_criticality={normalized_criticality}",
            f"confidence={confidence:.2f}",
        )
        items.append(
            RiskItem(
                str(finding.get("finding_id", "unknown")),
                str(finding.get("control_id", "unknown")),
                status,
                severity,
                normalized_criticality,
                score,
                priority,
                rationale,
            )
        )
    return tuple(sorted(items, key=lambda item: (-item.score, item.finding_id)))


def risk_report(
    report: Mapping[str, Any], *, asset_criticality: str = "medium"
) -> dict[str, Any]:
    items = prioritize_report(report, asset_criticality=asset_criticality)
    return {
        "schema": "configsentinel.risk.v1",
        "verdict_source": "deterministic_compliance_report",
        "asset_criticality": asset_criticality.lower(),
        "items": [item.as_dict() for item in items],
        "safety_note": "Risk priority is a review aid; it does not change compliance status or authorize remediation.",
    }
