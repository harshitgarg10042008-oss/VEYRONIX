"""Offline SIEM export adapters for evidence-backed audit summaries."""
from __future__ import annotations

import json
from typing import Any, Mapping


class SiemError(ValueError):
    """Raised when a report cannot be rendered as a safe SIEM event."""


def _events(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    audit = report.get("audit")
    findings = report.get("findings", [])
    if not isinstance(audit, Mapping) or not isinstance(findings, list):
        raise SiemError("report must contain audit metadata and findings list")
    events: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, Mapping) or str(finding.get("status")) not in {"FAIL", "UNKNOWN", "REVIEW_REQUIRED"}:
            continue
        evidence = finding.get("evidence", [])
        events.append({"event_type": "configsentinel.compliance.finding", "audit_id": str(audit.get("audit_id", "unknown")), "vendor": str(audit.get("vendor", "unknown")), "control_id": str(finding.get("control_id", "unknown")), "finding_id": str(finding.get("finding_id", "unknown")), "status": str(finding.get("status")), "severity": str(finding.get("severity", "INFO")), "confidence": float(finding.get("confidence", 0.0)), "evidence_count": len(evidence) if isinstance(evidence, list) else 0})
    return events


def render_siem(report: Mapping[str, Any], *, fmt: str = "jsonl") -> str:
    events = _events(report)
    if fmt == "jsonl":
        return "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
    lines: list[str] = []
    for event in events:
        if fmt == "cef":
            extension = " ".join(f"{key}={str(value).replace('=', '_').replace(' ', '_')}" for key, value in event.items() if key not in {"event_type", "severity"})
            lines.append(f"CEF:0|VEYRONIX|ConfigSentinel AI|1|{event['control_id']}|Compliance finding|{event['severity']}|{extension}")
        elif fmt == "leef":
            extension = "\t".join(f"{key}={value}" for key, value in event.items() if key not in {"event_type", "severity"})
            lines.append(f"LEEF:2.0|VEYRONIX|ConfigSentinel AI|1|{event['control_id']}\t{extension}")
        else:
            raise SiemError("format must be jsonl, cef, or leef")
    return "\n".join(lines) + ("\n" if lines else "")
