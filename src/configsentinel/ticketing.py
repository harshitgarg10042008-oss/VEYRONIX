"""Offline ticketing adapters; they create review artifacts and never submit tickets."""

from __future__ import annotations

import json
from typing import Any


class TicketingError(ValueError):
    """Raised when a report cannot be converted safely."""


def _findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise TicketingError("report findings must be a list")
    return [
        item
        for item in findings
        if isinstance(item, dict) and item.get("status") in {"FAIL", "UNKNOWN"}
    ]


def build_ticket_payload(report: dict[str, Any], adapter: str) -> dict[str, Any]:
    if not isinstance(report, dict) or not isinstance(report.get("audit"), dict):
        raise TicketingError("audit report must contain audit metadata")
    findings = _findings(report)
    audit = report["audit"]
    audit_id = str(audit.get("audit_id", "unknown"))
    vendor = str(audit.get("vendor", "unknown"))
    failed = sum(item.get("status") == "FAIL" for item in findings)
    unknown = sum(item.get("status") == "UNKNOWN" for item in findings)
    title = f"ConfigSentinel AI compliance review: {vendor} / {audit_id}"
    body = "\n".join(
        [
            f"ConfigSentinel AI evidence review for audit `{audit_id}`.",
            f"Vendor: `{vendor}`",
            f"Actionable failures: {failed}; unknown/manual-review findings: {unknown}.",
            "",
            *[
                f"- `{item.get('control_id', 'unknown')}` — {item.get('severity', 'UNKNOWN')} / {item.get('status', 'UNKNOWN')}: {item.get('title', item.get('message', 'Review evidence'))}"
                for item in findings
            ],
            "",
            "This is a review artifact. No device connection, ticket submission, or remediation execution was performed.",
        ]
    )
    if adapter == "jira":
        return {
            "fields": {
                "summary": title,
                "description": body,
                "issuetype": {"name": "Task"},
                "labels": ["configsentinel", "compliance-review"],
                "environment": "local-first; evidence-backed",
            }
        }
    if adapter == "github":
        return {
            "title": title,
            "body": body,
            "labels": ["configsentinel", "compliance-review"],
        }
    if adapter == "generic":
        return {
            "title": title,
            "body": body,
            "audit_id": audit_id,
            "vendor": vendor,
            "finding_count": len(findings),
            "findings": [
                {
                    "control_id": item.get("control_id"),
                    "status": item.get("status"),
                    "severity": item.get("severity"),
                    "title": item.get("title", item.get("message", "Review evidence")),
                }
                for item in findings
            ],
        }
    raise TicketingError(f"unsupported adapter: {adapter}")


def render_ticket_markdown(report: dict[str, Any]) -> str:
    payload = build_ticket_payload(report, "generic")
    return f"# {payload['title']}\n\n{payload['body']}\n\n## Structured metadata\n\n```json\n{json.dumps({k: payload[k] for k in ('audit_id', 'vendor', 'finding_count')}, indent=2, sort_keys=True)}\n```\n"
