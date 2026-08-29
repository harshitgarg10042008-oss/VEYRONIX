"""Resource-level least-privilege intent compilation for local review."""

from __future__ import annotations

import json
from typing import Any, Mapping

INTENT_SCHEMA = "configsentinel.resource-intent.v1"


class IntentError(ValueError):
    """Raised when a resource intent is malformed or cannot be checked safely."""


CONTROL_REQUIREMENTS = {
    "ssh_management": ("NET-MGMT-SSH-001", "PASS"),
    "no_telnet": ("NET-MGMT-TELNET-001", "PASS"),
    "no_plain_http": ("NET-MGMT-HTTP-001", "PASS"),
}


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IntentError(f"{label} must be an object")
    return value


def _bounded_text(value: Any, label: str, limit: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise IntentError(f"{label} is required and must be bounded")
    return text


def _finding_index(report: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    if report is None:
        return {}
    findings = report.get("findings", [])
    if not isinstance(findings, list) or len(findings) > 10000:
        raise IntentError("report findings are invalid or exceed limits")
    indexed: dict[str, Mapping[str, Any]] = {}
    for raw in findings:
        finding = _object(raw, "report finding")
        control_id = _bounded_text(finding.get("control_id"), "finding control_id")
        if control_id in indexed:
            raise IntentError(f"duplicate finding control: {control_id}")
        indexed[control_id] = finding
    return indexed


def _status_check(
    control_id: str, expected: str, findings: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    finding = findings.get(control_id)
    if finding is None:
        return {
            "control_id": control_id,
            "expected_status": expected,
            "observed_status": "NO_EVIDENCE",
            "state": "UNKNOWN",
            "evidence": [],
            "reason": "The supplied report contains no finding for this required control.",
        }
    status = str(finding.get("status", "UNKNOWN")).upper()
    evidence = finding.get("evidence", [])
    evidence_refs = []
    if isinstance(evidence, list):
        for span in evidence:
            if isinstance(span, Mapping):
                evidence_refs.append(
                    {
                        "start_line": span.get("start_line"),
                        "end_line": span.get("end_line"),
                        "redacted": bool(span.get("redacted", True)),
                    }
                )
    state = (
        "SATISFIED"
        if status == expected and evidence_refs
        else ("VIOLATED" if status == "FAIL" else "UNKNOWN")
    )
    return {
        "control_id": control_id,
        "expected_status": expected,
        "observed_status": status,
        "state": state,
        "evidence": evidence_refs,
        "finding_id": str(finding.get("finding_id", "")),
        "reason": "Derived from the supplied deterministic finding status and evidence references.",
    }


def compile_resource_intent(
    intent: Mapping[str, Any],
    *,
    report: Mapping[str, Any] | None = None,
    topology: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile intent into checks; it never emits executable vendor configuration."""
    subject = _bounded_text(intent.get("subject"), "intent.subject")
    resource = _bounded_text(intent.get("resource"), "intent.resource")
    allowed_via = intent.get("allowed_via", [])
    protocols = intent.get("protocols", ["ssh"])
    requirements = intent.get(
        "requirements", ["ssh_management", "no_telnet", "no_plain_http"]
    )
    if not isinstance(allowed_via, list) or not allowed_via or len(allowed_via) > 32:
        raise IntentError("intent.allowed_via must be a bounded non-empty array")
    if not isinstance(protocols, list) or not protocols or len(protocols) > 16:
        raise IntentError("intent.protocols must be a bounded non-empty array")
    if (
        not isinstance(requirements, list)
        or not requirements
        or len(requirements) > len(CONTROL_REQUIREMENTS)
    ):
        raise IntentError(
            "intent.requirements are invalid or exceed supported controls"
        )
    normalized_requirements = [str(item).strip() for item in requirements]
    if any(item not in CONTROL_REQUIREMENTS for item in normalized_requirements):
        raise IntentError("intent contains an unsupported requirement")
    findings = _finding_index(report)
    checks = [
        _status_check(*CONTROL_REQUIREMENTS[item], findings)
        for item in normalized_requirements
    ]
    if topology is not None:
        nodes = topology.get("nodes", [])
        known = (
            {str(node.get("id")) for node in nodes if isinstance(node, Mapping)}
            if isinstance(nodes, list)
            else set()
        )
        for hop in allowed_via:
            if str(hop).strip() not in known:
                raise IntentError(
                    f"allowed_via asset is absent from the supplied topology: {hop}"
                )
    violated = sum(check["state"] == "VIOLATED" for check in checks)
    unknown = sum(check["state"] == "UNKNOWN" for check in checks)
    return {
        "schema": INTENT_SCHEMA,
        "intent": {
            "intent_id": _bounded_text(
                intent.get("intent_id", "intent-local"), "intent_id"
            ),
            "subject": subject,
            "resource": resource,
            "allowed_via": [str(item)[:128] for item in allowed_via],
            "protocols": [str(item)[:64] for item in protocols],
            "requirements": normalized_requirements,
            "provenance": "operator_declared",
        },
        "checks": checks,
        "summary": {
            "state": (
                "VIOLATED"
                if violated
                else ("REVIEW_REQUIRED" if unknown else "SATISFIED")
            ),
            "check_count": len(checks),
            "satisfied_count": sum(check["state"] == "SATISFIED" for check in checks),
            "violated_count": violated,
            "unknown_count": unknown,
        },
        "safety": {
            "vendor_configuration_emitted": False,
            "commands_executable": False,
            "live_network_access": False,
            "traffic_inference": False,
            "verdicts_changed": False,
            "note": "Intent compilation checks a declared resource policy against deterministic report evidence; it does not prove reachability or authorize changes.",
        },
    }


def render_intent_report(report: Mapping[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


__all__ = [
    "INTENT_SCHEMA",
    "IntentError",
    "compile_resource_intent",
    "render_intent_report",
]
