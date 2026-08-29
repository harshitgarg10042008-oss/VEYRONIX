"""Hash-linked policy provenance compilation for evidence-first assurance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .policies import CustomPolicyPack, PolicyValidationError

PROVENANCE_SCHEMA = "configsentinel.policy-provenance.v1"
VERIFY_SCHEMA = "configsentinel.policy-provenance-verify.v1"
MAX_POLICY_BYTES = 256 * 1024
MAX_FINDINGS = 10000


class ProvenanceError(ValueError):
    """Raised when policy provenance cannot be safely compiled or verified."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, label: str, limit: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise ProvenanceError(f"{label} is required and bounded")
    return text


def _load_json(path: str | Path, limit: int) -> dict[str, Any]:
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > limit:
        raise ProvenanceError(
            "provenance input path is invalid or exceeds its size limit"
        )
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError("provenance input must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ProvenanceError("provenance input must be a JSON object")
    return value


def load_policy(path: str | Path) -> dict[str, Any]:
    return _load_json(path, MAX_POLICY_BYTES)


def _rule_payload(rule: Any, index: int) -> dict[str, Any]:
    mapping = {
        name: list(values) for name, values in sorted(rule.framework_mappings.items())
    }
    return {
        "rule_index": index,
        "control_id": rule.control_id,
        "title": rule.title,
        "intent": rule.intent,
        "severity": rule.severity.value,
        "mode": rule.mode,
        "applies_to": sorted(rule.applies_to),
        "regex_sha256": hashlib.sha256(
            rule.pattern.pattern.encode("utf-8")
        ).hexdigest(),
        "framework_mappings": mapping,
        "remediation_sha256": hashlib.sha256(
            rule.remediation.encode("utf-8")
        ).hexdigest(),
    }


def _report_meta(report: Mapping[str, Any]) -> dict[str, Any]:
    audit = report.get("audit")
    findings = report.get("findings")
    if (
        not isinstance(audit, Mapping)
        or not isinstance(findings, list)
        or len(findings) > MAX_FINDINGS
    ):
        raise ProvenanceError("report must contain bounded audit metadata and findings")
    return {
        "audit_id": str(audit.get("audit_id", "unknown"))[:128],
        "vendor": str(audit.get("vendor", "unknown"))[:64],
        "input_sha256": str(audit.get("input_sha256", "unknown"))[:128],
    }


def _finding_lineage(
    report: Mapping[str, Any], control_ids: set[str]
) -> list[dict[str, Any]]:
    findings = report.get("findings", [])
    result: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise ProvenanceError("report findings must be objects")
        control_id = _text(finding.get("control_id"), "finding.control_id")
        if control_id not in control_ids:
            continue
        evidence = finding.get("evidence", [])
        evidence_hashes: list[dict[str, Any]] = []
        if isinstance(evidence, list):
            for span in evidence:
                if isinstance(span, Mapping):
                    excerpt = str(span.get("excerpt", ""))
                    evidence_hashes.append(
                        {
                            "start_line": span.get("start_line"),
                            "end_line": span.get("end_line"),
                            "excerpt_sha256": hashlib.sha256(
                                excerpt.encode("utf-8")
                            ).hexdigest(),
                        }
                    )
        result.append(
            {
                "finding_id": _text(finding.get("finding_id"), "finding.finding_id"),
                "control_id": control_id,
                "status": str(finding.get("status", "UNKNOWN"))[:32],
                "severity": str(finding.get("severity", "UNKNOWN"))[:32],
                "evidence": evidence_hashes,
                "provenance_role": "observed_deterministic_finding",
            }
        )
    return sorted(result, key=lambda item: item["finding_id"])


def build_policy_provenance(
    policy_payload: Mapping[str, Any],
    *,
    report: Mapping[str, Any] | None = None,
    source_label: str = "local-policy-file",
) -> dict[str, Any]:
    """Compile validated custom policy into a hash-linked, review-only provenance graph."""
    if not isinstance(policy_payload, Mapping):
        raise ProvenanceError("policy must be a JSON object")
    try:
        pack = CustomPolicyPack.from_dict(dict(policy_payload))
    except PolicyValidationError as exc:
        raise ProvenanceError(str(exc)) from exc
    rules = [_rule_payload(rule, index) for index, rule in enumerate(pack.rules)]
    policy_sha256 = _digest(dict(policy_payload))
    nodes: list[dict[str, Any]] = [
        {
            "id": f"policy:{pack.pack_id}:{pack.version}",
            "type": "entity",
            "role": "policy_pack",
            "sha256": policy_sha256,
        }
    ]
    edges: list[dict[str, Any]] = []
    for rule in rules:
        rule_id = f"rule:{rule['control_id']}"
        nodes.append(
            {
                "id": rule_id,
                "type": "entity",
                "role": "policy_rule",
                "sha256": _digest(rule),
            }
        )
        edges.append({"from": nodes[0]["id"], "to": rule_id, "relation": "contains"})
        for framework, mappings in rule["framework_mappings"].items():
            mapping_id = f"mapping:{rule['control_id']}:{framework}"
            mapping_payload = {"framework": framework, "controls": mappings}
            nodes.append(
                {
                    "id": mapping_id,
                    "type": "entity",
                    "role": "framework_mapping",
                    "sha256": _digest(mapping_payload),
                }
            )
            edges.append({"from": rule_id, "to": mapping_id, "relation": "maps_to"})
        remediation_id = f"remediation:{rule['control_id']}"
        nodes.append(
            {
                "id": remediation_id,
                "type": "entity",
                "role": "remediation_intent",
                "sha256": rule["remediation_sha256"],
            }
        )
        edges.append(
            {"from": rule_id, "to": remediation_id, "relation": "suggests_review_only"}
        )
    finding_lineage = []
    if report is not None:
        meta = _report_meta(report)
        finding_lineage = _finding_lineage(
            report, {rule["control_id"] for rule in rules}
        )
        report_node = {
            "id": f"report:{meta['audit_id']}",
            "type": "entity",
            "role": "audit_report",
            "sha256": _digest(report),
        }
        nodes.append(report_node)
        for finding in finding_lineage:
            finding_id = f"finding:{finding['finding_id']}"
            nodes.append(
                {
                    "id": finding_id,
                    "type": "entity",
                    "role": "observed_finding",
                    "sha256": _digest(finding),
                }
            )
            edges.append(
                {
                    "from": report_node["id"],
                    "to": finding_id,
                    "relation": "contains_observation",
                }
            )
            edges.append(
                {
                    "from": f"rule:{finding['control_id']}",
                    "to": finding_id,
                    "relation": "explains_control_scope",
                }
            )
    provenance = {
        "schema": PROVENANCE_SCHEMA,
        "source": {
            "label": _text(source_label, "source_label"),
            "policy_sha256": policy_sha256,
            "pack_id": pack.pack_id,
            "version": pack.version,
            "report_sha256": _digest(report) if report is not None else None,
        },
        "rules": rules,
        "findings": finding_lineage,
        "graph": {"nodes": nodes, "edges": edges},
        "summary": {
            "rule_count": len(rules),
            "framework_mapping_count": sum(
                len(rule["framework_mappings"]) for rule in rules
            ),
            "finding_lineage_count": len(finding_lineage),
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "safety": {
            "raw_configuration_included": False,
            "raw_evidence_included": False,
            "regex_text_included": False,
            "remediation_text_included": False,
            "commands_generated": False,
            "verdicts_changed": False,
            "network_access": False,
            "policy_activation": False,
        },
    }
    provenance["provenance_sha256"] = _digest(provenance)
    return provenance


def verify_policy_provenance(
    provenance: Mapping[str, Any],
    policy_payload: Mapping[str, Any],
    *,
    report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(provenance, Mapping)
        or provenance.get("schema") != PROVENANCE_SCHEMA
    ):
        raise ProvenanceError("unsupported policy provenance schema")
    expected = build_policy_provenance(
        policy_payload,
        report=report,
        source_label=str(
            provenance.get("source", {}).get("label", "local-policy-file")
        ),
    )
    mismatches: list[str] = []
    if provenance.get("provenance_sha256") != _digest(
        {key: value for key, value in provenance.items() if key != "provenance_sha256"}
    ):
        mismatches.append("provenance hash mismatch")
    for field in ("policy_sha256", "report_sha256", "pack_id", "version"):
        if provenance.get("source", {}).get(field) != expected.get("source", {}).get(
            field
        ):
            mismatches.append(f"source.{field} mismatch")
    if provenance.get("rules") != expected.get("rules"):
        mismatches.append("rule lineage mismatch")
    if provenance.get("findings") != expected.get("findings"):
        mismatches.append("finding lineage mismatch")
    return {
        "schema": VERIFY_SCHEMA,
        "verified": not mismatches,
        "mismatches": mismatches,
        "provenance_sha256": str(provenance.get("provenance_sha256", "")),
        "safety": {
            "verdicts_changed": False,
            "policy_activated": False,
            "network_access": False,
        },
    }


__all__ = [
    "PROVENANCE_SCHEMA",
    "VERIFY_SCHEMA",
    "ProvenanceError",
    "build_policy_provenance",
    "load_policy",
    "verify_policy_provenance",
]
