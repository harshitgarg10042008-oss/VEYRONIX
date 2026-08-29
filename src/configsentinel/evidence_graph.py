"""Evidence graph projection for serialized audit reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class EvidenceGraphError(ValueError):
    """Raised when an audit report cannot be projected safely."""


def build_evidence_graph(report: dict[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(report, dict)
        or not isinstance(report.get("audit"), dict)
        or not isinstance(report.get("findings"), list)
    ):
        raise EvidenceGraphError("report must contain audit and findings")
    audit = report["audit"]
    audit_id = str(audit.get("audit_id", "audit"))
    nodes: dict[str, dict[str, Any]] = {
        f"audit:{audit_id}": {
            "id": f"audit:{audit_id}",
            "type": "audit",
            "label": audit_id,
            "vendor": audit.get("vendor", "unknown"),
            "input_sha256": audit.get("input_sha256", ""),
        }
    }
    edges: list[dict[str, str]] = []
    for index, finding in enumerate(report["findings"]):
        if not isinstance(finding, dict):
            raise EvidenceGraphError("finding entries must be objects")
        finding_id = str(finding.get("finding_id", f"finding-{index}"))
        finding_node = f"finding:{finding_id}"
        nodes[finding_node] = {
            "id": finding_node,
            "type": "finding",
            "label": finding.get("control_id", finding_id),
            "status": finding.get("status", "UNKNOWN"),
            "severity": finding.get("severity", "UNKNOWN"),
            "confidence": finding.get("confidence", 0.0),
        }
        edges.append(
            {"from": f"audit:{audit_id}", "to": finding_node, "relation": "produces"}
        )
        control_id = str(finding.get("control_id", "UNKNOWN"))
        control_node = f"control:{control_id}"
        nodes.setdefault(
            control_node, {"id": control_node, "type": "control", "label": control_id}
        )
        edges.append(
            {"from": finding_node, "to": control_node, "relation": "evaluates"}
        )
        for mapping in finding.get("framework_mappings", []):
            if not isinstance(mapping, dict):
                continue
            framework_id = str(mapping.get("framework_id", "unknown"))
            framework_node = f"framework:{framework_id}"
            nodes.setdefault(
                framework_node,
                {"id": framework_node, "type": "framework", "label": framework_id},
            )
            edges.append(
                {"from": control_node, "to": framework_node, "relation": "maps_to"}
            )
        for span_index, span in enumerate(finding.get("evidence", [])):
            if not isinstance(span, dict):
                continue
            evidence_node = f"evidence:{finding_id}:{span_index}"
            nodes[evidence_node] = {
                "id": evidence_node,
                "type": "evidence",
                "label": f"L{span.get('start_line', '?')}-L{span.get('end_line', '?')}",
                "excerpt": str(span.get("excerpt", "")),
                "redacted": bool(span.get("redacted", True)),
            }
            edges.append(
                {"from": finding_node, "to": evidence_node, "relation": "supported_by"}
            )
    return {"schema_version": "1.0", "nodes": list(nodes.values()), "edges": edges}


def load_report(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if (
        target.is_symlink()
        or not target.is_file()
        or target.stat().st_size > 10 * 1024 * 1024
    ):
        raise EvidenceGraphError("report path is invalid or too large")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceGraphError("report must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise EvidenceGraphError("report must be a JSON object")
    return payload


def write_graph(graph: dict[str, Any], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
