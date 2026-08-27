"""Evidence coverage and uncertainty budgets for evidence-first audit review."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Mapping

UNCERTAINTY_SCHEMA = "configsentinel.uncertainty-budget.v1"


class UncertaintyError(ValueError):
    """Raised when a serialized report cannot produce an uncertainty budget."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise UncertaintyError(f"{label} must be an object")
    return value


def _evidence_quality(finding: Mapping[str, Any]) -> tuple[bool, bool, list[str]]:
    evidence = finding.get("evidence", [])
    if not isinstance(evidence, list):
        raise UncertaintyError("finding evidence must be an array")
    present = bool(evidence)
    redacted = present and all(isinstance(span, Mapping) and span.get("redacted") is True for span in evidence)
    gaps: list[str] = []
    if not present:
        gaps.append("missing_source_evidence")
    elif not redacted:
        gaps.append("evidence_redaction_unverified")
    for span in evidence:
        item = _object(span, "evidence span")
        try:
            start = int(item.get("start_line"))
            end = int(item.get("end_line"))
        except (TypeError, ValueError) as exc:
            raise UncertaintyError("evidence line ranges must be integers") from exc
        if start < 1 or end < start:
            raise UncertaintyError("evidence line range is invalid")
    return present, redacted, gaps


def _category(status: str, evidence_present: bool, evidence_redacted: bool, confidence: float) -> str:
    if status == "CONTRADICTED":
        return "CONTRADICTED"
    if status in {"PASS", "FAIL"} and evidence_present and evidence_redacted:
        return "VERIFIED" if confidence >= 0.8 else "INFERRED"
    if status == "REVIEW_REQUIRED":
        return "INFERRED" if evidence_present else "UNKNOWN"
    if status == "UNKNOWN" or not evidence_present:
        return "UNKNOWN"
    return "INFERRED"


def build_uncertainty_budget(report: Mapping[str, Any]) -> dict[str, Any]:
    """Build a review budget from report metadata and evidence references only."""
    audit = _object(report.get("audit"), "report.audit")
    findings = report.get("findings")
    unknown_blocks = report.get("unknown_blocks", [])
    if not isinstance(findings, list) or not isinstance(unknown_blocks, list):
        raise UncertaintyError("report findings and unknown_blocks must be arrays")
    if not str(audit.get("audit_id", "")).strip() or not str(audit.get("vendor", "")).strip():
        raise UncertaintyError("report audit identity is incomplete")

    detail: list[dict[str, Any]] = []
    category_counts: Counter[str] = Counter()
    gaps: set[str] = set()
    evidence_backed = 0
    mapped = 0
    total_confidence = 0.0
    for raw in findings:
        finding = _object(raw, "report finding")
        finding_id = str(finding.get("finding_id", "")).strip()
        control_id = str(finding.get("control_id", "")).strip()
        status = str(finding.get("status", "")).strip().upper()
        if not finding_id or not control_id or not status:
            raise UncertaintyError("each finding needs finding_id, control_id, and status")
        try:
            confidence = float(finding.get("confidence", 0.0))
        except (TypeError, ValueError) as exc:
            raise UncertaintyError("finding confidence must be numeric") from exc
        if not 0.0 <= confidence <= 1.0:
            raise UncertaintyError("finding confidence must be between 0 and 1")
        evidence_present, evidence_redacted, finding_gaps = _evidence_quality(finding)
        mappings = finding.get("framework_mappings", [])
        if not isinstance(mappings, list):
            raise UncertaintyError("finding framework_mappings must be an array")
        mapping_present = any(isinstance(row, Mapping) and row.get("status") == "MAPPED" for row in mappings)
        if not mapping_present:
            finding_gaps.append("framework_mapping_unverified")
        finding_category = _category(status, evidence_present, evidence_redacted, confidence)
        category_counts[finding_category] += 1
        if evidence_present and evidence_redacted:
            evidence_backed += 1
        if mapping_present:
            mapped += 1
        total_confidence += confidence
        gaps.update(finding_gaps)
        detail.append(
            {
                "finding_id": finding_id,
                "control_id": control_id,
                "status": status,
                "category": finding_category,
                "confidence": round(confidence, 6),
                "evidence_present": evidence_present,
                "evidence_redacted": evidence_redacted,
                "framework_mapping_present": mapping_present,
                "gaps": sorted(set(finding_gaps)),
            }
        )

    if unknown_blocks:
        gaps.add("unknown_blocks_present")
    count = len(findings)
    coverage = round(evidence_backed / count, 6) if count else 1.0
    mapping_coverage = round(mapped / count, 6) if count else 1.0
    mean_confidence = round(total_confidence / count, 6) if count else 1.0
    review_required = bool(gaps) or bool(category_counts.get("UNKNOWN")) or bool(category_counts.get("CONTRADICTED"))
    assurance_state = "REVIEW_REQUIRED" if review_required else ("EVIDENCE_BACKED" if count else "NO_FINDINGS")
    return {
        "schema": UNCERTAINTY_SCHEMA,
        "audit": {
            "audit_id": str(audit["audit_id"]),
            "vendor": str(audit["vendor"]),
            "input_sha256": str(audit.get("input_sha256", "")),
            "parser_version": str(audit.get("parser_version", "")),
            "rule_pack_version": str(audit.get("rule_pack_version", "")),
            "frameworks": list(audit.get("frameworks", [])),
        },
        "assurance": {
            "state": assurance_state,
            "finding_count": count,
            "category_counts": dict(sorted(category_counts.items())),
            "evidence_coverage": coverage,
            "framework_mapping_coverage": mapping_coverage,
            "mean_confidence": mean_confidence,
            "unknown_block_count": len(unknown_blocks),
            "gaps": sorted(gaps),
        },
        "findings": detail,
        "verdict_boundary": {
            "verdicts_changed": False,
            "source_report_digest": _digest(report),
            "note": "This budget is advisory review metadata; it never changes PASS, FAIL, UNKNOWN, or REVIEW_REQUIRED statuses.",
        },
    }


def render_uncertainty_budget(report: Mapping[str, Any]) -> str:
    return json.dumps(build_uncertainty_budget(report), indent=2, sort_keys=True) + "\n"


__all__ = ["UNCERTAINTY_SCHEMA", "UncertaintyError", "build_uncertainty_budget", "render_uncertainty_budget"]
