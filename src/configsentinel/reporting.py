"""Deterministic audit report builders for Phase 8."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from .frameworks import REGISTRY_VERSION, mappings_for_finding, normalize_frameworks
from .models import AuditResult, Finding

REPORT_VERSION = "8.0.0"


def _finding_dict(finding: Finding, frameworks: tuple[str, ...]) -> dict[str, Any]:
    data = asdict(finding)
    data["status"] = finding.status.value
    data["severity"] = finding.severity.value
    data["evidence"] = [asdict(span) for span in finding.evidence]
    data["framework_mappings"] = list(mappings_for_finding(finding, frameworks))
    return data


def report_dict(result: AuditResult, frameworks: tuple[str, ...] | None = None) -> dict[str, Any]:
    selected = normalize_frameworks(frameworks)
    findings = [_finding_dict(finding, selected) for finding in result.findings]
    status_counts: dict[str, int] = {}
    for finding in result.findings:
        status_counts[finding.status.value] = status_counts.get(finding.status.value, 0) + 1
    mapped = sum(1 for finding in result.findings if any(row["status"] == "MAPPED" for row in mappings_for_finding(finding, selected)))
    return {
        "report_version": REPORT_VERSION,
        "audit": {
            "audit_id": result.audit_id,
            "vendor": result.vendor,
            "parser_version": result.parser_version,
            "rule_pack_version": result.rule_pack_version,
            "input_sha256": result.input_sha256,
            "framework_registry_version": REGISTRY_VERSION,
            "frameworks": list(selected),
        },
        "summary": {
            "finding_count": len(result.findings),
            "failed_count": result.failed_count,
            "unknown_count": len(result.unknown_blocks),
            "evaluated_count": result.evaluated_count,
            "mapped_finding_count": mapped,
            "status_counts": status_counts,
        },
        "findings": findings,
        "unknown_blocks": [asdict(span) for span in result.unknown_blocks],
        "reconciliation": {
            "status_count_total": sum(status_counts.values()),
            "matches_finding_count": sum(status_counts.values()) == len(result.findings),
            "failed_count_matches": status_counts.get("FAIL", 0) == result.failed_count,
        },
    }


def render_json(result: AuditResult, frameworks: tuple[str, ...] | None = None) -> str:
    return json.dumps(report_dict(result, frameworks), indent=2, sort_keys=True)


def _evidence_text(finding: Finding) -> str:
    if not finding.evidence:
        return "No evidence span recorded"
    return "; ".join(f"L{span.start_line}-L{span.end_line}: {span.excerpt}" for span in finding.evidence)


def render_markdown(result: AuditResult, frameworks: tuple[str, ...] | None = None) -> str:
    selected = normalize_frameworks(frameworks)
    report = report_dict(result, selected)
    lines = [
        "# ConfigSentinel AI Audit Report",
        "",
        f"**Audit ID:** `{result.audit_id}`  ",
        f"**Vendor:** `{result.vendor}`  ",
        f"**Input SHA-256:** `{result.input_sha256}`  ",
        f"**Frameworks:** {', '.join(selected)}  ",
        f"**Report version:** `{REPORT_VERSION}`  ",
        "",
        "## Executive summary",
        "",
        f"The audit evaluated **{report['summary']['evaluated_count']}** of **{report['summary']['finding_count']}** findings. It recorded **{report['summary']['failed_count']}** failures and **{report['summary']['unknown_count']}** unknown blocks. Unknown or unverified results are not treated as compliant.",
        "",
        "## Findings",
        "",
        "| Control | Status | Severity | Confidence | Evidence | Framework mapping |",
        "|---|---|---|---|---|---|",
    ]
    for finding in result.findings:
        mappings = mappings_for_finding(finding, selected)
        mapping_text = "; ".join(f"{row['framework_id']}: {', '.join(row['control_ids']) or 'UNVERIFIED'}" for row in mappings)
        lines.append(f"| {finding.control_id} | {finding.status.value} | {finding.severity.value} | {finding.confidence:.2f} | {_evidence_text(finding)} | {mapping_text} |")
    lines.extend([
        "",
        "## Reconciliation",
        "",
        f"- Finding totals reconcile: **{report['reconciliation']['matches_finding_count']}**.",
        f"- Failure total reconciles: **{report['reconciliation']['failed_count_matches']}**.",
        f"- Parser version: `{result.parser_version}`.",
        f"- Rule-pack version: `{result.rule_pack_version}`.",
        "",
        "## Safety note",
        "",
        "> This report is evidence for review. It does not authorize device changes. Generated remediation remains a non-executable preview requiring independent operator approval.",
        "",
    ])
    return "\n".join(lines)


def write_report(result: AuditResult, path: str, *, format: str = "markdown", frameworks: tuple[str, ...] | None = None) -> None:
    if format not in {"markdown", "json"}:
        raise ValueError("format must be markdown or json")
    content = render_markdown(result, frameworks) if format == "markdown" else render_json(result, frameworks)
    from pathlib import Path
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content + "\n", encoding="utf-8", newline="\n")


__all__ = ["REPORT_VERSION", "report_dict", "render_json", "render_markdown", "write_report"]
