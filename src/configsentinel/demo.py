"""Guided local demonstration and audit comparison artifacts."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Mapping


class DemoError(ValueError):
    """Raised when demonstration inputs are invalid."""


def _status_map(report: Mapping[str, Any]) -> dict[str, str]:
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise DemoError("report findings must be a list")
    return {str(item.get("control_id", item.get("finding_id", "unknown"))): str(item.get("status", "UNKNOWN")) for item in findings if isinstance(item, Mapping)}


def compare_reports(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    before_map, after_map = _status_map(before), _status_map(after)
    controls = sorted(set(before_map) | set(after_map))
    changes = [{"control_id": control, "before": before_map.get(control, "ABSENT"), "after": after_map.get(control, "ABSENT"), "changed": before_map.get(control) != after_map.get(control)} for control in controls]
    return {"schema": "configsentinel.audit-comparison.v1", "before_audit_id": str(before.get("audit", {}).get("audit_id", "unknown")), "after_audit_id": str(after.get("audit", {}).get("audit_id", "unknown")), "changes": changes, "changed_count": sum(item["changed"] for item in changes), "safety_note": "Comparison reflects serialized deterministic reports; it does not prove causality or authorize remediation."}


def render_guided_demo(report: Mapping[str, Any], *, comparison: Mapping[str, Any] | None = None) -> str:
    audit = report.get("audit", {})
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    rows = "".join(f"<tr><td>{html.escape(str(item.get('control_id', 'unknown')))}</td><td>{html.escape(str(item.get('status', 'UNKNOWN')))}</td><td>{html.escape(str(item.get('severity', 'INFO')))}</td></tr>" for item in findings if isinstance(item, Mapping))
    comparison_block = f"<pre>{html.escape(json.dumps(comparison, indent=2, sort_keys=True))}</pre>" if comparison else "<p>No comparison loaded. Add an after-report to show before/after status changes.</p>"
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ConfigSentinel AI guided demonstration</title><style>body{{font:16px system-ui,sans-serif;background:#0b1220;color:#edf4ff;margin:0}}main{{max-width:1000px;margin:auto;padding:28px}}h1{{color:#74c0fc}}section{{border:1px solid #30445f;background:#111b2e;margin:16px 0;padding:18px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;text-align:left;border-bottom:1px solid #30445f}}pre{{white-space:pre-wrap;color:#b9e6ff}}.step{{color:#ffd166;font-weight:700}}</style></head><body><main><h1>ConfigSentinel AI — SIH guided demonstration</h1><section><p class="step">Step 1 · Inspect</p><p>Audit <strong>{html.escape(str(audit.get('audit_id', 'unknown')))}</strong> for vendor <strong>{html.escape(str(audit.get('vendor', 'unknown')))}</strong>.</p><p>Failures: {html.escape(str(summary.get('failed_count', 'unknown')))} · Unknown: {html.escape(str(summary.get('unknown_count', 'unknown')))}</p></section><section><p class="step">Step 2 · Review evidence</p><table><thead><tr><th>Control</th><th>Status</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table></section><section><p class="step">Step 3 · Compare</p>{comparison_block}</section><section><p class="step">Step 4 · Explain the safety boundary</p><p>Results are deterministic and evidence-backed. Remediation remains a review-only preview; no device connection or automatic change is performed.</p></section></main></body></html>'''


def write_demo_html(report: Mapping[str, Any], output: str | Path, *, comparison: Mapping[str, Any] | None = None) -> None:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_guided_demo(report, comparison=comparison), encoding="utf-8")
