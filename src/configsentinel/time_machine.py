"""Deterministic point-in-time compliance reconstruction from supplied reports."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

TIME_MACHINE_SCHEMA = "configsentinel.compliance-time-machine.v1"
MAX_SNAPSHOTS = 256
MAX_FINDINGS_PER_SNAPSHOT = 10000


class TimeMachineError(ValueError):
    """Raised when historical audit snapshots are malformed or unsafe."""


def _text(value: Any, label: str, limit: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise TimeMachineError(f"{label} is required and bounded")
    return text


def _snapshot_rows(source: Any) -> list[Mapping[str, Any]]:
    if isinstance(source, Mapping):
        source = source.get("snapshots")
    if not isinstance(source, list) or not 1 <= len(source) <= MAX_SNAPSHOTS:
        raise TimeMachineError(
            f"snapshots must be a list containing 1-{MAX_SNAPSHOTS} entries"
        )
    rows: list[Mapping[str, Any]] = []
    for item in source:
        if not isinstance(item, Mapping):
            raise TimeMachineError("each snapshot must be an object")
        rows.append(item)
    return rows


def _parse_time(value: Any) -> str:
    text = _text(value, "observed_at", 80)
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TimeMachineError("observed_at must be an ISO-8601 timestamp") from exc
    return text


def _report_from_row(row: Mapping[str, Any]) -> Mapping[str, Any]:
    report = row.get("report", row)
    if (
        not isinstance(report, Mapping)
        or not isinstance(report.get("audit"), Mapping)
        or not isinstance(report.get("findings"), list)
    ):
        raise TimeMachineError(
            "each snapshot requires an audit object and findings list"
        )
    if len(report["findings"]) > MAX_FINDINGS_PER_SNAPSHOT:
        raise TimeMachineError("snapshot contains too many findings")
    return report


def _finding_projection(finding: Mapping[str, Any]) -> dict[str, Any]:
    control_id = _text(finding.get("control_id"), "finding.control_id")
    status = _text(finding.get("status", "UNKNOWN"), "finding.status", 32).upper()
    if status not in {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"}:
        raise TimeMachineError(f"unsupported finding status: {status}")
    evidence = finding.get("evidence", [])
    evidence_count = len(evidence) if isinstance(evidence, list) else 0
    return {
        "control_id": control_id,
        "status": status,
        "severity": str(finding.get("severity", "UNKNOWN"))[:32],
        "confidence": finding.get("confidence"),
        "evidence_count": evidence_count,
    }


def load_snapshot_source(path: str | Path) -> Any:
    target = Path(path)
    if (
        target.is_symlink()
        or not target.is_file()
        or target.stat().st_size > 10 * 1024 * 1024
    ):
        raise TimeMachineError("snapshot path is invalid or too large")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TimeMachineError("snapshot source must be valid UTF-8 JSON") from exc
    if not isinstance(payload, (list, Mapping)):
        raise TimeMachineError("snapshot source must be a JSON array or object")
    return payload


def build_time_machine(
    source: Any, *, control_id: str | None = None, vendor: str | None = None
) -> dict[str, Any]:
    """Replay only supplied snapshots; no interpolation or live historical lookup occurs."""
    rows = _snapshot_rows(source)
    selected_control = _text(control_id, "control_id") if control_id else None
    selected_vendor = _text(vendor, "vendor") if vendor else None
    timeline: list[dict[str, Any]] = []
    seen_times: set[str] = set()
    for row in rows:
        observed_at = _parse_time(row.get("observed_at"))
        if observed_at in seen_times:
            raise TimeMachineError("observed_at values must be unique")
        seen_times.add(observed_at)
        report = _report_from_row(row)
        audit = report["audit"]
        report_vendor = _text(audit.get("vendor", "unknown"), "audit.vendor")
        if selected_vendor and report_vendor != selected_vendor:
            continue
        findings: dict[str, dict[str, Any]] = {}
        for raw in report["findings"]:
            if not isinstance(raw, Mapping):
                raise TimeMachineError("finding entries must be objects")
            projected = _finding_projection(raw)
            if selected_control and projected["control_id"] != selected_control:
                continue
            if projected["control_id"] in findings:
                raise TimeMachineError(
                    f"duplicate control in snapshot: {projected['control_id']}"
                )
            findings[projected["control_id"]] = projected
        counts: dict[str, int] = {}
        for finding in findings.values():
            counts[finding["status"]] = counts.get(finding["status"], 0) + 1
        timeline.append(
            {
                "observed_at": observed_at,
                "audit_id": _text(audit.get("audit_id", "audit"), "audit.audit_id"),
                "vendor": report_vendor,
                "input_sha256": _text(
                    audit.get("input_sha256", "unknown"), "audit.input_sha256", 128
                ),
                "parser_version": str(audit.get("parser_version", "unknown"))[:64],
                "findings": dict(sorted(findings.items())),
                "status_counts": dict(sorted(counts.items())),
            }
        )
    if not timeline:
        raise TimeMachineError("no snapshots remain after filters")
    timeline.sort(key=lambda item: item["observed_at"])
    control_ids = sorted(
        {control for snapshot in timeline for control in snapshot["findings"]}
    )
    changes: list[dict[str, Any]] = []
    histories: dict[str, list[dict[str, Any]]] = {
        control: [] for control in control_ids
    }
    previous: dict[str, str] = {}
    for snapshot in timeline:
        for control in control_ids:
            finding = snapshot["findings"].get(control)
            status = finding["status"] if finding else "MISSING"
            histories[control].append(
                {
                    "observed_at": snapshot["observed_at"],
                    "status": status,
                    "evidence_count": (
                        finding.get("evidence_count", 0) if finding else 0
                    ),
                }
            )
            if control in previous and previous[control] != status:
                changes.append(
                    {
                        "control_id": control,
                        "observed_at": snapshot["observed_at"],
                        "from_status": previous[control],
                        "to_status": status,
                    }
                )
            previous[control] = status
    return {
        "schema": TIME_MACHINE_SCHEMA,
        "filters": {"control_id": selected_control, "vendor": selected_vendor},
        "timeline": timeline,
        "control_history": histories,
        "changes": changes,
        "summary": {
            "snapshot_count": len(timeline),
            "control_count": len(control_ids),
            "change_count": len(changes),
            "first_observed_at": timeline[0]["observed_at"],
            "last_observed_at": timeline[-1]["observed_at"],
        },
        "safety": {
            "raw_configuration_included": False,
            "historical_interpolation": False,
            "live_lookup": False,
            "verdicts_changed": False,
            "note": "The time machine replays supplied signed-or-hashed report snapshots only; it does not infer missing periods or establish that a snapshot represents live device state.",
        },
    }


def render_time_machine_html(machine: Mapping[str, Any]) -> str:
    payload = json.dumps(machine, sort_keys=True).replace("</", "<\\/")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ConfigSentinel AI compliance time machine</title><style>body{{font:15px system-ui,sans-serif;background:#0b1220;color:#e6edf7;margin:0}}main{{max-width:1100px;margin:auto;padding:24px}}h1{{color:#74c0fc}}.meta{{color:#a7b6ca}}select,button{{font:inherit;background:#172b46;color:#fff;border:1px solid #74c0fc;padding:8px}}#snapshot{{margin-top:18px;white-space:pre-wrap;background:#111b2e;padding:14px;min-height:260px}}table{{width:100%;border-collapse:collapse;margin-top:18px}}th,td{{padding:8px;text-align:left;border-bottom:1px solid #30445f}}</style></head><body><main><h1>ConfigSentinel AI compliance time machine</h1><p class="meta">Replay of supplied report snapshots only. Missing periods are not interpolated and no live device state is inferred.</p><label for="snapshot-select">Snapshot</label> <select id="snapshot-select"></select><section id="snapshot" aria-live="polite"></section><table><thead><tr><th>Control</th><th>Transitions</th><th>Latest status</th></tr></thead><tbody id="history"></tbody></table></main><script>const machine={payload};const select=document.getElementById('snapshot-select');const output=document.getElementById('snapshot');const history=document.getElementById('history');const timeline=machine.timeline||[];timeline.forEach((item,index)=>{{const option=document.createElement('option');option.value=String(index);option.textContent=item.observed_at+' — '+item.audit_id;select.appendChild(option)}});function render(index){{const item=timeline[index];output.textContent=JSON.stringify(item,null,2)}}select.addEventListener('change',()=>render(Number(select.value)));Object.entries(machine.control_history||{{}}).forEach(([control,events])=>{{const row=document.createElement('tr');const changes=events.filter((event,index)=>index>0&&event.status!==events[index-1].status).length;row.innerHTML='<td>'+control+'</td><td>'+changes+'</td><td>'+events[events.length-1].status+'</td>';history.appendChild(row)}});if(timeline.length)render(0);</script></body></html>"""


def write_time_machine_html(machine: Mapping[str, Any], output: str | Path) -> None:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_time_machine_html(machine), encoding="utf-8")


__all__ = [
    "TIME_MACHINE_SCHEMA",
    "TimeMachineError",
    "build_time_machine",
    "load_snapshot_source",
    "render_time_machine_html",
    "write_time_machine_html",
]
