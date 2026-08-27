"""Deterministic analytics for a collection of serialized audit reports."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


class AnalyticsError(ValueError):
    """Raised when a history collection is malformed or too large."""


def analyze_history(reports: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(reports)
    if len(rows) > 10_000:
        raise AnalyticsError("history contains too many reports")
    vendor_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    control_counts: Counter[str] = Counter()
    timeline: defaultdict[str, dict[str, int]] = defaultdict(lambda: {"reports": 0, "findings": 0, "failed": 0, "unknown": 0})
    for report in rows:
        if not isinstance(report, dict) or not isinstance(report.get("audit"), dict) or not isinstance(report.get("findings"), list):
            raise AnalyticsError("each history entry must be a serialized audit report")
        audit = report["audit"]
        vendor = str(audit.get("vendor", "unknown"))
        vendor_counts[vendor] += 1
        summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
        recorded_at = str(report.get("recorded_at") or audit.get("recorded_at") or datetime.now(timezone.utc).date().isoformat())[:10]
        try:
            datetime.strptime(recorded_at, "%Y-%m-%d")
        except ValueError as exc:
            raise AnalyticsError("recorded_at must begin with an ISO date") from exc
        point = timeline[recorded_at]
        point["reports"] += 1
        point["findings"] += len(report["findings"])
        point["failed"] += int(summary.get("failed_count", sum(1 for item in report["findings"] if isinstance(item, dict) and item.get("status") == "FAIL")))
        point["unknown"] += int(summary.get("unknown_count", 0))
        for finding in report["findings"]:
            if not isinstance(finding, dict):
                raise AnalyticsError("finding entries must be objects")
            severity_counts[str(finding.get("severity", "UNKNOWN"))] += 1
            status_counts[str(finding.get("status", "UNKNOWN"))] += 1
            control_counts[str(finding.get("control_id", "UNKNOWN"))] += 1
    return {"report_count": len(rows), "vendor_counts": dict(sorted(vendor_counts.items())), "severity_counts": dict(sorted(severity_counts.items())), "status_counts": dict(sorted(status_counts.items())), "control_counts": dict(sorted(control_counts.items())), "timeline": [{"date": date, **timeline[date]} for date in sorted(timeline)]}


def load_history(path: str | Path) -> list[dict[str, Any]]:
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.stat().st_size > 20 * 1024 * 1024:
        raise AnalyticsError("history path is invalid or exceeds the 20 MiB limit")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalyticsError("history must be valid UTF-8 JSON") from exc
    if not isinstance(payload, list):
        raise AnalyticsError("history input must be a JSON array")
    return payload


def write_history_analytics(analytics: dict[str, Any], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(analytics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
