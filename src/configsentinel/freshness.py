"""Deterministic assurance freshness decay and semantic drift assessment."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

FRESHNESS_SCHEMA = "configsentinel.assurance-freshness.v1"
MAX_FINDINGS = 10000


class FreshnessError(ValueError):
    """Raised when freshness or drift inputs are malformed."""


def _text(value: Any, label: str, limit: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise FreshnessError(f"{label} is required and bounded")
    return text


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _instant(value: Any, label: str) -> datetime:
    raw = _text(value, label, 64)
    if not raw.endswith("Z"):
        raise FreshnessError(f"{label} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as exc:
        raise FreshnessError(f"{label} is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise FreshnessError(f"{label} must include UTC")
    return parsed.astimezone(timezone.utc)


def _metadata(report: Mapping[str, Any], label: str) -> dict[str, Any]:
    audit = report.get("audit")
    findings = report.get("findings")
    if (
        not isinstance(audit, Mapping)
        or not isinstance(findings, list)
        or len(findings) > MAX_FINDINGS
    ):
        raise FreshnessError(
            f"{label} must contain bounded audit metadata and findings"
        )
    statuses: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise FreshnessError(f"{label}.findings must contain objects")
        finding_id = _text(finding.get("finding_id"), f"{label}.finding_id")
        if finding_id in statuses:
            raise FreshnessError(f"{label} contains duplicate finding_id: {finding_id}")
        statuses[finding_id] = {
            "status": str(finding.get("status", "UNKNOWN"))[:32],
            "severity": str(finding.get("severity", "UNKNOWN"))[:32],
            "control_id": str(finding.get("control_id", "UNKNOWN"))[:128],
        }
    return {
        "audit_id": str(audit.get("audit_id", "unknown"))[:128],
        "vendor": str(audit.get("vendor", "unknown"))[:64],
        "parser_version": str(audit.get("parser_version", "unknown"))[:64],
        "rule_pack_version": str(audit.get("rule_pack_version", "unknown"))[:64],
        "input_sha256": str(audit.get("input_sha256", "unknown"))[:128],
        "findings": statuses,
    }


def _drift(current: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    if baseline is None:
        return {
            "available": False,
            "drifted": False,
            "reasons": [],
            "added_findings": [],
            "removed_findings": [],
            "changed_findings": [],
        }
    reasons: list[str] = []
    for field in ("vendor", "parser_version", "rule_pack_version", "input_sha256"):
        if current[field] != baseline[field]:
            reasons.append(f"{field}_changed")
    current_ids = set(current["findings"])
    baseline_ids = set(baseline["findings"])
    added = sorted(current_ids - baseline_ids)
    removed = sorted(baseline_ids - current_ids)
    changed = sorted(
        finding_id
        for finding_id in current_ids & baseline_ids
        if current["findings"][finding_id] != baseline["findings"][finding_id]
    )
    if added:
        reasons.append("findings_added")
    if removed:
        reasons.append("findings_removed")
    if changed:
        reasons.append("finding_attributes_changed")
    return {
        "available": True,
        "drifted": bool(reasons),
        "reasons": reasons,
        "added_findings": added,
        "removed_findings": removed,
        "changed_findings": changed,
        "baseline_input_sha256": baseline["input_sha256"],
        "current_input_sha256": current["input_sha256"],
    }


def build_freshness_assessment(
    report: Mapping[str, Any],
    *,
    observed_at: str | None = None,
    as_of: str,
    ttl_seconds: int = 86400,
    baseline: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic freshness and drift assessment from explicit timestamps."""
    if ttl_seconds <= 0 or ttl_seconds > 365 * 24 * 60 * 60:
        raise FreshnessError("ttl_seconds must be between 1 second and 365 days")
    current = _metadata(report, "report")
    raw_observed = (
        observed_at
        or (
            report.get("audit", {}).get("observed_at")
            if isinstance(report.get("audit"), Mapping)
            else None
        )
        or report.get("observed_at")
    )
    observed = _instant(raw_observed, "observed_at")
    evaluation = _instant(as_of, "as_of")
    age_seconds = (evaluation - observed).total_seconds()
    if age_seconds < 0:
        raise FreshnessError("as_of cannot precede observed_at")
    decay = max(0.0, min(1.0, age_seconds / ttl_seconds))
    if age_seconds <= ttl_seconds:
        state = "FRESH"
    elif age_seconds <= 2 * ttl_seconds:
        state = "STALE"
    else:
        state = "EXPIRED"
    drift = _drift(
        current, _metadata(baseline, "baseline") if baseline is not None else None
    )
    if drift["drifted"]:
        assurance_state = "DRIFTED"
    elif state == "EXPIRED":
        assurance_state = "EXPIRED"
    elif state == "STALE":
        assurance_state = "AGING"
    else:
        assurance_state = "CURRENT"
    payload = {
        "schema": FRESHNESS_SCHEMA,
        "source": {
            "audit_id": current["audit_id"],
            "report_sha256": _digest(report),
            "observed_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "as_of": evaluation.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ttl_seconds": ttl_seconds,
        },
        "freshness": {
            "age_seconds": age_seconds,
            "decay_fraction": decay,
            "remaining_seconds": max(0.0, ttl_seconds - age_seconds),
            "state": state,
            "model": "linear_age_over_ttl_bounded_0_to_1",
        },
        "drift": drift,
        "assurance": {
            "state": assurance_state,
            "needs_reaudit": assurance_state in {"AGING", "EXPIRED", "DRIFTED"},
            "authoritative_verdict_source": "current_deterministic_audit",
            "verdicts_changed": False,
        },
        "safety": {
            "raw_configuration_included": False,
            "raw_evidence_included": False,
            "live_device_query": False,
            "automatic_approval": False,
            "verdicts_changed": False,
        },
    }
    payload["assessment_sha256"] = _digest(payload)
    return payload


def load_report_for_freshness(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if (
        target.is_symlink()
        or not target.is_file()
        or target.stat().st_size > 8 * 1024 * 1024
    ):
        raise FreshnessError("report path is invalid or exceeds 8 MiB")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreshnessError("report must be valid UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise FreshnessError("report must be a JSON object")
    return dict(value)


__all__ = [
    "FRESHNESS_SCHEMA",
    "FreshnessError",
    "build_freshness_assessment",
    "load_report_for_freshness",
]
