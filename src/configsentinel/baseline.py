"""Approved baseline and configuration-drift primitives."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AuditResult


class BaselineError(ValueError):
    """Raised when a baseline is invalid or cannot be safely read."""


@dataclass(frozen=True)
class BaselineSnapshot:
    schema_version: str
    label: str
    created_at: str
    input_sha256: str
    vendor: str
    parser_version: str
    finding_statuses: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "label": self.label,
            "created_at": self.created_at,
            "input_sha256": self.input_sha256,
            "vendor": self.vendor,
            "parser_version": self.parser_version,
            "finding_statuses": self.finding_statuses,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "BaselineSnapshot":
        if not isinstance(payload, dict):
            raise BaselineError("baseline must be a JSON object")
        required = (
            "schema_version",
            "label",
            "created_at",
            "input_sha256",
            "vendor",
            "parser_version",
            "finding_statuses",
        )
        if any(
            not isinstance(payload.get(key), str) or not payload[key].strip()
            for key in required[:-1]
        ):
            raise BaselineError("baseline metadata is incomplete")
        statuses = payload.get("finding_statuses")
        if not isinstance(statuses, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in statuses.items()
        ):
            raise BaselineError("finding_statuses must be a string map")
        if len(statuses) > 1000:
            raise BaselineError("baseline contains too many findings")
        return cls(
            *(payload[key] for key in required[:-1]),
            {str(key): str(value) for key, value in statuses.items()},
        )


def make_baseline(result: AuditResult, *, label: str = "approved") -> BaselineSnapshot:
    return BaselineSnapshot(
        "1.0",
        label,
        datetime.now(timezone.utc).isoformat(),
        result.input_sha256,
        result.vendor,
        result.parser_version,
        {finding.control_id: finding.status.value for finding in result.findings},
    )


def save_baseline(
    result: AuditResult, path: str | Path, *, label: str = "approved"
) -> BaselineSnapshot:
    snapshot = make_baseline(result, label=label)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(snapshot.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return snapshot


def load_baseline(path: str | Path) -> BaselineSnapshot:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise BaselineError("baseline path must be a regular file")
    if target.stat().st_size > 256 * 1024:
        raise BaselineError("baseline exceeds the 256 KiB limit")
    try:
        return BaselineSnapshot.from_dict(
            json.loads(target.read_text(encoding="utf-8"))
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError("baseline must be valid UTF-8 JSON") from exc


def compare_baseline(baseline: BaselineSnapshot, result: AuditResult) -> dict[str, Any]:
    current = {finding.control_id: finding.status.value for finding in result.findings}
    added = sorted(set(current) - set(baseline.finding_statuses))
    removed = sorted(set(baseline.finding_statuses) - set(current))
    changed = sorted(
        control_id
        for control_id in set(current) & set(baseline.finding_statuses)
        if current[control_id] != baseline.finding_statuses[control_id]
    )
    hash_changed = baseline.input_sha256 != result.input_sha256
    vendor_changed = baseline.vendor != result.vendor
    drifted = bool(hash_changed or vendor_changed or added or removed or changed)
    return {
        "drifted": drifted,
        "hash_changed": hash_changed,
        "vendor_changed": vendor_changed,
        "added_controls": added,
        "removed_controls": removed,
        "changed_controls": changed,
        "baseline_input_sha256": baseline.input_sha256,
        "current_input_sha256": result.input_sha256,
        "baseline_vendor": baseline.vendor,
        "current_vendor": result.vendor,
    }
