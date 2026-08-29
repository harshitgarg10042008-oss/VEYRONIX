"""Time-bound compliance exceptions for review workflow only."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ExceptionError(ValueError):
    """Raised when an exception record is invalid."""


@dataclass(frozen=True)
class ComplianceException:
    exception_id: str
    finding_id: str
    owner: str
    justification: str
    expires_at: str
    approved_by: str | None = None

    def status(self, *, now: datetime | None = None) -> str:
        current = now or datetime.now(timezone.utc)
        try:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ExceptionError("expires_at must be ISO-8601") from exc
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return (
            "ACTIVE"
            if expiry > current and self.approved_by
            else "PENDING" if expiry > current else "EXPIRED"
        )

    def as_dict(self, *, now: datetime | None = None) -> dict[str, Any]:
        return {
            "exception_id": self.exception_id,
            "finding_id": self.finding_id,
            "owner": self.owner,
            "justification": self.justification,
            "expires_at": self.expires_at,
            "approved_by": self.approved_by,
            "status": self.status(now=now),
            "verdict_impact": "none",
        }


def create_exception(
    exception_id: str, finding_id: str, owner: str, justification: str, expires_at: str
) -> ComplianceException:
    if not all(
        value.strip() for value in (exception_id, finding_id, owner, justification)
    ):
        raise ExceptionError(
            "exception_id, finding_id, owner, and justification are required"
        )
    if len(justification) > 2000 or len(owner) > 128:
        raise ExceptionError("exception fields exceed bounds")
    record = ComplianceException(
        exception_id[:128], finding_id[:256], owner[:128], justification, expires_at
    )
    if record.status() == "EXPIRED":
        raise ExceptionError("exception expiry must be in the future")
    return record


def save_exception(record: ComplianceException, path: str | Path) -> None:
    destination = Path(path)
    records: list[dict[str, Any]] = []
    if destination.exists():
        try:
            records = json.loads(destination.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ExceptionError("exception file is invalid") from exc
    if not isinstance(records, list) or any(
        not isinstance(item, dict) for item in records
    ):
        raise ExceptionError("exception file must contain a JSON array")
    records = [
        item for item in records if item.get("exception_id") != record.exception_id
    ]
    records.append(record.as_dict())
    if len(records) > 5000:
        raise ExceptionError("exception count exceeds limit")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def approve_exception(
    exception_id: str, approver: str, path: str | Path
) -> ComplianceException:
    if not approver.strip():
        raise ExceptionError("approver is required")
    source = Path(path)
    try:
        records = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExceptionError("exception file is invalid") from exc
    for item in records:
        if item.get("exception_id") == exception_id:
            record = ComplianceException(
                str(item["exception_id"]),
                str(item["finding_id"]),
                str(item["owner"]),
                str(item["justification"]),
                str(item["expires_at"]),
                approver[:128],
            )
            if record.status() == "EXPIRED":
                raise ExceptionError("expired exceptions cannot be approved")
            save_exception(record, source)
            return record
    raise ExceptionError("exception not found")


def load_exceptions(path: str | Path) -> tuple[ComplianceException, ...]:
    try:
        records = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExceptionError("exception file is invalid") from exc
    if not isinstance(records, list):
        raise ExceptionError("exception file must contain a JSON array")
    return tuple(
        ComplianceException(
            str(item["exception_id"]),
            str(item["finding_id"]),
            str(item["owner"]),
            str(item["justification"]),
            str(item["expires_at"]),
            item.get("approved_by"),
        )
        for item in records
        if isinstance(item, dict)
    )
