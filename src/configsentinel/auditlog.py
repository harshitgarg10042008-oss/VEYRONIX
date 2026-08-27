"""Tamper-evident audit records and signed evidence envelopes."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import AuditResult


class AuditLogError(ValueError):
    """Raised when an audit trail or signature is invalid."""


@dataclass(frozen=True)
class TrailEvent:
    sequence: int
    audit_id: str
    input_sha256: str
    vendor: str
    finding_statuses: dict[str, str]
    previous_hash: str
    event_hash: str

    def unsigned(self) -> dict[str, Any]:
        return {"sequence": self.sequence, "audit_id": self.audit_id, "input_sha256": self.input_sha256, "vendor": self.vendor, "finding_statuses": self.finding_statuses, "previous_hash": self.previous_hash}

    def as_dict(self) -> dict[str, Any]:
        payload = self.unsigned()
        payload["event_hash"] = self.event_hash
        return payload


class AuditTrail:
    """Append-only JSONL hash chain for local audit integrity verification."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.exists() and self.path.stat().st_size > 8 * 1024 * 1024:
            raise AuditLogError("audit trail exceeds the 8 MiB limit")

    def append(self, result: AuditResult) -> TrailEvent:
        events = self.events()
        sequence = len(events) + 1
        previous = events[-1].event_hash if events else "GENESIS"
        event = TrailEvent(sequence, result.audit_id, result.input_sha256, result.vendor, {finding.control_id: finding.status.value for finding in result.findings}, previous, "")
        event_hash = _digest(event.unsigned())
        event = TrailEvent(sequence, event.audit_id, event.input_sha256, event.vendor, event.finding_statuses, event.previous_hash, event_hash)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event.as_dict(), sort_keys=True) + "\n")
        return event

    def events(self) -> tuple[TrailEvent, ...]:
        if not self.path.exists():
            return ()
        result: list[TrailEvent] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                event = TrailEvent(int(payload["sequence"]), str(payload["audit_id"]), str(payload["input_sha256"]), str(payload["vendor"]), {str(key): str(value) for key, value in payload["finding_statuses"].items()}, str(payload["previous_hash"]), str(payload["event_hash"]))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise AuditLogError("audit trail contains an invalid event") from exc
            result.append(event)
        return tuple(result)

    def verify(self) -> tuple[bool, str]:
        previous = "GENESIS"
        for expected_sequence, event in enumerate(self.events(), 1):
            if event.sequence != expected_sequence or event.previous_hash != previous or not hmac.compare_digest(event.event_hash, _digest(event.unsigned())):
                return False, f"integrity failure at sequence {expected_sequence}"
            previous = event.event_hash
        return True, "audit trail verified"


def sign_envelope(payload: dict[str, Any], key: bytes) -> dict[str, Any]:
    if not key:
        raise AuditLogError("signing key cannot be empty")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"payload": payload, "algorithm": "HMAC-SHA256", "signature": hmac.new(key, canonical, hashlib.sha256).hexdigest()}


def verify_envelope(envelope: dict[str, Any], key: bytes) -> bool:
    if not key or not isinstance(envelope, dict) or envelope.get("algorithm") != "HMAC-SHA256":
        return False
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
