"""Local webhook contract and durable queue; no outbound network delivery."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class WebhookError(ValueError):
    """Raised when a webhook event is invalid or the queue is unsafe."""


@dataclass(frozen=True)
class WebhookEvent:
    event_id: str
    event_type: str
    occurred_at: str
    payload: dict[str, Any]
    payload_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {"event_id": self.event_id, "event_type": self.event_type, "occurred_at": self.occurred_at, "payload": self.payload, "payload_sha256": self.payload_sha256}


def make_audit_event(report: dict[str, Any]) -> WebhookEvent:
    if not isinstance(report, dict) or not isinstance(report.get("audit"), dict):
        raise WebhookError("audit report must contain audit metadata")
    payload = {"audit": report["audit"], "summary": report.get("summary", {}), "finding_ids": [str(item.get("finding_id")) for item in report.get("findings", []) if isinstance(item, dict)]}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    audit_id = str(report["audit"].get("audit_id", "unknown"))
    return WebhookEvent(f"audit.completed:{audit_id}", "audit.completed", datetime.now(timezone.utc).isoformat(), payload, digest)


class LocalWebhookQueue:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.exists() and self.path.stat().st_size > 8 * 1024 * 1024:
            raise WebhookError("webhook queue exceeds the 8 MiB limit")

    def enqueue(self, event: WebhookEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event.as_dict(), sort_keys=True) + "\n")

    def read(self) -> tuple[WebhookEvent, ...]:
        if not self.path.exists():
            return ()
        events: list[WebhookEvent] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                payload = json.loads(line)
                event = WebhookEvent(str(payload["event_id"]), str(payload["event_type"]), str(payload["occurred_at"]), dict(payload["payload"]), str(payload["payload_sha256"]))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise WebhookError("webhook queue contains an invalid event") from exc
            events.append(event)
        return tuple(events)
