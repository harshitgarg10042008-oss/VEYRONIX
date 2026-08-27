"""Local role-based governance for review-only audit and remediation workflows."""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class GovernanceError(ValueError):
    """Raised when an approval transition violates governance policy."""


class Role(str, Enum):
    OPERATOR = "operator"
    REVIEWER = "reviewer"
    ADMIN = "admin"


class Action(str, Enum):
    REQUEST = "REQUEST"
    APPROVE = "APPROVE"
    REJECT = "REJECT"


@dataclass(frozen=True)
class GovernanceEvent:
    event_id: str
    resource_id: str
    actor_id: str
    role: Role
    action: Action
    reason: str
    created_at: str

    def as_dict(self) -> dict[str, str]:
        return {"event_id": self.event_id, "resource_id": self.resource_id, "actor_id": self.actor_id, "role": self.role.value, "action": self.action.value, "reason": self.reason, "created_at": self.created_at}


class ApprovalLedger:
    """Append-only local JSONL ledger with separation-of-duty enforcement."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        if self.path and self.path.exists() and self.path.stat().st_size > 2 * 1024 * 1024:
            raise GovernanceError("governance ledger exceeds the 2 MiB limit")

    def request(self, resource_id: str, actor_id: str, *, role: Role = Role.OPERATOR, reason: str = "") -> GovernanceEvent:
        if role not in {Role.OPERATOR, Role.ADMIN}:
            raise GovernanceError("only operators or administrators can request approval")
        event = self._event(resource_id, actor_id, role, Action.REQUEST, reason or "Submitted for independent review")
        self._append(event)
        return event

    def decide(self, resource_id: str, actor_id: str, *, role: Role, approve: bool, reason: str = "") -> GovernanceEvent:
        if role not in {Role.REVIEWER, Role.ADMIN}:
            raise GovernanceError("only reviewers or administrators can decide an approval")
        events = self.events(resource_id)
        if not any(item.action == Action.REQUEST for item in events):
            raise GovernanceError("resource has no pending approval request")
        if any(item.action in {Action.APPROVE, Action.REJECT} for item in events):
            raise GovernanceError("resource already has a terminal decision")
        if any(item.action == Action.REQUEST and item.actor_id == actor_id for item in events):
            raise GovernanceError("separation of duties requires a different reviewer")
        action = Action.APPROVE if approve else Action.REJECT
        return self._append(self._event(resource_id, actor_id, role, action, reason or ("Approved after independent review" if approve else "Rejected during independent review")))

    def status(self, resource_id: str) -> str:
        events = self.events(resource_id)
        if any(item.action == Action.APPROVE for item in events):
            return "APPROVED"
        if any(item.action == Action.REJECT for item in events):
            return "REJECTED"
        if any(item.action == Action.REQUEST for item in events):
            return "PENDING_REVIEW"
        return "NOT_REQUESTED"

    def events(self, resource_id: str | None = None) -> tuple[GovernanceEvent, ...]:
        if not self.path or not self.path.exists():
            return ()
        result: list[GovernanceEvent] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                payload: dict[str, Any] = json.loads(line)
                event = GovernanceEvent(payload["event_id"], payload["resource_id"], payload["actor_id"], Role(payload["role"]), Action(payload["action"]), payload["reason"], payload["created_at"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise GovernanceError("governance ledger contains an invalid event") from exc
            if resource_id is None or event.resource_id == resource_id:
                result.append(event)
        return tuple(result)

    def _append(self, event: GovernanceEvent) -> GovernanceEvent:
        if not self.path:
            return event
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event.as_dict(), sort_keys=True) + "\n")
        return event

    @staticmethod
    def _event(resource_id: str, actor_id: str, role: Role, action: Action, reason: str) -> GovernanceEvent:
        if not resource_id.strip() or not actor_id.strip():
            raise GovernanceError("resource_id and actor_id are required")
        return GovernanceEvent(f"evt_{secrets.token_hex(8)}", resource_id, actor_id, role, action, reason[:500], datetime.now(timezone.utc).isoformat())
