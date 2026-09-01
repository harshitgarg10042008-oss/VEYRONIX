"""Incident-ready assurance timeline for ConfigSentinel AI.

This module provides an append-only timeline that ties deterministic audit results,
approvals, and remediation actions to specific incident case IDs.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class EventType(str, Enum):
    """Types of timeline events."""
    OBSERVATION = "OBSERVATION"
    SIMULATION = "SIMULATION"
    APPROVAL = "APPROVAL"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"
    INVALIDATION = "INVALIDATION"


@dataclass(frozen=True)
class TimelineEvent:
    """A single immutable event in the incident timeline."""
    event_id: str
    case_id: str
    event_type: EventType
    actor_id: str
    timestamp: str
    payload: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "case_id": self.case_id,
            "event_type": self.event_type.value,
            "actor_id": self.actor_id,
            "timestamp": self.timestamp,
            "payload": dict(self.payload),
        }


class IncidentTimeline:
    """An append-only timeline for incident cases."""
    
    def __init__(self) -> None:
        self._events: list[TimelineEvent] = []
        
    def record_event(
        self,
        case_id: str,
        event_type: EventType,
        actor_id: str,
        payload: Mapping[str, Any] | None = None,
    ) -> TimelineEvent:
        """Record a new event in the timeline."""
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id is required")
        if not actor_id or not str(actor_id).strip():
            raise ValueError("actor_id is required")
            
        event = TimelineEvent(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            case_id=str(case_id).strip(),
            event_type=event_type,
            actor_id=str(actor_id).strip(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            payload=dict(payload) if payload else {},
        )
        self._events.append(event)
        return event
        
    def get_events(self, case_id: str) -> list[TimelineEvent]:
        """Retrieve all events for a specific case ID in chronological order."""
        case_events = [e for e in self._events if e.case_id == case_id]
        # Sort by timestamp to ensure chronological order
        return sorted(case_events, key=lambda e: e.timestamp)

    def get_timeline_summary(self, case_id: str) -> dict[str, Any]:
        """Generate a summary report of the timeline for a case."""
        events = self.get_events(case_id)
        if not events:
            return {
                "case_id": case_id,
                "event_count": 0,
                "status": "EMPTY",
                "events": [],
            }
            
        has_verification = any(e.event_type == EventType.VERIFICATION for e in events)
        has_invalidation = any(e.event_type == EventType.INVALIDATION for e in events)
        
        if has_invalidation:
            status = "INVALIDATED"
        elif has_verification:
            status = "VERIFIED"
        else:
            status = "IN_PROGRESS"
            
        return {
            "case_id": case_id,
            "event_count": len(events),
            "status": status,
            "first_event_at": events[0].timestamp,
            "last_event_at": events[-1].timestamp,
            "events": [e.to_dict() for e in events],
        }

# Global singleton for demo purposes
TIMELINE_STORE = IncidentTimeline()
