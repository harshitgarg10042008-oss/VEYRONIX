"""Tests for incident timeline module."""

import pytest

from configsentinel.incident_timeline import (
    EventType,
    IncidentTimeline,
    TimelineEvent,
)


def test_record_event():
    timeline = IncidentTimeline()
    event = timeline.record_event(
        case_id="case-123",
        event_type=EventType.OBSERVATION,
        actor_id="operator-1",
        payload={"audit_id": "audit-456"},
    )
    
    assert event.case_id == "case-123"
    assert event.event_type == EventType.OBSERVATION
    assert event.actor_id == "operator-1"
    assert event.payload == {"audit_id": "audit-456"}
    assert event.event_id.startswith("evt_")


def test_get_events_chronological():
    timeline = IncidentTimeline()
    timeline.record_event("case-1", EventType.OBSERVATION, "actor-1")
    timeline.record_event("case-1", EventType.APPROVAL, "actor-2")
    timeline.record_event("case-1", EventType.REMEDIATION, "actor-1")
    
    events = timeline.get_events("case-1")
    assert len(events) == 3
    assert events[0].event_type == EventType.OBSERVATION
    assert events[1].event_type == EventType.APPROVAL
    assert events[2].event_type == EventType.REMEDIATION


def test_timeline_summary():
    timeline = IncidentTimeline()
    timeline.record_event("case-2", EventType.OBSERVATION, "actor-1")
    timeline.record_event("case-2", EventType.REMEDIATION, "actor-1")
    
    summary = timeline.get_timeline_summary("case-2")
    assert summary["case_id"] == "case-2"
    assert summary["event_count"] == 2
    assert summary["status"] == "IN_PROGRESS"
    
    timeline.record_event("case-2", EventType.VERIFICATION, "actor-1")
    summary2 = timeline.get_timeline_summary("case-2")
    assert summary2["status"] == "VERIFIED"


def test_invalid_input():
    timeline = IncidentTimeline()
    with pytest.raises(ValueError, match="case_id is required"):
        timeline.record_event("", EventType.OBSERVATION, "actor")
    with pytest.raises(ValueError, match="actor_id is required"):
        timeline.record_event("case-1", EventType.OBSERVATION, " ")
