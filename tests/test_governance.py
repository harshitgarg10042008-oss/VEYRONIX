from pathlib import Path

import pytest

from configsentinel.governance import ApprovalLedger, GovernanceError, Role


def test_review_requires_independent_reviewer(tmp_path: Path):
    ledger = ApprovalLedger(tmp_path / "events.jsonl")
    ledger.request("rem_123", "alice", role=Role.OPERATOR, reason="Review preview")
    with pytest.raises(GovernanceError, match="different reviewer"):
        ledger.decide("rem_123", "alice", role=Role.REVIEWER, approve=True)
    event = ledger.decide("rem_123", "bob", role=Role.REVIEWER, approve=True)
    assert ledger.status("rem_123") == "APPROVED"
    assert event.actor_id == "bob"
    assert len(ledger.events("rem_123")) == 2


def test_only_reviewer_or_admin_can_decide(tmp_path: Path):
    ledger = ApprovalLedger(tmp_path / "events.jsonl")
    ledger.request("audit_1", "operator", role=Role.OPERATOR)
    with pytest.raises(GovernanceError, match="reviewers"):
        ledger.decide("audit_1", "operator2", role=Role.OPERATOR, approve=False)


def test_terminal_decision_cannot_be_changed(tmp_path: Path):
    ledger = ApprovalLedger(tmp_path / "events.jsonl")
    ledger.request("audit_2", "operator", role=Role.OPERATOR)
    ledger.decide("audit_2", "reviewer", role=Role.REVIEWER, approve=False)
    with pytest.raises(GovernanceError, match="terminal"):
        ledger.decide("audit_2", "admin", role=Role.ADMIN, approve=True)


def test_missing_request_is_rejected(tmp_path: Path):
    ledger = ApprovalLedger(tmp_path / "events.jsonl")
    with pytest.raises(GovernanceError, match="no pending"):
        ledger.decide("missing", "reviewer", role=Role.REVIEWER, approve=True)


def test_rejection_is_terminal_no_override_possible(tmp_path: Path):
    """A rejected approval must remain rejected; no actor may flip it to approved."""
    ledger = ApprovalLedger(tmp_path / "events.jsonl")
    ledger.request(
        "rem_override", "operator", role=Role.OPERATOR, reason="first attempt"
    )
    ledger.decide("rem_override", "reviewer", role=Role.REVIEWER, approve=False)
    assert ledger.status("rem_override") == "REJECTED"
    with pytest.raises(GovernanceError, match="terminal"):
        ledger.decide("rem_override", "admin", role=Role.ADMIN, approve=True)
    assert ledger.status("rem_override") == "REJECTED"


def test_audit_trail_has_required_fields(tmp_path: Path):
    """Every event in the audit trail must carry actor, role, action, reason, timestamp, and event_id."""
    ledger = ApprovalLedger(tmp_path / "events.jsonl")
    ledger.request("rem_trail", "operator", role=Role.OPERATOR, reason="review request")
    ledger.decide(
        "rem_trail", "reviewer", role=Role.REVIEWER, approve=True, reason="accepted"
    )
    events = ledger.events("rem_trail")
    assert len(events) == 2
    for event in events:
        d = event.as_dict()
        for field in (
            "event_id",
            "resource_id",
            "actor_id",
            "role",
            "action",
            "reason",
            "created_at",
        ):
            assert d.get(field), f"audit trail event missing field: {field}"
        assert d["created_at"].startswith(
            "20"
        ), "created_at must be an ISO-8601 UTC timestamp"


def test_only_operator_or_admin_can_request(tmp_path: Path):
    """Reviewers must not be able to self-submit an approval request."""
    ledger = ApprovalLedger(tmp_path / "events.jsonl")
    with pytest.raises(GovernanceError, match="operators or administrators"):
        ledger.request(
            "rem_bad_role",
            "reviewer_alice",
            role=Role.REVIEWER,
            reason="self-approval attempt",
        )
    assert ledger.status("rem_bad_role") == "NOT_REQUESTED"


def test_ledger_event_ordering_is_chronological(tmp_path: Path):
    """Events must be returned in append order (REQUEST before APPROVE/REJECT)."""
    ledger = ApprovalLedger(tmp_path / "events.jsonl")
    ledger.request("rem_order", "operator", role=Role.OPERATOR)
    ledger.decide("rem_order", "reviewer", role=Role.REVIEWER, approve=True)
    events = ledger.events("rem_order")
    assert events[0].action.value == "REQUEST"
    assert events[1].action.value == "APPROVE"


def test_empty_resource_id_and_actor_id_are_rejected(tmp_path: Path):
    """Blank resource_id or actor_id must raise a GovernanceError."""
    ledger = ApprovalLedger(tmp_path / "events.jsonl")
    with pytest.raises(GovernanceError):
        ledger.request("  ", "operator", role=Role.OPERATOR)
    with pytest.raises(GovernanceError):
        ledger.request("rem_blank", "  ", role=Role.OPERATOR)
