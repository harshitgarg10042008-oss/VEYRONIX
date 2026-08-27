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
