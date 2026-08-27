from pathlib import Path

import pytest

from configsentinel import EvidenceSpan
from configsentinel.learning import LearningLoopError, ReviewDecision, UnknownSyntaxQueue


def make_queue():
    queue = UnknownSyntaxQueue()
    case = queue.enqueue(
        vendor="cisco_ios",
        parser_version="cisco-ios-3.0.0",
        evidence=EvidenceSpan(12, 12, " service mystery-control"),
        context="line vty 0 4\n service mystery-control",
        source_sha256="a" * 64,
    )
    return queue, case


def test_unknown_case_and_proposal_are_created():
    queue, case = make_queue()
    proposal = queue.propose(case.case_id, interpretation="Enables a secure management service", normalized_concept="management_secure_service", confidence=0.82)
    assert case.case_id.startswith("case_")
    assert proposal.decision == ReviewDecision.PENDING
    assert proposal.evidence_needed == ()


def test_approval_requires_second_reviewer():
    queue, case = make_queue()
    proposal = queue.propose(case.case_id, interpretation="Maps to logging", normalized_concept="logging_enabled", confidence=0.9)
    with pytest.raises(LearningLoopError):
        queue.review(proposal.proposal_id, reviewer="alice", decision=ReviewDecision.APPROVED, reason="Looks correct")


def test_approved_mapping_creates_fixture_and_audit_event(tmp_path: Path):
    queue, case = make_queue()
    proposal = queue.propose(case.case_id, interpretation="Maps to logging", normalized_concept="logging_enabled", confidence=0.9)
    mapping = queue.review(proposal.proposal_id, reviewer="alice", second_reviewer="bob", decision=ReviewDecision.APPROVED, reason="Verified against vendor documentation")
    assert mapping is not None
    fixture_path = tmp_path / "unknown.json"
    queue.write_regression_fixture(mapping.mapping_id, fixture_path)
    assert fixture_path.exists()
    assert queue.audit_trail()[0]["decision"] == ReviewDecision.APPROVED
    assert queue.regression_fixture(mapping.mapping_id)["source_case_id"] == case.case_id


def test_rejection_does_not_create_mapping():
    queue, case = make_queue()
    proposal = queue.propose(case.case_id, interpretation="Unclear service", normalized_concept="unknown", confidence=0.2)
    assert queue.review(proposal.proposal_id, reviewer="alice", decision=ReviewDecision.REJECTED, reason="Insufficient evidence") is None
    assert queue.mappings() == ()


def test_unknown_case_requires_source_provenance():
    queue = UnknownSyntaxQueue()
    with pytest.raises(LearningLoopError):
        queue.enqueue(vendor="cisco_ios", parser_version="1", evidence=EvidenceSpan(1, 1, " mystery"), context="mystery", source_sha256="")
