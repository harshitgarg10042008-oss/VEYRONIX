"""Tests for post-change verification loop functionality."""

from datetime import datetime, timezone

import pytest

from configsentinel.verification import (
    VerificationLoop,
    complete_verification,
    create_verification_loop,
    record_approval,
)


def test_create_verification_loop():
    """Test initialization of verification loop from baseline state."""
    loop = create_verification_loop(
        baseline_audit_id="audit-001",
        baseline_input_sha256="abc123",
        baseline_score=75,
        baseline_failed_controls=("NET-MGMT-TELNET-001", "NET-MGMT-HTTP-001"),
    )
    
    assert loop.baseline_audit_id == "audit-001"
    assert loop.baseline_input_sha256 == "abc123"
    assert loop.baseline_score == 75
    assert loop.baseline_failed_controls == ("NET-MGMT-TELNET-001", "NET-MGMT-HTTP-001")
    assert loop.verification_status == "PENDING"
    assert loop.approval_decision is None
    assert loop.post_change_audit_id is None
    assert not loop.is_complete


def test_create_verification_loop_with_proposal():
    """Test verification loop with proposed remediation bundle."""
    loop = create_verification_loop(
        baseline_audit_id="audit-001",
        baseline_input_sha256="abc123",
        baseline_score=75,
        baseline_failed_controls=("NET-MGMT-TELNET-001",),
        proposed_bundle_id="rem_xyz123",
        proposed_remediation_count=1,
    )
    
    assert loop.proposed_bundle_id == "rem_xyz123"
    assert loop.proposed_remediation_count == 1


def test_record_approval():
    """Test recording human approval decision."""
    loop = create_verification_loop(
        baseline_audit_id="audit-001",
        baseline_input_sha256="abc123",
        baseline_score=75,
        baseline_failed_controls=("NET-MGMT-TELNET-001",),
    )
    
    approved = record_approval(loop, actor_id="operator-001", decision="APPROVED")
    
    assert approved.approval_actor_id == "operator-001"
    assert approved.approval_decision == "APPROVED"
    assert approved.approval_timestamp is not None
    assert approved.verification_status == "PENDING"
    
    rejected = record_approval(loop, actor_id="operator-001", decision="REJECTED")
    assert rejected.approval_decision == "REJECTED"
    assert rejected.verification_status == "FAILED"


def test_record_approval_invalid_decision():
    """Test that invalid approval decisions are rejected."""
    loop = create_verification_loop(
        baseline_audit_id="audit-001",
        baseline_input_sha256="abc123",
        baseline_score=75,
        baseline_failed_controls=("NET-MGMT-TELNET-001",),
    )
    
    with pytest.raises(ValueError, match="Invalid approval decision"):
        record_approval(loop, actor_id="operator-001", decision="INVALID")


def test_complete_verification_success():
    """Test successful verification with resolved controls."""
    loop = create_verification_loop(
        baseline_audit_id="audit-001",
        baseline_input_sha256="abc123",
        baseline_score=75,
        baseline_failed_controls=("NET-MGMT-TELNET-001", "NET-MGMT-HTTP-001"),
    )
    
    approved = record_approval(loop, actor_id="operator-001", decision="APPROVED")
    
    completed = complete_verification(
        approved,
        post_change_audit_id="audit-002",
        post_change_input_sha256="def456",
        post_change_score=90,
        post_change_failed_controls=(),  # All resolved
    )
    
    assert completed.post_change_audit_id == "audit-002"
    assert completed.post_change_score == 90
    assert completed.resolved_controls == ("NET-MGMT-HTTP-001", "NET-MGMT-TELNET-001")
    assert completed.new_failures == ()
    assert completed.unchanged_failures == ()
    assert completed.verification_status == "VERIFIED"
    assert completed.is_complete
    assert completed.score_improvement == 15


def test_complete_verification_partial():
    """Test partial verification with some resolved and some new failures."""
    loop = create_verification_loop(
        baseline_audit_id="audit-001",
        baseline_input_sha256="abc123",
        baseline_score=75,
        baseline_failed_controls=("NET-MGMT-TELNET-001", "NET-MGMT-HTTP-001"),
    )
    
    approved = record_approval(loop, actor_id="operator-001", decision="APPROVED")
    
    completed = complete_verification(
        approved,
        post_change_audit_id="audit-002",
        post_change_input_sha256="def456",
        post_change_score=80,
        post_change_failed_controls=("NET-AUTH-AAA-001",),  # New failure
    )
    
    assert completed.resolved_controls == ("NET-MGMT-HTTP-001", "NET-MGMT-TELNET-001")
    assert completed.new_failures == ("NET-AUTH-AAA-001",)
    assert completed.unchanged_failures == ()
    assert completed.verification_status == "PARTIAL"


def test_complete_verification_unchanged():
    """Test verification with unchanged failures."""
    loop = create_verification_loop(
        baseline_audit_id="audit-001",
        baseline_input_sha256="abc123",
        baseline_score=75,
        baseline_failed_controls=("NET-MGMT-TELNET-001",),
    )
    
    approved = record_approval(loop, actor_id="operator-001", decision="APPROVED")
    
    completed = complete_verification(
        approved,
        post_change_audit_id="audit-002",
        post_change_input_sha256="def456",
        post_change_score=75,
        post_change_failed_controls=("NET-MGMT-TELNET-001",),  # Unchanged
    )
    
    assert completed.resolved_controls == ()
    assert completed.new_failures == ()
    assert completed.unchanged_failures == ("NET-MGMT-TELNET-001",)
    assert completed.verification_status == "FAILED"


def test_complete_verification_without_approval():
    """Test that verification cannot be completed without approval."""
    loop = create_verification_loop(
        baseline_audit_id="audit-001",
        baseline_input_sha256="abc123",
        baseline_score=75,
        baseline_failed_controls=("NET-MGMT-TELNET-001",),
    )
    
    with pytest.raises(ValueError, match="Cannot complete verification without approval"):
        complete_verification(
            loop,
            post_change_audit_id="audit-002",
            post_change_input_sha256="def456",
            post_change_score=90,
            post_change_failed_controls=(),
        )


def test_score_improvement_without_post_change():
    """Test score improvement returns 0 when post-change not available."""
    loop = create_verification_loop(
        baseline_audit_id="audit-001",
        baseline_input_sha256="abc123",
        baseline_score=75,
        baseline_failed_controls=("NET-MGMT-TELNET-001",),
    )
    
    assert loop.score_improvement == 0


def test_verification_loop_limitations():
    """Test that limitations are included in verification loop."""
    loop = create_verification_loop(
        baseline_audit_id="audit-001",
        baseline_input_sha256="abc123",
        baseline_score=75,
        baseline_failed_controls=("NET-MGMT-TELNET-001",),
    )
    
    assert len(loop.limitations) > 0
    assert "Post-change verification requires operator" in loop.limitations[0]
