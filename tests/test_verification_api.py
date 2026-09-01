"""Tests for verification loop API endpoints."""

import pytest

from fastapi.testclient import TestClient

from configsentinel.api import create_app


@pytest.fixture
def client():
    """Create a test client for the API."""
    app = create_app(allowed_origins=["http://localhost:3000"])
    return TestClient(app)


def test_create_verification_loop(client):
    """Test creating a new verification loop."""
    payload = {
        "baseline_audit_id": "audit-001",
        "baseline_input_sha256": "abc123",
        "baseline_score": 75,
        "baseline_failed_controls": ["NET-MGMT-TELNET-001", "NET-MGMT-HTTP-001"],
        "proposed_bundle_id": "rem_xyz123",
        "proposed_remediation_count": 2,
    }
    
    response = client.post("/api/verification/loops", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["loop_id"] == "loop_audit-001"
    assert data["baseline_audit_id"] == "audit-001"
    assert data["baseline_score"] == 75
    assert data["baseline_failed_controls"] == ["NET-MGMT-TELNET-001", "NET-MGMT-HTTP-001"]
    assert data["proposed_bundle_id"] == "rem_xyz123"
    assert data["proposed_remediation_count"] == 2
    assert data["verification_status"] == "PENDING"
    assert len(data["limitations"]) > 0


def test_create_verification_loop_minimal(client):
    """Test creating a verification loop with minimal payload."""
    payload = {
        "baseline_audit_id": "audit-002",
        "baseline_input_sha256": "def456",
        "baseline_score": 60,
        "baseline_failed_controls": ["NET-MGMT-SSH-001"],
    }
    
    response = client.post("/api/verification/loops", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["proposed_bundle_id"] is None
    assert data["proposed_remediation_count"] == 0


def test_approve_verification_loop(client):
    """Test approving a verification loop."""
    # First create a loop
    create_payload = {
        "baseline_audit_id": "audit-003",
        "baseline_input_sha256": "ghi789",
        "baseline_score": 70,
        "baseline_failed_controls": ["NET-MGMT-TELNET-001"],
    }
    client.post("/api/verification/loops", json=create_payload)
    
    # Then approve it
    approve_payload = {
        "loop_id": "loop_audit-003",
        "actor_id": "operator-001",
        "decision": "APPROVED",
    }
    
    response = client.post("/api/verification/loops/loop_audit-003/approve", json=approve_payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["loop_id"] == "loop_audit-003"
    assert data["approval_actor_id"] == "operator-001"
    assert data["approval_decision"] == "APPROVED"
    assert data["approval_timestamp"] is not None
    assert data["verification_status"] == "PENDING"


def test_reject_verification_loop(client):
    """Test rejecting a verification loop."""
    # First create a loop
    create_payload = {
        "baseline_audit_id": "audit-004",
        "baseline_input_sha256": "jkl012",
        "baseline_score": 65,
        "baseline_failed_controls": ["NET-MGMT-HTTP-001"],
    }
    client.post("/api/verification/loops", json=create_payload)
    
    # Then reject it
    approve_payload = {
        "loop_id": "loop_audit-004",
        "actor_id": "operator-001",
        "decision": "REJECTED",
    }
    
    response = client.post("/api/verification/loops/loop_audit-004/approve", json=approve_payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["approval_decision"] == "REJECTED"
    assert data["verification_status"] == "FAILED"


def test_approve_nonexistent_loop(client):
    """Test approving a loop that doesn't exist."""
    payload = {
        "loop_id": "loop_nonexistent",
        "actor_id": "operator-001",
        "decision": "APPROVED",
    }
    
    response = client.post("/api/verification/loops/loop_nonexistent/approve", json=payload)
    
    assert response.status_code == 404


def test_complete_verification_loop(client):
    """Test completing a verification loop with post-change results."""
    # Create and approve a loop
    create_payload = {
        "baseline_audit_id": "audit-005",
        "baseline_input_sha256": "mno345",
        "baseline_score": 70,
        "baseline_failed_controls": ["NET-MGMT-TELNET-001", "NET-MGMT-HTTP-001"],
    }
    client.post("/api/verification/loops", json=create_payload)
    
    approve_payload = {
        "loop_id": "loop_audit-005",
        "actor_id": "operator-001",
        "decision": "APPROVED",
    }
    client.post("/api/verification/loops/loop_audit-005/approve", json=approve_payload)
    
    # Complete with post-change results
    complete_payload = {
        "loop_id": "loop_audit-005",
        "post_change_audit_id": "audit-006",
        "post_change_input_sha256": "pqr678",
        "post_change_score": 90,
        "post_change_failed_controls": [],  # All resolved
    }
    
    response = client.post("/api/verification/loops/loop_audit-005/complete", json=complete_payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["loop_id"] == "loop_audit-005"
    assert data["post_change_audit_id"] == "audit-006"
    assert data["post_change_score"] == 90
    assert set(data["resolved_controls"]) == {"NET-MGMT-HTTP-001", "NET-MGMT-TELNET-001"}
    assert data["new_failures"] == []
    assert data["unchanged_failures"] == []
    assert data["verification_status"] == "VERIFIED"
    assert data["is_complete"] is True
    assert data["score_improvement"] == 20


def test_complete_verification_loop_partial(client):
    """Test completing verification with partial success (new failures)."""
    # Create and approve a loop
    create_payload = {
        "baseline_audit_id": "audit-007",
        "baseline_input_sha256": "stu901",
        "baseline_score": 70,
        "baseline_failed_controls": ["NET-MGMT-TELNET-001"],
    }
    client.post("/api/verification/loops", json=create_payload)
    
    approve_payload = {
        "loop_id": "loop_audit-007",
        "actor_id": "operator-001",
        "decision": "APPROVED",
    }
    client.post("/api/verification/loops/loop_audit-007/approve", json=approve_payload)
    
    # Complete with new failure
    complete_payload = {
        "loop_id": "loop_audit-007",
        "post_change_audit_id": "audit-008",
        "post_change_input_sha256": "vwx234",
        "post_change_score": 80,
        "post_change_failed_controls": ["NET-AUTH-AAA-001"],  # New failure
    }
    
    response = client.post("/api/verification/loops/loop_audit-007/complete", json=complete_payload)
    
    assert response.status_code == 200
    data = response.json()
    assert set(data["resolved_controls"]) == {"NET-MGMT-TELNET-001"}
    assert data["new_failures"] == ["NET-AUTH-AAA-001"]
    assert data["verification_status"] == "PARTIAL"
    assert data["is_complete"] is False


def test_complete_without_approval(client):
    """Test that completion fails without prior approval."""
    # Create a loop without approval
    create_payload = {
        "baseline_audit_id": "audit-009",
        "baseline_input_sha256": "yza567",
        "baseline_score": 70,
        "baseline_failed_controls": ["NET-MGMT-TELNET-001"],
    }
    client.post("/api/verification/loops", json=create_payload)
    
    # Try to complete without approval
    complete_payload = {
        "loop_id": "loop_audit-009",
        "post_change_audit_id": "audit-010",
        "post_change_input_sha256": "bcd890",
        "post_change_score": 90,
        "post_change_failed_controls": [],
    }
    
    response = client.post("/api/verification/loops/loop_audit-009/complete", json=complete_payload)
    
    assert response.status_code == 422  # Validation error


def test_get_verification_loop(client):
    """Test retrieving verification loop state."""
    # Create a loop
    create_payload = {
        "baseline_audit_id": "audit-011",
        "baseline_input_sha256": "efg123",
        "baseline_score": 75,
        "baseline_failed_controls": ["NET-MGMT-SSH-001"],
    }
    client.post("/api/verification/loops", json=create_payload)
    
    # Retrieve it
    response = client.get("/api/verification/loops/loop_audit-011")
    
    assert response.status_code == 200
    data = response.json()
    assert data["loop_id"] == "loop_audit-011"
    assert data["baseline_audit_id"] == "audit-011"
    assert data["verification_status"] == "PENDING"
    assert data["is_complete"] is False


def test_get_nonexistent_loop(client):
    """Test retrieving a loop that doesn't exist."""
    response = client.get("/api/verification/loops/loop_nonexistent")
    
    assert response.status_code == 404
