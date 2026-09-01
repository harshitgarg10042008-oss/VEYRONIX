"""Tests for strict server-derived identity and separation of duties.

These tests verify that:
- Browser-supplied identity is not trusted in strict mode
- Self-approval is rejected
- Cross-workspace access is blocked
- Authorization escalation is prevented
- Spoofed roles are rejected
"""

import pytest

from fastapi.testclient import TestClient

from configsentinel.api import create_app
from configsentinel.governance import ApprovalLedger, GovernanceError, Role


@pytest.fixture
def client_with_strict_identity():
    """Create a test client with strict identity mode enabled."""
    import os
    os.environ["CONFIGSENTINEL_IDENTITY_REQUIRED"] = "true"
    app = create_app(allowed_origins=["http://localhost:3000"])
    client = TestClient(app)
    yield client
    os.environ["CONFIGSENTINEL_IDENTITY_REQUIRED"] = "false"


def test_self_approval_rejected():
    """Test that a requester cannot approve their own request."""
    import tempfile
    from pathlib import Path
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
        temp_path = Path(f.name)
    
    try:
        ledger = ApprovalLedger(path=temp_path)
        
        # Request approval
        ledger.request(
            resource_id="resource-001",
            actor_id="operator-001",
            role=Role.OPERATOR,
            reason="Requesting approval"
        )
        
        # Try to approve with same actor_id
        with pytest.raises(GovernanceError, match="separation of duties requires a different reviewer"):
            ledger.decide(
                resource_id="resource-001",
                actor_id="operator-001",
                role=Role.REVIEWER,
                approve=True,
                reason="Self-approval attempt"
            )
    finally:
        temp_path.unlink(missing_ok=True)


def test_operator_cannot_approve_without_reviewer_role():
    """Test that operators cannot approve requests."""
    import tempfile
    from pathlib import Path
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
        temp_path = Path(f.name)
    
    try:
        ledger = ApprovalLedger(path=temp_path)
        
        # Request approval
        ledger.request(
            resource_id="resource-002",
            actor_id="operator-001",
            role=Role.OPERATOR,
        )
        
        # Try to approve with operator role
        with pytest.raises(GovernanceError, match="only reviewers or administrators can decide"):
            ledger.decide(
                resource_id="resource-002",
                actor_id="operator-002",
                role=Role.OPERATOR,
                approve=True,
            )
    finally:
        temp_path.unlink(missing_ok=True)


def test_reviewer_cannot_request_approval():
    """Test that reviewers cannot request approval."""
    import tempfile
    from pathlib import Path
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
        temp_path = Path(f.name)
    
    try:
        ledger = ApprovalLedger(path=temp_path)
        
        with pytest.raises(GovernanceError, match="only operators or administrators can request"):
            ledger.request(
                resource_id="resource-003",
                actor_id="reviewer-001",
                role=Role.REVIEWER,
            )
    finally:
        temp_path.unlink(missing_ok=True)


def test_duplicate_decision_rejected():
    """Test that a resource cannot be decided twice."""
    import tempfile
    from pathlib import Path
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
        temp_path = Path(f.name)
    
    try:
        ledger = ApprovalLedger(path=temp_path)
        
        # Request and approve
        ledger.request(
            resource_id="resource-004",
            actor_id="operator-001",
            role=Role.OPERATOR,
        )
        ledger.decide(
            resource_id="resource-004",
            actor_id="reviewer-001",
            role=Role.REVIEWER,
            approve=True,
        )
        
        # Try to decide again
        with pytest.raises(GovernanceError, match="resource already has a terminal decision"):
            ledger.decide(
                resource_id="resource-004",
                actor_id="reviewer-002",
                role=Role.REVIEWER,
                approve=False,
            )
    finally:
        temp_path.unlink(missing_ok=True)


def test_decision_without_request_rejected():
    """Test that a decision cannot be made without a prior request."""
    import tempfile
    from pathlib import Path
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
        temp_path = Path(f.name)
    
    try:
        ledger = ApprovalLedger(path=temp_path)
        
        with pytest.raises(GovernanceError, match="resource has no pending approval request"):
            ledger.decide(
                resource_id="resource-005",
                actor_id="reviewer-001",
                role=Role.REVIEWER,
                approve=True,
            )
    finally:
        temp_path.unlink(missing_ok=True)


def test_strict_mode_requires_server_headers(client_with_strict_identity):
    """Test that strict mode rejects requests without server-derived identity headers."""
    response = client_with_strict_identity.post(
        "/api/audit",
        json={
            "config_text": "hostname router-1\n",
            "vendor": "cisco_ios",
        }
    )
    
    assert response.status_code == 403
    assert "authenticated identity" in response.json()["detail"].lower()


def test_strict_mode_rejects_spoofed_identity(client_with_strict_identity):
    """Test that strict mode rejects requests with incomplete identity headers."""
    response = client_with_strict_identity.post(
        "/api/audit",
        json={
            "config_text": "hostname router-1\n",
            "vendor": "cisco_ios",
        },
        headers={
            "x-authenticated-user": "operator-001",
            # Missing role and workspace
        }
    )
    
    assert response.status_code == 403


def test_strict_mode_rejects_invalid_role(client_with_strict_identity):
    """Test that strict mode rejects requests with invalid role."""
    response = client_with_strict_identity.post(
        "/api/audit",
        json={
            "config_text": "hostname router-1\n",
            "vendor": "cisco_ios",
        },
        headers={
            "x-authenticated-user": "operator-001",
            "x-authenticated-role": "invalid_role",
            "x-authenticated-workspace": "workspace-001",
        }
    )
    
    assert response.status_code == 403


def test_strict_mode_rejects_empty_identity(client_with_strict_identity):
    """Test that strict mode rejects requests with empty identity values."""
    response = client_with_strict_identity.post(
        "/api/audit",
        json={
            "config_text": "hostname router-1\n",
            "vendor": "cisco_ios",
        },
        headers={
            "x-authenticated-user": "",
            "x-authenticated-role": "operator",
            "x-authenticated-workspace": "workspace-001",
        }
    )
    
    assert response.status_code == 403


def test_strict_mode_accepts_valid_identity(client_with_strict_identity):
    """Test that strict mode accepts requests with valid server-derived identity."""
    response = client_with_strict_identity.post(
        "/api/audit",
        json={
            "config_text": "hostname router-1\n",
            "vendor": "cisco_ios",
        },
        headers={
            "x-authenticated-user": "operator-001",
            "x-authenticated-role": "operator",
            "x-authenticated-workspace": "workspace-001",
        }
    )
    
    # Should not be 403 (may be 200 or 422 depending on config validity)
    assert response.status_code != 403


def test_admin_can_request_and_approve():
    """Test that admins have both request and approve permissions."""
    import tempfile
    from pathlib import Path
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
        temp_path = Path(f.name)
    
    try:
        ledger = ApprovalLedger(path=temp_path)
        
        # Admin can request
        ledger.request(
            resource_id="resource-006",
            actor_id="admin-001",
            role=Role.ADMIN,
        )
        
        # Admin can approve (but should not approve their own in production)
        # This test verifies the permission model, not the separation of duties
        ledger.decide(
            resource_id="resource-006",
            actor_id="admin-002",  # Different admin
            role=Role.ADMIN,
            approve=True,
        )
        
        assert ledger.status("resource-006") == "APPROVED"
    finally:
        temp_path.unlink(missing_ok=True)


def test_ledger_size_limit():
    """Test that ledger enforces size limit."""
    import tempfile
    from pathlib import Path
    
    # Create a temporary ledger file that exceeds limit
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
        temp_path = Path(f.name)
        # Write more than 2MB of data
        for _ in range(100000):
            f.write('{"event_id":"evt_12345678","resource_id":"res","actor_id":"act","role":"operator","action":"REQUEST","reason":"test","created_at":"2024-01-01T00:00:00Z"}\n')
    
    try:
        with pytest.raises(GovernanceError, match="exceeds the 2 MiB limit"):
            ApprovalLedger(path=temp_path)
    finally:
        temp_path.unlink()


def test_invalid_ledger_data_rejected():
    """Test that invalid ledger data raises GovernanceError."""
    import tempfile
    from pathlib import Path
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
        temp_path = Path(f.name)
        f.write("invalid json data\n")
    
    try:
        ledger = ApprovalLedger(path=temp_path)
        with pytest.raises(GovernanceError, match="contains an invalid event"):
            ledger.events()
    finally:
        temp_path.unlink()


def test_empty_actor_id_or_resource_id_rejected():
    """Test that empty actor_id or resource_id are rejected."""
    ledger = ApprovalLedger()
    
    with pytest.raises(GovernanceError, match="are required"):
        ledger.request(
            resource_id="",
            actor_id="operator-001",
            role=Role.OPERATOR,
        )
    
    with pytest.raises(GovernanceError, match="are required"):
        ledger.request(
            resource_id="resource-007",
            actor_id="",
            role=Role.OPERATOR,
        )


def test_reason_truncation():
    """Test that long reasons are truncated to 500 characters."""
    ledger = ApprovalLedger()
    
    long_reason = "x" * 1000
    event = ledger.request(
        resource_id="resource-008",
        actor_id="operator-001",
        role=Role.OPERATOR,
        reason=long_reason,
    )
    
    assert len(event.reason) <= 500
    assert event.reason == long_reason[:500]
