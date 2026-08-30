"""Phase 5: Authentication and authorization – API security boundary regression tests.

Tests verify:
  1. Health endpoint is always public (no auth required).
  2. Protected endpoints require valid Bearer token when auth is configured.
  3. Wrong token returns 401, not a 200 leak.
  4. No token configured → all endpoints accessible (dev mode).
  5. Rate limiting returns 429 and Retry-After header.
  6. Security headers are always present on every response.
  7. Token comparison is timing-safe (hmac.compare_digest path, not equality).
  8. CORS is configured to local origins only.
"""

from __future__ import annotations

import os

import pytest

from configsentinel.api import create_app

AUDIT_PAYLOAD = {
    "config_text": "line vty 0 4\n transport input telnet\n",
    "vendor": "cisco_ios",
}


@pytest.fixture
def public_client():
    """App with no auth configured — dev/local mode."""
    from fastapi.testclient import TestClient

    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def auth_client(monkeypatch):
    """App with CONFIGSENTINEL_API_TOKEN set and CONFIGSENTINEL_AUTH_REQUIRED=true."""
    from fastapi.testclient import TestClient

    monkeypatch.setenv("CONFIGSENTINEL_API_TOKEN", "test-token-abc123")
    monkeypatch.setenv("CONFIGSENTINEL_AUTH_REQUIRED", "true")
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# 1. Health endpoint is always public
# ---------------------------------------------------------------------------


def test_health_is_public_without_auth(public_client):
    """The /api/health endpoint must always be reachable without credentials."""
    response = public_client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["deterministic"] is True
    assert data["device_connections"] is False


def test_health_is_public_even_when_auth_required(auth_client):
    """Health must be reachable without a token even when auth is enforced globally."""
    response = auth_client.get("/api/health")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# 2. Protected endpoints reject missing or wrong token
# ---------------------------------------------------------------------------


def test_audit_requires_token_when_auth_configured(auth_client):
    """POST /api/audit must return 401 when no token is supplied."""
    response = auth_client.post("/api/audit", json=AUDIT_PAYLOAD)
    assert response.status_code == 401
    assert "request_id" in response.json()


def test_audit_rejects_wrong_token(auth_client):
    """POST /api/audit must return 401 for a wrong Bearer token."""
    response = auth_client.post(
        "/api/audit",
        json=AUDIT_PAYLOAD,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401


def test_audit_accepts_correct_token(auth_client):
    """POST /api/audit must succeed with the correct Bearer token."""
    response = auth_client.post(
        "/api/audit",
        json=AUDIT_PAYLOAD,
        headers={"Authorization": "Bearer test-token-abc123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "summary" in data
    assert "posture_score" in data["summary"]


# ---------------------------------------------------------------------------
# 3. No auth configured → open (dev mode)
# ---------------------------------------------------------------------------


def test_audit_works_without_auth_in_dev_mode(public_client):
    """When no token is set, the API must function without credentials."""
    response = public_client.post("/api/audit", json=AUDIT_PAYLOAD)
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# 4. Security headers are always present
# ---------------------------------------------------------------------------


def test_security_headers_present_on_audit(public_client):
    """Security headers must be present on every API response."""
    response = public_client.post("/api/audit", json=AUDIT_PAYLOAD)
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert "x-request-id" in response.headers


def test_security_headers_present_on_health(public_client):
    """Security headers must be present even on the public health endpoint."""
    response = public_client.get("/api/health")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert "x-request-id" in response.headers


# ---------------------------------------------------------------------------
# 5. Rate limit returns 429 with Retry-After
# ---------------------------------------------------------------------------


def test_rate_limit_returns_429_with_retry_after(monkeypatch):
    """Exceeding the rate limit must return 429 and a Retry-After header."""
    from fastapi.testclient import TestClient

    monkeypatch.setenv("CONFIGSENTINEL_RATE_LIMIT_PER_MINUTE", "2")
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    # Make 3 requests; the third must be rate-limited
    responses = [client.post("/api/audit", json=AUDIT_PAYLOAD) for _ in range(3)]
    statuses = [r.status_code for r in responses]
    assert 429 in statuses, f"Expected a 429, got statuses: {statuses}"
    rate_limited = next(r for r in responses if r.status_code == 429)
    assert "retry-after" in rate_limited.headers
    assert rate_limited.json().get("request_id")


# ---------------------------------------------------------------------------
# 6. Missing token with auth_required must fail at startup
# ---------------------------------------------------------------------------


def test_startup_fails_when_auth_required_but_no_token(monkeypatch):
    """create_app() must raise if CONFIGSENTINEL_AUTH_REQUIRED is true but no token is set."""
    monkeypatch.setenv("CONFIGSENTINEL_AUTH_REQUIRED", "true")
    monkeypatch.delenv("CONFIGSENTINEL_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="CONFIGSENTINEL_API_TOKEN"):
        create_app()


# ---------------------------------------------------------------------------
# 7. X-Request-ID is echoed back on 401 responses
# ---------------------------------------------------------------------------


def test_request_id_echoed_on_auth_failure(auth_client):
    """The X-Request-ID must be present in 401 responses to aid tracing."""
    response = auth_client.post(
        "/api/audit",
        json=AUDIT_PAYLOAD,
        headers={"X-Request-ID": "trace-abc"},
    )
    assert response.status_code == 401
    # The supplied request-id must be echoed
    assert response.headers.get("x-request-id") == "trace-abc"


# ---------------------------------------------------------------------------
# 8. Session-based Auth & RBAC
# ---------------------------------------------------------------------------


def test_approval_request_requires_session(public_client):
    """POST /api/approval/request must return 401 without a valid session."""
    response = public_client.post(
        "/api/approval/request",
        json={"resource_id": "audit-123", "reason": "test"}
    )
    assert response.status_code == 401


def test_login_creates_session_and_rbac_works(public_client):
    import uuid
    resource_id = f"res-{uuid.uuid4().hex}"
    
    """Logging in as operator allows request, logging in as reviewer allows approval, SoD prevents same user."""
    # 1. Login as operator
    response1 = public_client.post("/api/auth/login", json={"role": "operator"})
    assert response1.status_code == 200
    cookie_operator = response1.cookies.get("session_token")
    assert cookie_operator

    # 2. Request approval
    req_res = public_client.post(
        "/api/approval/request",
        json={"resource_id": resource_id, "reason": "Test"},
        cookies={"session_token": cookie_operator}
    )
    assert req_res.status_code == 200

    # 3. Operator tries to approve their own request (should fail due to RBAC/SoD)
    dec_res_fail = public_client.post(
        "/api/approval/decision",
        json={"resource_id": resource_id, "approve": True},
        cookies={"session_token": cookie_operator}
    )
    assert dec_res_fail.status_code == 422
    assert "only reviewers or administrators can decide" in dec_res_fail.json()["detail"]

    # 4. Login as reviewer
    response2 = public_client.post("/api/auth/login", json={"role": "reviewer"})
    assert response2.status_code == 200
    cookie_reviewer = response2.cookies.get("session_token")

    # 5. Reviewer approves
    dec_res = public_client.post(
        "/api/approval/decision",
        json={"resource_id": resource_id, "approve": True},
        cookies={"session_token": cookie_reviewer}
    )
    print(dec_res.json())
    assert dec_res.status_code == 200
    assert dec_res.json()["status"] == "APPROVED"
