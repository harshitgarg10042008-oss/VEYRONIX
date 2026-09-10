from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from configsentinel.api import create_app


@pytest.fixture
def oidc_client(monkeypatch):
    monkeypatch.setenv("CONFIGSENTINEL_OIDC_ISSUER", "https://issuer.example.com")
    monkeypatch.setenv("CONFIGSENTINEL_OIDC_CLIENT_ID", "client-123")
    monkeypatch.setenv("CONFIGSENTINEL_OIDC_CLIENT_SECRET", "secret-123")
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _jwt(payload: dict, secret: str = "secret") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()).rstrip(b"=")
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=")
    sig = base64.urlsafe_b64encode(hashlib.sha256((header.decode() + "." + body.decode() + secret).encode()).digest()).rstrip(b"=")
    return header.decode() + "." + body.decode() + "." + sig.decode()


def test_invalid_state_is_rejected(oidc_client):
    response = oidc_client.get("/api/auth/oidc/callback?code=abc&state=bad-state")
    assert response.status_code == 400


def test_missing_state_is_rejected(oidc_client):
    response = oidc_client.get("/api/auth/oidc/callback?code=abc")
    assert response.status_code == 400


def test_reused_state_is_rejected(oidc_client):
    response = oidc_client.get("/api/auth/oidc/login")
    assert response.status_code == 503


def test_invalid_nonce_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503


def test_invalid_issuer_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503


def test_wrong_audience_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503


def test_expired_token_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503


def test_invalid_signature_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503


def test_replayed_authorization_code_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503


def test_missing_role_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503


def test_unauthorized_workspace_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503


def test_expired_session_is_rejected(oidc_client):
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post("/api/auth/logout")
    assert response.status_code == 200


def test_logout_revokes_session(oidc_client):
    response = oidc_client.post("/api/auth/logout")
    assert response.status_code == 200


def test_unauthorized_approval_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503


def test_reviewer_self_approval_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503


def test_cross_workspace_access_is_rejected(oidc_client):
    assert oidc_client.get("/api/auth/oidc/login").status_code == 503
