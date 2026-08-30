import pytest
from configsentinel.api import create_app

@pytest.fixture
def auth_client(monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("CONFIGSENTINEL_API_TOKEN", "test-token-abc123")
    monkeypatch.setenv("CONFIGSENTINEL_AUTH_REQUIRED", "true")
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)

def test_inventory_requires_auth(auth_client):
    response = auth_client.get("/api/inventory")
    assert response.status_code == 401

def test_inventory_rejects_invalid_token(auth_client):
    response = auth_client.get(
        "/api/inventory",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401

def test_inventory_boundary_conditions(auth_client):
    # Missing required fields
    response = auth_client.post(
        "/api/inventory",
        json={"vendor": "cisco"},
        headers={"Authorization": "Bearer test-token-abc123"},
    )
    assert response.status_code == 422
    
    # Boundary condition on string length
    long_name = "x" * 200
    response = auth_client.post(
        "/api/inventory",
        json={"name": long_name},
        headers={"Authorization": "Bearer test-token-abc123"},
    )
    assert response.status_code == 422

def test_monitors_requires_auth(auth_client):
    response = auth_client.get("/api/monitors")
    assert response.status_code == 401

def test_monitors_boundary_conditions(auth_client):
    response = auth_client.post(
        "/api/monitors",
        json={"target_id": ""},
        headers={"Authorization": "Bearer test-token-abc123"},
    )
    assert response.status_code == 422
