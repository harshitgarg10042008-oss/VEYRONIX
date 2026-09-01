from unittest.mock import patch

from fastapi.testclient import TestClient

from configsentinel.api import create_app
from configsentinel.website_models import WebsiteScanRequest
from configsentinel.website_scanner import WebsiteScanner


def test_scan_error_fails_closed_instead_of_returning_placeholder_50():
    request = WebsiteScanRequest(
        url="https://example.com",
        authorization_confirmed=True,
    )
    with patch.object(WebsiteScanner, "_collect_observations", side_effect=RuntimeError("synthetic transport failure")):
        result = WebsiteScanner().scan(request)

    assert result.score == 0
    assert result.posture_classification.value == "HIGH_RISK"
    assert result.findings[0].rule_id == "SCAN-ERROR"
    assert result.findings[0].status.value == "UNKNOWN"


def test_openapi_contract_is_available_even_with_optional_routes():
    app = create_app()
    schema = app.openapi()

    assert schema["info"]["version"] == "0.4.0"
    assert "/api/v1/audit" in schema["paths"]
    assert "/api/websites/scans" in schema["paths"]


def test_legacy_feature_routes_are_registered():
    client = TestClient(create_app())

    assert client.post(
        "/api/secrets/scan", json={"config_text": "password=demo"}
    ).status_code == 200
    assert client.post(
        "/api/debt/report", json={"scope": "global"}
    ).status_code == 200
    assert client.get("/api/attack-graph/paths").status_code == 200
