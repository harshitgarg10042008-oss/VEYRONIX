"""Unit tests for website scan API endpoints."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json

from configsentinel.api import WebsiteScanPayload


class TestWebsiteScanPayload:
    def test_valid_payload(self):
        payload = WebsiteScanPayload(
            url="https://example.com",
            authorization_confirmed=True
        )
        assert payload.url == "https://example.com"
        assert payload.authorization_confirmed is True
        assert payload.workspace_id == "local"
    
    def test_url_too_long(self):
        with pytest.raises(Exception):  # Pydantic validation error
            WebsiteScanPayload(
                url="https://example.com/" + "x" * 3000,
                authorization_confirmed=True
            )
    
    def test_url_required(self):
        with pytest.raises(Exception):  # Pydantic validation error
            WebsiteScanPayload(
                url="",
                authorization_confirmed=True
            )


class TestWebsiteAPIEndpoints:
    @pytest.fixture
    def mock_app(self):
        """Create a mock FastAPI app for testing."""
        with patch("configsentinel.api.WebsiteScanStorage"), \
             patch("configsentinel.api.WebsiteScanner"):
            from configsentinel.api import create_app
            return create_app()
    
    @pytest.fixture
    def client(self, mock_app):
        """Create a test client."""
        from fastapi.testclient import TestClient
        return TestClient(mock_app)
    
    def test_website_health(self, client):
        """Test website scanner health endpoint."""
        response = client.get("/api/websites/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "scanner_enabled" in data
        assert "version" in data
    
    def test_website_rules(self, client):
        """Test website rules endpoint."""
        response = client.get("/api/websites/rules")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert "rule_count" in data
        assert "rules" in data
        assert isinstance(data["rules"], list)
    
    def test_create_scan_requires_auth(self, client):
        """Test that scan creation requires authorization confirmation."""
        response = client.post(
            "/api/websites/scans",
            json={
                "url": "https://example.com",
                "authorization_confirmed": False
            }
        )
        assert response.status_code == 422
    
    @patch("configsentinel.api.WebsiteScanner")
    @patch("configsentinel.api.WebsiteScanStorage")
    def test_create_scan_success(self, mock_storage, mock_scanner, client):
        """Test successful scan creation."""
        # Mock the scanner
        mock_scanner_instance = MagicMock()
        mock_result = MagicMock()
        mock_result.scan_id = "test-scan-123"
        mock_result.target_origin = "https://example.com"
        mock_result.final_url = "https://example.com"
        mock_result.posture_classification.value = "GOOD"
        mock_result.score = 85
        mock_result.findings = []
        mock_result.passed_count = 0
        mock_result.failed_count = 0
        mock_result.warning_count = 0
        mock_result.unknown_count = 0
        mock_result.critical_count = 0
        mock_result.high_count = 0
        mock_result.medium_count = 0
        mock_result.low_count = 0
        mock_result.rule_pack_version = "web-posture.v1"
        mock_result.scan_timestamp.isoformat.return_value = "2024-01-01T00:00:00"
        mock_result.limitations = "test limitations"
        
        mock_scanner_instance.scan.return_value = mock_result
        mock_scanner.return_value = mock_scanner_instance
        
        # Mock storage
        mock_storage_instance = MagicMock()
        mock_storage.return_value = mock_storage_instance
        
        response = client.post(
            "/api/websites/scans",
            json={
                "url": "https://example.com",
                "authorization_confirmed": True
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == "test-scan-123"
        assert data["score"] == 85
        assert data["posture_classification"] == "GOOD"
    
    def test_get_scan_endpoint_exists(self, client):
        """Test that get scan endpoint is registered."""
        # Check endpoint exists by looking at the app routes
        routes = [route.path for route in client.app.routes]
        assert "/api/websites/scans/{scan_id}" in routes
    
    def test_delete_scan_endpoint_exists(self, client):
        """Test that delete scan endpoint is registered."""
        # Check endpoint exists by looking at the app routes
        routes = [route.path for route in client.app.routes]
        assert "/api/websites/scans/{scan_id}" in routes
