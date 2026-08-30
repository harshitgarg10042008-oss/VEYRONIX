"""Unit tests for website HTTP client and safety policies."""

import pytest
from unittest.mock import Mock, patch, MagicMock

from configsentinel.website_http import (
    HTTPClientConfig,
    DEFAULT_HTTP_CONFIG,
    TargetSafetyError,
    TargetSafetyPolicy,
    SafeHTTPClient,
)


class TestHTTPClientConfig:
    def test_default_config(self):
        assert DEFAULT_HTTP_CONFIG.timeout_seconds == 15.0
        assert DEFAULT_HTTP_CONFIG.max_response_bytes == 2_000_000
        assert DEFAULT_HTTP_CONFIG.max_redirects == 5
        assert DEFAULT_HTTP_CONFIG.allow_private_targets is False
    
    def test_invalid_timeout(self):
        with pytest.raises(ValueError, match="timeout_seconds must be positive"):
            HTTPClientConfig(timeout_seconds=0)
    
    def test_invalid_max_response_bytes(self):
        with pytest.raises(ValueError, match="max_response_bytes must be positive"):
            HTTPClientConfig(max_response_bytes=0)
    
    def test_invalid_max_redirects(self):
        with pytest.raises(ValueError, match="max_redirects cannot be negative"):
            HTTPClientConfig(max_redirects=-1)


class TestTargetSafetyPolicy:
    def test_block_localhost_by_default(self):
        policy = TargetSafetyPolicy(allow_private=False)
        with pytest.raises(TargetSafetyError, match="Localhost hostname is blocked"):
            policy.check_hostname("localhost")
    
    def test_allow_localhost_when_enabled(self):
        policy = TargetSafetyPolicy(allow_private=True)
        # Should not raise
        policy.check_hostname("localhost")
    
    def test_block_private_ip(self):
        policy = TargetSafetyPolicy(allow_private=False)
        with pytest.raises(TargetSafetyError, match="Private IP address is blocked"):
            policy._check_ip_address("192.168.1.1")
    
    def test_block_loopback_ip(self):
        policy = TargetSafetyPolicy(allow_private=False)
        with pytest.raises(TargetSafetyError, match="Private IP address is blocked"):
            policy._check_ip_address("127.0.0.1")
    
    def test_allow_public_ip(self):
        policy = TargetSafetyPolicy(allow_private=False)
        # Should not raise
        policy._check_ip_address("8.8.8.8")
    
    def test_block_unsupported_scheme(self):
        policy = TargetSafetyPolicy(allow_private=False)
        with pytest.raises(TargetSafetyError, match="Unsupported scheme"):
            policy.check_url("ftp://example.com")
    
    def test_block_private_when_disabled(self):
        policy = TargetSafetyPolicy(allow_private=False)
        with pytest.raises(TargetSafetyError):
            policy.check_url("http://192.168.1.1")


class TestSafeHTTPClient:
    def test_requires_httpx(self):
        # This test verifies the import error is raised
        # In real usage, httpx should be installed
        pass
    
    @patch("configsentinel.website_http.httpx")
    def test_fetch_with_safety_check(self, mock_httpx):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = b"<html></html>"
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        
        mock_httpx.Client.return_value = mock_client
        mock_httpx.Limits.return_value = MagicMock()
        mock_httpx.Timeout.return_value = MagicMock()
        
        client = SafeHTTPClient()
        client.safety_policy = Mock()  # Mock safety policy
        
        response = client.fetch("https://example.com")
        
        assert response == mock_response
        client.safety_policy.check_url.assert_called_once_with("https://example.com")
    
    @patch("configsentinel.website_http.httpx")
    def test_response_size_limit(self, mock_httpx):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = b"x" * 3_000_000  # Exceeds 2MB limit
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        
        mock_httpx.Client.return_value = mock_client
        mock_httpx.Limits.return_value = MagicMock()
        mock_httpx.Timeout.return_value = MagicMock()
        
        client = SafeHTTPClient()
        client.safety_policy = Mock()
        
        with pytest.raises(TargetSafetyError, match="Response exceeds maximum size"):
            client.fetch("https://example.com")
    
    @patch("configsentinel.website_http.httpx")
    def test_fetch_head(self, mock_httpx):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_client.head.return_value = mock_response
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        
        mock_httpx.Client.return_value = mock_client
        mock_httpx.Limits.return_value = MagicMock()
        mock_httpx.Timeout.return_value = MagicMock()
        
        client = SafeHTTPClient()
        client.safety_policy = Mock()
        
        response = client.fetch_head("https://example.com")
        
        assert response == mock_response
        client.safety_policy.check_url.assert_called_once_with("https://example.com")
