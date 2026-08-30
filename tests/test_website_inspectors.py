"""Unit tests for website header and cookie inspectors."""

import pytest

from configsentinel.website_inspectors import (
    HeaderInspector,
    CookieInspector,
    ServerDisclosureInspector,
    SecurityTxtInspector,
)
from configsentinel.website_models import HeaderEvidence, CookieEvidence


class TestHeaderInspector:
    def test_inspect_present_header(self):
        inspector = HeaderInspector()
        evidence = inspector.inspect_header(
            "Content-Security-Policy",
            "default-src 'self'"
        )
        
        assert evidence.header_name == "Content-Security-Policy"
        assert evidence.present is True
        assert evidence.parsed_directives == {"default-src": "'self'"}
    
    def test_inspect_missing_header(self):
        inspector = HeaderInspector()
        evidence = inspector.inspect_header("X-Frame-Options", "")
        
        assert evidence.present is False
        assert evidence.header_value == ""
    
    def test_parse_csp(self):
        inspector = HeaderInspector()
        directives = inspector._parse_csp("default-src 'self'; script-src 'self' https://cdn.example.com")
        
        assert directives["default-src"] == "'self'"
        assert directives["script-src"] == "'self' https://cdn.example.com"
    
    def test_parse_hsts(self):
        inspector = HeaderInspector()
        directives = inspector._parse_hsts("max-age=31536000; includeSubDomains; preload")
        
        assert directives["max-age"] == "31536000"
        assert directives["includeSubDomains"] == ""
        assert directives["preload"] == ""
    
    def test_check_hsts_strength_missing(self):
        inspector = HeaderInspector()
        is_strong, rationale = inspector.check_hsts_strength("")
        
        assert is_strong is False
        assert "missing" in rationale.lower()
    
    def test_check_hsts_strength_short_max_age(self):
        inspector = HeaderInspector()
        is_strong, rationale = inspector.check_hsts_strength("max-age=3600")
        
        assert is_strong is False
        assert "too short" in rationale.lower()
    
    def test_check_hsts_strength_proper(self):
        inspector = HeaderInspector()
        is_strong, rationale = inspector.check_hsts_strength(
            "max-age=31536000; includeSubDomains; preload"
        )
        
        assert is_strong is True
        assert "properly configured" in rationale.lower()
    
    def test_check_csp_strength_missing(self):
        inspector = HeaderInspector()
        is_strong, rationale = inspector.check_csp_strength("")
        
        assert is_strong is False
        assert "missing" in rationale.lower()
    
    def test_check_csp_strength_permissive(self):
        inspector = HeaderInspector()
        is_strong, rationale = inspector.check_csp_strength("default-src *")
        
        assert is_strong is False
        assert "permissive" in rationale.lower()
    
    def test_check_csp_strength_good(self):
        inspector = HeaderInspector()
        is_strong, rationale = inspector.check_csp_strength("default-src 'self'")
        
        assert is_strong is True


class TestCookieInspector:
    def test_inspect_secure_cookie(self):
        inspector = CookieInspector()
        attributes = {
            "secure": "true",
            "httponly": "true",
            "samesite": "Strict",
            "domain": "example.com",
        }
        
        evidence = inspector.inspect_cookie("session", "value", attributes)
        
        assert evidence.cookie_name == "session"
        assert evidence.secure is True
        assert evidence.http_only is True
        assert evidence.same_site == "Strict"
    
    def test_inspect_insecure_cookie(self):
        inspector = CookieInspector()
        attributes = {"secure": "false", "httponly": "false", "samesite": "None"}
        
        evidence = inspector.inspect_cookie("tracking", "value", attributes)
        
        assert evidence.secure is False
        assert evidence.http_only is False
        assert evidence.same_site == "None"
    
    def test_check_cookie_security_secure(self):
        inspector = CookieInspector()
        cookie = CookieEvidence(
            cookie_name="session",
            domain="example.com",
            secure=True,
            http_only=True,
            same_site="Strict"
        )
        
        is_secure, rationale = inspector.check_cookie_security(cookie)
        assert is_secure is True
    
    def test_check_cookie_security_insecure(self):
        inspector = CookieInspector()
        cookie = CookieEvidence(
            cookie_name="session",
            domain="example.com",
            secure=False,
            http_only=False,
            same_site="None"
        )
        
        is_secure, rationale = inspector.check_cookie_security(cookie)
        assert is_secure is False
        assert "missing" in rationale.lower()


class TestServerDisclosureInspector:
    def test_no_server_header(self):
        inspector = ServerDisclosureInspector()
        is_safe, rationale = inspector.check_server_header("")
        
        assert is_safe is True
    
    def test_server_header_with_version(self):
        inspector = ServerDisclosureInspector()
        is_safe, rationale = inspector.check_server_header("nginx/1.18.0")
        
        assert is_safe is False
        assert "version" in rationale.lower()
    
    def test_server_header_software_disclosure(self):
        inspector = ServerDisclosureInspector()
        is_safe, rationale = inspector.check_server_header("cloudflare")
        
        assert is_safe is False
        assert "software" in rationale.lower()
    
    def test_server_header_minimal(self):
        inspector = ServerDisclosureInspector()
        is_safe, rationale = inspector.check_server_header("Server")
        
        assert is_safe is True


class TestSecurityTxtInspector:
    def test_missing_security_txt(self):
        inspector = SecurityTxtInspector()
        is_valid, rationale = inspector.check_security_txt("")
        
        assert is_valid is False
        assert "not found" in rationale.lower()
    
    def test_security_txt_missing_contact(self):
        inspector = SecurityTxtInspector()
        content = "Expires: 2024-12-31"
        is_valid, rationale = inspector.check_security_txt(content)
        
        assert is_valid is False
        assert "missing" in rationale.lower()
    
    def test_security_txt_valid(self):
        inspector = SecurityTxtInspector()
        content = "Contact: security@example.com\nExpires: 2024-12-31"
        is_valid, rationale = inspector.check_security_txt(content)
        
        assert is_valid is True
