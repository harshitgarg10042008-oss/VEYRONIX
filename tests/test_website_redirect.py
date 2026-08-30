"""Unit tests for redirect inspection."""

import pytest

from configsentinel.website_redirect import (
    RedirectPolicy,
    DEFAULT_REDIRECT_POLICY,
    RedirectInspector,
)
from configsentinel.website_models import RedirectEvidence


class TestRedirectPolicy:
    def test_default_policy(self):
        assert DEFAULT_REDIRECT_POLICY.max_redirects == 5
        assert DEFAULT_REDIRECT_POLICY.allow_scheme_downgrade is False
        assert DEFAULT_REDIRECT_POLICY.allow_origin_change is True
    
    def test_invalid_max_redirects(self):
        with pytest.raises(ValueError, match="max_redirects cannot be negative"):
            RedirectPolicy(max_redirects=-1)


class TestRedirectInspector:
    def test_analyze_simple_redirect(self):
        inspector = RedirectInspector()
        evidence = inspector.analyze_redirects(
            initial_url="http://example.com",
            final_url="https://example.com",
            redirect_history=["http://example.com", "https://example.com"],
        )
        
        assert evidence.initial_url == "http://example.com"
        assert evidence.final_url == "https://example.com"
        assert evidence.redirect_count == 2
        assert evidence.scheme_downgrade is False
    
    def test_scheme_downgrade_detection(self):
        inspector = RedirectInspector()
        evidence = inspector.analyze_redirects(
            initial_url="https://example.com",
            final_url="http://example.com",
            redirect_history=["https://example.com", "http://example.com"],
        )
        
        assert evidence.scheme_downgrade is True
    
    def test_origin_change_detection(self):
        inspector = RedirectInspector()
        evidence = inspector.analyze_redirects(
            initial_url="https://example.com",
            final_url="https://other.com",
            redirect_history=["https://example.com", "https://other.com"],
        )
        
        assert evidence.origin_change is True
    
    def test_no_origin_change_same_origin(self):
        inspector = RedirectInspector()
        evidence = inspector.analyze_redirects(
            initial_url="https://example.com",
            final_url="https://example.com/login",
            redirect_history=["https://example.com", "https://example.com/login"],
        )
        
        assert evidence.origin_change is False
    
    def test_redirect_loop_detection(self):
        inspector = RedirectInspector()
        redirect_history = [
            "https://example.com",
            "https://example.com/page1",
            "https://example.com",
        ]
        
        assert inspector.check_redirect_loop(redirect_history) is True
    
    def test_no_redirect_loop(self):
        inspector = RedirectInspector()
        redirect_history = [
            "https://example.com",
            "https://example.com/page1",
            "https://example.com/page2",
        ]
        
        assert inspector.check_redirect_loop(redirect_history) is False
    
    def test_excessive_redirects(self):
        policy = RedirectPolicy(max_redirects=3)
        inspector = RedirectInspector(policy=policy)
        assert inspector.check_excessive_redirects(5) is True
    
    def test_acceptable_redirects(self):
        policy = RedirectPolicy(max_redirects=5)
        inspector = RedirectInspector(policy=policy)
        assert inspector.check_excessive_redirects(3) is False
