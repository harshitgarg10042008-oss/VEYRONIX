"""Unit tests for mixed content detection."""

import pytest

from configsentinel.website_mixed_content import (
    MixedContentFinding,
    MixedContentDetector,
)


class TestMixedContentDetector:
    def test_no_mixed_content_on_http_page(self):
        detector = MixedContentDetector()
        html = '<script src="http://example.com/script.js"></script>'
        findings = detector.detect_mixed_content(html, "http://example.com")
        
        assert len(findings) == 0
    
    def test_detect_http_script_on_https_page(self):
        detector = MixedContentDetector()
        html = '<script src="http://example.com/script.js"></script>'
        findings = detector.detect_mixed_content(html, "https://example.com")
        
        assert len(findings) == 1
        assert findings[0].resource_type == "script"
        assert findings[0].resource_url == "http://example.com/script.js"
    
    def test_detect_http_style_on_https_page(self):
        detector = MixedContentDetector()
        html = '<link rel="stylesheet" href="http://example.com/style.css">'
        findings = detector.detect_mixed_content(html, "https://example.com")
        
        assert len(findings) == 1
        assert findings[0].resource_type == "style"
    
    def test_detect_http_image_on_https_page(self):
        detector = MixedContentDetector()
        html = '<img src="http://example.com/image.png">'
        findings = detector.detect_mixed_content(html, "https://example.com")
        
        assert len(findings) == 1
        assert findings[0].resource_type == "image"
    
    def test_https_resources_not_flagged(self):
        detector = MixedContentDetector()
        html = '<script src="https://example.com/script.js"></script>'
        findings = detector.detect_mixed_content(html, "https://example.com")
        
        assert len(findings) == 0
    
    def test_data_urls_not_flagged(self):
        detector = MixedContentDetector()
        html = '<img src="data:image/png;base64,abc123">'
        findings = detector.detect_mixed_content(html, "https://example.com")
        
        assert len(findings) == 0
    
    def test_relative_urls_not_flagged(self):
        detector = MixedContentDetector()
        html = '<script src="/script.js"></script>'
        findings = detector.detect_mixed_content(html, "https://example.com")
        
        assert len(findings) == 0
    
    def test_multiple_mixed_content_findings(self):
        detector = MixedContentDetector()
        html = '''
        <script src="http://example.com/script.js"></script>
        <img src="http://example.com/image.png">
        <link rel="stylesheet" href="http://example.com/style.css">
        '''
        findings = detector.detect_mixed_content(html, "https://example.com")
        
        assert len(findings) == 3
    
    def test_get_mixed_content_summary(self):
        detector = MixedContentDetector()
        findings = (
            MixedContentFinding(resource_type="script", resource_url="http://example.com/script.js"),
            MixedContentFinding(resource_type="script", resource_url="http://example.com/other.js"),
            MixedContentFinding(resource_type="image", resource_url="http://example.com/image.png"),
        )
        
        summary = detector.get_mixed_content_summary(findings)
        
        assert summary["total_count"] == 3
        assert summary["by_type"]["script"] == 2
        assert summary["by_type"]["image"] == 1
        assert summary["has_active_mixed_content"] is True
    
    def test_active_mixed_content_detection(self):
        detector = MixedContentDetector()
        findings = (
            MixedContentFinding(resource_type="image", resource_url="http://example.com/image.png"),
        )
        
        summary = detector.get_mixed_content_summary(findings)
        
        # Images are passive mixed content
        assert summary["has_active_mixed_content"] is False
    
    def test_frame_mixed_content_is_active(self):
        detector = MixedContentDetector()
        findings = (
            MixedContentFinding(resource_type="frame", resource_url="http://example.com/frame.html"),
        )
        
        summary = detector.get_mixed_content_summary(findings)
        
        assert summary["has_active_mixed_content"] is True
