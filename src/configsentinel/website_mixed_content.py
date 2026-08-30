"""Mixed content detection for website security scanning.

This module implements detection of mixed content where HTTPS pages reference
HTTP resources (scripts, styles, images, frames).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Tuple
from urllib.parse import urlparse


@dataclass(frozen=True)
class MixedContentFinding:
    """A single mixed content finding."""
    
    resource_type: str  # script, style, image, frame, etc.
    resource_url: str
    line_number: int = 0
    context: str = ""


class MixedContentDetector:
    """Detector for mixed content in HTML responses."""
    
    # Patterns for detecting resource references
    PATTERNS = {
        "script": re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "style": re.compile(r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE),
        "image": re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "frame": re.compile(r'<(iframe|frame)[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "background": re.compile(r'background(?:-image)?:\s*url\(["\']?([^)"\']+)["\']?\)', re.IGNORECASE),
    }
    
    def detect_mixed_content(
        self,
        html_content: str,
        page_url: str,
    ) -> Tuple[MixedContentFinding, ...]:
        """Detect mixed content in HTML.
        
        Args:
            html_content: The HTML content to analyze
            page_url: The URL of the page (to determine if it's HTTPS)
            
        Returns:
            Tuple of MixedContentFinding objects
        """
        findings = []
        
        # Check if page is HTTPS
        page_parsed = urlparse(page_url)
        if page_parsed.scheme != "https":
            # Page is HTTP, so mixed content doesn't apply
            return tuple(findings)
        
        # Scan for each resource type
        for resource_type, pattern in self.PATTERNS.items():
            matches = pattern.finditer(html_content)
            for match in matches:
                resource_url = match.group(1)
                
                # Skip data URLs and relative URLs that don't specify scheme
                if resource_url.startswith("data:") or not resource_url.startswith("http"):
                    continue
                
                # Check if resource is HTTP
                resource_parsed = urlparse(resource_url)
                if resource_parsed.scheme == "http":
                    line_number = html_content[:match.start()].count("\n") + 1
                    context = self._get_context(html_content, match.start())
                    
                    findings.append(
                        MixedContentFinding(
                            resource_type=resource_type,
                            resource_url=resource_url,
                            line_number=line_number,
                            context=context,
                        )
                    )
        
        return tuple(findings)
    
    def _get_context(self, content: str, position: int, context_length: int = 100) -> str:
        """Get context around a match for debugging."""
        start = max(0, position - context_length // 2)
        end = min(len(content), position + context_length // 2)
        return content[start:end]
    
    def get_mixed_content_summary(
        self,
        findings: Tuple[MixedContentFinding, ...],
    ) -> dict:
        """Get a summary of mixed content findings.
        
        Args:
            findings: Tuple of MixedContentFinding objects
            
        Returns:
            Dictionary with summary statistics
        """
        summary = {
            "total_count": len(findings),
            "by_type": {},
            "has_active_mixed_content": False,
        }
        
        for finding in findings:
            resource_type = finding.resource_type
            summary["by_type"][resource_type] = summary["by_type"].get(resource_type, 0) + 1
            
            # Scripts and styles are considered active mixed content
            if resource_type in {"script", "style", "frame"}:
                summary["has_active_mixed_content"] = True
        
        return summary
