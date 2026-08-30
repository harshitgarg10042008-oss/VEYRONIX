"""Redirect inspection and validation for website security scanning.

This module implements safe redirect chain analysis with scheme downgrade detection,
origin change detection, and loop prevention.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from .website_models import RedirectEvidence


@dataclass(frozen=True)
class RedirectPolicy:
    """Policy for safe redirect handling."""
    
    max_redirects: int = 5
    allow_scheme_downgrade: bool = False
    allow_origin_change: bool = True
    
    def __post_init__(self) -> None:
        if self.max_redirects < 0:
            raise ValueError("max_redirects cannot be negative")


DEFAULT_REDIRECT_POLICY = RedirectPolicy()


class RedirectInspector:
    """Inspector for analyzing redirect chains."""
    
    def __init__(self, policy: RedirectPolicy = DEFAULT_REDIRECT_POLICY) -> None:
        self.policy = policy
    
    def analyze_redirects(
        self,
        initial_url: str,
        final_url: str,
        redirect_history: list[str],
    ) -> RedirectEvidence:
        """Analyze a redirect chain for security issues.
        
        Args:
            initial_url: The starting URL
            final_url: The final URL after redirects
            redirect_history: List of URLs in the redirect chain
            
        Returns:
            RedirectEvidence with analysis results
        """
        redirect_count = len(redirect_history)
        
        # Check for scheme downgrade
        scheme_downgrade = self._check_scheme_downgrade(initial_url, final_url)
        
        # Check for origin change
        origin_change = self._check_origin_change(initial_url, final_url)
        
        # Build redirect chain
        redirect_chain = tuple(redirect_history)
        
        return RedirectEvidence(
            initial_url=initial_url,
            final_url=final_url,
            redirect_count=redirect_count,
            redirect_chain=redirect_chain,
            scheme_downgrade=scheme_downgrade,
            origin_change=origin_change,
        )
    
    def _check_scheme_downgrade(self, initial_url: str, final_url: str) -> bool:
        """Check if there was a scheme downgrade (HTTPS to HTTP)."""
        initial_parsed = urlparse(initial_url)
        final_parsed = urlparse(final_url)
        
        return initial_parsed.scheme == "https" and final_parsed.scheme == "http"
    
    def _check_origin_change(self, initial_url: str, final_url: str) -> bool:
        """Check if the origin (scheme + host + port) changed."""
        initial_parsed = urlparse(initial_url)
        final_parsed = urlparse(final_url)
        
        initial_origin = f"{initial_parsed.scheme}://{initial_parsed.netloc}"
        final_origin = f"{final_parsed.scheme}://{final_parsed.netloc}"
        
        return initial_origin != final_origin
    
    def check_redirect_loop(self, redirect_history: list[str]) -> bool:
        """Check if there's a redirect loop.
        
        Args:
            redirect_history: List of URLs in the redirect chain
            
        Returns:
            True if a loop is detected
        """
        seen = set()
        for url in redirect_history:
            if url in seen:
                return True
            seen.add(url)
        return False
    
    def check_excessive_redirects(self, redirect_count: int) -> bool:
        """Check if there are too many redirects.
        
        Args:
            redirect_count: Number of redirects
            
        Returns:
            True if redirect count exceeds policy limit
        """
        return redirect_count > self.policy.max_redirects
