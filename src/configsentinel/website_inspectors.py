"""Header and cookie inspectors for website security scanning.

This module implements deterministic inspection of security headers, cookies,
and other HTTP response signals.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs

from .website_models import HeaderEvidence, CookieEvidence


class HeaderInspector:
    """Inspector for security headers."""
    
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME sniffing protection",
        "Referrer-Policy": "Referrer control",
        "Permissions-Policy": "Browser permissions",
        "X-XSS-Protection": "XSS protection",
    }
    
    def inspect_header(
        self,
        header_name: str,
        header_value: str,
    ) -> HeaderEvidence:
        """Inspect a single security header.
        
        Args:
            header_name: The header name
            header_value: The header value
            
        Returns:
            HeaderEvidence with inspection results
        """
        if not header_value:
            return HeaderEvidence(
                header_name=header_name,
                header_value="",
                present=False,
            )
        
        parsed_directives = self._parse_header_directives(header_name, header_value)
        
        return HeaderEvidence(
            header_name=header_name,
            header_value=header_value,
            parsed_directives=parsed_directives,
            present=True,
        )
    
    def _parse_header_directives(self, header_name: str, header_value: str) -> dict[str, str]:
        """Parse header directives based on header type."""
        if header_name == "Content-Security-Policy":
            return self._parse_csp(header_value)
        elif header_name == "Strict-Transport-Security":
            return self._parse_hsts(header_value)
        elif header_name == "X-Frame-Options":
            return self._parse_x_frame_options(header_value)
        elif header_name == "Referrer-Policy":
            return self._parse_referrer_policy(header_value)
        else:
            return {"raw": header_value}
    
    def _parse_csp(self, csp_value: str) -> dict[str, str]:
        """Parse Content-Security-Policy directives."""
        directives = {}
        for part in csp_value.split(";"):
            part = part.strip()
            if not part:
                continue
            if " " in part:
                key, value = part.split(" ", 1)
                directives[key] = value
            else:
                directives[part] = ""
        return directives
    
    def _parse_hsts(self, hsts_value: str) -> dict[str, str]:
        """Parse Strict-Transport-Security directives."""
        directives = {}
        for part in hsts_value.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                key, value = part.split("=", 1)
                directives[key] = value
            else:
                directives[part] = ""
        return directives
    
    def _parse_x_frame_options(self, value: str) -> dict[str, str]:
        """Parse X-Frame-Options header."""
        return {"directive": value.strip()}
    
    def _parse_referrer_policy(self, value: str) -> dict[str, str]:
        """Parse Referrer-Policy header."""
        return {"policy": value.strip()}
    
    def check_hsts_strength(self, hsts_value: str) -> tuple[bool, str]:
        """Check if HSTS header is properly configured.
        
        Args:
            hsts_value: The HSTS header value
            
        Returns:
            Tuple of (is_strong, rationale)
        """
        if not hsts_value:
            return False, "HSTS header is missing"
        
        directives = self._parse_hsts(hsts_value)
        max_age = directives.get("max-age", "0")
        
        try:
            max_age_int = int(max_age)
            if max_age_int < 31536000:  # Less than 1 year
                return False, f"HSTS max-age is too short: {max_age_int} seconds"
        except ValueError:
            return False, "Invalid HSTS max-age value"
        
        if "includeSubDomains" not in directives:
            return False, "HSTS missing includeSubDomains directive"
        
        if "preload" not in directives:
            return False, "HSTS missing preload directive (optional but recommended)"
        
        return True, "HSTS is properly configured"
    
    def check_csp_strength(self, csp_value: str) -> tuple[bool, str]:
        """Check if CSP header is properly configured.
        
        Args:
            csp_value: The CSP header value
            
        Returns:
            Tuple of (is_strong, rationale)
        """
        if not csp_value:
            return False, "CSP header is missing"
        
        directives = self._parse_csp(csp_value)
        
        if "default-src" not in directives:
            return False, "CSP missing default-src directive"
        
        default_src = directives["default-src"].lower()
        
        if default_src == "*" or default_src == "'unsafe-inline'":
            return False, "CSP default-src is too permissive"
        
        return True, "CSP is present and not obviously permissive"


class CookieInspector:
    """Inspector for cookie security attributes."""
    
    def inspect_cookie(
        self,
        cookie_name: str,
        cookie_value: str,
        cookie_attributes: dict[str, str],
    ) -> CookieEvidence:
        """Inspect a cookie's security attributes.
        
        Args:
            cookie_name: The cookie name
            cookie_value: The cookie value (not stored for privacy)
            cookie_attributes: Dictionary of cookie attributes
            
        Returns:
            CookieEvidence with inspection results
        """
        secure = cookie_attributes.get("secure", "").lower() == "true"
        http_only = cookie_attributes.get("httponly", "").lower() == "true"
        same_site = cookie_attributes.get("samesite", "None").capitalize()
        domain = cookie_attributes.get("domain", "")
        path = cookie_attributes.get("path", "")
        
        return CookieEvidence(
            cookie_name=cookie_name,
            domain=domain,
            secure=secure,
            http_only=http_only,
            same_site=same_site,
            path=path,
        )
    
    def check_cookie_security(self, cookie: CookieEvidence) -> tuple[bool, str]:
        """Check if a cookie has proper security attributes.
        
        Args:
            cookie: The cookie evidence
            
        Returns:
            Tuple of (is_secure, rationale)
        """
        issues = []
        
        if not cookie.secure:
            issues.append("missing Secure flag")
        
        if not cookie.http_only:
            issues.append("missing HttpOnly flag")
        
        if cookie.same_site not in {"Strict", "Lax"}:
            issues.append(f"SameSite is {cookie.same_site} (should be Strict or Lax)")
        
        if issues:
            return False, f"Cookie security issues: {', '.join(issues)}"
        
        return True, "Cookie has proper security attributes"


class ServerDisclosureInspector:
    """Inspector for server information disclosure."""
    
    def check_server_header(self, server_header: str) -> tuple[bool, str]:
        """Check if server header discloses too much information.
        
        Args:
            server_header: The Server header value
            
        Returns:
            Tuple of (is_safe, rationale)
        """
        if not server_header:
            return True, "No server header present"
        
        # Check for version numbers
        if any(char.isdigit() for char in server_header):
            return False, f"Server header may disclose version: {server_header[:50]}"
        
        # Check for specific server software
        common_servers = ["nginx", "apache", "iis", "cloudflare"]
        server_lower = server_header.lower()
        for server in common_servers:
            if server in server_lower:
                return False, f"Server header discloses software: {server}"
        
        return True, "Server header appears minimal"


class SecurityTxtInspector:
    """Inspector for security.txt and security contact information."""
    
    def check_security_txt(self, content: str) -> tuple[bool, str]:
        """Check if security.txt is present and parseable.
        
        Args:
            content: The content of security.txt
            
        Returns:
            Tuple of (is_valid, rationale)
        """
        if not content:
            return False, "security.txt not found"
        
        # Check for required fields
        required_fields = ["Contact:", "Expires:"]
        missing_fields = []
        
        for field in required_fields:
            if field not in content:
                missing_fields.append(field)
        
        if missing_fields:
            return False, f"security.txt missing required fields: {', '.join(missing_fields)}"
        
        return True, "security.txt is present with required fields"
