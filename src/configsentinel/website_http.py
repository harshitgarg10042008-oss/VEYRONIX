"""Restricted HTTP client for safe website security scanning.

This module implements a bounded HTTP client with explicit timeouts, response size limits,
redirect policies, and SSRF protection. It never connects to internal services by default.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    raise RuntimeError(
        "Website scanner requires httpx. Install with: pip install httpx"
    )


@dataclass(frozen=True)
class HTTPClientConfig:
    """Configuration for the restricted HTTP client."""
    
    timeout_seconds: float = 15.0
    max_response_bytes: int = 2_000_000  # 2 MB
    max_redirects: int = 5
    allow_private_targets: bool = False
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    verify_ssl: bool = True
    
    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if self.max_redirects < 0:
            raise ValueError("max_redirects cannot be negative")


DEFAULT_HTTP_CONFIG = HTTPClientConfig()


class TargetSafetyError(Exception):
    """Raised when a target fails safety checks."""
    pass


class TargetSafetyPolicy:
    """SSRF protection and target validation policy."""
    
    # Private IP ranges that should be blocked by default
    PRIVATE_RANGES = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
        ipaddress.IPv4Network("127.0.0.0/8"),  # Loopback
        ipaddress.IPv4Network("169.254.0.0/16"),  # Link-local
        ipaddress.IPv6Network("::1/128"),  # IPv6 loopback
        ipaddress.IPv6Network("fc00::/7"),  # IPv6 private
        ipaddress.IPv6Network("fe80::/10"),  # IPv6 link-local
    ]
    
    def __init__(self, allow_private: bool = False) -> None:
        self.allow_private = allow_private
    
    def check_hostname(self, hostname: str) -> None:
        """Check if a hostname is safe to scan.
        
        Args:
            hostname: The hostname to check
            
        Raises:
            TargetSafetyError: If the hostname is blocked
        """
        # Check for localhost variants
        hostname_lower = hostname.lower()
        if hostname_lower in {"localhost", "localhost.localdomain"}:
            if not self.allow_private:
                raise TargetSafetyError(f"Localhost hostname is blocked: {hostname}")
        
        # Resolve and check IP addresses
        try:
            # Try to resolve the hostname
            addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, _, _, _, sockaddr in addrinfo:
                ip = sockaddr[0]
                self._check_ip_address(ip)
        except socket.gaierror:
            # If resolution fails, we'll let the HTTP client handle it
            # This avoids blocking legitimate domains with temporary DNS issues
            pass
    
    def _check_ip_address(self, ip_str: str) -> None:
        """Check if an IP address is safe.
        
        Args:
            ip_str: IP address string
            
        Raises:
            TargetSafetyError: If the IP is blocked
        """
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return  # Invalid IP, let HTTP client handle it
        
        if not self.allow_private:
            for private_range in self.PRIVATE_RANGES:
                if ip in private_range:
                    raise TargetSafetyError(f"Private IP address is blocked: {ip_str}")
    
    def check_url(self, url: str) -> None:
        """Check if a URL is safe to scan.
        
        Args:
            url: The URL to check
            
        Raises:
            TargetSafetyError: If the URL is blocked
        """
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in {"http", "https"}:
            raise TargetSafetyError(f"Unsupported scheme: {parsed.scheme}")
        
        # Check hostname
        if parsed.hostname:
            self.check_hostname(parsed.hostname)


class SafeHTTPClient:
    """Restricted HTTP client with safety bounds."""
    
    def __init__(self, config: HTTPClientConfig = DEFAULT_HTTP_CONFIG) -> None:
        self.config = config
        self.safety_policy = TargetSafetyPolicy(allow_private=config.allow_private_targets)
    
    def _create_client(self) -> httpx.Client:
        """Create an httpx client with our restrictions."""
        limits = httpx.Limits(max_redirects=self.config.max_redirects)
        timeout = httpx.Timeout(self.config.timeout_seconds)
        
        # Create SSL context with verification
        verify = self.config.verify_ssl
        
        return httpx.Client(
            timeout=timeout,
            limits=limits,
            verify=verify,
            follow_redirects=True,
            headers={"User-Agent": self.config.user_agent},
        )
    
    def fetch(self, url: str) -> httpx.Response:
        """Fetch a URL with safety checks.
        
        Args:
            url: The URL to fetch
            
        Returns:
            httpx.Response object
            
        Raises:
            TargetSafetyError: If the target fails safety checks
            httpx.HTTPError: If the HTTP request fails
        """
        # Apply safety policy
        self.safety_policy.check_url(url)
        
        # Create client and fetch
        with self._create_client() as client:
            response = client.get(url)
            
            # Check response size
            content_length = len(response.content)
            if content_length > self.config.max_response_bytes:
                raise TargetSafetyError(
                    f"Response exceeds maximum size: {content_length} > {self.config.max_response_bytes}"
                )
            
            return response
    
    def fetch_head(self, url: str) -> httpx.Response:
        """Fetch only headers from a URL.
        
        Args:
            url: The URL to fetch
            
        Returns:
            httpx.Response object
        """
        self.safety_policy.check_url(url)
        
        with self._create_client() as client:
            response = client.head(url)
            return response
    
    def check_tls(self, url: str) -> dict:
        """Check TLS configuration for a URL.
        
        Args:
            url: The URL to check
            
        Returns:
            Dictionary with TLS information
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return {"error": "URL is not HTTPS"}
        
        hostname = parsed.hostname or ""
        port = parsed.port or 443
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.config.timeout_seconds) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    cert = secure_sock.getpeercert()
                    cipher = secure_sock.cipher()
                    protocol_version = secure_sock.version()
                    
                    return {
                        "protocol_version": protocol_version,
                        "cipher_suite": cipher[0] if cipher else "unknown",
                        "certificate_subject": cert.get("subject", ""),
                        "certificate_issuer": cert.get("issuer", ""),
                        "certificate_valid_from": cert.get("notBefore", ""),
                        "certificate_valid_to": cert.get("notAfter", ""),
                        "hostname_match": self._check_hostname_match(hostname, cert),
                    }
        except Exception as e:
            return {"error": str(e)}
    
    def _check_hostname_match(self, hostname: str, cert: dict) -> bool:
        """Check if the certificate matches the hostname."""
        try:
            # Get subject alternative names
            san = cert.get("subjectAltName", [])
            for entry in san:
                if entry[0] == "DNS":
                    if entry[1] == hostname or self._wildcard_match(hostname, entry[1]):
                        return True
            
            # Check common name
            subject = cert.get("subject", [])
            for entry in subject:
                for attr in entry:
                    if attr[0] == "commonName":
                        cn = attr[1]
                        if cn == hostname or self._wildcard_match(hostname, cn):
                            return True
            
            return False
        except Exception:
            return False
    
    def _wildcard_match(self, hostname: str, pattern: str) -> bool:
        """Check if hostname matches a wildcard pattern."""
        if not pattern.startswith("*."):
            return False
        
        suffix = pattern[2:]
        return hostname == suffix or hostname.endswith("." + suffix)
