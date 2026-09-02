"""Deterministic website security rules and rule engine.

This module defines the rule pack for website security posture assessment
and the engine that evaluates observations against rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Any
from urllib.parse import urlparse

from .website_models import (
    WebsiteRule,
    WebsiteFinding,
    WebsiteFindingStatus,
    WebsiteSeverity,
    WebsiteEvidence,
    TLSEvidence,
    HeaderEvidence,
    RedirectEvidence,
)
from .website_scoring import calculate_score, classify_posture_from_findings


@dataclass(frozen=True)
class WebsiteRuleDefinition:
    """A website security rule with its check function."""
    
    rule: WebsiteRule
    check: Callable[[dict[str, Any]], tuple[WebsiteFindingStatus, str, WebsiteEvidence]]
    remediation: str


def _check_https(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    """Check if the site uses HTTPS."""
    url = observation.get("url", "")
    parsed = urlparse(url)
    
    if parsed.scheme == "https":
        return (
            WebsiteFindingStatus.PASS,
            "Website uses HTTPS",
            WebsiteEvidence(
                check_type="https",
                observed_value="HTTPS",
                expected_value="HTTPS"
            )
        )
    return (
        WebsiteFindingStatus.FAIL,
        "Website does not use HTTPS",
        WebsiteEvidence(
            check_type="https",
            observed_value="HTTP",
            expected_value="HTTPS"
        )
    )


def _check_hsts(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    """Check for HSTS header."""
    headers = observation.get("headers", {})
    hsts_value = headers.get("Strict-Transport-Security", "")
    
    if not hsts_value:
        return (
            WebsiteFindingStatus.WARN,
            "HSTS header is missing; transport security is not fully hardened",
            WebsiteEvidence(
                check_type="hsts",
                observed_value="missing",
                expected_value="present"
            )
        )
    
    # Check max-age
    if "max-age=" in hsts_value:
        try:
            max_age = int(hsts_value.split("max-age=")[1].split(";")[0].strip())
            if max_age >= 31536000:  # 1 year
                return (
                    WebsiteFindingStatus.PASS,
                    "HSTS is properly configured",
                    WebsiteEvidence(
                        check_type="hsts",
                        observed_value=hsts_value[:50],
                        expected_value="max-age >= 31536000"
                    )
                )
        except (ValueError, IndexError):
            pass
    
    return (
        WebsiteFindingStatus.WARN,
        "HSTS present but may not be optimally configured",
        WebsiteEvidence(
            check_type="hsts",
            observed_value=hsts_value[:50],
            expected_value="max-age >= 31536000; includeSubDomains"
        )
    )


def _check_csp(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    """Check for Content-Security-Policy header."""
    headers = observation.get("headers", {})
    csp_value = headers.get("Content-Security-Policy", "")
    
    if not csp_value:
        return (
            WebsiteFindingStatus.WARN,
            "Content-Security-Policy header is missing; browser policy hardening is recommended",
            WebsiteEvidence(
                check_type="csp",
                observed_value="missing",
                expected_value="present"
            )
        )
    
    # Check for obviously permissive policies
    if "default-src *" in csp_value or "default-src 'unsafe-inline'" in csp_value:
        return (
            WebsiteFindingStatus.WARN,
            "CSP is present but may be too permissive",
            WebsiteEvidence(
                check_type="csp",
                observed_value=csp_value[:50],
                expected_value="restrictive policy"
            )
        )
    
    return (
        WebsiteFindingStatus.PASS,
        "Content-Security-Policy is present",
        WebsiteEvidence(
            check_type="csp",
            observed_value=csp_value[:50],
            expected_value="present"
        )
    )


def _check_clickjacking(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    """Check for clickjacking protection."""
    headers = observation.get("headers", {})
    x_frame = headers.get("X-Frame-Options", "")
    csp = headers.get("Content-Security-Policy", "")
    
    # Check CSP frame-ancestors
    if "frame-ancestors" in csp:
        return (
            WebsiteFindingStatus.PASS,
            "Clickjacking protection via CSP frame-ancestors",
            WebsiteEvidence(
                check_type="clickjacking",
                observed_value="CSP frame-ancestors",
                expected_value="present"
            )
        )
    
    # Check X-Frame-Options
    if x_frame in {"DENY", "SAMEORIGIN"}:
        return (
            WebsiteFindingStatus.PASS,
            "Clickjacking protection via X-Frame-Options",
            WebsiteEvidence(
                check_type="clickjacking",
                observed_value=x_frame,
                expected_value="DENY or SAMEORIGIN"
            )
        )
    
    return (
            WebsiteFindingStatus.WARN,
            "No clickjacking protection detected; defense-in-depth hardening is recommended",
        WebsiteEvidence(
            check_type="clickjacking",
            observed_value="missing",
            expected_value="X-Frame-Options or CSP frame-ancestors"
        )
    )


def _check_mime_sniffing(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    """Check for MIME sniffing protection."""
    headers = observation.get("headers", {})
    x_content_type = headers.get("X-Content-Type-Options", "")
    
    if x_content_type == "nosniff":
        return (
            WebsiteFindingStatus.PASS,
            "MIME sniffing protection is enabled",
            WebsiteEvidence(
                check_type="mime_sniffing",
                observed_value="nosniff",
                expected_value="nosniff"
            )
        )
    
    return (
        WebsiteFindingStatus.WARN,
        "X-Content-Type-Options header is missing",
        WebsiteEvidence(
            check_type="mime_sniffing",
            observed_value="missing",
            expected_value="nosniff"
        )
    )


def _check_tls_version(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    """Check TLS protocol version."""
    tls_evidence = observation.get("tls_evidence")
    
    if not tls_evidence:
        return (
            WebsiteFindingStatus.UNKNOWN,
            "TLS evidence not available",
            WebsiteEvidence(
                check_type="tls_version",
                observed_value="unknown",
                expected_value="TLS 1.2 or 1.3"
            )
        )
    
    protocol = tls_evidence.get("protocol_version", "")
    
    if protocol in {"TLSv1.3", "TLSv1.2"}:
        return (
            WebsiteFindingStatus.PASS,
            f"Using secure TLS version: {protocol}",
            WebsiteEvidence(
                check_type="tls_version",
                observed_value=protocol,
                expected_value="TLS 1.2 or 1.3"
            )
        )
    
    if protocol in {"TLSv1.0", "TLSv1.1"}:
        return (
            WebsiteFindingStatus.FAIL,
            f"Using deprecated TLS version: {protocol}",
            WebsiteEvidence(
                check_type="tls_version",
                observed_value=protocol,
                expected_value="TLS 1.2 or 1.3"
            )
        )
    
    return (
        WebsiteFindingStatus.UNKNOWN,
        f"Unknown TLS version: {protocol}",
        WebsiteEvidence(
            check_type="tls_version",
            observed_value=protocol,
            expected_value="TLS 1.2 or 1.3"
        )
    )


def _check_redirect_safety(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    """Check redirect chain safety."""
    redirect_evidence = observation.get("redirect_evidence")
    
    if not redirect_evidence:
        return (
            WebsiteFindingStatus.UNKNOWN,
            "Redirect evidence not available",
            WebsiteEvidence(
                check_type="redirect",
                observed_value="unknown",
                expected_value="safe redirect chain"
            )
        )
    
    if redirect_evidence.get("scheme_downgrade"):
        return (
            WebsiteFindingStatus.FAIL,
            "Redirect chain includes HTTPS to HTTP downgrade",
            WebsiteEvidence(
                check_type="redirect",
                observed_value="scheme downgrade detected",
                expected_value="no scheme downgrade"
            )
        )
    
    if redirect_evidence.get("redirect_count", 0) > 5:
        return (
            WebsiteFindingStatus.WARN,
            "Excessive redirects in chain",
            WebsiteEvidence(
                check_type="redirect",
                observed_value=str(redirect_evidence["redirect_count"]),
                expected_value="<= 5 redirects"
            )
        )
    
    return (
        WebsiteFindingStatus.PASS,
        "Redirect chain appears safe",
        WebsiteEvidence(
            check_type="redirect",
            observed_value="safe",
            expected_value="safe redirect chain"
        )
    )


def _check_referrer_policy(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    headers = observation.get("headers", {})
    ref_policy = headers.get("Referrer-Policy", "")
    
    if not ref_policy:
        return (
            WebsiteFindingStatus.WARN,
            "Referrer-Policy header is missing",
            WebsiteEvidence(
                check_type="referrer_policy",
                observed_value="missing",
                expected_value="strict-origin-when-cross-origin or similar"
            )
        )
    
    if "unsafe-url" in ref_policy:
        return (
            WebsiteFindingStatus.FAIL,
            "Referrer-Policy is unsafe",
            WebsiteEvidence(
                check_type="referrer_policy",
                observed_value=ref_policy[:50],
                expected_value="restrictive policy"
            )
        )
        
    return (
        WebsiteFindingStatus.PASS,
        "Referrer-Policy is present",
        WebsiteEvidence(
            check_type="referrer_policy",
            observed_value=ref_policy[:50],
            expected_value="present"
        )
    )


def _check_permissions_policy(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    headers = observation.get("headers", {})
    perm_policy = headers.get("Permissions-Policy", "")
    
    if not perm_policy:
        return (
            WebsiteFindingStatus.WARN,
            "Permissions-Policy header is missing",
            WebsiteEvidence(
                check_type="permissions_policy",
                observed_value="missing",
                expected_value="present"
            )
        )
        
    return (
        WebsiteFindingStatus.PASS,
        "Permissions-Policy is present",
        WebsiteEvidence(
            check_type="permissions_policy",
            observed_value=perm_policy[:50],
            expected_value="present"
        )
    )


def _check_server_disclosure(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    headers = observation.get("headers", {})
    server_header = headers.get("Server", "")
    x_powered_by = headers.get("X-Powered-By", "")
    
    issues = []
    if server_header and any(char.isdigit() for char in server_header):
        issues.append(f"Server: {server_header[:20]}")
    if x_powered_by:
        issues.append("X-Powered-By header present")
        
    if issues:
        return (
            WebsiteFindingStatus.WARN,
            "Server version or technology disclosed",
            WebsiteEvidence(
                check_type="server_disclosure",
                observed_value=", ".join(issues),
                expected_value="minimal disclosure"
            )
        )
        
    return (
        WebsiteFindingStatus.PASS,
        "No unnecessary server disclosure detected",
        WebsiteEvidence(
            check_type="server_disclosure",
            observed_value="clean headers",
            expected_value="minimal disclosure"
        )
    )


def _check_cookie_flags(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    set_cookies = observation.get("set_cookies", [])
    
    if not set_cookies:
        return (
            WebsiteFindingStatus.NOT_APPLICABLE,
            "No cookies set in response",
            WebsiteEvidence(
                check_type="cookies",
                observed_value="no cookies",
                expected_value="N/A"
            )
        )
        
    issues = []
    for cookie in set_cookies:
        # Parse attributes as semicolon-delimited tokens. Substring matching
        # incorrectly treats values such as `insecure` as the Secure flag.
        attributes = {part.strip().split("=", 1)[0].lower() for part in cookie.split(";")}
        if "secure" not in attributes:
            issues.append("missing Secure flag")
        if "httponly" not in attributes:
            issues.append("missing HttpOnly flag")
            
    if issues:
        return (
            WebsiteFindingStatus.WARN,
            "Cookies are missing recommended security attributes",
            WebsiteEvidence(
                check_type="cookies",
                observed_value=", ".join(list(set(issues))),
                expected_value="Secure and HttpOnly"
            )
        )
        
    return (
        WebsiteFindingStatus.PASS,
        "Cookies have proper security attributes",
        WebsiteEvidence(
            check_type="cookies",
            observed_value=f"{len(set_cookies)} cookies secure",
            expected_value="Secure and HttpOnly"
        )
    )


def _check_mixed_content(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    mixed = observation.get("mixed_content")
    
    if not mixed:
        return (
            WebsiteFindingStatus.UNKNOWN,
            "Mixed content analysis unavailable",
            WebsiteEvidence(
                check_type="mixed_content",
                observed_value="unknown",
                expected_value="no mixed content"
            )
        )
        
    if mixed.get("has_active_mixed_content"):
        return (
            WebsiteFindingStatus.FAIL,
            "Active mixed content (scripts/styles) detected",
            WebsiteEvidence(
                check_type="mixed_content",
                observed_value="active mixed content",
                expected_value="no mixed content"
            )
        )
        
    if mixed.get("findings_count", 0) > 0:
        return (
            WebsiteFindingStatus.WARN,
            "Passive mixed content (images/media) detected",
            WebsiteEvidence(
                check_type="mixed_content",
                observed_value=f"{mixed['findings_count']} resources",
                expected_value="no mixed content"
            )
        )
        
    return (
        WebsiteFindingStatus.PASS,
        "No mixed content detected",
        WebsiteEvidence(
            check_type="mixed_content",
            observed_value="0 resources",
            expected_value="no mixed content"
        )
    )


def _check_security_txt(observation: dict[str, Any]) -> tuple[WebsiteFindingStatus, str, WebsiteEvidence]:
    sec_txt = observation.get("security_txt")
    
    if sec_txt is None:
        return (
            WebsiteFindingStatus.WARN,
            "security.txt not found",
            WebsiteEvidence(
                check_type="security_txt",
                observed_value="missing",
                expected_value="present"
            )
        )
        
    if "Contact:" not in sec_txt:
        return (
            WebsiteFindingStatus.FAIL,
            "security.txt missing required Contact directive",
            WebsiteEvidence(
                check_type="security_txt",
                observed_value="missing Contact",
                expected_value="Contact: directive"
            )
        )
        
    return (
        WebsiteFindingStatus.PASS,
        "security.txt is present",
        WebsiteEvidence(
            check_type="security_txt",
            observed_value="valid file",
            expected_value="present"
        )
    )


WEBSITE_RULE_PACK_VERSION = "web-posture.v1"

WEBSITE_RULE_PACK: tuple[WebsiteRuleDefinition, ...] = (
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-HTTPS-001",
            "HTTPS Required",
            "Website must use HTTPS for all connections",
            WebsiteSeverity.CRITICAL,
            "tls"
        ),
        _check_https,
        "Configure HTTPS with a valid TLS certificate",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-HSTS-001",
            "HSTS Header",
            "HTTP Strict Transport Security should be enabled",
            WebsiteSeverity.HIGH,
            "headers"
        ),
        _check_hsts,
        "Enable HSTS with max-age >= 31536000 and includeSubDomains",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-CSP-001",
            "Content Security Policy",
            "Content-Security-Policy header should be present",
            WebsiteSeverity.HIGH,
            "headers"
        ),
        _check_csp,
        "Implement a restrictive CSP policy",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-FRAME-001",
            "Clickjacking Protection",
            "Protection against clickjacking should be enabled",
            WebsiteSeverity.MEDIUM,
            "headers"
        ),
        _check_clickjacking,
        "Use X-Frame-Options or CSP frame-ancestors",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-MIME-001",
            "MIME Sniffing Protection",
            "X-Content-Type-Options should be set to nosniff",
            WebsiteSeverity.LOW,
            "headers"
        ),
        _check_mime_sniffing,
        "Set X-Content-Type-Options: nosniff",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-TLS-001",
            "TLS Version",
            "Modern TLS version should be used",
            WebsiteSeverity.HIGH,
            "tls"
        ),
        _check_tls_version,
        "Configure server to use TLS 1.2 or 1.3",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-REDIRECT-001",
            "Redirect Safety",
            "Redirect chain should be safe",
            WebsiteSeverity.MEDIUM,
            "redirects"
        ),
        _check_redirect_safety,
        "Ensure redirects don't downgrade schemes or loop excessively",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-REFERRER-001",
            "Referrer Policy",
            "Referrer-Policy header should be restrictive",
            WebsiteSeverity.LOW,
            "headers"
        ),
        _check_referrer_policy,
        "Configure Referrer-Policy to strict-origin-when-cross-origin",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-PERMISSIONS-001",
            "Permissions Policy",
            "Permissions-Policy header should be present",
            WebsiteSeverity.INFO,
            "headers"
        ),
        _check_permissions_policy,
        "Configure Permissions-Policy to restrict browser features",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-SERVER-001",
            "Server Disclosure",
            "Server versions should not be disclosed",
            WebsiteSeverity.LOW,
            "headers"
        ),
        _check_server_disclosure,
        "Remove version numbers from Server header and disable X-Powered-By",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-COOKIE-001",
            "Cookie Security",
            "Cookies must have Secure and HttpOnly flags",
            WebsiteSeverity.MEDIUM,
            "cookies"
        ),
        _check_cookie_flags,
        "Add Secure and HttpOnly attributes to all cookies",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-MIXED-001",
            "Mixed Content",
            "HTTPS pages should not load HTTP resources",
            WebsiteSeverity.HIGH,
            "html"
        ),
        _check_mixed_content,
        "Update all resource links to use HTTPS",
    ),
    WebsiteRuleDefinition(
        WebsiteRule(
            "WEB-SECTXT-001",
            "Security Contact",
            "/.well-known/security.txt should be present",
            WebsiteSeverity.INFO,
            "metadata"
        ),
        _check_security_txt,
        "Publish a valid security.txt file with Contact information",
    ),
)


class WebsiteRuleEngine:
    """Engine for evaluating website security rules."""
    
    def __init__(self, rule_pack: tuple[WebsiteRuleDefinition, ...] = WEBSITE_RULE_PACK) -> None:
        self.rule_pack = rule_pack
    
    def evaluate(
        self,
        observation: dict[str, Any],
        scan_id: str,
        target_hash: str,
    ) -> tuple[WebsiteFinding, ...]:
        """Evaluate all rules against an observation.
        
        Args:
            observation: Dictionary of observed data
            scan_id: The scan ID
            target_hash: Hash of the target URL
            
        Returns:
            Tuple of WebsiteFinding objects
        """
        findings = []
        
        for rule_definition in self.rule_pack:
            status, rationale, evidence = rule_definition.check(observation)
            
            finding = WebsiteFinding(
                finding_id=f"{scan_id}:{rule_definition.rule.rule_id}",
                scan_id=scan_id,
                rule_id=rule_definition.rule.rule_id,
                title=rule_definition.rule.title,
                status=status,
                severity=rule_definition.rule.severity,
                evidence=evidence,
                rationale=rationale,
                remediation=rule_definition.remediation,
                observed_at=datetime.utcnow(),
                rule_version=rule_definition.rule.version,
                target_hash=target_hash,
                limitations="This check only evaluates observable HTTP/TLS signals",
            )
            
            findings.append(finding)
        
        return tuple(findings)
    
    def compute_scan_result(
        self,
        findings: tuple[WebsiteFinding, ...],
        scan_id: str,
        target_origin: str,
        final_url: str,
    ) -> dict[str, Any]:
        """Compute the complete scan result with score and classification.
        
        Args:
            findings: Tuple of WebsiteFinding objects
            scan_id: The scan ID
            target_origin: The target origin
            final_url: The final URL after redirects
            
        Returns:
            Dictionary with complete scan result
        """
        score = calculate_score(findings)
        classification = classify_posture_from_findings(findings, score)
        
        return {
            "scan_id": scan_id,
            "target_origin": target_origin,
            "final_url": final_url,
            "score": score,
            "classification": classification.value,
            "findings_count": len(findings),
            "passed_count": sum(f.status == WebsiteFindingStatus.PASS for f in findings),
            "failed_count": sum(f.status == WebsiteFindingStatus.FAIL for f in findings),
            "warning_count": sum(f.status == WebsiteFindingStatus.WARN for f in findings),
            "unknown_count": sum(f.status == WebsiteFindingStatus.UNKNOWN for f in findings),
            "rule_pack_version": WEBSITE_RULE_PACK_VERSION,
        }
