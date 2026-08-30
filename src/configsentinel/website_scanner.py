"""Main website security scanner orchestrator.

This module coordinates the HTTP client, inspectors, and rule engine to perform
complete website security posture scans.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from .website_http import SafeHTTPClient, HTTPClientConfig, TargetSafetyError
from .website_redirect import RedirectInspector, RedirectPolicy
from .website_tls import TLSInspector
from .website_inspectors import HeaderInspector, CookieInspector, ServerDisclosureInspector, SecurityTxtInspector
from .website_mixed_content import MixedContentDetector
from .website_rules import WebsiteRuleEngine, WEBSITE_RULE_PACK_VERSION
from .website_models import (
    WebsiteScanRequest,
    WebsiteScanResult,
    WebsiteFinding,
    WebsiteFindingStatus,
    WebsiteSeverity,
    PostureClassification,
    compute_target_hash,
)
from .website_scoring import calculate_score, classify_posture_from_findings


class WebsiteScanner:
    """Main scanner for website security posture assessment."""
    
    def __init__(
        self,
        http_config: Optional[HTTPClientConfig] = None,
        redirect_policy: Optional[RedirectPolicy] = None,
    ) -> None:
        self.http_client = SafeHTTPClient(http_config or HTTPClientConfig())
        self.redirect_inspector = RedirectInspector(redirect_policy or RedirectPolicy())
        self.tls_inspector = TLSInspector(timeout_seconds=http_config.timeout_seconds if http_config else 15.0)
        self.header_inspector = HeaderInspector()
        self.cookie_inspector = CookieInspector()
        self.server_inspector = ServerDisclosureInspector()
        self.security_txt_inspector = SecurityTxtInspector()
        self.mixed_content_detector = MixedContentDetector()
        self.rule_engine = WebsiteRuleEngine()
    
    def scan(self, request: WebsiteScanRequest) -> WebsiteScanResult:
        """Perform a complete website security scan.
        
        Args:
            request: The scan request
            
        Returns:
            WebsiteScanResult with complete findings
        """
        scan_id = str(uuid.uuid4())
        target_hash = compute_target_hash(request.url)
        
        try:
            # Fetch the target URL
            response = self.http_client.fetch(request.url)
            
            # Collect observations
            observation = self._collect_observations(request.url, response)
            
            # Evaluate rules
            findings = self.rule_engine.evaluate(observation, scan_id, target_hash)
            
            # Calculate score and classification
            score = calculate_score(findings)
            classification = classify_posture_from_findings(findings, score)
            
            # Build result
            return WebsiteScanResult(
                scan_id=scan_id,
                target_origin=request.target_origin,
                final_url=str(response.url),
                posture_classification=classification,
                score=score,
                findings=findings,
                rule_pack_version=WEBSITE_RULE_PACK_VERSION,
                limitations="This scan only evaluates observable HTTP/TLS signals and does not prove absence of vulnerabilities",
            )
            
        except TargetSafetyError as e:
            # Return a result with a single critical finding about the blocked target
            from .website_models import WebsiteEvidence
            finding = WebsiteFinding(
                finding_id=f"{scan_id}:BLOCKED-TARGET",
                scan_id=scan_id,
                rule_id="BLOCKED-TARGET",
                title="Target blocked by safety policy",
                status=WebsiteFindingStatus.FAIL,
                severity=WebsiteSeverity.CRITICAL,
                evidence=WebsiteEvidence(
                    check_type="target_safety",
                    observed_value="blocked",
                    expected_value="allowed"
                ),
                rationale=str(e),
                remediation="Use an authorized public target or enable local-lab mode",
                observed_at=datetime.utcnow(),
                rule_version=WEBSITE_RULE_PACK_VERSION,
                target_hash=target_hash,
                limitations="Target was blocked by SSRF protection policy",
            )
            
            return WebsiteScanResult(
                scan_id=scan_id,
                target_origin=request.target_origin,
                final_url=request.url,
                posture_classification=PostureClassification.HIGH_RISK,
                score=0,
                findings=(finding,),
                rule_pack_version=WEBSITE_RULE_PACK_VERSION,
                limitations="Target was blocked by safety policy",
            )
        except Exception as e:
            # Return a result with an error finding
            from .website_models import WebsiteEvidence
            finding = WebsiteFinding(
                finding_id=f"{scan_id}:SCAN-ERROR",
                scan_id=scan_id,
                rule_id="SCAN-ERROR",
                title="Scan failed with error",
                status=WebsiteFindingStatus.UNKNOWN,
                severity=WebsiteSeverity.INFO,
                evidence=WebsiteEvidence(
                    check_type="scan_error",
                    observed_value=str(e),
                    expected_value="successful scan"
                ),
                rationale=f"Scan failed: {str(e)}",
                remediation="Check target availability and network connectivity",
                observed_at=datetime.utcnow(),
                rule_version=WEBSITE_RULE_PACK_VERSION,
                target_hash=target_hash,
                limitations="Scan encountered an error",
            )
            
            return WebsiteScanResult(
                scan_id=scan_id,
                target_origin=request.target_origin,
                final_url=request.url,
                posture_classification=PostureClassification.NEEDS_REVIEW,
                score=50,
                findings=(finding,),
                rule_pack_version=WEBSITE_RULE_PACK_VERSION,
                limitations="Scan encountered an error",
            )
    
    def _collect_observations(self, url: str, response) -> dict:
        """Collect all observations from the HTTP response.
        
        Args:
            url: The requested URL
            response: The HTTP response object
            
        Returns:
            Dictionary of observations
        """
        observation = {
            "url": url,
            "final_url": str(response.url),
            "status_code": response.status_code,
            "headers": dict(response.headers),
        }
        
        # Add TLS evidence if HTTPS
        if str(response.url).startswith("https://"):
            tls_result = self.tls_inspector.inspect_tls(str(response.url))
            observation["tls_evidence"] = {
                "protocol_version": tls_result.protocol_version,
                "cipher_suite": tls_result.cipher_suite,
                "hostname_match": tls_result.hostname_match,
                "certificate_errors": tls_result.certificate_errors,
            }
        
        # Add redirect evidence
        redirect_history = getattr(response, "history", [])
        if redirect_history:
            redirect_chain = [str(r.url) for r in redirect_history]
            redirect_evidence = self.redirect_inspector.analyze_redirects(
                url,
                str(response.url),
                redirect_chain
            )
            observation["redirect_evidence"] = {
                "redirect_count": redirect_evidence.redirect_count,
                "scheme_downgrade": redirect_evidence.scheme_downgrade,
                "origin_change": redirect_evidence.origin_change,
            }
        
        # Extract raw set-cookie headers (dict(headers) loses duplicates)
        raw_set_cookies = []
        if hasattr(response, "headers") and hasattr(response.headers, "get_list"):
            raw_set_cookies = response.headers.get_list("set-cookie")
        elif "set-cookie" in response.headers:
            # Fallback if get_list is not available
            raw_set_cookies = [response.headers["set-cookie"]]
            
        observation["set_cookies"] = raw_set_cookies
        
        # Add HTML content for mixed content detection
        content_type = response.headers.get("content-type", "")
        if "text/html" in content_type:
            html_content = response.text
            mixed_content_findings = self.mixed_content_detector.detect_mixed_content(
                html_content,
                str(response.url)
            )
            observation["mixed_content"] = {
                "findings_count": len(mixed_content_findings),
                "has_active_mixed_content": any(
                    f.resource_type in {"script", "style", "frame"}
                    for f in mixed_content_findings
                ),
            }
            
        # Try to fetch security.txt
        security_txt_url = ""
        parsed_url = __import__("urllib.parse").parse.urlparse(str(response.url))
        if parsed_url.scheme and parsed_url.netloc:
            security_txt_url = f"{parsed_url.scheme}://{parsed_url.netloc}/.well-known/security.txt"
            try:
                sec_txt_response = self.http_client.fetch(security_txt_url)
                if sec_txt_response.status_code == 200 and "text/plain" in sec_txt_response.headers.get("content-type", ""):
                    observation["security_txt"] = sec_txt_response.text
                else:
                    observation["security_txt"] = None
            except Exception:
                observation["security_txt"] = None
        
        return observation
