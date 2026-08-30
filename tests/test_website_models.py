"""Unit tests for website security posture models."""

from datetime import datetime, timedelta
import pytest

from configsentinel.website_models import (
    WebsiteFindingStatus,
    WebsiteSeverity,
    PostureClassification,
    WebsiteEvidence,
    WebsiteRule,
    WebsiteFinding,
    TLSEvidence,
    HeaderEvidence,
    CookieEvidence,
    RedirectEvidence,
    WebsiteScanRequest,
    WebsiteScanResult,
    compute_target_hash,
    classify_posture,
)


class TestWebsiteEvidence:
    def test_valid_evidence(self):
        evidence = WebsiteEvidence(
            check_type="https_check",
            observed_value="TLS 1.3",
            expected_value="TLS 1.2 or higher"
        )
        assert evidence.check_type == "https_check"
        assert evidence.observed_value == "TLS 1.3"
        assert evidence.redacted is True
    
    def test_evidence_requires_check_type(self):
        with pytest.raises(ValueError, match="check_type is required"):
            WebsiteEvidence(check_type="", observed_value="value")
    
    def test_evidence_requires_observed_value(self):
        with pytest.raises(ValueError, match="observed_value is required"):
            WebsiteEvidence(check_type="check", observed_value="")


class TestWebsiteRule:
    def test_valid_rule(self):
        rule = WebsiteRule(
            rule_id="WEB-HTTPS-001",
            title="HTTPS required",
            intent="Website must use HTTPS",
            severity=WebsiteSeverity.HIGH,
            check_family="tls"
        )
        assert rule.rule_id == "WEB-HTTPS-001"
        assert rule.version == "web-posture.v1"
    
    def test_rule_requires_fields(self):
        with pytest.raises(ValueError, match="rule_id is required"):
            WebsiteRule(
                rule_id="",
                title="Title",
                intent="Intent",
                severity=WebsiteSeverity.HIGH,
                check_family="tls"
            )
        
        with pytest.raises(ValueError, match="title and intent are required"):
            WebsiteRule(
                rule_id="WEB-001",
                title="",
                intent="Intent",
                severity=WebsiteSeverity.HIGH,
                check_family="tls"
            )


class TestWebsiteFinding:
    def test_valid_finding(self):
        evidence = WebsiteEvidence(
            check_type="https",
            observed_value="http"
        )
        finding = WebsiteFinding(
            finding_id="scan_1:WEB-HTTPS-001",
            scan_id="scan_1",
            rule_id="WEB-HTTPS-001",
            title="HTTPS not used",
            status=WebsiteFindingStatus.FAIL,
            severity=WebsiteSeverity.HIGH,
            evidence=evidence,
            rationale="Website uses HTTP instead of HTTPS",
            remediation="Enable HTTPS",
            observed_at=datetime.utcnow(),
            rule_version="web-posture.v1",
            target_hash="abc123"
        )
        assert finding.status == WebsiteFindingStatus.FAIL
    
    def test_fail_finding_requires_rationale(self):
        evidence = WebsiteEvidence(check_type="https", observed_value="http")
        with pytest.raises(ValueError, match="FAIL findings require rationale"):
            WebsiteFinding(
                finding_id="scan_1:WEB-001",
                scan_id="scan_1",
                rule_id="WEB-001",
                title="Title",
                status=WebsiteFindingStatus.FAIL,
                severity=WebsiteSeverity.HIGH,
                evidence=evidence,
                rationale="",
                remediation="Fix",
                observed_at=datetime.utcnow(),
                rule_version="web-posture.v1",
                target_hash="abc123"
            )
    
    def test_fail_finding_requires_remediation(self):
        evidence = WebsiteEvidence(check_type="https", observed_value="http")
        with pytest.raises(ValueError, match="FAIL findings require remediation"):
            WebsiteFinding(
                finding_id="scan_1:WEB-001",
                scan_id="scan_1",
                rule_id="WEB-001",
                title="Title",
                status=WebsiteFindingStatus.FAIL,
                severity=WebsiteSeverity.HIGH,
                evidence=evidence,
                rationale="Rationale",
                remediation="",
                observed_at=datetime.utcnow(),
                rule_version="web-posture.v1",
                target_hash="abc123"
            )


class TestTLSEvidence:
    def test_valid_tls(self):
        now = datetime.utcnow()
        tls = TLSEvidence(
            protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            certificate_valid_from=now - timedelta(days=365),
            certificate_valid_to=now + timedelta(days=365),
            certificate_issuer="Let's Encrypt",
            certificate_subject="example.com",
            hostname_match=True
        )
        assert tls.is_valid is True
    
    def test_invalid_tls_hostname_mismatch(self):
        now = datetime.utcnow()
        tls = TLSEvidence(
            protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            certificate_valid_from=now - timedelta(days=365),
            certificate_valid_to=now + timedelta(days=365),
            certificate_issuer="Let's Encrypt",
            certificate_subject="other.com",
            hostname_match=False
        )
        assert tls.is_valid is False
    
    def test_expired_certificate(self):
        now = datetime.utcnow()
        tls = TLSEvidence(
            protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            certificate_valid_from=now - timedelta(days=730),
            certificate_valid_to=now - timedelta(days=1),
            certificate_issuer="Let's Encrypt",
            certificate_subject="example.com",
            hostname_match=True
        )
        assert tls.is_valid is False


class TestHeaderEvidence:
    def test_valid_header(self):
        header = HeaderEvidence(
            header_name="Content-Security-Policy",
            header_value="default-src 'self'"
        )
        assert header.present is True
        assert header.header_name == "Content-Security-Policy"
    
    def test_header_requires_name(self):
        with pytest.raises(ValueError, match="header_name is required"):
            HeaderEvidence(header_name="", header_value="value")


class TestCookieEvidence:
    def test_secure_cookie(self):
        cookie = CookieEvidence(
            cookie_name="session",
            domain="example.com",
            secure=True,
            http_only=True,
            same_site="Strict"
        )
        assert cookie.secure is True
        assert cookie.http_only is True
    
    def test_insecure_cookie(self):
        cookie = CookieEvidence(
            cookie_name="session",
            domain="example.com",
            secure=False,
            http_only=False,
            same_site="None"
        )
        assert cookie.secure is False


class TestRedirectEvidence:
    def test_valid_redirect(self):
        redirect = RedirectEvidence(
            initial_url="http://example.com",
            final_url="https://example.com",
            redirect_count=1,
            redirect_chain=("http://example.com", "https://example.com")
        )
        assert redirect.redirect_count == 1
        assert redirect.scheme_downgrade is False
    
    def test_scheme_downgrade(self):
        redirect = RedirectEvidence(
            initial_url="https://example.com",
            final_url="http://example.com",
            redirect_count=1,
            redirect_chain=("https://example.com", "http://example.com"),
            scheme_downgrade=True
        )
        assert redirect.scheme_downgrade is True
    
    def test_negative_redirect_count_invalid(self):
        with pytest.raises(ValueError, match="redirect_count cannot be negative"):
            RedirectEvidence(
                initial_url="http://example.com",
                final_url="https://example.com",
                redirect_count=-1
            )


class TestWebsiteScanRequest:
    def test_valid_https_request(self):
        request = WebsiteScanRequest(
            url="https://example.com",
            authorization_confirmed=True
        )
        assert request.target_origin == "https://example.com"
    
    def test_valid_http_request(self):
        request = WebsiteScanRequest(
            url="http://example.com",
            authorization_confirmed=True
        )
        assert request.target_origin == "http://example.com"
    
    def test_invalid_scheme(self):
        with pytest.raises(ValueError, match="Only http and https schemes are supported"):
            WebsiteScanRequest(
                url="ftp://example.com",
                authorization_confirmed=True
            )
    
    def test_requires_authorization(self):
        with pytest.raises(ValueError, match="authorization_confirmed must be True"):
            WebsiteScanRequest(
                url="https://example.com",
                authorization_confirmed=False
            )
    
    def test_invalid_url_format(self):
        with pytest.raises(ValueError, match="Only http and https schemes are supported"):
            WebsiteScanRequest(
                url="not-a-url",
                authorization_confirmed=True
            )


class TestWebsiteScanResult:
    def test_valid_result(self):
        result = WebsiteScanResult(
            scan_id="scan_1",
            target_origin="https://example.com",
            final_url="https://example.com",
            posture_classification=PostureClassification.GOOD,
            score=85,
            findings=()
        )
        assert result.score == 85
        assert result.passed_count == 0
        assert result.failed_count == 0
    
    def test_score_clamping(self):
        with pytest.raises(ValueError, match="score must be between 0 and 100"):
            WebsiteScanResult(
                scan_id="scan_1",
                target_origin="https://example.com",
                final_url="https://example.com",
                posture_classification=PostureClassification.GOOD,
                score=150,
                findings=()
            )
    
    def test_finding_counts(self):
        evidence = WebsiteEvidence(check_type="test", observed_value="value")
        findings = (
            WebsiteFinding(
                finding_id="f1",
                scan_id="scan_1",
                rule_id="r1",
                title="Pass",
                status=WebsiteFindingStatus.PASS,
                severity=WebsiteSeverity.INFO,
                evidence=evidence,
                rationale="",
                remediation="",
                observed_at=datetime.utcnow(),
                rule_version="v1",
                target_hash="hash"
            ),
            WebsiteFinding(
                finding_id="f2",
                scan_id="scan_1",
                rule_id="r2",
                title="Fail",
                status=WebsiteFindingStatus.FAIL,
                severity=WebsiteSeverity.HIGH,
                evidence=evidence,
                rationale="Fail",
                remediation="Fix",
                observed_at=datetime.utcnow(),
                rule_version="v1",
                target_hash="hash"
            ),
        )
        result = WebsiteScanResult(
            scan_id="scan_1",
            target_origin="https://example.com",
            final_url="https://example.com",
            posture_classification=PostureClassification.NEEDS_REVIEW,
            score=70,
            findings=findings
        )
        assert result.passed_count == 1
        assert result.failed_count == 1
        assert result.high_count == 1


class TestComputeTargetHash:
    def test_hash_is_deterministic(self):
        url = "https://example.com"
        hash1 = compute_target_hash(url)
        hash2 = compute_target_hash(url)
        assert hash1 == hash2
        assert len(hash1) == 16
    
    def test_hash_differs_by_url(self):
        hash1 = compute_target_hash("https://example.com")
        hash2 = compute_target_hash("https://other.com")
        assert hash1 != hash2


class TestClassifyPosture:
    def test_critical_finding_high_risk(self):
        assert classify_posture(score=80, critical_count=1, high_count=0) == PostureClassification.HIGH_RISK
    
    def test_multiple_high_findings_high_risk(self):
        assert classify_posture(score=80, critical_count=0, high_count=3) == PostureClassification.HIGH_RISK
    
    def test_low_score_high_risk(self):
        assert classify_posture(score=40, critical_count=0, high_count=0) == PostureClassification.HIGH_RISK
    
    def test_single_high_finding_needs_review(self):
        assert classify_posture(score=80, critical_count=0, high_count=1) == PostureClassification.NEEDS_REVIEW
    
    def test_many_medium_findings_needs_review(self):
        assert classify_posture(score=80, critical_count=0, high_count=0, medium_count=5) == PostureClassification.NEEDS_REVIEW
    
    def test_medium_score_needs_review(self):
        assert classify_posture(score=60, critical_count=0, high_count=0) == PostureClassification.NEEDS_REVIEW
    
    def test_good_posture(self):
        assert classify_posture(score=90, critical_count=0, high_count=0) == PostureClassification.GOOD
