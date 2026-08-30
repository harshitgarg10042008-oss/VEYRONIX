"""Unit tests for website security posture scoring."""

from datetime import datetime
import pytest

from configsentinel.website_models import (
    WebsiteFinding,
    WebsiteFindingStatus,
    WebsiteSeverity,
    WebsiteEvidence,
    PostureClassification,
)
from configsentinel.website_scoring import (
    ScoringWeights,
    DEFAULT_WEIGHTS,
    calculate_score,
    classify_posture_from_findings,
    get_severity_distribution,
    get_status_distribution,
)


def make_finding(
    status: WebsiteFindingStatus,
    severity: WebsiteSeverity,
) -> WebsiteFinding:
    """Helper to create a test finding."""
    evidence = WebsiteEvidence(
        check_type="test",
        observed_value="value"
    )
    return WebsiteFinding(
        finding_id="f1",
        scan_id="scan_1",
        rule_id="r1",
        title="Test",
        status=status,
        severity=severity,
        evidence=evidence,
        rationale="rationale" if status == WebsiteFindingStatus.FAIL else "",
        remediation="fix" if status == WebsiteFindingStatus.FAIL else "",
        observed_at=datetime.utcnow(),
        rule_version="v1",
        target_hash="hash"
    )


class TestScoringWeights:
    def test_default_weights(self):
        assert DEFAULT_WEIGHTS.critical_weight == 25
        assert DEFAULT_WEIGHTS.high_weight == 15
        assert DEFAULT_WEIGHTS.medium_weight == 8
        assert DEFAULT_WEIGHTS.low_weight == 3
        assert DEFAULT_WEIGHTS.version == "web-posture.v1"
    
    def test_positive_weights_required(self):
        with pytest.raises(ValueError, match="Critical and high weights must be positive"):
            ScoringWeights(critical_weight=0, high_weight=15)


class TestCalculateScore:
    def test_perfect_score(self):
        findings = (make_finding(WebsiteFindingStatus.PASS, WebsiteSeverity.INFO),)
        score = calculate_score(findings)
        assert score == 100
    
    def test_critical_deduction(self):
        findings = (make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.CRITICAL),)
        score = calculate_score(findings)
        assert score == 75  # 100 - 25
    
    def test_high_deduction(self):
        findings = (make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.HIGH),)
        score = calculate_score(findings)
        assert score == 85  # 100 - 15
    
    def test_medium_deduction(self):
        findings = (make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.MEDIUM),)
        score = calculate_score(findings)
        assert score == 92  # 100 - 8
    
    def test_low_deduction(self):
        findings = (make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.LOW),)
        score = calculate_score(findings)
        assert score == 97  # 100 - 3
    
    def test_info_deduction(self):
        findings = (make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.INFO),)
        score = calculate_score(findings)
        assert score == 99  # 100 - 1
    
    def test_warning_deduction(self):
        findings = (make_finding(WebsiteFindingStatus.WARN, WebsiteSeverity.INFO),)
        score = calculate_score(findings)
        assert score == 95  # 100 - 5
    
    def test_unknown_penalty(self):
        findings = (make_finding(WebsiteFindingStatus.UNKNOWN, WebsiteSeverity.INFO),)
        score = calculate_score(findings)
        assert score == 98  # 100 - 2
    
    def test_multiple_findings(self):
        findings = (
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.CRITICAL),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.HIGH),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.MEDIUM),
        )
        score = calculate_score(findings)
        assert score == 52  # 100 - 25 - 15 - 8
    
    def test_score_floor(self):
        findings = (
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.CRITICAL),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.CRITICAL),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.CRITICAL),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.CRITICAL),
        )
        score = calculate_score(findings)
        assert score == 0  # Clamped at 0
    
    def test_not_applicable_no_deduction(self):
        findings = (make_finding(WebsiteFindingStatus.NOT_APPLICABLE, WebsiteSeverity.INFO),)
        score = calculate_score(findings)
        assert score == 100
    
    def test_custom_weights(self):
        findings = (make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.CRITICAL),)
        custom_weights = ScoringWeights(critical_weight=50)
        score = calculate_score(findings, custom_weights)
        assert score == 50  # 100 - 50


class TestClassifyPostureFromFindings:
    def test_critical_finding_high_risk(self):
        findings = (make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.CRITICAL),)
        classification = classify_posture_from_findings(findings, score=80)
        assert classification == PostureClassification.HIGH_RISK
    
    def test_three_high_findings_high_risk(self):
        findings = (
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.HIGH),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.HIGH),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.HIGH),
        )
        classification = classify_posture_from_findings(findings, score=80)
        assert classification == PostureClassification.HIGH_RISK
    
    def test_low_score_high_risk(self):
        findings = ()
        classification = classify_posture_from_findings(findings, score=40)
        assert classification == PostureClassification.HIGH_RISK
    
    def test_single_high_finding_needs_review(self):
        findings = (make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.HIGH),)
        classification = classify_posture_from_findings(findings, score=80)
        assert classification == PostureClassification.NEEDS_REVIEW
    
    def test_five_medium_findings_needs_review(self):
        findings = tuple(
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.MEDIUM)
            for _ in range(5)
        )
        classification = classify_posture_from_findings(findings, score=80)
        assert classification == PostureClassification.NEEDS_REVIEW
    
    def test_medium_score_needs_review(self):
        findings = ()
        classification = classify_posture_from_findings(findings, score=60)
        assert classification == PostureClassification.NEEDS_REVIEW
    
    def test_good_posture(self):
        findings = (
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.LOW),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.LOW),
        )
        classification = classify_posture_from_findings(findings, score=90)
        assert classification == PostureClassification.GOOD


class TestGetSeverityDistribution:
    def test_empty_findings(self):
        findings = ()
        distribution = get_severity_distribution(findings)
        assert distribution == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
    
    def test_mixed_severities(self):
        findings = (
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.CRITICAL),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.HIGH),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.HIGH),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.MEDIUM),
        )
        distribution = get_severity_distribution(findings)
        assert distribution["critical"] == 1
        assert distribution["high"] == 2
        assert distribution["medium"] == 1
        assert distribution["low"] == 0
        assert distribution["info"] == 0
    
    def test_non_fail_not_counted(self):
        findings = (
            make_finding(WebsiteFindingStatus.PASS, WebsiteSeverity.CRITICAL),
            make_finding(WebsiteFindingStatus.WARN, WebsiteSeverity.HIGH),
        )
        distribution = get_severity_distribution(findings)
        assert distribution["critical"] == 0
        assert distribution["high"] == 0


class TestGetStatusDistribution:
    def test_empty_findings(self):
        findings = ()
        distribution = get_status_distribution(findings)
        assert distribution == {
            "pass": 0,
            "fail": 0,
            "warn": 0,
            "unknown": 0,
            "not_applicable": 0,
        }
    
    def test_mixed_statuses(self):
        findings = (
            make_finding(WebsiteFindingStatus.PASS, WebsiteSeverity.INFO),
            make_finding(WebsiteFindingStatus.FAIL, WebsiteSeverity.HIGH),
            make_finding(WebsiteFindingStatus.WARN, WebsiteSeverity.INFO),
            make_finding(WebsiteFindingStatus.UNKNOWN, WebsiteSeverity.INFO),
        )
        distribution = get_status_distribution(findings)
        assert distribution["pass"] == 1
        assert distribution["fail"] == 1
        assert distribution["warn"] == 1
        assert distribution["unknown"] == 1
        assert distribution["not_applicable"] == 0
