"""Deterministic scoring for website security posture assessment.

This module implements reproducible score calculation based on severity-weighted
deduction from findings. The scoring model is versioned and documented.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .website_models import (
    WebsiteFinding,
    WebsiteFindingStatus,
    WebsiteSeverity,
    PostureClassification,
)


@dataclass(frozen=True)
class ScoringWeights:
    """Versioned scoring weights for severity-based deduction."""
    
    version: str = "web-posture.v1"
    critical_weight: int = 25
    high_weight: int = 15
    medium_weight: int = 8
    low_weight: int = 3
    info_weight: int = 1
    warning_weight: int = 2
    unknown_penalty: int = 0
    
    def __post_init__(self) -> None:
        if self.critical_weight <= 0 or self.high_weight <= 0:
            raise ValueError("Critical and high weights must be positive")


DEFAULT_WEIGHTS = ScoringWeights()


def calculate_score(
    findings: tuple[WebsiteFinding, ...],
    weights: ScoringWeights = DEFAULT_WEIGHTS,
) -> int:
    """Calculate deterministic security posture score from findings.
    
    Score starts at 100 and deducts points based on severity:
    - Critical findings: 25 points each
    - High findings: 15 points each
    - Medium findings: 8 points each
    - Low findings: 3 points each
    - Info findings: 1 point each
    - Warnings: 2 points each (defense-in-depth recommendation)
    - Unknown: 0 points; uncertainty is shown separately and never treated as a vulnerability
    
    The score is clamped between 0 and 100.
    
    Args:
        findings: Tuple of website security findings
        weights: Versioned scoring weights
        
    Returns:
        Integer score between 0 and 100
    """
    base_score = 100
    deduction = 0
    
    for finding in findings:
        if finding.status == WebsiteFindingStatus.PASS:
            continue
        if finding.status == WebsiteFindingStatus.NOT_APPLICABLE:
            continue
        
        if finding.status == WebsiteFindingStatus.FAIL:
            if finding.severity == WebsiteSeverity.CRITICAL:
                deduction += weights.critical_weight
            elif finding.severity == WebsiteSeverity.HIGH:
                deduction += weights.high_weight
            elif finding.severity == WebsiteSeverity.MEDIUM:
                deduction += weights.medium_weight
            elif finding.severity == WebsiteSeverity.LOW:
                deduction += weights.low_weight
            elif finding.severity == WebsiteSeverity.INFO:
                deduction += weights.info_weight
        elif finding.status == WebsiteFindingStatus.WARN:
            deduction += weights.warning_weight
        elif finding.status == WebsiteFindingStatus.UNKNOWN:
            # Missing observability is not proof of an insecure condition.
            deduction += weights.unknown_penalty
    
    score = base_score - deduction
    return max(0, min(100, score))


def classify_posture_from_findings(
    findings: tuple[WebsiteFinding, ...],
    score: int,
) -> PostureClassification:
    """Classify overall posture based on findings and score.
    
    Classification rules:
    - HIGH_RISK: Any critical finding, 3+ high findings, or score < 50
    - NEEDS_REVIEW: Any high finding, 5+ medium findings, or score < 75
    - GOOD: Otherwise
    
    Args:
        findings: Tuple of website security findings
        score: Calculated posture score
        
    Returns:
        Posture classification
    """
    critical_count = sum(
        f.severity == WebsiteSeverity.CRITICAL and f.status == WebsiteFindingStatus.FAIL
        for f in findings
    )
    high_count = sum(
        f.severity == WebsiteSeverity.HIGH and f.status == WebsiteFindingStatus.FAIL
        for f in findings
    )
    medium_count = sum(
        f.severity == WebsiteSeverity.MEDIUM and f.status == WebsiteFindingStatus.FAIL
        for f in findings
    )
    
    if critical_count > 0 or high_count >= 3 or score < 50:
        return PostureClassification.HIGH_RISK
    if high_count > 0 or medium_count >= 5 or score < 75:
        return PostureClassification.NEEDS_REVIEW
    return PostureClassification.GOOD


def get_severity_distribution(
    findings: tuple[WebsiteFinding, ...],
) -> Mapping[str, int]:
    """Get count of findings by severity.
    
    Args:
        findings: Tuple of website security findings
        
    Returns:
        Dictionary mapping severity names to counts
    """
    distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    
    for finding in findings:
        if finding.status == WebsiteFindingStatus.FAIL:
            distribution[finding.severity.value.lower()] += 1
    
    return distribution


def get_status_distribution(
    findings: tuple[WebsiteFinding, ...],
) -> Mapping[str, int]:
    """Get count of findings by status.
    
    Args:
        findings: Tuple of website security findings
        
    Returns:
        Dictionary mapping status names to counts
    """
    distribution = {
        "pass": 0,
        "fail": 0,
        "warn": 0,
        "unknown": 0,
        "not_applicable": 0,
    }
    
    for finding in findings:
        distribution[finding.status.value.lower()] += 1
    
    return distribution
