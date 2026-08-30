"""Website Security Posture Checker - domain models and rule schemas.

This module defines the deterministic models for website security posture assessment,
including findings, rules, evidence, and scoring. All models are frozen dataclasses
to ensure immutability and reproducibility.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping
from urllib.parse import urlparse


class WebsiteFindingStatus(str, Enum):
    """Status of a website security check."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class WebsiteSeverity(str, Enum):
    """Severity level for website security findings."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PostureClassification(str, Enum):
    """Overall security posture classification."""
    GOOD = "GOOD"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    HIGH_RISK = "HIGH_RISK"


@dataclass(frozen=True)
class WebsiteEvidence:
    """Normalized evidence from a website security check."""
    
    check_type: str
    observed_value: str
    expected_value: str = ""
    raw_evidence: str = ""
    redacted: bool = True
    
    def __post_init__(self) -> None:
        if not self.check_type.strip():
            raise ValueError("check_type is required")
        if not self.observed_value.strip():
            raise ValueError("observed_value is required")


@dataclass(frozen=True)
class WebsiteRule:
    """A deterministic website security rule."""
    
    rule_id: str
    title: str
    intent: str
    severity: WebsiteSeverity
    check_family: str
    version: str = "web-posture.v1"
    framework_mappings: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("rule_id is required")
        if not self.title.strip() or not self.intent.strip():
            raise ValueError("title and intent are required")


@dataclass(frozen=True)
class WebsiteFinding:
    """A single website security finding."""
    
    finding_id: str
    scan_id: str
    rule_id: str
    title: str
    status: WebsiteFindingStatus
    severity: WebsiteSeverity
    evidence: WebsiteEvidence
    rationale: str
    remediation: str
    observed_at: datetime
    rule_version: str
    target_hash: str
    limitations: str = ""
    
    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("finding_id is required")
        if not self.scan_id.strip():
            raise ValueError("scan_id is required")
        if not self.rule_id.strip():
            raise ValueError("rule_id is required")
        if self.status == WebsiteFindingStatus.FAIL and not self.rationale.strip():
            raise ValueError("FAIL findings require rationale")
        if self.status == WebsiteFindingStatus.FAIL and not self.remediation.strip():
            raise ValueError("FAIL findings require remediation")


@dataclass(frozen=True)
class TLSEvidence:
    """TLS certificate and protocol evidence."""
    
    protocol_version: str
    cipher_suite: str
    certificate_valid_from: datetime
    certificate_valid_to: datetime
    certificate_issuer: str
    certificate_subject: str
    hostname_match: bool
    certificate_errors: tuple[str, ...] = ()
    
    @property
    def is_valid(self) -> bool:
        now = datetime.utcnow()
        return (
            self.hostname_match
            and self.certificate_valid_from <= now <= self.certificate_valid_to
            and len(self.certificate_errors) == 0
        )


@dataclass(frozen=True)
class HeaderEvidence:
    """Security header evidence."""
    
    header_name: str
    header_value: str
    parsed_directives: dict[str, str] = field(default_factory=dict)
    present: bool = True
    parse_error: str = ""
    
    def __post_init__(self) -> None:
        if not self.header_name.strip():
            raise ValueError("header_name is required")


@dataclass(frozen=True)
class CookieEvidence:
    """Cookie security attributes evidence."""
    
    cookie_name: str
    domain: str
    secure: bool
    http_only: bool
    same_site: str
    path: str = ""
    
    def __post_init__(self) -> None:
        if not self.cookie_name.strip():
            raise ValueError("cookie_name is required")


@dataclass(frozen=True)
class RedirectEvidence:
    """Redirect chain evidence."""
    
    initial_url: str
    final_url: str
    redirect_count: int
    redirect_chain: tuple[str, ...] = ()
    scheme_downgrade: bool = False
    origin_change: bool = False
    
    def __post_init__(self) -> None:
        if not self.initial_url.strip():
            raise ValueError("initial_url is required")
        if not self.final_url.strip():
            raise ValueError("final_url is required")
        if self.redirect_count < 0:
            raise ValueError("redirect_count cannot be negative")


@dataclass(frozen=True)
class WebsiteScanRequest:
    """Request to scan a website for security posture."""
    
    url: str
    authorization_confirmed: bool
    workspace_id: str = "local"
    
    def __post_init__(self) -> None:
        if not self.url.strip():
            raise ValueError("url is required")
        parsed = urlparse(self.url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http and https schemes are supported")
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
        if not self.authorization_confirmed:
            raise ValueError("authorization_confirmed must be True")
    
    @property
    def target_origin(self) -> str:
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"


@dataclass(frozen=True)
class WebsiteScanResult:
    """Complete website security scan result."""
    
    scan_id: str
    target_origin: str
    final_url: str
    posture_classification: PostureClassification
    score: int
    findings: tuple[WebsiteFinding, ...]
    tls_evidence: TLSEvidence | None = None
    redirect_evidence: RedirectEvidence | None = None
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    rule_pack_version: str = "web-posture.v1"
    scanner_version: str = "1.0.0"
    limitations: str = ""
    
    @property
    def passed_count(self) -> int:
        return sum(f.status == WebsiteFindingStatus.PASS for f in self.findings)
    
    @property
    def failed_count(self) -> int:
        return sum(f.status == WebsiteFindingStatus.FAIL for f in self.findings)
    
    @property
    def warning_count(self) -> int:
        return sum(f.status == WebsiteFindingStatus.WARN for f in self.findings)
    
    @property
    def unknown_count(self) -> int:
        return sum(f.status == WebsiteFindingStatus.UNKNOWN for f in self.findings)
    
    @property
    def critical_count(self) -> int:
        return sum(f.severity == WebsiteSeverity.CRITICAL for f in self.findings)
    
    @property
    def high_count(self) -> int:
        return sum(f.severity == WebsiteSeverity.HIGH for f in self.findings)
    
    @property
    def medium_count(self) -> int:
        return sum(f.severity == WebsiteSeverity.MEDIUM for f in self.findings)
    
    @property
    def low_count(self) -> int:
        return sum(f.severity == WebsiteSeverity.LOW for f in self.findings)
    
    def __post_init__(self) -> None:
        if not self.scan_id.strip():
            raise ValueError("scan_id is required")
        if not 0 <= self.score <= 100:
            raise ValueError("score must be between 0 and 100")


WEBSITE_RULE_PACK_VERSION = "web-posture.v1"


def compute_target_hash(url: str) -> str:
    """Compute a privacy-preserving hash for the target."""
    import hashlib
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def classify_posture(score: int, critical_count: int, high_count: int, medium_count: int = 0) -> PostureClassification:
    """Classify overall posture based on score and severity distribution."""
    if critical_count > 0 or high_count >= 3 or score < 50:
        return PostureClassification.HIGH_RISK
    if high_count > 0 or medium_count >= 5 or score < 75:
        return PostureClassification.NEEDS_REVIEW
    return PostureClassification.GOOD
