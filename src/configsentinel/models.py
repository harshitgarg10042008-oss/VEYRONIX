"""Typed, provider-independent domain contracts for ConfigSentinel AI."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class FindingStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class EvidenceSpan:
    """A source-backed span; line numbers are 1-indexed."""

    start_line: int
    end_line: int
    excerpt: str
    redacted: bool = True

    def __post_init__(self) -> None:
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("Evidence line range is invalid")
        if not self.excerpt.strip():
            raise ValueError("Evidence excerpt cannot be empty")


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    intent: str
    severity: Severity
    framework_mappings: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    applies_to: tuple[str, ...] = ()
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if not self.control_id.strip():
            raise ValueError("control_id is required")
        if not self.title.strip() or not self.intent.strip():
            raise ValueError("control title and intent are required")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    audit_id: str
    control_id: str
    status: FindingStatus
    severity: Severity
    confidence: float
    evidence: tuple[EvidenceSpan, ...] = ()
    observed_state: str = ""
    expected_state: str = ""
    rationale: str = ""
    remediation_preview: str | None = None
    llm_assisted: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.status in {FindingStatus.FAIL, FindingStatus.PASS} and not self.evidence:
            raise ValueError("PASS and FAIL findings require evidence")
        if self.status == FindingStatus.FAIL and not self.rationale.strip():
            raise ValueError("FAIL findings require rationale")


@dataclass(frozen=True)
class AuditRequest:
    config_text: str
    vendor: str = "auto"
    frameworks: tuple[str, ...] = ("cis-network",)
    project_id: str = "local"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.config_text.strip():
            raise ValueError("config_text cannot be empty")
        if len(self.config_text.encode("utf-8")) > 5 * 1024 * 1024:
            raise ValueError("config_text exceeds the 5 MiB SDK safety limit")


@dataclass(frozen=True)
class AuditResult:
    audit_id: str
    vendor: str
    parser_version: str
    rule_pack_version: str
    findings: tuple[Finding, ...]
    unknown_blocks: tuple[EvidenceSpan, ...] = ()
    input_sha256: str = ""

    @property
    def evaluated_count(self) -> int:
        return sum(f.status not in {FindingStatus.UNKNOWN, FindingStatus.REVIEW_REQUIRED} for f in self.findings)

    @property
    def failed_count(self) -> int:
        return sum(f.status == FindingStatus.FAIL for f in self.findings)


@dataclass(frozen=True)
class RemediationPreview:
    finding_id: str
    vendor: str
    before: str
    after: str
    rollback_notes: str
    requires_human_approval: bool = True
    executable: bool = False

    def __post_init__(self) -> None:
        if self.executable:
            raise ValueError("MVP remediation previews must never be executable")
        if not self.requires_human_approval:
            raise ValueError("Remediation requires human approval")


@dataclass(frozen=True)
class LLMExplanation:
    finding_id: str
    explanation: str
    confidence: float
    evidence_needed: tuple[str, ...] = ()
    safety_status: str = "REVIEW_REQUIRED"
    model_id: str = "configured-at-runtime"
    prompt_version: str = "1.0.0"

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.safety_status not in {"PASS", "REVIEW_REQUIRED", "REJECTED"}:
            raise ValueError("invalid safety_status")
