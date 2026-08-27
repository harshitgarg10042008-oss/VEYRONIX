"""ConfigSentinel AI public SDK."""

from .client import ConfigSentinelClient, FixtureAuditEngine
from .llm import EXPLANATION_SCHEMA, LLMConfig, LLMCopilot, LLMError, OpenAICompatibleProvider
from .models import (
    AuditRequest,
    AuditResult,
    Control,
    EvidenceSpan,
    Finding,
    FindingStatus,
    LLMExplanation,
    RemediationPreview,
    Severity,
)
from .security import RedactionResult, SecretRedactor, assert_safe_for_llm

__all__ = [
    "AuditRequest",
    "AuditResult",
    "ConfigSentinelClient",
    "Control",
    "EvidenceSpan",
    "EXPLANATION_SCHEMA",
    "Finding",
    "FindingStatus",
    "FixtureAuditEngine",
    "LLMConfig",
    "LLMCopilot",
    "LLMError",
    "LLMExplanation",
    "OpenAICompatibleProvider",
    "RedactionResult",
    "RemediationPreview",
    "SecretRedactor",
    "Severity",
    "assert_safe_for_llm",
]

__version__ = "0.2.0"
