"""ConfigSentinel AI public SDK."""

from .canonical import CanonicalConfig, ParseResult, ParserError
from .client import ConfigSentinelClient, FixtureAuditEngine
from .controls import CONTROL_PACK, CONTROL_PACK_VERSION, evaluate
from .engine import DeterministicComplianceEngine
from .parsers import CiscoIOSParser, GenericFirewallParser, JunosParser, PARSER_REGISTRY, detect_and_parse
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
    "CanonicalConfig",
    "CiscoIOSParser",
    "CONTROL_PACK",
    "CONTROL_PACK_VERSION",
    "AuditResult",
    "ConfigSentinelClient",
    "DeterministicComplianceEngine",
    "detect_and_parse",
    "Control",
    "EvidenceSpan",
    "EXPLANATION_SCHEMA",
    "Finding",
    "FindingStatus",
    "GenericFirewallParser",
    "FixtureAuditEngine",
    "LLMConfig",
    "LLMCopilot",
    "LLMError",
    "LLMExplanation",
    "JunosParser",
    "OpenAICompatibleProvider",
    "PARSER_REGISTRY",
    "ParseResult",
    "ParserError",
    "RedactionResult",
    "RemediationPreview",
    "SecretRedactor",
    "evaluate",
    "Severity",
    "assert_safe_for_llm",
]

__version__ = "0.2.0"
