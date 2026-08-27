"""ConfigSentinel AI public SDK."""

from .canonical import CanonicalConfig, ParseResult, ParserError
from .client import ConfigSentinelClient, FixtureAuditEngine
from .controls import CONTROL_PACK, CONTROL_PACK_VERSION, evaluate
from .engine import DeterministicComplianceEngine
from .frameworks import FRAMEWORKS, REGISTRY_VERSION, FrameworkDefinition, get_framework, mappings_for_finding, normalize_frameworks
from .ingestion import ConfigIngestionService, IngestedConfig, IngestionError, IngestionPolicy
from .hardening import AuditMetrics, HardeningError, ResourceBudget, benchmark_call, metrics_for, safe_output_path, sha256_text, timed
from .learning import ApprovedMapping, LearningLoopError, ReviewDecision, ReviewEvent, SyntaxProposal, UnknownSyntaxCase, UnknownSyntaxQueue
from .parsers import CiscoIOSParser, GenericFirewallParser, JunosParser, PARSER_REGISTRY, detect_and_parse
from .llm import EXPLANATION_SCHEMA, LLMConfig, LLMCopilot, LLMError, OpenAICompatibleProvider
from .remediation import RemediationBundle, RemediationError, RemediationStep, generate_bundle, previews
from .reporting import REPORT_VERSION, render_json, render_markdown, report_dict, write_report
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
    "AuditRequest", "CanonicalConfig", "CiscoIOSParser", "CONTROL_PACK", "CONTROL_PACK_VERSION", "AuditResult",
    "ConfigSentinelClient", "ConfigIngestionService", "DeterministicComplianceEngine", "detect_and_parse", "Control",
    "EvidenceSpan", "EXPLANATION_SCHEMA", "Finding", "FindingStatus", "IngestedConfig", "IngestionError", "IngestionPolicy",
    "GenericFirewallParser", "FixtureAuditEngine", "LLMConfig", "LLMCopilot", "LLMError", "LLMExplanation", "JunosParser",
    "OpenAICompatibleProvider", "PARSER_REGISTRY", "ParseResult", "ParserError", "RedactionResult", "RemediationBundle",
    "RemediationError", "RemediationStep", "RemediationPreview", "SecretRedactor", "evaluate", "Severity",
    "assert_safe_for_llm", "generate_bundle", "previews", "AuditMetrics", "HardeningError", "ResourceBudget", "benchmark_call", "metrics_for", "safe_output_path", "sha256_text", "timed", "ApprovedMapping", "LearningLoopError", "ReviewDecision", "ReviewEvent", "SyntaxProposal", "UnknownSyntaxCase", "UnknownSyntaxQueue", "FrameworkDefinition", "FRAMEWORKS", "REGISTRY_VERSION",
    "get_framework", "mappings_for_finding", "normalize_frameworks", "REPORT_VERSION", "report_dict", "render_json",
    "render_markdown", "write_report",
]

__version__ = "0.3.0"
