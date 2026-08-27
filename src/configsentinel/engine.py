"""Integrated Phase 3 audit engine."""

from __future__ import annotations

from .canonical import ParseResult
from .client import AuditEngine
from .controls import CONTROL_PACK_VERSION, evaluate
from .models import AuditRequest, AuditResult
from .parsers import detect_and_parse


class DeterministicComplianceEngine(AuditEngine):
    """Run parsing and compliance controls without requiring an LLM."""

    def run(self, request: AuditRequest, *, audit_id: str, redacted_config: str, input_sha256: str) -> AuditResult:
        parsed: ParseResult = detect_and_parse(redacted_config, request.vendor)
        findings = evaluate(parsed.config, audit_id)
        return AuditResult(
            audit_id=audit_id,
            vendor=parsed.config.metadata.get("plugin_id", parsed.config.vendor),
            parser_version=parsed.parser_version,
            rule_pack_version=CONTROL_PACK_VERSION,
            findings=findings,
            unknown_blocks=parsed.config.unknown_blocks,
            input_sha256=input_sha256,
        )
