"""Integrated Phase 3 audit engine."""

from __future__ import annotations

from .canonical import ParseResult
from .client import AuditEngine
from .controls import CONTROL_PACK_VERSION, evaluate
from .models import AuditRequest, AuditResult
from .policies import CustomPolicyPack, evaluate_custom
from .parsers import detect_and_parse


class DeterministicComplianceEngine(AuditEngine):
    """Run built-in and optional custom controls without requiring an LLM."""

    def __init__(self, policy_packs: tuple[CustomPolicyPack, ...] = ()) -> None:
        self.policy_packs = policy_packs

    def run(
        self,
        request: AuditRequest,
        *,
        audit_id: str,
        redacted_config: str,
        input_sha256: str,
    ) -> AuditResult:
        parsed: ParseResult = detect_and_parse(redacted_config, request.vendor)
        findings = evaluate(parsed.config, audit_id)
        for pack in self.policy_packs:
            findings += evaluate_custom(
                pack,
                redacted_config,
                audit_id=audit_id,
                vendor=parsed.config.metadata.get("plugin_id", parsed.config.vendor),
            )
        return AuditResult(
            audit_id=audit_id,
            vendor=parsed.config.metadata.get("plugin_id", parsed.config.vendor),
            parser_version=parsed.parser_version,
            rule_pack_version=CONTROL_PACK_VERSION,
            findings=findings,
            unknown_blocks=parsed.config.unknown_blocks,
            input_sha256=input_sha256,
        )
