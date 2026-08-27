"""Public SDK client for ConfigSentinel AI.

Phase 2 provides contracts and orchestration boundaries. Parser and policy
plugins are intentionally injected so later phases can add implementations
without changing the SDK surface.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Iterable
from typing import Any, Protocol

from .ingestion import ConfigIngestionService, IngestedConfig
from .models import AuditRequest, AuditResult, Finding, FindingStatus, Severity
from .security import SecretRedactor
from .reporting import render_json, render_markdown
from .frameworks import normalize_frameworks


class AuditEngine(Protocol):
    def run(self, request: AuditRequest, *, audit_id: str, redacted_config: str, input_sha256: str) -> AuditResult:
        """Run deterministic parsing and policy evaluation."""


class ConfigSentinelClient:
    """Stable SDK facade for local or remote audit implementations."""

    def __init__(self, engine: AuditEngine | None = None, *, redactor: SecretRedactor | None = None, ingestion: ConfigIngestionService | None = None) -> None:
        self.engine = engine
        self.redactor = redactor or SecretRedactor()
        self.ingestion = ingestion or ConfigIngestionService(redactor=self.redactor)
        self._controls: dict[str, Any] = {}
        self._plugins: dict[str, Any] = {}

    def register_control(self, control_id: str, control: Any) -> None:
        if not control_id.strip():
            raise ValueError("control_id is required")
        if control_id in self._controls:
            raise ValueError(f"control already registered: {control_id}")
        self._controls[control_id] = control

    def register_plugin(self, plugin_id: str, plugin: Any) -> None:
        if not plugin_id.strip():
            raise ValueError("plugin_id is required")
        if plugin_id in self._plugins:
            raise ValueError(f"plugin already registered: {plugin_id}")
        self._plugins[plugin_id] = plugin

    def audit(self, request: AuditRequest) -> AuditResult:
        if self.engine is None:
            raise RuntimeError("no audit engine configured; parser/policy engine will be added in a later phase")
        redacted = self.redactor.redact(request.config_text)
        audit_id = f"audit_{uuid.uuid4().hex}"
        return self.engine.run(request, audit_id=audit_id, redacted_config=redacted.text, input_sha256=redacted.input_sha256)

    def audit_text(self, config_text: str, *, vendor: str = "auto", frameworks: Iterable[str] = ("cis-network",), project_id: str = "local") -> AuditResult:
        return self.audit(AuditRequest(config_text=config_text, vendor=vendor, frameworks=tuple(frameworks), project_id=project_id))

    def ingest(self, filename: str, content: bytes) -> IngestedConfig:
        """Validate, hash, redact, and optionally quarantine configuration bytes."""
        return self.ingestion.ingest_bytes(filename, content)

    def audit_file(self, path: str, *, vendor: str = "auto", frameworks: Iterable[str] = ("cis-network",), project_id: str = "local") -> AuditResult:
        """Audit a validated file; only redacted content reaches the engine."""
        ingested = self.ingestion.ingest_file(path)
        request = AuditRequest(config_text=ingested.redacted_text, vendor=vendor, frameworks=tuple(frameworks), project_id=project_id)
        return self.audit(request)

    def report_markdown(self, result: AuditResult, *, frameworks: Iterable[str] = ("cis-network",)) -> str:
        """Render a deterministic, evidence-linked Markdown report."""
        return render_markdown(result, normalize_frameworks(frameworks))

    def report_json(self, result: AuditResult, *, frameworks: Iterable[str] = ("cis-network",)) -> str:
        """Render a deterministic JSON report with reconciliation metadata."""
        return render_json(result, normalize_frameworks(frameworks))


class FixtureAuditEngine:
    """Small deterministic engine used for SDK contract tests and examples.

    It is deliberately not the final compliance engine. It demonstrates the
    contract: findings require evidence and unsupported content is UNKNOWN.
    """

    def run(self, request: AuditRequest, *, audit_id: str, redacted_config: str, input_sha256: str) -> AuditResult:
        lines = redacted_config.splitlines()
        evidence = tuple(
            __import__("configsentinel.models", fromlist=["EvidenceSpan"]).EvidenceSpan(i, i, line)
            for i, line in enumerate(lines, 1)
            if line.strip()
        )
        has_telnet = any("transport input telnet" in line.lower() for line in lines)
        finding = Finding(
            finding_id=f"finding_{hashlib.sha256((audit_id + 'NET-MGMT-SSH-001').encode()).hexdigest()[:12]}",
            audit_id=audit_id,
            control_id="NET-MGMT-SSH-001",
            status=FindingStatus.FAIL if has_telnet else FindingStatus.UNKNOWN,
            severity=Severity.HIGH,
            confidence=1.0 if has_telnet else 0.0,
            evidence=evidence if has_telnet else (),
            observed_state="Telnet management access detected" if has_telnet else "Configuration area not yet evaluated",
            expected_state="Secure management access only",
            rationale="Deterministic fixture rule detected a Telnet VTY transport directive." if has_telnet else "No Phase 2 parser is authorized to infer compliance for this input.",
        )
        return AuditResult(
            audit_id=audit_id,
            vendor=request.vendor,
            parser_version="phase2-fixture-0.1.0",
            rule_pack_version="phase2-fixture-0.1.0",
            findings=(finding,),
            input_sha256=input_sha256,
        )
