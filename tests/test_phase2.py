from __future__ import annotations

import json

import pytest

from configsentinel import (
    AuditRequest,
    ConfigSentinelClient,
    EvidenceSpan,
    Finding,
    FindingStatus,
    FixtureAuditEngine,
    LLMConfig,
    LLMCopilot,
    LLMError,
    SecretRedactor,
    Severity,
)


class FakeProvider:
    def __init__(self, payload: dict):
        self.payload = payload
        self.calls = []

    def complete(self, *, system, user, response_schema, timeout_s):
        self.calls.append(
            {
                "system": system,
                "user": user,
                "schema": response_schema,
                "timeout_s": timeout_s,
            }
        )
        return json.dumps(self.payload)


def test_redactor_preserves_hash_and_masks_common_secrets():
    result = SecretRedactor().redact(
        "enable secret super-secret\nusername admin password pw123\n"
    )
    assert result.redaction_count == 2
    assert "super-secret" not in result.text
    assert "pw123" not in result.text
    assert len(result.input_sha256) == 64


def test_sdk_fixture_engine_never_marks_unknown_as_pass():
    client = ConfigSentinelClient(engine=FixtureAuditEngine())
    result = client.audit_text("interface Gi0/1\n", vendor="cisco_ios")
    assert result.findings[0].status == FindingStatus.UNKNOWN
    assert result.findings[0].confidence == 0.0


def test_sdk_fixture_engine_detects_telnet_with_evidence():
    client = ConfigSentinelClient(engine=FixtureAuditEngine())
    result = client.audit_text(
        "line vty 0 4\n transport input telnet\n", vendor="cisco_ios"
    )
    finding = result.findings[0]
    assert finding.status == FindingStatus.FAIL
    assert finding.evidence
    assert finding.severity == Severity.HIGH


def test_model_rejects_verdict_without_evidence():
    with pytest.raises(ValueError):
        Finding(
            finding_id="f1",
            audit_id="a1",
            control_id="C1",
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            confidence=1.0,
            rationale="bad",
        )


def test_llm_copilot_returns_structured_explanation():
    provider = FakeProvider(
        {
            "explanation": "The evidence shows an insecure management transport.",
            "confidence": 0.9,
            "evidence_needed": [],
            "safety_status": "REVIEW_REQUIRED",
        }
    )
    finding = Finding(
        finding_id="f1",
        audit_id="a1",
        control_id="NET-MGMT-SSH-001",
        status=FindingStatus.FAIL,
        severity=Severity.HIGH,
        confidence=1.0,
        evidence=(EvidenceSpan(1, 1, "transport input telnet"),),
        observed_state="Telnet enabled",
        expected_state="Secure management only",
        rationale="Deterministic rule detected Telnet.",
    )
    copilot = LLMCopilot(
        provider=provider, config=LLMConfig(enabled=True, model="test")
    )
    explanation = copilot.explain_finding(
        finding, "transport input telnet\npassword hidden"
    )
    assert explanation.safety_status == "REVIEW_REQUIRED"
    assert provider.calls
    assert "password hidden" not in provider.calls[0]["user"]


def test_llm_rejects_unexpected_fields():
    provider = FakeProvider(
        {
            "explanation": "ok",
            "confidence": 0.5,
            "evidence_needed": [],
            "safety_status": "REVIEW_REQUIRED",
            "execute": "no",
        }
    )
    finding = Finding(
        finding_id="f1",
        audit_id="a1",
        control_id="C1",
        status=FindingStatus.UNKNOWN,
        severity=Severity.MEDIUM,
        confidence=0.0,
    )
    copilot = LLMCopilot(
        provider=provider, config=LLMConfig(enabled=True, model="test")
    )
    with pytest.raises(LLMError):
        copilot.explain_finding(finding, "unknown command")


def test_disabled_llm_fails_closed():
    finding = Finding(
        finding_id="f1",
        audit_id="a1",
        control_id="C1",
        status=FindingStatus.UNKNOWN,
        severity=Severity.MEDIUM,
        confidence=0.0,
    )
    copilot = LLMCopilot(config=LLMConfig(enabled=False))
    with pytest.raises(LLMError):
        copilot.explain_finding(finding, "unknown command")
