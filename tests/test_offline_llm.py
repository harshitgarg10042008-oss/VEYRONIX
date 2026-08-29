from configsentinel.client import ConfigSentinelClient
from configsentinel.engine import DeterministicComplianceEngine
from configsentinel.llm import LLMCopilot
from configsentinel.models import EvidenceSpan, Finding, FindingStatus, Severity


def test_offline_copilot_explains_without_network():
    finding = Finding(
        "finding-1",
        "audit-1",
        "NET-MGMT-TELNET-001",
        FindingStatus.FAIL,
        Severity.HIGH,
        1.0,
        (EvidenceSpan(3, 3, "transport input telnet"),),
        rationale="Telnet transport is enabled.",
    )
    explanation = LLMCopilot.offline().explain_finding(
        finding, "transport input telnet\n"
    )
    assert explanation.model_id == "configured-at-runtime"
    assert explanation.safety_status == "REVIEW_REQUIRED"
    assert "NET-MGMT-TELNET-001" in explanation.explanation
    assert "transport input telnet" in explanation.explanation


def test_offline_copilot_preserves_unknown_review_boundary():
    finding = Finding(
        "finding-2",
        "audit-2",
        "ORG-CUSTOM-001",
        FindingStatus.UNKNOWN,
        Severity.MEDIUM,
        0.0,
        (),
        rationale="Pattern was not found.",
    )
    explanation = LLMCopilot.offline().explain_finding(finding, "version 17.9\n")
    assert explanation.safety_status == "REVIEW_REQUIRED"
    assert explanation.evidence_needed
