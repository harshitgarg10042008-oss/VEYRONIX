import pytest

from configsentinel.risk import RiskError, prioritize_report, risk_report


def test_risk_prioritizes_failed_critical_finding():
    report = {"findings": [{"finding_id": "f2", "control_id": "low", "status": "UNKNOWN", "severity": "LOW", "confidence": 0.2}, {"finding_id": "f1", "control_id": "critical", "status": "FAIL", "severity": "CRITICAL", "confidence": 1.0}]}
    items = prioritize_report(report, asset_criticality="critical")
    assert items[0].finding_id == "f1"
    assert items[0].priority == "P1"


def test_risk_does_not_include_pass_and_preserves_safety_note():
    payload = risk_report({"findings": [{"finding_id": "pass", "status": "PASS", "severity": "LOW", "confidence": 1.0}]})
    assert payload["items"] == []
    assert "does not change compliance status" in payload["safety_note"]


def test_invalid_criticality_rejected():
    with pytest.raises(RiskError):
        prioritize_report({"findings": []}, asset_criticality="unknown")
