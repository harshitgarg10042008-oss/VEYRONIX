import json
from pathlib import Path

import pytest

from configsentinel.intent import IntentError, compile_resource_intent


INTENT = {
    "intent_id": "mgmt-boundary",
    "subject": "network-administrators",
    "resource": "edge-management",
    "allowed_via": ["jump-host"],
    "protocols": ["ssh"],
    "requirements": ["ssh_management", "no_telnet", "no_plain_http"],
}

REPORT = {
    "findings": [
        {"finding_id": "ssh", "control_id": "NET-MGMT-SSH-001", "status": "PASS", "evidence": [{"start_line": 1, "end_line": 1, "redacted": True}]},
        {"finding_id": "telnet", "control_id": "NET-MGMT-TELNET-001", "status": "PASS", "evidence": [{"start_line": 2, "end_line": 2, "redacted": True}]},
        {"finding_id": "http", "control_id": "NET-MGMT-HTTP-001", "status": "FAIL", "evidence": [{"start_line": 3, "end_line": 3, "redacted": True}]},
    ]
}

TOPOLOGY = {"nodes": [{"id": "jump-host"}, {"id": "edge-management"}], "links": [{"source": "jump-host", "target": "edge-management"}]}


def test_intent_compiler_is_vendor_neutral_and_verdict_preserving():
    compiled = compile_resource_intent(INTENT, report=REPORT, topology=TOPOLOGY)

    assert compiled["schema"] == "configsentinel.resource-intent.v1"
    assert compiled["summary"]["state"] == "VIOLATED"
    assert compiled["summary"]["satisfied_count"] == 2
    assert compiled["summary"]["violated_count"] == 1
    assert compiled["checks"][2]["control_id"] == "NET-MGMT-HTTP-001"
    assert compiled["safety"]["vendor_configuration_emitted"] is False
    assert compiled["safety"]["verdicts_changed"] is False


def test_intent_without_report_fails_closed_to_review_required():
    compiled = compile_resource_intent(INTENT, topology=TOPOLOGY)

    assert compiled["summary"]["state"] == "REVIEW_REQUIRED"
    assert all(check["state"] == "UNKNOWN" for check in compiled["checks"])
    assert all(check["observed_status"] == "NO_EVIDENCE" for check in compiled["checks"])


def test_intent_rejects_unknown_assets_and_requirements():
    with pytest.raises(IntentError):
        compile_resource_intent(INTENT, topology={"nodes": [{"id": "other"}], "links": []})
    with pytest.raises(IntentError):
        compile_resource_intent({**INTENT, "requirements": ["unsupported"]})


def test_intent_cli_writes_review_artifact(tmp_path: Path, capsys):
    from configsentinel.cli import main

    intent_path = tmp_path / "intent.json"
    report_path = tmp_path / "report.json"
    topology_path = tmp_path / "topology.json"
    out_path = tmp_path / "intent-result.json"
    intent_path.write_text(json.dumps(INTENT), encoding="utf-8")
    report_path.write_text(json.dumps(REPORT), encoding="utf-8")
    topology_path.write_text(json.dumps(TOPOLOGY), encoding="utf-8")

    assert main(["intent-compile", str(intent_path), "--report", str(report_path), "--topology", str(topology_path), "--out", str(out_path)]) == 0
    assert "intent_compile=" in capsys.readouterr().out
    assert json.loads(out_path.read_text(encoding="utf-8"))["safety"]["commands_executable"] is False
