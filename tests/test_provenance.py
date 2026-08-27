from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from configsentinel.provenance import ProvenanceError, build_policy_provenance, verify_policy_provenance


POLICY = {
    "pack_id": "edge-policy",
    "version": "1.0.0",
    "controls": [{
        "control_id": "CUSTOM-SSH-001",
        "title": "Require secure management",
        "intent": "SSH transport must be present.",
        "severity": "HIGH",
        "match": {"regex": "transport input ssh", "mode": "require"},
        "applies_to": ["cisco_ios"],
        "remediation": "Review the management transport configuration after approval.",
        "framework_mappings": {"nist_800_53": ["AC-17"], "cis": ["NET-MGMT-SSH-001"]},
    }],
}

REPORT = {
    "audit": {"audit_id": "prov-audit", "vendor": "cisco_ios", "input_sha256": "a" * 64},
    "findings": [{"finding_id": "prov-finding", "control_id": "CUSTOM-SSH-001", "status": "PASS", "severity": "HIGH", "evidence": [{"excerpt": "transport input ssh", "start_line": 4, "end_line": 4}]}],
}


def test_provenance_is_hash_linked_and_excludes_raw_rule_material() -> None:
    result = build_policy_provenance(POLICY, report=REPORT)
    assert result["summary"] == {"rule_count": 1, "framework_mapping_count": 2, "finding_lineage_count": 1, "node_count": 7, "edge_count": 6}
    assert result["safety"]["policy_activation"] is False
    serialized = json.dumps(result, sort_keys=True)
    assert "transport input ssh" not in serialized
    assert "Review the management transport configuration" not in serialized
    assert "raw_configuration_included" in serialized
    assert verify_policy_provenance(result, POLICY, report=REPORT)["verified"] is True


def test_provenance_verification_rejects_policy_or_report_tampering() -> None:
    result = build_policy_provenance(POLICY, report=REPORT)
    changed_policy = copy.deepcopy(POLICY)
    changed_policy["controls"][0]["severity"] = "CRITICAL"
    invalid = verify_policy_provenance(result, changed_policy, report=REPORT)
    assert invalid["verified"] is False
    assert "source.policy_sha256 mismatch" in invalid["mismatches"]
    changed_report = copy.deepcopy(REPORT)
    changed_report["findings"][0]["status"] = "FAIL"
    invalid_report = verify_policy_provenance(result, POLICY, report=changed_report)
    assert invalid_report["verified"] is False
    assert "finding lineage mismatch" in invalid_report["mismatches"]


def test_provenance_rejects_invalid_policy() -> None:
    invalid = copy.deepcopy(POLICY)
    invalid["controls"][0]["match"]["regex"] = "["
    with pytest.raises(ProvenanceError):
        build_policy_provenance(invalid)


def test_provenance_cli_compile_and_verify(tmp_path: Path, capsys) -> None:
    from configsentinel.cli import main

    policy_path = tmp_path / "policy.json"
    provenance_path = tmp_path / "provenance.json"
    verify_path = tmp_path / "verify.json"
    policy_path.write_text(json.dumps(POLICY), encoding="utf-8")
    assert main(["policy-provenance", str(policy_path), "--out", str(provenance_path)]) == 0
    assert "policy_activated=False" in capsys.readouterr().out
    assert main(["policy-provenance-verify", str(provenance_path), str(policy_path), "--out", str(verify_path)]) == 0
    assert "verified=True" in capsys.readouterr().out
    assert json.loads(verify_path.read_text(encoding="utf-8"))["verified"] is True
