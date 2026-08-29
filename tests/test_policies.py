from pathlib import Path

import pytest

from configsentinel.client import ConfigSentinelClient
from configsentinel.engine import DeterministicComplianceEngine
from configsentinel.policies import CustomPolicyPack, PolicyValidationError


def pack(mode="require"):
    return {
        "pack_id": "org-baseline",
        "version": "1.0.0",
        "controls": [
            {
                "control_id": "ORG-MGMT-001",
                "title": "Approved banner",
                "intent": "Require an approved management banner.",
                "severity": "HIGH",
                "match": {"mode": mode, "regex": "banner motd"},
                "applies_to": ["cisco_ios"],
                "framework_mappings": {"cis-network": ["ORG-MGMT-001"]},
                "remediation": "Add the approved banner after review.",
            }
        ],
    }


def test_custom_required_rule_produces_evidence_backed_pass():
    result = ConfigSentinelClient(
        engine=DeterministicComplianceEngine((CustomPolicyPack.from_dict(pack()),))
    ).audit_text("version 17.9\nbanner motd ^authorized^\n", vendor="cisco_ios")
    finding = next(
        item for item in result.findings if item.control_id == "ORG-MGMT-001"
    )
    assert finding.status.value == "PASS"
    assert finding.evidence[0].start_line == 2


def test_custom_forbidden_rule_fails_with_evidence():
    result = ConfigSentinelClient(
        engine=DeterministicComplianceEngine(
            (CustomPolicyPack.from_dict(pack("forbid")),)
        )
    ).audit_text("version 17.9\nbanner motd ^legacy^\n", vendor="cisco_ios")
    finding = next(
        item for item in result.findings if item.control_id == "ORG-MGMT-001"
    )
    assert finding.status.value == "FAIL"
    assert finding.evidence


def test_policy_validation_rejects_duplicate_or_invalid_rules():
    invalid = pack()
    invalid["controls"][0]["match"]["mode"] = "execute"
    with pytest.raises(PolicyValidationError):
        CustomPolicyPack.from_dict(invalid)


def test_policy_file_loads_from_json(tmp_path: Path):
    path = tmp_path / "policy.json"
    import json

    path.write_text(json.dumps(pack()), encoding="utf-8")
    loaded = CustomPolicyPack.from_file(path)
    assert loaded.pack_id == "org-baseline"
    assert loaded.rules[0].control_id == "ORG-MGMT-001"
