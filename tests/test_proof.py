import copy
import json
from pathlib import Path

from configsentinel.proof import build_proof_bundle, verify_proof_bundle


REPORT = {
    "audit": {
        "audit_id": "audit-proof",
        "vendor": "cisco_ios",
        "parser_version": "3.0.0",
        "rule_pack_version": "3.0.0",
        "input_sha256": "e" * 64,
    },
    "findings": [
        {
            "finding_id": "finding-telnet",
            "control_id": "NET-MGMT-TELNET-001",
            "status": "FAIL",
            "severity": "HIGH",
            "confidence": 1.0,
            "rationale": "Telnet is explicitly enabled on the management VTY.",
            "evidence": [{"start_line": 3, "end_line": 4, "excerpt": "transport input <REDACTED>", "redacted": True}],
        }
    ],
    "unknown_blocks": [],
}


def test_proof_bundle_binds_evidence_and_never_contains_commands_or_excerpts():
    proof = build_proof_bundle(REPORT)

    assert proof["schema"] == "configsentinel.proof-carrying-remediation.v1"
    assert proof["summary"]["proof_count"] == 1
    assert proof["summary"]["state"] == "READY_FOR_REVIEW"
    assert proof["safety"]["commands_included"] is False
    assert proof["safety"]["raw_evidence_included"] is False
    assert "transport input" not in json.dumps(proof)
    assert proof["proofs"][0]["review"] == {"requires_human_approval": True, "executable": False}
    assert verify_proof_bundle(proof, REPORT)["verified"] is True


def test_proof_verification_rejects_source_or_evidence_tampering():
    proof = build_proof_bundle(REPORT)
    changed = copy.deepcopy(REPORT)
    changed["audit"]["input_sha256"] = "f" * 64
    result = verify_proof_bundle(proof, changed)
    assert result["verified"] is False
    assert "source contract mismatch" in result["mismatches"]

    tampered = copy.deepcopy(proof)
    tampered["proofs"][0]["source"]["evidence"][0]["excerpt_sha256"] = "0" * 64
    result = verify_proof_bundle(tampered, REPORT)
    assert result["verified"] is False
    assert any("evidence binding mismatch" in item for item in result["mismatches"])


def test_proof_cli_creates_and_verifies_review_artifacts(tmp_path: Path, capsys):
    from configsentinel.cli import main

    report_path = tmp_path / "report.json"
    proof_path = tmp_path / "proof.json"
    verification_path = tmp_path / "verification.json"
    report_path.write_text(json.dumps(REPORT), encoding="utf-8")

    assert main(["remediation-proof", str(report_path), "--out", str(proof_path)]) == 0
    assert "remediation_proof=" in capsys.readouterr().out
    assert main(["remediation-proof-verify", str(proof_path), str(report_path), "--out", str(verification_path)]) == 0
    assert "verified=True" in capsys.readouterr().out
    assert json.loads(verification_path.read_text(encoding="utf-8"))["verified"] is True
