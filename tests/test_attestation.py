import copy
import json
from pathlib import Path

from configsentinel.attestation import build_attestation, verify_attestation


def sample_report() -> dict:
    return {
        "report_version": "8.0.0",
        "audit": {
            "audit_id": "audit_demo",
            "vendor": "cisco_ios",
            "parser_version": "3.0.0",
            "rule_pack_version": "4.0.0",
            "framework_registry_version": "2.0.0",
            "frameworks": ["cis-network"],
            "input_sha256": "a" * 64,
        },
        "summary": {
            "finding_count": 1,
            "failed_count": 1,
            "unknown_count": 0,
            "evaluated_count": 1,
        },
        "findings": [
            {
                "finding_id": "finding_1",
                "audit_id": "audit_demo",
                "control_id": "NET-MGMT-SSH-001",
                "status": "FAIL",
                "severity": "HIGH",
                "confidence": 1.0,
                "evidence": [
                    {
                        "start_line": 4,
                        "end_line": 4,
                        "excerpt": "transport input telnet",
                        "redacted": True,
                    }
                ],
                "rationale": "Telnet is enabled.",
            }
        ],
        "unknown_blocks": [],
        "reconciliation": {
            "status_count_total": 1,
            "matches_finding_count": True,
            "failed_count_matches": True,
        },
    }


def test_attestation_is_deterministic_and_contains_no_raw_evidence():
    report = sample_report()
    first = build_attestation(report, b"demo-key", issued_at="2026-08-27T00:00:00Z")
    second = build_attestation(report, b"demo-key", issued_at="2026-08-27T00:00:00Z")

    assert first == second
    serialized = json.dumps(first, sort_keys=True)
    assert "transport input telnet" not in serialized
    assert first["payload"]["source_kind"] == "redacted_audit_report"
    assert first["payload"]["reviewer_status"] == "REVIEW_REQUIRED"


def test_attestation_signature_and_claim_replay_are_verified():
    report = sample_report()
    token = build_attestation(report, b"demo-key", issued_at="2026-08-27T00:00:00Z")

    assert verify_attestation(token, report, b"demo-key") == (
        True,
        "attestation verified and replayed",
    )
    assert verify_attestation(token, report, b"wrong-key")[0] is False

    changed = copy.deepcopy(report)
    changed["findings"][0]["status"] = "PASS"
    valid, reason = verify_attestation(token, changed, b"demo-key")
    assert valid is False
    assert reason == "attestation claim does not match supplied report"


def test_attestation_rejects_invalid_report_digest_and_empty_key():
    report = sample_report()
    invalid = copy.deepcopy(report)
    invalid["audit"]["input_sha256"] = "not-a-digest"

    try:
        build_attestation(invalid, b"demo-key")
    except ValueError as exc:
        assert "lowercase SHA-256" in str(exc)
    else:
        raise AssertionError("invalid digest was accepted")

    try:
        build_attestation(report, b"")
    except ValueError as exc:
        assert "signing key" in str(exc)
    else:
        raise AssertionError("empty signing key was accepted")


def test_attestation_cli_create_and_verify(tmp_path: Path, capsys):
    from configsentinel.cli import main

    report_path = tmp_path / "report.json"
    key_path = tmp_path / "key.bin"
    token_path = tmp_path / "attestation.json"
    report_path.write_text(json.dumps(sample_report()), encoding="utf-8")
    key_path.write_bytes(b"demo-key")

    assert (
        main(
            [
                "attestation-create",
                str(report_path),
                "--key-file",
                str(key_path),
                "--out",
                str(token_path),
                "--issued-at",
                "2026-08-27T00:00:00Z",
            ]
        )
        == 0
    )
    assert "attestation=" in capsys.readouterr().out
    assert (
        main(
            [
                "attestation-verify",
                str(report_path),
                str(token_path),
                "--key-file",
                str(key_path),
            ]
        )
        == 0
    )
    assert "VALID" in capsys.readouterr().out
