from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from configsentinel.exchange import (
    ExchangeError,
    build_exchange_capsule,
    verify_exchange_capsule,
)

REPORT = {
    "audit": {
        "audit_id": "audit-exchange-1",
        "vendor": "cisco_ios",
        "parser_version": "3.0.0",
        "rule_pack_version": "3.0.0",
        "input_sha256": "a" * 64,
        "frameworks": ["cis-network"],
    },
    "findings": [
        {
            "finding_id": "failing-ssh",
            "control_id": "NET-MGMT-SSH-001",
            "status": "FAIL",
            "severity": "HIGH",
            "confidence": 1.0,
            "evidence": [
                {
                    "excerpt": "transport input telnet",
                    "start_line": 4,
                    "end_line": 4,
                    "redacted": True,
                }
            ],
            "risk": {"priority": "P1", "asset_criticality": "critical", "score": 9},
        },
        {
            "finding_id": "passing-aaa",
            "control_id": "NET-AUTH-001",
            "status": "PASS",
            "severity": "LOW",
            "evidence": [
                {
                    "excerpt": "secret should not escape",
                    "start_line": 10,
                    "end_line": 10,
                }
            ],
        },
    ],
    "unknown_blocks": [],
}


def test_capsule_is_deterministic_minimized_and_hash_bound() -> None:
    first = build_exchange_capsule(REPORT, recipient="reviewer-a", key=b"exchange-key")
    second = build_exchange_capsule(REPORT, recipient="reviewer-a", key=b"exchange-key")
    
    # Remove volatile timestamp-based fields before deterministic equality check
    for capsule in (first, second):
        capsule.pop("expires_at", None)
        capsule.pop("access_log", None)
        
    assert first == second
    encoded = json.dumps(first, sort_keys=True)
    assert "transport input telnet" not in encoded
    assert "secret should not escape" not in encoded
    assert first["payload"]["safety"] == {
        "raw_configuration_included": False,
        "raw_evidence_included": False,
        "passing_findings_included": False,
        "network_submission": False,
        "verdicts_changed": False,
    }
    assert first["payload"]["summary"]["finding_count"] == 1


def test_signed_capsule_verifies_and_rejects_tampering() -> None:
    capsule = build_exchange_capsule(REPORT, key=b"exchange-key")
    assert verify_exchange_capsule(capsule, key=b"exchange-key")["verified"] is True
    tampered = json.loads(json.dumps(capsule))
    tampered["payload"]["findings"][0]["severity"] = "LOW"
    result = verify_exchange_capsule(tampered, key=b"exchange-key")
    assert result["verified"] is False
    assert "capsule hash mismatch" in result["mismatches"]
    assert verify_exchange_capsule(capsule, key=b"wrong-key")["verified"] is False


def test_exchange_rejects_malformed_report() -> None:
    with pytest.raises(ExchangeError):
        build_exchange_capsule({"findings": []})


def test_exchange_cli_create_and_verify(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    capsule = tmp_path / "capsule.json"
    result = tmp_path / "verify.json"
    key = tmp_path / "key"
    report.write_text(json.dumps(REPORT), encoding="utf-8")
    key.write_bytes(b"exchange-key")
    env = {"PYTHONPATH": "src"}
    create = subprocess.run(
        [
            sys.executable,
            "-m",
            "configsentinel.cli",
            "audit-exchange",
            str(report),
            "--key-file",
            str(key),
            "--out",
            str(capsule),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert create.returncode == 0, create.stderr
    verify = subprocess.run(
        [
            sys.executable,
            "-m",
            "configsentinel.cli",
            "audit-exchange-verify",
            str(capsule),
            "--key-file",
            str(key),
            "--out",
            str(result),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert verify.returncode == 0, verify.stderr
    assert json.loads(result.read_text(encoding="utf-8"))["verified"] is True
