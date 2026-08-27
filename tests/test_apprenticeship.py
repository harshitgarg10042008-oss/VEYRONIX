import json
from pathlib import Path

import pytest

from configsentinel.apprenticeship import ApprenticeshipError, create_contract, evaluate_contract


MAPPING = {
    "mapping_id": "mapping_123",
    "vendor": "cisco_ios",
    "parser_version": "3.1.0",
    "source_case_id": "case_123",
    "syntax_fingerprint": "f" * 64,
    "normalized_concept": "management_telnet_enabled",
    "interpretation": "This directive enables legacy Telnet management.",
    "mapping_version": "9.0.0",
    "approved_by": "reviewer-b",
    "approved_at": "2026-08-27T00:00:00Z",
}


def test_contract_is_redacted_and_requires_human_promotion():
    contract = create_contract(MAPPING, positive_examples=["transport input telnet"], counterexamples=["transport input ssh"])

    assert contract["schema"] == "configsentinel.parser-apprenticeship-contract.v1"
    assert contract["promotion"]["status"] == "PENDING_CONTRACT_TESTS"
    assert contract["promotion"]["promoted_into_parser"] is False
    assert contract["safety"]["redacted_examples_included"] is True
    assert contract["safety"]["raw_secrets_included"] is False

    result = evaluate_contract(contract)
    assert result["promotion"]["status"] == "READY_FOR_HUMAN_REVIEW"
    assert result["promotion"]["promoted_into_parser"] is False
    assert result["safety"]["verdicts_changed"] is False


def test_contract_rejects_bad_counterexamples_and_missing_mapping_fields():
    contract = create_contract(MAPPING, positive_examples=["transport input telnet"], counterexamples=["transport input ssh"])
    contract["examples"]["counterexamples"] = ["transport input telnet"]
    result = evaluate_contract(contract)
    assert result["promotion"]["status"] == "REJECTED"

    with pytest.raises(ApprenticeshipError):
        create_contract({**MAPPING, "approved_by": ""}, positive_examples=["transport input telnet"], counterexamples=["transport input ssh"])
    redacted = create_contract(MAPPING, positive_examples=["password super-secret"], counterexamples=["transport input ssh"])
    assert "super-secret" not in json.dumps(redacted)
    assert "<REDACTED_PASSWORD>" in redacted["examples"]["positive"][0]


def test_contract_cli_creates_and_tests_artifacts(tmp_path: Path, capsys):
    from configsentinel.cli import main

    mapping_path = tmp_path / "mapping.json"
    contract_path = tmp_path / "contract.json"
    result_path = tmp_path / "contract-test.json"
    mapping_path.write_text(json.dumps(MAPPING), encoding="utf-8")

    assert main(["apprenticeship-contract", str(mapping_path), "--positive", "transport input telnet", "--counterexample", "transport input ssh", "--out", str(contract_path)]) == 0
    assert "apprenticeship_contract=" in capsys.readouterr().out
    assert main(["apprenticeship-test", str(contract_path), "--out", str(result_path)]) == 0
    assert "READY_FOR_HUMAN_REVIEW" in capsys.readouterr().out
    assert json.loads(result_path.read_text(encoding="utf-8"))["promotion"]["promoted_into_parser"] is False
