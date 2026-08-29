import copy
import json
from pathlib import Path

from configsentinel.uncertainty import build_uncertainty_budget


def sample_report() -> dict:
    return {
        "report_version": "8.0.0",
        "audit": {
            "audit_id": "audit_budget",
            "vendor": "cisco_ios",
            "parser_version": "3.0.0",
            "rule_pack_version": "4.0.0",
            "frameworks": ["cis-network"],
            "input_sha256": "b" * 64,
        },
        "summary": {"finding_count": 2, "failed_count": 1, "unknown_count": 1},
        "findings": [
            {
                "finding_id": "finding_fail",
                "control_id": "NET-MGMT-SSH-001",
                "status": "FAIL",
                "confidence": 1.0,
                "evidence": [{"start_line": 4, "end_line": 4, "redacted": True}],
                "framework_mappings": [
                    {"framework_id": "cis-network", "status": "MAPPED"}
                ],
            },
            {
                "finding_id": "finding_unknown",
                "control_id": "NET-AAA-001",
                "status": "UNKNOWN",
                "confidence": 0.25,
                "evidence": [],
                "framework_mappings": [],
            },
        ],
        "unknown_blocks": [
            {"start_line": 10, "end_line": 11, "excerpt": "unknown", "redacted": True}
        ],
        "reconciliation": {
            "status_count_total": 2,
            "matches_finding_count": True,
            "failed_count_matches": True,
        },
    }


def test_budget_exposes_evidence_and_mapping_gaps_without_verdict_changes():
    report = sample_report()
    before = copy.deepcopy(report["findings"])
    budget = build_uncertainty_budget(report)

    assert budget["assurance"]["state"] == "REVIEW_REQUIRED"
    assert budget["assurance"]["evidence_coverage"] == 0.5
    assert budget["assurance"]["framework_mapping_coverage"] == 0.5
    assert set(budget["assurance"]["gaps"]) == {
        "framework_mapping_unverified",
        "missing_source_evidence",
        "unknown_blocks_present",
    }
    assert budget["findings"][0]["category"] == "VERIFIED"
    assert budget["findings"][1]["category"] == "UNKNOWN"
    assert budget["verdict_boundary"]["verdicts_changed"] is False
    assert report["findings"] == before


def test_budget_detects_unredacted_evidence_and_low_confidence():
    report = sample_report()
    report["findings"][0]["evidence"][0]["redacted"] = False
    report["findings"][0]["confidence"] = 0.6
    budget = build_uncertainty_budget(report)

    detail = budget["findings"][0]
    assert detail["category"] == "INFERRED"
    assert "evidence_redaction_unverified" in detail["gaps"]
    assert budget["assurance"]["evidence_coverage"] == 0.0


def test_uncertainty_budget_cli_writes_json(tmp_path: Path, capsys):
    from configsentinel.cli import main

    report_path = tmp_path / "report.json"
    output_path = tmp_path / "budget.json"
    report_path.write_text(json.dumps(sample_report()), encoding="utf-8")

    assert (
        main(["uncertainty-budget", str(report_path), "--out", str(output_path)]) == 0
    )
    assert "uncertainty_budget=" in capsys.readouterr().out
    rendered = json.loads(output_path.read_text(encoding="utf-8"))
    assert rendered["schema"] == "configsentinel.uncertainty-budget.v1"
