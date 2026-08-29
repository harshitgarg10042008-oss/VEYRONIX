from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from configsentinel.freshness import FreshnessError, build_freshness_assessment


def report(input_hash: str = "a" * 64, status: str = "FAIL") -> dict:
    return {
        "audit": {
            "audit_id": "freshness-audit",
            "vendor": "cisco_ios",
            "parser_version": "3.0.0",
            "rule_pack_version": "3.0.0",
            "input_sha256": input_hash,
        },
        "findings": [
            {
                "finding_id": "f-1",
                "control_id": "CTRL-1",
                "status": status,
                "severity": "HIGH",
            }
        ],
    }


def test_freshness_is_deterministic_and_not_a_verdict_engine() -> None:
    first = build_freshness_assessment(
        report(),
        observed_at="2026-08-27T00:00:00Z",
        as_of="2026-08-27T06:00:00Z",
        ttl_seconds=86400,
    )
    second = build_freshness_assessment(
        report(),
        observed_at="2026-08-27T00:00:00Z",
        as_of="2026-08-27T06:00:00Z",
        ttl_seconds=86400,
    )
    assert first == second
    assert first["freshness"]["state"] == "FRESH"
    assert first["freshness"]["decay_fraction"] == 0.25
    assert first["assurance"]["state"] == "CURRENT"
    assert first["safety"]["verdicts_changed"] is False


def test_stale_and_expired_assurance_require_reaudit() -> None:
    stale = build_freshness_assessment(
        report(),
        observed_at="2026-08-27T00:00:00Z",
        as_of="2026-08-28T12:00:00Z",
        ttl_seconds=86400,
    )
    expired = build_freshness_assessment(
        report(),
        observed_at="2026-08-27T00:00:00Z",
        as_of="2026-08-30T00:00:00Z",
        ttl_seconds=86400,
    )
    assert stale["freshness"]["state"] == "STALE"
    assert stale["assurance"]["state"] == "AGING"
    assert expired["freshness"]["state"] == "EXPIRED"
    assert expired["assurance"]["state"] == "EXPIRED"
    assert expired["assurance"]["needs_reaudit"] is True


def test_semantic_drift_is_separate_from_freshness() -> None:
    baseline = report()
    current = report(input_hash="b" * 64, status="PASS")
    result = build_freshness_assessment(
        current,
        observed_at="2026-08-27T00:00:00Z",
        as_of="2026-08-27T01:00:00Z",
        ttl_seconds=86400,
        baseline=baseline,
    )
    assert result["freshness"]["state"] == "FRESH"
    assert result["drift"]["drifted"] is True
    assert "input_sha256_changed" in result["drift"]["reasons"]
    assert "finding_attributes_changed" in result["drift"]["reasons"]
    assert result["assurance"]["state"] == "DRIFTED"
    assert result["assurance"]["verdicts_changed"] is False


def test_rejects_invalid_time_and_negative_age() -> None:
    with pytest.raises(FreshnessError):
        build_freshness_assessment(
            report(), observed_at="2026-08-27T00:00:00", as_of="2026-08-27T01:00:00Z"
        )
    with pytest.raises(FreshnessError):
        build_freshness_assessment(
            report(), observed_at="2026-08-27T01:00:00Z", as_of="2026-08-27T00:00:00Z"
        )


def test_freshness_cli(tmp_path: Path, capsys) -> None:
    from configsentinel.cli import main

    report_path = tmp_path / "report.json"
    out_path = tmp_path / "freshness.json"
    report_path.write_text(json.dumps(report()), encoding="utf-8")
    assert (
        main(
            [
                "assurance-freshness",
                str(report_path),
                "--observed-at",
                "2026-08-27T00:00:00Z",
                "--as-of",
                "2026-08-27T01:00:00Z",
                "--out",
                str(out_path),
            ]
        )
        == 0
    )
    assert "verdicts_changed=False" in capsys.readouterr().out
    assert json.loads(out_path.read_text(encoding="utf-8"))["schema"].endswith(
        "assurance-freshness.v1"
    )
