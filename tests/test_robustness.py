from __future__ import annotations

import json
from pathlib import Path

import pytest

from configsentinel.robustness import RobustnessError, run_robustness_pack

CONFIG = "version 17.3\nhostname edge\nline vty 0 4\n transport input ssh\n"


def test_robustness_pack_is_bounded_and_hash_only() -> None:
    result = run_robustness_pack(CONFIG, vendor="cisco_ios", max_cases=8)
    assert result["summary"]["case_count"] == 8
    assert result["summary"]["crash_count"] == 0
    assert result["summary"]["passed"] is True
    assert result["safety"]["raw_configuration_included"] is False
    assert result["safety"]["exception_messages_included"] is False
    serialized = json.dumps(result, sort_keys=True)
    assert "transport input ssh" not in serialized
    assert "robustness marker" not in serialized


def test_robustness_reports_semantic_deviation_without_normalizing_it() -> None:
    result = run_robustness_pack(CONFIG, vendor="cisco_ios", max_cases=4)
    assert result["summary"]["pass_criteria"]
    assert any(item["case_id"] == "baseline" for item in result["cases"])
    assert all(
        "semantic_fields_changed_vs_baseline" in item
        for item in result["cases"]
        if item["outcome"] == "ACCEPTED"
    )


def test_robustness_rejects_unsafe_inputs_and_unknown_vendor() -> None:
    with pytest.raises(RobustnessError):
        run_robustness_pack("", vendor="cisco_ios")
    with pytest.raises(RobustnessError):
        run_robustness_pack(CONFIG, vendor="unknown")
    with pytest.raises(RobustnessError):
        run_robustness_pack(CONFIG, vendor="cisco_ios", max_cases=0)
    with pytest.raises(RobustnessError):
        run_robustness_pack("x" * (1024 * 1024 + 1), vendor="cisco_ios")


def test_robustness_cli(tmp_path: Path, capsys) -> None:
    from configsentinel.cli import main

    config_path = tmp_path / "edge.cfg"
    output_path = tmp_path / "robustness.json"
    config_path.write_text(CONFIG, encoding="utf-8")
    assert (
        main(
            [
                "parser-robustness",
                str(config_path),
                "--vendor",
                "cisco_ios",
                "--max-cases",
                "3",
                "--out",
                str(output_path),
            ]
        )
        == 0
    )
    assert "crashes=0" in capsys.readouterr().out
    assert (
        json.loads(output_path.read_text(encoding="utf-8"))["summary"]["case_count"]
        == 3
    )
