import json
from pathlib import Path

import pytest

from configsentinel.mutation import MutationError, run_mutation_lab

CISCO_CONFIG = """version 17.9
hostname edge
ip ssh version 2
line vty 0 4
 transport input ssh
"""


def test_mutation_lab_passes_preservation_and_targeted_change_relations():
    report = run_mutation_lab(CISCO_CONFIG, vendor="cisco_ios")

    assert report["schema"] == "configsentinel.semantic-mutation-lab.v1"
    assert report["summary"]["passed"] is True
    assert report["summary"]["mutation_count"] == 5
    assert all(item["passed"] for item in report["mutations"])
    assert report["mutations"][0]["relation"] == "PRESERVE"
    assert report["mutations"][3]["relation"] == "CHANGE"
    assert report["mutations"][3]["observed_status"] == "FAIL"
    assert "NET-MGMT-TELNET-001" in report["mutations"][3]["changed_controls"]
    assert report["safety"]["raw_configuration_included"] is False
    assert CISCO_CONFIG not in json.dumps(report)


def test_mutation_lab_is_deterministic_and_bounded():
    first = run_mutation_lab(CISCO_CONFIG, vendor="cisco_ios", max_mutations=3)
    second = run_mutation_lab(CISCO_CONFIG, vendor="cisco_ios", max_mutations=3)

    assert first == second
    assert first["summary"]["mutation_count"] == 3
    with pytest.raises(MutationError):
        run_mutation_lab(CISCO_CONFIG, vendor="cisco_ios", max_mutations=0)
    with pytest.raises(MutationError):
        run_mutation_lab(CISCO_CONFIG, vendor="auto")


def test_mutation_lab_supports_junos_targeted_mutation():
    report = run_mutation_lab("set system services ssh\n", vendor="junos")

    assert report["summary"]["passed"] is True
    telnet = next(
        item for item in report["mutations"] if item["mutation_id"] == "enable_telnet"
    )
    assert telnet["observed_status"] == "FAIL"


def test_mutation_lab_cli_writes_artifact(tmp_path: Path, capsys):
    from configsentinel.cli import main

    source = tmp_path / "edge.cfg"
    output = tmp_path / "mutation.json"
    source.write_text(CISCO_CONFIG, encoding="utf-8")

    assert (
        main(
            ["mutation-lab", str(source), "--vendor", "cisco_ios", "--out", str(output)]
        )
        == 0
    )
    assert "mutation_lab=" in capsys.readouterr().out
    rendered = json.loads(output.read_text(encoding="utf-8"))
    assert rendered["summary"]["passed"] is True
