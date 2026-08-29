import json
from pathlib import Path

import pytest

from configsentinel.differential import DifferentialError, run_differential_test

CISCO = """version 17.9
hostname edge
ip ssh version 2
aaa new-model
logging host 192.0.2.10
ntp server 192.0.2.20
snmp-server group monitor v3
no ip http server
line vty 0 4
 transport input ssh
"""

JUNOS = """set system services ssh protocol-version v2
set system authentication-order password
set system syslog host 192.0.2.10 any any
set system ntp server 192.0.2.20
set snmp v3
delete system services telnet
"""


def test_differential_test_reports_equivalent_selected_semantics():
    report = run_differential_test(
        {"cisco_ios": CISCO, "junos": JUNOS},
        fields=(
            "management_ssh_enabled",
            "management_ssh_version",
            "aaa_enabled",
            "logging_enabled",
            "ntp_enabled",
            "snmp_secure",
        ),
        case_id="secure-management-equivalence",
    )

    assert report["schema"] == "configsentinel.cross-vendor-differential.v1"
    assert report["comparison"]["equivalent"] is True
    assert report["comparison"]["semantic_disagreement_count"] == 0
    assert report["comparison"]["control_disagreement_count"] == 0
    assert report["safety"]["authoritative_vendor_selected"] is False
    assert report["safety"]["raw_configuration_included"] is False


def test_differential_test_surfaces_disagreement_instead_of_selecting_a_winner():
    report = run_differential_test(
        {
            "cisco_ios": CISCO,
            "junos": "set system services ssh\nset system services telnet\n",
        },
        fields=("management_ssh_version", "management_telnet_enabled"),
        case_id="disagreement",
    )

    assert report["comparison"]["equivalent"] is False
    assert any(
        item["field"] == "management_ssh_version"
        for item in report["comparison"]["semantic_disagreements"]
    )
    assert report["safety"]["authoritative_vendor_selected"] is False


def test_differential_test_is_bounded_and_requires_explicit_variants():
    with pytest.raises(DifferentialError):
        run_differential_test({"cisco_ios": CISCO})
    with pytest.raises(DifferentialError):
        run_differential_test(
            {"cisco_ios": CISCO, "junos": JUNOS}, fields=("not-a-field",)
        )


def test_differential_cli_writes_hash_only_report(tmp_path: Path, capsys):
    from configsentinel.cli import main

    cisco_path = tmp_path / "cisco.cfg"
    junos_path = tmp_path / "junos.cfg"
    output_path = tmp_path / "differential.json"
    cisco_path.write_text(CISCO, encoding="utf-8")
    junos_path.write_text(JUNOS, encoding="utf-8")

    assert (
        main(
            [
                "differential-test",
                "--variant",
                f"cisco_ios={cisco_path}",
                "--variant",
                f"junos={junos_path}",
                "--field",
                "management_ssh_enabled",
                "--field",
                "management_ssh_version",
                "--out",
                str(output_path),
            ]
        )
        == 0
    )
    assert "differential_test=" in capsys.readouterr().out
    rendered = json.loads(output_path.read_text(encoding="utf-8"))
    assert rendered["comparison"]["equivalent"] is True
    assert CISCO not in json.dumps(rendered)
