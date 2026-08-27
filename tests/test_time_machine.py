import json
from pathlib import Path

import pytest

from configsentinel.time_machine import TimeMachineError, build_time_machine, render_time_machine_html


SNAPSHOTS = [
    {
        "observed_at": "2026-08-25T10:00:00+00:00",
        "report": {
            "audit": {"audit_id": "audit-old", "vendor": "cisco_ios", "input_sha256": "a" * 64, "parser_version": "3.0.0"},
            "findings": [{"finding_id": "ssh-old", "control_id": "NET-MGMT-SSH-001", "status": "FAIL", "severity": "HIGH", "evidence": [{"excerpt": "raw should not be copied", "start_line": 4, "end_line": 4}]}],
        },
    },
    {
        "observed_at": "2026-08-27T10:00:00+00:00",
        "report": {
            "audit": {"audit_id": "audit-new", "vendor": "cisco_ios", "input_sha256": "b" * 64, "parser_version": "3.0.0"},
            "findings": [{"finding_id": "ssh-new", "control_id": "NET-MGMT-SSH-001", "status": "PASS", "severity": "HIGH", "evidence": [{"excerpt": "raw should not be copied", "start_line": 6, "end_line": 6}]}],
        },
    },
]


def test_time_machine_replays_and_detects_transitions_without_interpolation():
    machine = build_time_machine(SNAPSHOTS)

    assert machine["schema"] == "configsentinel.compliance-time-machine.v1"
    assert machine["summary"]["snapshot_count"] == 2
    assert machine["summary"]["change_count"] == 1
    assert machine["changes"] == [{"control_id": "NET-MGMT-SSH-001", "observed_at": "2026-08-27T10:00:00+00:00", "from_status": "FAIL", "to_status": "PASS"}]
    assert machine["control_history"]["NET-MGMT-SSH-001"][1]["status"] == "PASS"
    assert machine["safety"]["historical_interpolation"] is False
    assert "raw should not be copied" not in json.dumps(machine)


def test_time_machine_filters_vendor_and_control_and_rejects_duplicate_times():
    machine = build_time_machine(SNAPSHOTS, vendor="cisco_ios", control_id="NET-MGMT-SSH-001")
    assert machine["summary"]["snapshot_count"] == 2
    with pytest.raises(TimeMachineError):
        build_time_machine(SNAPSHOTS + [SNAPSHOTS[0]])
    with pytest.raises(TimeMachineError):
        build_time_machine(SNAPSHOTS, vendor="junos")


def test_time_machine_html_is_self_contained():
    html = render_time_machine_html(build_time_machine(SNAPSHOTS))
    assert "ConfigSentinel AI compliance time machine" in html
    assert "Missing periods are not interpolated" in html
    assert "https://" not in html


def test_time_machine_cli_writes_json_and_html(tmp_path: Path, capsys):
    from configsentinel.cli import main

    source = tmp_path / "snapshots.json"
    output = tmp_path / "time-machine.json"
    html = tmp_path / "time-machine.html"
    source.write_text(json.dumps(SNAPSHOTS), encoding="utf-8")

    assert main(["time-machine", str(source), "--control-id", "NET-MGMT-SSH-001", "--out", str(output), "--html-out", str(html)]) == 0
    assert "time_machine=" in capsys.readouterr().out
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["change_count"] == 1
    assert html.exists()
