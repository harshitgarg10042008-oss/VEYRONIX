from pathlib import Path

import pytest

from configsentinel import (
    ConfigSentinelClient,
    DeterministicComplianceEngine,
    RemediationError,
    generate_bundle,
)
from configsentinel.cli import main


def _audit(vendor="cisco_ios"):
    text = "version 17.9\nline vty 0 4\n transport input telnet\n"
    return ConfigSentinelClient(engine=DeterministicComplianceEngine()).audit_text(text, vendor=vendor)


def test_cisco_bundle_contains_preview_and_no_execution_path():
    bundle = generate_bundle(_audit())
    assert bundle.step_count >= 1
    assert "preview only" in bundle.script
    assert "transport input ssh" in bundle.script
    assert "no device connection" in bundle.script


def test_non_failure_findings_do_not_generate_commands():
    bundle = generate_bundle(_audit("junos"))
    assert bundle.vendor == "junos"
    assert all(step.command for step in bundle.steps)


def test_unsupported_vendor_fails_closed():
    with pytest.raises(RemediationError):
        generate_bundle(_audit("firewall_generic"))


def test_command_validator_blocks_dangerous_templates(monkeypatch):
    from configsentinel import remediation
    monkeypatch.setitem(remediation._COMMANDS, ("cisco_ios", "NET-MGMT-TELNET-001"), ("reload", "never"))
    with pytest.raises(RemediationError):
        generate_bundle(_audit())


def test_cli_requires_dry_run_for_approval(tmp_path: Path, capsys):
    config = tmp_path / "edge.conf"
    config.write_text("version 17.9\nline vty 0 4\n transport input telnet\n", encoding="utf-8")
    code = main(["audit", str(config), "--vendor", "cisco_ios", "--approve"])
    captured = capsys.readouterr()
    assert code == 2
    assert "requires --dry-run" in captured.err


def test_cli_generates_preview_without_execution(tmp_path: Path, capsys):
    config = tmp_path / "edge.conf"
    output = tmp_path / "out.txt"
    config.write_text("version 17.9\nline vty 0 4\n transport input telnet\n", encoding="utf-8")
    code = main(["audit", str(config), "--vendor", "cisco_ios", "--dry-run", "--approve", "--remediation-out", str(output)])
    captured = capsys.readouterr()
    assert code == 0
    assert output.exists()
    assert "no device connection or execution" in captured.out
    assert "transport input ssh" in output.read_text(encoding="utf-8")
