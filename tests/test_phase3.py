from configsentinel import (
    ConfigSentinelClient,
    DeterministicComplianceEngine,
    FindingStatus,
    detect_and_parse,
)


def test_cisco_parser_extracts_secure_ssh_and_telnet_failure():
    text = """version 17.9
hostname edge-1
ip ssh version 2
aaa new-model
logging host 10.0.0.10
ntp server 10.0.0.20
line vty 0 4
 transport input telnet ssh
"""
    result = detect_and_parse(text, "cisco_ios")
    assert result.config.management_ssh_version == "2"
    assert result.config.management_telnet_enabled is True
    assert result.config.spans_for("management_telnet_enabled")[0].start_line == 8


def test_junos_parser_extracts_secure_ssh_and_logging():
    text = """set system services ssh protocol-version v2
set system authentication-order password
set system syslog host 10.0.0.10 any info
set system ntp server 10.0.0.20
set snmp v3 usm local-engine user audit
"""
    result = detect_and_parse(text, "junos")
    assert result.config.management_ssh_enabled is True
    assert result.config.management_ssh_version == "2"
    assert result.config.aaa_enabled is True
    assert result.config.logging_enabled is True
    assert result.config.snmp_secure is True


def test_unknown_lines_are_preserved_and_never_compliant():
    result = detect_and_parse("version 17.9\nmagic future command\n", "cisco_ios")
    assert result.config.unknown_blocks
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    audit = client.audit_text(
        "version 17.9\nmagic future command\n", vendor="cisco_ios"
    )
    assert any(f.status == FindingStatus.UNKNOWN for f in audit.findings)


def test_engine_produces_evidence_backed_failures():
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    audit = client.audit_text(
        "version 17.9\nline vty 0 4\n transport input telnet\n", vendor="cisco_ios"
    )
    telnet = next(f for f in audit.findings if f.control_id == "NET-MGMT-TELNET-001")
    assert telnet.status == FindingStatus.FAIL
    assert telnet.evidence
    assert telnet.confidence == 1.0


def test_auto_detection_rejects_ambiguous_input():
    try:
        detect_and_parse("hostname edge-1\n", "auto")
    except ValueError as exc:
        assert "identify vendor" in str(exc)
    else:
        raise AssertionError("ambiguous input must fail closed")
